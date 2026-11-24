-- Density UAP safety spine v0.1
-- Implements: evidence-status type system (Corollary 10), proven-bridge rule,
-- bind receipts, receiver-owned effect fence, single-use nonce ledger.
create extension if not exists pgcrypto;
create schema if not exists core;
create schema if not exists uap;
create schema if not exists verify;
create schema if not exists sem;
create schema if not exists effect;

create table if not exists core.systems (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table uap.port_epochs (
  id         uuid primary key default gen_random_uuid(),
  system_id  uuid not null references core.systems(id),
  epoch_no   int  not null,
  roots_hash text not null,
  unique (system_id, epoch_no)
);

-- Signing keys are registered with a role; the synthesizer can never verify.
create table verify.keys (
  key_id text primary key,
  role   text not null check (role in ('SYNTHESIZER','VERIFIER'))
);

create table verify.refinement_receipts (
  id                 uuid primary key default gen_random_uuid(),
  port_epoch_id      uuid not null references uap.port_epochs(id),
  consequence_key    text not null,
  live_class_hash    text not null,
  constant_value     text not null,
  verifier_key_id    text not null references verify.keys(key_id),
  synthesizer_key_id text not null references verify.keys(key_id),
  signature_verified boolean not null,
  probe_action_ids   uuid[] not null default '{}',
  issued_at          timestamptz not null default now(),
  check (verifier_key_id <> synthesizer_key_id)
);

create type evidence_status as enum
  ('SETTLED_TRUE','SETTLED_FALSE','UNRESOLVED','NOT_APPLICABLE','INCONCLUSIVE');

create table sem.settlements (
  id              uuid primary key default gen_random_uuid(),
  port_epoch_id   uuid not null references uap.port_epochs(id),
  consequence_key text not null,
  status          evidence_status not null default 'UNRESOLVED',
  live_class_hash text not null,
  refinement_id   uuid references verify.refinement_receipts(id),
  updated_at      timestamptz not null default now(),
  unique (port_epoch_id, consequence_key)
);

-- Requested -> translated -> applied readback
create table effect.bind_receipts (
  action_id        uuid primary key,
  port_epoch_id    uuid not null references uap.port_epochs(id),
  coord            text not null,
  requested        numeric not null,
  translated       numeric not null,
  applied_readback numeric not null,
  native_quanta    bigint not null,
  tolerance        numeric not null,
  within_tolerance boolean generated always as
                     (abs(applied_readback - translated) <= tolerance) stored,
  sub_quantum      boolean generated always as (native_quanta = 0) stored
);

-- Corollary 10(2): strengthening needs a verifier receipt bound to this epoch,
-- this consequence, this live class, from a VERIFIER key distinct from the synthesizer,
-- and resting on no mismatched or sub-quantum probe.
create function sem.guard_settlement() returns trigger language plpgsql as $$
declare r verify.refinement_receipts%rowtype; vrole text; srole text;
begin
  if new.status in ('SETTLED_TRUE','SETTLED_FALSE')
     and (tg_op = 'INSERT' or old.status not in ('SETTLED_TRUE','SETTLED_FALSE')
          or old.refinement_id is distinct from new.refinement_id) then
    if new.refinement_id is null then
      raise exception 'ILLEGAL_STRENGTHENING_CAST: no refinement receipt for %', new.consequence_key;
    end if;
    select * into r from verify.refinement_receipts where id = new.refinement_id;
    select role into vrole from verify.keys where key_id = r.verifier_key_id;
    select role into srole from verify.keys where key_id = r.synthesizer_key_id;
    if r.port_epoch_id <> new.port_epoch_id or r.consequence_key <> new.consequence_key
       or r.live_class_hash <> new.live_class_hash or not r.signature_verified
       or vrole <> 'VERIFIER' or srole <> 'SYNTHESIZER' then
      raise exception 'ILLEGAL_STRENGTHENING_CAST: receipt does not bind % on this live class', new.consequence_key;
    end if;
    if (new.status = 'SETTLED_TRUE') <> (r.constant_value = 'true') then
      raise exception 'ILLEGAL_STRENGTHENING_CAST: status disagrees with verified constant';
    end if;
    if exists (select 1 from effect.bind_receipts b
               where b.action_id = any (r.probe_action_ids)
                 and (not b.within_tolerance or b.sub_quantum)) then
      raise exception 'BINDING_MISMATCH: settlement rests on a mismatched or sub-quantum probe';
    end if;
  end if;
  return new;
end $$;

create trigger settlements_guard before insert or update on sem.settlements
  for each row execute function sem.guard_settlement();

-- Weakening (Corollary 10(1)) is always allowed: no trigger blocks SETTLED -> UNRESOLVED.

-- Proven-bridge rule
create type bridge_state as enum ('CANONICAL_EQUIVALENT','RECOVERABLE_BY_MAP',
  'DOMAIN_LOCAL_ONLY','BRIDGE_UNPROVEN','INAPPLICABLE');

create table uap.semantic_bridges (
  id              uuid primary key default gen_random_uuid(),
  port_epoch_id   uuid not null references uap.port_epochs(id),
  native_field    text not null,
  canonical_field text not null,
  state           bridge_state not null default 'BRIDGE_UNPROVEN',
  unique (port_epoch_id, native_field, canonical_field)
);

create table sem.canonical_values (
  id              uuid primary key default gen_random_uuid(),
  port_epoch_id   uuid not null references uap.port_epochs(id),
  native_field    text not null,
  canonical_field text not null,
  value           jsonb not null
);

create function sem.guard_canonical() returns trigger language plpgsql as $$
begin
  if not exists (select 1 from uap.semantic_bridges b
                 where b.port_epoch_id = new.port_epoch_id
                   and b.native_field = new.native_field
                   and b.canonical_field = new.canonical_field
                   and b.state in ('CANONICAL_EQUIVALENT','RECOVERABLE_BY_MAP')) then
    raise exception 'BRIDGE_UNPROVEN: % -> %', new.native_field, new.canonical_field;
  end if;
  return new;
end $$;

create trigger canonical_guard before insert or update on sem.canonical_values
  for each row execute function sem.guard_canonical();

-- Receiver-owned effect fence + single-use nonce ledger.
-- The fence lives at the effect destination; ownership moves by epoch, never by copying ledgers.
create table effect.fences (
  destination   text primary key,
  owner_epoch   bigint not null,
  owner_id      text not null
);

create table effect.nonces (
  nonce        text primary key,             -- single-use: second insert fails
  certificate  text not null,
  consumed_at  timestamptz not null default now()
);

create table effect.effects (
  action_id    text primary key,             -- global action identity: one effect per action
  destination  text not null references effect.fences(destination),
  owner_epoch  bigint not null,
  payload_hash text not null,
  committed_at timestamptz not null default now()
);

-- Apply an effect exactly once. Returns 'COMMITTED', 'ALREADY_COMMITTED' (idempotent retry)
-- or raises STALE_OWNER / NONCE_REPLAY / PAYLOAD_CONFLICT.
create function effect.apply_once(p_dest text, p_epoch bigint, p_action text,
                                  p_payload_hash text, p_nonce text, p_cert text)
returns text language plpgsql as $$
declare f effect.fences%rowtype; e effect.effects%rowtype;
begin
  select * into f from effect.fences where destination = p_dest for update;
  if f.owner_epoch <> p_epoch then
    raise exception 'STALE_OWNER: epoch % fenced by %', p_epoch, f.owner_epoch;
  end if;
  select * into e from effect.effects where action_id = p_action;
  if found then
    if e.payload_hash <> p_payload_hash then
      raise exception 'PAYLOAD_CONFLICT: action % already bound to another payload', p_action;
    end if;
    return 'ALREADY_COMMITTED';
  end if;
  begin
    insert into effect.nonces(nonce, certificate) values (p_nonce, p_cert);
  exception when unique_violation then
    raise exception 'NONCE_REPLAY: %', p_nonce;
  end;
  insert into effect.effects(action_id, destination, owner_epoch, payload_hash)
    values (p_action, p_dest, p_epoch, p_payload_hash);
  return 'COMMITTED';
end $$;

-- Ownership transfer: successor bumps the epoch at the receiver; old owner is fenced.
create function effect.transfer_owner(p_dest text, p_new_owner text) returns bigint
language sql as $$
  update effect.fences set owner_epoch = owner_epoch + 1, owner_id = p_new_owner
  where destination = p_dest returning owner_epoch;
$$;
