-- migration 20261122235514 s1_0001_keys_and_transitions (root: rtkslhpxdcjoeqhucebp)
create extension if not exists pgsodium;

create table p0.keys (
  key_id text primary key,
  role text not null check (role in ('KERNEL','OWNER_POLICY','OWNER','RECOVERY','VERIFIER','GATEWAY','UAC','UAP','PORT')),
  process text not null,
  pubkey bytea not null check (octet_length(pubkey) = 32),
  status text not null default 'active' check (status in ('active','revoked')),
  administrator text not null,
  enrolled_at timestamptz not null default now());

create or replace function p0.keys_forward_only() returns trigger language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' then raise exception 'KEY_RECORD_PERMANENT: keys are revoked, never deleted'; end if;
  if new.pubkey <> old.pubkey or new.role <> old.role or new.key_id <> old.key_id then raise exception 'KEY_RECORD_PERMANENT: only status may change'; end if;
  if old.status = 'revoked' and new.status <> 'revoked' then raise exception 'KEY_RECORD_PERMANENT: a revoked key cannot be reinstated'; end if;
  return new;
end $$;
create trigger keys_forward_only before update or delete on p0.keys for each row execute function p0.keys_forward_only();

create table p0.transitions (
  machine text not null,
  from_state text not null,
  to_state text not null,
  actor_role text not null,
  required_receipt_roles text[] not null default '{}',
  guard text not null,
  enforced boolean not null default true,
  primary key (machine, from_state, to_state));

insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('kernel','(none)','ACTIVE','p0d','{}','kernel genesis under the recorded root amendment',true),
 ('node','(none)','PROPOSED','p0d','{}','genesis candidate recorded with its systems and settled evidence',true),
 ('node','PROPOSED','ADMITTED','p0d','{VERIFIER}','every system covered by current settled evidence; one successor per predecessor',true),
 ('node','PROPOSED','REFUSED','p0d','{}','admission conditions not met',true),
 ('node','ADMITTED','SUPERSEDED','p0d','{VERIFIER}','successor admitted under an identity transition certificate',true),
 ('node','ADMITTED','RETIRED','p0d','{OWNER}','owner retires the Node',true),
 ('secure_boot','(none)','PROPOSED','p0d','{}','artifact digest and measurement recorded',true),
 ('secure_boot','PROPOSED','ADMITTED','p0d','{OWNER}','owner admits the build under predecessor authority',true),
 ('secure_boot','ADMITTED','RETIRED','p0d','{OWNER}','build retired; keys rotated',true),
 ('owner_approval','(none)','RECORDED','p0d','{OWNER}','owner signature over the exact plan digest',true),
 ('standing_policy','(none)','ACTIVE','p0d','{OWNER}','owner-signed bounded policy',true),
 ('standing_policy','ACTIVE','EXHAUSTED','p0d','{}','uses reached the bound',true),
 ('standing_policy','ACTIVE','REVOKED','p0d','{OWNER}','owner revokes',true),
 ('port_ladder','*','*','uapd','{VERIFIER}','existing uap.guard_ladder trigger remains authoritative',false),
 ('settlement','*','*','verifierd','{VERIFIER}','existing sem.guard_settlement trigger remains authoritative',false),
 ('projection','*','*','uapd','{VERIFIER}','existing uap.guard_projection trigger remains authoritative',false),
 ('semantic_bridge','*','*','uapd','{VERIFIER}','existing uap.guard_bridge trigger remains authoritative',false);

alter table p0.keys enable row level security;
alter table p0.transitions enable row level security;
revoke all on p0.keys, p0.transitions from anon, authenticated;
grant select on p0.keys, p0.transitions to uacd, uapd, verifierd, p0d, gatewayd, portd;
grant insert, update on p0.keys to p0d;
create policy p0_keys_read on p0.keys for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy p0_keys_write on p0.keys for all to p0d using (true) with check (true);
create policy p0_transitions_read on p0.transitions for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
insert into p0.table_owners (tbl, owner_role, note) values
 ('p0.keys','p0d','public keys only; status forward-only'),
 ('p0.transitions','p0d','changed only by migration');
