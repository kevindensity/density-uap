-- migration 20261122234151 ledger_0001_durable_log (ledger: mzglmdydfcoljrwleooq)
create schema ledger;

create table ledger.issuers (
  issuer_id text primary key, pubkey bytea not null check (octet_length(pubkey) = 32), root_gen int not null,
  status text not null default 'active' check (status in ('active','revoked')), administrator text not null,
  enrolled_at timestamptz not null default now());
create table ledger.recovery (id int primary key default 1 check (id = 1), pubkey bytea not null check (octet_length(pubkey) = 32), administrator text not null);
create table ledger.state (id int primary key default 1 check (id = 1), authority_epoch bigint not null default 1, updated_at timestamptz not null default now());
insert into ledger.state default values;
create table ledger.consumed (grant_id uuid primary key, consumed_at timestamptz not null default now(), consumer text not null);
create table ledger.revocations (id bigint generated always as identity primary key, target_issuer text not null references ledger.issuers, new_epoch bigint not null,
  signer text not null, signer_sig text not null, recovery_sig text not null, at timestamptz not null default now());
create table ledger.sent (grant_id uuid primary key, plan_digest text not null, emitter text not null, target text not null, request jsonb not null, sent_at timestamptz not null default now());
create table ledger.outcomes (grant_id uuid primary key references ledger.sent, outcome text not null check (outcome in ('DONE','REFUSED','RECOVERY_REQUIRED')),
  detail jsonb, decided_by text not null, at timestamptz not null default now());
create table ledger.id_sequence (name text primary key, last_value bigint not null);

-- forward-only guarantees
create or replace function ledger.append_only() returns trigger language plpgsql set search_path = pg_catalog as $$
begin raise exception 'LEDGER_APPEND_ONLY: % on %.% is not permitted', tg_op, tg_table_schema, tg_table_name; end $$;
create trigger consumed_append_only before update or delete on ledger.consumed for each row execute function ledger.append_only();
create trigger revocations_append_only before update or delete on ledger.revocations for each row execute function ledger.append_only();
create trigger sent_append_only before update or delete on ledger.sent for each row execute function ledger.append_only();
create trigger outcomes_append_only before update or delete on ledger.outcomes for each row execute function ledger.append_only();

create or replace function ledger.forward_only() returns trigger language plpgsql set search_path = pg_catalog as $$
begin
  if tg_op = 'DELETE' then raise exception 'LEDGER_FORWARD_ONLY: delete on %.% is not permitted', tg_table_schema, tg_table_name; end if;
  if tg_table_name = 'state' and new.authority_epoch < old.authority_epoch then raise exception 'LEDGER_FORWARD_ONLY: authority epoch cannot move backwards'; end if;
  if tg_table_name = 'issuers' and old.status = 'revoked' and new.status <> 'revoked' then raise exception 'LEDGER_FORWARD_ONLY: a revoked issuer cannot be reinstated; enrol a new issuer'; end if;
  if tg_table_name = 'id_sequence' and new.last_value < old.last_value then raise exception 'LEDGER_FORWARD_ONLY: identifier sequence cannot move backwards'; end if;
  return new;
end $$;
create trigger state_forward_only before update or delete on ledger.state for each row execute function ledger.forward_only();
create trigger issuers_forward_only before update or delete on ledger.issuers for each row execute function ledger.forward_only();
create trigger id_sequence_forward_only before update or delete on ledger.id_sequence for each row execute function ledger.forward_only();

-- access: nothing for API roles; one login role for the root project's foreign data wrapper
revoke all on schema ledger from anon, authenticated, public;
alter default privileges in schema ledger revoke all on tables from anon, authenticated;
do $$ declare t text; begin
  foreach t in array array['issuers','recovery','state','consumed','revocations','sent','outcomes','id_sequence'] loop
    execute format('alter table ledger.%I enable row level security', t);
    execute format('revoke all on ledger.%I from anon, authenticated', t);
  end loop; end $$;

do $$ declare pw text := encode(extensions.gen_random_bytes(24), 'hex'); begin
  if not exists (select 1 from pg_roles where rolname = 'ledger_fdw') then
    execute format('create role ledger_fdw login password %L', pw);
    perform vault.create_secret(pw, 'ledger_fdw_password', 'login password for the root project foreign data wrapper; rotate after wiring');
  end if; end $$;
grant usage on schema ledger to ledger_fdw;
grant select on all tables in schema ledger to ledger_fdw;
grant insert on ledger.consumed, ledger.revocations, ledger.sent, ledger.outcomes to ledger_fdw;
grant update (authority_epoch, updated_at) on ledger.state to ledger_fdw;
grant update (status) on ledger.issuers to ledger_fdw;
grant insert, update on ledger.id_sequence to ledger_fdw;
do $$ declare t text; begin
  foreach t in array array['issuers','recovery','state','consumed','revocations','sent','outcomes','id_sequence'] loop
    execute format('create policy %I on ledger.%I for all to ledger_fdw using (true) with check (true)', t || '_fdw', t);
  end loop; end $$;
