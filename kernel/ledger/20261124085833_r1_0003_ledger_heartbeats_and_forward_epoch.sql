-- migration 20261124085833 r1_0003_ledger_heartbeats_and_forward_epoch (ledger: mzglmdydfcoljrwleooq)
create table ledger.heartbeats (seq bigserial primary key, nonce text not null unique, written_at timestamptz not null default clock_timestamp());
create or replace function ledger.heartbeats_append_only() returns trigger language plpgsql as $$ begin raise exception 'HEARTBEATS_APPEND_ONLY'; end $$;
create trigger heartbeats_append_only before update or delete on ledger.heartbeats for each row execute function ledger.heartbeats_append_only();
alter table ledger.heartbeats enable row level security;
revoke all on ledger.heartbeats from public, anon, authenticated;
grant select, insert on ledger.heartbeats to ledger_fdw;
grant usage on sequence ledger.heartbeats_seq_seq to ledger_fdw;
create policy heartbeats_root on ledger.heartbeats for all to ledger_fdw using (true) with check (true);

-- the epoch only moves forward (a restore can still roll it back; the root's continuity witness catches that)
create or replace function ledger.epoch_forward_only() returns trigger language plpgsql as $$
begin
  if new.authority_epoch < old.authority_epoch then raise exception 'EPOCH_FORWARD_ONLY'; end if;
  new.updated_at := now(); return new;
end $$;
create trigger epoch_forward_only before update on ledger.state for each row execute function ledger.epoch_forward_only();
grant update (authority_epoch, updated_at) on ledger.state to ledger_fdw;
do $$ begin
  if exists (select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'ledger' and c.relname = 'state' and c.relrowsecurity) then
    execute 'create policy state_root_advance on ledger.state for update to ledger_fdw using (true) with check (true)'; end if;
end $$;
