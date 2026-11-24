-- migration 20261124075813 s4_0011_epoch_lock_for_remote_fences (ledger: mzglmdydfcoljrwleooq)
-- Remote fences linearize against revocation without any power over the epoch: they share-lock this row; advancing the
-- epoch must first take it exclusively, so a revocation waits for every in-flight effect, local or remote.
create table ledger.epoch_lock (id int primary key check (id = 1));
insert into ledger.epoch_lock values (1);
create or replace function ledger.epoch_lock_immutable() returns trigger language plpgsql as $$
begin raise exception 'EPOCH_LOCK_ROW_IMMUTABLE'; end $$;
create trigger epoch_lock_immutable before insert or update or delete on ledger.epoch_lock for each row execute function ledger.epoch_lock_immutable();
create or replace function ledger.epoch_advance_waits() returns trigger language plpgsql as $$
begin perform 1 from ledger.epoch_lock where id = 1 for update; return new; end $$;
create trigger epoch_advance_waits before update on ledger.state for each row execute function ledger.epoch_advance_waits();
alter table ledger.epoch_lock enable row level security;
revoke all on ledger.epoch_lock from public, anon, authenticated;
grant select, update on ledger.epoch_lock to fence_customer_sim;          -- update privilege only to take FOR SHARE; the row refuses edits
create policy epoch_lock_fence on ledger.epoch_lock for all to fence_customer_sim using (true) with check (true);
