-- migration 20261124085925 r1_0005_epoch_lock_trigger_definer (ledger: mzglmdydfcoljrwleooq)
create or replace function ledger.epoch_advance_waits() returns trigger language plpgsql security definer set search_path = ledger, pg_catalog as $$
begin perform 1 from ledger.epoch_lock where id = 1 for update; return new; end $$;
