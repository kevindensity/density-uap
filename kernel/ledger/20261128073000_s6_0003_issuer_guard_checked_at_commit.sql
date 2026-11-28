-- s6_0003 (ledger). Applied 28 Nov 2026. Regression fix: s6_0001's immediate guard blocked the gate harnesses that enrol
-- temporary test issuers inside transactions they always roll back. The guard now runs at COMMIT (deferred constraint
-- trigger): an unsigned key change can exist only in a transaction that is rolled back and can never be committed.
-- Proven: a committed unsigned change is refused (LEDGER_UNSIGNED_KEY_CHANGE); a rolled-back test issuer leaves no trace.
drop trigger issuers_key_guard on ledger.issuers;
create or replace function ledger.issuer_key_guard() returns trigger language plpgsql set search_path to pg_catalog as $f$
begin
  if (tg_op = 'INSERT' or new.pubkey is distinct from old.pubkey or new.root_gen is distinct from old.root_gen or new.issuer_id is distinct from old.issuer_id)
     and not exists (select 1 from ledger.issuer_rotations r where r.signed and r.txid = txid_current()
                     and r.issuer_id = new.issuer_id and r.new_pubkey = new.pubkey and r.new_root_gen = new.root_gen)
     and exists (select 1 from ledger.issuers i where i.issuer_id = new.issuer_id and i.pubkey = new.pubkey and i.root_gen = new.root_gen) then
    raise exception 'LEDGER_UNSIGNED_KEY_CHANGE: issuer % cannot be committed with a key or generation that no recovery-root signature authorized', new.issuer_id;
  end if;
  return null;
end $f$;
create constraint trigger issuers_key_guard after insert or update on ledger.issuers deferrable initially deferred
  for each row execute function ledger.issuer_key_guard();
-- recovery root genesis (separate statement, 28 Nov 2026): ledger.recovery id 1, public key 61e37148..., proof of possession verified
