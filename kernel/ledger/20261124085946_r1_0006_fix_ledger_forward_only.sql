-- migration 20261124085946 r1_0006_fix_ledger_forward_only (ledger: mzglmdydfcoljrwleooq)
-- Each check is nested under its own table: PL/pgSQL does not short-circuit, so a condition naming another table's
-- fields made every update to state, issuers and id_sequence fail (epoch advance and issuer revocation were impossible).
create or replace function ledger.forward_only() returns trigger language plpgsql set search_path to 'pg_catalog' as $function$
begin
  if tg_op = 'DELETE' then raise exception 'LEDGER_FORWARD_ONLY: delete on %.% is not permitted', tg_table_schema, tg_table_name; end if;
  if tg_table_name = 'state' then
    if new.authority_epoch < old.authority_epoch then raise exception 'LEDGER_FORWARD_ONLY: authority epoch cannot move backwards'; end if;
  elsif tg_table_name = 'issuers' then
    if old.status = 'revoked' and new.status <> 'revoked' then raise exception 'LEDGER_FORWARD_ONLY: a revoked issuer cannot be reinstated; enrol a new issuer'; end if;
  elsif tg_table_name = 'id_sequence' then
    if new.last_value < old.last_value then raise exception 'LEDGER_FORWARD_ONLY: identifier sequence cannot move backwards'; end if;
  end if;
  return new;
end $function$;
