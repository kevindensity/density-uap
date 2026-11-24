-- migration 20261124073722 s4_0003_observer_readback (root: rtkslhpxdcjoeqhucebp)
create schema if not exists p0_target;
revoke all on schema p0_target from public, anon, authenticated;
import foreign schema sandbox limit to (flags) from server uap_ledger into p0_target;
import foreign schema fence limit to (receipts) from server uap_ledger into p0_target;
do $$ begin
  if not exists (select 1 from information_schema.foreign_tables where foreign_table_schema = 'p0_ledger' and foreign_table_name = 'sent') then
    execute 'import foreign schema ledger limit to (sent) from server uap_ledger into p0_ledger'; end if;
  if not exists (select 1 from information_schema.foreign_tables where foreign_table_schema = 'p0_ledger' and foreign_table_name = 'outcomes') then
    execute 'import foreign schema ledger limit to (outcomes) from server uap_ledger into p0_ledger'; end if;
  if not exists (select 1 from information_schema.foreign_tables where foreign_table_schema = 'p0_ledger' and foreign_table_name = 'consumed') then
    execute 'import foreign schema ledger limit to (consumed) from server uap_ledger into p0_ledger'; end if;
end $$;

-- Finality by an observer that is not the emitter: only an observed effect is DID. A receipt whose poststate is the
-- intended outcome and a grant consumed exactly once -> DID. No receipt and an unconsumed grant -> NOT_APPLIED (the effect
-- is proven absent; nothing is re-sent here). Anything else -> UNKNOWN, left for investigation, never guessed.
create or replace function p0.effect_readback(p_grant uuid) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare s record; rc record; consumed boolean; cur text; intended text; outcome text; prior text; detail jsonb;
begin
  select * into s from p0_ledger.sent where grant_id = p_grant;
  if not found then return jsonb_build_object('outcome', 'NO_SENT_RECORD'); end if;
  select outcome into prior from p0_ledger.outcomes where grant_id = p_grant and decided_by like 'root-readback%' order by at desc limit 1;
  if prior is not null then return jsonb_build_object('outcome', prior, 'already_decided', true); end if;
  select * into rc from p0_target.receipts where grant_id = p_grant;
  consumed := exists (select 1 from p0_ledger.consumed where grant_id = p_grant);
  intended := s.request->>'intended_poststate';
  select encode(sha256(convert_to(row_to_json(f)::text, 'UTF8')), 'hex') into cur from p0_target.flags f where f.key = s.request->>'key';
  if rc.grant_id is not null and consumed and rc.poststate = intended then outcome := 'DID';
  elsif rc.grant_id is null and not consumed then outcome := 'NOT_APPLIED';
  else outcome := 'UNKNOWN'; end if;
  detail := jsonb_build_object('receipt', rc.grant_id is not null, 'consumed', consumed, 'intended_poststate', intended,
    'receipt_poststate', rc.poststate, 'current_row_digest', cur, 'current_matches_intended', cur = intended, 'emitter', s.emitter);
  insert into p0_ledger.outcomes (grant_id, outcome, detail, decided_by, at) values (p_grant, outcome, detail, 'root-readback (ledger_fdw, not the emitter)', now());
  return jsonb_build_object('outcome', outcome) || detail;
end $function$;
revoke all on function p0.effect_readback(uuid) from public, anon, authenticated;
grant execute on function p0.effect_readback(uuid) to p0d;
