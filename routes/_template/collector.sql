-- Collector skeleton for a route. Rules (checked by the route gates):
--   * read the scope; refuse unless it is DECLARED and lists this route
--   * never read the Vault: lease credentials with broker.issue_lease(...) and broker.redeem(...)
--   * record body.sources: one status per source ('ok', 'failed: ...', 'partial: ...')
--   * refuse what cannot be certified complete (truncated, paginated beyond budget) instead of storing it as complete
--   * stay inside the route's budget
--   * admit the capture through the kernel (capture machine), sealed with its content digest
create or replace function uac.acquire_example(p_scope uuid) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare sc uac.scopes%rowtype; body jsonb := '{}'::jsonb; sources jsonb := '{}'::jsonb;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if sc.status is distinct from 'DECLARED' or not ('family.name' = any (sc.routes)) then
    return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED_FOR_ROUTE'); end if;
  -- observe here; set sources->'<source>' for each channel used
  body := body || jsonb_build_object('sources', sources);
  return uac.admit_capture(p_scope, 'family.name', body);   -- seals and admits through the kernel
end $f$;
