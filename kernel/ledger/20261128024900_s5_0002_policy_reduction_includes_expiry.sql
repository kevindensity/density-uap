-- migration s5_0002_policy_reduction_includes_expiry (ledger: mzglmdydfcoljrwleooq)
create or replace function ledger.policy_reduction(p_policy_stream uuid) returns text language sql stable security definer set search_path = ledger, pg_catalog as $$
  select r.event_kind || ' at ' || r.admitted_at::text from ledger.authority_reductions r
   where r.stream_id = p_policy_stream and r.event_kind in ('standing_policy:ACTIVE->REVOKED', 'standing_policy:ACTIVE->EXHAUSTED', 'standing_policy:ACTIVE->EXPIRED')
   order by r.root_seq desc limit 1 $$;
revoke all on function ledger.policy_reduction(uuid) from public, anon, authenticated;
grant execute on function ledger.policy_reduction(uuid) to gatewayd_ledger;
