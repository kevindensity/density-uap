-- migration s6_0002_gateway_reads_issuers_from_ledger (ledger: mzglmdydfcoljrwleooq). Applied 28 Nov 2026 (incident D13).
create or replace function ledger.active_issuers() returns table(issuer_id text, pubkey_hex text, root_gen int)
  language sql stable security definer set search_path to pg_catalog as $f$
  select i.issuer_id, encode(i.pubkey, 'hex'), i.root_gen from ledger.issuers i where i.status = 'active' $f$;
revoke all on function ledger.active_issuers() from public, anon, authenticated;
grant execute on function ledger.active_issuers() to gatewayd_ledger;
