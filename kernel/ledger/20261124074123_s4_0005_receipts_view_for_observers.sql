-- migration 20261124074123 s4_0005_receipts_view_for_observers (ledger: mzglmdydfcoljrwleooq)
create view fence.receipts_v with (security_invoker = false) as
  select receipt_id, grant_id, tbl::text as tbl, pk, op, prestate, poststate, history_head, authority_epoch, committed_at from fence.receipts;
revoke all on fence.receipts_v from public, anon, authenticated;
grant select on fence.receipts_v to ledger_fdw;
