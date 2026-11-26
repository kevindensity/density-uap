-- migration 20261126012719 resettle_0005_one_unconsumed_receipt_per_event (root: rtkslhpxdcjoeqhucebp)
-- A claim re-proven on the same evidence produces the same event identity as before. The rule is one UNCONSUMED
-- receipt per event identity: a consumed receipt (admitted_event set) never blocks a fresh one.
alter table verify.kernel_receipts drop constraint kernel_receipts_one_per_event;
create unique index kernel_receipts_one_unconsumed_per_event on verify.kernel_receipts (stream_id, identity_digest) where admitted_event is null;
