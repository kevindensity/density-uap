-- migration 20261123033334 s1_0005_ledger_grants_for_kernel_and_gateway (root: rtkslhpxdcjoeqhucebp)
-- These grants were first issued in the same statement batch as a self-aborting cross-database test,
-- which rolled them back. Applied here on their own.
grant usage on schema p0_ledger to p0d, gatewayd;
grant select on all tables in schema p0_ledger to p0d, gatewayd;
grant insert on p0_ledger.consumed, p0_ledger.revocations to p0d;
grant update on p0_ledger.state, p0_ledger.issuers, p0_ledger.id_sequence to p0d;
grant insert on p0_ledger.id_sequence to p0d;
grant insert on p0_ledger.sent, p0_ledger.outcomes, p0_ledger.consumed to gatewayd;
