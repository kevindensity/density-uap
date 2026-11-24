# Owner decisions applied 2026-11-21 (second set)

1. AB1 intake v2 (P0 contract change, approved).
   evidence.fg_candidate_intake_receipts source_contract check widened to v1 | v2 (existing rows unaffected).
   New projection.fg_candidate_intake_v02: identical guarantees to v1 (auth, tenant membership, explicit consent, candidate-only,
   NOT_EVALUATED standing and currentness, authority NONE, not execution-eligible, replay-mutation refusal, immutable receipts),
   but requires persistence_class DURABLE_CUSTODY_ROOTED plus custody {ledger_ref, vault_seq}. v1 unchanged.
   Grants mirror v1 (authenticated only). Verified: unauthenticated call refused (FG_INTAKE_02_AUTH_REQUIRED); 0 receipts.
   Density UAP feeder updated to v2: two bundles PREPARED with 0 blockers (DIW, AB1; 25 findings each), chained only to
   submitted bundles. Not submitted: submitting identity and tenant still to be chosen.
3. Verifier credentials rotated in-database (uap.rotate_verifier): new passwords generated in Density UAP, set by each role over
   its own TLS connection, verified against the probe, stored in the vault; never displayed. Old passwords refused on both systems.
4. AB1 ordering laws L01-L14 and monitor liveness promoted to DESIGN_INVARIANT (alert-capable). AB1: 16 of 19 rules alert-capable.
After: DIW 17/17 holding, AB1 19/19 holding, 0 alerts.
