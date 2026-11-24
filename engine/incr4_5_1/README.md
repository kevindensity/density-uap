# UAP-INC-R4 results, AB1 monitor, P1 feeder (2026-11-21)

## 4. AB1 ordering-law audit (plan frozen at vault seq 17 before running)
14 laws, exhaustive over the execution history: 0 violations. Authority released before every dispatch; release valid at send
(min margin 57.1 s). Observation, verification, finality and receipts commit in one transaction (gap 0 s); AB1 labels these
READBACK / READBACK_VERIFIED with no independence certificate - consistent, not overclaimed.

## 5. AB1 continuous monitor
AB1: schema uap_probe, function check_rules() (3 monitor rules, 14 laws, RLS invariant, monitor liveness, DRIFT watch);
role uap_verifier with execute only (direct reads of execution, authority_ops, auth and CREATE TABLE refused).
Density UAP: uap.monitored_systems registry, generic uap.recheck(system); jobs uap-recheck-diw-daily 06:00 and
uap-recheck-ab1-daily 06:10 UTC. First runs: AB1 19/19 holding, DIW 17/17 holding, 0 alerts.
Alert-capable: DIW claim<->lineage, DIW gap<->action, AB1 RLS. Liveness and ordering laws are observed (drift notices) until decided.
Credential note: the AB1 verifier password passed through the build conversation once; rotate as for DIW.

## 1. P1 feeder to AB1 P0 intake
Target: projection.fg_candidate_intake_v01, contract density-uac-candidate-evidence/v1 (non-authorizing candidates).
Density UAP: uap.p0_candidate_bundles, uap.prepare_fg_bundle(system), uap.validate_fg_bundle (mirrors every intake check
plus an honesty check). Two chained bundles prepared (DIW, AB1; 25 findings each; evidence_root = custody Merkle root).
Both BLOCKED_CONTRACT_MISMATCH: the v1 intake requires persistence_class VOLATILE_MEMORY_ONLY, which is false for a
durable custody-rooted source. A falsified declaration would pass the intake and fail only the honesty check.
Not submitted: submission also requires acting as an authenticated AB1 tenant member. See PROPOSED_ab1_intake_v2_NOT_APPLIED.sql.
