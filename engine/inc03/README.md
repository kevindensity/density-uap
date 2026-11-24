# UAP increment 03 - threshold-aware discovery and DCA-UAP-03 finality

## Custody (the order that matters)
1. Source frozen into the custody vault as ORIGINAL_FREEZE (UAP-INC-03, vault seq 5, Merkle root 1baf3529...) and its root
   published to git and to the append-only `custody.published_roots` table **before** the run.
2. The harness refuses to execute unless every source file it uses matches that freeze byte for byte (CUSTODY_MISMATCH).
3. Outputs frozen afterwards as RECEIVED_ARTIFACT (UAP-INC-03-RESULTS, vault seq 6) and published.

Run: databases `uapinc3` (migrations 0001-0004) and `legacy_erp3` (fixtures/legacy_erp.sql), then
`VAULT_RUN_ID=<run_id> python3 run_inc03.py`. Results land in ../inc03_results/.

## Result - one recorded run: 60/60 gates
| Scenario | Gates | Recall | False promotions | Probe calls |
| --- | --- | --- | --- | --- |
| DCA-UAP-01 API | 8/8 | 1.000 (11/11) | 0 | 869 |
| DCA-UAP-01 DB | 8/8 | 1.000 (11/11) | 0 | 428 |
| DCA-UAP-01 CLI | 8/8 | 1.000 (6/6) | 0 | 279 |
| DCA-UAP-02 drift v4.2 -> v4.3 | 6/6 | 1.000 (14/14) | 0 | - |
| DCA-UAP-03 finality, API | 10/10 | - | - | - |
| DCA-UAP-03 finality, DB | 10/10 | - | - | - |
| DCA-UAP-03 finality, CLI | 10/10 | - | - | - |

Threshold bisection closed all five INC-02 misses (status<-discount_code, needs_approval<-sku, needs_approval<-promo_code,
status<-channel and the related v4.3 dependency). Finality drills per carrier: clean write once; ACK lost after commit ->
lookup finds it, no resend; crash before commit -> lookup finds nothing, resent once; lookup unavailable -> UNCERTAIN_WITHHOLD,
still exactly one effect; naive retry control -> two effects; stale owner and payload conflict refused; an independent
verifier re-read every drill outcome through the lookup; each effect port reached ACTIONABLE only after a grant and a
qualified finality adapter.

## Claim boundary
Local single host, synthetic deterministic fixtures, one recorded run. Database faults are injected at the client
(commit then drop the reply), CLI faults by process exit, API faults by the server closing the connection. Lookup-based
recovery assumes a lookup that reflects committed writes when it answers; a lagging replica would need a freshness bound.
