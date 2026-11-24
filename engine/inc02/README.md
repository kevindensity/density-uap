# UAP increment 02 - canonical schema, three carriers, boundary probes, drift

Run: create databases `uapinc` (apply migrations 0001-0003) and `legacy_erp` (fixtures/legacy_erp.sql), then `python3 run_inc02.py`.

## Result - one recorded run (results/SCORE.json, predictions hashed before the truth was opened)
| Leg | Gates | Recall | False promotions | Probe calls |
| --- | --- | --- | --- | --- |
| API (HTTP, legacy order service) | 8/8 | 0.909 (10/11) | 0 | 552 |
| DB (legacy ERP: catalog, history, rolled-back probes) | 8/8 | 0.818 (9/11) | 0 | 252 |
| CLI (1998 freight rating tool) | 8/8 | 1.000 (6/6) | 0 | 246 |
| DCA-UAP-02 drift (v4.2 -> v4.3) and credential rotation | 6/6 | 0.857 (12/14) | 0 | - |

Missed dependencies all need a probe that sits *at* a threshold and then switches a categorical input
(status<-discount_code, needs_approval<-sku/promo_code, status<-channel). Geometric boundary search overshoots the threshold,
so the categorical switch does not cross back. Next increment: bisect to the boundary before categorical probing.

## Claim boundary
Local single host, synthetic deterministic fixtures, one recorded run per scenario. The in-run FREEZE.json hashed the source
before execution; the custody-vault entry for this increment was written after the run and is recorded as RECEIVED_ARTIFACT.
