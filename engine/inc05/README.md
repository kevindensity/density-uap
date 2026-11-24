# UAP increment 05 - semantics layer

Custody: source frozen as ORIGINAL_FREEZE (UAP-INC-05, vault seq 9, root c99925bc...) and published before the run. The harness
also refuses to run unless its upstream input (INC-04 PREDICTIONS.json) matches the published UAP-INC-04-RESULTS freeze byte for
byte, so every semantic claim traces to certified INC-04 projections. Two unrecorded development runs preceded the freeze.

## Components (uapcore/semantics.py, supabase/migrations/0005_uap_semantics.sql)
- CADR-001: access channels stand only through finite ancestry to unrevoked roots (least fixed point, AND over parents).
  Unrooted cycles have no standing; revoking a root removes everything derived from it.
- Evidence-gated bridges: a native field reaches a canonical Density field only with anchors from a channel that has access
  standing, a native channel that has access standing, exactly one surviving transform, and held-out anchors the transform predicts.
  Zero survivors = CONTRADICTORY; several = DOMAIN_LOCAL_ONLY.
- ICC-001: for unresolved fields, the claims every surviving interpretation agrees on (ordering, zero set, ratios, partition rules)
  and the cheapest evidence that would separate the rest.
- PIE-001: cross-system operations licensed per canonical field, with required distinctions from MCD.
- MCD-001: smallest extra feature under which a consequence becomes a function of the canonical signature, checked on held-out records.

## Result - one recorded run: 13/13 gates
Bridges: OMS total and ERP line_total -> order.amount_usd (equivalent); OMS status -> requires_approval (map HOLD->true);
ERP needs_approval -> requires_approval (equivalent); CLI rate -> shipment.cost_cents (x100); OMS tax -> CONTRADICTORY (the ledger
uses another tax basis); ERP shipping and CLI eta_days -> DOMAIN_LOCAL_ONLY with invariant cores. Canonical writes accepted only
through the five proven bridges. MCD: same canonical amount, different approval outcome in 14 conflicting cases; minimal distinction
source_system, confirmed on held-out records; without it, no available feature separates them (the random weekday feature was not
accepted). PIE: amounts can be summed and compared across OMS and ERP; approval policy cannot transfer without source_system;
shipment costs cannot be compared across ERP and CLI. CADR: documentation-channel evidence and a revoked ERP channel both refused.

## Claim boundary
Local, synthetic, one recorded run. Transforms come from a fixed candidate family (scales and boolean maps); real systems will need
richer families (offsets, currency conversion with dated rates, enumerations).
