# UAP increment 04 - grammar beyond single-field dependencies

Custody: source frozen as ORIGINAL_FREEZE (UAP-INC-04, vault seq 7, root 8835af84...) and published before the recorded run;
the harness refuses to run unless every source file matches. Two unrecorded development runs on a scratch vault preceded the
freeze; the second fixed a real flaw (see below). Results frozen afterwards as RECEIVED_ARTIFACT.

## What it adds (uapcore/grammar.py, uapcore/grammar_verify.py)
- Joint dependencies: o depends on (i, j) jointly when i's effect on o changes with j (mixed difference above a 0.025
  rounding floor, or a categorical change pattern that differs). Only pairs of already-settled single dependencies are tested.
- MAGNITUDE_RELATION: a two-class output that a single cut on another numeric output separates, with the cut bracketed by
  the closest observations on each side. Inside the bracket the relation abstains (UNRESOLVED) rather than guessing.
- Partitions by counterexample-guided synthesis: L0 (constant, single-input table) -> L1 (threshold on a certified
  magnitude relation, two-input table) -> L2 (table over all dependencies), escalating only when refuted.
- Independent verifier with its own seed, own threshold-localized probes and key: re-finds interaction witnesses and searches
  for counterexamples to every relation and partition before anything settles.

## Result - one recorded run: 18/18 gates, 0 false claims
| Leg | Joint dependencies found | Magnitude relation | Partition |
| --- | --- | --- | --- |
| API | 10 of 12 (2 missed) | status flips on total, cut in (999.96, 1000.78] - true cut 1000 | status: L1 threshold, exact on 480 scorer points |
| DB | 9 of 9 | needs_approval flips on line_total, cut in (1995.0, 2002.5] - true cut 2000 | needs_approval: L1 threshold, exact on 240 points |
| CLI | 3 of 3 | none (correct) | eta_days: L1 two-input table (zone, express), exact on 240 points |

The additive pairs (shipping vs warehouse, eta_days zone x express) were never claimed as joint. The two missed joint
dependencies (status with discount_code x qty and x unit_price) need both inputs varied at the threshold at once.

## Development-run finding
In the first development run the threshold program assigned a class inside its own bracket. The scorer caught it on the API
(99.58%) and the verifier refuted the database relation for the same reason. The fix makes the program abstain inside the
bracket, which is the epistemic type rule (no strengthening without evidence).
