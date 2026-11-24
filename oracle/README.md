# density-core-b0

The B0 deliverable of the UAC → UAP → Node build specification: the minimum constitutional
core made real.

| Part | What it is | Check |
| --- | --- | --- |
| `crates/dc-types` | Core contracts: canonical JSON (RFC 8785 rules) and domain-prefixed SHA-256, ids, `Ref<K>`, envelope, epochs, validity, standing, `Candidate`/`NoAuthority`, the outcome taxonomy | `cargo test -p dc-types` (11 tests) |
| `crates/reference-kernel` | K38 oracle: P0 binding, grants, effect chain, settlement, durable log and restore, table-driven state machines | `cargo test -p reference-kernel` (3 + 14 tests, 1 compile-fail doctest) |
| `tla/Kernel.tla` | TLA+ model of binding, grant, revocation, backup/restore and the effect chain | `java -cp tla2tools.jar tlc2.TLC -config Kernel.cfg -deadlock Kernel.tla` (must pass); `KernelDefect.cfg` must fail |
| `traceability/matrix.yaml` | Law → tier, phase, machines, contracts, tests | `python3 traceability/generate.py` fails if a referenced test is missing |

Toolchain: Rust 1.75 or later (dependencies pinned in the workspace manifest), Java 17 or later
for TLC (tla2tools.jar v1.8.0), Python 3 with PyYAML.

## Findings made while building it

1. **Identifier sequences must be durable.** With the id counter inside restorable state, a
   restore could reissue a nonce the durable log already records as revoked or consumed.
   The counter now lives in the durable log (test `k35_restore_never_reissues_an_identifier`).
2. **SENT records must survive restore.** TLC found a double emission: backup after release,
   emit, restore, emit again. SENT records keyed by grant now live in the durable log, and a
   restored effect with a SENT record goes to reconciliation (TLA `EmitAtMostOnce`; test
   `k35_restore_between_release_and_emit_never_double_emits`).
3. **The emitter's identity must be durable.** After that restore the in-memory emitter was
   gone, so the independence check passed vacuously and the emitter could confirm its own
   effect. Independence is now judged against the durable SENT record, and an unknown
   emitter refuses finality.
4. **Missing records are typed unknowns, not crashes** (randomized traces after restore).
