# Provenance

Each admitted (and candidate) build: the binary, its source, the commit that source is checked at, and where it was verified. Hashes are SHA-256. Re-verified on
the Sprites on 24 Nov 2026 when this repository was created. A future gate will check that every admitted build's
source hash matches a file in this repository at a recorded commit.

| Component | Status (kernel) | Binary | Source file | Source SHA-256 | Source commit | Host |
| --- | --- | --- | --- | --- | --- | --- |
| `p0d` | ADMITTED | `920b512c78706e1c2d48479ab3d5fa464151216a409e72a81ee7bd2981761164` | `services/crates/p0d/src/main.rs` | `7e07d3471b778db6aaf482f4b5ace932b0fa213cfe4dde376cf90eab5438aece` | `7db2f27f5f8b4d084f97cae62cbb125ab4b71d74` | mcp-density-kernel |
| `owner-issuer` | ADMITTED | `27c699e3d0d4760a0b4f217b87f05a74b8e3076e65299b8d720c2e8fb5763b8f` | `services/crates/owner-issuer/src/main.rs` | `55a9f948120086f6a97689e7660a1fbcb6a06c0f46a6ac2911b69b72b284fb1e` | `7db2f27f5f8b4d084f97cae62cbb125ab4b71d74` | mcp-density-kernel |
| `verifierd` | RETIRED (superseded by `087cdbad…`) | `eff1883bfbbe50f44ae944b3a152a3ef78ab026e5ece4fe7d99b8e65b7a2f7c4` | `services/crates/verifierd/src/main.rs` | `8b6a85b869319453752a61ad12b26f8bf1cdee6edd9c14e08489e210afb4eaea` | `7db2f27f5f8b4d084f97cae62cbb125ab4b71d74` | mcp-density-verifier |
| `verifierd` | RETIRED (superseded by `51024011…`) | `087cdbadba9445897a4fa112b8d07a2bdd2baa8bf465835cfb00e310e5f0026b` | `services/crates/verifierd/src/main.rs` | `7ae8f1b34e1ca5e9c90f39441fc6186c29b2f54d266fa37a6a4612e58ebb55e0` | `de458a8244fd499e14cf747e9d927c9d1c2f36b5` | mcp-density-verifier |
| `verifierd` | ADMITTED (reproducible build of `17e90b6d`, identical on both Sprites; gate run `8a511938…` 141/141; owner-signed; dependency-exact evidence) | `51024011e26663e43f7ede14d6c1b6d691f24af1158929680930dbfb528099a0` | `services/crates/verifierd/src/main.rs` | `c418d61e542a5837d1b8559229cb10b6202a5787803f98d965d7432257ce20ea` | `17e90b6d0def24a08d48c5668dc1bb538e7a181d` | mcp-density-verifier |
| `uacd` | ADMITTED (shadow mode only; reproducible build of `c28c5102`, identical in two build directories; gate run `8fbf98b2…` 148/148; owner-signed) | `45b987a74248dcfafa319161461318ce13f0cd18700a10f20cfbecdfc5a9a110` | `services/crates/uacd/src/main.rs` | `4b17a4101329296cc929d9b24cd1cf4177b043247c0d6991bf0d26b952434379` | `c28c5102faef8df3d75f778f0dfc702c1208dcd9` | mcp-density-kernel |

Retired verifier builds (kept in the kernel's lineage): `08df873d…` (probe witness), `b6a8a12b…` (signed trigger),
`1cfc9287…`, `33814adc…`, `3e71624c…`, `309dc7a6…`.

**Limitation recorded honestly.** Builds are not yet reproducible from this repository alone: the binaries were built
on the Sprites from the same sources, and the source hashes above match the files committed here, but a clean rebuild
producing byte-identical binaries has not been demonstrated.

## Reproducible builds

Recipe: [`scripts/build-reproducible.sh`](scripts/build-reproducible.sh) (rustc 1.99.1, `cargo build --release --locked`,
source paths remapped, `SOURCE_DATE_EPOCH` fixed, one codegen unit, symbols stripped, no incremental state).

Proven on 24 Nov 2026: commit `7db2f27f5f8b4d084f97cae62cbb125ab4b71d74` built twice on mcp-density-kernel in two
different directories gave byte-identical binaries:

| Component | Reproducible build of `7db2f27f` |
| --- | --- |
| `p0d` | `fe7ffcd736472adf0e998ce3990af3339b01e35309bb32490b919ed4e1af9d8f` |
| `owner-issuer` | `28902284fa300f3a48dd9e6ef9252c73a8a56585307087637a7631c048f9bb9b` |
| `verifierd` | `96121b2700b80f46d78934d5406845477441ce8e3cf0715dee41120fb657ea97` |

**What this does and does not establish.**
- The currently admitted binaries (`920b512c…`, `27c699e3…`, `eff1883b…`) were built before this recipe and differ from
  the reproducible builds; their link to the source is by source hash only (checked by the provenance gate).
- Reproduction is proven on one host. The registry and toolchain paths are remapped only where the recipe names
  them, so a host with a different `CARGO_HOME` may differ until the recipe remaps those paths too; a cross-host
  reproduction (verifier Sprite) is the next check.
- From the next admission, a build is admitted from this recipe, so its binary hash can be re-derived from its commit.

## Issuer key rotation, 28 Nov 2026

**Cause.** The launchers started `p0d` and `owner-issuer` as `sudo -u <user> env $(cat secrets) <binary>`. The `sudo`
process stays alive as the service's parent, so both signing seeds sat in a command line readable by every local user
of mcp-density-kernel (including `uacd`, which parses untrusted internet content); `/proc` had no `hidepid`. Holding
both seeds is enough to forge a two-signature grant. 13 of each seed's 32 bytes were also printed in an operator
session while diagnosing it.

**Done.**
- Launchers: each service user reads its own 0600 env file and exports it inside its own shell; no secret on any
  command line (also `uacd`'s database URL in the differential loop). Verified: no process carries a seed or URL.
- `/proc` remounted `hidepid=invisible`; the watchdog re-applies it at start. Verified: `uacd`, `uapd`, `gatewayd`
  and `sprite` cannot see `p0d` or `owner-issuer`.
- New keys generated by each binary's `keygen` as its own user, written straight to the staged env file; only
  public keys printed (`scripts/rotate-issuer-keys-stage.sh`). `p0d` `336db1e8…`, `owner-policy` `720459db…`.
- Ledger `ledger.issuers` (read by both fences through foreign tables) updated in place, same issuer ids and
  `root_gen` 1, because the binaries hard-code both. Root `p0.keys`: `p0d-kernel-2` and `owner-policy-2` enrolled,
  `p0d-kernel` and `owner-policy` revoked.
- Proof on the live customer-sim fence, in a rolled-back transaction: a fresh grant passed the two-signature
  check; the same grant forged with the old seeds was refused `CFP_QUORUM` (`scripts/rotate-issuer-keys-proof.py`).
- Old env files and `keygen.json` shredded; no other copy of a seed on disk.

**Open.**
- `root_gen` is hard-coded to 1, so a rotation cannot be distinguished by generation at the fence; make it
  configurable in the next rebuild (needs re-admission).
- No recovery root is enrolled (`ledger.recovery` is empty), so the designed revocation protocol
  (`ledger.revocations`, signer plus recovery signature, epoch bump) cannot run. Enrol one, held offline.
- Both issuers still share one Sprite and one administrator; custody independence (K50) needs `owner-issuer`
  under a separate host and administrator.

## Candidate builds for admission, 28 Nov 2026 (not yet admitted)

Changes: database layer (`verify-full` by default, keepalives, bounded queries, reconnect in place), configurable
`ISSUER_ROOT_GEN`, `p0d` startup check against its ledger enrolment, `uapd` added as its own build unit. Built twice
with `scripts/build-reproducible.sh` in two directories (`/home/sprite/fix`, `/home/sprite/fixB`): identical.

| Component | Hash |
| --- | --- |
| `p0d` | `597d60ab1d8a06ba9856acd2e2e03d6d29ac43c734bcf8accea4f099590ec845` |
| `owner-issuer` | `c15136b665672a5ddcfb29a1694c558cd017bbf3d24aa2f3d0291d99e7c9d7e7` |
| `verifierd` | `122a026f28b1679e9ac6bc292d34a43c078576b41aa732fe37899249f497d180` |
| `uacd` | `ecf660f6cfacdd8bbf9bab848a09e64b3abaacd0260b0a59edc9ec33faceef7f` |
| `uapd` | `290d85d49cb2c62027ef076340fb0217437ebf40244ac3a8dc9e75672ee6c927` |
