# Provenance

Each admitted (and candidate) build: the binary, its source, the commit that source is checked at, and where it was verified. Hashes are SHA-256. Re-verified on
the Sprites on 24 Nov 2026 when this repository was created. A future gate will check that every admitted build's
source hash matches a file in this repository at a recorded commit.

| Component | Status (kernel) | Binary | Source file | Source SHA-256 | Source commit | Host |
| --- | --- | --- | --- | --- | --- | --- |
| `p0d` | ADMITTED | `920b512c78706e1c2d48479ab3d5fa464151216a409e72a81ee7bd2981761164` | `services/crates/p0d/src/main.rs` | `7e07d3471b778db6aaf482f4b5ace932b0fa213cfe4dde376cf90eab5438aece` | `7db2f27f5f8b4d084f97cae62cbb125ab4b71d74` | mcp-density-kernel |
| `owner-issuer` | ADMITTED | `27c699e3d0d4760a0b4f217b87f05a74b8e3076e65299b8d720c2e8fb5763b8f` | `services/crates/owner-issuer/src/main.rs` | `55a9f948120086f6a97689e7660a1fbcb6a06c0f46a6ac2911b69b72b284fb1e` | `7db2f27f5f8b4d084f97cae62cbb125ab4b71d74` | mcp-density-kernel |
| `verifierd` | RETIRED (superseded by `087cdbad…`) | `eff1883bfbbe50f44ae944b3a152a3ef78ab026e5ece4fe7d99b8e65b7a2f7c4` | `services/crates/verifierd/src/main.rs` | `8b6a85b869319453752a61ad12b26f8bf1cdee6edd9c14e08489e210afb4eaea` | `7db2f27f5f8b4d084f97cae62cbb125ab4b71d74` | mcp-density-verifier |
| `verifierd` | ADMITTED (reproducible build of `de458a82`, identical on both Sprites; gate run `c4550fc1…` 141/141; owner-signed) | `087cdbadba9445897a4fa112b8d07a2bdd2baa8bf465835cfb00e310e5f0026b` | `services/crates/verifierd/src/main.rs` | `7ae8f1b34e1ca5e9c90f39441fc6186c29b2f54d266fa37a6a4612e58ebb55e0` | `de458a8244fd499e14cf747e9d927c9d1c2f36b5` | mcp-density-verifier |

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
