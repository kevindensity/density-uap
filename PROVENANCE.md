# Provenance

Each admitted build: the binary that runs, its source, and where it was verified. Hashes are SHA-256. Re-verified on
the Sprites on 24 Nov 2026 when this repository was created. A future gate will check that every admitted build's
source hash matches a file in this repository at a recorded commit.

| Component | Status (kernel) | Binary (running) | Source file | Source SHA-256 | Host |
| --- | --- | --- | --- | --- | --- |
| `p0d` | ADMITTED | `920b512c78706e1c2d48479ab3d5fa464151216a409e72a81ee7bd2981761164` | `services/crates/p0d/src/main.rs` | `7e07d3471b778db6aaf482f4b5ace932b0fa213cfe4dde376cf90eab5438aece` | mcp-density-kernel |
| `owner-issuer` | ADMITTED | `27c699e3d0d4760a0b4f217b87f05a74b8e3076e65299b8d720c2e8fb5763b8f` | `services/crates/owner-issuer/src/main.rs` | `55a9f948120086f6a97689e7660a1fbcb6a06c0f46a6ac2911b69b72b284fb1e` | mcp-density-kernel |
| `verifierd` | ADMITTED (blind; gate run `58e87f3a…` 126/126) | `eff1883bfbbe50f44ae944b3a152a3ef78ab026e5ece4fe7d99b8e65b7a2f7c4` | `services/crates/verifierd/src/main.rs` | `8b6a85b869319453752a61ad12b26f8bf1cdee6edd9c14e08489e210afb4eaea` | mcp-density-verifier |

Retired verifier builds (kept in the kernel's lineage): `08df873d…` (probe witness), `b6a8a12b…` (signed trigger),
`1cfc9287…`, `33814adc…`, `3e71624c…`, `309dc7a6…`.

**Limitation recorded honestly.** Builds are not yet reproducible from this repository alone: the binaries were built
on the Sprites from the same sources, and the source hashes above match the files committed here, but a clean rebuild
producing byte-identical binaries has not been demonstrated.
