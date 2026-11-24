# density-uap

Source of truth for Density's Universal Adaptive Connector and Port (UAC/UAP), its kernel, and the conformance
machinery that governs it. Everything that runs in production is built from this repository; every admitted build
is listed in [PROVENANCE.md](PROVENANCE.md) with the hashes that tie the running binary to its source.

## Layout

| Path | What it is |
| --- | --- |
| `kernel/root`, `kernel/ledger`, `kernel/customer` | Every migration applied to the root (kernel, UAP, UAC, broker, gates), the durable ledger, and the customer-style effect target, exported in order from each project's migration history. Secret-shaped strings (password verifiers, password literals, connection-string passwords) are redacted at export. |
| `services/` | Rust workspace: `p0d` (kernel daemon), `owner-issuer`, `verifierd` (blind verifier), `p0-core`. |
| `sprites/kernel`, `sprites/verifier` | Python services and launchers on the Fly Sprites: effect gateway, UAC probe service, GitHub collector, re-read route, verifier isolation audit, watchdogs. |
| `edge/` | Supabase edge functions: `universal-port` (REST and MCP, read-only) and `idp-connect` (consent callback). |
| `engine/` | The `uapcore` descent engine and the INC-02 to INC-07 harnesses, with their pre-registered predictions and sealed truths. |
| `oracle/` | B0 reference kernel (the K38 oracle), `dc-types`, the TLA+ model, the traceability matrix and the differential trace exporter. |
| `fence/` | `pg_fence` (Consequence Fence Protocol reference, C) and its tests. |
| `owner-tools/` | Owner signing scripts. They contain public keys and event identities only; the owner's private key never leaves the owner's machine. |
| `docs/` | Specification and build plan (exported from the working Claude Doc). |

## Rules

- **No secrets, ever.** Vault entries, passwords, keys and tokens stay in Supabase Vault or on the Sprites under owner-only permissions. Every commit is scanned; a finding aborts the push.
- **Builds come from commits.** A build is admitted only with a PROMOTED gate run and the owner's signature; PROVENANCE.md records the source and binary hashes of every admitted build.
- **Pushes come from the kernel Sprite** through a repository-scoped deploy key held by the `gitsync` user.
