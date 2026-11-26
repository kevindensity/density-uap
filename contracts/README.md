# Contracts: one source, three targets

`schemas/*.json` (JSON Schema 2020-12 with `x-density` annotations) is the only place a contract is defined.
`gen.py` generates:

- Rust: `services/crates/dc-contracts` (serde types; closed objects refuse unknown fields)
- TypeScript: `packages/contracts/src/index.ts`
- SQL: `generated/schemas.sql`, loaded into `contracts.schemas`; `contracts.check(schema_id, doc)` validates any document

Digests are SHA-256 over canonical JSON (sorted keys, no whitespace). `contracts.digest()` in Postgres recomputes the
generator's digests exactly. Never edit generated files: `gen.py --check` fails CI on any difference, and the gate
`gates.contract_checks()` fails if the database's schemas differ from this directory on `main` or any live row does
not conform.

`x-density.oracle` names the SQL function that stays the reference oracle when a Rust process (uacd, uapd) takes the
job over: the two must agree on live captures for 14 days before cut-over.
