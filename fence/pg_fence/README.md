# pg_fence 0.1: Consequence Fence Protocol (CFP/1) reference prototype

A protected PostgreSQL table refuses any insert, update or delete unless the transaction first
admits a CFP grant with `select fence.begin(grant)`. The grant is quorum-signed (Ed25519),
single-use, bound to the exact prestate and history of the target row, bound to the current
authority epoch, and verified inside the same transaction that commits the effect. Every
admitted effect writes a receipt in that transaction.

## Layout

| File | Purpose |
| --- | --- |
| `pg_fence.c` | Ed25519 verification (libsodium) |
| `pg_fence--0.1.sql` | Signing input, grant admission, row guard, receipts, protection, quorum-signed revocation, setup |
| `ledger_schema.sql` | The durable ledger (issuers, recovery root, authority epoch, consumed grants) for its own database |
| `tests/run_cfp_tests.py` | End-to-end conformance tests against a live cluster |
| `tests/cfp_report.json`, `tests/cfp_run.txt` | Results of the run below |

## Build and run

    apt-get install postgresql-server-dev-16 libsodium-dev
    make && make install
    createdb fence_ledger && psql -d fence_ledger -f ledger_schema.sql
    psql -d app -c "create extension pg_fence"
    psql -d app -c "select fence.setup('pg://demo/billing','durable','fence_ledger',5432,'postgres','/var/run/postgresql')"
    psql -d app -c "select fence.protect('public.invoices','id')"

## Result (PostgreSQL 16.15, 22 Nov 2026): 54 of 54 checks pass

Admission (both ledger modes): valid grant applies with a receipt; unfenced write, replay,
wrong audience, changed prestate, history mismatch, quorum shortfall, a grant claiming a lower
quorum, an unenrolled signer, a forged signature, a tampered grant, a grant used on another
row or another operation, a multi-row statement, and an expired budget are all refused;
`session_replication_role = replica` cannot bypass the guard; a rolled-back grant is
unconsumed and usable exactly once.

Revocation: an effect admitted before a revocation commits completes, and the revocation
waits for it (1.5 s in the test); afterwards the epoch has advanced, old-epoch grants and
grants signed by the revoked issuer are refused, and an issuer cannot revoke itself.

Restore drills: after `pg_dump`, consuming a grant (and, in one variant, revoking an issuer),
dropping the database and `pg_restore`, replay is refused with the durable ledger
(`CFP_REPLAY`, or `CFP_STALE_EPOCH` when an issuer was revoked). With the ledger restored
alongside the application (negative control), the replay succeeds in both variants, which is
exactly why the ledger must live outside the restored database.

Overhead (median of 200 single-row update transactions): unfenced 1.1 ms; fenced with a local
ledger 5.5 ms; fenced with the durable ledger over postgres_fdw 9 to 11 ms.

## Findings made while building it

1. Extension-owned tables are excluded from `pg_dump` unless registered with
   `pg_extension_config_dump`; without that, a backup of a fenced database silently loses its
   protection list, configuration and receipts. Registered in 0.1.
2. `IMPORT FOREIGN SCHEMA` does not carry remote column defaults, so inserts through foreign
   tables must set every column explicitly.
3. A ledger restored together with the application database resurrects consumed grants and
   revoked issuers (negative control above); the durable ledger must be backed up and restored
   independently and only forward.
4. The refusal code for a multi-row statement depends on row processing order
   (`CFP_EFFECT_MISMATCH` or `CFP_GRANT_ALREADY_APPLIED`); both abort the whole statement.

5. Privilege model (found by the B2 demonstration): applications must hold no privileges on the fence's
   tables or ledger. `fence.begin`, the guard and the digest helpers run as `SECURITY DEFINER` with a pinned
   search path; applications get only EXECUTE on `fence.begin`, `fence.row_digest` and `fence.history_head`.
   The 54 checks pass after the change (`tests/cfp_run_v2.txt`).

## Known limits of this prototype

- The commit across the application and ledger databases is not two-phase: postgres_fdw
  commits the remote transaction just before the local one. If the local commit then fails,
  the grant is consumed without its effect, which fails safe (a new grant is needed) but is
  not yet tested.
- A role with DDL rights can drop the guard trigger. Production needs an event trigger that
  refuses or receipts DDL on protected tables, and protected tables owned by a role that
  applications never use.
- Grant admission is PL/pgSQL; a pgrx implementation and a ledger connection pool would cut
  the overhead substantially.
- Single-row effects only; multi-row and predicate effects need an operation-digest check.
- No threshold (FROST) signatures yet: quorum is t distinct Ed25519 signatures.
