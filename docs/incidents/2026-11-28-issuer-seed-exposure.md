# Incident, 28 Nov 2026: issuer seeds exposed on launcher command lines

Status: contained. Keys rotated and the exposure closed on 28 Nov. Prevention is in place, but three items wait on
the owner (see "Open"). This record also lists the operator's own errors made during the response, because several
of them were the same class of failure as the incident.

## What happened

`p0d` and `owner-issuer` were started as `sudo -u <user> env $(cat secrets) <binary>`. The `sudo` process stays
alive as the service's parent, so both Ed25519 signing seeds sat in a command line that every local user of
mcp-density-kernel could read (`/proc/<pid>/cmdline`; `/proc` had no `hidepid`). That includes `uacd`, which parses
untrusted internet content. Both seeds together can forge a valid two-signature CFP grant, so the quorum gave no
protection against anyone with a foothold on that one host. While diagnosing it, the operator printed the first
13 of each seed's 32 bytes into a working session.

Checked 28 Nov against the durable ledger: all 10 grants ever consumed at the two fenced targets match a gateway
SENT record, all 14 SENT records name one of the two owner-signed policies, and the last consumption was 24 Nov. A
grant forged with the exposed seeds and used at a fence would appear as consumed without a SENT; none does. That
does not prove a negative (a forged grant could have been minted and never used), which is why both keys were
rotated: no grant signed with the old keys can verify any more.

## Defects found during the 27 and 28 Nov work, and their fixes

| # | Defect | Fix | Where |
| --- | --- | --- | --- |
| D1 | Signing seeds on launcher command lines; `/proc` without `hidepid` | Service users read their own 0600 env files inside their own shell; `hidepid=invisible`, re-applied by the watchdog; both keys rotated, old keys revoked, old seeds shredded; proven on the live fence (old-key grant refused `CFP_QUORUM`) | `sprites/kernel/run-*.sh`, `PROVENANCE.md` |
| D2 | Standing policies had no `EXPIRED` state; `used` never updated; reduction guards were prose that admission never evaluated | `ACTIVE->EXPIRED`; both guards enforced at admission; `p0.policy_watch()` every 5 minutes counting uses in the ledger | root `s5_0001` |
| D3 | Causal-access certificate tested `used < max OR ledger < max`; with `used` stuck at 0 it called exhausted policies actionable | Ledger count only | root `s5_0001` |
| D4 | Seed-port oracle took an arbitrary OAuth client per app; reported Slack sign-in only though a 2-user client holds Drive scopes | Access summarizes every client; found by the `uapd` differential | root `onboard_0002` |
| D5 | Any superuser `UPDATE` could change an issuer key silently | Key or generation changes only with a recovery-root signature verified by the ledger in the same transaction; generations only increase; history append-only. 10/10 adversarial cases | ledger `s6_0001` |
| D6 | No recovery root enrolled: the designed revocation path could not run | Recovery root generated offline on the owner's Mac and enrolled 28 Nov (ledger.recovery id 1, `61e37148...`) after its proof of possession verified | Closed |
| D7 | `root_gen` hard-coded to 1: rotations indistinguishable at the fence | `ISSUER_ROOT_GEN`; `p0d` refuses to start unless its key and generation match its ledger enrolment | `p0d`, `owner-issuer` (live after admission) |
| D8 | After the host slept, the kernel's single database connection went half-open: no keepalive, no timeout, no reconnect, so every request hung until the watchdog killed the process (about 30 restarts since 24 Nov) | Keepalives, TCP user timeout, bounded queries, reconnect in place; proven with a frozen relay: bounded failure in 23 s, recovery in 0.7 s without a restart | `p0-core` (live after admission) |
| D9 | Database TLS defaulted to encrypt-only: no certificate verification anywhere | Default `verify-full`, missing CA is a startup error, `require` must be explicit and warns every start | `p0-core` (live after CA and admission) |
| D10 | Watchdog killed `p0d` after one 5-second miss | Four consecutive misses; runs the hygiene gate every minute | `sprites/kernel/watchdog.sh` (with the new `p0d`) |
| D11 | Both issuers on one host under one administrator | Not fixable by software alone | Open |
| D12 | Build-admission gate runs accepted self-reported external checks (`gates.external_checks` trusted any list of passes), so a run could be padded to meet the suite-size floor | External evidence must be signed by an enrolled `BUILD_ATTESTOR` key for this exact component@sha256, within 24 hours; the attestor (`scripts/attest.py`) hashes the binary and runs every check itself, and refuses to sign unless the run used `verify-full`. Unverified evidence yields one failing check and no passes. 7/7 forgery cases refused (unsigned, replayed for another build, tampered, padded, stale, unenrolled key). Limit: root on the build host can still sign (D11) | root `g3_0001` |
| D13 | The effect gateway kept a hard-coded copy of the issuer public keys; the rotation updated the ledger but not this copy, so from 03:24 UTC on 28 Nov the gateway would have refused every grant (none was attempted: last SENT 24 Nov) | Copy removed: the gateway reads active keys and generations from the ledger (`ledger.active_issuers`) at every release and also checks each signature's generation. Tested on a live grant: genuine passes; tampered signature, wrong generation and altered body refused | ledger `s6_0002`, `sprites/kernel/effect_gateway.py` |
| D14 | The same launcher pattern on mcp-density-verifier: `verifierd`'s signing seed and database URL were on a command line readable by every account there; `/proc` not hidden | Launcher fixed, `hidepid`; key rotated (`verifier-2` enrolled, `verifier-1` revoked); `verifierd_login` password replaced by a SCRAM verifier generated on the Sprite; seed, env and password copies shredded; gate suites naming `verifier-1` still 3/3 and 3/3. Misuse cannot be ruled out for the 294 settlements the old key signed: see Open | `sprites/verifier/run-verifier.sh` |
| D15 | Database TLS was unverified everywhere, including the Python services (`sslmode=require`) | CA verified against the pooler's presented root through an independent channel (fingerprint `80:70:25:AD...CA:FA`, valid to 26 Apr 2031); every client on both Sprites runs `verify-full`; proven by a negative control (without the root: `UnknownIssuer`). The hygiene gate refuses any unverified client mode | live 28 Nov |
| D16 | `verify.keys` was a second registry of verifier key ids; the rotation to `verifier-2` did not update it, so every re-settlement, including the daily sweep, would have been refused | The settlement guard takes the verifier's role and status from `p0.keys` (the single authority, where signatures are checked) and requires an active key, so a revoked key cannot strengthen by any path | root `v2_0001` |
| D17 | The verifier watchdog killed `verifierd` after one slow health check; health shares the database connection with sweeps, so the daily 06:50 sweep was killed on 26 and 27 Nov | Restart only after about two minutes of consecutive failure; the lasting fix is the reconnecting database layer in `verifierd`'s rebuild | `sprites/verifier/watchdog.sh` |
| D18 | Blind commitments were unique per (claim, value, evidence) regardless of verifier, so a second verifier's commitment to an unchanged claim was silently dropped, and `verifierd` signed its receipt anyway; admission also never checked that the commitment preceded the receipt | Commitments unique per verifier; admission requires commitment time <= receipt time; receipts can be voided with a reason (never deleted). Open for the rebuild: `verifierd` must refuse to sign when its commitment was not stored | root `v2_0002` |
| D19 | The uacd differential counted a source the SQL oracle could only partly observe (compressed page: 'partial') as a disagreement, so every density.dev run since 26 Nov read DIVERGE | Partial or failed on either side is UNAVAILABLE; DIFFERS means both observed and disagree. Fresh run: AGREE, 18 agree, 2 unavailable | root `uac_0011` |
| D20 | `rereadd` slept until 06:42 UTC on a Sprite that hibernates, so no independent re-read had happened since 24 Nov | Catch-up schedule: re-read whenever the last success is 23 hours old, checked every 5 minutes; the root's daily sweep wakes the Sprite | `sprites/verifier/rereadd.py` |
| D21 | Re-reads were keyed by content alone, so re-observing an unchanged domain was silently dropped and the domain looked stale | Keyed by (content, time); signature binds the observation time; time must be within 10 minutes of the insert; an insert that stores nothing is a failure, never a silent success | root `uac_0012`, `rereadd.py` |

## Operator errors during the response

| # | Error | Consequence | Correction and rule |
| --- | --- | --- | --- |
| E1 | Reported both standing policies "unused" from `p0.standing_policies.used` without checking the ledger | Owner chose lower caps on wrong data | Caught and corrected before signing (9/20 and 5/10 were used). Rule: a kernel projection is not evidence until checked against the authority it projects |
| E2 | Claimed the certificate ignored expiry without reading the function | Overstated a defect | Retracted; the real defect was D3. Rule: read the code before describing it |
| E3 | A diagnostic printed process command lines, exposing 13 bytes of each seed | Made rotation mandatory | Rule: never print command lines, environments or secret files. Use `scripts/secret-hygiene.sh`, which prints pids, names and rules only |
| E4 | Ran `uapd` with `env $(cat ...)`, the pattern behind D1 | Its database password briefly on a command line | Fixed; the gate and the pre-commit lint both refuse the pattern |
| E5 | Rotated the issuer keys with an unsigned superuser `UPDATE` | The response used the silent path the ledger should forbid | Recorded in `ledger.issuer_rotations` as UNSIGNED; D5 closes the path |
| E6 | Gave the owner a script path that did not exist on his Mac, and did not check its Python dependency | Two failed attempts | Owner scripts now check their dependency and say exactly how to run them |
| E7 | A migration created a trigger before its function | None (caught by the dry run) | Rule kept: every migration is dry-run on the live database in a forced rollback first |
| E8 | The first resilience test silently could not install its firewall rule | None (the test asserts failure and so failed) | Rule kept: every test must be able to fail; replaced by an isolated frozen relay |
| E9 | Listed fixable gaps as to-dos | Delay | This record and the fixes above |
| E10 | The rotation updated the ledger and the kernel records but missed a fifth copy of the keys, in the gateway | Every effect would have been refused | D13: the copy no longer exists. Rule: a key has one authoritative location; consumers read it, never copy it |
| E11 | Applied the launcher fix to one Sprite and did not check the other for the same pattern | The verifier exposure (D14) ran a day longer | Rule: a fix for a pattern is applied to every host and every service, and the gate runs on every host |
| E12 | Checked key enrolment in `p0.keys` and the ledger but not `verify.keys`, a third registry | Found before the daily sweep would have failed | D16; same rule as E10 |
| E13 | Triggered the sweep through the SQL tool, whose statement timeout cut the request; with the single-miss watchdog this also killed `verifierd` mid-sweep | None lasting; led to finding D17 | Long operations are run on the host with an explicit timeout, never through a tool with a shorter one |
| E14 | The v2_0001 guard change compared a missing role with `<>`, which is NULL, so a receipt naming a non-verifier key passed | Caught by the admission suite (spine.synthesizer_as_verifier). Checked the window: all 148 receipts issued while it was open came from the active verifier-2 | v2_0003, v2_0004. Rule: every security comparison is NULL-safe |
| E15 | The s6_0001 ledger guard ran immediately and blocked the differential and fence-conformance gate harnesses | Those gates could not run | s6_0003 (checked at commit). Rule: run the full admission suite after any change to a guard, before declaring it done |

## Prevention now in force

- **Runtime gate** `scripts/secret-hygiene.sh`, every minute from the watchdog: secrets on command lines, `hidepid`,
  secret file modes and owners, stale key copies, launcher patterns, and (once the CA is installed) any service not on
  `verify-full`. Every rule was proven by planting the violation.
- **Commit gate** `scripts/lint-secrets.sh` as the repository's pre-commit hook: refuses the launcher pattern, key or
  seed values, and database URLs with passwords.
- **Ledger** (D5): no silent key change, even by the superuser through ordinary SQL.
- **Service** (D7): an issuer refuses to start with a key its ledger does not enrol.
- **Kernel projections** (D2): reductions are admitted events, so the kernel's account cannot drift from the ledger.

## Order of the remaining work

Gate runs for the rebuilt binaries must exercise them for real (health, enrolment self-check, admission, a co-signed
grant verified at the fence, frozen-connection recovery) in their `verify-full` configuration, so they follow the CA.
Admission (owner signature) cites those runs and must happen within 7 days of them. The recovery root is independent
and can be created first (`owner-tools/density_recovery_root_genesis.py`).

## Re-verification after D14 (done 28 Nov)

Of the 294 settlements `verifier-1` signed, 215 had already been superseded; 79 still stood on its receipts. Each was
demoted through the kernel (`REVERIFY_AFTER_KEY_EXPOSURE`, recorded in `verify.reverification_2026_11_28`) and
re-evaluated by `verifier-2` from current evidence, committing its value blind before reading the compiler's. All 79
reached the same outcome as before (76 true, 3 false) and are settled again under `verifier-2`, each with a prior
`verifier-2` commitment. No current standing depends on the exposed key. Limit: this confirms each claim against
today's evidence, not the evidence of its original settlement.

## Open (rebuild)

- `verifierd`: refuse to sign when its blind commitment was not stored (D18); adopt the reconnecting database layer (D17).

## Open (owner)

1. **CA certificate** (Supabase dashboard, Database settings, SSL Configuration): needed to switch to `verify-full`.
2. **One signing session** on the owner's Mac: generate the recovery root (kept offline), sign the generation-2
   rotation of both issuers, and admit the rebuilt services.
3. **Custody independence** (D11): `owner-issuer` needs a second host and a second administrator.
