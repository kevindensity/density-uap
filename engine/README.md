# Density UAP safety spine + DCA-UAP-01 (API leg) v0.1

## What is here
- `supabase/migrations/0001_uap_safety_spine.sql` - evidence-status type system (Corollary 10) as a Postgres trigger,
  proven-bridge rule, bind receipts, receiver-owned effect fence, single-use nonce ledger, owner-epoch transfer.
- `supabase/tests/001_spine.sql` - 13 checks. Result on PostgreSQL 16: 13/13 PASS.
- `rust/uap-evidence` - `Unresolved<T>` / `Settled<T>`; `refine` is the only constructor of `Settled`; `weaken` always allowed. 6 tests PASS.
- `rust/densityd-fence` - hardened certificate gate replacing D1 v1.3 `verify_envelope`: hash, k-of-n Ed25519 quorum over distinct keys,
  org/domain/epoch/subject binding, validity window, effect bounds, mandatory single-use, durable fsync'd nonce ledger (survives restart),
  receiver fence. Includes the two-ledger negative control (duplicates) and the receiver fence (does not). 5 tests PASS.
- `dca_uap_01/` - one-shot local DCA-UAP-01 API-leg run against an opaque legacy-style HTTP fixture with a negative-reference bank.

## Commands
    createdb spine && psql -d spine -f supabase/migrations/0001_uap_safety_spine.sql && psql -d spine -f supabase/tests/001_spine.sql
    cd rust && cargo test            # Cargo.lock pins versions compatible with rustc 1.75
    createdb spine_run && psql -d spine_run -f supabase/migrations/0001_uap_safety_spine.sql
    cd dca_uap_01 && python3 run_dca_uap_01.py   # needs psycopg2 and a local postgres user 'postgres'/'pg'

## DCA-UAP-01 (API leg) result - single recorded run
9/9 gates PASS. 0 false semantic promotions. 8 of 11 true dependencies settled (recall 0.727).
- Settled through verifier receipts and the Postgres trigger: total<-{qty,unit_price,discount_code}, tax<-{qty,unit_price,discount_code,region}, ref<-note.
- `request_id` caught by the replay-twin gate as NONDETERMINISTIC and never settled; `server` never varied and was never claimed.
- `ref<-note` flagged as an echo dependency.
- The fixture's documentation was wrong in two places; the port promoted neither claim and recovered total<-discount_code, which the docs denied.
- A synthesizer attempt to settle without a verifier receipt was refused by the database: ILLEGAL_STRENGTHENING_CAST.
- Effect: the legacy endpoint has no idempotency. With the ACK deliberately dropped, the successor owner hit ALREADY_COMMITTED at the
  fence, checked the outcome through the lookup endpoint and did not resend: 1 world effect. Naive retry negative control: 2 effects.
- Missed: status<-{qty,unit_price,discount_code}. `status` only changes when total crosses 1000, and no probe crossed it, so those stay
  UNRESOLVED:NO_WITNESS. This is the correct outcome (silence is not absence) and is exactly the case the interface-acquisition
  compiler (RIA-001) or a boundary-seeking probe would address next.

## Claim boundary
Local, single host, synthetic deterministic fixture, one recorded run with a fresh OS-entropy seed. HMAC stands in for verifier
signatures in the harness (Ed25519 is used in densityd-fence). This is the API leg only: canonical DCA-UAP-01 also requires a DB/CLI
leg and a legacy fixture. No production system, Supabase project or external provider was touched.
