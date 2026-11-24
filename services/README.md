# density-services: p0d (kernel) and owner-issuer

Rust services for stage S1 of the Supabase build plan. Admission stays in the database: `p0.admit_event`
is the single path for constitutional change, and p0d only forwards to it. p0d holds the kernel issuer key and
issues CFP/1 grants only after obtaining and verifying the owner-issuer's co-signature; it never returns a
single-signed grant. owner-issuer co-signs only grants already signed by the kernel, for allowed audiences,
within the maximum validity window.

## Key ceremony (run once per service, on the host that will keep the secret)
    p0d keygen            # prints seed_hex_store_as_secret and pubkey_hex_enrol
    owner-issuer keygen
Store each seed only as that service's secret; enrol only the public keys (p0.keys and each fence ledger).

## Environment
| Service | Variable | Meaning |
| --- | --- | --- |
| p0d | DATABASE_URL | Supabase session pooler URL for the root project, as a login role inheriting `p0d` |
| p0d | P0D_KEY_SEED | Kernel signing seed (secret) |
| p0d | OWNER_ISSUER_ADDR | host:port of owner-issuer on the private network |
| p0d | OWNER_ISSUER_PUBKEY | owner-issuer public key (hex) |
| p0d | MAX_GRANT_TTL_S, LISTEN, P0D_KEY_ID | optional (300, 0.0.0.0:8080, p0d-kernel) |
| owner-issuer | OWNER_KEY_SEED | owner-policy signing seed (secret) |
| owner-issuer | P0D_PUBKEY | kernel public key (hex) |
| owner-issuer | ALLOWED_AUDIENCES | comma-separated CFP audiences it will co-sign for |
| owner-issuer | MAX_GRANT_TTL_S, LISTEN | optional (300, 0.0.0.0:8081) |

## Endpoints
p0d: `GET /v1/health`, `GET /v1/pubkey`, `POST /v1/events` (submission to p0.admit_event; 200 accept or replay,
202 defer, 409 reject), `POST /v1/grants` (audience, effect, prestate digest, history head, intent, ttl).
owner-issuer: `POST /v1/cosign`, `GET /v1/pubkey`. Neither exposes a public port in production.

## Results (22 Nov 2026)
- Unit tests: 2/2 (signing-input layout, Ed25519 round trip).
- End-to-end, against a replica built from the live kernel's exact function definitions plus a pg_fence target:
  19/19 (key ceremony; health; events: accept, replay, defer without receipt, stale revision, accept with
  verifier receipt; eight concurrent HTTP clients on one revision, exactly one accepted; grant with two
  independently verified signatures accepted by pg_fence at the target, replay refused, kernel-only signature
  refused; refusals for audience, window, unsigned and over-long grants; owner-issuer down gives
  QUORUM_UNAVAILABLE and no grant; a co-signature that does not verify is rejected).
- Replica parity: event identity and receipt-message bytes are identical on the live database
  (PostgreSQL 17.12) and the replica (PostgreSQL 16.15).
- Built with Rust 1.75 using exact version pins (see Cargo.toml and Cargo.lock); the Dockerfiles use a newer
  Rust image and the same lockfile.
