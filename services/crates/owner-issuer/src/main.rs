//! owner-issuer: the second quorum signer. It co-signs a CFP grant only when the kernel has already
//! signed it, the audience is allowed, the quorum is two, and the validity window is within policy.
use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use p0_core::{verify_hex, Grant, GrantSignature, Key};
use serde_json::{json, Value};
use std::sync::Arc;

struct App { key: Key, p0d_pub: String, audiences: Vec<String>, max_ttl_s: i64 }

fn refuse(reason: &str) -> (StatusCode, Json<Value>) { (StatusCode::FORBIDDEN, Json(json!({"decision": "REFUSE", "reason": reason}))) }

async fn cosign(State(a): State<Arc<App>>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let g: Grant = match serde_json::from_value(body["grant"].clone()) { Ok(g) => g, Err(_) => return refuse("MALFORMED_GRANT") };
    if g.v != "cfp/1" { return refuse("VERSION"); }
    if g.quorum.t != 2 { return refuse("QUORUM_POLICY"); }
    if !a.audiences.iter().any(|x| x == &g.audience) { return refuse("AUDIENCE_NOT_ALLOWED"); }
    let (Ok(nb), Ok(na)) = (chrono::DateTime::parse_from_rfc3339(&g.not_before), chrono::DateTime::parse_from_rfc3339(&g.not_after)) else { return refuse("MALFORMED_WINDOW") };
    if (na - nb).num_seconds() > a.max_ttl_s + 60 { return refuse("TTL_TOO_LONG"); }
    if g.signatures.iter().any(|s| s.issuer == "owner-policy") { return refuse("ALREADY_COSIGNED"); }
    let msg = g.signing_input();
    let kernel_ok = g.signatures.iter().any(|s| s.issuer == "p0d" && verify_hex(&a.p0d_pub, &msg, &s.sig));
    if !kernel_ok { return refuse("NOT_SIGNED_BY_KERNEL"); }
    (StatusCode::OK, Json(serde_json::to_value(GrantSignature { issuer: "owner-policy".into(), root_gen: 1, sig: a.key.sign_hex(&msg) }).unwrap()))
}
async fn pubkey(State(a): State<Arc<App>>) -> Json<Value> { Json(json!({"key_id": "owner-policy", "role": "OWNER_POLICY", "pubkey": a.key.public_hex()})) }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("keygen") {
        let k = Key::generate();
        println!("{}", json!({"role": "OWNER_POLICY", "seed_hex_store_as_secret": k.seed_hex(), "pubkey_hex_enrol": k.public_hex()}));
        return Ok(());
    }
    let need = |k: &str| std::env::var(k).map_err(|_| anyhow::anyhow!("missing environment variable {k}"));
    let app = Arc::new(App {
        key: Key::from_seed_hex(&need("OWNER_KEY_SEED")?)?, p0d_pub: need("P0D_PUBKEY")?,
        audiences: need("ALLOWED_AUDIENCES")?.split(',').map(|s| s.trim().to_string()).collect(),
        max_ttl_s: std::env::var("MAX_GRANT_TTL_S").ok().and_then(|v| v.parse().ok()).unwrap_or(300),
    });
    let router = Router::new().route("/v1/cosign", post(cosign)).route("/v1/pubkey", get(pubkey)).with_state(app);
    let listener = tokio::net::TcpListener::bind(std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:8081".into())).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
