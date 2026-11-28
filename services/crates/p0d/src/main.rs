//! p0d: the kernel service. Admission stays in the database (p0.admit_event is the single path);
//! p0d holds the kernel issuer key, forwards submissions, and issues two-issuer CFP grants by
//! obtaining and verifying the owner-issuer's co-signature. It never returns a single-signed grant.
use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use p0_core::{post_json, verify_hex, Effect, Grant, GrantSignature, History, Key, Prestate, Quorum};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;


struct App { db: p0_core::db::Db, root_gen: u32, key: Key, key_id: String, owner_addr: String, owner_pub: String, max_ttl_s: i64 }
type S = State<Arc<App>>;

fn env(k: &str) -> anyhow::Result<String> { std::env::var(k).map_err(|_| anyhow::anyhow!("missing environment variable {k}")) }

async fn health(State(a): S) -> (StatusCode, Json<Value>) {
    match a.db.query_one("select authority_epoch::text from p0_ledger.state where id = 1", &[]).await {
        Ok(r) => (StatusCode::OK, Json(json!({"status": "ok", "authority_epoch": r.get::<_, String>(0)}))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"status": "LEDGER_UNAVAILABLE", "detail": e.to_string()}))),
    }
}
async fn pubkey(State(a): S) -> Json<Value> { Json(json!({"key_id": a.key_id, "role": "KERNEL", "pubkey": a.key.public_hex()})) }

/// Forward a submission to the single admission path and return its decision unchanged.
async fn events(State(a): S, Json(sub): Json<Value>) -> (StatusCode, Json<Value>) {
    match a.db.query_one("select p0.admit_event($1::jsonb)", &[&sub]).await {
        Ok(r) => {
            let d: Value = r.get(0);
            let code = match d["decision"].as_str() { Some("ACCEPT") | Some("REPLAY") => StatusCode::OK, Some("DEFER") => StatusCode::ACCEPTED, _ => StatusCode::CONFLICT };
            (code, Json(d))
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"decision": "DEFER", "reason": "KERNEL_UNAVAILABLE", "detail": e.to_string()}))),
    }
}

#[derive(Deserialize)]
struct GrantRequest { audience: String, effect: Effect, prestate_digest: String, history_head: String, intent: String, ttl_s: Option<i64> }

async fn grants(State(a): S, Json(r): Json<GrantRequest>) -> (StatusCode, Json<Value>) {
    let ttl = r.ttl_s.unwrap_or(120);
    if ttl <= 0 || ttl > a.max_ttl_s { return (StatusCode::BAD_REQUEST, Json(json!({"decision": "REFUSE", "reason": "TTL_OUT_OF_RANGE", "max_ttl_s": a.max_ttl_s}))); }
    let epoch = match a.db.query_one("select authority_epoch::text from p0_ledger.state where id = 1", &[]).await {
        Ok(row) => row.get::<_, String>(0),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"decision": "DEFER", "reason": "LEDGER_UNAVAILABLE"}))),
    };
    let now = chrono::Utc::now();
    let mut g = Grant {
        v: "cfp/1".into(), grant_id: uuid::Uuid::new_v4().to_string(), audience: r.audience, effect: r.effect,
        prestate: Prestate { scheme: "row-json-sha256/1".into(), digest: r.prestate_digest }, history: History { head: r.history_head },
        authority_epoch: epoch, intent: r.intent,
        not_before: (now - chrono::Duration::seconds(30)).to_rfc3339(), not_after: (now + chrono::Duration::seconds(ttl)).to_rfc3339(),
        quorum: Quorum { t: 2 }, signatures: vec![],
    };
    let msg = g.signing_input();
    g.signatures.push(GrantSignature { issuer: "p0d".into(), root_gen: a.root_gen, sig: a.key.sign_hex(&msg) });
    let co = match post_json(&a.owner_addr, "/v1/cosign", &json!({"grant": g})).await {
        Ok((200, v)) => v,
        Ok((code, v)) => return (StatusCode::CONFLICT, Json(json!({"decision": "REFUSE", "reason": "OWNER_ISSUER_REFUSED", "status": code, "detail": v}))),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"decision": "DEFER", "reason": "QUORUM_UNAVAILABLE"}))),
    };
    let sig: GrantSignature = match serde_json::from_value(co.clone()) { Ok(s) => s, Err(_) => return (StatusCode::BAD_GATEWAY, Json(json!({"decision": "REFUSE", "reason": "MALFORMED_COSIGNATURE"}))) };
    if sig.issuer != "owner-policy" || !verify_hex(&a.owner_pub, &msg, &sig.sig) {
        return (StatusCode::BAD_GATEWAY, Json(json!({"decision": "REFUSE", "reason": "COSIGNATURE_INVALID"})));
    }
    g.signatures.push(sig);
    (StatusCode::OK, Json(json!({"decision": "ISSUED", "grant": g})))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("keygen") {
        let k = Key::generate();
        println!("{}", json!({"role": "KERNEL", "seed_hex_store_as_secret": k.seed_hex(), "pubkey_hex_enrol": k.public_hex()}));
        return Ok(());
    }
    eprintln!("p0d: database TLS mode {}", p0_core::db::mode());
    let db = p0_core::db::Db::new(&env("DATABASE_URL")?).await?;
    let key = Key::from_seed_hex(&env("P0D_KEY_SEED")?)?;
    let root_gen: u32 = std::env::var("ISSUER_ROOT_GEN").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    // refuse to run with a key the ledger does not enrol: a half-finished rotation fails here, loudly, at start
    let row = db.query_one("select encode(pubkey, 'hex'), root_gen, status from p0_ledger.issuers where issuer_id = 'p0d'", &[]).await
        .map_err(|e| anyhow::anyhow!("cannot read this issuer's enrolment from the ledger: {e}"))?;
    let (enrolled, gen, status): (String, i32, String) = (row.get(0), row.get(1), row.get(2));
    if enrolled != key.public_hex() || gen as u32 != root_gen || status != "active" {
        anyhow::bail!("ENROLMENT_MISMATCH: this key {}… root_gen {root_gen}; ledger enrols {}… root_gen {gen} status {status}", &key.public_hex()[..8], &enrolled[..8]);
    }
    eprintln!("p0d: key {}… root_gen {root_gen} matches its ledger enrolment", &key.public_hex()[..8]);
    let app = Arc::new(App {
        db, root_gen, key, key_id: std::env::var("P0D_KEY_ID").unwrap_or_else(|_| "p0d-kernel".into()),
        owner_addr: env("OWNER_ISSUER_ADDR")?, owner_pub: env("OWNER_ISSUER_PUBKEY")?,
        max_ttl_s: std::env::var("MAX_GRANT_TTL_S").ok().and_then(|v| v.parse().ok()).unwrap_or(300),
    });
    let router = Router::new().route("/v1/health", get(health)).route("/v1/pubkey", get(pubkey))
        .route("/v1/events", post(events)).route("/v1/grants", post(grants)).with_state(app);
    let listener = tokio::net::TcpListener::bind(std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into())).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
