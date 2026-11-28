//! verifierd: the independent verifier. It signs a VERIFIER receipt for a submission only after checking
//! the claim against the live records itself, reading the Node's systems from the kernel's own projection
//! (never from the submission) and the settled evidence from the semantics tables. The receipt is an Ed25519
//! signature over p0.receipt_message(kind, stream, identity), exactly what p0.admit_event verifies.
use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use p0_core::{verify_hex, Key};
use serde_json::{json, Value};
use std::sync::Arc;

struct App { db: p0_core::db::Db, key: Key, key_id: String, trigger_pub: String, nonces: std::sync::Mutex<std::collections::HashMap<String, i64>> }
type S = State<Arc<App>>;

fn refuse(reason: &str, detail: Value) -> (StatusCode, Json<Value>) { (StatusCode::CONFLICT, Json(json!({"decision": "REFUSE", "reason": reason, "detail": detail}))) }

/// Every request that can make the verifier work must carry a trigger signed by the root scheduler key pinned in this
/// verifier's own configuration: for this exact action, issued within 120 seconds, with a nonce never seen before.
fn check_trigger(a: &App, body: &Value, action: &str) -> Result<(), (StatusCode, Json<Value>)> {
    let deny = |r: &str| (StatusCode::UNAUTHORIZED, Json(json!({"decision": "REFUSE", "reason": r})));
    let t = &body["trigger"];
    let (Some(act), Some(ts), Some(nonce), Some(sig)) = (t["action"].as_str(), t["issued_at"].as_str(), t["nonce"].as_str(), t["sig"].as_str()) else { return Err(deny("TRIGGER_MISSING")) };
    if act != action { return Err(deny("TRIGGER_WRONG_ACTION")); }
    let Ok(issued) = ts.parse::<i64>() else { return Err(deny("TRIGGER_MALFORMED")) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    if (now - issued).abs() > 120 { return Err(deny("TRIGGER_STALE")); }
    if !verify_hex(&a.trigger_pub, format!("DENSITY-TRIGGER/1|{act}|{ts}|{nonce}").as_bytes(), sig) { return Err(deny("TRIGGER_BAD_SIGNATURE")); }
    let mut seen = a.nonces.lock().unwrap();
    seen.retain(|_, t| now - *t <= 300);
    if seen.contains_key(nonce) { return Err(deny("TRIGGER_REPLAYED")); }
    seen.insert(nonce.to_string(), now);
    Ok(())
}

async fn evidence_basis(a: &App, stream: uuid::Uuid, expected_state: &str) -> Result<Value, (StatusCode, Json<Value>)> {
    let row = a.db.query_opt("select status, systems from p0.nodes where stream_id = $1", &[&stream]).await
        .map_err(|e| refuse("RECORDS_UNAVAILABLE", json!(e.to_string())))?
        .ok_or_else(|| refuse("UNKNOWN_NODE", json!(stream.to_string())))?;
    let status: String = row.get(0); let systems: Value = row.get(1);
    if status != expected_state { return Err(refuse("NODE_NOT_IN_EXPECTED_STATE", json!({"status": status, "expected": expected_state}))); }
    let ids: Vec<String> = systems.as_array().map(|v| v.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    if ids.is_empty() { return Err(refuse("NO_SYSTEMS", json!(null))); }
    let mut basis = vec![];
    for id in &ids {
        let sid = uuid::Uuid::parse_str(id).map_err(|_| refuse("MALFORMED_SYSTEM_ID", json!(id)))?;
        let r = a.db.query_opt(
            "select s.name, p.current_epoch::text,
                    count(*) filter (where st.status::text in ('SETTLED_TRUE','SETTLED_FALSE')),
                    count(*) filter (where st.status::text = 'UNRESOLVED')
               from core.systems s join uap.ports p on p.system_id = s.id
               left join sem.settlements st on st.port_epoch_id = p.current_epoch
              where s.id = $1 group by s.name, p.current_epoch", &[&sid]).await
            .map_err(|e| refuse("RECORDS_UNAVAILABLE", json!(e.to_string())))?;
        let Some(r) = r else { return Err(refuse("SYSTEM_WITHOUT_PORT", json!(id))); };
        let settled: i64 = r.get(2); let unresolved: i64 = r.get(3);
        if settled == 0 { return Err(refuse("NO_SETTLED_EVIDENCE", json!({"system": id}))); }
        basis.push(json!({"system_id": id, "system": r.get::<_, String>(0), "port_epoch": r.get::<_, String>(1), "settled": settled, "unresolved": unresolved}));
    }
    Ok(json!({"systems": basis}))
}

/// Independent recomputation of a capture-backed claim from the latest stored capture bodies. Shares no code with
/// the compiler's SQL evaluator. Refuses when the value disagrees with the requested outcome or the submission cites
/// evidence that is not the latest capture of each scope.
/// Blind evaluation: the claim's value from its registered definition and the latest evidence ONLY. It never sees the
/// compiler's submission, so the verifier's answer is fixed before the compiler's answer is read.
async fn evaluate_claim(a: &App, stream: uuid::Uuid) -> Result<(String, String, bool, serde_json::Map<String, Value>), (StatusCode, Json<Value>)> {
    let st = a.db.query_opt("select consequence_key, status::text from sem.settlements where id = $1", &[&stream]).await
        .map_err(|e| refuse("RECORDS_UNAVAILABLE", json!(e.to_string())))?.ok_or_else(|| refuse("UNKNOWN_SETTLEMENT", json!(stream.to_string())))?;
    let key: String = st.get(0); let status: String = st.get(1);
    if status != "UNRESOLVED" { return Err(refuse("SETTLEMENT_NOT_UNRESOLVED", json!(status))); }
    let cl = a.db.query_opt("select evaluator, scopes, spec from uap.capture_claims where consequence_key = $1", &[&key]).await
        .map_err(|e| refuse("RECORDS_UNAVAILABLE", json!(e.to_string())))?.ok_or_else(|| refuse("NOT_A_CAPTURE_CLAIM", json!(key)))?;
    let evaluator: String = cl.get(0); let scopes: Vec<uuid::Uuid> = cl.get(1); let spec: Option<Value> = cl.get(2);
    let mut digests = serde_json::Map::new(); let mut bodies: Vec<Value> = vec![];
    // dependency-exact evidence: the latest capture that bears on this claim (verify.evidence_capture), same rule as the kernel
    let spec_v: Value = spec.clone().unwrap_or(Value::Null);
    for s in &scopes {
        let r = a.db.query_opt("select b.content_digest, b.body from uac.capture_bodies b where b.content_digest = verify.evidence_capture($1, $2)", &[s, &spec_v]).await
            .map_err(|e| refuse("RECORDS_UNAVAILABLE", json!(e.to_string())))?.ok_or_else(|| refuse("NO_CAPTURE", json!(s.to_string())))?;
        digests.insert(s.to_string(), json!(r.get::<_, String>(0))); bodies.push(r.get::<_, Value>(1));
    }
    let by_scope: std::collections::HashMap<String, &Value> = scopes.iter().map(|s| s.to_string()).zip(bodies.iter()).collect();
    let obs = bodies.iter().find(|b| b.get("snapshots").is_some());
    let repo = |name: &str| bodies.iter().find(|b| b["repository"] == name);
    let arr = |v: &Value, k: &str| v[k].as_array().cloned().unwrap_or_default();
    let value = match evaluator.as_str() {
        "K1" => {
            let (Some(o), Some(d)) = (obs, repo("kevindensity/density-lens-production")) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(evaluator))) };
            let cur = arr(o, "repositories").into_iter().find(|r| r["full_name"] == "kevindensity/density-lens-production").map(|r| r["current_snapshot_id"].clone());
            let commit = cur.and_then(|id| arr(o, "snapshots").into_iter().find(|s| s["id"] == id).map(|s| s["commit_sha"].clone()));
            commit.is_some() && commit.unwrap() == d["head"]
        }
        "K2" => { let Some(o) = obs else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(evaluator))) };
                  arr(o, "refresh_runs").iter().all(|r| r["expected_snapshot_id"].is_null() || r["expected_snapshot_id"] == r["snapshot_id"]) }
        "K3" => { let Some(o) = obs else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(evaluator))) };
                  let rec: Vec<Value> = arr(o, "receipts").into_iter().map(|r| r["snapshot_id"].clone()).collect();
                  arr(o, "snapshots").iter().all(|s| rec.contains(&s["id"])) }
        "K4" => {
            let (Some(o), Some(c)) = (obs, repo("kevindensity/codespace")) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(evaluator))) };
            let files: std::collections::HashSet<String> = arr(c, "files").into_iter().filter_map(|f| f.as_str().map(String::from)).collect();
            arr(o, "migrations").iter().all(|m| files.contains(&format!("supabase/migrations/{}_{}.sql", m["version"].as_str().unwrap_or(""), m["name"].as_str().unwrap_or(""))))
        }
        "SPEC" => {
            let Some(sp) = spec else { return Err(refuse("SPEC_MISSING", json!(key))) };
            let body_of = |side: &Value| side["scope"].as_str().and_then(|s| by_scope.get(s).copied());
            match sp["op"].as_str() {
                Some("includes") => {
                    let (Some(lb), Some(rb)) = (body_of(&sp["left"]), body_of(&sp["right"])) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(key))) };
                    let right: std::collections::HashSet<String> = path_values(rb, sp["right"]["path"].as_str().unwrap_or("")).into_iter().collect();
                    path_values(lb, sp["left"]["path"].as_str().unwrap_or("")).iter().all(|v| right.contains(v))
                }
                Some("rowwise_equal") => {
                    let Some(lb) = body_of(&sp["left"]) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(key))) };
                    let (lf, rf) = (sp["left_field"].as_str().unwrap_or(""), sp["right_field"].as_str().unwrap_or(""));
                    arr(lb, sp["array"].as_str().unwrap_or("")).iter().all(|e| match (e[lf].as_str(), e[rf].as_str()) { (Some(x), Some(y)) => x == y, _ => true })
                }
                Some("contains") => {
                    let Some(lb) = body_of(&sp["left"]) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(key))) };
                    let needle = sp["needle"].as_str().unwrap_or("").to_lowercase();
                    if needle.is_empty() { return Err(refuse("EMPTY_NEEDLE", json!(key))); }
                    path_values(lb, sp["left"]["path"].as_str().unwrap_or("")).iter().any(|v| v.to_lowercase().contains(&needle))
                }
                Some("probe_witness") => {
                    // From the sealed probe evidence alone: the base and the switched input each observed at least 3 times,
                    // every observation of each agreeing, the two disagreeing. Anything less is not decidable.
                    let Some(lb) = body_of(&sp["left"]) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(key))) };
                    let (o, inp) = (sp["output"].as_str().unwrap_or(""), sp["input"].as_str().unwrap_or(""));
                    let base = sp["base"].clone(); let mut sw = base.clone(); sw[inp] = sp["switch_value"].clone();
                    let probes = lb["probes"].as_array().cloned().unwrap_or_default();
                    let seen = |q: &Value| probes.iter().filter(|p| &p["i"] == q).map(|p| p["o"][o].clone()).collect::<Vec<Value>>();
                    let distinct = |v: &Vec<Value>| { let mut d: Vec<Value> = vec![]; for x in v { if !d.contains(x) { d.push(x.clone()); } } d };
                    let (vb, vs) = (seen(&base), seen(&sw)); let (db, ds) = (distinct(&vb), distinct(&vs));
                    if vb.len() < 3 || vs.len() < 3 || db.len() != 1 || ds.len() != 1 {
                        return Err(refuse("WITNESS_NOT_REPLICATED", json!({"base_observations": vb.len(), "switched_observations": vs.len(), "base_values": db, "switched_values": ds})));
                    }
                    db[0] != ds[0]
                }
                other => return Err(refuse("UNKNOWN_SPEC_OP", json!(other))),
            }
        }
        other => return Err(refuse("UNKNOWN_EVALUATOR", json!(other))),
    };
    Ok((key, evaluator, value, digests))
}

/// Comparison against a submission, for the direct receipt path: evaluate first, then look at what was asked.
async fn capture_claim_basis(a: &App, stream: uuid::Uuid, expect_true: bool, sub: &Value) -> Result<Value, (StatusCode, Json<Value>)> {
    let (key, evaluator, value, digests) = evaluate_claim(a, stream).await?;
    if sub["payload"]["capture_digests"] != Value::Object(digests.clone()) { return Err(refuse("STALE_EVIDENCE", json!({"latest": digests, "cited": sub["payload"]["capture_digests"]}))); }
    if value != expect_true { return Err(refuse("VALUE_DISAGREES", json!({"verifier_value": value, "requested": expect_true}))); }
    Ok(json!({"claim": key, "evaluator": evaluator, "verifier_value": value, "capture_digests": digests}))
}

/// Values at a path in a capture body: "array[].field", "array[]" or "key" (strings only).
fn path_values(body: &Value, path: &str) -> Vec<String> {
    if let Some((a, f)) = path.split_once("[].") {
        body[a].as_array().map(|v| v.iter().filter_map(|e| e[f].as_str().map(String::from)).collect()).unwrap_or_default()
    } else if let Some(a) = path.strip_suffix("[]") {
        body[a].as_array().map(|v| v.iter().filter_map(|e| e.as_str().map(String::from)).collect()).unwrap_or_default()
    } else { body[path].as_str().map(|s| vec![s.to_string()]).unwrap_or_default() }
}

/// Sweep: find unresolved capture claims with no receipt since their latest reopening (verify.needs_receipt), take the compiler's requested submission, recompute
/// independently, and record a signed receipt only where the verifier's own value agrees.
async fn sweep(State(a): S, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if let Err(e) = check_trigger(&a, &body, "sweep-capture-claims") { return e; }
    let rows = match a.db.query("select s.id, s.consequence_key from sem.settlements s join uap.capture_claims c using (consequence_key)
                                  where s.status::text = 'UNRESOLVED' and verify.needs_receipt(s.id)", &[]).await {
        Ok(r) => r, Err(e) => return refuse("RECORDS_UNAVAILABLE", json!(e.to_string())) };
    let (mut signed, mut refused) = (0, vec![]);
    for r in rows {
        let (stream, key): (uuid::Uuid, String) = (r.get(0), r.get(1));
        // 1. blind: compute our own value from the claim definition and evidence alone
        let (_, evaluator, value, digests) = match evaluate_claim(&a, stream).await {
            Ok(x) => x, Err((_, Json(v))) => { refused.push(json!({"claim": key, "reason": v["reason"], "detail": v["detail"]})); continue } };
        let mut scopes: Vec<&String> = digests.keys().collect(); scopes.sort();
        let evidence = scopes.iter().map(|k| format!("{}={}", k, digests[k.as_str()].as_str().unwrap_or(""))).collect::<Vec<_>>().join(",");
        // 2. commit it, signed, before the compiler's answer is read
        let mat = match a.db.query_one("select msg, sha256 from verify.blind_commitment_material($1, $2, $3)", &[&stream, &value, &evidence]).await {
            Ok(x) => x, Err(e) => { refused.push(json!({"claim": key, "reason": e.to_string()})); continue } };
        let (bmsg, bsha): (Vec<u8>, String) = (mat.get(0), mat.get(1));
        // the commitment must be stored by THIS key before anything else is read: no stored commitment, no receipt (D18)
        match a.db.execute("insert into verify.blind_commitments (stream_id, consequence_key, verifier_value, evidence, commitment_sha256, key_id, sig) values ($1,$2,$3,$4,$5,$6,$7) on conflict do nothing",
                           &[&stream, &key, &value, &evidence, &bsha, &a.key_id, &a.key.sign_hex(&bmsg)]).await {
            Ok(1) => {}
            Ok(_) => { refused.push(json!({"claim": key, "reason": "BLIND_COMMITMENT_NOT_STORED", "detail": {"blind_commitment": bsha}})); continue }
            Err(e) => { refused.push(json!({"claim": key, "reason": e.to_string()})); continue }
        }
        // 3. only now read the compiler's submission, and compare against the committed value
        let sub: Value = match a.db.query_one("select uap.claim_submission($1)", &[&key]).await { Ok(x) => x.get(0), Err(e) => { refused.push(json!({"claim": key, "reason": e.to_string()})); continue } };
        let Some(kind) = sub["event_kind"].as_str().map(String::from) else { refused.push(json!({"claim": key, "reason": "NO_SUBMISSION", "detail": sub})); continue };
        if sub["payload"]["capture_digests"] != Value::Object(digests.clone()) { refused.push(json!({"claim": key, "reason": "STALE_EVIDENCE", "blind_commitment": bsha})); continue }
        if kind.ends_with("SETTLED_TRUE") != value {
            refused.push(json!({"claim": key, "reason": "VALUE_DISAGREES_WITH_BLIND_COMMITMENT", "detail": {"verifier_value": value, "requested": kind, "blind_commitment": bsha}})); continue }
        let basis = json!({"claim": key, "evaluator": evaluator, "verifier_value": value, "capture_digests": digests, "blind_commitment": bsha});
        let row = match a.db.query_one("select p0.receipt_message($1, $2, p0.event_identity($3::jsonb)), p0.event_identity($3::jsonb)", &[&kind, &stream.to_string(), &sub]).await {
            Ok(x) => x, Err(e) => { refused.push(json!({"claim": key, "reason": e.to_string()})); continue } };
        let (msg, ident): (Vec<u8>, String) = (row.get(0), row.get(1));
        if let Err(e) = a.db.execute("insert into verify.kernel_receipts (stream_id, consequence_key, event_kind, identity_digest, key_id, sig, basis) values ($1,$2,$3,$4,$5,$6,$7)",
                                     &[&stream, &key, &kind, &ident, &a.key_id, &a.key.sign_hex(&msg), &basis]).await {
            refused.push(json!({"claim": key, "reason": e.to_string()})); continue }
        signed += 1;
    }
    (StatusCode::OK, Json(json!({"signed": signed, "refused": refused})))
}

async fn receipts(State(a): S, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if let Err(e) = check_trigger(&a, &body, "receipts") { return e; }
    let sub = body["submission"].clone();
    let (Some(kind), Some(stream)) = (sub["event_kind"].as_str(), sub["stream_id"].as_str().and_then(|s| uuid::Uuid::parse_str(s).ok())) else { return refuse("MALFORMED_SUBMISSION", json!(null)) };
    let basis = match kind {
        "node:PROPOSED->ADMITTED" => match evidence_basis(&a, stream, "PROPOSED").await { Ok(b) => b, Err(e) => return e },
        "node:ADMITTED->SUPERSEDED" => match evidence_basis(&a, stream, "ADMITTED").await { Ok(b) => b, Err(e) => return e },
        "conformance:OPEN->RECEIPTED" => {
            match a.db.query_opt("select state from p0.streams where stream_id = $1 and machine = 'conformance'", &[&stream]).await {
                Ok(Some(r)) if r.get::<_, String>(0) == "OPEN" => json!({"conformance_stream": "OPEN"}),
                Ok(Some(r)) => return refuse("STREAM_NOT_OPEN", json!(r.get::<_, String>(0))),
                Ok(None) => return refuse("UNKNOWN_STREAM", json!(stream.to_string())),
                Err(e) => return refuse("RECORDS_UNAVAILABLE", json!(e.to_string())),
            }
        }
        "settlement:UNRESOLVED->SETTLED_TRUE" | "settlement:UNRESOLVED->SETTLED_FALSE" =>
            match capture_claim_basis(&a, stream, kind.ends_with("SETTLED_TRUE"), &sub).await { Ok(b) => b, Err(e) => return e },
        other => return refuse("UNSUPPORTED_EVENT", json!(other)),
    };
    let msg = match a.db.query_one("select p0.receipt_message($1, $2, p0.event_identity($3::jsonb))", &[&kind, &stream.to_string(), &sub]).await {
        Ok(r) => r.get::<_, Vec<u8>>(0),
        Err(e) => return refuse("RECORDS_UNAVAILABLE", json!(e.to_string())),
    };
    (StatusCode::OK, Json(json!({"decision": "RECEIPT", "receipt": {"role": "VERIFIER", "key_id": a.key_id, "sig": a.key.sign_hex(&msg)}, "basis": basis})))
}
async fn pubkey(State(a): S) -> Json<Value> { Json(json!({"key_id": a.key_id, "role": "VERIFIER", "pubkey": a.key.public_hex()})) }
async fn health(State(a): S) -> (StatusCode, Json<Value>) {
    match a.db.query_one("select count(*) from p0.event_contracts", &[]).await {
        Ok(r) => (StatusCode::OK, Json(json!({"status": "ok", "contracts": r.get::<_, i64>(0)}))),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"status": "RECORDS_UNAVAILABLE", "detail": e.to_string()}))),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("keygen") {
        let k = Key::generate();
        println!("{}", json!({"role": "VERIFIER", "seed_hex_store_as_secret": k.seed_hex(), "pubkey_hex_enrol": k.public_hex()}));
        return Ok(());
    }
    let need = |k: &str| std::env::var(k).map_err(|_| anyhow::anyhow!("missing environment variable {k}"));
    eprintln!("verifierd: database TLS mode {}", p0_core::db::mode());
    let db = p0_core::db::Db::new(&need("DATABASE_URL")?).await?;
    let key = Key::from_seed_hex(&need("VERIFIER_KEY_SEED")?)?;
    let key_id = need("VERIFIER_KEY_ID")?;
    // refuse to run unless this key is the active VERIFIER key in p0.keys AND registered as a verifier in verify.keys:
    // a rotation that misses either registry fails here, loudly, at start (D16)
    let ok: bool = db.query_one("select exists (select 1 from p0.keys where key_id = $1 and role = 'VERIFIER' and status = 'active' and encode(pubkey, 'hex') = $2)
                                   and exists (select 1 from verify.keys where key_id = $1 and role = 'VERIFIER')", &[&key_id, &key.public_hex()]).await
        .map_err(|e| anyhow::anyhow!("cannot read this verifier's enrolment: {e}"))?.get(0);
    if !ok { anyhow::bail!("ENROLMENT_MISMATCH: key {key_id} ({}...) is not the active VERIFIER key in p0.keys and verify.keys", &key.public_hex()[..8]); }
    eprintln!("verifierd: key {key_id} matches its enrolment");
    let app = Arc::new(App { db, key, key_id,
                             trigger_pub: need("VERIFIER_TRIGGER_PUBKEY")?, nonces: std::sync::Mutex::new(std::collections::HashMap::new()) });
    let router = Router::new().route("/v1/receipts", post(receipts)).route("/v1/sweep-capture-claims", post(sweep)).route("/v1/pubkey", get(pubkey)).route("/v1/health", get(health)).with_state(app);
    axum::serve(tokio::net::TcpListener::bind(std::env::var("LISTEN").unwrap_or_else(|_| "0.0.0.0:8090".into())).await?, router).await?;
    Ok(())
}
