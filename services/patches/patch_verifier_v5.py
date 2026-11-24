import sys
p = sys.argv[1]; s = open(p).read()
def rep(a, b, n=1):
    global s
    assert s.count(a) == n, (a[:70], s.count(a)); s = s.replace(a, b)
rep('use p0_core::Key;', 'use p0_core::{verify_hex, Key};')
rep('struct App { db: tokio_postgres::Client, key: Key, key_id: String }',
    'struct App { db: tokio_postgres::Client, key: Key, key_id: String, trigger_pub: String, nonces: std::sync::Mutex<std::collections::HashMap<String, i64>> }')
rep('async fn evidence_basis(', '''/// Every request that can make the verifier work must carry a trigger signed by the root scheduler key pinned in this
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

async fn evidence_basis(''')
rep('''async fn sweep(State(a): S) -> (StatusCode, Json<Value>) {''', '''async fn sweep(State(a): S, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if let Err(e) = check_trigger(&a, &body, "sweep-capture-claims") { return e; }''')
rep('''    let sub = body["submission"].clone();''', '''    if let Err(e) = check_trigger(&a, &body, "receipts") { return e; }
    let sub = body["submission"].clone();''')
rep('''                             key_id: std::env::var("VERIFIER_KEY_ID").unwrap_or_else(|_| "verifier-1".into()) });''',
    '''                             key_id: std::env::var("VERIFIER_KEY_ID").unwrap_or_else(|_| "verifier-1".into()),
                             trigger_pub: need("VERIFIER_TRIGGER_PUBKEY")?, nonces: std::sync::Mutex::new(std::collections::HashMap::new()) });''')
open(p, 'w').write(s); print("patched")
