import sys
p = sys.argv[1]; s = open(p).read()
def rep(a, b):
    global s
    assert s.count(a) == 1, ("anchor", a[:70], s.count(a)); s = s.replace(a, b)
# 1. evaluation, with no access to the compiler's submission
rep('async fn capture_claim_basis(a: &App, stream: uuid::Uuid, expect_true: bool, sub: &Value) -> Result<Value, (StatusCode, Json<Value>)> {',
    '/// Blind evaluation: the claim\'s value from its registered definition and the latest evidence ONLY. It never sees the\n'
    '/// compiler\'s submission, so the verifier\'s answer is fixed before the compiler\'s answer is read.\n'
    'async fn evaluate_claim(a: &App, stream: uuid::Uuid) -> Result<(String, String, bool, serde_json::Map<String, Value>), (StatusCode, Json<Value>)> {')
rep('    if sub["payload"]["capture_digests"] != Value::Object(digests.clone()) { return Err(refuse("STALE_EVIDENCE", json!({"latest": digests, "cited": sub["payload"]["capture_digests"]}))); }\n', '')
rep('''    if value != expect_true { return Err(refuse("VALUE_DISAGREES", json!({"verifier_value": value, "requested": expect_true}))); }
    Ok(json!({"claim": key, "evaluator": evaluator, "verifier_value": value, "capture_digests": digests}))
}''', '''    Ok((key, evaluator, value, digests))
}

/// Comparison against a submission, for the direct receipt path: evaluate first, then look at what was asked.
async fn capture_claim_basis(a: &App, stream: uuid::Uuid, expect_true: bool, sub: &Value) -> Result<Value, (StatusCode, Json<Value>)> {
    let (key, evaluator, value, digests) = evaluate_claim(a, stream).await?;
    if sub["payload"]["capture_digests"] != Value::Object(digests.clone()) { return Err(refuse("STALE_EVIDENCE", json!({"latest": digests, "cited": sub["payload"]["capture_digests"]}))); }
    if value != expect_true { return Err(refuse("VALUE_DISAGREES", json!({"verifier_value": value, "requested": expect_true}))); }
    Ok(json!({"claim": key, "evaluator": evaluator, "verifier_value": value, "capture_digests": digests}))
}''')
# 2. the sweep: evaluate, sign and commit, and only then read the compiler's submission
rep('''        let sub: Value = match a.db.query_one("select uap.claim_submission($1)", &[&key]).await { Ok(x) => x.get(0), Err(e) => { refused.push(json!({"claim": key, "reason": e.to_string()})); continue } };
        let Some(kind) = sub["event_kind"].as_str().map(String::from) else { refused.push(json!({"claim": key, "reason": "NO_SUBMISSION"})); continue };
        let basis = match capture_claim_basis(&a, stream, kind.ends_with("SETTLED_TRUE"), &sub).await {
            Ok(b) => b, Err((_, Json(v))) => { refused.push(json!({"claim": key, "reason": v["reason"], "detail": v["detail"]})); continue } };''',
'''        // 1. blind: compute our own value from the claim definition and evidence alone
        let (_, evaluator, value, digests) = match evaluate_claim(&a, stream).await {
            Ok(x) => x, Err((_, Json(v))) => { refused.push(json!({"claim": key, "reason": v["reason"], "detail": v["detail"]})); continue } };
        let mut scopes: Vec<&String> = digests.keys().collect(); scopes.sort();
        let evidence = scopes.iter().map(|k| format!("{}={}", k, digests[k.as_str()].as_str().unwrap_or(""))).collect::<Vec<_>>().join(",");
        // 2. commit it, signed, before the compiler's answer is read
        let mat = match a.db.query_one("select msg, sha256 from verify.blind_commitment_material($1, $2, $3)", &[&stream, &value, &evidence]).await {
            Ok(x) => x, Err(e) => { refused.push(json!({"claim": key, "reason": e.to_string()})); continue } };
        let (bmsg, bsha): (Vec<u8>, String) = (mat.get(0), mat.get(1));
        if let Err(e) = a.db.execute("insert into verify.blind_commitments (stream_id, consequence_key, verifier_value, evidence, commitment_sha256, key_id, sig) values ($1,$2,$3,$4,$5,$6,$7) on conflict do nothing",
                                     &[&stream, &key, &value, &evidence, &bsha, &a.key_id, &a.key.sign_hex(&bmsg)]).await {
            refused.push(json!({"claim": key, "reason": e.to_string()})); continue }
        // 3. only now read the compiler's submission, and compare against the committed value
        let sub: Value = match a.db.query_one("select uap.claim_submission($1)", &[&key]).await { Ok(x) => x.get(0), Err(e) => { refused.push(json!({"claim": key, "reason": e.to_string()})); continue } };
        let Some(kind) = sub["event_kind"].as_str().map(String::from) else { refused.push(json!({"claim": key, "reason": "NO_SUBMISSION", "detail": sub})); continue };
        if sub["payload"]["capture_digests"] != Value::Object(digests.clone()) { refused.push(json!({"claim": key, "reason": "STALE_EVIDENCE", "blind_commitment": bsha})); continue }
        if kind.ends_with("SETTLED_TRUE") != value {
            refused.push(json!({"claim": key, "reason": "VALUE_DISAGREES_WITH_BLIND_COMMITMENT", "detail": {"verifier_value": value, "requested": kind, "blind_commitment": bsha}})); continue }
        let basis = json!({"claim": key, "evaluator": evaluator, "verifier_value": value, "capture_digests": digests, "blind_commitment": bsha});''')
open(p, 'w').write(s); print("patched")
