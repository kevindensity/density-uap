use dc_envelope::*;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::collections::BTreeMap;

const S: &str = "density:uac.capture_admission/1";
fn key(b: u8) -> SigningKey { SigningKey::from_bytes(&[b; 32]) }
fn ring() -> Keyring { Keyring(BTreeMap::from([("uacd-1".to_string(), (key(1).verifying_key(), vec![S.to_string()]))])) }
fn sealed() -> String {
    serde_json::to_string(&seal(S, json!({"route": "public.domain", "scope": "5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003", "subject": "x", "body": {"a": 1.0}, "summary": {}}),
        "uacd-1", "2026-11-26T12:00:00Z", &key(1)).unwrap()).unwrap()
}
fn tamper(f: impl Fn(&mut serde_json::Value)) -> String { let mut v: serde_json::Value = serde_json::from_str(&sealed()).unwrap(); f(&mut v); v.to_string() }

#[test] fn genuine_envelope_opens() { assert!(open(&sealed(), &ring()).is_ok()); }
#[test] fn reserialized_payload_still_opens() {
    // reordered keys and 1.0 written as 1: same canonical bytes, same digest, same signature
    assert!(open(&tamper(|v| v["payload"]["body"] = json!({"a": 1})), &ring()).is_ok());
}
#[test] fn changed_payload_is_refused() { assert_eq!(open(&tamper(|v| v["payload"]["subject"] = json!("y")), &ring()).unwrap_err(), Refusal::DigestMismatch); }
#[test] fn digest_swapped_with_payload_is_refused() {
    let w = tamper(|v| { v["payload"]["subject"] = json!("y"); v["payload_sha256"] = json!(dc_canonical::digest_hex(&v["payload"]).unwrap()); });
    assert_eq!(open(&w, &ring()).unwrap_err(), Refusal::BadSignature);
}
#[test] fn unknown_key_is_refused() { assert_eq!(open(&tamper(|v| v["issuer_key_id"] = json!("other")), &ring()).unwrap_err(), Refusal::UnknownKey); }
#[test] fn key_not_allowed_for_schema_is_refused() { assert_eq!(open(&tamper(|v| v["schema"] = json!("density:core.signed_envelope/1")), &ring()).unwrap_err(), Refusal::SchemaNotAllowedForKey); }
#[test] fn wrong_signer_is_refused() {
    let w = serde_json::to_string(&seal(S, json!({"k": 1}), "uacd-1", "t", &key(2)).unwrap()).unwrap();
    assert_eq!(open(&w, &ring()).unwrap_err(), Refusal::BadSignature);
}
#[test] fn changed_timestamp_is_refused() { assert_eq!(open(&tamper(|v| v["issued_at"] = json!("2027-01-01T00:00:00Z")), &ring()).unwrap_err(), Refusal::BadSignature); }
#[test] fn duplicate_key_smuggling_is_refused() {
    let w = sealed(); let i = w.find("\"payload\"").unwrap();
    let smuggled = format!("{}\"payload\":{{\"evil\":true}},{}", &w[..i], &w[i..]);
    assert!(matches!(open(&smuggled, &ring()).unwrap_err(), Refusal::NotAnEnvelope(_)));
}
#[test] fn extra_field_is_refused() { assert!(matches!(open(&tamper(|v| v["note"] = json!(1)), &ring()).unwrap_err(), Refusal::NotAnEnvelope(_))); }
