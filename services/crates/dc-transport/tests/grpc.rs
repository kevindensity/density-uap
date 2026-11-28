//! Envelopes over real gRPC on localhost. Every refusal below is decided by dc-envelope or the canonical-bytes rule;
//! the transport adds no trust of its own.
use dc_contracts::SignedEnvelope;
use dc_envelope::{seal, Keyring};
use dc_transport::{pb, pb::envelope_exchange_client::EnvelopeExchangeClient, server, to_wire, Sink};
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const S: &str = "density:uac.capture_admission/1";
fn key(b: u8) -> SigningKey { SigningKey::from_bytes(&[b; 32]) }
fn ring() -> Keyring { Keyring(BTreeMap::from([("uacd-1".to_string(), (key(1).verifying_key(), vec![S.to_string()]))])) }
fn env() -> SignedEnvelope {
    seal(S, json!({"route": "public.domain", "subject": "x", "body": {"b": [1, 2.5, "é"], "a": 1.0}}), "uacd-1", "2026-11-28T03:00:00Z", &key(1)).unwrap()
}

#[derive(Clone, Default)]
struct Rec { got: Arc<Mutex<Vec<SignedEnvelope>>>, refuse: bool }
impl Sink for Rec {
    fn accept(&self, e: SignedEnvelope) -> Result<(), String> {
        if self.refuse { return Err("SINK_SAYS_NO".into()); }
        self.got.lock().unwrap().push(e); Ok(())
    }
}

async fn start(sink: Rec) -> EnvelopeExchangeClient<tonic::transport::Channel> {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(tonic::transport::Server::builder().add_service(server(ring(), sink))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(l)));
    EnvelopeExchangeClient::connect(format!("http://{addr}")).await.unwrap()
}
async fn send(c: &mut EnvelopeExchangeClient<tonic::transport::Channel>, w: pb::SignedEnvelope) -> pb::Ack { c.submit(w).await.unwrap().into_inner() }

#[tokio::test] async fn genuine_envelope_is_accepted_and_delivered_intact() {
    let r = Rec::default(); let mut c = start(r.clone()).await; let e = env();
    let a = send(&mut c, to_wire(&e).unwrap()).await;
    assert_eq!((a.decision.as_str(), a.payload_sha256.as_str()), ("ACCEPTED", e.payload_sha256.as_str()));
    assert_eq!(canon(&r.got.lock().unwrap()[0]), canon(&e));
}
#[tokio::test] async fn digest_is_sha256_of_the_wire_bytes() {
    // any language can check this without a JSON library
    let w = to_wire(&env()).unwrap();
    assert_eq!(hex(&Sha256::digest(&w.payload_jcs)), w.payload_sha256);
}
#[tokio::test] async fn changed_payload_is_refused() {
    let r = Rec::default(); let mut c = start(r.clone()).await; let mut w = to_wire(&env()).unwrap();
    w.payload_jcs = String::from_utf8(w.payload_jcs).unwrap().replace("\"x\"", "\"y\"").into_bytes();
    assert_eq!(send(&mut c, w).await.reason, "DIGEST_MISMATCH"); assert!(r.got.lock().unwrap().is_empty());
}
#[tokio::test] async fn changed_payload_with_recomputed_digest_is_refused() {
    let mut c = start(Rec::default()).await; let mut w = to_wire(&env()).unwrap();
    w.payload_jcs = String::from_utf8(w.payload_jcs).unwrap().replace("\"x\"", "\"y\"").into_bytes();
    w.payload_sha256 = hex(&Sha256::digest(&w.payload_jcs));
    assert_eq!(send(&mut c, w).await.reason, "BAD_SIGNATURE");
}
#[tokio::test] async fn non_canonical_bytes_are_refused_even_when_equivalent() {
    // same JSON value, different bytes: refused, so the signed digest is always the hash of what travelled
    let mut c = start(Rec::default()).await; let mut w = to_wire(&env()).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&w.payload_jcs).unwrap();
    w.payload_jcs = serde_json::to_vec_pretty(&v).unwrap();
    assert_eq!(send(&mut c, w).await.reason, "PAYLOAD_NOT_CANONICAL");
}
#[tokio::test] async fn duplicate_key_smuggling_in_payload_bytes_is_refused() {
    let mut c = start(Rec::default()).await; let mut w = to_wire(&env()).unwrap();
    let t = String::from_utf8(w.payload_jcs).unwrap();
    w.payload_jcs = format!("{{\"subject\":\"evil\",{}", &t[1..]).into_bytes();
    assert_eq!(send(&mut c, w).await.reason, "PAYLOAD_NOT_JSON");
}
#[tokio::test] async fn invalid_utf8_is_refused() {
    let mut c = start(Rec::default()).await; let mut w = to_wire(&env()).unwrap(); w.payload_jcs.push(0xff);
    assert_eq!(send(&mut c, w).await.reason, "PAYLOAD_NOT_UTF8");
}
#[tokio::test] async fn unknown_key_is_refused() {
    let mut c = start(Rec::default()).await; let mut w = to_wire(&env()).unwrap(); w.issuer_key_id = "other".into();
    assert_eq!(send(&mut c, w).await.reason, "UNKNOWN_KEY");
}
#[tokio::test] async fn schema_not_allowed_for_key_is_refused() {
    let mut c = start(Rec::default()).await; let mut w = to_wire(&env()).unwrap(); w.schema = "density:core.signed_envelope/1".into();
    assert_eq!(send(&mut c, w).await.reason, "SCHEMA_NOT_ALLOWED_FOR_KEY");
}
#[tokio::test] async fn wrong_signer_is_refused() {
    let mut c = start(Rec::default()).await;
    let e = seal(S, json!({"k": 1}), "uacd-1", "t", &key(2)).unwrap();
    assert_eq!(send(&mut c, to_wire(&e).unwrap()).await.reason, "BAD_SIGNATURE");
}
#[tokio::test] async fn changed_timestamp_is_refused() {
    let mut c = start(Rec::default()).await; let mut w = to_wire(&env()).unwrap(); w.issued_at = "2027-01-01T00:00:00Z".into();
    assert_eq!(send(&mut c, w).await.reason, "BAD_SIGNATURE");
}
#[tokio::test] async fn sink_rejection_is_reported_and_nothing_is_kept() {
    let r = Rec { refuse: true, ..Default::default() }; let mut c = start(r.clone()).await;
    let a = send(&mut c, to_wire(&env()).unwrap()).await;
    assert_eq!((a.decision.as_str(), a.reason.as_str()), ("SINK_REJECTED", "SINK_SAYS_NO")); assert!(r.got.lock().unwrap().is_empty());
}
#[tokio::test] async fn one_envelope_crosses_json_and_grpc_unchanged() {
    // sealed once; opened from JSON text by dc-envelope and from gRPC bytes by this crate: identical result
    let r = Rec::default(); let mut c = start(r.clone()).await; let e = env();
    let from_json = dc_envelope::open(&serde_json::to_string(&e).unwrap(), &ring()).unwrap();
    assert_eq!(send(&mut c, to_wire(&from_json).unwrap()).await.decision, "ACCEPTED");
    assert_eq!(canon(&r.got.lock().unwrap()[0]), canon(&from_json));
}

/// Envelopes compared as signed: canonical payload text plus every other field. (1.0 and 1 are one number in
/// RFC 8785; the receiver delivers the canonical form.)
fn canon(e: &SignedEnvelope) -> (String, String, String, String, String, String) {
    (e.schema.clone(), dc_canonical::canonical(&e.payload).unwrap(), e.payload_sha256.clone(), e.issuer_key_id.clone(), e.issued_at.clone(), e.signature.clone())
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
