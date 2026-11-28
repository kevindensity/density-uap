//! Signed envelopes between Density services (contract density:core.signed_envelope/1).
//! The signature covers a domain-separated message over the RFC 8785 digest of the payload, so it survives any
//! transport (gRPC, HTTP, a file) and any re-serialization; the receiver recomputes the digest and never trusts the
//! stated one. Verification happens here, in Rust, never in the database (Fabric and Atlas master, decision 1).
use dc_contracts::SignedEnvelope;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;
use std::collections::BTreeMap;

pub const DOMAIN: &str = "DENSITY-ENVELOPE/1";

fn message(schema: &str, digest: &str, key_id: &str, issued_at: &str) -> Vec<u8> {
    format!("{DOMAIN}|{schema}|{digest}|{key_id}|{issued_at}").into_bytes()
}

pub fn seal(schema: &str, payload: Value, key_id: &str, issued_at: &str, key: &SigningKey) -> Result<SignedEnvelope, String> {
    let digest = dc_canonical::digest_hex(&payload)?;
    let sig = key.sign(&message(schema, &digest, key_id, issued_at));
    Ok(SignedEnvelope { schema: schema.into(), payload, payload_sha256: digest, issuer_key_id: key_id.into(), issued_at: issued_at.into(), signature: hex::encode(sig.to_bytes()) })
}

/// Which keys may sign which schemas: key id -> (verifying key, schemas it may sign).
pub struct Keyring(pub BTreeMap<String, (VerifyingKey, Vec<String>)>);

#[derive(Debug, PartialEq)]
pub enum Refusal { NotAnEnvelope(String), DigestMismatch, UnknownKey, SchemaNotAllowedForKey, BadSignature, PayloadNotCanonicalizable(String) }

/// Verify wire text: strict parse (duplicate keys refused), contract shape, recomputed digest, keyring, signature.
pub fn open(wire: &str, ring: &Keyring) -> Result<SignedEnvelope, Refusal> {
    let v = dc_canonical::parse_strict(wire).map_err(Refusal::NotAnEnvelope)?;
    let env: SignedEnvelope = serde_json::from_value(v).map_err(|e| Refusal::NotAnEnvelope(e.to_string()))?;
    verify(&env, ring)?;
    Ok(env)
}

pub fn verify(env: &SignedEnvelope, ring: &Keyring) -> Result<(), Refusal> {
    let digest = dc_canonical::digest_hex(&env.payload).map_err(Refusal::PayloadNotCanonicalizable)?;
    if digest != env.payload_sha256 { return Err(Refusal::DigestMismatch); }
    let (vk, schemas) = ring.0.get(&env.issuer_key_id).ok_or(Refusal::UnknownKey)?;
    if !schemas.iter().any(|s| s == &env.schema) { return Err(Refusal::SchemaNotAllowedForKey); }
    let bytes = hex::decode(&env.signature).map_err(|_| Refusal::BadSignature)?;
    let sig = Signature::from_slice(&bytes).map_err(|_| Refusal::BadSignature)?;
    vk.verify_strict(&message(&env.schema, &digest, &env.issuer_key_id, &env.issued_at), &sig).map_err(|_| Refusal::BadSignature)
}
