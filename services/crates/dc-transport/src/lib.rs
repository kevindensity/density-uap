//! gRPC transport for `SignedEnvelope` (contract density:core.signed_envelope/1).
//!
//! Security lives in `dc-envelope`; this crate only carries envelopes. The payload travels as `payload_jcs`, the
//! RFC 8785 bytes exactly as hashed and signed, and the receiver accepts them only if they are already canonical
//! (re-canonicalizing reproduces them byte for byte). That gives one property any language can check without a
//! JSON library: `payload_sha256 == sha256(payload_jcs)`.
pub mod pb {
    tonic::include_proto!("density.envelope.v1");
}

/// The compiled descriptor of `envelope.proto`, so tests can hold the wire contract still.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/envelope_fds.bin"));

use dc_contracts::SignedEnvelope;
use dc_envelope::{Keyring, Refusal};
use std::sync::Arc;
use tonic::{Request, Response, Status};

#[derive(Debug, PartialEq)]
pub enum WireRefusal { PayloadNotUtf8, PayloadNotJson(String), PayloadNotCanonical, Envelope(Refusal) }

impl WireRefusal {
    pub fn code(&self) -> String {
        match self {
            WireRefusal::PayloadNotUtf8 => "PAYLOAD_NOT_UTF8".into(),
            WireRefusal::PayloadNotJson(_) => "PAYLOAD_NOT_JSON".into(),
            WireRefusal::PayloadNotCanonical => "PAYLOAD_NOT_CANONICAL".into(),
            WireRefusal::Envelope(r) => match r {
                Refusal::NotAnEnvelope(_) => "NOT_AN_ENVELOPE", Refusal::DigestMismatch => "DIGEST_MISMATCH",
                Refusal::UnknownKey => "UNKNOWN_KEY", Refusal::SchemaNotAllowedForKey => "SCHEMA_NOT_ALLOWED_FOR_KEY",
                Refusal::BadSignature => "BAD_SIGNATURE", Refusal::PayloadNotCanonicalizable(_) => "PAYLOAD_NOT_CANONICALIZABLE",
            }.into(),
        }
    }
}

/// Sender side: the payload is written once, canonically, and those bytes are what travel.
pub fn to_wire(env: &SignedEnvelope) -> Result<pb::SignedEnvelope, String> {
    Ok(pb::SignedEnvelope {
        schema: env.schema.clone(), payload_jcs: dc_canonical::canonical(&env.payload)?.into_bytes(),
        payload_sha256: env.payload_sha256.clone(), issuer_key_id: env.issuer_key_id.clone(),
        issued_at: env.issued_at.clone(), signature: env.signature.clone(),
    })
}

/// Receiver side: strict UTF-8, strict JSON (duplicate keys refused), byte-exact canonical form, then the full
/// `dc-envelope` verification (recomputed digest, keyring, schema allowance, signature).
pub fn open_wire(w: &pb::SignedEnvelope, ring: &Keyring) -> Result<SignedEnvelope, WireRefusal> {
    let text = std::str::from_utf8(&w.payload_jcs).map_err(|_| WireRefusal::PayloadNotUtf8)?;
    let payload = dc_canonical::parse_strict(text).map_err(WireRefusal::PayloadNotJson)?;
    if dc_canonical::canonical(&payload).map_err(WireRefusal::PayloadNotJson)? != text { return Err(WireRefusal::PayloadNotCanonical); }
    let env = SignedEnvelope {
        schema: w.schema.clone(), payload, payload_sha256: w.payload_sha256.clone(), issuer_key_id: w.issuer_key_id.clone(),
        issued_at: w.issued_at.clone(), signature: w.signature.clone(),
    };
    dc_envelope::verify(&env, ring).map_err(WireRefusal::Envelope)?;
    Ok(env)
}

/// Where verified envelopes go. A sink sees only envelopes that passed `open_wire`.
pub trait Sink: Send + Sync + 'static {
    fn accept(&self, env: SignedEnvelope) -> Result<(), String>;
}

pub struct Exchange<S: Sink> { ring: Arc<Keyring>, sink: S }

#[tonic::async_trait]
impl<S: Sink> pb::envelope_exchange_server::EnvelopeExchange for Exchange<S> {
    async fn submit(&self, req: Request<pb::SignedEnvelope>) -> Result<Response<pb::Ack>, Status> {
        let w = req.into_inner();
        let ack = match open_wire(&w, &self.ring) {
            Err(r) => pb::Ack { decision: "REFUSED".into(), reason: r.code(), payload_sha256: String::new() },
            Ok(env) => {
                let d = env.payload_sha256.clone();
                match self.sink.accept(env) {
                    Ok(()) => pb::Ack { decision: "ACCEPTED".into(), reason: String::new(), payload_sha256: d },
                    Err(e) => pb::Ack { decision: "SINK_REJECTED".into(), reason: e, payload_sha256: d },
                }
            }
        };
        Ok(Response::new(ack))
    }
}

pub fn server<S: Sink>(ring: Keyring, sink: S) -> pb::envelope_exchange_server::EnvelopeExchangeServer<Exchange<S>> {
    pb::envelope_exchange_server::EnvelopeExchangeServer::new(Exchange { ring: Arc::new(ring), sink })
}
