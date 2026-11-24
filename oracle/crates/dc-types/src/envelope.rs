//! The common envelope and the identity, epoch, validity and standing types it carries.

use crate::canonical::{digest, CanonicalError, Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObjectId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TenantId(pub String);

/// Digest-pinned typed reference: a superseded digest resolves to the old version, never the new one.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Ref<K> {
    pub kind: String,
    pub id: ObjectId,
    pub digest: Digest,
    #[serde(skip)]
    _k: PhantomData<fn() -> K>,
}
impl<K> Ref<K> {
    pub fn new(kind: &str, id: ObjectId, digest: Digest) -> Self { Self { kind: kind.into(), id, digest, _k: PhantomData } }
}
impl<K> Clone for Ref<K> { fn clone(&self) -> Self { Self::new(&self.kind, self.id.clone(), self.digest) } }
impl<K> PartialEq for Ref<K> { fn eq(&self, o: &Self) -> bool { self.kind == o.kind && self.id == o.id && self.digest == o.digest } }
impl<K> Eq for Ref<K> {}

/// Processes with distinct login roles and (for two of them) distinct keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Process { EdgeIngress, Uacd, GenesisSandbox, Uapd, Verifierd, P0d, Noded, EffectGateway }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerRef { pub process: Process, pub key_id: Option<String> }

/// Constitutive epochs per domain (source, schema, authority, topology, semantic ...).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochVector(pub BTreeMap<String, u64>);
impl EpochVector {
    /// Two cuts are assemblable only if no shared domain disagrees (K20).
    pub fn compatible(&self, other: &Self) -> bool {
        self.0.iter().all(|(k, v)| other.0.get(k).map_or(true, |w| w == v))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalCut { pub frontier: BTreeMap<String, u64> }

/// Validity bound to generations and semantic exit predicates, not to a timestamp alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidityEnvelope {
    pub observed_at_ms: i64,
    pub not_after_ms: Option<i64>,
    pub generations: BTreeMap<String, u64>,
    pub dependency_root: Digest,
    pub exit_predicates: Vec<String>,
}
impl ValidityEnvelope {
    /// Current only if not expired and every recorded generation still matches.
    pub fn is_current(&self, now_ms: i64, generations_now: &BTreeMap<String, u64>, fired_exits: &[String]) -> bool {
        self.not_after_ms.map_or(true, |t| now_ms <= t)
            && self.generations.iter().all(|(k, v)| generations_now.get(k) == Some(v))
            && !self.exit_predicates.iter().any(|p| fired_exits.contains(p))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Standing { Candidate, Settled { receipt: ObjectId }, Unresolved, Stale, Revoked }

impl Standing {
    /// Weakening transitions are always allowed; strengthening needs a receipt (K10).
    pub fn is_weakening(from: &Standing, to: &Standing) -> bool {
        matches!((from, to), (_, Standing::Unresolved) | (_, Standing::Stale) | (_, Standing::Revoked))
            && !matches!(from, Standing::Revoked)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplayClass { ByteIdentical, Distributional { test: String, tolerance: f64 } }

/// Unit type that carries no grant, by construction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoAuthority;

/// Core envelope fields. Extensions add fields in later schema minors only.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConstitutionalEnvelope<T> {
    pub object_id: ObjectId,
    pub schema: String,
    pub tenant: TenantId,
    pub issuer: IssuerRef,
    pub payload: T,
    pub scope: ObjectId,
    pub evidence_roots: Vec<Digest>,
    pub dependency_root: Digest,
    pub causal_cut: CausalCut,
    pub epochs: EpochVector,
    pub validity: ValidityEnvelope,
    pub standing: Standing,
    pub supersedes: Option<ObjectId>,
    pub replay_class: ReplayClass,
}

impl<T: Serialize> ConstitutionalEnvelope<T> {
    /// Digest of the canonical envelope; signatures live outside it (see `Signed`).
    pub fn digest(&self) -> Result<Digest, CanonicalError> { digest(self) }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation { pub signer: IssuerRef, pub signature_hex: String }

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Signed<T> { pub envelope: ConstitutionalEnvelope<T>, pub signatures: Vec<Attestation> }

/// Every proposal enters the system as a candidate with no authority (K02).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Candidate<T> { pub body: T, pub authority: NoAuthority }
impl<T> Candidate<T> { pub fn new(body: T) -> Self { Self { body, authority: NoAuthority } } }

#[cfg(test)]
mod tests {
    use super::*;

    fn validity() -> ValidityEnvelope {
        ValidityEnvelope { observed_at_ms: 0, not_after_ms: Some(100), generations: [("schema".into(), 3)].into(), dependency_root: Digest([0; 32]), exit_predicates: vec!["owner_changed".into()] }
    }
    #[test]
    fn validity_tracks_generations_and_exits() {
        let v = validity();
        let gens: BTreeMap<String, u64> = [("schema".into(), 3)].into();
        assert!(v.is_current(50, &gens, &[]));
        assert!(!v.is_current(101, &gens, &[]));
        assert!(!v.is_current(50, &[("schema".into(), 4)].into(), &[]));
        assert!(!v.is_current(50, &gens, &["owner_changed".into()]));
    }
    #[test]
    fn epoch_compatibility() {
        let a = EpochVector([("schema".into(), 2), ("authority".into(), 5)].into());
        let b = EpochVector([("schema".into(), 2)].into());
        let c = EpochVector([("schema".into(), 3)].into());
        assert!(a.compatible(&b));
        assert!(!a.compatible(&c));
    }
    #[test]
    fn weakening_is_free_and_revoked_is_terminal() {
        assert!(Standing::is_weakening(&Standing::Settled { receipt: ObjectId("r".into()) }, &Standing::Stale));
        assert!(!Standing::is_weakening(&Standing::Candidate, &Standing::Settled { receipt: ObjectId("r".into()) }));
        assert!(!Standing::is_weakening(&Standing::Revoked, &Standing::Stale));
    }
    #[test]
    fn envelope_digest_excludes_signatures() {
        let env = ConstitutionalEnvelope { object_id: ObjectId("o1".into()), schema: "uap.claim/1.0".into(), tenant: TenantId("t".into()), issuer: IssuerRef { process: Process::Uapd, key_id: None }, payload: 7u32, scope: ObjectId("s".into()), evidence_roots: vec![], dependency_root: Digest([1; 32]), causal_cut: CausalCut::default(), epochs: EpochVector::default(), validity: validity(), standing: Standing::Candidate, supersedes: None, replay_class: ReplayClass::ByteIdentical };
        let d1 = env.digest().unwrap();
        let signed = Signed { envelope: env.clone(), signatures: vec![Attestation { signer: IssuerRef { process: Process::Verifierd, key_id: Some("k".into()) }, signature_hex: "ab".into() }] };
        assert_eq!(signed.envelope.digest().unwrap(), d1);
    }
}
