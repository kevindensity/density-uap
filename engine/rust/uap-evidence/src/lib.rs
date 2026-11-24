//! Epistemic type system for the Universal Adaptive Port (Corollary 10).
//! Weakening is always available; strengthening exists only through `refine`,
//! which requires a receipt signed by a VERIFIER key distinct from the synthesizer
//! and bound to the same consequence and live class.
use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsequenceKey(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveClassHash(pub String);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyId(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRole { Synthesizer, Verifier }

/// Abstracts signature checking so the crate stays transport-agnostic.
pub trait VerifierRegistry {
    fn role(&self, key: &KeyId) -> Option<KeyRole>;
    fn signature_valid(&self, receipt: &RefinementReceipt) -> bool;
}

#[derive(Clone, Debug)]
pub struct RefinementReceipt {
    pub consequence: ConsequenceKey,
    pub live_class: LiveClassHash,
    /// Value the verifier found constant on the live class; None = not constant.
    pub constant_value: Option<String>,
    pub verifier: KeyId,
    pub synthesizer: KeyId,
    pub signature: Vec<u8>,
}

/// Not yet settled. The only way up is `refine`.
#[derive(Debug)]
pub struct Unresolved<T> { pub key: ConsequenceKey, pub live: LiveClassHash, _t: PhantomData<T> }
/// Settled on the live class. No public constructor.
#[derive(Debug)]
pub struct Settled<T> { key: ConsequenceKey, value: T, receipt: RefinementReceipt }
/// Definite "does not apply" - a value, not uncertainty (MECH-01 root cause 1).
#[derive(Debug, PartialEq, Eq)]
pub struct NotApplicable { pub key: ConsequenceKey }
/// No admissible channel bears on the consequence.
#[derive(Debug, PartialEq, Eq)]
pub struct Inconclusive { pub key: ConsequenceKey }

#[derive(Debug, PartialEq, Eq)]
pub enum RefineError { UnknownKey, NotAVerifier, SynthesizerSigned, BadSignature, WrongConsequence, WrongLiveClass, NotConstant, Unparseable }

impl<T> Unresolved<T> {
    pub fn new(key: ConsequenceKey, live: LiveClassHash) -> Self { Unresolved { key, live, _t: PhantomData } }
}

impl<T> Settled<T> {
    pub fn key(&self) -> &ConsequenceKey { &self.key }
    pub fn value(&self) -> &T { &self.value }
    pub fn receipt(&self) -> &RefinementReceipt { &self.receipt }
    /// Corollary 10(1): weakening is always sound.
    pub fn weaken(self, live: LiveClassHash) -> Unresolved<T> { Unresolved::new(self.key, live) }
}

/// The only constructor of `Settled<T>` (Corollary 10(2)).
pub fn refine<T: std::str::FromStr>(
    u: Unresolved<T>, receipt: RefinementReceipt, reg: &impl VerifierRegistry,
) -> Result<Settled<T>, (Unresolved<T>, RefineError)> {
    let fail = |u, e| Err((u, e));
    match (reg.role(&receipt.verifier), reg.role(&receipt.synthesizer)) {
        (None, _) | (_, None) => return fail(u, RefineError::UnknownKey),
        (Some(KeyRole::Verifier), Some(KeyRole::Synthesizer)) => {}
        (Some(KeyRole::Synthesizer), _) => return fail(u, RefineError::SynthesizerSigned),
        _ => return fail(u, RefineError::NotAVerifier),
    }
    if receipt.verifier == receipt.synthesizer { return fail(u, RefineError::SynthesizerSigned); }
    if !reg.signature_valid(&receipt) { return fail(u, RefineError::BadSignature); }
    if receipt.consequence != u.key { return fail(u, RefineError::WrongConsequence); }
    if receipt.live_class != u.live { return fail(u, RefineError::WrongLiveClass); }
    let Some(raw) = receipt.constant_value.clone() else { return fail(u, RefineError::NotConstant) };
    match raw.parse::<T>() {
        Ok(v) => Ok(Settled { key: u.key, value: v, receipt }),
        Err(_) => fail(u, RefineError::Unparseable),
    }
}

/// Actions require settled preconditions at the type level.
pub fn authorize_action<P>(pre: &Settled<P>, allowed: impl Fn(&P) -> bool) -> bool { allowed(pre.value()) }

#[cfg(test)]
mod tests {
    use super::*;
    struct Reg;
    impl VerifierRegistry for Reg {
        fn role(&self, k: &KeyId) -> Option<KeyRole> {
            match k.0.as_str() { "ver" => Some(KeyRole::Verifier), "syn" | "syn2" => Some(KeyRole::Synthesizer), _ => None }
        }
        fn signature_valid(&self, r: &RefinementReceipt) -> bool { r.signature == b"ok" }
    }
    fn rcpt(v: &str, s: &str, live: &str, val: Option<&str>, sig: &[u8]) -> RefinementReceipt {
        RefinementReceipt { consequence: ConsequenceKey("dep:qty->total".into()), live_class: LiveClassHash(live.into()),
            constant_value: val.map(|x| x.into()), verifier: KeyId(v.into()), synthesizer: KeyId(s.into()), signature: sig.to_vec() }
    }
    fn u() -> Unresolved<bool> { Unresolved::new(ConsequenceKey("dep:qty->total".into()), LiveClassHash("L1".into())) }

    #[test] fn valid_receipt_settles() {
        let s = refine(u(), rcpt("ver","syn","L1",Some("true"),b"ok"), &Reg).unwrap();
        assert!(*s.value()); assert!(authorize_action(&s, |v| *v));
    }
    #[test] fn synthesizer_cannot_self_certify() {
        assert_eq!(refine(u(), rcpt("syn2","syn","L1",Some("true"),b"ok"), &Reg).unwrap_err().1, RefineError::SynthesizerSigned);
        assert_eq!(refine(u(), rcpt("syn","syn","L1",Some("true"),b"ok"), &Reg).unwrap_err().1, RefineError::SynthesizerSigned);
    }
    #[test] fn wrong_live_class_refused() {
        assert_eq!(refine(u(), rcpt("ver","syn","L0",Some("true"),b"ok"), &Reg).unwrap_err().1, RefineError::WrongLiveClass);
    }
    #[test] fn non_constant_refused() {
        assert_eq!(refine(u(), rcpt("ver","syn","L1",None,b"ok"), &Reg).unwrap_err().1, RefineError::NotConstant);
    }
    #[test] fn bad_signature_refused() {
        assert_eq!(refine(u(), rcpt("ver","syn","L1",Some("true"),b"forged"), &Reg).unwrap_err().1, RefineError::BadSignature);
    }
    #[test] fn weakening_always_allowed() {
        let s = refine(u(), rcpt("ver","syn","L1",Some("true"),b"ok"), &Reg).unwrap();
        let w = s.weaken(LiveClassHash("L2".into()));
        assert_eq!(w.live.0, "L2");
    }
}
