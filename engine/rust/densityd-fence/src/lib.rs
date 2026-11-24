//! Hardened densityd certificate gate.
//! Closes the replay gap found in D1 v1.3 (`single_use` parsed but never enforced,
//! no nonce ledger, subject binding and effect bounds unchecked, single key).
//! Order of checks: hash -> k-of-n signatures -> scope (org, domain, epoch, subject)
//! -> validity window -> effect bounds -> durable single-use nonce consumption.
//! The nonce is persisted (fsync) BEFORE the caller may perform any effect.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePayload {
    pub certificate_id: String,
    pub nonce: String,
    pub organization_id: String,
    pub authority_domain_id: String,
    pub subject_binding_id: String,
    pub geometry_epoch_id: String,
    pub effect_class_id: String,
    pub permitted_effect: serde_json::Value,
    pub valid_from_unix: i64,
    pub expires_at_unix: i64,
    pub single_use: bool,
}

pub struct Envelope {
    pub canonical_payload_json: Vec<u8>,
    pub payload_sha256: String,
    pub signatures: Vec<(usize, Vec<u8>)>, // (key index, signature bytes)
}

pub struct Expect<'a> {
    pub org: &'a str, pub domain: &'a str, pub epoch: &'a str, pub subject: &'a str,
    pub effect_class: &'a str, pub now_unix: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    HashMismatch, QuorumNotMet, Malformed, OrgMismatch, DomainMismatch, EpochMismatch,
    SubjectMismatch, OutsideWindow, EffectClassMismatch, EffectOutOfBounds, NotSingleUse,
    NonceReplay, LedgerIo,
}

/// Durable append-only single-use ledger. A nonce is consumed by writing and fsyncing
/// a line; a crash after fsync leaves it consumed (safe), a crash before leaves it unused.
pub struct NonceLedger { path: PathBuf, seen: HashSet<String> }

impl NonceLedger {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut seen = HashSet::new();
        if path.exists() {
            for line in BufReader::new(File::open(path)?).lines() { seen.insert(line?); }
        }
        Ok(NonceLedger { path: path.to_path_buf(), seen })
    }
    fn consume(&mut self, nonce: &str) -> Result<(), Refusal> {
        if self.seen.contains(nonce) { return Err(Refusal::NonceReplay); }
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path).map_err(|_| Refusal::LedgerIo)?;
        writeln!(f, "{nonce}").map_err(|_| Refusal::LedgerIo)?;
        f.sync_all().map_err(|_| Refusal::LedgerIo)?;
        self.seen.insert(nonce.to_string());
        Ok(())
    }
}

/// k-of-n verification over distinct registered keys, then scope, window, bounds, nonce.
pub fn verify_and_consume(
    env: &Envelope, keys: &[VerifyingKey], k: usize, expect: &Expect,
    bounds: impl Fn(&serde_json::Value) -> bool, ledger: &mut NonceLedger,
) -> Result<CertificatePayload, Refusal> {
    if hex::encode(Sha256::digest(&env.canonical_payload_json)) != env.payload_sha256 { return Err(Refusal::HashMismatch); }
    let mut ok = HashSet::new();
    for (idx, sig) in &env.signatures {
        if let (Some(key), Ok(s)) = (keys.get(*idx), Signature::from_slice(sig)) {
            if key.verify(&env.canonical_payload_json, &s).is_ok() { ok.insert(*idx); }
        }
    }
    if ok.len() < k { return Err(Refusal::QuorumNotMet); }
    let p: CertificatePayload = serde_json::from_slice(&env.canonical_payload_json).map_err(|_| Refusal::Malformed)?;
    if p.organization_id != expect.org { return Err(Refusal::OrgMismatch); }
    if p.authority_domain_id != expect.domain { return Err(Refusal::DomainMismatch); }
    if p.geometry_epoch_id != expect.epoch { return Err(Refusal::EpochMismatch); }
    if p.subject_binding_id != expect.subject { return Err(Refusal::SubjectMismatch); }
    if expect.now_unix < p.valid_from_unix || expect.now_unix >= p.expires_at_unix { return Err(Refusal::OutsideWindow); }
    if p.effect_class_id != expect.effect_class { return Err(Refusal::EffectClassMismatch); }
    if !bounds(&p.permitted_effect) { return Err(Refusal::EffectOutOfBounds); }
    if !p.single_use { return Err(Refusal::NotSingleUse); } // policy: every actuating certificate is single-use
    ledger.consume(&p.nonce)?;
    Ok(p)
}

/// Receiver-owned fence (CEM-TRUST EFFECT-02): one ledger at the destination, epoch-fenced owners.
#[derive(Default)]
pub struct ReceiverFence { pub owner_epoch: u64, pub effects: std::collections::HashMap<String, String> }
#[derive(Debug, PartialEq, Eq)]
pub enum FenceOutcome { Committed, AlreadyCommitted }
impl ReceiverFence {
    pub fn apply(&mut self, epoch: u64, action: &str, payload: &str) -> Result<FenceOutcome, &'static str> {
        if epoch != self.owner_epoch { return Err("STALE_OWNER"); }
        match self.effects.get(action) {
            Some(p) if p == payload => Ok(FenceOutcome::AlreadyCommitted),
            Some(_) => Err("PAYLOAD_CONFLICT"),
            None => { self.effects.insert(action.into(), payload.into()); Ok(FenceOutcome::Committed) }
        }
    }
    pub fn transfer(&mut self) -> u64 { self.owner_epoch += 1; self.owner_epoch }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keys() -> Vec<SigningKey> { (1u8..=4).map(|i| SigningKey::from_bytes(&[i; 32])).collect() }
    fn payload(nonce: &str, single: bool, amount: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "certificateId":"c1","nonce":nonce,"organizationId":"org","authorityDomainId":"dom",
            "subjectBindingId":"subj","geometryEpochId":"ep","effectClassId":"SET_LIMIT",
            "permittedEffect":{"limit":amount},"validFromUnix":100,"expiresAtUnix":200,"singleUse":single})).unwrap()
    }
    fn env(p: Vec<u8>, signers: &[usize]) -> Envelope {
        let ks = keys();
        let sigs = signers.iter().map(|&i| (i, ks[i].sign(&p).to_bytes().to_vec())).collect();
        Envelope { payload_sha256: hex::encode(Sha256::digest(&p)), canonical_payload_json: p, signatures: sigs }
    }
    fn exp(now: i64) -> Expect<'static> { Expect { org:"org", domain:"dom", epoch:"ep", subject:"subj", effect_class:"SET_LIMIT", now_unix: now } }
    fn vks() -> Vec<VerifyingKey> { keys().iter().map(|k| k.verifying_key()).collect() }
    fn bounds(v: &serde_json::Value) -> bool { v["limit"].as_i64().map_or(false, |l| (0..=1000).contains(&l)) }

    #[test] fn valid_certificate_consumed_once_then_replay_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut led = NonceLedger::open(&dir.path().join("nonces")).unwrap();
        let e = env(payload("n1", true, 500), &[0, 1, 2]);
        assert!(verify_and_consume(&e, &vks(), 3, &exp(150), bounds, &mut led).is_ok());
        assert_eq!(verify_and_consume(&e, &vks(), 3, &exp(150), bounds, &mut led).unwrap_err(), Refusal::NonceReplay);
    }
    #[test] fn replay_refused_after_restart() {
        let dir = tempfile::tempdir().unwrap(); let path = dir.path().join("nonces");
        let e = env(payload("n2", true, 500), &[0, 1, 2]);
        { let mut led = NonceLedger::open(&path).unwrap(); verify_and_consume(&e, &vks(), 3, &exp(150), bounds, &mut led).unwrap(); }
        let mut led2 = NonceLedger::open(&path).unwrap();
        assert_eq!(verify_and_consume(&e, &vks(), 3, &exp(150), bounds, &mut led2).unwrap_err(), Refusal::NonceReplay);
    }
    #[test] fn quorum_subject_bounds_window_and_single_use_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let mut led = NonceLedger::open(&dir.path().join("nonces")).unwrap();
        assert_eq!(verify_and_consume(&env(payload("a", true, 500), &[0, 1]), &vks(), 3, &exp(150), bounds, &mut led).unwrap_err(), Refusal::QuorumNotMet);
        assert_eq!(verify_and_consume(&env(payload("b", true, 500), &[0, 0, 0]), &vks(), 3, &exp(150), bounds, &mut led).unwrap_err(), Refusal::QuorumNotMet);
        let mut x = exp(150); x.subject = "other";
        assert_eq!(verify_and_consume(&env(payload("c", true, 500), &[0, 1, 2]), &vks(), 3, &x, bounds, &mut led).unwrap_err(), Refusal::SubjectMismatch);
        assert_eq!(verify_and_consume(&env(payload("d", true, 5000), &[0, 1, 2]), &vks(), 3, &exp(150), bounds, &mut led).unwrap_err(), Refusal::EffectOutOfBounds);
        assert_eq!(verify_and_consume(&env(payload("e", true, 500), &[0, 1, 2]), &vks(), 3, &exp(250), bounds, &mut led).unwrap_err(), Refusal::OutsideWindow);
        assert_eq!(verify_and_consume(&env(payload("f", false, 500), &[0, 1, 2]), &vks(), 3, &exp(150), bounds, &mut led).unwrap_err(), Refusal::NotSingleUse);
        let mut e = env(payload("g", true, 500), &[0, 1, 2]); e.canonical_payload_json[5] ^= 1;
        assert_eq!(verify_and_consume(&e, &vks(), 3, &exp(150), bounds, &mut led).unwrap_err(), Refusal::HashMismatch);
    }
    #[test] fn negative_control_two_local_ledgers_duplicate_effect() {
        // Owner A and owner B each keep their own idempotency set; ownership moves A -> B
        // after A committed but before A's acknowledgement reached B.
        let mut world_effects = 0;
        let mut ledger_a: HashSet<&str> = HashSet::new();
        let ledger_b: HashSet<&str> = HashSet::new();
        if ledger_a.insert("act-1") { world_effects += 1; }      // A executes, ACK lost
        let mut ledger_b = ledger_b;
        if ledger_b.insert("act-1") { world_effects += 1; }      // B retries: its ledger is empty
        assert_eq!(world_effects, 2, "independent local ledgers duplicate the effect");
    }
    #[test] fn receiver_fence_prevents_duplicate_across_owner_transfer() {
        let mut f = ReceiverFence::default();
        assert_eq!(f.apply(0, "act-1", "h1"), Ok(FenceOutcome::Committed)); // A executes, ACK lost
        let e = f.transfer();                                               // B takes ownership
        assert_eq!(f.apply(0, "act-2", "h2"), Err("STALE_OWNER"));          // A is fenced
        assert_eq!(f.apply(e, "act-1", "h1"), Ok(FenceOutcome::AlreadyCommitted)); // B retries safely
        assert_eq!(f.apply(e, "act-1", "hX"), Err("PAYLOAD_CONFLICT"));
        assert_eq!(f.effects.len(), 1);
    }
}
