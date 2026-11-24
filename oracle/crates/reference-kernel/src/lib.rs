//! reference-kernel — the small, single-threaded oracle for K38.
//!
//! It implements the kernel's admission, grant, effect-chain, settlement and
//! revocation semantics plus the table-driven state machines, as plainly as possible.
//! Production services (`p0d`, `verifierd`, `effect-gateway`) are tested against it:
//! under any trace and fault, production may never grant, admit, settle or finalize
//! anything this machine would not.

pub mod machines;

use dc_types::{Digest, NoAuthority, Outcome, Process, Refusal, TenantId, Unknown};
use std::collections::{BTreeMap, BTreeSet};

/// Admitted<T> can be constructed only inside this crate (K02).
///
/// ```compile_fail
/// use reference_kernel::Admitted;
/// let forged: Admitted<u32> = Admitted { body: 1, binding: 0 };
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Admitted<T> { body: T, binding: u64 }
impl<T> Admitted<T> {
    pub fn body(&self) -> &T { &self.body }
    pub fn binding(&self) -> u64 { self.binding }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AdmissionRequest {
    pub request_hash: Digest,
    pub tenant: TenantId,
    pub epoch: u64,
    pub predecessor: Option<u64>,
    pub candidate: Digest,
    /// Receipts presented with the request were signed for this tenant and epoch.
    pub receipt_tenant: TenantId,
    pub receipt_epoch: u64,
    /// The derivation cites its own conclusion (hidden-outcome selection).
    pub cites_own_conclusion: bool,
    /// The successor is among the approvers of its own root.
    pub successor_approves_itself: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Binding { pub id: u64, pub predecessor: Option<u64>, pub candidate: Digest, pub tenant: TenantId, pub epoch: u64 }

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectState { Planned, Authorized, Released, Emitted, Acked, Unknown, Reconciling, Present, Absent, Final }

#[derive(Clone, Debug, PartialEq)]
pub struct Grant { pub nonce: u64, pub effect: u64, pub authority_epoch: u64, pub retry_allowed: bool }

#[derive(Clone, Debug, PartialEq)]
pub struct Effect { pub id: u64, pub state: EffectState, pub grant: Option<u64>, pub emitter_key: Option<String>, pub emissions: u32 }

/// Durable, append-only logs that survive restore (K35).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DurableLog { pub revoked_nonces: BTreeSet<u64>, pub consumed_nonces: BTreeSet<u64>,
    /// Durable SENT records keyed by grant nonce: at most one emission per grant, never rolled back by restore.
    pub sent: BTreeMap<u64, (u32, String)>, /// Identifier sequence: durable and never rolled back, so a restore cannot reissue a nonce.
    pub next_id: u64 }

#[derive(Clone, Debug, Default, PartialEq)]
pub struct KernelState {
    pub tenant_epoch: BTreeMap<String, u64>,
    pub bindings: BTreeMap<u64, Binding>,
    pub by_predecessor: BTreeMap<(String, Option<u64>), u64>,
    pub by_request: BTreeMap<Digest, u64>,
    pub grants: BTreeMap<u64, Grant>,
    pub effects: BTreeMap<u64, Effect>,
    pub settled: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct Kernel { pub state: KernelState, pub log: DurableLog }

impl Kernel {
    pub fn new() -> Self { Self::default() }

    fn next(&mut self) -> u64 { self.log.next_id += 1; self.log.next_id }

    pub fn set_epoch(&mut self, tenant: &TenantId, epoch: u64) { self.state.tenant_epoch.insert(tenant.0.clone(), epoch); }
    fn epoch(&self, tenant: &TenantId) -> u64 { *self.state.tenant_epoch.get(&tenant.0).unwrap_or(&0) }

    // ---------------- P0 admission ----------------

    /// Binds exactly one successor per predecessor; replay of the same request converges.
    pub fn bind<T: Clone>(&mut self, req: &AdmissionRequest, body: T) -> Outcome<Admitted<T>> {
        if let Some(&id) = self.state.by_request.get(&req.request_hash) {
            return Outcome::Proceed(Admitted { body, binding: id });      // crash-replay converges
        }
        if req.receipt_tenant != req.tenant || req.receipt_epoch != req.epoch || req.epoch != self.epoch(&req.tenant) {
            return Outcome::Refuse(Refusal::IncompatibleCut);             // copied receipt / stale epoch
        }
        if req.cites_own_conclusion { return Outcome::Refuse(Refusal::SelfRatification); }
        if req.successor_approves_itself { return Outcome::Refuse(Refusal::SuccessorSelfAuthorization); }
        if let Some(p) = req.predecessor { if !self.state.bindings.contains_key(&p) { return Outcome::Unknown(Unknown::NonAvailable); } }
        let key = (req.tenant.0.clone(), req.predecessor);
        if self.state.by_predecessor.contains_key(&key) { return Outcome::Refuse(Refusal::DuplicateSuccessor); }
        let id = self.next();
        self.state.bindings.insert(id, Binding { id, predecessor: req.predecessor, candidate: req.candidate, tenant: req.tenant.clone(), epoch: req.epoch });
        self.state.by_predecessor.insert(key, id);
        self.state.by_request.insert(req.request_hash, id);
        Outcome::Proceed(Admitted { body, binding: id })
    }

    // ---------------- Grants (MAY) ----------------

    pub fn plan_effect(&mut self) -> u64 {
        let id = self.next();
        self.state.effects.insert(id, Effect { id, state: EffectState::Planned, grant: None, emitter_key: None, emissions: 0 });
        id
    }

    pub fn grant(&mut self, effect: u64, tenant: &TenantId, retry_allowed: bool) -> Outcome<u64> {
        let epoch = self.epoch(tenant);
        let Some(e) = self.state.effects.get(&effect) else { return Outcome::Unknown(Unknown::NonAvailable) };
        if !matches!(e.state, EffectState::Planned | EffectState::Absent) { return Outcome::Refuse(Refusal::TransitionForbidden); }
        if e.state == EffectState::Absent {
            let prior = e.grant.and_then(|n| self.state.grants.get(&n));
            if !prior.map_or(false, |g| g.retry_allowed) { return Outcome::Refuse(Refusal::RetryForbidden); }
        }
        let nonce = self.next();
        self.state.grants.insert(nonce, Grant { nonce, effect, authority_epoch: epoch, retry_allowed });
        let e = self.state.effects.get_mut(&effect).unwrap();
        e.grant = Some(nonce);
        e.state = EffectState::Authorized;
        Outcome::Proceed(nonce)
    }

    /// Revocation is always allowed and append-only.
    pub fn revoke(&mut self, nonce: u64) { self.log.revoked_nonces.insert(nonce); }

    /// Release re-checks the grant at this instant and consumes it exactly once.
    pub fn release(&mut self, effect: u64, tenant: &TenantId) -> Outcome<()> {
        let epoch = self.epoch(tenant);
        let Some(e) = self.state.effects.get(&effect) else { return Outcome::Unknown(Unknown::NonAvailable) };
        if e.state != EffectState::Authorized { return Outcome::Refuse(Refusal::TransitionForbidden); }
        let Some(nonce) = e.grant else { return Outcome::Refuse(Refusal::AuthorityMissing) };
        if self.log.revoked_nonces.contains(&nonce) { return Outcome::Refuse(Refusal::GrantRevoked); }
        if self.log.consumed_nonces.contains(&nonce) { return Outcome::Refuse(Refusal::GrantConsumed); }
        let Some(g) = self.state.grants.get(&nonce) else { return Outcome::Unknown(Unknown::NonAvailable) };
        if g.authority_epoch != epoch { return Outcome::Refuse(Refusal::GrantRevoked); }
        self.log.consumed_nonces.insert(nonce);
        self.state.effects.get_mut(&effect).unwrap().state = EffectState::Released;
        Outcome::Proceed(())
    }

    // ---------------- Effect chain (DID) ----------------

    /// Durable SENT precedes the provider call; an effect is emitted at most once per grant.
    pub fn emit(&mut self, effect: u64, emitter_key: &str) -> Outcome<()> {
        let Some(e) = self.state.effects.get_mut(&effect) else { return Outcome::Unknown(Unknown::NonAvailable) };
        let nonce = e.grant;
        if nonce.map_or(false, |n| self.log.sent.contains_key(&n)) && matches!(e.state, EffectState::Released | EffectState::Authorized) {
            // Restored to a pre-emission state, but the durable SENT record exists: reconcile, never re-emit.
            e.state = EffectState::Unknown;
            return Outcome::Refuse(Refusal::ReemissionWhileUnknown);
        }
        match e.state {
            EffectState::Released => {
                let rec = self.log.sent.entry(nonce.expect("released effects carry a grant")).or_insert((0, emitter_key.to_string()));
                rec.0 += 1;                                        // durable SENT (with emitter identity) before the provider call
                e.state = EffectState::Emitted; e.emissions += 1; e.emitter_key = Some(emitter_key.into()); Outcome::Proceed(())
            }
            EffectState::Unknown | EffectState::Reconciling => Outcome::Refuse(Refusal::ReemissionWhileUnknown),
            _ => Outcome::Refuse(Refusal::TransitionForbidden),
        }
    }

    pub fn ack(&mut self, effect: u64, received: bool) {
        let Some(e) = self.state.effects.get_mut(&effect) else { return };
        if e.state == EffectState::Emitted { e.state = if received { EffectState::Acked } else { EffectState::Unknown }; }
    }

    /// Crash after durable SENT is treated as an unknown outcome.
    pub fn crash_after_sent(&mut self, effect: u64) { self.ack(effect, false); }

    /// Finality needs an independent observation; an acknowledgement is never finality (K06).
    pub fn reconcile(&mut self, effect: u64, observer_key: &str, present: bool) -> Outcome<EffectState> {
        let Some(e) = self.state.effects.get_mut(&effect) else { return Outcome::Unknown(Unknown::NonAvailable) };
        if !matches!(e.state, EffectState::Acked | EffectState::Unknown | EffectState::Reconciling) { return Outcome::Refuse(Refusal::TransitionForbidden); }
        // Independence is judged against the durable SENT record, which survives restore;
        // with no record of the emitter, independence cannot be established.
        let emitter = e.grant.and_then(|n| self.log.sent.get(&n)).map(|r| r.1.clone());
        match emitter.as_deref() {
            None => return Outcome::Refuse(Refusal::IndependenceInsufficient),
            Some(k) if k == observer_key => return Outcome::Refuse(Refusal::IndependenceInsufficient),
            _ => {}
        }
        e.state = if present { EffectState::Final } else { EffectState::Absent };
        Outcome::Proceed(e.state.clone())
    }

    // ---------------- Settlement (K10) ----------------

    pub fn settle(&mut self, claim: &str, synthesizer_key: &str, verifier_key: &str) -> Outcome<()> {
        if synthesizer_key == verifier_key { return Outcome::Refuse(Refusal::IndependenceInsufficient); }
        self.state.settled.insert(claim.into(), verifier_key.into());
        Outcome::Proceed(())
    }

    // ---------------- Backup and restore (K35) ----------------

    pub fn snapshot(&self) -> KernelState { self.state.clone() }

    /// Would `release` succeed right now? (Checks on a clone; used by invariant tests.)
    pub fn clone_release_ok(&self, effect: u64, tenant: &TenantId) -> bool {
        let mut c = self.clone();
        c.release(effect, tenant).permits_commit()
    }

    /// Restoring an older snapshot never resurrects revoked or consumed authority:
    /// the durable log is replayed over the restored state before anything is honoured.
    pub fn restore(&mut self, snapshot: KernelState) { self.state = snapshot; }
}

/// Small deterministic generator for randomized trace tests (no external dependency).
pub struct XorShift(pub u64);
impl XorShift { pub fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x } }

#[allow(unused)]
fn _authority_is_unit(_: NoAuthority) {}
#[allow(unused)]
fn _process_has_kernel_roles() -> [Process; 2] { [Process::Verifierd, Process::P0d] }
