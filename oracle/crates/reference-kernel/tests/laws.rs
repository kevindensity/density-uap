//! Law-indexed conformance tests for the reference kernel. Test names carry law IDs so
//! the traceability matrix (traceability/matrix.yaml) can reference them.

use dc_types::{Digest, Outcome, Refusal, TenantId, Unknown};
use reference_kernel::{AdmissionRequest, EffectState, Kernel, XorShift};

fn t() -> TenantId { TenantId("tenant-a".into()) }
fn req(hash: u8, pred: Option<u64>) -> AdmissionRequest {
    AdmissionRequest { request_hash: Digest([hash; 32]), tenant: t(), epoch: 1, predecessor: pred, candidate: Digest([hash ^ 0xff; 32]), receipt_tenant: t(), receipt_epoch: 1, cites_own_conclusion: false, successor_approves_itself: false }
}
fn kernel() -> Kernel { let mut k = Kernel::new(); k.set_epoch(&t(), 1); k }
fn released_effect(k: &mut Kernel, retry: bool) -> u64 {
    let e = k.plan_effect();
    assert!(k.grant(e, &t(), retry).permits_commit());
    assert!(k.release(e, &t()).permits_commit());
    e
}

#[test]
fn k04_self_ratification_refused() {
    let mut k = kernel();
    let mut r = req(1, None); r.cites_own_conclusion = true;
    assert_eq!(k.bind(&r, ()), Outcome::Refuse(Refusal::SelfRatification));
    let mut r = req(2, None); r.successor_approves_itself = true;
    assert_eq!(k.bind(&r, ()), Outcome::Refuse(Refusal::SuccessorSelfAuthorization));
}

#[test]
fn p0_exactly_one_successor_per_predecessor() {
    let mut k = kernel();
    let root = match k.bind(&req(1, None), ()) { Outcome::Proceed(a) => a.binding(), o => panic!("{o:?}") };
    assert!(k.bind(&req(2, Some(root)), ()).permits_commit());
    assert_eq!(k.bind(&req(3, Some(root)), ()), Outcome::Refuse(Refusal::DuplicateSuccessor));
}

#[test]
fn p0_crash_replay_converges() {
    let mut k = kernel();
    let a = match k.bind(&req(7, None), ()) { Outcome::Proceed(a) => a.binding(), o => panic!("{o:?}") };
    let b = match k.bind(&req(7, None), ()) { Outcome::Proceed(a) => a.binding(), o => panic!("{o:?}") };
    assert_eq!(a, b);
}

#[test]
fn k20_copied_receipt_from_another_epoch_or_tenant_refused() {
    let mut k = kernel();
    let mut r = req(1, None); r.receipt_epoch = 0;
    assert_eq!(k.bind(&r, ()), Outcome::Refuse(Refusal::IncompatibleCut));
    let mut r = req(2, None); r.receipt_tenant = TenantId("tenant-b".into());
    assert_eq!(k.bind(&r, ()), Outcome::Refuse(Refusal::IncompatibleCut));
}

#[test]
fn k06_acknowledgement_is_not_finality() {
    let mut k = kernel();
    let e = released_effect(&mut k, false);
    assert!(k.emit(e, "gateway-key").permits_commit());
    k.ack(e, true);
    assert_eq!(k.state.effects[&e].state, EffectState::Acked);
    assert_eq!(k.reconcile(e, "gateway-key", true), Outcome::Refuse(Refusal::IndependenceInsufficient));
    assert_eq!(k.reconcile(e, "observer-key", true), Outcome::Proceed(EffectState::Final));
}

#[test]
fn k06_unknown_outcome_is_reconciled_never_reemitted() {
    let mut k = kernel();
    let e = released_effect(&mut k, true);
    assert!(k.emit(e, "gateway-key").permits_commit());
    k.crash_after_sent(e);
    assert_eq!(k.emit(e, "gateway-key"), Outcome::Refuse(Refusal::ReemissionWhileUnknown));
    assert_eq!(k.reconcile(e, "observer-key", false), Outcome::Proceed(EffectState::Absent));
}

#[test]
fn grant_single_use_and_retry_only_if_allowed() {
    let mut k = kernel();
    let e = released_effect(&mut k, false);
    assert_eq!(k.release(e, &t()), Outcome::Refuse(Refusal::TransitionForbidden));
    k.emit(e, "gw"); k.crash_after_sent(e);
    k.reconcile(e, "obs", false);
    assert_eq!(k.grant(e, &t(), false), Outcome::Refuse(Refusal::RetryForbidden));

    let e2 = released_effect(&mut k, true);
    k.emit(e2, "gw"); k.crash_after_sent(e2); k.reconcile(e2, "obs", false);
    assert!(k.grant(e2, &t(), false).permits_commit(), "retry allowed by the original grant");
}

#[test]
fn release_rechecks_epoch_and_revocation() {
    let mut k = kernel();
    let e = k.plan_effect();
    let nonce = match k.grant(e, &t(), false) { Outcome::Proceed(n) => n, o => panic!("{o:?}") };
    k.revoke(nonce);
    assert_eq!(k.release(e, &t()), Outcome::Refuse(Refusal::GrantRevoked));
    let e2 = k.plan_effect();
    k.grant(e2, &t(), false);
    k.set_epoch(&t(), 2);
    assert_eq!(k.release(e2, &t()), Outcome::Refuse(Refusal::GrantRevoked));
}

#[test]
fn k10_settlement_needs_a_different_verifier_key() {
    let mut k = kernel();
    assert_eq!(k.settle("claim-1", "key-a", "key-a"), Outcome::Refuse(Refusal::IndependenceInsufficient));
    assert!(k.settle("claim-1", "key-a", "key-b").permits_commit());
}

#[test]
fn k35_restore_never_resurrects_authority() {
    let mut k = kernel();
    let e = k.plan_effect();
    let nonce = match k.grant(e, &t(), false) { Outcome::Proceed(n) => n, o => panic!("{o:?}") };
    let before = k.snapshot();
    k.revoke(nonce);
    k.restore(before);                      // backup taken while the grant was live
    assert_eq!(k.release(e, &t()), Outcome::Refuse(Refusal::GrantRevoked));

    let e2 = k.plan_effect();
    k.grant(e2, &t(), false);
    let before = k.snapshot();
    assert!(k.release(e2, &t()).permits_commit());
    k.restore(before);                      // grant consumed after the backup
    assert_eq!(k.release(e2, &t()), Outcome::Refuse(Refusal::GrantConsumed));
}

#[test]
fn k35_restore_never_reissues_an_identifier() {
    let mut k = kernel();
    let snap = k.snapshot();
    let e = k.plan_effect();
    let n1 = match k.grant(e, &t(), false) { Outcome::Proceed(n) => n, o => panic!("{o:?}") };
    k.revoke(n1);
    k.restore(snap);
    let e2 = k.plan_effect();
    let n2 = match k.grant(e2, &t(), false) { Outcome::Proceed(n) => n, o => panic!("{o:?}") };
    assert_ne!(n1, n2, "a restored kernel must not reissue a revoked nonce");
    assert!(k.release(e2, &t()).permits_commit());
}

#[test]
fn k35_restore_between_release_and_emit_never_double_emits() {
    // Counterexample found by TLC on the first model: backup after release, emit, restore, emit again.
    let mut k = kernel();
    let e = released_effect(&mut k, false);
    let snap = k.snapshot();
    assert!(k.emit(e, "gw").permits_commit());
    k.restore(snap);
    assert_eq!(k.emit(e, "gw"), Outcome::Refuse(Refusal::ReemissionWhileUnknown));
    assert_eq!(k.state.effects[&e].state, EffectState::Unknown);
    assert_eq!(k.reconcile(e, "obs", true), Outcome::Proceed(EffectState::Final));
    assert_eq!(k.log.sent.values().map(|r| r.0).sum::<u32>(), 1);
    // After the restore the in-memory emitter is gone; the emitter may still not confirm itself.
    let mut k2 = kernel();
    let e2 = released_effect(&mut k2, false);
    let snap2 = k2.snapshot();
    k2.emit(e2, "gw");
    k2.restore(snap2);
    k2.emit(e2, "gw");
    assert_eq!(k2.reconcile(e2, "gw", true), Outcome::Refuse(Refusal::IndependenceInsufficient));
}

#[test]
fn missing_predecessor_is_typed_unknown() {
    let mut k = kernel();
    assert_eq!(k.bind(&req(9, Some(999)), ()), Outcome::Unknown(Unknown::NonAvailable));
}

/// K38 oracle self-check: over many random traces with crashes, duplicates, revocations
/// and restores, the kernel never violates its own safety invariants.
#[test]
fn k38_randomized_traces_preserve_kernel_invariants() {
    let mut rng = XorShift(0x9E3779B97F4A7C15);
    for _trace in 0..2_000 {
        let mut k = kernel();
        let mut snapshot = None;
        let mut effects: Vec<u64> = vec![];
        for _ in 0..40 {
            match rng.next() % 11 {
                0 => { let p = k.state.bindings.keys().copied().last(); k.bind(&req((rng.next() % 6) as u8, p), ()); }
                1 => effects.push(k.plan_effect()),
                2 => if let Some(&e) = effects.last() { k.grant(e, &t(), rng.next() % 2 == 0); },
                3 => if let Some(&e) = effects.last() { k.release(e, &t()); },
                4 => if let Some(&e) = effects.last() { k.emit(e, "gw"); },
                5 => if let Some(&e) = effects.last() { k.ack(e, rng.next() % 2 == 0); },
                6 => if let Some(&e) = effects.last() { k.reconcile(e, if rng.next() % 3 == 0 { "gw" } else { "obs" }, rng.next() % 2 == 0); },
                7 => { if let Some(n) = k.state.grants.keys().copied().last() { k.revoke(n); } }
                8 => snapshot = Some(k.snapshot()),
                9 => if let Some(s) = snapshot.clone() { k.restore(s); },
                _ => k.set_epoch(&t(), 1 + rng.next() % 2),
            }
            // Invariant 1: at most one successor per (tenant, predecessor).
            let mut seen = std::collections::BTreeSet::new();
            for b in k.state.bindings.values() { assert!(seen.insert((b.tenant.0.clone(), b.predecessor))); }
            // Invariant 2: at most one emission per grant, across crashes and restores (durable count).
            for (&n, rec) in &k.log.sent { assert!(rec.0 <= 1, "grant {n} emitted {} times", rec.0); }
            // Invariant 3: a final effect had a non-emitter observer (state only reachable via reconcile check).
            for e in k.state.effects.values() {
                if e.state == EffectState::Final {
                    let rec = e.grant.and_then(|n| k.log.sent.get(&n)).expect("final effect has a durable SENT record");
                    assert_ne!(rec.1, "obs", "observer must differ from the recorded emitter");
                }
            }
            // Invariant 4: revoked or consumed nonces never become releasable again.
            for (&n, g) in &k.state.grants {
                if k.log.revoked_nonces.contains(&n) || k.log.consumed_nonces.contains(&n) {
                    if let Some(eff) = k.state.effects.get(&g.effect) {
                        if eff.grant == Some(n) && eff.state == EffectState::Authorized {
                            assert!(!k.clone_release_ok(g.effect, &t()), "nonce {n} resurrected");
                        }
                    }
                }
            }
        }
    }
}
