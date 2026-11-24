//! Differential trace export: random operation sequences with the reference kernel's expected outcome per step.
use reference_kernel::*;
use dc_types::{Outcome, TenantId};
fn class<T>(o: &Outcome<T>) -> String {
    match o { Outcome::Proceed(_) => "OK".into(), Outcome::Refuse(r) => format!("{:?}", r), Outcome::Unknown(u) => format!("UNKNOWN_{:?}", u), #[allow(unreachable_patterns)] _ => "OTHER".into() }
}
fn main() {
    let t = TenantId("tenant-a".into());
    let mut rng = XorShift(0x9E3779B97F4A7C15);
    let mut traces = vec![];
    for n in 0..40 {
        let mut k = Kernel::new(); k.set_epoch(&t, 1); let mut epoch = 1u64;
        let e = k.plan_effect();
        let mut snap: Option<KernelState> = None; let mut steps = vec![];
        let len = 4 + (rng.next() % 5) as usize;
        for _ in 0..len {
            let (op, out) = match rng.next() % 5 {
                0 => { let retry = rng.next() % 2 == 0; let o = k.grant(e, &t, retry); if matches!(o, Outcome::Proceed(_)) { snap = Some(k.snapshot()); } (format!("G{}", if retry { "+retry" } else { "" }), class(&o)) }
                1 => { let o = k.release(e, &t); if matches!(o, Outcome::Proceed(_)) { let _ = k.emit(e, "gatewayd"); k.ack(e, true); } ("R".to_string(), class(&o)) }
                2 => { match snap.clone() { Some(s) if k.log.consumed_nonces.len() > 0 => { k.restore(s); let o = k.release(e, &t); ("RR".to_string(), class(&o)) } _ => ("RR".to_string(), "SKIP".to_string()) } }
                3 => { epoch += 1; k.set_epoch(&t, epoch); ("E".to_string(), "OK".to_string()) }
                _ => { match k.state.effects.get(&e).and_then(|x| x.grant) { Some(nonce) => { k.revoke(nonce); ("X".to_string(), "OK".to_string()) } None => ("X".to_string(), "SKIP".to_string()) } }
            };
            steps.push(format!("{{\"op\":\"{}\",\"expect\":\"{}\"}}", op, out));
        }
        traces.push(format!("{{\"trace\":{},\"steps\":[{}]}}", n, steps.join(",")));
    }
    println!("[{}]", traces.join(","));
}
