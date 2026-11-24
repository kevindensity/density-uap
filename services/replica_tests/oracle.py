"""Independent oracle for p0.admit_event: models the kernel's machines and the eleven-step order,
generates random walks with one injected fault per step, and predicts every decision."""
import json, random, sys
T = {  # (machine, from, to): required receipt roles
 ("node","(none)","PROPOSED"):[], ("node","PROPOSED","ADMITTED"):["VERIFIER"], ("node","PROPOSED","REFUSED"):[],
 ("node","ADMITTED","SUPERSEDED"):["VERIFIER"], ("node","ADMITTED","RETIRED"):["OWNER"],
 ("secure_boot","(none)","PROPOSED"):[], ("secure_boot","PROPOSED","ADMITTED"):["OWNER"], ("secure_boot","ADMITTED","RETIRED"):["OWNER"],
 ("owner_approval","(none)","RECORDED"):["OWNER"],
 ("standing_policy","(none)","ACTIVE"):["OWNER"], ("standing_policy","ACTIVE","EXHAUSTED"):[], ("standing_policy","ACTIVE","REVOKED"):["OWNER"],
 ("conformance","(none)","OPEN"):[], ("conformance","OPEN","OPEN"):[], ("conformance","OPEN","RECEIPTED"):["VERIFIER"]}
KIND = lambda m,f,t: f"{m}:{f}->{t}"
FAULTS = ["none"]*6 + ["unknown_event","wire_numeric","replay","conflict","subject","missing_ref","misbound_ref","stale_epoch",
          "receipt_missing","receipt_forged","receipt_revoked","receipt_wrong_role","stale_revision","bad_predecessor","invalid_transition","unknown_stream","dup_name"]
def gen(seed, n_streams, steps):
    rng = random.Random(seed); script = []; machines = ["node","secure_boot","owner_approval","standing_policy","conformance"]
    for s in range(n_streams):
        m = machines[s % len(machines)]; state = "(none)"; created = False; accepted_any = False; named_genesis = False
        for _ in range(steps):
            valid = [(f,t) for (mm,f,t) in T if mm == m and f == state]
            f = rng.choice(FAULTS)
            if not valid: f = rng.choice(["invalid_transition", "unknown_event"])   # terminal state: no lawful step exists
            # faults that need preconditions fall back to a plain valid step
            if f in ("replay","conflict","misbound_ref") and not accepted_any: f = "none"
            if f in ("stale_revision","bad_predecessor") and not created: f = "none"
            if f == "unknown_stream" and created: f = "none"
            if f == "dup_name" and not (m == "node" and state == "(none)" and s >= len(machines)): f = "none"
            if not valid and f not in ("invalid_transition", "unknown_event"): f = "invalid_transition"
            step = {"s": s, "f": f}
            if f == "invalid_transition" or f == "unknown_stream":
                cands = [(ff,tt) for (mm,ff,tt) in T if mm == m and ff != state and (ff != "(none)" or created)]
                if f == "unknown_stream": cands = [(ff,tt) for (mm,ff,tt) in T if mm == m and ff != "(none)"]
                if not cands: step["f"] = f = "unknown_event"; frm, to = "(none)", "X"
                else: frm, to = rng.choice(cands)
            elif f == "unknown_event" and not valid:
                frm, to = rng.choice([(ff, tt) for (mm, ff, tt) in T if mm == m])
            else:
                frm, to = rng.choice(valid)
            step["k"] = KIND(m, frm, to); need = T.get((m, frm, to), [])
            step["need"] = need
            # receipt mode
            rc = "valid"
            if f.startswith("receipt_"):
                if not need: f = step["f"] = "none"
                else: rc = f.split("_",1)[1]
            step["rc"] = rc
            # expected decision, following the kernel's order
            if f == "unknown_event": ev = "REJECT/UNKNOWN_EVENT"
            elif f == "wire_numeric": ev = "REJECT/WIRE_REJECTED"
            elif f == "replay": ev = "REPLAY/"
            elif f == "conflict": ev = "CONFLICT/EVENT_IDENTITY_CONFLICT"
            elif f == "subject": ev = "REJECT/SUBJECT_TYPE_MISMATCH"
            elif f == "missing_ref": ev = "DEFER/MISSING_REFERENCE"
            elif f == "misbound_ref": ev = "REJECT/BINDING_MISMATCH"
            elif f == "stale_epoch": ev = "DEFER/GENERATION_NOT_CURRENT"
            elif rc == "missing": ev = "DEFER/MISSING_REQUIRED_GUARD"
            elif rc in ("forged","revoked","wrong_role"): ev = "REJECT/GUARD_REJECTED"
            elif not created and frm != "(none)": ev = "REJECT/UNKNOWN_STREAM"
            elif f == "stale_revision": ev = "REJECT/STALE_REVISION"
            elif f == "bad_predecessor": ev = "REJECT/PREDECESSOR_MISMATCH"
            elif frm != state: ev = "REJECT/PRIOR_STATE_NOT_ALLOWED"
            elif f == "dup_name": ev = "REJECT/PROJECTION_CONSTRAINT"
            else: ev = "ACCEPT/"
            step["ev"] = ev
            if ev == "ACCEPT/":
                state = to; created = True; accepted_any = True
            script.append(step)
    return script
if __name__ == "__main__":
    seed, n, steps = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    sc = gen(seed, n, steps); json.dump(sc, open(f"script_{seed}.json","w"), separators=(",",":"))
    from collections import Counter
    print(len(sc), "steps;", dict(Counter(x["ev"] for x in sc)))
