//! Table-driven state machines: a transition not in the table is forbidden.
//! Mirrors the Postgres `sm.transitions` table and `sm.enforce()` trigger.

use dc_types::{Outcome, Process, Refusal};

#[derive(Clone, Debug, PartialEq)]
pub struct Transition { pub machine: &'static str, pub from: &'static str, pub to: &'static str, pub actor: Process, pub always_allowed: bool }

pub fn core_table() -> Vec<Transition> {
    use Process::*;
    let t = |machine, from, to, actor, always_allowed| Transition { machine, from, to, actor, always_allowed };
    vec![
        // Port lifecycle (core subset)
        t("port", "(none)", "UNBOUND", Uapd, false),
        t("port", "UNBOUND", "CONTACTED", Uacd, false),
        t("port", "CONTACTED", "BOOTSTRAP_GROUNDED", Verifierd, false),
        t("port", "BOOTSTRAP_GROUNDED", "CONSTITUTING", Uapd, false),
        t("port", "CONSTITUTING", "QUALIFIED", Verifierd, false),
        t("port", "QUALIFIED", "ADMISSION_PENDING", Uapd, false),
        t("port", "ADMISSION_PENDING", "ACTIVE", P0d, false),
        t("port", "ADMISSION_PENDING", "CONSTITUTING", P0d, false),
        t("port", "ACTIVE", "RECONSTITUTING", Uapd, true),
        t("port", "RECONSTITUTING", "ACTIVE", P0d, false),
        t("port", "*", "SUSPENDED", Uacd, true),
        t("port", "*", "SUSPENDED", P0d, true),
        // Connection ladder (core subset: reads only in B2)
        t("connection", "(none)", "DECLARED", Uacd, false),
        t("connection", "DECLARED", "CONTRACTED", Uapd, false),
        t("connection", "CONTRACTED", "EXECUTABLE", Uapd, false),
        t("connection", "EXECUTABLE", "SUPPORTED", Uapd, false),
        t("connection", "SUPPORTED", "SEMANTICS_RECONCILED", Verifierd, false),
        t("connection", "SEMANTICS_RECONCILED", "BRIDGE_AUTHORIZED", Verifierd, false),
        t("connection", "*", "REVOKED", P0d, true),
        // Settlement
        t("settlement", "CANDIDATE", "SETTLED", Verifierd, false),
        t("settlement", "*", "UNRESOLVED", Uacd, true),
        t("settlement", "*", "STALE", Uacd, true),
        t("settlement", "*", "REVOKED", P0d, true),
    ]
}

/// Checks a transition against the table and the acting login role.
pub fn check(table: &[Transition], machine: &str, from: &str, to: &str, actor: Process) -> Outcome<bool> {
    let hit = table.iter().find(|t| t.machine == machine && (t.from == from || t.from == "*") && t.to == to && t.actor == actor);
    match hit { Some(t) => Outcome::Proceed(t.always_allowed), None => Outcome::Refuse(Refusal::TransitionForbidden) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ungranted_admission_path_is_forbidden() {
        let t = core_table();
        // No path from QUALIFIED straight to ACTIVE, and uapd can never activate (K05).
        assert_eq!(check(&t, "port", "QUALIFIED", "ACTIVE", Process::Uapd), Outcome::Refuse(Refusal::TransitionForbidden));
        assert_eq!(check(&t, "port", "ADMISSION_PENDING", "ACTIVE", Process::Uapd), Outcome::Refuse(Refusal::TransitionForbidden));
        assert_eq!(check(&t, "port", "ADMISSION_PENDING", "ACTIVE", Process::P0d), Outcome::Proceed(false));
    }
    #[test]
    fn weakening_is_always_allowed() {
        let t = core_table();
        assert_eq!(check(&t, "port", "ACTIVE", "SUSPENDED", Process::Uacd), Outcome::Proceed(true));
        assert_eq!(check(&t, "settlement", "SETTLED", "STALE", Process::Uacd), Outcome::Proceed(true));
    }
    #[test]
    fn writes_are_not_in_the_b2_core() {
        let t = core_table();
        assert_eq!(check(&t, "connection", "BRIDGE_AUTHORIZED", "WRITE_AUTHORIZED", Process::Verifierd), Outcome::Refuse(Refusal::TransitionForbidden));
    }
}
