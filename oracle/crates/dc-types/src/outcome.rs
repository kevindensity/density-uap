//! The single outcome taxonomy (core subset). Every function and transition returns one.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", content = "detail", rename_all = "snake_case")]
pub enum Outcome<T> {
    Proceed(T),
    Sufficient { for_purposes: Vec<String> },
    Need(Need),
    Unknown(Unknown),
    Refuse(Refusal),
    Defer { until: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Need { DescentRequired, ProbeRequired, NewAccessRequired, RepresentationExtension, GroundedAdmission, MoreSamples { have: u32, need: u32 } }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unknown { NonAvailable, NonIdentifiable, ModelClassInadequate, BlindSpot, NoSafeProbe, MonitoringInsufficient, Stale, ScopeConflict, UnsupportedRepresentation, IndependenceFinalityUnresolved, LawfulImpossible }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal { NotStanding, ScopeDenied, AuthorityMissing, SelfRatification, IndependenceInsufficient, IncompatibleCut, BindingMismatch, SuccessorSelfAuthorization, DuplicateSuccessor, GrantConsumed, GrantRevoked, RetryForbidden, ReemissionWhileUnknown, TransitionForbidden, DenyProtectedValue, FalseDischarge }

impl<T> Outcome<T> {
    /// Only Proceed permits a consequential commit (constitutional alphabet).
    pub fn permits_commit(&self) -> bool { matches!(self, Outcome::Proceed(_)) }
    /// A typed unknown or refusal is a conformant answer (K13).
    pub fn is_conformant_non_answer(&self) -> bool { matches!(self, Outcome::Unknown(_) | Outcome::Refuse(_) | Outcome::Need(_) | Outcome::Defer { .. }) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json;

    #[test]
    fn only_proceed_commits() {
        assert!(Outcome::Proceed(1).permits_commit());
        assert!(!Outcome::<()>::Unknown(Unknown::ScopeConflict).permits_commit());
        assert!(Outcome::<()>::Refuse(Refusal::FalseDischarge).is_conformant_non_answer());
    }
    #[test]
    fn wire_form_is_stable() {
        let o: Outcome<()> = Outcome::Need(Need::MoreSamples { have: 2, need: 5 });
        assert_eq!(canonical_json(&o).unwrap(), r#"{"detail":{"more_samples":{"have":2,"need":5}},"outcome":"need"}"#);
    }
}
