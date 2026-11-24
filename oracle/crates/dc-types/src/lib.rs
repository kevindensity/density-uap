//! dc-types — the minimum constitutional core contracts (B0).
//!
//! Scope: identity, canonical encoding and digest, the common envelope, epochs and
//! validity, standing, the single outcome taxonomy, and the candidate/admitted split.
//! Everything else in the specification is an extension and lives in other crates.

pub mod canonical;
pub mod envelope;
pub mod outcome;

pub use canonical::{canonical_json, digest, CanonicalError, Digest, DOMAIN_PREFIX};
pub use envelope::*;
pub use outcome::*;
