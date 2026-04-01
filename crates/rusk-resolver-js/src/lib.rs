//! JavaScript/TypeScript ecosystem resolver for rusk.
//!
//! Implements the `CandidateProvider` trait for the npm ecosystem, translating
//! npm registry metadata into resolver candidates.

pub mod provider;
pub mod semver_range;
pub mod peer;
pub mod optional;

pub use provider::JsCandidateProvider;
pub use semver_range::parse_npm_range;
pub use peer::{PeerDependency, PeerValidation};
pub use optional::{OptionalDependency, OptionalStatus};
