//! Peer dependency handling for npm resolution.
//!
//! Handles peer dependencies, optional peers, and peer dependency conflicts
//! according to npm v7+ semantics.

use rusk_core::{PackageId, Version};

/// A peer dependency requirement.
#[derive(Clone, Debug)]
pub struct PeerDependency {
    /// The package that declares this peer dependency.
    pub declared_by: PackageId,
    /// The required peer package.
    pub peer_package: String,
    /// The version range constraint.
    pub version_range: String,
    /// Whether this peer dependency is optional.
    pub optional: bool,
}

/// Result of peer dependency validation.
#[derive(Clone, Debug)]
pub enum PeerValidation {
    /// The peer dependency is satisfied.
    Satisfied {
        peer: String,
        resolved_version: Version,
    },
    /// The peer dependency is missing but optional.
    OptionalMissing { peer: String },
    /// The peer dependency is missing and required.
    Missing {
        peer: String,
        required_by: PackageId,
        range: String,
    },
    /// The peer dependency exists but at an incompatible version.
    Conflict {
        peer: String,
        resolved_version: Version,
        required_range: String,
        required_by: PackageId,
    },
}

impl PeerValidation {
    /// Whether this is a blocking issue.
    pub fn is_error(&self) -> bool {
        matches!(self, PeerValidation::Missing { .. } | PeerValidation::Conflict { .. })
    }

    /// Whether this is just a warning.
    pub fn is_warning(&self) -> bool {
        matches!(self, PeerValidation::OptionalMissing { .. })
    }
}
