//! Optional dependency handling for npm resolution.
//!
//! Manages optionalDependencies from package.json, which are dependencies
//! that are allowed to fail installation without causing the parent
//! package installation to fail.

use rusk_core::PackageId;

/// An optional dependency with its installation status.
#[derive(Clone, Debug)]
pub struct OptionalDependency {
    /// The package that declared this optional dependency.
    pub parent: PackageId,
    /// The optional dependency package name.
    pub name: String,
    /// The version range requested.
    pub version_range: String,
    /// Installation status.
    pub status: OptionalStatus,
}

/// Status of an optional dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OptionalStatus {
    /// Successfully resolved and will be installed.
    Resolved,
    /// Could not be resolved (missing from registry, version conflict, etc.).
    Skipped { reason: String },
    /// Platform mismatch (os/cpu fields don't match).
    PlatformMismatch,
    /// Not yet evaluated.
    Pending,
}

/// Filter a list of optional dependencies, keeping only those that should
/// be installed on the current platform.
pub fn filter_optional_for_platform(
    deps: &[OptionalDependency],
) -> Vec<&OptionalDependency> {
    deps.iter()
        .filter(|d| d.status != OptionalStatus::PlatformMismatch)
        .collect()
}
