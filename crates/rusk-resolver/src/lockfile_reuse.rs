//! Lockfile reuse optimization.
//!
//! When a lockfile exists, prefer the previously-locked versions to minimize
//! churn. This module provides logic to seed the solver with locked versions
//! and detect when the lockfile is compatible with the current manifest.

use rusk_core::{PackageId, Sha256Digest, Version};
use std::collections::HashMap;

/// A locked package entry from the lockfile.
#[derive(Clone, Debug)]
pub struct LockedVersion {
    /// The package.
    pub package: PackageId,
    /// The locked version.
    pub version: Version,
    /// The locked content digest.
    pub digest: Sha256Digest,
}

/// Strategy for lockfile reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockfileStrategy {
    /// Use the lockfile exactly; fail if any change is needed (--frozen).
    Frozen,
    /// Prefer locked versions but allow updates where needed.
    PreferLocked,
    /// Ignore the lockfile and resolve fresh.
    Fresh,
}

/// Determine which locked versions can be reused given the current manifest constraints.
pub fn reusable_versions(
    locked: &[LockedVersion],
    _strategy: LockfileStrategy,
) -> HashMap<PackageId, LockedVersion> {
    // In a full implementation, this would check each locked version
    // against the current manifest constraints to see if it's still valid.
    locked
        .iter()
        .map(|lv| (lv.package.clone(), lv.clone()))
        .collect()
}
