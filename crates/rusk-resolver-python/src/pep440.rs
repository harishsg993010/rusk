//! PEP 440 version handling utilities.
//!
//! Provides helpers for working with PEP 440 versions and specifiers
//! in the context of the resolver.

use pep440_rs::{Version, VersionSpecifiers};

/// Parse a PEP 440 version string.
pub fn parse_version(s: &str) -> Result<Version, String> {
    s.parse::<Version>()
        .map_err(|e| format!("invalid PEP 440 version '{s}': {e}"))
}

/// Parse a PEP 440 version specifier string (e.g., ">=1.0,<2.0").
pub fn parse_specifiers(s: &str) -> Result<VersionSpecifiers, String> {
    s.parse::<VersionSpecifiers>()
        .map_err(|e| format!("invalid PEP 440 specifier '{s}': {e}"))
}

/// Check if a version matches a specifier set.
pub fn version_matches(version: &Version, specifiers: &VersionSpecifiers) -> bool {
    specifiers.contains(version)
}

/// Check if a version is a prerelease.
pub fn is_prerelease(version: &Version) -> bool {
    version.is_pre()
}

/// Sort versions in descending order (latest first), stable before pre.
pub fn sort_versions_descending(versions: &mut [Version]) {
    versions.sort_by(|a, b| b.cmp(a));
}
