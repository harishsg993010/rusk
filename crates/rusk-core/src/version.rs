use serde::{Deserialize, Serialize};
use std::fmt;

/// Unified version type wrapping ecosystem-specific versions.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum Version {
    /// npm semver version
    Semver(semver::Version),
    /// PEP 440 version
    Pep440(pep440_rs::Version),
}

impl Version {
    /// Sentinel root version for the resolver.
    pub fn root() -> Self {
        Version::Semver(semver::Version::new(0, 0, 0))
    }

    pub fn is_prerelease(&self) -> bool {
        match self {
            Version::Semver(v) => !v.pre.is_empty(),
            Version::Pep440(v) => v.is_pre(),
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Version::Semver(a), Version::Semver(b)) => a.cmp(b),
            (Version::Pep440(a), Version::Pep440(b)) => a.cmp(b),
            (Version::Semver(_), Version::Pep440(_)) => std::cmp::Ordering::Less,
            (Version::Pep440(_), Version::Semver(_)) => std::cmp::Ordering::Greater,
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::Semver(v) => write!(f, "{v}"),
            Version::Pep440(v) => write!(f, "{v}"),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::Semver(v) => write!(f, "{v}"),
            Version::Pep440(v) => write!(f, "{v}"),
        }
    }
}

/// Version requirement / constraint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum VersionReq {
    /// npm semver range
    SemverReq(semver::VersionReq),
    /// PEP 440 version specifiers
    Pep440Req(pep440_rs::VersionSpecifiers),
}

impl VersionReq {
    /// Check if a version matches this requirement.
    pub fn matches(&self, version: &Version) -> bool {
        match (self, version) {
            (VersionReq::SemverReq(req), Version::Semver(ver)) => req.matches(ver),
            (VersionReq::Pep440Req(req), Version::Pep440(ver)) => req.contains(ver),
            _ => false,
        }
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionReq::SemverReq(r) => write!(f, "{r}"),
            VersionReq::Pep440Req(r) => write!(f, "{r}"),
        }
    }
}
