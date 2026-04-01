//! Trust-aware candidate filtering.
//!
//! Filters version candidates based on trust policy and revocation status
//! before they are considered by the resolver. This ensures that revoked
//! or policy-denied candidates are excluded early.

use crate::candidate::VersionCandidate;
use rusk_revocation::{RevocationChecker, RevocationState};
use tracing::debug;

/// Filters candidates based on trust policy and revocation checks.
pub struct TrustAwareCandidateFilter {
    /// The revocation state to check against.
    revocation_state: RevocationState,
    /// Whether to hard-reject yanked packages (vs. warn).
    reject_yanked: bool,
    /// Whether to allow prereleases.
    allow_prereleases: bool,
}

/// Result of filtering a set of candidates.
#[derive(Clone, Debug)]
pub struct FilterResult {
    /// Candidates that passed all checks.
    pub accepted: Vec<VersionCandidate>,
    /// Candidates that were rejected, with reasons.
    pub rejected: Vec<(VersionCandidate, String)>,
}

impl TrustAwareCandidateFilter {
    /// Create a new filter with the given revocation state.
    pub fn new(revocation_state: RevocationState) -> Self {
        Self {
            revocation_state,
            reject_yanked: true,
            allow_prereleases: false,
        }
    }

    /// Configure whether yanked packages should be rejected.
    pub fn with_reject_yanked(mut self, reject: bool) -> Self {
        self.reject_yanked = reject;
        self
    }

    /// Configure whether prereleases are allowed.
    pub fn with_allow_prereleases(mut self, allow: bool) -> Self {
        self.allow_prereleases = allow;
        self
    }

    /// Filter a set of candidates, returning accepted and rejected sets.
    pub fn filter(&self, candidates: Vec<VersionCandidate>) -> FilterResult {
        let checker = RevocationChecker::new(&self.revocation_state);
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        for candidate in candidates {
            match self.check_candidate(&candidate, &checker) {
                Ok(()) => accepted.push(candidate),
                Err(reason) => {
                    debug!(
                        package = %candidate.package,
                        version = %candidate.version,
                        reason = %reason,
                        "candidate rejected by trust filter"
                    );
                    rejected.push((candidate, reason));
                }
            }
        }

        accepted.sort_by(|a, b| b.version.cmp(&a.version));

        FilterResult { accepted, rejected }
    }

    /// Check a single candidate against trust filters.
    fn check_candidate(
        &self,
        candidate: &VersionCandidate,
        checker: &RevocationChecker<'_>,
    ) -> Result<(), String> {
        // Check if the package version is revoked
        let ecosystem = candidate.package.ecosystem.to_string();
        let version_str = candidate.version.to_string();
        let result = checker.check_version(
            &ecosystem,
            &candidate.package.display_name(),
            &version_str,
        );
        if result.is_revoked() {
            return Err(format!("version revoked"));
        }

        // Check if the artifact digest is revoked
        if let Some(digest) = &candidate.digest {
            let result = checker.check_artifact(digest);
            if result.is_revoked() {
                return Err(format!("artifact digest revoked"));
            }
        }

        // Check yanked status
        if self.reject_yanked && candidate.yanked {
            return Err("package version is yanked".to_string());
        }

        // Check prerelease policy
        if !self.allow_prereleases && candidate.prerelease {
            return Err("prerelease version not allowed".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CandidateMetadata;
    use rusk_core::{PackageId, Version};

    fn make_candidate(name: &str, version: &str, yanked: bool, prerelease: bool) -> VersionCandidate {
        VersionCandidate {
            package: PackageId::js(name),
            version: Version::Semver(semver::Version::parse(version).unwrap()),
            digest: None,
            dependencies: vec![],
            metadata: CandidateMetadata::None,
            yanked,
            prerelease,
        }
    }

    #[test]
    fn filter_accepts_normal_candidates() {
        let filter = TrustAwareCandidateFilter::new(RevocationState::new());
        let candidates = vec![
            make_candidate("foo", "1.0.0", false, false),
            make_candidate("foo", "2.0.0", false, false),
        ];
        let result = filter.filter(candidates);
        assert_eq!(result.accepted.len(), 2);
        assert!(result.rejected.is_empty());
    }

    #[test]
    fn filter_rejects_yanked() {
        let filter = TrustAwareCandidateFilter::new(RevocationState::new());
        let candidates = vec![
            make_candidate("foo", "1.0.0", true, false),
            make_candidate("foo", "2.0.0", false, false),
        ];
        let result = filter.filter(candidates);
        assert_eq!(result.accepted.len(), 1);
        assert_eq!(result.rejected.len(), 1);
    }

    #[test]
    fn filter_rejects_prereleases_by_default() {
        let filter = TrustAwareCandidateFilter::new(RevocationState::new());
        let candidates = vec![
            make_candidate("foo", "1.0.0-alpha.1", false, true),
            make_candidate("foo", "1.0.0", false, false),
        ];
        let result = filter.filter(candidates);
        assert_eq!(result.accepted.len(), 1);
        assert_eq!(result.accepted[0].version.to_string(), "1.0.0");
    }

    #[test]
    fn filter_allows_prereleases_when_configured() {
        let filter = TrustAwareCandidateFilter::new(RevocationState::new())
            .with_allow_prereleases(true);
        let candidates = vec![
            make_candidate("foo", "1.0.0-alpha.1", false, true),
        ];
        let result = filter.filter(candidates);
        assert_eq!(result.accepted.len(), 1);
    }

    #[test]
    fn results_sorted_descending() {
        let filter = TrustAwareCandidateFilter::new(RevocationState::new());
        let candidates = vec![
            make_candidate("foo", "1.0.0", false, false),
            make_candidate("foo", "3.0.0", false, false),
            make_candidate("foo", "2.0.0", false, false),
        ];
        let result = filter.filter(candidates);
        assert_eq!(result.accepted[0].version.to_string(), "3.0.0");
        assert_eq!(result.accepted[1].version.to_string(), "2.0.0");
        assert_eq!(result.accepted[2].version.to_string(), "1.0.0");
    }
}
