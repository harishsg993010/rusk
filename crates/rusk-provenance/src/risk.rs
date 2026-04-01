use crate::normalize::NormalizedProvenance;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

/// Risk flags that indicate potential supply-chain concerns detected
/// during provenance analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    /// The builder is not recognized as a trusted CI system.
    UnknownBuilder,
    /// The build was not performed in a hermetic environment.
    NonHermeticBuild,
    /// The build is not reproducible.
    NonReproducible,
    /// Source repository uses a mutable reference (e.g., branch, not tag/commit).
    MutableSourceRef,
    /// No source information is available.
    NoSourceInfo,
    /// The build happened suspiciously long ago.
    StaleBuild,
    /// Multiple subjects in a single attestation (unusual).
    MultipleSubjects,
    /// SLSA level is below the minimum required.
    LowSlsaLevel,
    /// Materials/dependencies have no pinned digests.
    UnpinnedMaterials,
    /// The predicate type is not a recognized SLSA format.
    NonSlsaPredicate,
    /// Builder ID does not match the expected CI system for this source.
    BuilderSourceMismatch,
}

impl RiskFlag {
    /// Human-readable description of this risk flag.
    pub fn description(&self) -> &'static str {
        match self {
            RiskFlag::UnknownBuilder => "Build was performed by an unrecognized CI system",
            RiskFlag::NonHermeticBuild => "Build environment was not hermetic (may have network access)",
            RiskFlag::NonReproducible => "Build is not marked as reproducible",
            RiskFlag::MutableSourceRef => "Source uses a mutable reference (branch) instead of a commit or tag",
            RiskFlag::NoSourceInfo => "No source repository information available in provenance",
            RiskFlag::StaleBuild => "Build was performed more than 90 days ago",
            RiskFlag::MultipleSubjects => "Attestation covers multiple artifacts (unusual for single-package provenance)",
            RiskFlag::LowSlsaLevel => "SLSA build level is below recommended minimum (L3)",
            RiskFlag::UnpinnedMaterials => "Build inputs lack pinned digests",
            RiskFlag::NonSlsaPredicate => "Attestation uses a non-SLSA predicate format",
            RiskFlag::BuilderSourceMismatch => "Builder CI system does not match the source repository host",
        }
    }

    /// Severity score (0-10) for risk prioritization.
    pub fn severity(&self) -> u8 {
        match self {
            RiskFlag::UnknownBuilder => 8,
            RiskFlag::NonHermeticBuild => 6,
            RiskFlag::NonReproducible => 4,
            RiskFlag::MutableSourceRef => 7,
            RiskFlag::NoSourceInfo => 9,
            RiskFlag::StaleBuild => 3,
            RiskFlag::MultipleSubjects => 2,
            RiskFlag::LowSlsaLevel => 5,
            RiskFlag::UnpinnedMaterials => 6,
            RiskFlag::NonSlsaPredicate => 7,
            RiskFlag::BuilderSourceMismatch => 8,
        }
    }
}

/// Compute risk flags for a normalized provenance record.
///
/// This performs heuristic analysis of the provenance metadata to identify
/// potential supply-chain risks. Each flag indicates a specific concern.
pub fn compute_risk_flags(provenance: &NormalizedProvenance) -> Vec<RiskFlag> {
    let mut flags = Vec::new();

    // Check builder identity.
    if provenance.builder.identity.builder_type == "unknown" {
        flags.push(RiskFlag::UnknownBuilder);
    }

    // Check build environment.
    if !provenance.build_config.hermetic {
        flags.push(RiskFlag::NonHermeticBuild);
    }

    if !provenance.build_config.reproducible {
        flags.push(RiskFlag::NonReproducible);
    }

    // Check source information.
    match &provenance.source {
        None => {
            flags.push(RiskFlag::NoSourceInfo);
        }
        Some(source) => {
            // Check for mutable references.
            if let Some(git_ref) = &source.git_ref {
                if git_ref.starts_with("refs/heads/") {
                    flags.push(RiskFlag::MutableSourceRef);
                }
            }

            // Check builder-source consistency.
            check_builder_source_match(
                &provenance.builder.identity.builder_id,
                &source.repository_url,
                &mut flags,
            );
        }
    }

    // Check build staleness.
    if let Some(build_time) = provenance.metadata.build_started {
        let age = Utc::now() - build_time;
        if age > Duration::days(90) {
            flags.push(RiskFlag::StaleBuild);
        }
    }

    // Check subject count.
    if provenance.subjects.len() > 1 {
        flags.push(RiskFlag::MultipleSubjects);
    }

    // Check SLSA level.
    match provenance.metadata.slsa_level {
        Some(level) if level < 3 => flags.push(RiskFlag::LowSlsaLevel),
        None => flags.push(RiskFlag::LowSlsaLevel),
        _ => {}
    }

    // Check materials pinning.
    let unpinned = provenance
        .materials
        .iter()
        .any(|m| m.digest.is_none());
    if unpinned && !provenance.materials.is_empty() {
        flags.push(RiskFlag::UnpinnedMaterials);
    }

    // Check predicate type.
    if provenance.metadata.predicate_type != "https://slsa.dev/provenance/v1"
        && provenance.metadata.predicate_type != "https://slsa.dev/provenance/v0.2"
    {
        flags.push(RiskFlag::NonSlsaPredicate);
    }

    // Sort by severity (highest first) for consistent output.
    flags.sort_by(|a, b| b.severity().cmp(&a.severity()));
    flags.dedup();
    flags
}

/// Check if the builder CI system matches the source repository host.
fn check_builder_source_match(
    builder_id: &str,
    source_url: &url::Url,
    flags: &mut Vec<RiskFlag>,
) {
    let source_host = source_url.host_str().unwrap_or("");

    let builder_matches = if source_host.contains("github.com") {
        builder_id.contains("github.com")
    } else if source_host.contains("gitlab") {
        builder_id.contains("gitlab")
    } else {
        // Can't determine match for unknown hosts - skip this check.
        return;
    };

    if !builder_matches {
        flags.push(RiskFlag::BuilderSourceMismatch);
    }
}

/// Compute the maximum severity across a set of risk flags.
pub fn max_severity(flags: &[RiskFlag]) -> u8 {
    flags.iter().map(|f| f.severity()).max().unwrap_or(0)
}

/// Filter flags by minimum severity threshold.
pub fn filter_by_severity(flags: &[RiskFlag], min_severity: u8) -> Vec<RiskFlag> {
    flags
        .iter()
        .filter(|f| f.severity() >= min_severity)
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::*;
    use rusk_core::{BuilderIdentity, Sha256Digest};
    use url::Url;

    fn make_good_provenance() -> NormalizedProvenance {
        NormalizedProvenance {
            subjects: vec![ProvenanceSubject {
                name: "pkg-1.0.0.tar.gz".to_string(),
                sha256: Sha256Digest::compute(b"artifact"),
            }],
            source: Some(ProvenanceSource {
                repository_url: Url::parse("https://github.com/owner/repo").unwrap(),
                git_ref: Some("refs/tags/v1.0.0".to_string()),
                commit_sha: Some("abc123def456".to_string()),
            }),
            builder: ProvenanceBuilder {
                identity: BuilderIdentity {
                    builder_type: "github-actions".to_string(),
                    builder_id: "https://github.com/actions/runner".to_string(),
                },
                version: Some("2.310.0".to_string()),
            },
            build_config: ProvBuildConfig {
                command: None,
                environment: std::collections::HashMap::new(),
                hermetic: true,
                reproducible: true,
            },
            materials: vec![ProvMaterial {
                uri: "git+https://github.com/owner/repo".to_string(),
                digest: Some(Sha256Digest::compute(b"dep")),
            }],
            metadata: ProvMetadata {
                build_started: Some(Utc::now() - Duration::hours(1)),
                build_finished: Some(Utc::now()),
                slsa_level: Some(3),
                predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            },
        }
    }

    #[test]
    fn good_provenance_minimal_flags() {
        let prov = make_good_provenance();
        let flags = compute_risk_flags(&prov);
        // Good provenance should have no flags.
        assert!(flags.is_empty(), "unexpected flags: {:?}", flags);
    }

    #[test]
    fn unknown_builder_flagged() {
        let mut prov = make_good_provenance();
        prov.builder.identity.builder_type = "unknown".to_string();
        prov.builder.identity.builder_id = "https://example.com/builder".to_string();
        let flags = compute_risk_flags(&prov);
        assert!(flags.contains(&RiskFlag::UnknownBuilder));
        // Also builder-source mismatch since example.com != github.com.
        assert!(flags.contains(&RiskFlag::BuilderSourceMismatch));
    }

    #[test]
    fn mutable_ref_flagged() {
        let mut prov = make_good_provenance();
        prov.source.as_mut().unwrap().git_ref = Some("refs/heads/main".to_string());
        let flags = compute_risk_flags(&prov);
        assert!(flags.contains(&RiskFlag::MutableSourceRef));
    }

    #[test]
    fn no_source_flagged() {
        let mut prov = make_good_provenance();
        prov.source = None;
        let flags = compute_risk_flags(&prov);
        assert!(flags.contains(&RiskFlag::NoSourceInfo));
    }

    #[test]
    fn non_hermetic_flagged() {
        let mut prov = make_good_provenance();
        prov.build_config.hermetic = false;
        let flags = compute_risk_flags(&prov);
        assert!(flags.contains(&RiskFlag::NonHermeticBuild));
    }

    #[test]
    fn severity_ordering() {
        let flags = vec![
            RiskFlag::StaleBuild,           // severity 3
            RiskFlag::NoSourceInfo,          // severity 9
            RiskFlag::NonHermeticBuild,      // severity 6
        ];
        assert_eq!(max_severity(&flags), 9);

        let high = filter_by_severity(&flags, 7);
        assert_eq!(high, vec![RiskFlag::NoSourceInfo]);
    }

    #[test]
    fn risk_flag_descriptions() {
        // Ensure all variants have non-empty descriptions.
        let all_flags = vec![
            RiskFlag::UnknownBuilder,
            RiskFlag::NonHermeticBuild,
            RiskFlag::NonReproducible,
            RiskFlag::MutableSourceRef,
            RiskFlag::NoSourceInfo,
            RiskFlag::StaleBuild,
            RiskFlag::MultipleSubjects,
            RiskFlag::LowSlsaLevel,
            RiskFlag::UnpinnedMaterials,
            RiskFlag::NonSlsaPredicate,
            RiskFlag::BuilderSourceMismatch,
        ];
        for flag in all_flags {
            assert!(!flag.description().is_empty());
            assert!(flag.severity() > 0);
        }
    }
}
