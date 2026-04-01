use crate::attestation::{DsseEnvelope, InTotoStatement};
use crate::normalize::NormalizedProvenance;
use crate::risk::RiskFlag;
use chrono::{DateTime, Utc};
use rusk_core::{BuilderIdentity, Sha256Digest, SignerIdentity};
use serde::{Deserialize, Serialize};

/// A fully verified provenance bundle tying together the raw attestation,
/// normalized provenance, verification results, and risk analysis.
///
/// This is the final output of the provenance verification pipeline and
/// provides everything downstream consumers (policy engine, auditing) need.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedProvenance {
    /// The artifact digest this provenance covers.
    pub artifact_digest: Sha256Digest,

    /// The signer who signed the attestation envelope.
    pub signer: SignerIdentity,

    /// The builder that produced the artifact.
    pub builder: BuilderIdentity,

    /// Source repository URL (if available).
    pub source_repo: Option<String>,

    /// Git commit SHA (if available).
    pub source_commit: Option<String>,

    /// Timestamp of the attestation verification.
    pub verified_at: DateTime<Utc>,

    /// Normalized provenance data.
    pub normalized: NormalizedProvenance,

    /// Risk flags identified during analysis.
    pub risk_flags: Vec<RiskFlag>,

    /// The raw DSSE envelope (for audit/re-verification).
    #[serde(skip)]
    pub raw_envelope: Option<DsseEnvelope>,

    /// The parsed in-toto statement (for detailed inspection).
    #[serde(skip)]
    pub raw_statement: Option<InTotoStatement>,
}

impl VerifiedProvenance {
    /// Create a verified provenance bundle from the pipeline outputs.
    pub fn new(
        artifact_digest: Sha256Digest,
        signer: SignerIdentity,
        normalized: NormalizedProvenance,
        risk_flags: Vec<RiskFlag>,
        envelope: DsseEnvelope,
        statement: InTotoStatement,
    ) -> Self {
        let source_repo = normalized
            .source
            .as_ref()
            .map(|s| s.repository_url.to_string());
        let source_commit = normalized
            .source
            .as_ref()
            .and_then(|s| s.commit_sha.clone());

        Self {
            artifact_digest,
            signer,
            builder: normalized.builder.identity.clone(),
            source_repo,
            source_commit,
            verified_at: Utc::now(),
            normalized,
            risk_flags,
            raw_envelope: Some(envelope),
            raw_statement: Some(statement),
        }
    }

    /// Whether any high-severity (>= 7) risk flags were identified.
    pub fn has_high_risk(&self) -> bool {
        self.risk_flags.iter().any(|f| f.severity() >= 7)
    }

    /// Whether any risk flags were identified at all.
    pub fn has_risk(&self) -> bool {
        !self.risk_flags.is_empty()
    }

    /// Get the maximum risk severity.
    pub fn max_risk_severity(&self) -> u8 {
        crate::risk::max_severity(&self.risk_flags)
    }

    /// Convert to the rusk-core `VerifiedProvenanceRef` for the trust state.
    pub fn to_trust_ref(&self) -> rusk_core::trust::VerifiedProvenanceRef {
        rusk_core::trust::VerifiedProvenanceRef {
            builder: self.builder.clone(),
            source_repo: self.source_repo.clone().unwrap_or_default(),
            commit: self.source_commit.clone().unwrap_or_default(),
        }
    }

    /// Summary string for logging/display.
    pub fn summary(&self) -> String {
        let risk_str = if self.risk_flags.is_empty() {
            "no risks".to_string()
        } else {
            format!("{} risk(s), max severity {}", self.risk_flags.len(), self.max_risk_severity())
        };

        format!(
            "provenance: builder={}, source={}, {}",
            self.builder.builder_type,
            self.source_repo.as_deref().unwrap_or("unknown"),
            risk_str,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalize::*;
    use url::Url;

    fn make_test_provenance() -> VerifiedProvenance {
        let normalized = NormalizedProvenance {
            subjects: vec![ProvenanceSubject {
                name: "pkg-1.0.0.tar.gz".to_string(),
                sha256: Sha256Digest::compute(b"artifact"),
            }],
            source: Some(ProvenanceSource {
                repository_url: Url::parse("https://github.com/owner/repo").unwrap(),
                git_ref: Some("refs/tags/v1.0.0".to_string()),
                commit_sha: Some("abc123".to_string()),
            }),
            builder: ProvenanceBuilder {
                identity: BuilderIdentity {
                    builder_type: "github-actions".to_string(),
                    builder_id: "https://github.com/actions/runner".to_string(),
                },
                version: Some("2.310.0".to_string()),
            },
            build_config: ProvBuildConfig::default(),
            materials: vec![],
            metadata: ProvMetadata {
                build_started: Some(Utc::now()),
                build_finished: None,
                slsa_level: Some(3),
                predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            },
        };

        VerifiedProvenance {
            artifact_digest: Sha256Digest::compute(b"artifact"),
            signer: SignerIdentity {
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                subject: "repo:owner/repo:ref:refs/tags/v1.0.0".to_string(),
                fingerprint: None,
            },
            builder: normalized.builder.identity.clone(),
            source_repo: Some("https://github.com/owner/repo".to_string()),
            source_commit: Some("abc123".to_string()),
            verified_at: Utc::now(),
            normalized,
            risk_flags: vec![],
            raw_envelope: None,
            raw_statement: None,
        }
    }

    #[test]
    fn no_risk_flags() {
        let prov = make_test_provenance();
        assert!(!prov.has_risk());
        assert!(!prov.has_high_risk());
        assert_eq!(prov.max_risk_severity(), 0);
    }

    #[test]
    fn with_risk_flags() {
        let mut prov = make_test_provenance();
        prov.risk_flags = vec![RiskFlag::NonHermeticBuild, RiskFlag::NoSourceInfo];
        assert!(prov.has_risk());
        assert!(prov.has_high_risk()); // NoSourceInfo has severity 9
        assert_eq!(prov.max_risk_severity(), 9);
    }

    #[test]
    fn trust_ref_conversion() {
        let prov = make_test_provenance();
        let trust_ref = prov.to_trust_ref();
        assert_eq!(trust_ref.builder.builder_type, "github-actions");
        assert_eq!(trust_ref.source_repo, "https://github.com/owner/repo");
        assert_eq!(trust_ref.commit, "abc123");
    }

    #[test]
    fn summary_format() {
        let prov = make_test_provenance();
        let summary = prov.summary();
        assert!(summary.contains("github-actions"));
        assert!(summary.contains("no risks"));
    }
}
