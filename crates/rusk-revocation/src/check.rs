use crate::store::RevocationState;
use rusk_core::{ArtifactId, BuilderIdentity, Sha256Digest, SignerIdentity};
use serde::{Deserialize, Serialize};

/// The result of a revocation check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RevocationCheckResult {
    /// The entity is not revoked.
    Clear,
    /// The entity has been revoked.
    Revoked {
        /// What type of entity was revoked.
        entity_type: String,
        /// The reason for revocation.
        reason: String,
        /// The epoch at which the revocation was applied.
        epoch: u64,
    },
}

impl RevocationCheckResult {
    /// Whether the check passed (entity is not revoked).
    pub fn is_clear(&self) -> bool {
        matches!(self, RevocationCheckResult::Clear)
    }

    /// Whether the entity is revoked.
    pub fn is_revoked(&self) -> bool {
        matches!(self, RevocationCheckResult::Revoked { .. })
    }

    /// Convert to a `rusk_core::trust::RevocationState`.
    pub fn to_trust_state(&self) -> rusk_core::trust::RevocationState {
        match self {
            RevocationCheckResult::Clear => rusk_core::trust::RevocationState::Clear,
            RevocationCheckResult::Revoked {
                reason, epoch, ..
            } => rusk_core::trust::RevocationState::Revoked {
                reason: reason.clone(),
                epoch: *epoch,
            },
        }
    }
}

/// Comprehensive revocation checker that queries the revocation state
/// for various entity types.
pub struct RevocationChecker<'a> {
    state: &'a RevocationState,
}

impl<'a> RevocationChecker<'a> {
    /// Create a new revocation checker against the given state.
    pub fn new(state: &'a RevocationState) -> Self {
        Self { state }
    }

    /// Get the current revocation epoch.
    pub fn current_epoch(&self) -> u64 {
        self.state.epoch
    }

    /// Check if a signer identity is revoked.
    pub fn check_signer(&self, signer: &SignerIdentity) -> RevocationCheckResult {
        if self
            .state
            .is_signer_revoked(&signer.issuer, &signer.subject)
        {
            tracing::warn!(
                issuer = %signer.issuer,
                subject = %signer.subject,
                "signer is revoked"
            );
            RevocationCheckResult::Revoked {
                entity_type: "signer".to_string(),
                reason: format!("signer {}@{} has been revoked", signer.subject, signer.issuer),
                epoch: self.state.epoch,
            }
        } else {
            RevocationCheckResult::Clear
        }
    }

    /// Check if a builder identity is revoked.
    pub fn check_builder(&self, builder: &BuilderIdentity) -> RevocationCheckResult {
        if self
            .state
            .is_builder_revoked(&builder.builder_type, &builder.builder_id)
        {
            tracing::warn!(
                builder_type = %builder.builder_type,
                builder_id = %builder.builder_id,
                "builder is revoked"
            );
            RevocationCheckResult::Revoked {
                entity_type: "builder".to_string(),
                reason: format!(
                    "builder {}:{} has been revoked",
                    builder.builder_type, builder.builder_id
                ),
                epoch: self.state.epoch,
            }
        } else {
            RevocationCheckResult::Clear
        }
    }

    /// Check if a specific artifact is revoked (by digest).
    pub fn check_artifact(&self, digest: &Sha256Digest) -> RevocationCheckResult {
        if self.state.is_artifact_revoked(digest) {
            tracing::warn!(digest = %digest, "artifact is revoked");
            RevocationCheckResult::Revoked {
                entity_type: "artifact".to_string(),
                reason: format!("artifact {} has been revoked", digest),
                epoch: self.state.epoch,
            }
        } else {
            RevocationCheckResult::Clear
        }
    }

    /// Check if a package version is revoked/yanked.
    pub fn check_version(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> RevocationCheckResult {
        if self
            .state
            .is_version_revoked(ecosystem, package_name, version)
        {
            tracing::warn!(
                ecosystem = ecosystem,
                package = package_name,
                version = version,
                "package version is revoked"
            );
            RevocationCheckResult::Revoked {
                entity_type: "package_version".to_string(),
                reason: format!(
                    "{}:{} version {} has been revoked",
                    ecosystem, package_name, version
                ),
                epoch: self.state.epoch,
            }
        } else {
            RevocationCheckResult::Clear
        }
    }

    /// Check if a provenance attestation has been revoked.
    pub fn check_provenance(&self, attestation_digest: &Sha256Digest) -> RevocationCheckResult {
        if self.state.is_provenance_revoked(attestation_digest) {
            tracing::warn!(digest = %attestation_digest, "provenance attestation is revoked");
            RevocationCheckResult::Revoked {
                entity_type: "provenance".to_string(),
                reason: format!("provenance attestation {} has been revoked", attestation_digest),
                epoch: self.state.epoch,
            }
        } else {
            RevocationCheckResult::Clear
        }
    }

    /// Perform a comprehensive check on an artifact: check the artifact itself,
    /// its signer, its builder, and its package version.
    pub fn check_comprehensive(
        &self,
        artifact_id: &ArtifactId,
        signer: Option<&SignerIdentity>,
        builder: Option<&BuilderIdentity>,
    ) -> Vec<RevocationCheckResult> {
        let mut results = Vec::new();

        // Check artifact digest.
        results.push(self.check_artifact(&artifact_id.digest));

        // Check package version.
        let ecosystem = artifact_id.package.ecosystem.to_string();
        let version = artifact_id.version.to_string();
        results.push(self.check_version(
            &ecosystem,
            &artifact_id.package.display_name(),
            &version,
        ));

        // Check signer if available.
        if let Some(signer) = signer {
            results.push(self.check_signer(signer));
        }

        // Check builder if available.
        if let Some(builder) = builder {
            results.push(self.check_builder(builder));
        }

        results
    }

    /// Check if any result in a list indicates revocation.
    pub fn any_revoked(results: &[RevocationCheckResult]) -> bool {
        results.iter().any(|r| r.is_revoked())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{RevocationBundle, RevocationEntry};
    use chrono::Utc;

    fn setup_state() -> RevocationState {
        let mut state = RevocationState::new();
        let mut bundle = RevocationBundle::new(1);

        bundle.add_entry(RevocationEntry::Signer {
            issuer: "https://accounts.google.com".to_string(),
            subject: "bad@example.com".to_string(),
            reason: "compromised".to_string(),
            revoked_at: Utc::now(),
        });

        bundle.add_entry(RevocationEntry::Artifact {
            digest: Sha256Digest::compute(b"malware"),
            reason: "contains malware".to_string(),
            revoked_at: Utc::now(),
        });

        bundle.add_entry(RevocationEntry::PackageVersion {
            ecosystem: "js".to_string(),
            package_name: "bad-pkg".to_string(),
            version: "1.0.0".to_string(),
            reason: "supply chain attack".to_string(),
            revoked_at: Utc::now(),
        });

        state.apply_bundle(&bundle).unwrap();
        state
    }

    #[test]
    fn check_revoked_signer() {
        let state = setup_state();
        let checker = RevocationChecker::new(&state);

        let bad_signer = SignerIdentity {
            issuer: "https://accounts.google.com".to_string(),
            subject: "bad@example.com".to_string(),
            fingerprint: None,
        };
        assert!(checker.check_signer(&bad_signer).is_revoked());

        let good_signer = SignerIdentity {
            issuer: "https://accounts.google.com".to_string(),
            subject: "good@example.com".to_string(),
            fingerprint: None,
        };
        assert!(checker.check_signer(&good_signer).is_clear());
    }

    #[test]
    fn check_revoked_artifact() {
        let state = setup_state();
        let checker = RevocationChecker::new(&state);

        let bad_digest = Sha256Digest::compute(b"malware");
        assert!(checker.check_artifact(&bad_digest).is_revoked());

        let good_digest = Sha256Digest::compute(b"legit");
        assert!(checker.check_artifact(&good_digest).is_clear());
    }

    #[test]
    fn check_revoked_version() {
        let state = setup_state();
        let checker = RevocationChecker::new(&state);

        assert!(checker.check_version("js", "bad-pkg", "1.0.0").is_revoked());
        assert!(checker.check_version("js", "bad-pkg", "2.0.0").is_clear());
        assert!(checker.check_version("python", "bad-pkg", "1.0.0").is_clear());
    }

    #[test]
    fn to_trust_state_conversion() {
        let clear = RevocationCheckResult::Clear;
        assert!(matches!(
            clear.to_trust_state(),
            rusk_core::trust::RevocationState::Clear
        ));

        let revoked = RevocationCheckResult::Revoked {
            entity_type: "artifact".to_string(),
            reason: "bad".to_string(),
            epoch: 5,
        };
        match revoked.to_trust_state() {
            rusk_core::trust::RevocationState::Revoked { reason, epoch } => {
                assert_eq!(reason, "bad");
                assert_eq!(epoch, 5);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn any_revoked_helper() {
        let results = vec![
            RevocationCheckResult::Clear,
            RevocationCheckResult::Clear,
        ];
        assert!(!RevocationChecker::any_revoked(&results));

        let results_with_revoked = vec![
            RevocationCheckResult::Clear,
            RevocationCheckResult::Revoked {
                entity_type: "signer".to_string(),
                reason: "bad".to_string(),
                epoch: 1,
            },
        ];
        assert!(RevocationChecker::any_revoked(&results_with_revoked));
    }
}
