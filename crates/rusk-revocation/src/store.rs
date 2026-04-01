use crate::bundle::{RevocationBundle, RevocationBundleError, RevocationEntry};
use chrono::{DateTime, Utc};
use rusk_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The local revocation state, tracking all known revocations.
///
/// This is the in-memory representation that gets queried during verification.
/// It is updated by applying `RevocationBundle`s.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RevocationState {
    /// Current epoch (highest applied bundle epoch).
    pub epoch: u64,

    /// Revoked signer identities, stored as "issuer:subject" keys.
    pub revoked_signers: HashSet<String>,

    /// Revoked builder identities, stored as "type:id" keys.
    pub revoked_builders: HashSet<String>,

    /// Revoked artifact digests.
    pub revoked_artifacts: HashSet<Sha256Digest>,

    /// Revoked provenance attestation digests.
    pub revoked_provenance: HashSet<Sha256Digest>,

    /// Revoked package versions, stored as "ecosystem:name:version" keys.
    pub revoked_versions: HashSet<String>,

    /// Timestamp of the last update.
    pub last_updated: Option<DateTime<Utc>>,
}

impl RevocationState {
    /// Create a new empty revocation state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a revocation bundle to this state.
    ///
    /// The bundle's epoch must be greater than the current epoch (monotonic).
    pub fn apply_bundle(&mut self, bundle: &RevocationBundle) -> Result<(), RevocationBundleError> {
        if bundle.epoch <= self.epoch && self.epoch > 0 {
            return Err(RevocationBundleError::StaleEpoch {
                bundle: bundle.epoch,
                current: self.epoch,
            });
        }

        for entry in &bundle.entries {
            self.apply_entry(entry);
        }

        self.epoch = bundle.epoch;
        self.last_updated = Some(Utc::now());

        tracing::info!(
            epoch = bundle.epoch,
            entries = bundle.entries.len(),
            "applied revocation bundle"
        );

        Ok(())
    }

    /// Apply a single revocation entry.
    fn apply_entry(&mut self, entry: &RevocationEntry) {
        match entry {
            RevocationEntry::Signer {
                issuer, subject, ..
            } => {
                let key = format!("{}:{}", issuer, subject);
                self.revoked_signers.insert(key);
            }
            RevocationEntry::Builder {
                builder_type,
                builder_id,
                ..
            } => {
                let key = format!("{}:{}", builder_type, builder_id);
                self.revoked_builders.insert(key);
            }
            RevocationEntry::Artifact { digest, .. } => {
                self.revoked_artifacts.insert(*digest);
            }
            RevocationEntry::Provenance {
                attestation_digest, ..
            } => {
                self.revoked_provenance.insert(*attestation_digest);
            }
            RevocationEntry::PackageVersion {
                ecosystem,
                package_name,
                version,
                ..
            } => {
                let key = format!("{}:{}:{}", ecosystem, package_name, version);
                self.revoked_versions.insert(key);
            }
        }
    }

    /// Check if a signer identity is revoked.
    pub fn is_signer_revoked(&self, issuer: &str, subject: &str) -> bool {
        let key = format!("{}:{}", issuer, subject);
        self.revoked_signers.contains(&key)
    }

    /// Check if a builder identity is revoked.
    pub fn is_builder_revoked(&self, builder_type: &str, builder_id: &str) -> bool {
        let key = format!("{}:{}", builder_type, builder_id);
        self.revoked_builders.contains(&key)
    }

    /// Check if an artifact digest is revoked.
    pub fn is_artifact_revoked(&self, digest: &Sha256Digest) -> bool {
        self.revoked_artifacts.contains(digest)
    }

    /// Check if a provenance attestation is revoked.
    pub fn is_provenance_revoked(&self, attestation_digest: &Sha256Digest) -> bool {
        self.revoked_provenance.contains(attestation_digest)
    }

    /// Check if a package version is revoked.
    pub fn is_version_revoked(&self, ecosystem: &str, name: &str, version: &str) -> bool {
        let key = format!("{}:{}:{}", ecosystem, name, version);
        self.revoked_versions.contains(&key)
    }

    /// Total number of revocation entries across all categories.
    pub fn total_revocations(&self) -> usize {
        self.revoked_signers.len()
            + self.revoked_builders.len()
            + self.revoked_artifacts.len()
            + self.revoked_provenance.len()
            + self.revoked_versions.len()
    }

    /// Persist the state to a JSON file.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), RevocationBundleError> {
        let json = serde_json::to_vec_pretty(self)?;
        let temp_path = path.with_extension("json.tmp");
        std::fs::write(&temp_path, &json)?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// Load state from a JSON file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, RevocationBundleError> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Reset all state (for testing or re-initialization).
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_signer_revocation() {
        let mut state = RevocationState::new();
        let mut bundle = RevocationBundle::new(1);
        bundle.add_entry(RevocationEntry::Signer {
            issuer: "https://accounts.google.com".to_string(),
            subject: "bad@example.com".to_string(),
            reason: "key compromise".to_string(),
            revoked_at: Utc::now(),
        });

        state.apply_bundle(&bundle).unwrap();

        assert!(state.is_signer_revoked("https://accounts.google.com", "bad@example.com"));
        assert!(!state.is_signer_revoked("https://accounts.google.com", "good@example.com"));
        assert_eq!(state.epoch, 1);
    }

    #[test]
    fn apply_artifact_revocation() {
        let mut state = RevocationState::new();
        let digest = Sha256Digest::compute(b"malware");
        let mut bundle = RevocationBundle::new(1);
        bundle.add_entry(RevocationEntry::Artifact {
            digest,
            reason: "contains malware".to_string(),
            revoked_at: Utc::now(),
        });

        state.apply_bundle(&bundle).unwrap();
        assert!(state.is_artifact_revoked(&digest));
        assert!(!state.is_artifact_revoked(&Sha256Digest::zero()));
    }

    #[test]
    fn apply_version_revocation() {
        let mut state = RevocationState::new();
        let mut bundle = RevocationBundle::new(1);
        bundle.add_entry(RevocationEntry::PackageVersion {
            ecosystem: "js".to_string(),
            package_name: "evil-pkg".to_string(),
            version: "1.0.0".to_string(),
            reason: "typosquat".to_string(),
            revoked_at: Utc::now(),
        });

        state.apply_bundle(&bundle).unwrap();
        assert!(state.is_version_revoked("js", "evil-pkg", "1.0.0"));
        assert!(!state.is_version_revoked("js", "evil-pkg", "2.0.0"));
    }

    #[test]
    fn stale_epoch_rejected() {
        let mut state = RevocationState::new();
        let bundle1 = RevocationBundle::new(5);
        state.apply_bundle(&bundle1).unwrap();

        let bundle2 = RevocationBundle::new(3);
        let result = state.apply_bundle(&bundle2);
        assert!(result.is_err());
    }

    #[test]
    fn total_revocations() {
        let mut state = RevocationState::new();
        let mut bundle = RevocationBundle::new(1);
        bundle.add_entry(RevocationEntry::Signer {
            issuer: "a".to_string(),
            subject: "b".to_string(),
            reason: "c".to_string(),
            revoked_at: Utc::now(),
        });
        bundle.add_entry(RevocationEntry::Artifact {
            digest: Sha256Digest::zero(),
            reason: "d".to_string(),
            revoked_at: Utc::now(),
        });

        state.apply_bundle(&bundle).unwrap();
        assert_eq!(state.total_revocations(), 2);
    }

    #[test]
    fn reset_clears_state() {
        let mut state = RevocationState::new();
        let mut bundle = RevocationBundle::new(1);
        bundle.add_entry(RevocationEntry::Artifact {
            digest: Sha256Digest::zero(),
            reason: "test".to_string(),
            revoked_at: Utc::now(),
        });
        state.apply_bundle(&bundle).unwrap();
        assert_eq!(state.total_revocations(), 1);

        state.reset();
        assert_eq!(state.total_revocations(), 0);
        assert_eq!(state.epoch, 0);
    }
}
