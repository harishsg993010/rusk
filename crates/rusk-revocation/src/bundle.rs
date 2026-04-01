use chrono::{DateTime, Utc};
use rusk_core::Sha256Digest;
use serde::{Deserialize, Serialize};

/// Errors from revocation bundle processing.
#[derive(Debug, thiserror::Error)]
pub enum RevocationBundleError {
    #[error("invalid bundle signature")]
    InvalidSignature,

    #[error("bundle epoch {bundle} is not newer than current epoch {current}")]
    StaleEpoch { bundle: u64, current: u64 },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// A single revocation entry specifying what has been revoked and why.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RevocationEntry {
    /// A signer identity has been revoked (compromised key, etc.).
    Signer {
        /// OIDC issuer of the revoked signer.
        issuer: String,
        /// OIDC subject of the revoked signer.
        subject: String,
        /// Human-readable reason.
        reason: String,
        /// When the revocation takes effect.
        revoked_at: DateTime<Utc>,
    },

    /// A builder identity has been revoked.
    Builder {
        /// Builder type identifier.
        builder_type: String,
        /// Builder ID URL.
        builder_id: String,
        /// Reason for revocation.
        reason: String,
        revoked_at: DateTime<Utc>,
    },

    /// A specific artifact (by digest) has been revoked.
    Artifact {
        /// SHA-256 digest of the revoked artifact.
        digest: Sha256Digest,
        /// Reason for revocation.
        reason: String,
        revoked_at: DateTime<Utc>,
    },

    /// A provenance attestation has been revoked (e.g., fraudulent).
    Provenance {
        /// SHA-256 digest of the attestation envelope.
        attestation_digest: Sha256Digest,
        /// Reason for revocation.
        reason: String,
        revoked_at: DateTime<Utc>,
    },

    /// A specific package version has been revoked (yanked).
    PackageVersion {
        /// Package ecosystem (e.g., "js", "python").
        ecosystem: String,
        /// Package name.
        package_name: String,
        /// Version string.
        version: String,
        /// Reason for revocation.
        reason: String,
        revoked_at: DateTime<Utc>,
    },
}

impl RevocationEntry {
    /// Get the revocation timestamp.
    pub fn revoked_at(&self) -> DateTime<Utc> {
        match self {
            RevocationEntry::Signer { revoked_at, .. }
            | RevocationEntry::Builder { revoked_at, .. }
            | RevocationEntry::Artifact { revoked_at, .. }
            | RevocationEntry::Provenance { revoked_at, .. }
            | RevocationEntry::PackageVersion { revoked_at, .. } => *revoked_at,
        }
    }

    /// Get the reason for revocation.
    pub fn reason(&self) -> &str {
        match self {
            RevocationEntry::Signer { reason, .. }
            | RevocationEntry::Builder { reason, .. }
            | RevocationEntry::Artifact { reason, .. }
            | RevocationEntry::Provenance { reason, .. }
            | RevocationEntry::PackageVersion { reason, .. } => reason,
        }
    }

    /// A short type label for display.
    pub fn entry_type(&self) -> &'static str {
        match self {
            RevocationEntry::Signer { .. } => "signer",
            RevocationEntry::Builder { .. } => "builder",
            RevocationEntry::Artifact { .. } => "artifact",
            RevocationEntry::Provenance { .. } => "provenance",
            RevocationEntry::PackageVersion { .. } => "package_version",
        }
    }
}

/// A signed bundle of revocation entries, distributed atomically.
///
/// Revocation bundles are fetched periodically from the revocation service
/// and applied to the local revocation state. Each bundle has a monotonically
/// increasing epoch number.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationBundle {
    /// Monotonically increasing epoch number.
    pub epoch: u64,
    /// When this bundle was published.
    pub published_at: DateTime<Utc>,
    /// The revocation entries in this bundle.
    pub entries: Vec<RevocationEntry>,
    /// Hex-encoded signature over the canonical bundle content.
    pub signature_hex: Option<String>,
    /// SHA-256 digest of the previous bundle (chain integrity).
    pub previous_digest: Option<Sha256Digest>,
}

impl RevocationBundle {
    /// Create a new empty bundle at the given epoch.
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            published_at: Utc::now(),
            entries: Vec::new(),
            signature_hex: None,
            previous_digest: None,
        }
    }

    /// Add a revocation entry to this bundle.
    pub fn add_entry(&mut self, entry: RevocationEntry) {
        self.entries.push(entry);
    }

    /// Number of entries in this bundle.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether this bundle is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute the digest of this bundle's content for chaining.
    pub fn content_digest(&self) -> Sha256Digest {
        let content = serde_json::json!({
            "epoch": self.epoch,
            "published_at": self.published_at.to_rfc3339(),
            "entries": self.entries,
        });
        let bytes = serde_json::to_vec(&content).unwrap_or_default();
        Sha256Digest::compute(&bytes)
    }

    /// Parse a bundle from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, RevocationBundleError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Serialize this bundle to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, RevocationBundleError> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Get entries of a specific type.
    pub fn entries_of_type(&self, entry_type: &str) -> Vec<&RevocationEntry> {
        self.entries
            .iter()
            .filter(|e| e.entry_type() == entry_type)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_creation() {
        let mut bundle = RevocationBundle::new(1);
        assert!(bundle.is_empty());

        bundle.add_entry(RevocationEntry::Signer {
            issuer: "https://accounts.google.com".to_string(),
            subject: "compromised@example.com".to_string(),
            reason: "key compromise".to_string(),
            revoked_at: Utc::now(),
        });

        assert_eq!(bundle.len(), 1);
        assert!(!bundle.is_empty());
    }

    #[test]
    fn entry_types() {
        let signer = RevocationEntry::Signer {
            issuer: "test".to_string(),
            subject: "test".to_string(),
            reason: "test".to_string(),
            revoked_at: Utc::now(),
        };
        assert_eq!(signer.entry_type(), "signer");

        let artifact = RevocationEntry::Artifact {
            digest: Sha256Digest::zero(),
            reason: "malware".to_string(),
            revoked_at: Utc::now(),
        };
        assert_eq!(artifact.entry_type(), "artifact");

        let pkg = RevocationEntry::PackageVersion {
            ecosystem: "js".to_string(),
            package_name: "evil-pkg".to_string(),
            version: "1.0.0".to_string(),
            reason: "typosquat".to_string(),
            revoked_at: Utc::now(),
        };
        assert_eq!(pkg.entry_type(), "package_version");
    }

    #[test]
    fn bundle_json_roundtrip() {
        let mut bundle = RevocationBundle::new(5);
        bundle.add_entry(RevocationEntry::Artifact {
            digest: Sha256Digest::compute(b"bad"),
            reason: "contains malware".to_string(),
            revoked_at: Utc::now(),
        });

        let json = bundle.to_json().unwrap();
        let parsed = RevocationBundle::from_json(&json).unwrap();
        assert_eq!(parsed.epoch, 5);
        assert_eq!(parsed.entries.len(), 1);
    }

    #[test]
    fn content_digest_deterministic() {
        let bundle = RevocationBundle::new(1);
        let d1 = bundle.content_digest();
        let d2 = bundle.content_digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn entries_by_type() {
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
        bundle.add_entry(RevocationEntry::Signer {
            issuer: "e".to_string(),
            subject: "f".to_string(),
            reason: "g".to_string(),
            revoked_at: Utc::now(),
        });

        assert_eq!(bundle.entries_of_type("signer").len(), 2);
        assert_eq!(bundle.entries_of_type("artifact").len(), 1);
        assert_eq!(bundle.entries_of_type("builder").len(), 0);
    }
}
