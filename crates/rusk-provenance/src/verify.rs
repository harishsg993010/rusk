//! Provenance verification logic.
//!
//! Verifies that a provenance attestation correctly binds an artifact
//! to its source, builder, and build configuration.

use crate::attestation::InTotoStatement;
use crate::normalize::NormalizedProvenance;
use rusk_core::{Sha256Digest, VerificationResult};

/// Result of provenance verification.
#[derive(Clone, Debug)]
pub enum ProvenanceVerifyResult {
    /// Provenance verified successfully.
    Verified {
        provenance: NormalizedProvenance,
    },
    /// Provenance signature is invalid.
    SignatureInvalid {
        reason: String,
    },
    /// Provenance subject does not match the artifact.
    SubjectMismatch {
        expected: Sha256Digest,
        found: Vec<String>,
    },
    /// Provenance is missing required fields.
    Incomplete {
        missing_fields: Vec<String>,
    },
}

impl ProvenanceVerifyResult {
    /// Whether the verification passed.
    pub fn is_verified(&self) -> bool {
        matches!(self, ProvenanceVerifyResult::Verified { .. })
    }
}

/// Verify that the provenance statement correctly references the given artifact.
pub fn verify_subject_binding(
    statement: &InTotoStatement,
    expected_digest: &Sha256Digest,
) -> bool {
    let expected_hex = expected_digest.to_hex();
    statement.subject.iter().any(|s| {
        s.digest.get("sha256").map_or(false, |d| d == &expected_hex)
    })
}
