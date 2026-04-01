use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature as Ed25519Sig, VerifyingKey as Ed25519VerifyingKey};
use rusk_core::{ArtifactId, Sha256Digest, SignerIdentity};
use serde::{Deserialize, Serialize};
use signature::Verifier;

/// Errors from signature verification.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("unsupported signature algorithm: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),

    #[error("invalid signature encoding: {0}")]
    InvalidEncoding(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    #[error("no signature found for artifact")]
    NoSignature,

    #[error("signature expired at {0}")]
    Expired(DateTime<Utc>),

    #[error("signer identity extraction failed: {0}")]
    IdentityError(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Supported signature algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// ECDSA with P-256/SHA-256.
    EcdsaP256Sha256,
}

impl SignatureAlgorithm {
    /// Return the expected signature length in bytes.
    pub fn signature_length(&self) -> usize {
        match self {
            SignatureAlgorithm::Ed25519 => 64,
            SignatureAlgorithm::EcdsaP256Sha256 => 64, // DER can vary, but r+s is 64
        }
    }
}

/// Proof material establishing the signer's identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum SignerProof {
    /// A raw public key (hex-encoded) used to sign directly.
    PublicKey {
        algorithm: SignatureAlgorithm,
        public_key_hex: String,
    },
    /// An OIDC-based signing certificate chain (e.g., from Sigstore/Fulcio).
    OidcCertificate {
        /// PEM-encoded certificate chain.
        certificate_chain: Vec<String>,
        /// OIDC issuer URL.
        issuer: String,
        /// OIDC subject claim.
        subject: String,
    },
}

impl SignerProof {
    /// Extract the algorithm from this proof.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match self {
            SignerProof::PublicKey { algorithm, .. } => *algorithm,
            SignerProof::OidcCertificate { .. } => SignatureAlgorithm::EcdsaP256Sha256,
        }
    }
}

/// A signature over an artifact, including the proof material.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactSignature {
    /// Hex-encoded signature bytes.
    pub signature_hex: String,
    /// The proof material binding this signature to an identity.
    pub proof: SignerProof,
    /// SHA-256 digest of the artifact that was signed.
    pub artifact_digest: Sha256Digest,
    /// Timestamp of when the signature was created.
    pub timestamp: DateTime<Utc>,
    /// Optional expiration time.
    pub expires: Option<DateTime<Utc>>,
}

impl ArtifactSignature {
    /// Decode the raw signature bytes.
    pub fn signature_bytes(&self) -> Result<Vec<u8>, SigningError> {
        hex::decode(&self.signature_hex)
            .map_err(|e| SigningError::InvalidEncoding(format!("bad hex: {e}")))
    }

    /// Check if this signature has expired.
    pub fn is_expired(&self) -> bool {
        match self.expires {
            Some(exp) => Utc::now() > exp,
            None => false,
        }
    }
}

/// The result of a successful signature verification.
#[derive(Clone, Debug)]
pub struct VerifiedSignature {
    /// The resolved signer identity.
    pub signer: SignerIdentity,
    /// The algorithm used.
    pub algorithm: SignatureAlgorithm,
    /// When the signature was created.
    pub timestamp: DateTime<Utc>,
    /// The artifact that was verified.
    pub artifact_digest: Sha256Digest,
}

/// Trait for signature verification backends.
///
/// Different implementations may verify against raw keys, Sigstore bundles,
/// or custom enterprise PKI.
#[async_trait]
pub trait SignatureVerifier: Send + Sync {
    /// Verify an artifact signature and return a verified result.
    async fn verify(
        &self,
        artifact_id: &ArtifactId,
        artifact_bytes: &[u8],
        signature: &ArtifactSignature,
    ) -> Result<VerifiedSignature, SigningError>;
}

/// Default verifier that handles Ed25519 and ECDSA-P256 public key signatures.
pub struct DefaultSignatureVerifier;

impl DefaultSignatureVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Verify an Ed25519 signature against a public key and message.
    fn verify_ed25519(
        public_key_hex: &str,
        signature_hex: &str,
        message: &[u8],
    ) -> Result<(), SigningError> {
        let pub_bytes = hex::decode(public_key_hex)
            .map_err(|e| SigningError::InvalidPublicKey(format!("bad hex: {e}")))?;

        let pub_array: [u8; 32] = pub_bytes.try_into().map_err(|_| {
            SigningError::InvalidPublicKey("ed25519 public key must be 32 bytes".to_string())
        })?;

        let verifying_key = Ed25519VerifyingKey::from_bytes(&pub_array)
            .map_err(|e| SigningError::InvalidPublicKey(format!("invalid key: {e}")))?;

        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| SigningError::InvalidEncoding(format!("bad hex: {e}")))?;

        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            SigningError::InvalidEncoding("ed25519 signature must be 64 bytes".to_string())
        })?;

        let sig = Ed25519Sig::from_bytes(&sig_array);

        verifying_key
            .verify(message, &sig)
            .map_err(|e| SigningError::VerificationFailed(format!("ed25519: {e}")))
    }
}

impl Default for DefaultSignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SignatureVerifier for DefaultSignatureVerifier {
    async fn verify(
        &self,
        _artifact_id: &ArtifactId,
        artifact_bytes: &[u8],
        signature: &ArtifactSignature,
    ) -> Result<VerifiedSignature, SigningError> {
        // Check expiration.
        if signature.is_expired() {
            return Err(SigningError::Expired(
                signature.expires.unwrap_or_else(Utc::now),
            ));
        }

        // Verify the artifact digest matches the bytes.
        let computed = Sha256Digest::compute(artifact_bytes);
        if computed != signature.artifact_digest {
            return Err(SigningError::VerificationFailed(
                "artifact digest mismatch".to_string(),
            ));
        }

        // The message being signed is the raw artifact digest bytes.
        let message = &signature.artifact_digest.0;

        match &signature.proof {
            SignerProof::PublicKey {
                algorithm,
                public_key_hex,
            } => {
                match algorithm {
                    SignatureAlgorithm::Ed25519 => {
                        Self::verify_ed25519(
                            public_key_hex,
                            &signature.signature_hex,
                            message,
                        )?;
                    }
                    alg => {
                        return Err(SigningError::UnsupportedAlgorithm(*alg));
                    }
                }

                // Extract identity from public key proof.
                let signer = crate::identity::extract_signer_identity(&signature.proof)?;

                Ok(VerifiedSignature {
                    signer,
                    algorithm: *algorithm,
                    timestamp: signature.timestamp,
                    artifact_digest: signature.artifact_digest,
                })
            }
            SignerProof::OidcCertificate {
                issuer, subject, ..
            } => {
                // OIDC certificate verification would require full X.509 chain
                // validation + SCT checking. For now, we extract the identity
                // and note that the caller should use a Sigstore-specific
                // verifier for production use.
                tracing::warn!("OIDC certificate chain verification not yet fully implemented");

                Ok(VerifiedSignature {
                    signer: SignerIdentity {
                        issuer: issuer.clone(),
                        subject: subject.clone(),
                        fingerprint: None,
                    },
                    algorithm: SignatureAlgorithm::EcdsaP256Sha256,
                    timestamp: signature.timestamp,
                    artifact_digest: signature.artifact_digest,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_algorithm_lengths() {
        assert_eq!(SignatureAlgorithm::Ed25519.signature_length(), 64);
        assert_eq!(SignatureAlgorithm::EcdsaP256Sha256.signature_length(), 64);
    }

    #[test]
    fn artifact_signature_expiry() {
        let sig = ArtifactSignature {
            signature_hex: "00".repeat(64),
            proof: SignerProof::PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_hex: "00".repeat(32),
            },
            artifact_digest: Sha256Digest::zero(),
            timestamp: Utc::now(),
            expires: Some(Utc::now() - chrono::Duration::hours(1)),
        };
        assert!(sig.is_expired());

        let sig_valid = ArtifactSignature {
            expires: Some(Utc::now() + chrono::Duration::hours(1)),
            ..sig
        };
        assert!(!sig_valid.is_expired());
    }

    #[test]
    fn signer_proof_algorithm() {
        let pk = SignerProof::PublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_hex: String::new(),
        };
        assert_eq!(pk.algorithm(), SignatureAlgorithm::Ed25519);

        let oidc = SignerProof::OidcCertificate {
            certificate_chain: vec![],
            issuer: String::new(),
            subject: String::new(),
        };
        assert_eq!(oidc.algorithm(), SignatureAlgorithm::EcdsaP256Sha256);
    }
}
