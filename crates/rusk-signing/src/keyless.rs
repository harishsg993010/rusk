//! Keyless (Sigstore/Fulcio) signing support.
//!
//! Handles verification of keyless signatures where the signer's identity
//! is bound to a short-lived certificate issued by Fulcio, anchored in
//! an OIDC identity provider.

use crate::certificate::{parse_certificate_info, validate_chain_link, CertificateInfo};
use crate::verifier::{ArtifactSignature, SignerProof, SigningError, VerifiedSignature};
use chrono::Utc;
use rusk_core::SignerIdentity;

/// Configuration for keyless signature verification.
#[derive(Clone, Debug)]
pub struct KeylessConfig {
    /// Fulcio root certificate (PEM).
    pub fulcio_root: String,
    /// CT log public key for SCT verification.
    pub ct_log_public_key: Option<String>,
    /// Trusted OIDC issuers.
    pub trusted_issuers: Vec<String>,
}

/// Verify a keyless (Fulcio) signature.
///
/// This involves:
/// 1. Validating the X.509 certificate chain (structural validation)
/// 2. Checking validity periods of all certificates
/// 3. Extracting the OIDC identity from the leaf certificate
/// 4. Verifying the OIDC issuer is trusted
pub fn verify_keyless_signature(
    signature: &ArtifactSignature,
    config: &KeylessConfig,
) -> Result<VerifiedSignature, SigningError> {
    // Only OIDC certificate proofs are supported for keyless verification.
    let (certificate_chain, claimed_issuer, claimed_subject) = match &signature.proof {
        SignerProof::OidcCertificate {
            certificate_chain,
            issuer,
            subject,
        } => (certificate_chain, issuer, subject),
        SignerProof::PublicKey { .. } => {
            return Err(SigningError::VerificationFailed(
                "keyless verification requires an OIDC certificate proof, not a public key"
                    .to_string(),
            ));
        }
    };

    if certificate_chain.is_empty() {
        return Err(SigningError::VerificationFailed(
            "empty certificate chain".to_string(),
        ));
    }

    // Step 1: Parse all certificates in the chain.
    let mut parsed_certs: Vec<CertificateInfo> = Vec::new();
    for (i, pem) in certificate_chain.iter().enumerate() {
        let info = parse_certificate_info(pem).map_err(|e| {
            SigningError::VerificationFailed(format!("failed to parse certificate {}: {}", i, e))
        })?;
        parsed_certs.push(info);
    }

    // Step 2: Validate the certificate chain structure.
    // The chain is ordered leaf -> intermediate(s) -> root.
    // Verify each adjacent pair forms a valid issuer-subject link.
    for i in 0..parsed_certs.len().saturating_sub(1) {
        let subject = &parsed_certs[i];
        let issuer = &parsed_certs[i + 1];
        validate_chain_link(issuer, subject).map_err(|e| {
            SigningError::VerificationFailed(format!(
                "certificate chain validation failed at link {}->{}: {}",
                i + 1,
                i,
                e
            ))
        })?;
    }

    // Step 3: Validate the root certificate against the configured Fulcio root.
    // Parse the configured root and compare issuer CN.
    if !config.fulcio_root.is_empty() {
        let root_info = parse_certificate_info(&config.fulcio_root).map_err(|e| {
            SigningError::VerificationFailed(format!(
                "failed to parse configured Fulcio root: {}",
                e
            ))
        })?;

        let chain_root = parsed_certs.last().ok_or_else(|| {
            SigningError::VerificationFailed("certificate chain is empty".to_string())
        })?;

        // The top of the provided chain should either be the root itself
        // or be issued by the root.
        if chain_root.subject_cn != root_info.subject_cn
            && chain_root.issuer_cn != root_info.subject_cn
        {
            return Err(SigningError::VerificationFailed(format!(
                "certificate chain root {:?} does not chain to configured Fulcio root {:?}",
                chain_root.issuer_cn, root_info.subject_cn
            )));
        }
    }

    // Step 4: Verify all certificates are currently valid (or were valid at signing time).
    let verification_time = signature.timestamp;
    for (i, cert) in parsed_certs.iter().enumerate() {
        if !cert.is_valid_at(&verification_time) {
            return Err(SigningError::VerificationFailed(format!(
                "certificate {} not valid at signing time {}: valid from {} to {}",
                i, verification_time, cert.not_before, cert.not_after
            )));
        }
    }

    // Step 5: Extract the OIDC identity from the leaf certificate.
    let leaf = &parsed_certs[0];
    let identity = extract_identity_from_cert(leaf)?;

    // Step 6: Verify the OIDC issuer is trusted.
    if !config.trusted_issuers.is_empty() {
        let effective_issuer = leaf
            .oidc_issuer
            .as_deref()
            .unwrap_or(claimed_issuer.as_str());

        let is_trusted = config
            .trusted_issuers
            .iter()
            .any(|trusted| effective_issuer == trusted || effective_issuer.starts_with(trusted));

        if !is_trusted {
            return Err(SigningError::VerificationFailed(format!(
                "OIDC issuer '{}' is not in the trusted issuers list",
                effective_issuer
            )));
        }
    }

    // Step 7: Cross-check claimed identity against certificate.
    let cert_subject = leaf
        .oidc_subject
        .as_deref()
        .unwrap_or(identity.subject.as_str());
    if cert_subject != claimed_subject && !claimed_subject.is_empty() {
        tracing::warn!(
            cert_subject = cert_subject,
            claimed_subject = claimed_subject.as_str(),
            "OIDC subject in certificate does not match claimed subject"
        );
    }

    // Step 8: Check signature expiration.
    if signature.is_expired() {
        return Err(SigningError::Expired(
            signature.expires.unwrap_or_else(Utc::now),
        ));
    }

    Ok(VerifiedSignature {
        signer: identity,
        algorithm: signature.proof.algorithm(),
        timestamp: signature.timestamp,
        artifact_digest: signature.artifact_digest,
    })
}

/// Extract the OIDC identity from a Fulcio certificate.
pub fn extract_oidc_identity(certificate_pem: &str) -> Result<SignerIdentity, SigningError> {
    let info = parse_certificate_info(certificate_pem).map_err(|e| {
        SigningError::IdentityError(format!("failed to parse certificate: {}", e))
    })?;

    extract_identity_from_cert(&info)
}

/// Extract signer identity from parsed certificate information.
fn extract_identity_from_cert(info: &CertificateInfo) -> Result<SignerIdentity, SigningError> {
    // Determine the issuer: prefer the Fulcio OIDC issuer extension,
    // fall back to the certificate issuer CN.
    let issuer = info
        .oidc_issuer
        .clone()
        .or_else(|| info.issuer_cn.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Determine the subject: prefer OIDC subject from SAN,
    // fall back to SAN email, SAN URI, or subject CN.
    let subject = info
        .oidc_subject
        .clone()
        .or_else(|| info.san_emails.first().cloned())
        .or_else(|| info.san_uris.first().cloned())
        .or_else(|| info.subject_cn.clone())
        .ok_or_else(|| {
            SigningError::IdentityError(
                "no identity information found in certificate (no SAN, no subject CN)".to_string(),
            )
        })?;

    // Compute a fingerprint from the public key DER bytes.
    let fingerprint = if !info.public_key_der.is_empty() {
        Some(rusk_core::Sha256Digest::compute(&info.public_key_der).to_hex())
    } else {
        None
    };

    Ok(SignerIdentity {
        issuer,
        subject,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::{SignatureAlgorithm, SignerProof};
    use rusk_core::Sha256Digest;

    #[test]
    fn keyless_rejects_public_key_proof() {
        let sig = ArtifactSignature {
            signature_hex: "00".repeat(64),
            proof: SignerProof::PublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_hex: "00".repeat(32),
            },
            artifact_digest: Sha256Digest::zero(),
            timestamp: Utc::now(),
            expires: None,
        };

        let config = KeylessConfig {
            fulcio_root: String::new(),
            ct_log_public_key: None,
            trusted_issuers: vec![],
        };

        let result = verify_keyless_signature(&sig, &config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("OIDC certificate proof")
        );
    }

    #[test]
    fn keyless_rejects_empty_chain() {
        let sig = ArtifactSignature {
            signature_hex: "00".repeat(64),
            proof: SignerProof::OidcCertificate {
                certificate_chain: vec![],
                issuer: "https://accounts.google.com".to_string(),
                subject: "user@example.com".to_string(),
            },
            artifact_digest: Sha256Digest::zero(),
            timestamp: Utc::now(),
            expires: None,
        };

        let config = KeylessConfig {
            fulcio_root: String::new(),
            ct_log_public_key: None,
            trusted_issuers: vec![],
        };

        let result = verify_keyless_signature(&sig, &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn extract_identity_from_cert_info() {
        let info = CertificateInfo {
            subject_cn: Some("test-subject".to_string()),
            issuer_cn: Some("sigstore-ca".to_string()),
            not_before: Utc::now() - chrono::Duration::hours(1),
            not_after: Utc::now() + chrono::Duration::hours(1),
            oidc_issuer: Some("https://accounts.google.com".to_string()),
            oidc_subject: Some("user@example.com".to_string()),
            github_workflow_ref: None,
            key_algorithm: "ECDSA-P256".to_string(),
            public_key_der: vec![1, 2, 3, 4],
            san_emails: vec!["user@example.com".to_string()],
            san_uris: vec![],
            san_dns_names: vec![],
        };

        let identity = extract_identity_from_cert(&info).unwrap();
        assert_eq!(identity.issuer, "https://accounts.google.com");
        assert_eq!(identity.subject, "user@example.com");
        assert!(identity.fingerprint.is_some());
    }
}
