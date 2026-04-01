use crate::verifier::{SignerProof, SigningError};
use rusk_core::SignerIdentity;

/// Extract a `SignerIdentity` from a `SignerProof`.
///
/// For public-key proofs, the "issuer" is set to a synthetic URI and the
/// subject is the hex fingerprint of the key. For OIDC proofs, the real
/// issuer and subject claims are used.
pub fn extract_signer_identity(proof: &SignerProof) -> Result<SignerIdentity, SigningError> {
    match proof {
        SignerProof::PublicKey {
            public_key_hex,
            algorithm,
            ..
        } => {
            // Compute a fingerprint from the public key as the identity.
            let key_bytes = hex::decode(public_key_hex)
                .map_err(|e| SigningError::IdentityError(format!("bad key hex: {e}")))?;
            let fingerprint = rusk_core::Sha256Digest::compute(&key_bytes).to_hex();

            Ok(SignerIdentity {
                issuer: format!("urn:rusk:key:{algorithm:?}"),
                subject: fingerprint.clone(),
                fingerprint: Some(fingerprint),
            })
        }
        SignerProof::OidcCertificate {
            issuer, subject, ..
        } => Ok(SignerIdentity {
            issuer: issuer.clone(),
            subject: subject.clone(),
            fingerprint: None,
        }),
    }
}

/// Utility for matching signer identities against expected patterns.
///
/// Supports exact match, issuer-only match, and glob-style subject matching.
#[derive(Clone, Debug)]
pub struct IdentityMatcher {
    rules: Vec<IdentityMatchRule>,
}

/// A single identity matching rule.
#[derive(Clone, Debug)]
pub struct IdentityMatchRule {
    /// Expected issuer (exact match). If None, any issuer is accepted.
    pub issuer: Option<String>,
    /// Expected subject pattern. Supports trailing `*` wildcard.
    pub subject_pattern: String,
}

impl IdentityMatchRule {
    /// Check if a signer identity matches this rule.
    pub fn matches(&self, identity: &SignerIdentity) -> bool {
        // Check issuer if specified.
        if let Some(expected_issuer) = &self.issuer {
            if identity.issuer != *expected_issuer {
                return false;
            }
        }

        // Check subject pattern.
        match_pattern(&self.subject_pattern, &identity.subject)
    }
}

/// Simple glob matching supporting trailing `*` wildcard.
fn match_pattern(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

impl IdentityMatcher {
    /// Create a new matcher with no rules (matches nothing).
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule requiring an exact issuer and subject pattern.
    pub fn add_rule(&mut self, issuer: Option<String>, subject_pattern: String) -> &mut Self {
        self.rules.push(IdentityMatchRule {
            issuer,
            subject_pattern,
        });
        self
    }

    /// Convenience: match any identity from a specific OIDC issuer.
    pub fn allow_issuer(&mut self, issuer: &str) -> &mut Self {
        self.add_rule(Some(issuer.to_string()), "*".to_string())
    }

    /// Convenience: match a specific subject at a specific issuer.
    pub fn allow_exact(&mut self, issuer: &str, subject: &str) -> &mut Self {
        self.add_rule(Some(issuer.to_string()), subject.to_string())
    }

    /// Check if any rule matches the given identity.
    pub fn matches(&self, identity: &SignerIdentity) -> bool {
        self.rules.iter().any(|rule| rule.matches(identity))
    }

    /// Return the first matching rule, if any.
    pub fn find_match<'a>(&'a self, identity: &SignerIdentity) -> Option<&'a IdentityMatchRule> {
        self.rules.iter().find(|rule| rule.matches(identity))
    }

    /// Number of configured rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for IdentityMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github_identity() -> SignerIdentity {
        SignerIdentity {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject: "repo:owner/repo:ref:refs/heads/main".to_string(),
            fingerprint: None,
        }
    }

    #[test]
    fn extract_from_public_key() {
        let proof = SignerProof::PublicKey {
            algorithm: crate::verifier::SignatureAlgorithm::Ed25519,
            public_key_hex: "00".repeat(32),
        };
        let identity = extract_signer_identity(&proof).unwrap();
        assert!(identity.issuer.contains("Ed25519"));
        assert!(identity.fingerprint.is_some());
    }

    #[test]
    fn extract_from_oidc() {
        let proof = SignerProof::OidcCertificate {
            certificate_chain: vec![],
            issuer: "https://accounts.google.com".to_string(),
            subject: "user@example.com".to_string(),
        };
        let identity = extract_signer_identity(&proof).unwrap();
        assert_eq!(identity.issuer, "https://accounts.google.com");
        assert_eq!(identity.subject, "user@example.com");
    }

    #[test]
    fn matcher_exact() {
        let mut matcher = IdentityMatcher::new();
        matcher.allow_exact(
            "https://token.actions.githubusercontent.com",
            "repo:owner/repo:ref:refs/heads/main",
        );

        assert!(matcher.matches(&github_identity()));

        let other = SignerIdentity {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            subject: "repo:other/repo:ref:refs/heads/main".to_string(),
            fingerprint: None,
        };
        assert!(!matcher.matches(&other));
    }

    #[test]
    fn matcher_wildcard_subject() {
        let mut matcher = IdentityMatcher::new();
        matcher.add_rule(
            Some("https://token.actions.githubusercontent.com".to_string()),
            "repo:owner/*".to_string(),
        );

        assert!(matcher.matches(&github_identity()));
    }

    #[test]
    fn matcher_issuer_only() {
        let mut matcher = IdentityMatcher::new();
        matcher.allow_issuer("https://token.actions.githubusercontent.com");

        assert!(matcher.matches(&github_identity()));

        let google = SignerIdentity {
            issuer: "https://accounts.google.com".to_string(),
            subject: "user@example.com".to_string(),
            fingerprint: None,
        };
        assert!(!matcher.matches(&google));
    }

    #[test]
    fn empty_matcher_matches_nothing() {
        let matcher = IdentityMatcher::new();
        assert!(!matcher.matches(&github_identity()));
    }
}
