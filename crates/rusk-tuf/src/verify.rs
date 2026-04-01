use crate::metadata::{
    RootMetadata, SignedMetadata, TufKey, TufKeyScheme, TufMetadataError, TufRole,
};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use signature::Verifier;
use std::collections::HashMap;

/// Errors that can occur during TUF signature verification.
#[derive(Debug, thiserror::Error)]
pub enum TufVerifyError {
    #[error("insufficient valid signatures: need {threshold}, got {valid}")]
    ThresholdNotMet { threshold: u32, valid: u32 },

    #[error("no keys found for role {0}")]
    NoKeysForRole(TufRole),

    #[error("key decode error for key {key_id}: {reason}")]
    KeyDecode { key_id: String, reason: String },

    #[error("signature decode error: {0}")]
    SignatureDecode(String),

    #[error("metadata error: {0}")]
    Metadata(#[from] TufMetadataError),

    #[error("unsupported key scheme: {0:?}")]
    UnsupportedScheme(TufKeyScheme),
}

/// TUF metadata verifier that holds the trusted root keys.
pub struct TufVerifier {
    /// Trusted keys indexed by key ID.
    trusted_keys: HashMap<String, TufKey>,
    /// Role definitions from the trusted root.
    trusted_root: RootMetadata,
}

impl TufVerifier {
    /// Create a new verifier from a trusted root metadata.
    ///
    /// The caller is responsible for bootstrapping the initial trusted root
    /// (e.g., from a pinned root embedded in the binary).
    pub fn new(trusted_root: RootMetadata) -> Self {
        let trusted_keys = trusted_root.keys.clone();
        Self {
            trusted_keys,
            trusted_root,
        }
    }

    /// Get a reference to the current trusted root metadata.
    pub fn trusted_root(&self) -> &RootMetadata {
        &self.trusted_root
    }

    /// Verify the signatures on a signed metadata envelope against the
    /// trusted key set for the given role.
    ///
    /// Returns the number of valid signatures found. Fails if the threshold
    /// is not met.
    pub fn verify_signatures<T: serde::Serialize>(
        &self,
        signed_metadata: &SignedMetadata<T>,
        role: TufRole,
    ) -> Result<u32, TufVerifyError> {
        let role_def = self
            .trusted_root
            .role_definition(role)
            .ok_or(TufVerifyError::NoKeysForRole(role))?;

        let canonical_bytes = signed_metadata.canonical_signed_bytes()?;

        let mut valid_count: u32 = 0;
        let mut seen_keyids = std::collections::HashSet::new();

        for tuf_sig in &signed_metadata.signatures {
            // Skip duplicate key IDs (only count each key once).
            if !seen_keyids.insert(&tuf_sig.keyid) {
                tracing::debug!(keyid = %tuf_sig.keyid, "skipping duplicate signature");
                continue;
            }

            // Only consider signatures from keys authorized for this role.
            if !role_def.is_authorized(&tuf_sig.keyid) {
                tracing::debug!(keyid = %tuf_sig.keyid, role = %role, "key not authorized for role");
                continue;
            }

            // Look up the key.
            let key = match self.trusted_keys.get(&tuf_sig.keyid) {
                Some(k) => k,
                None => {
                    tracing::debug!(keyid = %tuf_sig.keyid, "key not found in trusted set");
                    continue;
                }
            };

            match verify_single_signature(key, &tuf_sig.sig, &canonical_bytes) {
                Ok(true) => {
                    tracing::debug!(keyid = %tuf_sig.keyid, "signature valid");
                    valid_count += 1;
                }
                Ok(false) => {
                    tracing::warn!(keyid = %tuf_sig.keyid, "signature verification failed");
                }
                Err(e) => {
                    tracing::warn!(keyid = %tuf_sig.keyid, error = %e, "signature check error");
                }
            }
        }

        if valid_count < role_def.threshold {
            return Err(TufVerifyError::ThresholdNotMet {
                threshold: role_def.threshold,
                valid: valid_count,
            });
        }

        tracing::info!(
            role = %role,
            valid = valid_count,
            threshold = role_def.threshold,
            "signature verification passed"
        );

        Ok(valid_count)
    }

    /// Rotate to a new trusted root.
    ///
    /// The new root must be verified against both the old root's keys and the
    /// new root's own keys (per TUF spec section 5.3.4).
    pub fn rotate_root(
        &mut self,
        new_root_signed: &SignedMetadata<RootMetadata>,
    ) -> Result<(), TufVerifyError> {
        // Step 1: Verify with old root's keys.
        self.verify_signatures(new_root_signed, TufRole::Root)?;

        // Step 2: Create a temporary verifier with the new root's keys to
        // verify the new root is self-consistent.
        let new_verifier = TufVerifier::new(new_root_signed.signed.clone());
        new_verifier.verify_signatures(new_root_signed, TufRole::Root)?;

        // Step 3: Check version is incremented.
        let old_version = self.trusted_root.common.version;
        let new_version = new_root_signed.signed.common.version;
        if new_version != old_version + 1 {
            return Err(TufVerifyError::Metadata(
                TufMetadataError::VersionMismatch {
                    expected: old_version + 1,
                    actual: new_version,
                },
            ));
        }

        // Accept the new root.
        self.trusted_root = new_root_signed.signed.clone();
        self.trusted_keys = self.trusted_root.keys.clone();

        tracing::info!(version = new_version, "root rotation complete");

        Ok(())
    }
}

/// Verify a single signature using the appropriate algorithm.
fn verify_single_signature(
    key: &TufKey,
    sig_hex: &str,
    message: &[u8],
) -> Result<bool, TufVerifyError> {
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| TufVerifyError::SignatureDecode("invalid hex in signature".to_string()))?;

    match key.scheme {
        TufKeyScheme::Ed25519 => {
            let pub_bytes = key.public_key_bytes().map_err(|e| TufVerifyError::KeyDecode {
                key_id: key.key_id(),
                reason: e.to_string(),
            })?;

            let pub_array: [u8; 32] =
                pub_bytes
                    .try_into()
                    .map_err(|_| TufVerifyError::KeyDecode {
                        key_id: key.key_id(),
                        reason: "ed25519 public key must be 32 bytes".to_string(),
                    })?;

            let verifying_key =
                VerifyingKey::from_bytes(&pub_array).map_err(|e| TufVerifyError::KeyDecode {
                    key_id: key.key_id(),
                    reason: format!("invalid ed25519 public key: {e}"),
                })?;

            let sig_array: [u8; 64] =
                sig_bytes
                    .try_into()
                    .map_err(|_| TufVerifyError::SignatureDecode(
                        "ed25519 signature must be 64 bytes".to_string(),
                    ))?;

            let sig = Ed25519Signature::from_bytes(&sig_array);

            match verifying_key.verify(message, &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        ref scheme => Err(TufVerifyError::UnsupportedScheme(scheme.clone())),
    }
}

/// Convenience: verify a signed metadata blob given a raw JSON byte slice
/// and a trusted root.
pub fn verify_metadata_bytes(
    json_bytes: &[u8],
    role: TufRole,
    trusted_root: &RootMetadata,
) -> Result<serde_json::Value, TufVerifyError> {
    let signed: SignedMetadata<serde_json::Value> =
        serde_json::from_slice(json_bytes).map_err(TufMetadataError::Json)?;

    let verifier = TufVerifier::new(trusted_root.clone());
    verifier.verify_signatures(&signed, role)?;

    Ok(signed.signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::*;
    use std::collections::HashMap;

    fn make_test_root() -> RootMetadata {
        let mut keys = HashMap::new();
        let key = TufKey {
            keytype: TufKeyType::Ed25519,
            scheme: TufKeyScheme::Ed25519,
            keyval: TufKeyValue {
                public: "0".repeat(64), // 32 zero bytes in hex
            },
        };
        let kid = key.key_id();
        keys.insert(kid.clone(), key);

        let mut roles = HashMap::new();
        roles.insert(
            "root".to_string(),
            RoleDefinition {
                threshold: 1,
                keyids: vec![kid.clone()],
            },
        );
        roles.insert(
            "targets".to_string(),
            RoleDefinition {
                threshold: 1,
                keyids: vec![kid],
            },
        );

        RootMetadata {
            common: CommonMetadata {
                spec_version: "1.0.31".to_string(),
                version: 1,
                expires: chrono::Utc::now() + chrono::Duration::hours(24),
            },
            consistent_snapshot: false,
            keys,
            roles,
        }
    }

    #[test]
    fn verifier_creation() {
        let root = make_test_root();
        let verifier = TufVerifier::new(root);
        assert_eq!(verifier.trusted_root().common.version, 1);
    }

    #[test]
    fn threshold_not_met_with_no_sigs() {
        let root = make_test_root();
        let verifier = TufVerifier::new(root);

        let signed = SignedMetadata {
            signatures: vec![],
            signed: serde_json::json!({"test": true}),
        };

        let result = verifier.verify_signatures(&signed, TufRole::Root);
        assert!(result.is_err());
        match result.unwrap_err() {
            TufVerifyError::ThresholdNotMet { threshold, valid } => {
                assert_eq!(threshold, 1);
                assert_eq!(valid, 0);
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
