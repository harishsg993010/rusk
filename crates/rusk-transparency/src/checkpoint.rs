use chrono::{DateTime, Utc};
use rusk_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use url::Url;

/// Errors from checkpoint verification.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("checkpoint tree size {new} is smaller than previous {previous} (tree must be append-only)")]
    TreeShrunk { previous: u64, new: u64 },

    #[error("checkpoint is from an unknown log: {0}")]
    UnknownLog(String),

    #[error("checkpoint parse error: {0}")]
    Parse(String),
}

/// A signed transparency log checkpoint, as used by Sigstore Rekor and
/// similar append-only logs.
///
/// The checkpoint binds a tree size and root hash to a point in time,
/// signed by the log operator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransparencyCheckpoint {
    /// URL of the transparency log that issued this checkpoint.
    pub log_url: Url,
    /// Human-readable log origin identifier.
    pub origin: String,
    /// The tree size (number of entries) at the time of this checkpoint.
    pub tree_size: u64,
    /// The Merkle tree root hash at this tree size.
    pub root_hash: Sha256Digest,
    /// Timestamp when this checkpoint was created.
    pub timestamp: DateTime<Utc>,
    /// Hex-encoded signature over the checkpoint body.
    pub signature_hex: String,
    /// Hex-encoded public key of the log that signed this checkpoint.
    pub log_public_key_hex: String,
}

impl TransparencyCheckpoint {
    /// Compute the checkpoint body bytes that were signed.
    ///
    /// Format (per the signed note specification):
    /// ```text
    /// <origin>\n
    /// <tree_size>\n
    /// <base64(root_hash)>\n
    /// ```
    pub fn checkpoint_body(&self) -> Vec<u8> {
        use std::fmt::Write;
        let root_b64 = base64_encode(&self.root_hash.0);
        let mut body = String::new();
        writeln!(&mut body, "{}", self.origin).unwrap();
        writeln!(&mut body, "{}", self.tree_size).unwrap();
        writeln!(&mut body, "{}", root_b64).unwrap();
        body.into_bytes()
    }

    /// Parse a checkpoint from the signed note text format.
    pub fn parse_note(
        note_text: &str,
        log_url: Url,
        log_public_key_hex: String,
    ) -> Result<Self, CheckpointError> {
        let mut lines = note_text.lines();

        let origin = lines
            .next()
            .ok_or_else(|| CheckpointError::Parse("missing origin line".to_string()))?
            .to_string();

        let tree_size_str = lines
            .next()
            .ok_or_else(|| CheckpointError::Parse("missing tree size line".to_string()))?;
        let tree_size: u64 = tree_size_str
            .parse()
            .map_err(|e| CheckpointError::Parse(format!("invalid tree size: {e}")))?;

        let root_b64 = lines
            .next()
            .ok_or_else(|| CheckpointError::Parse("missing root hash line".to_string()))?;
        let root_bytes = base64_decode(root_b64)
            .map_err(|e| CheckpointError::Parse(format!("invalid root hash base64: {e}")))?;
        let root_array: [u8; 32] = root_bytes
            .try_into()
            .map_err(|_| CheckpointError::Parse("root hash must be 32 bytes".to_string()))?;

        // Remaining lines may include a blank line followed by the signature.
        let signature_hex = lines
            .filter(|l| !l.is_empty())
            .last()
            .unwrap_or("")
            .to_string();

        Ok(Self {
            log_url,
            origin,
            tree_size,
            root_hash: Sha256Digest(root_array),
            timestamp: Utc::now(),
            signature_hex,
            log_public_key_hex,
        })
    }

    /// Check that this checkpoint's tree size is not smaller than a previous one
    /// (append-only invariant).
    pub fn verify_consistency_with(&self, previous: &TransparencyCheckpoint) -> Result<(), CheckpointError> {
        if self.tree_size < previous.tree_size {
            return Err(CheckpointError::TreeShrunk {
                previous: previous.tree_size,
                new: self.tree_size,
            });
        }
        // If tree sizes are equal, root hashes must match.
        if self.tree_size == previous.tree_size && self.root_hash != previous.root_hash {
            return Err(CheckpointError::SignatureInvalid(
                "same tree size but different root hashes".to_string(),
            ));
        }
        Ok(())
    }
}

/// Trait for verifying checkpoint signatures.
///
/// Different implementations can support different key types (Ed25519, ECDSA, etc.)
/// and different log operator trust anchors.
pub trait CheckpointVerifier: Send + Sync {
    /// Verify the signature on a checkpoint.
    fn verify_checkpoint(&self, checkpoint: &TransparencyCheckpoint) -> Result<(), CheckpointError>;
}

/// Ed25519-based checkpoint verifier.
pub struct Ed25519CheckpointVerifier {
    /// Map of log origin to trusted Ed25519 public key (32 bytes).
    trusted_keys: std::collections::HashMap<String, [u8; 32]>,
}

impl Ed25519CheckpointVerifier {
    pub fn new() -> Self {
        Self {
            trusted_keys: std::collections::HashMap::new(),
        }
    }

    /// Add a trusted log public key.
    pub fn add_trusted_key(
        &mut self,
        origin: &str,
        public_key_hex: &str,
    ) -> Result<(), CheckpointError> {
        let bytes = hex::decode(public_key_hex)
            .map_err(|e| CheckpointError::Parse(format!("invalid key hex: {e}")))?;
        let array: [u8; 32] = bytes.try_into().map_err(|_| {
            CheckpointError::Parse("ed25519 public key must be 32 bytes".to_string())
        })?;
        self.trusted_keys.insert(origin.to_string(), array);
        Ok(())
    }
}

impl Default for Ed25519CheckpointVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckpointVerifier for Ed25519CheckpointVerifier {
    fn verify_checkpoint(&self, checkpoint: &TransparencyCheckpoint) -> Result<(), CheckpointError> {
        let pub_bytes = self
            .trusted_keys
            .get(&checkpoint.origin)
            .ok_or_else(|| CheckpointError::UnknownLog(checkpoint.origin.clone()))?;

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(pub_bytes)
            .map_err(|e| CheckpointError::SignatureInvalid(format!("bad key: {e}")))?;

        let sig_bytes = hex::decode(&checkpoint.signature_hex)
            .map_err(|e| CheckpointError::SignatureInvalid(format!("bad sig hex: {e}")))?;

        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
            CheckpointError::SignatureInvalid("signature must be 64 bytes".to_string())
        })?;

        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);
        let body = checkpoint.checkpoint_body();

        use signature::Verifier;
        verifying_key
            .verify(&body, &signature)
            .map_err(|e| CheckpointError::SignatureInvalid(format!("ed25519: {e}")))
    }
}

// Minimal base64 helpers to avoid pulling in another dependency.

fn base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim_end_matches('=');
    let mut result = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.chars() {
        let val = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(format!("invalid base64 char: {ch}")),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(result)
}

/// Re-export hex for use without pulling in the crate directly in this module.
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        ::hex::decode(s).map_err(|e| format!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"hello world";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_empty() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn checkpoint_body_format() {
        let cp = TransparencyCheckpoint {
            log_url: Url::parse("https://rekor.example.com").unwrap(),
            origin: "rekor.example.com".to_string(),
            tree_size: 1000,
            root_hash: Sha256Digest::zero(),
            timestamp: Utc::now(),
            signature_hex: String::new(),
            log_public_key_hex: String::new(),
        };

        let body = cp.checkpoint_body();
        let body_str = String::from_utf8(body).unwrap();
        assert!(body_str.starts_with("rekor.example.com\n"));
        assert!(body_str.contains("1000\n"));
    }

    #[test]
    fn consistency_check_append_only() {
        let cp1 = TransparencyCheckpoint {
            log_url: Url::parse("https://rekor.example.com").unwrap(),
            origin: "rekor".to_string(),
            tree_size: 100,
            root_hash: Sha256Digest::compute(b"root1"),
            timestamp: Utc::now(),
            signature_hex: String::new(),
            log_public_key_hex: String::new(),
        };

        let cp2 = TransparencyCheckpoint {
            tree_size: 200,
            root_hash: Sha256Digest::compute(b"root2"),
            ..cp1.clone()
        };

        assert!(cp2.verify_consistency_with(&cp1).is_ok());

        // Shrinking tree is not allowed.
        let cp3 = TransparencyCheckpoint {
            tree_size: 50,
            ..cp1.clone()
        };
        assert!(cp3.verify_consistency_with(&cp1).is_err());
    }

    #[test]
    fn same_size_different_root_rejected() {
        let cp1 = TransparencyCheckpoint {
            log_url: Url::parse("https://rekor.example.com").unwrap(),
            origin: "rekor".to_string(),
            tree_size: 100,
            root_hash: Sha256Digest::compute(b"root1"),
            timestamp: Utc::now(),
            signature_hex: String::new(),
            log_public_key_hex: String::new(),
        };

        let cp2 = TransparencyCheckpoint {
            root_hash: Sha256Digest::compute(b"root2"),
            ..cp1.clone()
        };

        assert!(cp2.verify_consistency_with(&cp1).is_err());
    }
}
