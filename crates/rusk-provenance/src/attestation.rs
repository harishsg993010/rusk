use chrono::{DateTime, Utc};
use rusk_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Errors during attestation parsing.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("invalid DSSE envelope: {0}")]
    InvalidEnvelope(String),

    #[error("unsupported payload type: {0}")]
    UnsupportedPayloadType(String),

    #[error("invalid in-toto statement: {0}")]
    InvalidStatement(String),

    #[error("base64 decode error: {0}")]
    Base64Decode(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// A signature within a DSSE envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DsseSignature {
    /// The key ID of the signer.
    pub keyid: String,
    /// Base64-encoded signature bytes.
    pub sig: String,
}

impl DsseSignature {
    /// Decode the raw signature bytes.
    pub fn sig_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        base64_decode(&self.sig).map_err(AttestationError::Base64Decode)
    }
}

/// A Dead Simple Signing Envelope (DSSE) as used by in-toto and Sigstore.
///
/// See: <https://github.com/secure-systems-lab/dsse>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// The payload type URI (e.g., "application/vnd.in-toto+json").
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded payload bytes.
    pub payload: String,
    /// Signatures over the PAE-encoded message.
    pub signatures: Vec<DsseSignature>,
}

impl DsseEnvelope {
    /// The expected payload type for in-toto attestations.
    pub const IN_TOTO_PAYLOAD_TYPE: &'static str = "application/vnd.in-toto+json";

    /// Decode the payload bytes.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        base64_decode(&self.payload).map_err(AttestationError::Base64Decode)
    }

    /// Compute the Pre-Authentication Encoding (PAE) message that is actually
    /// signed.
    ///
    /// PAE(payloadType, payload) = "DSSEv1" + SP + LEN(payloadType) + SP +
    ///     payloadType + SP + LEN(payload) + SP + payload
    pub fn pae_message(&self) -> Result<Vec<u8>, AttestationError> {
        let payload_bytes = self.payload_bytes()?;
        let mut pae = Vec::new();
        pae.extend_from_slice(b"DSSEv1 ");
        pae.extend_from_slice(self.payload_type.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(self.payload_type.as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(payload_bytes.len().to_string().as_bytes());
        pae.push(b' ');
        pae.extend_from_slice(&payload_bytes);
        Ok(pae)
    }

    /// Check if this envelope contains an in-toto statement.
    pub fn is_in_toto(&self) -> bool {
        self.payload_type == Self::IN_TOTO_PAYLOAD_TYPE
    }

    /// Parse the payload as an in-toto Statement.
    pub fn parse_in_toto_statement(&self) -> Result<InTotoStatement, AttestationError> {
        if !self.is_in_toto() {
            return Err(AttestationError::UnsupportedPayloadType(
                self.payload_type.clone(),
            ));
        }
        let bytes = self.payload_bytes()?;
        serde_json::from_slice(&bytes).map_err(AttestationError::Json)
    }
}

/// A subject (artifact) in an in-toto statement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InTotoSubject {
    /// The artifact name/path.
    pub name: String,
    /// Map of digest algorithm to hex value.
    pub digest: HashMap<String, String>,
}

impl InTotoSubject {
    /// Get the SHA-256 digest if present.
    pub fn sha256(&self) -> Option<Result<Sha256Digest, rusk_core::digest::DigestError>> {
        self.digest.get("sha256").map(|hex| Sha256Digest::from_hex(hex))
    }
}

/// An in-toto v1 Statement, the core provenance attestation format.
///
/// See: <https://in-toto.io/Statement/v1>
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InTotoStatement {
    /// Statement type URI (must be "https://in-toto.io/Statement/v1").
    #[serde(rename = "_type")]
    pub statement_type: String,

    /// The subjects (artifacts) this statement attests to.
    pub subject: Vec<InTotoSubject>,

    /// Predicate type URI (e.g., "https://slsa.dev/provenance/v1").
    #[serde(rename = "predicateType")]
    pub predicate_type: String,

    /// The predicate payload (schema depends on predicate_type).
    pub predicate: serde_json::Value,
}

impl InTotoStatement {
    /// The expected statement type for v1.
    pub const V1_TYPE: &'static str = "https://in-toto.io/Statement/v1";
    /// The v0.1 statement type (still common).
    pub const V01_TYPE: &'static str = "https://in-toto.io/Statement/v0.1";
    /// SLSA provenance v1 predicate type.
    pub const SLSA_PROVENANCE_V1: &'static str = "https://slsa.dev/provenance/v1";
    /// SLSA provenance v0.2 predicate type.
    pub const SLSA_PROVENANCE_V02: &'static str = "https://slsa.dev/provenance/v0.2";

    /// Check if this is a valid in-toto v1 or v0.1 statement.
    pub fn is_valid_type(&self) -> bool {
        self.statement_type == Self::V1_TYPE || self.statement_type == Self::V01_TYPE
    }

    /// Check if the predicate is SLSA provenance (any version).
    pub fn is_slsa_provenance(&self) -> bool {
        self.predicate_type == Self::SLSA_PROVENANCE_V1
            || self.predicate_type == Self::SLSA_PROVENANCE_V02
    }

    /// Find a subject by its SHA-256 digest.
    pub fn find_subject_by_digest(&self, digest: &Sha256Digest) -> Option<&InTotoSubject> {
        let target_hex = digest.to_hex();
        self.subject
            .iter()
            .find(|s| s.digest.get("sha256").map_or(false, |h| h == &target_hex))
    }

    /// Extract the builder ID from a SLSA provenance predicate (best effort).
    pub fn slsa_builder_id(&self) -> Option<String> {
        // SLSA v1: predicate.runDetails.builder.id
        if let Some(id) = self.predicate
            .get("runDetails")
            .and_then(|rd| rd.get("builder"))
            .and_then(|b| b.get("id"))
            .and_then(|id| id.as_str())
        {
            return Some(id.to_string());
        }

        // SLSA v0.2: predicate.builder.id
        self.predicate
            .get("builder")
            .and_then(|b| b.get("id"))
            .and_then(|id| id.as_str())
            .map(|s| s.to_string())
    }

    /// Extract the source repository URI from a SLSA provenance predicate.
    pub fn slsa_source_uri(&self) -> Option<String> {
        // SLSA v1: predicate.buildDefinition.resolvedDependencies[0].uri
        if let Some(uri) = self.predicate
            .get("buildDefinition")
            .and_then(|bd| bd.get("resolvedDependencies"))
            .and_then(|deps| deps.as_array())
            .and_then(|arr| arr.first())
            .and_then(|dep| dep.get("uri"))
            .and_then(|u| u.as_str())
        {
            return Some(uri.to_string());
        }

        // SLSA v0.2: predicate.materials[0].uri
        self.predicate
            .get("materials")
            .and_then(|m| m.as_array())
            .and_then(|arr| arr.first())
            .and_then(|mat| mat.get("uri"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    }

    /// Extract the build invocation timestamp.
    pub fn build_timestamp(&self) -> Option<DateTime<Utc>> {
        // SLSA v1: predicate.runDetails.metadata.startedOn
        let ts_str = self.predicate
            .get("runDetails")
            .and_then(|rd| rd.get("metadata"))
            .and_then(|m| m.get("startedOn"))
            .and_then(|t| t.as_str())
            .or_else(|| {
                // SLSA v0.2: predicate.metadata.buildStartedOn
                self.predicate
                    .get("metadata")
                    .and_then(|m| m.get("buildStartedOn"))
                    .and_then(|t| t.as_str())
            })?;

        ts_str.parse().ok()
    }
}

/// Parse a raw attestation (JSON bytes) into a DSSE envelope and extract the
/// in-toto statement.
pub fn parse_attestation(
    json_bytes: &[u8],
) -> Result<(DsseEnvelope, InTotoStatement), AttestationError> {
    let envelope: DsseEnvelope = serde_json::from_slice(json_bytes)
        .map_err(|e| AttestationError::InvalidEnvelope(format!("JSON: {e}")))?;

    let statement = envelope.parse_in_toto_statement()?;

    if !statement.is_valid_type() {
        return Err(AttestationError::InvalidStatement(format!(
            "unknown statement type: {}",
            statement.statement_type
        )));
    }

    Ok((envelope, statement))
}

// Minimal base64 decoder.
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
            '\n' | '\r' | ' ' => continue,
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

#[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_encoding() {
        let payload_json = r#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"test","predicate":{}}"#;
        let payload_b64 = base64_encode(payload_json.as_bytes());

        let envelope = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: payload_b64,
            signatures: vec![],
        };

        let pae = envelope.pae_message().unwrap();
        let pae_str = String::from_utf8_lossy(&pae);
        assert!(pae_str.starts_with("DSSEv1 "));
        assert!(pae_str.contains("application/vnd.in-toto+json"));
    }

    #[test]
    fn parse_in_toto_statement() {
        let statement = InTotoStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![InTotoSubject {
                name: "pkg-1.0.0.tar.gz".to_string(),
                digest: {
                    let mut m = HashMap::new();
                    m.insert(
                        "sha256".to_string(),
                        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
                    );
                    m
                },
            }],
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate: serde_json::json!({
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/actions/runner"
                    },
                    "metadata": {
                        "startedOn": "2024-01-15T10:00:00Z"
                    }
                },
                "buildDefinition": {
                    "resolvedDependencies": [{
                        "uri": "git+https://github.com/owner/repo@refs/heads/main"
                    }]
                }
            }),
        };

        assert!(statement.is_valid_type());
        assert!(statement.is_slsa_provenance());
        assert_eq!(
            statement.slsa_builder_id().unwrap(),
            "https://github.com/actions/runner"
        );
        assert!(statement.slsa_source_uri().unwrap().contains("owner/repo"));

        let digest = Sha256Digest::compute(b"hello world");
        assert!(statement.find_subject_by_digest(&digest).is_some());
    }

    #[test]
    fn dsse_envelope_roundtrip() {
        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [],
            "predicateType": "test",
            "predicate": {}
        });

        let payload_b64 = base64_encode(serde_json::to_string(&statement).unwrap().as_bytes());

        let envelope = DsseEnvelope {
            payload_type: DsseEnvelope::IN_TOTO_PAYLOAD_TYPE.to_string(),
            payload: payload_b64,
            signatures: vec![],
        };

        assert!(envelope.is_in_toto());
        let parsed = envelope.parse_in_toto_statement().unwrap();
        assert_eq!(parsed.statement_type, "https://in-toto.io/Statement/v1");
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"test data for base64";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
