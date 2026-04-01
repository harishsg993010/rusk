//! npm-specific provenance handling.
//!
//! Handles npm's Sigstore-based provenance attestations that are
//! attached to packages published via GitHub Actions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// npm provenance bundle as published alongside npm packages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmProvenanceBundle {
    /// The media type of the bundle.
    #[serde(rename = "mediaType", default)]
    pub media_type: Option<String>,
    /// The DSSE envelope containing the attestation.
    pub dsse_envelope: Option<serde_json::Value>,
    /// Verification material (certificates, etc.).
    pub verification_material: Option<VerificationMaterial>,
}

/// Verification material for Sigstore-based npm provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationMaterial {
    /// Transparency log entries (Rekor).
    #[serde(rename = "tlogEntries", default)]
    pub tlog_entries: Vec<serde_json::Value>,
    /// Certificate chain from Fulcio.
    #[serde(rename = "x509CertificateChain", default)]
    pub x509_certificate_chain: Option<serde_json::Value>,
}

/// Parse npm provenance from the registry metadata.
pub fn parse_npm_provenance(json: &str) -> Result<NpmProvenanceBundle, String> {
    serde_json::from_str(json).map_err(|e| format!("failed to parse npm provenance: {e}"))
}

/// Extract the source repository URL from npm provenance.
pub fn extract_source_repo(bundle: &NpmProvenanceBundle) -> Option<String> {
    // The source repo is typically in the DSSE envelope's predicate
    let envelope = bundle.dsse_envelope.as_ref()?;
    let payload = envelope.get("payload")?;
    // Payload is base64-encoded in-toto statement
    // In a full implementation, we'd decode and parse it
    None
}
