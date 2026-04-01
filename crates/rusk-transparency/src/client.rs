//! Transparency log client.
//!
//! HTTP client for interacting with transparency logs (Sigstore Rekor, etc.)
//! to fetch inclusion proofs, checkpoints, and search for entries.

use crate::checkpoint::TransparencyCheckpoint;
use crate::proof::InclusionProof;
use async_trait::async_trait;
use rusk_core::Sha256Digest;
use url::Url;

/// Error from transparency log client operations.
#[derive(Debug, thiserror::Error)]
pub enum TransparencyClientError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("entry not found for digest {0}")]
    NotFound(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("log not configured: {0}")]
    NotConfigured(String),
}

/// Trait for transparency log clients.
#[async_trait]
pub trait TransparencyClient: Send + Sync {
    /// Fetch the latest checkpoint from the log.
    async fn get_checkpoint(&self) -> Result<TransparencyCheckpoint, TransparencyClientError>;

    /// Search for a log entry by artifact digest.
    async fn search_by_digest(
        &self,
        digest: &Sha256Digest,
    ) -> Result<Option<LogEntry>, TransparencyClientError>;

    /// Get an inclusion proof for a specific log entry.
    async fn get_inclusion_proof(
        &self,
        entry_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, TransparencyClientError>;
}

/// A log entry from a transparency log.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Index of this entry in the log.
    pub log_index: u64,
    /// The artifact digest this entry is about.
    pub artifact_digest: Sha256Digest,
    /// The integrated time (when the entry was added to the log).
    pub integrated_time: chrono::DateTime<chrono::Utc>,
    /// The entry body (varies by log type).
    pub body: serde_json::Value,
}

/// Configuration for connecting to a transparency log.
#[derive(Clone, Debug)]
pub struct TransparencyLogConfig {
    /// Base URL of the transparency log API.
    pub url: Url,
    /// Public key of the log (for checkpoint verification).
    pub public_key_hex: String,
    /// Human-readable origin identifier.
    pub origin: String,
}
