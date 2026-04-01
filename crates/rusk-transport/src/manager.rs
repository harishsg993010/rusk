//! Download manager for batched, concurrent HTTP downloads.
//!
//! Coordinates downloading multiple package artifacts in parallel, writing
//! them into the CAS, and tracking progress across the batch.

use crate::progress::{DownloadProgress, ProgressTracker};
use crate::retry::{is_retriable, RetryStrategy};
use crate::stream::StreamingHashReader;
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use rusk_cas::{CasStore, WriteOutcome};
use rusk_core::Sha256Digest;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, instrument, warn};
use url::Url;

/// Error type for transport operations.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("HTTP error for {url}: {message}")]
    Http { url: String, message: String },

    #[error("digest mismatch for {url}: expected {expected}, got {actual}")]
    DigestMismatch {
        url: String,
        expected: String,
        actual: String,
    },

    #[error("all retries exhausted for {url} after {attempts} attempts")]
    RetriesExhausted { url: String, attempts: u32 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("request error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// A request to download a single artifact.
#[derive(Clone, Debug)]
pub struct DownloadRequest {
    /// URL to download from.
    pub url: Url,
    /// Expected SHA-256 digest for integrity verification. If `None`, the
    /// digest is computed but not checked against an expected value.
    pub expected_digest: Option<Sha256Digest>,
    /// Opaque label used in progress/log messages.
    pub label: String,
}

/// Result of a successful download.
#[derive(Clone, Debug)]
pub struct DownloadResult {
    /// The computed SHA-256 digest of the downloaded content.
    pub digest: Sha256Digest,
    /// Total bytes downloaded.
    pub size: u64,
    /// Whether this was a cache hit (already existed in CAS).
    pub cached: bool,
    /// The label from the original request.
    pub label: String,
}

/// Configuration for the download manager.
#[derive(Clone, Debug)]
pub struct DownloadManagerConfig {
    /// Maximum number of concurrent downloads.
    pub max_concurrent: usize,
    /// Retry strategy for transient failures.
    pub retry_strategy: RetryStrategy,
}

impl Default for DownloadManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 16,
            retry_strategy: RetryStrategy::default(),
        }
    }
}

/// Manages batched, concurrent downloads with retry and integrity checking.
pub struct DownloadManager {
    client: reqwest::Client,
    cas: Arc<CasStore>,
    config: DownloadManagerConfig,
    semaphore: Arc<Semaphore>,
}

impl DownloadManager {
    /// Create a new download manager.
    pub fn new(cas: Arc<CasStore>, config: DownloadManagerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self {
            client: reqwest::Client::builder()
                .user_agent("rusk/0.1")
                .build()
                .expect("failed to build HTTP client"),
            cas,
            config,
            semaphore,
        }
    }

    /// Download a batch of artifacts concurrently.
    ///
    /// Returns results in the same order as the input requests. If any
    /// download fails after retries, its entry is an `Err`.
    #[instrument(skip(self, requests, tracker), fields(batch_size = requests.len()))]
    pub async fn download_batch(
        &self,
        requests: Vec<DownloadRequest>,
        tracker: &ProgressTracker,
    ) -> Vec<Result<DownloadResult, TransportError>> {
        let total = requests.len();
        info!(count = total, "starting download batch");

        let results: Vec<Result<DownloadResult, TransportError>> =
            stream::iter(requests.into_iter().enumerate())
                .map(|(idx, req)| {
                    let client = self.client.clone();
                    let cas = self.cas.clone();
                    let semaphore = self.semaphore.clone();
                    let strategy = self.config.retry_strategy.clone();
                    let tracker = tracker.clone();

                    async move {
                        let _permit = semaphore
                            .acquire()
                            .await
                            .expect("semaphore closed unexpectedly");

                        let result =
                            download_single(&client, &cas, &req, &strategy, &tracker).await;

                        match &result {
                            Ok(r) => {
                                debug!(
                                    label = %r.label,
                                    digest = %r.digest,
                                    size = r.size,
                                    cached = r.cached,
                                    "download complete"
                                );
                            }
                            Err(e) => {
                                error!(label = %req.label, error = %e, "download failed");
                            }
                        }

                        result
                    }
                })
                .buffer_unordered(self.config.max_concurrent)
                .collect()
                .await;

        let succeeded = results.iter().filter(|r| r.is_ok()).count();
        let failed = results.iter().filter(|r| r.is_err()).count();
        info!(succeeded, failed, total, "download batch finished");

        results
    }

    /// Download a single artifact (convenience wrapper).
    pub async fn download_one(
        &self,
        request: DownloadRequest,
        tracker: &ProgressTracker,
    ) -> Result<DownloadResult, TransportError> {
        let results = self.download_batch(vec![request], tracker).await;
        results
            .into_iter()
            .next()
            .expect("batch returned empty results")
    }
}

/// Perform a single download with retries.
async fn download_single(
    client: &reqwest::Client,
    cas: &CasStore,
    request: &DownloadRequest,
    strategy: &RetryStrategy,
    tracker: &ProgressTracker,
) -> Result<DownloadResult, TransportError> {
    // If we already have it in the CAS, skip the download.
    if let Some(expected) = &request.expected_digest {
        if cas.contains(expected) {
            let entry = cas
                .entry(expected)
                .map_err(TransportError::Io)?
                .expect("CAS contains returned true but entry not found");
            tracker.record_progress(DownloadProgress {
                label: request.label.clone(),
                bytes_downloaded: entry.size,
                total_bytes: Some(entry.size),
                done: true,
            });
            return Ok(DownloadResult {
                digest: *expected,
                size: entry.size,
                cached: true,
                label: request.label.clone(),
            });
        }
    }

    let mut last_error = None;
    for attempt in 0..=strategy.max_retries {
        if attempt > 0 {
            let delay = strategy.delay_for_attempt(attempt);
            warn!(
                label = %request.label,
                attempt,
                delay_ms = delay.as_millis() as u64,
                "retrying download"
            );
            tokio::time::sleep(delay).await;
        }

        match attempt_download(client, cas, request, tracker).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if !is_retriable(&e) {
                    return Err(e);
                }
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| TransportError::RetriesExhausted {
        url: request.url.to_string(),
        attempts: strategy.max_retries + 1,
    }))
}

/// Single download attempt (no retries).
async fn attempt_download(
    client: &reqwest::Client,
    cas: &CasStore,
    request: &DownloadRequest,
    tracker: &ProgressTracker,
) -> Result<DownloadResult, TransportError> {
    let response = client
        .get(request.url.as_str())
        .send()
        .await
        .map_err(|e| TransportError::Http {
            url: request.url.to_string(),
            message: e.to_string(),
        })?;

    let status = response.status();
    if !status.is_success() {
        return Err(TransportError::Http {
            url: request.url.to_string(),
            message: format!("HTTP {}", status),
        });
    }

    let total_bytes = response.content_length();
    let body = response.bytes().await.map_err(|e| TransportError::Http {
        url: request.url.to_string(),
        message: e.to_string(),
    })?;

    // Compute hash and verify
    let mut reader = StreamingHashReader::new(&body[..]);
    let data = reader.read_all()?;
    let digest = reader.finalize();

    if let Some(expected) = &request.expected_digest {
        if digest != *expected {
            return Err(TransportError::DigestMismatch {
                url: request.url.to_string(),
                expected: expected.to_hex(),
                actual: digest.to_hex(),
            });
        }
    }

    // Write to CAS
    let size = data.len() as u64;
    let cached = match cas.write(&data).map_err(TransportError::Io)? {
        WriteOutcome::AlreadyExists { .. } => true,
        WriteOutcome::Written { .. } => false,
    };

    tracker.record_progress(DownloadProgress {
        label: request.label.clone(),
        bytes_downloaded: size,
        total_bytes,
        done: true,
    });

    Ok(DownloadResult {
        digest,
        size,
        cached,
        label: request.label.clone(),
    })
}
