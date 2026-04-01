//! HTTP transport layer for rusk.
//!
//! Manages HTTP downloads with streaming hash verification, configurable
//! retry policies, progress tracking, and content-addressed storage integration.

pub mod manager;
pub mod stream;
pub mod retry;
pub mod progress;

pub use manager::{DownloadManager, DownloadManagerConfig, DownloadRequest, DownloadResult, TransportError};
pub use stream::StreamingHashReader;
pub use retry::{RetryStrategy, is_retriable};
pub use progress::{ProgressTracker, DownloadProgress};
