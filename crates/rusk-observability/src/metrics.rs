//! Lightweight metrics collection for rusk operations.
//!
//! Tracks timing, counts, and byte throughput for operations like resolution,
//! download, and materialization. Not a full metrics backend -- just enough
//! to power the CLI progress display and structured reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Timing metrics for a single operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimingMetrics {
    pub operation: String,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u64,
}

/// Aggregate metrics for a rusk operation (install, update, etc.).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OperationMetrics {
    /// Total packages resolved.
    pub packages_resolved: u64,
    /// Total packages downloaded.
    pub packages_downloaded: u64,
    /// Total bytes downloaded.
    pub bytes_downloaded: u64,
    /// Total packages materialized (linked/extracted).
    pub packages_materialized: u64,
    /// Per-phase timing breakdowns.
    pub timings: Vec<TimingMetrics>,
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of cache misses.
    pub cache_misses: u64,
}

/// Thread-safe metrics collector that accumulates counters during an operation.
#[derive(Clone, Debug)]
pub struct MetricsCollector {
    packages_resolved: Arc<AtomicU64>,
    packages_downloaded: Arc<AtomicU64>,
    bytes_downloaded: Arc<AtomicU64>,
    packages_materialized: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    start: Instant,
}

impl MetricsCollector {
    /// Create a new collector, recording the start time.
    pub fn new() -> Self {
        Self {
            packages_resolved: Arc::new(AtomicU64::new(0)),
            packages_downloaded: Arc::new(AtomicU64::new(0)),
            bytes_downloaded: Arc::new(AtomicU64::new(0)),
            packages_materialized: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            start: Instant::now(),
        }
    }

    pub fn record_resolved(&self, count: u64) {
        self.packages_resolved.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_downloaded(&self, count: u64, bytes: u64) {
        self.packages_downloaded.fetch_add(count, Ordering::Relaxed);
        self.bytes_downloaded.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_materialized(&self, count: u64) {
        self.packages_materialized.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot current counters into an `OperationMetrics`.
    pub fn snapshot(&self) -> OperationMetrics {
        OperationMetrics {
            packages_resolved: self.packages_resolved.load(Ordering::Relaxed),
            packages_downloaded: self.packages_downloaded.load(Ordering::Relaxed),
            bytes_downloaded: self.bytes_downloaded.load(Ordering::Relaxed),
            packages_materialized: self.packages_materialized.load(Ordering::Relaxed),
            timings: Vec::new(),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
        }
    }

    /// Elapsed time since the collector was created.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
