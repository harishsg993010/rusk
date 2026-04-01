//! Download progress tracking.
//!
//! Provides a thread-safe progress tracker that aggregates download progress
//! across concurrent downloads for display by the CLI layer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Progress update for a single download.
#[derive(Clone, Debug)]
pub struct DownloadProgress {
    /// Label identifying which download this is for.
    pub label: String,
    /// Bytes downloaded so far.
    pub bytes_downloaded: u64,
    /// Total expected bytes, if known.
    pub total_bytes: Option<u64>,
    /// Whether this download is complete.
    pub done: bool,
}

/// Callback signature for progress notifications.
pub type ProgressCallback = Box<dyn Fn(&DownloadProgress) + Send + Sync>;

/// Thread-safe tracker that aggregates progress across multiple concurrent downloads.
#[derive(Clone)]
pub struct ProgressTracker {
    inner: Arc<ProgressTrackerInner>,
}

struct ProgressTrackerInner {
    /// Total bytes downloaded across all items.
    total_bytes_downloaded: AtomicU64,
    /// Total expected bytes across all items (if known).
    total_expected_bytes: AtomicU64,
    /// Number of completed downloads.
    completed_count: AtomicU64,
    /// Total number of downloads in the batch.
    total_count: AtomicU64,
    /// Optional callback for each progress update.
    callback: Mutex<Option<ProgressCallback>>,
}

impl ProgressTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ProgressTrackerInner {
                total_bytes_downloaded: AtomicU64::new(0),
                total_expected_bytes: AtomicU64::new(0),
                completed_count: AtomicU64::new(0),
                total_count: AtomicU64::new(0),
                callback: Mutex::new(None),
            }),
        }
    }

    /// Create a tracker with a progress callback.
    pub fn with_callback(callback: ProgressCallback) -> Self {
        let tracker = Self::new();
        *tracker.inner.callback.lock().unwrap() = Some(callback);
        tracker
    }

    /// Set the total number of downloads expected.
    pub fn set_total(&self, total: u64) {
        self.inner.total_count.store(total, Ordering::Relaxed);
    }

    /// Record a progress update from a download.
    pub fn record_progress(&self, progress: DownloadProgress) {
        self.inner
            .total_bytes_downloaded
            .fetch_add(progress.bytes_downloaded, Ordering::Relaxed);

        if let Some(total) = progress.total_bytes {
            self.inner
                .total_expected_bytes
                .fetch_add(total, Ordering::Relaxed);
        }

        if progress.done {
            self.inner.completed_count.fetch_add(1, Ordering::Relaxed);
        }

        // Invoke callback if registered
        if let Ok(guard) = self.inner.callback.lock() {
            if let Some(cb) = guard.as_ref() {
                cb(&progress);
            }
        }
    }

    /// Get the total bytes downloaded so far.
    pub fn bytes_downloaded(&self) -> u64 {
        self.inner.total_bytes_downloaded.load(Ordering::Relaxed)
    }

    /// Get the number of completed downloads.
    pub fn completed(&self) -> u64 {
        self.inner.completed_count.load(Ordering::Relaxed)
    }

    /// Get the total number of downloads.
    pub fn total(&self) -> u64 {
        self.inner.total_count.load(Ordering::Relaxed)
    }

    /// Get the completion fraction (0.0 to 1.0), or 0.0 if total is unknown.
    pub fn fraction(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            self.completed() as f64 / total as f64
        }
    }

    /// Returns true if all downloads are complete.
    pub fn is_done(&self) -> bool {
        let total = self.total();
        total > 0 && self.completed() >= total
    }
}

impl Default for ProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_counts_correctly() {
        let tracker = ProgressTracker::new();
        tracker.set_total(3);

        tracker.record_progress(DownloadProgress {
            label: "a".into(),
            bytes_downloaded: 100,
            total_bytes: Some(100),
            done: true,
        });
        tracker.record_progress(DownloadProgress {
            label: "b".into(),
            bytes_downloaded: 200,
            total_bytes: Some(200),
            done: true,
        });

        assert_eq!(tracker.completed(), 2);
        assert_eq!(tracker.bytes_downloaded(), 300);
        assert!(!tracker.is_done());

        tracker.record_progress(DownloadProgress {
            label: "c".into(),
            bytes_downloaded: 50,
            total_bytes: Some(50),
            done: true,
        });
        assert!(tracker.is_done());
    }

    #[test]
    fn callback_invoked() {
        let call_count = Arc::new(AtomicU64::new(0));
        let count_clone = call_count.clone();

        let tracker = ProgressTracker::with_callback(Box::new(move |_progress| {
            count_clone.fetch_add(1, Ordering::Relaxed);
        }));

        tracker.record_progress(DownloadProgress {
            label: "x".into(),
            bytes_downloaded: 10,
            total_bytes: None,
            done: false,
        });

        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }
}
