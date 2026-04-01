//! Garbage collection for the content-addressed store.
//!
//! Identifies unreferenced blobs and reclaims disk space. Supports both
//! dry-run planning and actual collection.

use crate::index::CasIndex;
use crate::store::CasStore;
use rusk_core::Sha256Digest;
use std::io;
use tracing::{info, instrument};

/// Statistics from a GC run.
#[derive(Clone, Debug, Default)]
pub struct GcStats {
    /// Number of blobs examined.
    pub examined: u64,
    /// Number of blobs deleted.
    pub deleted: u64,
    /// Bytes reclaimed.
    pub bytes_reclaimed: u64,
}

/// A planned GC operation (dry run output).
#[derive(Clone, Debug)]
pub struct GcPlan {
    /// Digests that would be deleted.
    pub deletions: Vec<Sha256Digest>,
    /// Total bytes that would be reclaimed.
    pub reclaimable_bytes: u64,
}

/// Garbage collector for the CAS.
pub struct GarbageCollector<'a> {
    store: &'a CasStore,
}

impl<'a> GarbageCollector<'a> {
    pub fn new(store: &'a CasStore) -> Self {
        Self { store }
    }

    /// Plan a GC run without actually deleting anything.
    #[instrument(skip(self, index))]
    pub fn plan(&self, index: &CasIndex) -> GcPlan {
        let unreferenced = index.unreferenced();
        let deletions: Vec<Sha256Digest> = unreferenced.iter().map(|e| e.digest).collect();
        let reclaimable_bytes: u64 = unreferenced.iter().map(|e| e.size).sum();

        info!(
            candidates = deletions.len(),
            reclaimable_bytes, "GC plan computed"
        );

        GcPlan {
            deletions,
            reclaimable_bytes,
        }
    }

    /// Execute a GC plan, deleting unreferenced blobs.
    #[instrument(skip(self, plan))]
    pub fn execute(&self, plan: &GcPlan) -> io::Result<GcStats> {
        let mut stats = GcStats {
            examined: plan.deletions.len() as u64,
            ..Default::default()
        };

        for digest in &plan.deletions {
            if let Some(entry) = self.store.entry(digest)? {
                self.store.delete(digest)?;
                stats.deleted += 1;
                stats.bytes_reclaimed += entry.size;
            }
        }

        info!(
            deleted = stats.deleted,
            bytes_reclaimed = stats.bytes_reclaimed,
            "GC completed"
        );

        Ok(stats)
    }
}
