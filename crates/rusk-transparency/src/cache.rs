//! Transparency data caching.
//!
//! Caches checkpoints, inclusion proofs, and log entries to avoid
//! redundant network requests to transparency logs.

use crate::checkpoint::TransparencyCheckpoint;
use crate::proof::InclusionProof;
use rusk_core::Sha256Digest;
use std::collections::HashMap;
use std::sync::Mutex;

/// Cache for transparency log data.
pub struct TransparencyCache {
    /// Cached checkpoints, keyed by log origin.
    checkpoints: Mutex<HashMap<String, TransparencyCheckpoint>>,
    /// Cached inclusion proofs, keyed by artifact digest.
    proofs: Mutex<HashMap<Sha256Digest, InclusionProof>>,
    /// Maximum number of cached proofs.
    max_proofs: usize,
}

impl TransparencyCache {
    /// Create a new cache with the given maximum proof count.
    pub fn new(max_proofs: usize) -> Self {
        Self {
            checkpoints: Mutex::new(HashMap::new()),
            proofs: Mutex::new(HashMap::new()),
            max_proofs,
        }
    }

    /// Create a cache with default settings.
    pub fn default_cache() -> Self {
        Self::new(10_000)
    }

    /// Cache a checkpoint for a log.
    pub fn put_checkpoint(&self, origin: String, checkpoint: TransparencyCheckpoint) {
        self.checkpoints.lock().unwrap().insert(origin, checkpoint);
    }

    /// Get a cached checkpoint for a log.
    pub fn get_checkpoint(&self, origin: &str) -> Option<TransparencyCheckpoint> {
        self.checkpoints.lock().unwrap().get(origin).cloned()
    }

    /// Cache an inclusion proof for an artifact.
    pub fn put_proof(&self, digest: Sha256Digest, proof: InclusionProof) {
        let mut proofs = self.proofs.lock().unwrap();
        if proofs.len() >= self.max_proofs {
            // Simple eviction: clear all when full
            proofs.clear();
        }
        proofs.insert(digest, proof);
    }

    /// Get a cached inclusion proof for an artifact.
    pub fn get_proof(&self, digest: &Sha256Digest) -> Option<InclusionProof> {
        self.proofs.lock().unwrap().get(digest).cloned()
    }

    /// Clear all cached data.
    pub fn clear(&self) {
        self.checkpoints.lock().unwrap().clear();
        self.proofs.lock().unwrap().clear();
    }

    /// Number of cached proofs.
    pub fn proof_count(&self) -> usize {
        self.proofs.lock().unwrap().len()
    }
}
