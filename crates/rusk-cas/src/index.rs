//! CAS index for tracking stored artifacts and metadata.
//!
//! Maintains an in-memory index of all stored blobs, their sizes, and
//! reference counts. Used by the garbage collector to determine liveness.

use rusk_core::Sha256Digest;
use std::collections::HashMap;

/// Metadata tracked for each entry in the index.
#[derive(Clone, Debug)]
pub struct IndexEntry {
    /// Content digest.
    pub digest: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
    /// Number of live references (lockfiles, materialized trees) pointing to this blob.
    pub ref_count: u32,
    /// Whether this entry has been verified since the last integrity check.
    pub verified: bool,
}

/// In-memory index of the CAS contents.
pub struct CasIndex {
    entries: HashMap<Sha256Digest, IndexEntry>,
}

impl CasIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register or update an entry in the index.
    pub fn insert(&mut self, digest: Sha256Digest, size: u64) {
        self.entries
            .entry(digest)
            .and_modify(|e| {
                e.ref_count += 1;
            })
            .or_insert(IndexEntry {
                digest,
                size,
                ref_count: 1,
                verified: false,
            });
    }

    /// Look up an entry by digest.
    pub fn get(&self, digest: &Sha256Digest) -> Option<&IndexEntry> {
        self.entries.get(digest)
    }

    /// Increment the reference count for a digest.
    pub fn add_ref(&mut self, digest: &Sha256Digest) {
        if let Some(entry) = self.entries.get_mut(digest) {
            entry.ref_count += 1;
        }
    }

    /// Decrement the reference count for a digest.
    pub fn release_ref(&mut self, digest: &Sha256Digest) {
        if let Some(entry) = self.entries.get_mut(digest) {
            entry.ref_count = entry.ref_count.saturating_sub(1);
        }
    }

    /// Return all entries with zero references (candidates for GC).
    pub fn unreferenced(&self) -> Vec<&IndexEntry> {
        self.entries
            .values()
            .filter(|e| e.ref_count == 0)
            .collect()
    }

    /// Total number of entries in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total size in bytes of all indexed entries.
    pub fn total_size(&self) -> u64 {
        self.entries.values().map(|e| e.size).sum()
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &IndexEntry> {
        self.entries.values()
    }
}

impl Default for CasIndex {
    fn default() -> Self {
        Self::new()
    }
}
