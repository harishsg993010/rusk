use crate::verifier::VerifiedSignature;
use dashmap::DashMap;
use rusk_core::Sha256Digest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A thread-safe cache for verified signature results.
///
/// The cache is keyed by artifact SHA-256 digest and stores the verification
/// result along with the revocation epoch at which it was verified. When the
/// revocation epoch advances (due to new revocation data), all entries from
/// prior epochs are considered stale and will be evicted on access.
pub struct SignatureCache {
    /// Map from artifact digest to cached entry.
    entries: Arc<DashMap<Sha256Digest, CacheEntry>>,
    /// Current revocation epoch. When this advances, cached results from
    /// earlier epochs are invalidated.
    current_epoch: Arc<AtomicU64>,
    /// Maximum number of entries before eviction.
    max_entries: usize,
}

/// A single cached verification result.
#[derive(Clone, Debug)]
struct CacheEntry {
    /// The verified signature result.
    verified: VerifiedSignature,
    /// The revocation epoch when this entry was stored.
    epoch: u64,
}

impl SignatureCache {
    /// Create a new cache with the given maximum size and initial epoch.
    pub fn new(max_entries: usize, initial_epoch: u64) -> Self {
        Self {
            entries: Arc::new(DashMap::with_capacity(max_entries)),
            current_epoch: Arc::new(AtomicU64::new(initial_epoch)),
            max_entries,
        }
    }

    /// Create a cache with default settings (10,000 entries, epoch 0).
    pub fn default_cache() -> Self {
        Self::new(10_000, 0)
    }

    /// Get a cached verification result for the given artifact digest.
    ///
    /// Returns `None` if not cached or if the entry is from a stale epoch.
    pub fn get(&self, digest: &Sha256Digest) -> Option<VerifiedSignature> {
        let current_epoch = self.current_epoch.load(Ordering::Acquire);

        let entry = self.entries.get(digest)?;
        if entry.epoch < current_epoch {
            // Stale entry - remove it and return None.
            drop(entry);
            self.entries.remove(digest);
            tracing::debug!(
                digest = %digest,
                "evicted stale signature cache entry"
            );
            return None;
        }

        Some(entry.verified.clone())
    }

    /// Insert a verified signature result into the cache.
    ///
    /// If the cache is at capacity, a random entry is evicted (DashMap does not
    /// support LRU natively, so we do a simple size check and shrink).
    pub fn insert(&self, digest: Sha256Digest, verified: VerifiedSignature) {
        let epoch = self.current_epoch.load(Ordering::Acquire);

        // Simple capacity enforcement: if over limit, remove ~10% of entries.
        if self.entries.len() >= self.max_entries {
            self.evict_batch();
        }

        self.entries.insert(
            digest,
            CacheEntry {
                verified,
                epoch,
            },
        );
    }

    /// Advance the revocation epoch, invalidating all entries from prior epochs.
    ///
    /// Returns the new epoch value.
    pub fn advance_epoch(&self) -> u64 {
        let new = self.current_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        tracing::info!(epoch = new, "revocation epoch advanced, cache entries will be lazily invalidated");
        new
    }

    /// Explicitly set the epoch (e.g., when loading from a revocation bundle).
    ///
    /// The new epoch must be >= the current epoch (monotonic enforcement).
    /// Returns `true` if the epoch was updated, `false` if it was already at or ahead.
    pub fn set_epoch(&self, epoch: u64) -> bool {
        let current = self.current_epoch.load(Ordering::Acquire);
        if epoch > current {
            self.current_epoch.store(epoch, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Get the current revocation epoch.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Acquire)
    }

    /// Remove a specific entry from the cache (e.g., on explicit revocation).
    pub fn invalidate(&self, digest: &Sha256Digest) -> bool {
        self.entries.remove(digest).is_some()
    }

    /// Remove all cache entries.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Eagerly purge all entries from epochs older than the current epoch.
    pub fn purge_stale(&self) {
        let current_epoch = self.current_epoch.load(Ordering::Acquire);
        self.entries.retain(|_, entry| entry.epoch >= current_epoch);
    }

    /// Evict approximately 10% of entries to make room.
    fn evict_batch(&self) {
        let to_remove = self.max_entries / 10;
        let current_epoch = self.current_epoch.load(Ordering::Acquire);

        // First try to remove stale entries.
        let mut removed = 0;
        let keys_to_remove: Vec<Sha256Digest> = self
            .entries
            .iter()
            .filter(|entry| entry.epoch < current_epoch)
            .take(to_remove)
            .map(|entry| *entry.key())
            .collect();

        for key in keys_to_remove {
            self.entries.remove(&key);
            removed += 1;
        }

        // If we didn't remove enough stale entries, remove oldest remaining.
        if removed < to_remove {
            let still_needed = to_remove - removed;
            let mut entries_by_epoch: Vec<(Sha256Digest, u64)> = self
                .entries
                .iter()
                .map(|e| (*e.key(), e.epoch))
                .collect();
            entries_by_epoch.sort_by_key(|(_, epoch)| *epoch);

            for (key, _) in entries_by_epoch.into_iter().take(still_needed) {
                self.entries.remove(&key);
            }
        }
    }
}

impl Clone for SignatureCache {
    fn clone(&self) -> Self {
        Self {
            entries: Arc::clone(&self.entries),
            current_epoch: Arc::clone(&self.current_epoch),
            max_entries: self.max_entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::SignatureAlgorithm;
    use chrono::Utc;

    fn make_verified(digest: Sha256Digest) -> VerifiedSignature {
        VerifiedSignature {
            signer: rusk_core::SignerIdentity {
                issuer: "test".to_string(),
                subject: "test@example.com".to_string(),
                fingerprint: None,
            },
            algorithm: SignatureAlgorithm::Ed25519,
            timestamp: Utc::now(),
            artifact_digest: digest,
        }
    }

    #[test]
    fn basic_insert_and_get() {
        let cache = SignatureCache::new(100, 0);
        let digest = Sha256Digest::compute(b"test-artifact");
        let verified = make_verified(digest);

        cache.insert(digest, verified.clone());
        let cached = cache.get(&digest).unwrap();
        assert_eq!(cached.signer.subject, "test@example.com");
    }

    #[test]
    fn epoch_invalidation() {
        let cache = SignatureCache::new(100, 0);
        let digest = Sha256Digest::compute(b"test-artifact");
        let verified = make_verified(digest);

        cache.insert(digest, verified);
        assert!(cache.get(&digest).is_some());

        // Advance epoch - old entry becomes stale.
        cache.advance_epoch();
        assert!(cache.get(&digest).is_none());
        assert_eq!(cache.len(), 0); // Entry was removed on access.
    }

    #[test]
    fn explicit_invalidation() {
        let cache = SignatureCache::new(100, 0);
        let digest = Sha256Digest::compute(b"test");
        cache.insert(digest, make_verified(digest));

        assert!(cache.invalidate(&digest));
        assert!(cache.get(&digest).is_none());
    }

    #[test]
    fn monotonic_epoch() {
        let cache = SignatureCache::new(100, 5);
        assert_eq!(cache.current_epoch(), 5);

        // Can advance forward.
        assert!(cache.set_epoch(10));
        assert_eq!(cache.current_epoch(), 10);

        // Cannot go backward.
        assert!(!cache.set_epoch(3));
        assert_eq!(cache.current_epoch(), 10);
    }

    #[test]
    fn purge_stale_entries() {
        let cache = SignatureCache::new(100, 0);

        for i in 0..5u8 {
            let digest = Sha256Digest::compute(&[i]);
            cache.insert(digest, make_verified(digest));
        }
        assert_eq!(cache.len(), 5);

        cache.advance_epoch();

        // Add one entry at the new epoch.
        let fresh_digest = Sha256Digest::compute(b"fresh");
        cache.insert(fresh_digest, make_verified(fresh_digest));

        cache.purge_stale();
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&fresh_digest).is_some());
    }

    #[test]
    fn clone_shares_state() {
        let cache = SignatureCache::new(100, 0);
        let cache2 = cache.clone();

        let digest = Sha256Digest::compute(b"shared");
        cache.insert(digest, make_verified(digest));

        assert!(cache2.get(&digest).is_some());
    }
}
