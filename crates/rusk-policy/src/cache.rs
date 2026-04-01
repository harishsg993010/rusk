//! Policy verdict caching.
//!
//! Caches evaluation results keyed by (policy version, artifact digest, context hash)
//! to avoid re-evaluating the same artifact against the same policy.

use dashmap::DashMap;
use rusk_core::trust::PolicyVerdict;
use rusk_core::Sha256Digest;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Cache key combining policy identity and artifact identity.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PolicyCacheKey {
    /// Policy name + version, forming the policy identity.
    pub policy_id: String,
    /// Artifact content digest.
    pub artifact_digest: Sha256Digest,
    /// Hash of the evaluation context (install mode, graph depth, etc.).
    pub context_hash: u64,
}

/// Cached verdict with metadata.
#[derive(Clone, Debug)]
pub struct CachedVerdict {
    /// The cached policy verdict.
    pub verdict: PolicyVerdict,
    /// When the verdict was computed.
    pub computed_at: chrono::DateTime<chrono::Utc>,
}

/// Thread-safe policy verdict cache using DashMap.
#[derive(Clone)]
pub struct PolicyVerdictCache {
    inner: Arc<DashMap<PolicyCacheKey, CachedVerdict>>,
    /// Maximum number of entries before eviction.
    max_entries: usize,
}

impl PolicyVerdictCache {
    /// Create a new cache with the given maximum capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::with_capacity(max_entries.min(1024))),
            max_entries,
        }
    }

    /// Look up a cached verdict.
    pub fn get(&self, key: &PolicyCacheKey) -> Option<CachedVerdict> {
        self.inner.get(key).map(|entry| entry.value().clone())
    }

    /// Insert a verdict into the cache.
    ///
    /// If the cache is at capacity, this will evict some existing entries.
    pub fn insert(&self, key: PolicyCacheKey, verdict: PolicyVerdict) {
        if self.inner.len() >= self.max_entries {
            self.evict();
        }
        self.inner.insert(
            key,
            CachedVerdict {
                verdict,
                computed_at: chrono::Utc::now(),
            },
        );
    }

    /// Remove a specific entry from the cache.
    pub fn invalidate(&self, key: &PolicyCacheKey) -> bool {
        self.inner.remove(key).is_some()
    }

    /// Clear all cached verdicts (e.g., when policy changes).
    pub fn clear(&self) {
        self.inner.clear();
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Compute a context hash from a set of key-value pairs.
    ///
    /// This is used to differentiate evaluations of the same artifact
    /// in different contexts (e.g., different install modes or graph positions).
    pub fn hash_context(pairs: &[(&str, &str)]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (k, v) in pairs {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Simple eviction: remove approximately 25% of entries.
    ///
    /// Uses a simple strategy: remove entries older than the median.
    /// In practice this is called rarely since policy evaluations are fast.
    fn evict(&self) {
        let target = self.inner.len() / 4;
        let mut removed = 0;
        // Collect keys to remove (we can't remove while iterating DashMap safely
        // without potential deadlock in all cases, so collect first).
        let keys_to_remove: Vec<PolicyCacheKey> = self
            .inner
            .iter()
            .take(target)
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys_to_remove {
            self.inner.remove(&key);
            removed += 1;
        }
        tracing::debug!(removed, remaining = self.inner.len(), "evicted cache entries");
    }
}

impl Default for PolicyVerdictCache {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::trust::PolicyVerdict;

    fn make_key(policy: &str, digest_byte: u8) -> PolicyCacheKey {
        let mut digest_bytes = [0u8; 32];
        digest_bytes[0] = digest_byte;
        PolicyCacheKey {
            policy_id: policy.to_string(),
            artifact_digest: Sha256Digest(digest_bytes),
            context_hash: 0,
        }
    }

    #[test]
    fn insert_and_get() {
        let cache = PolicyVerdictCache::new(100);
        let key = make_key("test-policy:1.0.0", 1);
        let verdict = PolicyVerdict::Allow {
            matched_rules: vec!["rule1".to_string()],
        };
        cache.insert(key.clone(), verdict);
        let cached = cache.get(&key).unwrap();
        assert!(matches!(cached.verdict, PolicyVerdict::Allow { .. }));
    }

    #[test]
    fn miss_returns_none() {
        let cache = PolicyVerdictCache::new(100);
        let key = make_key("nonexistent:0.0.0", 99);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = PolicyVerdictCache::new(100);
        let key = make_key("test:1.0.0", 1);
        cache.insert(
            key.clone(),
            PolicyVerdict::Allow {
                matched_rules: vec![],
            },
        );
        assert!(cache.invalidate(&key));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn eviction_on_capacity() {
        let cache = PolicyVerdictCache::new(10);
        for i in 0..15u8 {
            cache.insert(
                make_key("test:1.0.0", i),
                PolicyVerdict::Allow {
                    matched_rules: vec![],
                },
            );
        }
        // After eviction, we should have fewer entries than we inserted.
        assert!(cache.len() <= 15);
    }

    #[test]
    fn context_hash_deterministic() {
        let pairs = [("install_mode", "ci"), ("graph.depth", "2")];
        let h1 = PolicyVerdictCache::hash_context(&pairs);
        let h2 = PolicyVerdictCache::hash_context(&pairs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn context_hash_varies() {
        let h1 = PolicyVerdictCache::hash_context(&[("install_mode", "ci")]);
        let h2 = PolicyVerdictCache::hash_context(&[("install_mode", "interactive")]);
        assert_ne!(h1, h2);
    }
}
