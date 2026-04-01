//! Registry metadata cache.
//!
//! Provides an in-memory cache for registry metadata to reduce network
//! requests during resolution. Respects HTTP cache semantics where applicable.

use crate::metadata::{PackageMetadata, VersionMetadata};
use rusk_core::{PackageId, Version};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Cached entry with expiry tracking.
#[derive(Clone, Debug)]
struct CacheEntry<T> {
    value: T,
    inserted_at: Instant,
    ttl: Duration,
}

impl<T> CacheEntry<T> {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// Thread-safe in-memory metadata cache.
///
/// Caches both package-level metadata (version listings) and individual
/// version metadata to avoid redundant network requests during resolution.
#[derive(Clone)]
pub struct MetadataCache {
    /// Package metadata cache, keyed by canonical package ID.
    packages: Arc<RwLock<HashMap<String, CacheEntry<PackageMetadata>>>>,
    /// Version metadata cache, keyed by "canonical_id@version".
    versions: Arc<RwLock<HashMap<String, CacheEntry<VersionMetadata>>>>,
    /// Default TTL for cache entries.
    default_ttl: Duration,
    /// Maximum number of package entries.
    max_packages: usize,
}

impl MetadataCache {
    /// Create a new metadata cache with the given TTL and capacity.
    pub fn new(default_ttl: Duration, max_packages: usize) -> Self {
        Self {
            packages: Arc::new(RwLock::new(HashMap::new())),
            versions: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
            max_packages,
        }
    }

    /// Look up cached package metadata.
    pub fn get_package(&self, package: &PackageId) -> Option<PackageMetadata> {
        let key = package.canonical();
        let cache = self.packages.read().ok()?;
        let entry = cache.get(&key)?;
        if entry.is_expired() {
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Insert package metadata into the cache.
    pub fn insert_package(&self, package: &PackageId, metadata: PackageMetadata) {
        let key = package.canonical();
        if let Ok(mut cache) = self.packages.write() {
            // Simple eviction: if at capacity, remove expired entries first.
            if cache.len() >= self.max_packages {
                cache.retain(|_, entry| !entry.is_expired());
            }
            // If still at capacity after eviction, remove oldest entry.
            if cache.len() >= self.max_packages {
                if let Some(oldest_key) = cache
                    .iter()
                    .min_by_key(|(_, e)| e.inserted_at)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest_key);
                }
            }
            cache.insert(
                key,
                CacheEntry {
                    value: metadata,
                    inserted_at: Instant::now(),
                    ttl: self.default_ttl,
                },
            );
        }
    }

    /// Look up cached version metadata.
    pub fn get_version(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Option<VersionMetadata> {
        let key = format!("{}@{}", package.canonical(), version);
        let cache = self.versions.read().ok()?;
        let entry = cache.get(&key)?;
        if entry.is_expired() {
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Insert version metadata into the cache.
    pub fn insert_version(
        &self,
        package: &PackageId,
        version: &Version,
        metadata: VersionMetadata,
    ) {
        let key = format!("{}@{}", package.canonical(), version);
        if let Ok(mut cache) = self.versions.write() {
            cache.insert(
                key,
                CacheEntry {
                    value: metadata,
                    inserted_at: Instant::now(),
                    ttl: self.default_ttl,
                },
            );
        }
    }

    /// Invalidate all cached data for a specific package.
    pub fn invalidate_package(&self, package: &PackageId) {
        let key = package.canonical();
        if let Ok(mut cache) = self.packages.write() {
            cache.remove(&key);
        }
        // Also remove all version entries for this package.
        let prefix = format!("{}@", key);
        if let Ok(mut cache) = self.versions.write() {
            cache.retain(|k, _| !k.starts_with(&prefix));
        }
    }

    /// Clear all cached data.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.packages.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.versions.write() {
            cache.clear();
        }
    }

    /// Number of cached package entries (not counting expired).
    pub fn package_count(&self) -> usize {
        self.packages
            .read()
            .map(|cache| cache.values().filter(|e| !e.is_expired()).count())
            .unwrap_or(0)
    }

    /// Number of cached version entries (not counting expired).
    pub fn version_count(&self) -> usize {
        self.versions
            .read()
            .map(|cache| cache.values().filter(|e| !e.is_expired()).count())
            .unwrap_or(0)
    }
}

impl Default for MetadataCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(300), 10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::PackageId;

    #[test]
    fn insert_and_retrieve_package() {
        let cache = MetadataCache::new(Duration::from_secs(60), 100);
        let pkg = PackageId::js("express");
        let metadata = PackageMetadata {
            package: pkg.clone(),
            description: Some("Fast web framework".to_string()),
            versions: vec![],
            version_metadata: HashMap::new(),
            dist_tags: HashMap::new(),
        };
        cache.insert_package(&pkg, metadata.clone());
        let retrieved = cache.get_package(&pkg).unwrap();
        assert_eq!(retrieved.description, Some("Fast web framework".to_string()));
    }

    #[test]
    fn miss_returns_none() {
        let cache = MetadataCache::default();
        let pkg = PackageId::js("nonexistent");
        assert!(cache.get_package(&pkg).is_none());
    }

    #[test]
    fn invalidate_removes_entries() {
        let cache = MetadataCache::default();
        let pkg = PackageId::js("lodash");
        let metadata = PackageMetadata {
            package: pkg.clone(),
            description: None,
            versions: vec![],
            version_metadata: HashMap::new(),
            dist_tags: HashMap::new(),
        };
        cache.insert_package(&pkg, metadata);
        assert!(cache.get_package(&pkg).is_some());
        cache.invalidate_package(&pkg);
        assert!(cache.get_package(&pkg).is_none());
    }

    #[test]
    fn expired_entries_not_returned() {
        let cache = MetadataCache::new(Duration::from_millis(0), 100);
        let pkg = PackageId::js("stale");
        let metadata = PackageMetadata {
            package: pkg.clone(),
            description: None,
            versions: vec![],
            version_metadata: HashMap::new(),
            dist_tags: HashMap::new(),
        };
        cache.insert_package(&pkg, metadata);
        // TTL is 0ms, so it should be expired immediately.
        assert!(cache.get_package(&pkg).is_none());
    }
}
