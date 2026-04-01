//! Filesystem layout for the content-addressed store.
//!
//! Uses a two-level sharded directory structure where the first byte (two hex chars)
//! of the digest forms the shard directory name. This prevents any single directory
//! from containing too many entries.
//!
//! Layout:
//!   <root>/
//!     <shard_prefix>/
//!       <full_hex_digest>
//!     tmp/

use rusk_core::Sha256Digest;
use std::io;
use std::path::{Path, PathBuf};

/// Represents the resolved path within a shard.
#[derive(Clone, Debug)]
pub struct ShardPath {
    /// The shard prefix (e.g., "ab").
    pub shard: String,
    /// The full file path.
    pub path: PathBuf,
}

/// Manages the filesystem layout for CAS storage.
#[derive(Clone, Debug)]
pub struct StoreLayout {
    root: PathBuf,
}

impl StoreLayout {
    /// Create a layout rooted at the given directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Get the root directory of the store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Get the temp directory for atomic writes.
    pub fn temp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Compute the path for a blob identified by its digest.
    pub fn blob_path(&self, digest: &Sha256Digest) -> PathBuf {
        let hex = digest.to_hex();
        let shard = &hex[..2];
        self.root.join(shard).join(&hex)
    }

    /// Get the shard directory for a digest.
    pub fn shard_dir(&self, digest: &Sha256Digest) -> PathBuf {
        let hex = digest.to_hex();
        let shard = &hex[..2];
        self.root.join(shard)
    }

    /// Resolve to a `ShardPath`.
    pub fn shard_path(&self, digest: &Sha256Digest) -> ShardPath {
        let hex = digest.to_hex();
        let shard = hex[..2].to_string();
        let path = self.root.join(&shard).join(&hex);
        ShardPath { shard, path }
    }

    /// Ensure all required directories exist.
    pub fn ensure_dirs(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.temp_dir())?;
        Ok(())
    }

    /// List all shard directories that exist.
    pub fn list_shards(&self) -> io::Result<Vec<PathBuf>> {
        let mut shards = Vec::new();
        if self.root.exists() {
            for entry in std::fs::read_dir(&self.root)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() && path.file_name().map_or(false, |n| n.len() == 2) {
                    shards.push(path);
                }
            }
        }
        Ok(shards)
    }
}
