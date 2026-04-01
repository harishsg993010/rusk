//! Core content-addressed store implementation.
//!
//! Artifacts are stored by SHA-256 digest in a two-level sharded directory.
//! Writes are atomic (write to temp, then rename) to prevent partial reads.

use crate::layout::StoreLayout;
use rusk_core::Sha256Digest;
use std::io;
use std::path::{Path, PathBuf};
use tracing::instrument;

/// Outcome of a write operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// New entry was written.
    Written { digest: Sha256Digest, size: u64 },
    /// Entry already existed (deduplication).
    AlreadyExists { digest: Sha256Digest },
}

/// Metadata for a stored entry.
#[derive(Clone, Debug)]
pub struct CasEntry {
    /// The content digest.
    pub digest: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
    /// Absolute path on disk.
    pub path: PathBuf,
}

/// Content-addressed store backed by a sharded filesystem directory.
pub struct CasStore {
    layout: StoreLayout,
}

impl CasStore {
    /// Open or create a CAS store at the given root directory.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let layout = StoreLayout::new(root.into());
        layout.ensure_dirs()?;
        Ok(Self { layout })
    }

    /// Store content and return the digest. Uses atomic rename to prevent partial writes.
    #[instrument(skip(self, data), fields(size = data.len()))]
    pub fn write(&self, data: &[u8]) -> io::Result<WriteOutcome> {
        let digest = Sha256Digest::compute(data);
        let target = self.layout.blob_path(&digest);

        if target.exists() {
            return Ok(WriteOutcome::AlreadyExists { digest });
        }

        // Ensure parent shard directory exists
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Atomic write: write to temp file, then rename
        let temp_dir = self.layout.temp_dir();
        std::fs::create_dir_all(&temp_dir)?;
        let temp = tempfile::NamedTempFile::new_in(&temp_dir)?;
        std::fs::write(temp.path(), data)?;
        temp.persist(&target)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(WriteOutcome::Written {
            digest,
            size: data.len() as u64,
        })
    }

    /// Read content by digest. Returns `None` if not found.
    #[instrument(skip(self))]
    pub fn read(&self, digest: &Sha256Digest) -> io::Result<Option<Vec<u8>>> {
        let path = self.layout.blob_path(digest);
        if path.exists() {
            let data = std::fs::read(&path)?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Read content using memory-mapped I/O for large files.
    #[instrument(skip(self))]
    pub fn mmap_read(&self, digest: &Sha256Digest) -> io::Result<Option<memmap2::Mmap>> {
        let path = self.layout.blob_path(digest);
        if path.exists() {
            let file = std::fs::File::open(&path)?;
            // SAFETY: we assume no concurrent writes to the same blob (CAS is append-only).
            let mmap = unsafe { memmap2::Mmap::map(&file)? };
            Ok(Some(mmap))
        } else {
            Ok(None)
        }
    }

    /// Check whether a digest exists in the store.
    pub fn contains(&self, digest: &Sha256Digest) -> bool {
        self.layout.blob_path(digest).exists()
    }

    /// Get the entry metadata for a digest, if it exists.
    pub fn entry(&self, digest: &Sha256Digest) -> io::Result<Option<CasEntry>> {
        let path = self.layout.blob_path(digest);
        if path.exists() {
            let meta = std::fs::metadata(&path)?;
            Ok(Some(CasEntry {
                digest: *digest,
                size: meta.len(),
                path,
            }))
        } else {
            Ok(None)
        }
    }

    /// Delete a single entry by digest. Returns true if it existed.
    pub fn delete(&self, digest: &Sha256Digest) -> io::Result<bool> {
        let path = self.layout.blob_path(digest);
        if path.exists() {
            std::fs::remove_file(&path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the store root path.
    pub fn root(&self) -> &Path {
        self.layout.root()
    }
}
