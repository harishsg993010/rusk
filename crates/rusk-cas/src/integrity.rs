//! Integrity verification for CAS blobs.
//!
//! Walks the store and re-hashes each blob to verify that the on-disk
//! content matches the expected SHA-256 digest. Reports any corruption.

use crate::layout::StoreLayout;
use rusk_core::Sha256Digest;
use std::io;
use std::path::PathBuf;
use tracing::{info, warn, instrument};

/// Result of integrity verification for a single blob.
#[derive(Clone, Debug)]
pub struct BlobCheckResult {
    pub expected: Sha256Digest,
    pub path: PathBuf,
    pub valid: bool,
    pub size: u64,
}

/// Summary report of an integrity check run.
#[derive(Clone, Debug, Default)]
pub struct IntegrityReport {
    /// Total blobs checked.
    pub checked: u64,
    /// Blobs that passed verification.
    pub valid: u64,
    /// Blobs with digest mismatches.
    pub corrupted: u64,
    /// Detailed results for corrupted blobs.
    pub corrupted_blobs: Vec<BlobCheckResult>,
}

/// Verifies integrity of the CAS store by re-hashing blob contents.
pub struct IntegrityChecker {
    layout: StoreLayout,
}

impl IntegrityChecker {
    pub fn new(layout: StoreLayout) -> Self {
        Self { layout }
    }

    /// Verify a single blob's integrity.
    pub fn check_blob(&self, expected: &Sha256Digest) -> io::Result<BlobCheckResult> {
        let path = self.layout.blob_path(expected);
        let data = std::fs::read(&path)?;
        let actual = Sha256Digest::compute(&data);
        let valid = actual == *expected;

        if !valid {
            warn!(
                expected = %expected,
                actual = %actual,
                path = %path.display(),
                "CAS blob integrity mismatch"
            );
        }

        Ok(BlobCheckResult {
            expected: *expected,
            path,
            valid,
            size: data.len() as u64,
        })
    }

    /// Run a full integrity check on all blobs in the store.
    #[instrument(skip(self))]
    pub fn check_all(&self) -> io::Result<IntegrityReport> {
        let mut report = IntegrityReport::default();

        let root = self.layout.root();
        if !root.exists() {
            return Ok(report);
        }

        // Walk the shard directories
        for shard_entry in std::fs::read_dir(root)? {
            let shard_entry = shard_entry?;
            let shard_path = shard_entry.path();
            if !shard_path.is_dir() {
                continue;
            }

            for blob_entry in std::fs::read_dir(&shard_path)? {
                let blob_entry = blob_entry?;
                let file_name = blob_entry.file_name();
                let hex_name = file_name.to_string_lossy();

                if let Ok(digest) = Sha256Digest::from_hex(&hex_name) {
                    report.checked += 1;
                    let result = self.check_blob(&digest)?;
                    if result.valid {
                        report.valid += 1;
                    } else {
                        report.corrupted += 1;
                        report.corrupted_blobs.push(result);
                    }
                }
            }
        }

        info!(
            checked = report.checked,
            valid = report.valid,
            corrupted = report.corrupted,
            "integrity check complete"
        );

        Ok(report)
    }
}
