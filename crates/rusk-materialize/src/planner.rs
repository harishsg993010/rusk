//! Materialization planning.
//!
//! Computes the set of files that need to be placed on disk from the resolved
//! dependency graph and the CAS store. The plan is computed before any file
//! system mutations, allowing preview and validation.

use rusk_core::{PackageId, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A complete plan for materializing resolved packages to disk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaterializationPlan {
    /// Target root directory (e.g., `node_modules` or `site-packages`).
    pub target_dir: PathBuf,
    /// Ordered list of entries to materialize.
    pub entries: Vec<MaterializationEntry>,
    /// Total bytes that will be written/linked.
    pub total_bytes: u64,
    /// Number of packages that are already up-to-date.
    pub up_to_date: usize,
}

impl MaterializationPlan {
    /// Create a new empty plan targeting the given directory.
    pub fn new(target_dir: PathBuf) -> Self {
        Self {
            target_dir,
            entries: Vec::new(),
            total_bytes: 0,
            up_to_date: 0,
        }
    }

    /// Add an entry to the plan.
    pub fn add_entry(&mut self, entry: MaterializationEntry) {
        self.total_bytes += entry.size;
        self.entries.push(entry);
    }

    /// Mark a package as already up-to-date (no work needed).
    pub fn mark_up_to_date(&mut self) {
        self.up_to_date += 1;
    }

    /// Number of entries that need materialization.
    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the plan requires any file system mutations.
    pub fn has_work(&self) -> bool {
        !self.entries.is_empty()
    }

    /// Sort entries in dependency order (dependencies first).
    pub fn sort_by_depth(&mut self) {
        self.entries.sort_by_key(|e| e.depth);
    }
}

/// A single entry in the materialization plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaterializationEntry {
    /// The package being materialized.
    pub package: PackageId,
    /// Exact version.
    pub version: Version,
    /// CAS digest of the archive.
    pub digest: Sha256Digest,
    /// Target path relative to the plan's target_dir.
    pub relative_path: PathBuf,
    /// Type of file/directory to create.
    pub file_type: FileType,
    /// Size in bytes.
    pub size: u64,
    /// Depth in the dependency tree.
    pub depth: u32,
}

/// Type of materialized entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    /// A directory containing extracted package contents.
    Directory,
    /// An extracted archive (tarball, wheel).
    ExtractedArchive,
    /// A symlink to another location (e.g., hoisted package).
    Symlink,
    /// A single file (e.g., a .pth file).
    File,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::Sha256Digest;

    #[test]
    fn plan_tracks_stats() {
        let mut plan = MaterializationPlan::new(PathBuf::from("/tmp/node_modules"));
        assert!(!plan.has_work());
        assert_eq!(plan.pending_count(), 0);

        plan.add_entry(MaterializationEntry {
            package: PackageId::js("express"),
            version: Version::Semver(semver::Version::new(4, 18, 2)),
            digest: Sha256Digest::zero(),
            relative_path: PathBuf::from("express"),
            file_type: FileType::ExtractedArchive,
            size: 1024,
            depth: 1,
        });

        assert!(plan.has_work());
        assert_eq!(plan.pending_count(), 1);
        assert_eq!(plan.total_bytes, 1024);
    }
}
