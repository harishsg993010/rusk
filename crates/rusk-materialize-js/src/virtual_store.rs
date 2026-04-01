//! Virtual store planning for pnpm-style node_modules.
//!
//! Plans the `.rusk/` virtual store directory structure where each package
//! is stored at a content-addressed path, and hoisted symlinks in
//! `node_modules/` point into the store. This deduplicates packages
//! across multiple dependents.

use rusk_core::{PackageId, Sha256Digest, Version};
use rusk_materialize::planner::{FileType, MaterializationEntry, MaterializationPlan};
use std::collections::HashMap;
use std::path::PathBuf;

/// An entry in the virtual store.
#[derive(Clone, Debug)]
pub struct VirtualStoreEntry {
    /// Package identity.
    pub package: PackageId,
    /// Version.
    pub version: Version,
    /// CAS digest.
    pub digest: Sha256Digest,
    /// The store path: `.rusk/<name>@<version>`
    pub store_path: PathBuf,
    /// Symlinks that should point to this entry.
    pub symlinks: Vec<PathBuf>,
}

/// Plans the virtual store layout.
pub struct VirtualStorePlanner {
    /// All entries in the virtual store.
    entries: Vec<VirtualStoreEntry>,
    /// Deduplication map: digest -> store entry index.
    dedup: HashMap<Sha256Digest, usize>,
}

impl VirtualStorePlanner {
    /// Create a new planner.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            dedup: HashMap::new(),
        }
    }

    /// Add a package to the virtual store plan.
    ///
    /// If a package with the same digest already exists, the new request
    /// is deduplicated and only a symlink is added.
    pub fn add_package(
        &mut self,
        package: PackageId,
        version: Version,
        digest: Sha256Digest,
        symlink_path: PathBuf,
    ) {
        if let Some(&idx) = self.dedup.get(&digest) {
            // Already in the store; just add a symlink
            self.entries[idx].symlinks.push(symlink_path);
        } else {
            let store_path = PathBuf::from(".rusk").join(format!(
                "{}@{}",
                package.display_name(),
                version
            ));
            let idx = self.entries.len();
            self.entries.push(VirtualStoreEntry {
                package,
                version,
                digest,
                store_path,
                symlinks: vec![symlink_path],
            });
            self.dedup.insert(digest, idx);
        }
    }

    /// Finalize the plan into a MaterializationPlan.
    pub fn into_plan(self, target_dir: PathBuf) -> MaterializationPlan {
        let mut plan = MaterializationPlan::new(target_dir);

        for entry in &self.entries {
            // The actual package extraction
            plan.add_entry(MaterializationEntry {
                package: entry.package.clone(),
                version: entry.version.clone(),
                digest: entry.digest,
                relative_path: entry
                    .store_path
                    .join("node_modules")
                    .join(entry.package.display_name()),
                file_type: FileType::ExtractedArchive,
                size: 0, // Will be filled from CAS
                depth: 0,
            });

            // Symlinks pointing to the store entry
            for symlink in &entry.symlinks {
                plan.add_entry(MaterializationEntry {
                    package: entry.package.clone(),
                    version: entry.version.clone(),
                    digest: entry.digest,
                    relative_path: symlink.clone(),
                    file_type: FileType::Symlink,
                    size: 0,
                    depth: 0,
                });
            }
        }

        plan
    }

    /// Number of unique packages in the store (after dedup).
    pub fn unique_count(&self) -> usize {
        self.entries.len()
    }

    /// Total number of symlinks.
    pub fn symlink_count(&self) -> usize {
        self.entries.iter().map(|e| e.symlinks.len()).sum()
    }
}

impl Default for VirtualStorePlanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deduplication() {
        let mut planner = VirtualStorePlanner::new();
        let digest = Sha256Digest::compute(b"same-content");

        planner.add_package(
            PackageId::js("lodash"),
            Version::Semver(semver::Version::new(4, 17, 21)),
            digest,
            PathBuf::from("express/node_modules/lodash"),
        );
        planner.add_package(
            PackageId::js("lodash"),
            Version::Semver(semver::Version::new(4, 17, 21)),
            digest,
            PathBuf::from("webpack/node_modules/lodash"),
        );

        assert_eq!(planner.unique_count(), 1);
        assert_eq!(planner.symlink_count(), 2);
    }
}
