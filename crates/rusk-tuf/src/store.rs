use crate::metadata::{
    RootMetadata, SignedMetadata, SnapshotMetadata, TargetsMetadata, TimestampMetadata,
    TufMetadataError, TufRole,
};
use std::path::{Path, PathBuf};

/// Errors from the TUF local store.
#[derive(Debug, thiserror::Error)]
pub enum TufStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("metadata error: {0}")]
    Metadata(#[from] TufMetadataError),

    #[error("no trusted {role} metadata found on disk")]
    NotFound { role: String },
}

/// Local filesystem store for persisting trusted TUF state between runs.
///
/// Directory layout:
/// ```text
/// <base_dir>/
///   root.json              -- current trusted root
///   timestamp.json         -- current trusted timestamp
///   snapshot.json          -- current trusted snapshot
///   targets.json           -- current trusted top-level targets
///   delegated/
///     <role_name>.json     -- delegated target metadata
///   previous/
///     <version>.root.json  -- archived root versions for auditing
/// ```
pub struct TufLocalStore {
    base_dir: PathBuf,
}

impl TufLocalStore {
    /// Create or open a TUF local store at the given directory.
    pub fn open(base_dir: impl Into<PathBuf>) -> Result<Self, TufStoreError> {
        let base_dir = base_dir.into();
        std::fs::create_dir_all(&base_dir)?;
        std::fs::create_dir_all(base_dir.join("delegated"))?;
        std::fs::create_dir_all(base_dir.join("previous"))?;
        Ok(Self { base_dir })
    }

    /// Return the base directory path.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    // ---- Root metadata ----

    /// Load the trusted root metadata from disk.
    pub fn load_root(&self) -> Result<SignedMetadata<RootMetadata>, TufStoreError> {
        let path = self.base_dir.join(TufRole::Root.filename());
        self.load_signed_from(&path)
    }

    /// Persist a new trusted root metadata. Also archives the previous version.
    pub fn store_root(
        &self,
        signed_root: &SignedMetadata<RootMetadata>,
    ) -> Result<(), TufStoreError> {
        // Archive the current root if it exists.
        let current_path = self.base_dir.join(TufRole::Root.filename());
        if current_path.exists() {
            if let Ok(old) = self.load_root() {
                let archive_name = format!("{}.root.json", old.signed.common.version);
                let archive_path = self.base_dir.join("previous").join(archive_name);
                let old_bytes = serde_json::to_vec_pretty(&old)?;
                std::fs::write(archive_path, old_bytes)?;
            }
        }

        self.write_signed(&current_path, signed_root)
    }

    /// Check if a trusted root exists on disk.
    pub fn has_root(&self) -> bool {
        self.base_dir.join(TufRole::Root.filename()).exists()
    }

    // ---- Timestamp metadata ----

    /// Load the trusted timestamp metadata.
    pub fn load_timestamp(&self) -> Result<SignedMetadata<TimestampMetadata>, TufStoreError> {
        let path = self.base_dir.join(TufRole::Timestamp.filename());
        self.load_signed_from(&path)
    }

    /// Persist the trusted timestamp metadata.
    pub fn store_timestamp(
        &self,
        signed: &SignedMetadata<TimestampMetadata>,
    ) -> Result<(), TufStoreError> {
        let path = self.base_dir.join(TufRole::Timestamp.filename());
        self.write_signed(&path, signed)
    }

    // ---- Snapshot metadata ----

    /// Load the trusted snapshot metadata.
    pub fn load_snapshot(&self) -> Result<SignedMetadata<SnapshotMetadata>, TufStoreError> {
        let path = self.base_dir.join(TufRole::Snapshot.filename());
        self.load_signed_from(&path)
    }

    /// Persist the trusted snapshot metadata.
    pub fn store_snapshot(
        &self,
        signed: &SignedMetadata<SnapshotMetadata>,
    ) -> Result<(), TufStoreError> {
        let path = self.base_dir.join(TufRole::Snapshot.filename());
        self.write_signed(&path, signed)
    }

    // ---- Targets metadata ----

    /// Load the trusted top-level targets metadata.
    pub fn load_targets(&self) -> Result<SignedMetadata<TargetsMetadata>, TufStoreError> {
        let path = self.base_dir.join(TufRole::Targets.filename());
        self.load_signed_from(&path)
    }

    /// Persist the trusted top-level targets metadata.
    pub fn store_targets(
        &self,
        signed: &SignedMetadata<TargetsMetadata>,
    ) -> Result<(), TufStoreError> {
        let path = self.base_dir.join(TufRole::Targets.filename());
        self.write_signed(&path, signed)
    }

    // ---- Delegated targets ----

    /// Load a delegated targets metadata by role name.
    pub fn load_delegated(
        &self,
        role_name: &str,
    ) -> Result<SignedMetadata<TargetsMetadata>, TufStoreError> {
        let path = self
            .base_dir
            .join("delegated")
            .join(format!("{role_name}.json"));
        self.load_signed_from(&path)
    }

    /// Persist a delegated targets metadata.
    pub fn store_delegated(
        &self,
        role_name: &str,
        signed: &SignedMetadata<TargetsMetadata>,
    ) -> Result<(), TufStoreError> {
        let path = self
            .base_dir
            .join("delegated")
            .join(format!("{role_name}.json"));
        self.write_signed(&path, signed)
    }

    // ---- Purge / reset ----

    /// Remove all trusted metadata (for a complete re-bootstrap).
    pub fn purge(&self) -> Result<(), TufStoreError> {
        for entry in std::fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                std::fs::remove_file(path)?;
            }
        }
        // Also clear delegated.
        let delegated_dir = self.base_dir.join("delegated");
        if delegated_dir.exists() {
            for entry in std::fs::read_dir(&delegated_dir)? {
                let entry = entry?;
                std::fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    /// List all archived root versions.
    pub fn list_archived_roots(&self) -> Result<Vec<u64>, TufStoreError> {
        let previous_dir = self.base_dir.join("previous");
        let mut versions = Vec::new();
        if previous_dir.exists() {
            for entry in std::fs::read_dir(&previous_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Parse "<version>.root.json"
                if let Some(rest) = name_str.strip_suffix(".root.json") {
                    if let Ok(v) = rest.parse::<u64>() {
                        versions.push(v);
                    }
                }
            }
        }
        versions.sort();
        Ok(versions)
    }

    // ---- Internal helpers ----

    fn load_signed_from<T: serde::de::DeserializeOwned>(
        &self,
        path: &Path,
    ) -> Result<SignedMetadata<T>, TufStoreError> {
        if !path.exists() {
            return Err(TufStoreError::NotFound {
                role: path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }
        let bytes = std::fs::read(path)?;
        let signed: SignedMetadata<T> = serde_json::from_slice(&bytes)?;
        Ok(signed)
    }

    fn write_signed<T: serde::Serialize>(
        &self,
        path: &Path,
        signed: &SignedMetadata<T>,
    ) -> Result<(), TufStoreError> {
        // Atomic write: write to temp file then rename.
        let temp_path = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(signed)?;
        std::fs::write(&temp_path, &bytes)?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::*;
    use std::collections::HashMap;

    fn make_signed_root() -> SignedMetadata<RootMetadata> {
        SignedMetadata {
            signatures: vec![],
            signed: RootMetadata {
                common: CommonMetadata {
                    spec_version: "1.0.31".to_string(),
                    version: 1,
                    expires: chrono::Utc::now() + chrono::Duration::hours(24),
                },
                consistent_snapshot: false,
                keys: HashMap::new(),
                roles: HashMap::new(),
            },
        }
    }

    #[test]
    fn store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = TufLocalStore::open(dir.path()).unwrap();

        assert!(!store.has_root());

        let root = make_signed_root();
        store.store_root(&root).unwrap();

        assert!(store.has_root());

        let loaded = store.load_root().unwrap();
        assert_eq!(loaded.signed.common.version, 1);
    }

    #[test]
    fn archive_on_root_update() {
        let dir = tempfile::tempdir().unwrap();
        let store = TufLocalStore::open(dir.path()).unwrap();

        let root_v1 = make_signed_root();
        store.store_root(&root_v1).unwrap();

        let mut root_v2 = make_signed_root();
        root_v2.signed.common.version = 2;
        store.store_root(&root_v2).unwrap();

        let loaded = store.load_root().unwrap();
        assert_eq!(loaded.signed.common.version, 2);

        let archived = store.list_archived_roots().unwrap();
        assert_eq!(archived, vec![1]);
    }

    #[test]
    fn purge_clears_all() {
        let dir = tempfile::tempdir().unwrap();
        let store = TufLocalStore::open(dir.path()).unwrap();

        store.store_root(&make_signed_root()).unwrap();
        assert!(store.has_root());

        store.purge().unwrap();
        assert!(!store.has_root());
    }
}
