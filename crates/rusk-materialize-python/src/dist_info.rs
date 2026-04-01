//! dist-info directory management.
//!
//! Manages the .dist-info directories that PEP 376 requires for
//! installed packages, including METADATA, RECORD, and INSTALLER files.

use std::io;
use std::path::{Path, PathBuf};

/// Represents a .dist-info directory for an installed package.
#[derive(Clone, Debug)]
pub struct DistInfo {
    /// Path to the .dist-info directory.
    pub path: PathBuf,
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
}

impl DistInfo {
    /// Create a new DistInfo from a package name and version.
    pub fn new(site_packages: &Path, name: &str, version: &str) -> Self {
        let dir_name = format!("{}-{}.dist-info", normalize_name(name), version);
        Self {
            path: site_packages.join(&dir_name),
            name: name.to_string(),
            version: version.to_string(),
        }
    }

    /// Create the .dist-info directory and write required files.
    pub fn create(&self, metadata_content: &str) -> io::Result<()> {
        std::fs::create_dir_all(&self.path)?;

        // Write METADATA file
        std::fs::write(self.path.join("METADATA"), metadata_content)?;

        // Write INSTALLER file
        std::fs::write(self.path.join("INSTALLER"), "rusk\n")?;

        Ok(())
    }

    /// Write the RECORD file listing all installed files and their hashes.
    pub fn write_record(&self, entries: &[RecordEntry]) -> io::Result<()> {
        let mut content = String::new();
        for entry in entries {
            content.push_str(&format!(
                "{},{},{}\n",
                entry.path, entry.hash, entry.size
            ));
        }
        // The RECORD file itself has no hash
        content.push_str(&format!(
            "{},,\n",
            self.path.join("RECORD").to_string_lossy()
        ));
        std::fs::write(self.path.join("RECORD"), content)?;
        Ok(())
    }

    /// Check if the dist-info directory exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

/// An entry in the RECORD file.
#[derive(Clone, Debug)]
pub struct RecordEntry {
    /// Relative path to the file.
    pub path: String,
    /// Hash in the format "sha256=<base64>".
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
}

/// Normalize a Python package name for use in dist-info directory names.
fn normalize_name(name: &str) -> String {
    name.to_lowercase().replace(['-', '.', ' '], "_")
}
