//! Wheel unpacking and installation.
//!
//! Handles unpacking Python wheel (.whl) files into site-packages,
//! writing RECORD files, and creating console_scripts entry points.

use rusk_cas::CasStore;
use rusk_core::{PackageId, Sha256Digest, Version};
use sha2::{Digest, Sha256};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, instrument};

/// Error type for wheel installation.
#[derive(Debug, thiserror::Error)]
pub enum WheelInstallError {
    #[error("invalid wheel filename: {0}")]
    InvalidFilename(String),
    #[error("wheel not found in CAS: {0}")]
    NotInCas(Sha256Digest),
    #[error("wheel extraction failed: {0}")]
    ExtractionFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

/// Metadata parsed from a wheel filename.
///
/// Wheel filenames follow the pattern:
/// `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`
#[derive(Clone, Debug)]
pub struct WheelMetadata {
    /// Distribution name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Build tag (optional).
    pub build: Option<String>,
    /// Python tag (e.g., "py3", "cp311").
    pub python_tag: String,
    /// ABI tag (e.g., "none", "cp311").
    pub abi_tag: String,
    /// Platform tag (e.g., "any", "manylinux_2_17_x86_64").
    pub platform_tag: String,
}

impl WheelMetadata {
    /// Parse metadata from a wheel filename.
    pub fn from_filename(filename: &str) -> Result<Self, WheelInstallError> {
        let name = filename
            .strip_suffix(".whl")
            .ok_or_else(|| WheelInstallError::InvalidFilename(filename.to_string()))?;

        let parts: Vec<&str> = name.split('-').collect();
        match parts.len() {
            5 => Ok(Self {
                name: parts[0].to_string(),
                version: parts[1].to_string(),
                build: None,
                python_tag: parts[2].to_string(),
                abi_tag: parts[3].to_string(),
                platform_tag: parts[4].to_string(),
            }),
            6 => Ok(Self {
                name: parts[0].to_string(),
                version: parts[1].to_string(),
                build: Some(parts[2].to_string()),
                python_tag: parts[3].to_string(),
                abi_tag: parts[4].to_string(),
                platform_tag: parts[5].to_string(),
            }),
            _ => Err(WheelInstallError::InvalidFilename(filename.to_string())),
        }
    }

    /// Whether this is a pure Python wheel (platform-independent).
    pub fn is_pure_python(&self) -> bool {
        self.abi_tag == "none" && self.platform_tag == "any"
    }

    /// The dist-info directory name for this wheel.
    pub fn dist_info_dir(&self) -> String {
        format!("{}-{}.dist-info", self.name, self.version)
    }

    /// The data directory name for this wheel.
    pub fn data_dir(&self) -> String {
        format!("{}-{}.data", self.name, self.version)
    }
}

/// Installs wheels from the CAS into a site-packages directory.
pub struct WheelInstaller {
    cas: Arc<CasStore>,
    site_packages: PathBuf,
}

impl WheelInstaller {
    /// Create a new wheel installer.
    pub fn new(cas: Arc<CasStore>, site_packages: PathBuf) -> Self {
        Self {
            cas,
            site_packages,
        }
    }

    /// Install a wheel from the CAS into site-packages.
    #[instrument(skip(self), fields(package = %package, version = %version))]
    pub fn install_wheel(
        &self,
        package: &PackageId,
        version: &Version,
        digest: &Sha256Digest,
        wheel_filename: &str,
    ) -> Result<InstalledWheel, WheelInstallError> {
        let metadata = WheelMetadata::from_filename(wheel_filename)?;

        // Read the wheel archive from CAS
        let wheel_data = self
            .cas
            .read(digest)
            .map_err(WheelInstallError::Io)?
            .ok_or_else(|| WheelInstallError::NotInCas(*digest))?;

        info!(
            package = %package,
            filename = wheel_filename,
            size = wheel_data.len(),
            "installing wheel"
        );

        let extracted = extract_wheel(&wheel_data, &self.site_packages)?;

        // Write the INSTALLER marker into the dist-info directory
        let dist_info = self.site_packages.join(metadata.dist_info_dir());
        if dist_info.exists() {
            std::fs::write(dist_info.join("INSTALLER"), "rusk\n")?;
        }

        let package_dir = self
            .site_packages
            .join(metadata.name.replace('-', "_"));

        debug!(
            dist_info = %dist_info.display(),
            package_dir = %package_dir.display(),
            files = extracted.files.len(),
            "wheel installation complete"
        );

        Ok(InstalledWheel {
            metadata,
            dist_info_path: dist_info,
            package_dir,
        })
    }
}

/// Result of extracting a wheel archive.
#[derive(Clone, Debug)]
pub struct ExtractedWheel {
    /// Paths of all files that were extracted, relative to site-packages.
    pub files: Vec<PathBuf>,
    /// Total bytes written.
    pub total_bytes: u64,
}

/// Extract a wheel (zip archive) into a site-packages directory.
///
/// Wheels are zip files whose contents should be placed directly into
/// site-packages. This function extracts all entries, preserving the
/// directory structure, and writes a RECORD file listing all extracted
/// files with their SHA-256 hashes and sizes.
pub fn extract_wheel(wheel_data: &[u8], site_packages: &Path) -> Result<ExtractedWheel, WheelInstallError> {
    use std::io::Cursor;

    let reader = Cursor::new(wheel_data);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| WheelInstallError::ExtractionFailed(format!("invalid zip archive: {e}")))?;

    let mut files: Vec<PathBuf> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut record_entries: Vec<String> = Vec::new();
    let mut dist_info_dir: Option<String> = None;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)
            .map_err(|e| WheelInstallError::ExtractionFailed(format!("failed to read zip entry {i}: {e}")))?;

        let entry_path = match entry.enclosed_name() {
            Some(p) => p.to_owned(),
            None => {
                debug!(index = i, "skipping zip entry with unsafe path");
                continue;
            }
        };

        // Detect the dist-info directory name
        if dist_info_dir.is_none() {
            if let Some(first_component) = entry_path.components().next() {
                let comp = first_component.as_os_str().to_string_lossy();
                if comp.ends_with(".dist-info") {
                    dist_info_dir = Some(comp.to_string());
                }
            }
        }

        let target = site_packages.join(&entry_path);

        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
            continue;
        }

        // Ensure parent directory exists
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Read the entry contents
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)
            .map_err(|e| WheelInstallError::ExtractionFailed(
                format!("failed to read entry {}: {e}", entry_path.display())
            ))?;

        // Compute SHA-256 for the RECORD file
        let hash = Sha256::digest(&buf);
        let hash_hex = hex_encode(&hash);
        let size = buf.len() as u64;

        // Write the file
        std::fs::write(&target, &buf)?;

        let rel_path_str = entry_path.to_string_lossy().replace('\\', "/");
        record_entries.push(format!(
            "{},sha256={},{}",
            rel_path_str, hash_hex, size
        ));

        files.push(entry_path);
        total_bytes += size;
    }

    // Write the RECORD file into the dist-info directory
    if let Some(ref di) = dist_info_dir {
        let record_path = site_packages.join(di).join("RECORD");
        // The RECORD file itself is listed without a hash (per PEP 376)
        let record_self = format!("{}/RECORD,,", di);
        record_entries.push(record_self);
        let record_content = record_entries.join("\n") + "\n";
        std::fs::write(&record_path, &record_content)?;
    }

    info!(
        files = files.len(),
        total_bytes,
        "wheel extraction complete"
    );

    Ok(ExtractedWheel {
        files,
        total_bytes,
    })
}

/// Simple hex encoding for SHA-256 digests.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Result of installing a wheel.
#[derive(Clone, Debug)]
pub struct InstalledWheel {
    /// Parsed wheel metadata.
    pub metadata: WheelMetadata,
    /// Path to the .dist-info directory.
    pub dist_info_path: PathBuf,
    /// Path to the package directory.
    pub package_dir: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pure_wheel() {
        let meta = WheelMetadata::from_filename("requests-2.31.0-py3-none-any.whl").unwrap();
        assert_eq!(meta.name, "requests");
        assert_eq!(meta.version, "2.31.0");
        assert!(meta.build.is_none());
        assert_eq!(meta.python_tag, "py3");
        assert_eq!(meta.abi_tag, "none");
        assert_eq!(meta.platform_tag, "any");
        assert!(meta.is_pure_python());
    }

    #[test]
    fn parse_platform_wheel() {
        let meta = WheelMetadata::from_filename(
            "numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.whl",
        )
        .unwrap();
        assert_eq!(meta.name, "numpy");
        assert_eq!(meta.version, "1.26.0");
        assert_eq!(meta.python_tag, "cp311");
        assert!(!meta.is_pure_python());
    }

    #[test]
    fn parse_wheel_with_build_tag() {
        let meta = WheelMetadata::from_filename(
            "example-1.0.0-1-py3-none-any.whl",
        )
        .unwrap();
        assert_eq!(meta.build, Some("1".to_string()));
    }

    #[test]
    fn dist_info_dir_name() {
        let meta = WheelMetadata::from_filename("requests-2.31.0-py3-none-any.whl").unwrap();
        assert_eq!(meta.dist_info_dir(), "requests-2.31.0.dist-info");
    }

    #[test]
    fn invalid_filename_rejected() {
        assert!(WheelMetadata::from_filename("not-a-wheel.tar.gz").is_err());
    }
}
