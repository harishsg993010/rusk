//! Python virtual environment management.
//!
//! Creates and manages virtual environments for isolated Python package
//! installation. Handles detecting the system Python, creating venvs,
//! and locating the site-packages directory.

use rusk_core::platform::PythonVersion;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, info, instrument};

/// Error type for venv operations.
#[derive(Debug, thiserror::Error)]
pub enum VenvError {
    #[error("Python interpreter not found: {0}")]
    PythonNotFound(String),
    #[error("venv creation failed: {0}")]
    CreationFailed(String),
    #[error("invalid venv at {path}: {reason}")]
    InvalidVenv { path: PathBuf, reason: String },
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

/// Manages Python virtual environments for package installation.
pub struct VenvManager {
    /// Root directory containing the venv.
    venv_dir: PathBuf,
    /// Python version in this venv.
    python_version: PythonVersion,
}

impl VenvManager {
    /// Create a new venv manager for an existing venv.
    pub fn open(venv_dir: PathBuf) -> Result<Self, VenvError> {
        if !venv_dir.exists() {
            return Err(VenvError::InvalidVenv {
                path: venv_dir,
                reason: "directory does not exist".to_string(),
            });
        }

        let python_version = detect_venv_python(&venv_dir)?;

        Ok(Self {
            venv_dir,
            python_version,
        })
    }

    /// Create a new virtual environment at the given path.
    #[instrument(skip_all, fields(venv = %venv_dir.display()))]
    pub fn create(venv_dir: PathBuf, python: &str) -> Result<Self, VenvError> {
        info!("creating virtual environment at {}", venv_dir.display());

        // Use the system Python to create the venv
        let output = std::process::Command::new(python)
            .args(["-m", "venv", &venv_dir.to_string_lossy()])
            .output()
            .map_err(|e| VenvError::PythonNotFound(format!("{}: {}", python, e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(VenvError::CreationFailed(stderr.to_string()));
        }

        Self::open(venv_dir)
    }

    /// Get the venv root directory.
    pub fn root(&self) -> &Path {
        &self.venv_dir
    }

    /// Get the Python version in this venv.
    pub fn python_version(&self) -> &PythonVersion {
        &self.python_version
    }

    /// Get the path to the Python executable in the venv.
    pub fn python_path(&self) -> PathBuf {
        if cfg!(windows) {
            self.venv_dir.join("Scripts").join("python.exe")
        } else {
            self.venv_dir.join("bin").join("python")
        }
    }

    /// Get the site-packages directory.
    pub fn site_packages(&self) -> PathBuf {
        let version_dir = format!(
            "python{}.{}",
            self.python_version.major, self.python_version.minor
        );
        if cfg!(windows) {
            self.venv_dir.join("Lib").join("site-packages")
        } else {
            self.venv_dir
                .join("lib")
                .join(&version_dir)
                .join("site-packages")
        }
    }

    /// Check if a package is installed in this venv by looking for its dist-info.
    pub fn is_installed(&self, package_name: &str) -> bool {
        let site_packages = self.site_packages();
        if let Ok(entries) = std::fs::read_dir(&site_packages) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(package_name) && name.ends_with(".dist-info") {
                    return true;
                }
            }
        }
        false
    }

    /// List all installed packages in this venv.
    pub fn list_installed(&self) -> Vec<InstalledDistInfo> {
        let site_packages = self.site_packages();
        let mut installed = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&site_packages) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".dist-info") {
                    if let Some(info) = parse_dist_info_name(&name) {
                        installed.push(info);
                    }
                }
            }
        }

        installed
    }
}

/// Information parsed from a .dist-info directory name.
#[derive(Clone, Debug)]
pub struct InstalledDistInfo {
    /// Normalized package name.
    pub name: String,
    /// Installed version.
    pub version: String,
}

/// Detect the Python version from a venv by examining pyvenv.cfg.
fn detect_venv_python(venv_dir: &Path) -> Result<PythonVersion, VenvError> {
    let cfg_path = venv_dir.join("pyvenv.cfg");
    if cfg_path.exists() {
        let content = std::fs::read_to_string(&cfg_path)?;
        for line in content.lines() {
            let line = line.trim();
            if let Some(version) = line.strip_prefix("version") {
                let version = version.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
                let parts: Vec<&str> = version.split('.').collect();
                if parts.len() >= 2 {
                    if let (Ok(major), Ok(minor)) = (parts[0].parse(), parts[1].parse()) {
                        return Ok(PythonVersion::new(major, minor));
                    }
                }
            }
        }
    }

    // Fallback: assume Python 3.11
    debug!("could not detect Python version from pyvenv.cfg, defaulting to 3.11");
    Ok(PythonVersion::new(3, 11))
}

/// Parse a `.dist-info` directory name like `requests-2.31.0.dist-info`.
fn parse_dist_info_name(name: &str) -> Option<InstalledDistInfo> {
    let without_suffix = name.strip_suffix(".dist-info")?;
    let (pkg_name, version) = without_suffix.rsplit_once('-')?;
    Some(InstalledDistInfo {
        name: pkg_name.to_string(),
        version: version.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dist_info() {
        let info = parse_dist_info_name("requests-2.31.0.dist-info").unwrap();
        assert_eq!(info.name, "requests");
        assert_eq!(info.version, "2.31.0");
    }

    #[test]
    fn parse_dist_info_with_hyphens() {
        let info = parse_dist_info_name("my_package-1.0.0.dist-info").unwrap();
        assert_eq!(info.name, "my_package");
        assert_eq!(info.version, "1.0.0");
    }

    #[test]
    fn site_packages_path_structure() {
        let manager = VenvManager {
            venv_dir: PathBuf::from("/tmp/test-venv"),
            python_version: PythonVersion::new(3, 11),
        };
        let sp = manager.site_packages();
        let sp_str = sp.to_string_lossy();
        assert!(sp_str.contains("site-packages"));
    }
}
