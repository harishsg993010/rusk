//! Source distribution types and utilities.
//!
//! Handles identification and processing of Python source distributions
//! (sdists), which come as `.tar.gz` or `.zip` files.

use serde::{Deserialize, Serialize};

/// Type of source distribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SdistFormat {
    /// Gzipped tar archive (.tar.gz).
    TarGz,
    /// Zip archive (.zip).
    Zip,
    /// Legacy formats (.tar.bz2, .tar.xz).
    LegacyArchive,
}

/// Parsed source distribution filename info.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdistInfo {
    /// Package name (normalized).
    pub name: String,
    /// Version string.
    pub version: String,
    /// Archive format.
    pub format: SdistFormat,
}

/// Error parsing a source distribution filename.
#[derive(Debug, thiserror::Error)]
pub enum SdistParseError {
    #[error("unrecognized sdist filename format: {0}")]
    UnrecognizedFormat(String),
    #[error("could not extract name and version from: {0}")]
    ParseFailed(String),
}

impl SdistInfo {
    /// Parse a source distribution filename into its components.
    ///
    /// Expected formats:
    /// - `<name>-<version>.tar.gz`
    /// - `<name>-<version>.zip`
    /// - `<name>-<version>.tar.bz2`
    pub fn parse(filename: &str) -> Result<Self, SdistParseError> {
        let (basename, format) = if let Some(base) = filename.strip_suffix(".tar.gz") {
            (base, SdistFormat::TarGz)
        } else if let Some(base) = filename.strip_suffix(".zip") {
            (base, SdistFormat::Zip)
        } else if let Some(base) = filename.strip_suffix(".tar.bz2") {
            (base, SdistFormat::LegacyArchive)
        } else if let Some(base) = filename.strip_suffix(".tar.xz") {
            (base, SdistFormat::LegacyArchive)
        } else {
            return Err(SdistParseError::UnrecognizedFormat(filename.to_string()));
        };

        // Split on last '-' to separate name from version.
        let dash_pos = basename
            .rfind('-')
            .ok_or_else(|| SdistParseError::ParseFailed(filename.to_string()))?;

        let name = &basename[..dash_pos];
        let version = &basename[dash_pos + 1..];

        if name.is_empty() || version.is_empty() {
            return Err(SdistParseError::ParseFailed(filename.to_string()));
        }

        Ok(Self {
            name: normalize_name(name),
            version: version.to_string(),
            format,
        })
    }

    /// Check if this sdist requires a build step to install.
    ///
    /// Source distributions always require building, unlike wheels.
    pub fn requires_build(&self) -> bool {
        true
    }
}

/// Detect whether a filename is a source distribution.
pub fn is_sdist(filename: &str) -> bool {
    filename.ends_with(".tar.gz")
        || filename.ends_with(".zip")
        || filename.ends_with(".tar.bz2")
        || filename.ends_with(".tar.xz")
}

/// Detect whether a filename is a wheel.
pub fn is_wheel(filename: &str) -> bool {
    filename.ends_with(".whl")
}

/// Normalize a Python distribution name (PEP 503: lowercase, replace [-_.] with -).
fn normalize_name(name: &str) -> String {
    name.to_lowercase()
        .replace(['_', '.'], "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tar_gz() {
        let info = SdistInfo::parse("requests-2.31.0.tar.gz").unwrap();
        assert_eq!(info.name, "requests");
        assert_eq!(info.version, "2.31.0");
        assert_eq!(info.format, SdistFormat::TarGz);
    }

    #[test]
    fn parse_zip() {
        let info = SdistInfo::parse("Flask-2.3.3.zip").unwrap();
        assert_eq!(info.name, "flask");
        assert_eq!(info.version, "2.3.3");
        assert_eq!(info.format, SdistFormat::Zip);
    }

    #[test]
    fn parse_underscore_name() {
        let info = SdistInfo::parse("my_package-1.0.0.tar.gz").unwrap();
        assert_eq!(info.name, "my-package");
    }

    #[test]
    fn parse_legacy_format() {
        let info = SdistInfo::parse("old-pkg-0.1.tar.bz2").unwrap();
        assert_eq!(info.format, SdistFormat::LegacyArchive);
    }

    #[test]
    fn unrecognized_format() {
        assert!(SdistInfo::parse("file.exe").is_err());
    }

    #[test]
    fn detection() {
        assert!(is_sdist("foo-1.0.tar.gz"));
        assert!(is_sdist("foo-1.0.zip"));
        assert!(!is_sdist("foo-1.0-py3-none-any.whl"));
        assert!(is_wheel("foo-1.0-py3-none-any.whl"));
        assert!(!is_wheel("foo-1.0.tar.gz"));
    }

    #[test]
    fn sdist_requires_build() {
        let info = SdistInfo::parse("foo-1.0.tar.gz").unwrap();
        assert!(info.requires_build());
    }
}
