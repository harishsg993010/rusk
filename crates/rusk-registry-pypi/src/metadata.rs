//! PyPI-specific metadata types.
//!
//! Models the PyPI JSON API and Simple Repository API responses.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PyPI JSON API response for a package (`GET /pypi/<package>/json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PypiPackageIndex {
    /// Project-level info.
    pub info: PypiProjectInfo,
    /// All releases keyed by version string, each containing a list of files.
    #[serde(default)]
    pub releases: HashMap<String, Vec<PypiFile>>,
    /// URLs for the latest version (also present under releases).
    #[serde(default)]
    pub urls: Vec<PypiFile>,
}

/// Project-level info from PyPI JSON API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PypiProjectInfo {
    /// Canonical package name.
    pub name: String,
    /// Package version (latest).
    pub version: String,
    /// Short description.
    #[serde(default)]
    pub summary: Option<String>,
    /// Long description.
    #[serde(default)]
    pub description: Option<String>,
    /// Requires-dist (PEP 508 dependency specifiers).
    #[serde(default)]
    pub requires_dist: Option<Vec<String>>,
    /// Required Python version.
    #[serde(default)]
    pub requires_python: Option<String>,
    /// Author name.
    #[serde(default)]
    pub author: Option<String>,
    /// Author email.
    #[serde(default)]
    pub author_email: Option<String>,
    /// Project homepage.
    #[serde(default)]
    pub home_page: Option<String>,
    /// License string.
    #[serde(default)]
    pub license: Option<String>,
    /// Whether the project has been yanked.
    #[serde(default)]
    pub yanked: bool,
    /// Yank reason, if yanked.
    #[serde(default)]
    pub yanked_reason: Option<String>,
}

/// A single file/release entry from PyPI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PypiFile {
    /// Filename (e.g., "requests-2.31.0-py3-none-any.whl").
    pub filename: String,
    /// Download URL.
    pub url: String,
    /// Digest information.
    #[serde(default)]
    pub digests: PypiDigests,
    /// Package type: "bdist_wheel", "sdist", etc.
    #[serde(default)]
    pub packagetype: String,
    /// Required Python version for this file.
    #[serde(default)]
    pub requires_python: Option<String>,
    /// File size in bytes.
    #[serde(default)]
    pub size: Option<u64>,
    /// Upload time string.
    #[serde(default)]
    pub upload_time_iso_8601: Option<String>,
    /// Whether this specific file is yanked.
    #[serde(default)]
    pub yanked: bool,
    /// Yank reason for this file.
    #[serde(default)]
    pub yanked_reason: Option<String>,
}

/// Digest information from PyPI.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PypiDigests {
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub md5: Option<String>,
    #[serde(default)]
    pub blake2b_256: Option<String>,
}

impl PypiPackageIndex {
    /// Get all version strings in the releases map.
    pub fn version_strings(&self) -> Vec<&str> {
        self.releases.keys().map(|s| s.as_str()).collect()
    }

    /// Get files for a specific version.
    pub fn files_for_version(&self, version: &str) -> &[PypiFile] {
        self.releases.get(version).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get the best wheel for a given version (first wheel found).
    pub fn best_wheel(&self, version: &str) -> Option<&PypiFile> {
        self.files_for_version(version)
            .iter()
            .find(|f| f.packagetype == "bdist_wheel")
    }

    /// Get the sdist for a given version.
    pub fn sdist(&self, version: &str) -> Option<&PypiFile> {
        self.files_for_version(version)
            .iter()
            .find(|f| f.packagetype == "sdist")
    }
}

impl PypiFile {
    /// Whether this file is a wheel.
    pub fn is_wheel(&self) -> bool {
        self.packagetype == "bdist_wheel" || self.filename.ends_with(".whl")
    }

    /// Whether this file is a source distribution.
    pub fn is_sdist(&self) -> bool {
        self.packagetype == "sdist"
            || self.filename.ends_with(".tar.gz")
            || self.filename.ends_with(".zip")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_pypi_response() {
        let json = r#"{
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "summary": "Python HTTP for Humans.",
                "requires_dist": ["charset-normalizer (<4,>=2)", "idna (<4,>=2.5)"]
            },
            "releases": {
                "2.31.0": [
                    {
                        "filename": "requests-2.31.0-py3-none-any.whl",
                        "url": "https://files.pythonhosted.org/packages/.../requests-2.31.0-py3-none-any.whl",
                        "digests": { "sha256": "abc123" },
                        "packagetype": "bdist_wheel",
                        "requires_python": ">=3.7"
                    },
                    {
                        "filename": "requests-2.31.0.tar.gz",
                        "url": "https://files.pythonhosted.org/packages/.../requests-2.31.0.tar.gz",
                        "digests": { "sha256": "def456" },
                        "packagetype": "sdist"
                    }
                ]
            },
            "urls": []
        }"#;
        let index: PypiPackageIndex = serde_json::from_str(json).unwrap();
        assert_eq!(index.info.name, "requests");
        assert_eq!(index.releases.len(), 1);

        let files = index.files_for_version("2.31.0");
        assert_eq!(files.len(), 2);
        assert!(index.best_wheel("2.31.0").is_some());
        assert!(index.sdist("2.31.0").is_some());
    }

    #[test]
    fn file_type_detection() {
        let wheel = PypiFile {
            filename: "foo-1.0-py3-none-any.whl".to_string(),
            url: String::new(),
            digests: PypiDigests::default(),
            packagetype: "bdist_wheel".to_string(),
            requires_python: None,
            size: None,
            upload_time_iso_8601: None,
            yanked: false,
            yanked_reason: None,
        };
        assert!(wheel.is_wheel());
        assert!(!wheel.is_sdist());
    }
}
