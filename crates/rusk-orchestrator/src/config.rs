//! Orchestrator configuration.
//!
//! Centralizes all configuration that the orchestrator needs from the
//! various subsystems it coordinates.

use rusk_core::Ecosystem;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level orchestrator configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Project root directory.
    pub project_dir: PathBuf,
    /// Path to the CAS store.
    pub cas_dir: PathBuf,
    /// Target ecosystem(s).
    pub ecosystems: Vec<Ecosystem>,
    /// Whether to run in frozen/lockfile-only mode.
    #[serde(default)]
    pub frozen: bool,
    /// Whether to include dev dependencies.
    #[serde(default = "default_true")]
    pub include_dev: bool,
    /// Maximum number of concurrent downloads.
    #[serde(default = "default_concurrency")]
    pub download_concurrency: usize,
    /// Whether to allow prereleases.
    #[serde(default)]
    pub allow_prereleases: bool,
    /// Enterprise configuration file path, if any.
    pub enterprise_config: Option<PathBuf>,
    /// Path to the policy file, if any.
    pub policy_file: Option<PathBuf>,
    /// Output format (text or json).
    #[serde(default)]
    pub output_format: OutputFormat,
}

fn default_true() -> bool {
    true
}

fn default_concurrency() -> usize {
    16
}

/// Output format for orchestrator results.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl OrchestratorConfig {
    /// Create a configuration for a project directory with sensible defaults.
    pub fn for_project(project_dir: PathBuf) -> Self {
        let cas_dir = project_dir.join(".rusk").join("cas");
        Self {
            project_dir,
            cas_dir,
            ecosystems: Vec::new(),
            frozen: false,
            include_dev: true,
            download_concurrency: default_concurrency(),
            allow_prereleases: false,
            enterprise_config: None,
            policy_file: None,
            output_format: OutputFormat::Text,
        }
    }

    /// Path to the manifest file (rusk.toml).
    pub fn manifest_path(&self) -> PathBuf {
        self.project_dir.join("rusk.toml")
    }

    /// Path to the lockfile (rusk.lock).
    pub fn lockfile_path(&self) -> PathBuf {
        self.project_dir.join("rusk.lock")
    }

    /// Path to the install state file.
    pub fn state_path(&self) -> PathBuf {
        self.project_dir.join(".rusk").join("state.json")
    }

    /// Path to the node_modules directory.
    pub fn node_modules_path(&self) -> PathBuf {
        self.project_dir.join("node_modules")
    }

    /// Path to the extracted package cache.
    /// Stores pre-extracted tarballs keyed by digest for fast hardlink installs.
    pub fn extracted_cache_dir(&self) -> PathBuf {
        self.project_dir.join(".rusk").join("extracted")
    }

    /// Path to the Python site-packages directory.
    /// Uses a simplified path without python version subdirs.
    pub fn site_packages_path(&self) -> PathBuf {
        self.project_dir
            .join(".venv")
            .join("lib")
            .join("site-packages")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_paths() {
        let config = OrchestratorConfig::for_project(PathBuf::from("/tmp/my-project"));
        assert!(config.manifest_path().to_string_lossy().contains("rusk.toml"));
        assert!(config.lockfile_path().to_string_lossy().contains("rusk.lock"));
        assert!(config.state_path().to_string_lossy().contains("state.json"));
    }

    #[test]
    fn defaults_include_dev() {
        let config = OrchestratorConfig::for_project(PathBuf::from("/tmp/test"));
        assert!(config.include_dev);
        assert!(!config.frozen);
        assert_eq!(config.download_concurrency, 16);
    }
}
