//! CLI-specific configuration loading.
//!
//! Loads configuration from ~/.config/rusk/config.toml and merges it
//! with command-line arguments and environment variables.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Raw TOML config structure that we parse from the file.
#[derive(Clone, Debug, Default, Deserialize)]
struct RawConfig {
    /// Path to the CAS cache directory.
    cache_dir: Option<String>,
    /// Maximum concurrent downloads.
    max_concurrent_downloads: Option<usize>,
    /// Default registry URL.
    default_registry: Option<String>,
    /// Whether to enable color output.
    color: Option<bool>,
    /// Whether to show progress bars.
    progress: Option<bool>,
}

/// CLI configuration options.
#[derive(Clone, Debug, Default)]
pub struct CliConfig {
    /// Path to the CAS cache directory.
    pub cache_dir: Option<PathBuf>,
    /// Maximum concurrent downloads.
    pub max_concurrent_downloads: Option<usize>,
    /// Default registry URL.
    pub default_registry: Option<String>,
    /// Whether to enable color output (auto-detected from terminal).
    pub color: bool,
    /// Whether to show progress bars.
    pub progress: bool,
}

impl CliConfig {
    /// Load configuration from the default config file location.
    pub fn load() -> Self {
        let config_path = default_config_path();
        let mut config = if config_path.exists() {
            Self::load_from(&config_path).unwrap_or_default()
        } else {
            Self {
                color: console::colors_enabled(),
                progress: console::user_attended(),
                ..Default::default()
            }
        };

        // Environment variable overrides
        if let Ok(val) = std::env::var("RUSK_CACHE_DIR") {
            config.cache_dir = Some(PathBuf::from(val));
        }
        if let Ok(val) = std::env::var("RUSK_MAX_CONCURRENT_DOWNLOADS") {
            if let Ok(n) = val.parse::<usize>() {
                config.max_concurrent_downloads = Some(n);
            }
        }
        if let Ok(val) = std::env::var("RUSK_DEFAULT_REGISTRY") {
            config.default_registry = Some(val);
        }
        if let Ok(val) = std::env::var("NO_COLOR") {
            if !val.is_empty() {
                config.color = false;
            }
        }

        config
    }

    /// Load configuration from a specific file.
    pub fn load_from(path: &Path) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let raw: RawConfig = toml::from_str(&content).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse config file: {}", e),
            )
        })?;

        Ok(Self {
            cache_dir: raw.cache_dir.map(PathBuf::from),
            max_concurrent_downloads: raw.max_concurrent_downloads,
            default_registry: raw.default_registry,
            color: raw.color.unwrap_or_else(console::colors_enabled),
            progress: raw.progress.unwrap_or_else(console::user_attended),
        })
    }

    /// Get the cache directory, falling back to the platform default.
    pub fn cache_dir(&self) -> PathBuf {
        self.cache_dir
            .clone()
            .unwrap_or_else(default_cache_dir)
    }
}

/// Default configuration file path: ~/.config/rusk/config.toml
fn default_config_path() -> PathBuf {
    dirs_path("config").join("config.toml")
}

/// Default cache directory: ~/.cache/rusk/
fn default_cache_dir() -> PathBuf {
    dirs_path("cache")
}

/// Platform-aware directory resolution.
fn dirs_path(#[allow(unused_variables)] kind: &str) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        match kind {
            "config" => PathBuf::from(base).join(".config").join("rusk"),
            "cache" => PathBuf::from(base).join(".cache").join("rusk"),
            _ => PathBuf::from(base).join(".rusk"),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let base = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        match kind {
            "config" => PathBuf::from(&base)
                .join("Library")
                .join("Application Support")
                .join("rusk"),
            "cache" => PathBuf::from(&base).join("Library").join("Caches").join("rusk"),
            _ => PathBuf::from(base).join(".rusk"),
        }
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| {
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string())
        });
        PathBuf::from(base).join("rusk")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let base = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(base).join(".rusk")
    }
}
