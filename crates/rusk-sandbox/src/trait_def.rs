//! Sandbox trait and associated types.
//!
//! Defines the interface that all sandbox implementations must satisfy.
//! The sandbox provides build isolation, resource limits, and capability
//! restrictions for running untrusted build scripts.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusk_core::{PackageId, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

/// Error type for sandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox setup failed: {0}")]
    Setup(String),
    #[error("build failed with exit code {code}: {message}")]
    BuildFailed { code: i32, message: String },
    #[error("build timed out after {elapsed:?}")]
    Timeout { elapsed: Duration },
    #[error("capability denied: {0}")]
    CapabilityDenied(String),
    #[error("sandbox not available: {0}")]
    NotAvailable(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for a sandbox invocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Maximum execution time.
    pub timeout: Duration,
    /// Maximum memory in bytes.
    pub max_memory_bytes: u64,
    /// Maximum disk space in bytes.
    pub max_disk_bytes: u64,
    /// Capabilities granted to the build.
    pub capabilities: SandboxCapabilities,
    /// Environment variables to pass to the build.
    pub env: HashMap<String, String>,
    /// Working directory inside the sandbox.
    pub work_dir: PathBuf,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            max_memory_bytes: 2 * 1024 * 1024 * 1024, // 2 GB
            max_disk_bytes: 10 * 1024 * 1024 * 1024,  // 10 GB
            capabilities: SandboxCapabilities::default(),
            env: HashMap::new(),
            work_dir: PathBuf::from("/build"),
        }
    }
}

/// Capabilities that can be granted to a sandboxed build.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    /// Allow network access during the build.
    pub network: bool,
    /// Allow reading from the filesystem outside the sandbox.
    pub filesystem_read: bool,
    /// Allow executing arbitrary binaries.
    pub exec: bool,
    /// Allow creating child processes.
    pub fork: bool,
}

impl Default for SandboxCapabilities {
    fn default() -> Self {
        Self {
            network: false,
            filesystem_read: false,
            exec: true,
            fork: true,
        }
    }
}

impl SandboxCapabilities {
    /// Fully restricted: no network, no filesystem, no exec.
    pub fn restricted() -> Self {
        Self {
            network: false,
            filesystem_read: false,
            exec: false,
            fork: false,
        }
    }

    /// Permissive: everything allowed (for trusted builds).
    pub fn permissive() -> Self {
        Self {
            network: true,
            filesystem_read: true,
            exec: true,
            fork: true,
        }
    }
}

/// Output from a sandbox build execution.
#[derive(Clone, Debug)]
pub struct SandboxOutput {
    /// Exit code of the build process.
    pub exit_code: i32,
    /// Standard output captured from the build.
    pub stdout: Vec<u8>,
    /// Standard error captured from the build.
    pub stderr: Vec<u8>,
    /// Duration of the build.
    pub duration: Duration,
    /// Artifacts produced by the build.
    pub artifacts: Vec<BuildArtifact>,
    /// When the build started.
    pub started_at: DateTime<Utc>,
    /// When the build completed.
    pub completed_at: DateTime<Utc>,
}

impl SandboxOutput {
    /// Whether the build succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    /// Get stdout as a string (lossy).
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    /// Get stderr as a string (lossy).
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

/// A build artifact produced by the sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildArtifact {
    /// Filename of the artifact.
    pub filename: String,
    /// Path to the artifact inside the sandbox.
    pub path: PathBuf,
    /// SHA-256 digest of the artifact contents.
    pub digest: Sha256Digest,
    /// Size in bytes.
    pub size: u64,
}

/// Trait for sandbox implementations.
///
/// Different implementations may use containers (Docker), process isolation
/// (seccomp/landlock on Linux), or simple process spawning.
#[async_trait]
pub trait Sandbox: Send + Sync {
    /// Execute a build command in the sandbox.
    async fn execute(
        &self,
        package: &PackageId,
        version: &Version,
        command: &str,
        config: &SandboxConfig,
    ) -> Result<SandboxOutput, SandboxError>;

    /// Check whether this sandbox implementation is available on the current system.
    fn is_available(&self) -> bool;

    /// Human-readable name of this sandbox implementation.
    fn name(&self) -> &str;

    /// Prepare the sandbox environment (download images, set up directories, etc.).
    async fn prepare(&self, config: &SandboxConfig) -> Result<(), SandboxError> {
        // Default: no preparation needed
        let _ = config;
        Ok(())
    }

    /// Clean up sandbox resources after a build.
    async fn cleanup(&self) -> Result<(), SandboxError> {
        // Default: no cleanup needed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_sane() {
        let config = SandboxConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(300));
        assert!(!config.capabilities.network);
        assert!(config.capabilities.exec);
    }

    #[test]
    fn restricted_capabilities() {
        let caps = SandboxCapabilities::restricted();
        assert!(!caps.network);
        assert!(!caps.filesystem_read);
        assert!(!caps.exec);
        assert!(!caps.fork);
    }

    #[test]
    fn permissive_capabilities() {
        let caps = SandboxCapabilities::permissive();
        assert!(caps.network);
        assert!(caps.filesystem_read);
        assert!(caps.exec);
        assert!(caps.fork);
    }
}
