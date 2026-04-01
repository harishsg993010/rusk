//! Local provenance generation.
//!
//! Records metadata about locally-executed builds to create provenance
//! attestations. These are weaker than CI/CD provenance (since the local
//! machine is not a trusted builder) but still useful for tracking and
//! auditing.

use chrono::{DateTime, Utc};
use rusk_core::{BuilderIdentity, PackageId, Sha256Digest, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Provenance record for a locally-built artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalProvenance {
    /// Package that was built.
    pub package: PackageId,
    /// Version that was built.
    pub version: Version,
    /// SHA-256 digest of the output artifact.
    pub artifact_digest: Sha256Digest,
    /// Builder identity (local machine).
    pub builder: BuilderIdentity,
    /// When the build started.
    pub build_started_at: DateTime<Utc>,
    /// When the build completed.
    pub build_completed_at: DateTime<Utc>,
    /// Source metadata (commit hash, repo URL, etc.).
    pub source: SourceInfo,
    /// Build environment metadata.
    pub environment: BuildEnvironment,
    /// Whether the build was reproducible (same inputs -> same output).
    pub reproducible: Option<bool>,
}

/// Source code metadata for provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceInfo {
    /// Git repository URL, if available.
    pub repo_url: Option<String>,
    /// Git commit hash, if available.
    pub commit: Option<String>,
    /// Git branch, if available.
    pub branch: Option<String>,
    /// Whether the working tree was clean (no uncommitted changes).
    pub clean: Option<bool>,
}

/// Build environment metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildEnvironment {
    /// Operating system.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Hostname (sanitized).
    pub hostname: Option<String>,
    /// Relevant tool versions (node, python, rust, etc.).
    pub tool_versions: HashMap<String, String>,
}

impl LocalProvenance {
    /// Create a new provenance record.
    pub fn new(
        package: PackageId,
        version: Version,
        artifact_digest: Sha256Digest,
    ) -> Self {
        Self {
            package,
            version,
            artifact_digest,
            builder: BuilderIdentity {
                builder_type: "local".to_string(),
                builder_id: "local-machine".to_string(),
            },
            build_started_at: Utc::now(),
            build_completed_at: Utc::now(),
            source: SourceInfo::detect(),
            environment: BuildEnvironment::detect(),
            reproducible: None,
        }
    }

    /// Set the build timestamps.
    pub fn with_timestamps(
        mut self,
        started: DateTime<Utc>,
        completed: DateTime<Utc>,
    ) -> Self {
        self.build_started_at = started;
        self.build_completed_at = completed;
        self
    }

    /// Mark whether the build was reproducible.
    pub fn with_reproducibility(mut self, reproducible: bool) -> Self {
        self.reproducible = Some(reproducible);
        self
    }

    /// Build duration.
    pub fn duration(&self) -> chrono::Duration {
        self.build_completed_at - self.build_started_at
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

impl SourceInfo {
    /// Attempt to detect source info from the current directory.
    pub fn detect() -> Self {
        let repo_url = std::process::Command::new("git")
            .args(["remote", "get-url", "origin"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        let commit = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        let branch = std::process::Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

        let clean = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| o.stdout.is_empty());

        Self {
            repo_url,
            commit,
            branch,
            clean,
        }
    }
}

impl BuildEnvironment {
    /// Detect the current build environment.
    pub fn detect() -> Self {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let hostname = hostname::get()
            .ok()
            .map(|h| h.to_string_lossy().to_string());

        let mut tool_versions = HashMap::new();

        // Detect Node.js version
        if let Ok(output) = std::process::Command::new("node").arg("--version").output() {
            if output.status.success() {
                tool_versions.insert(
                    "node".to_string(),
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                );
            }
        }

        // Detect Python version
        if let Ok(output) = std::process::Command::new("python3")
            .arg("--version")
            .output()
        {
            if output.status.success() {
                tool_versions.insert(
                    "python".to_string(),
                    String::from_utf8_lossy(&output.stdout).trim().to_string(),
                );
            }
        }

        Self {
            os,
            arch,
            hostname,
            tool_versions,
        }
    }
}

/// Simple hostname detection without external dependencies.
mod hostname {
    use std::ffi::OsString;
    use std::io;

    pub fn get() -> io::Result<OsString> {
        // Try HOSTNAME env var first (common on Linux), then COMPUTERNAME (Windows)
        if let Some(h) = std::env::var_os("HOSTNAME") {
            return Ok(h);
        }
        if let Some(h) = std::env::var_os("COMPUTERNAME") {
            return Ok(h);
        }
        // Fallback: run `hostname` command
        let output = std::process::Command::new("hostname").output()?;
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(OsString::from(name))
        } else {
            Ok(OsString::from("unknown"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_local_provenance() {
        let pkg = PackageId::js("my-package");
        let version = Version::Semver(semver::Version::new(1, 0, 0));
        let digest = Sha256Digest::compute(b"artifact-content");

        let prov = LocalProvenance::new(pkg, version, digest);
        assert_eq!(prov.builder.builder_type, "local");
        assert!(prov.duration() >= chrono::Duration::zero());
    }

    #[test]
    fn provenance_to_json() {
        let pkg = PackageId::js("test");
        let version = Version::Semver(semver::Version::new(0, 1, 0));
        let digest = Sha256Digest::zero();

        let prov = LocalProvenance::new(pkg, version, digest);
        let json = prov.to_json();
        assert!(json.contains("\"builder_type\""));
        assert!(json.contains("local"));
    }
}
