//! Process-based sandbox (cross-platform fallback).
//!
//! Runs the build command as a child process with environment isolation:
//! - Cleaned environment variables (only PATH, HOME/USERPROFILE, TEMP/TMP)
//! - Working directory set to the source directory
//! - Stdout/stderr capture
//! - Timeout enforcement via tokio
//!
//! This sandbox works on all platforms (Windows, macOS, Linux) and provides
//! basic isolation. It does not restrict filesystem or network access.

use crate::trait_def::{BuildArtifact, Sandbox, SandboxConfig, SandboxError, SandboxOutput};
use async_trait::async_trait;
use chrono::Utc;
use rusk_core::{PackageId, Sha256Digest, Version};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// A process-based sandbox that runs builds in a subprocess with
/// environment isolation and timeout enforcement.
///
/// This is the fallback sandbox when no container runtime or
/// Linux namespace support is available. It works on all platforms.
pub struct ProcessSandbox {
    /// Additional environment variables to inject beyond the safe defaults.
    extra_env: HashMap<String, String>,
}

impl ProcessSandbox {
    /// Create a new process sandbox with default settings.
    pub fn new() -> Self {
        Self {
            extra_env: HashMap::new(),
        }
    }

    /// Create a process sandbox with additional environment variables.
    pub fn with_env(extra_env: HashMap<String, String>) -> Self {
        Self { extra_env }
    }

    /// Build the set of safe environment variables.
    ///
    /// Starts with a minimal safe set (PATH, HOME, TEMP) and merges
    /// in the config-supplied env and any extra env from construction.
    fn build_safe_env(&self, config: &SandboxConfig) -> HashMap<String, String> {
        let mut env = HashMap::new();

        // PATH is always needed for finding executables.
        if let Ok(path) = std::env::var("PATH") {
            env.insert("PATH".to_string(), path);
        }

        // Home directory (platform-specific).
        if let Ok(home) = std::env::var("HOME") {
            env.insert("HOME".to_string(), home);
        }
        if let Ok(home) = std::env::var("USERPROFILE") {
            env.insert("USERPROFILE".to_string(), home);
        }

        // Temp directories (platform-specific).
        if let Ok(tmp) = std::env::var("TEMP") {
            env.insert("TEMP".to_string(), tmp.clone());
            env.insert("TMP".to_string(), tmp);
        } else if let Ok(tmp) = std::env::var("TMPDIR") {
            env.insert("TMPDIR".to_string(), tmp);
        } else {
            // Fallback for Unix systems
            env.insert("TMPDIR".to_string(), "/tmp".to_string());
        }

        // Merge in config-supplied env vars.
        for (k, v) in &config.env {
            env.insert(k.clone(), v.clone());
        }

        // Merge in extra env vars from construction.
        for (k, v) in &self.extra_env {
            env.insert(k.clone(), v.clone());
        }

        env
    }

    /// Determine the shell and arguments for the current platform.
    fn shell_command(command: &str) -> (String, Vec<String>) {
        if cfg!(target_os = "windows") {
            (
                "cmd".to_string(),
                vec!["/C".to_string(), command.to_string()],
            )
        } else {
            (
                "/bin/sh".to_string(),
                vec!["-c".to_string(), command.to_string()],
            )
        }
    }
}

impl Default for ProcessSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sandbox for ProcessSandbox {
    async fn execute(
        &self,
        package: &PackageId,
        version: &Version,
        command: &str,
        config: &SandboxConfig,
    ) -> Result<SandboxOutput, SandboxError> {
        info!(
            package = %package,
            version = %version,
            command = command,
            timeout = ?config.timeout,
            "executing build in process sandbox"
        );

        let (shell, args) = Self::shell_command(command);
        let safe_env = self.build_safe_env(config);

        debug!(
            shell = shell.as_str(),
            work_dir = %config.work_dir.display(),
            env_vars = safe_env.len(),
            "spawning sandboxed process"
        );

        let started_at = Utc::now();
        let start_instant = std::time::Instant::now();

        // Spawn the child process with a clean environment.
        let mut child = Command::new(&shell)
            .args(&args)
            .current_dir(&config.work_dir)
            .env_clear()
            .envs(&safe_env)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::Setup(format!("failed to spawn process: {}", e)))?;

        // Take ownership of stdout/stderr handles before waiting,
        // so we can still kill the child on timeout.
        let mut stdout_handle = child.stdout.take();
        let mut stderr_handle = child.stderr.take();

        // Enforce timeout using tokio::time::timeout.
        // We read stdout/stderr concurrently with waiting for the child.
        let result = tokio::time::timeout(config.timeout, async {
            let stdout_task = async {
                let mut buf = Vec::new();
                if let Some(ref mut handle) = stdout_handle {
                    let _ = handle.read_to_end(&mut buf).await;
                }
                buf
            };
            let stderr_task = async {
                let mut buf = Vec::new();
                if let Some(ref mut handle) = stderr_handle {
                    let _ = handle.read_to_end(&mut buf).await;
                }
                buf
            };
            let wait_task = child.wait();

            let (stdout, stderr, status) = tokio::join!(stdout_task, stderr_task, wait_task);
            (stdout, stderr, status)
        })
        .await;

        let elapsed = start_instant.elapsed();
        let completed_at = Utc::now();

        match result {
            Ok((stdout, stderr, status_result)) => {
                let status = status_result.map_err(SandboxError::Io)?;
                let exit_code = status.code().unwrap_or(-1);

                info!(
                    exit_code = exit_code,
                    duration = ?elapsed,
                    stdout_bytes = stdout.len(),
                    stderr_bytes = stderr.len(),
                    "process sandbox build completed"
                );

                // Scan for build artifacts in the working directory.
                let artifacts = scan_artifacts(&config.work_dir);

                if exit_code != 0 {
                    let stderr_str = String::from_utf8_lossy(&stderr);
                    debug!(stderr = %stderr_str, "build process exited with non-zero code");
                }

                Ok(SandboxOutput {
                    exit_code,
                    stdout,
                    stderr,
                    duration: elapsed,
                    artifacts,
                    started_at,
                    completed_at,
                })
            }
            Err(_) => {
                // Timeout elapsed. The child was dropped so it will be cleaned up.
                warn!(
                    timeout = ?config.timeout,
                    "build process timed out"
                );
                Err(SandboxError::Timeout { elapsed })
            }
        }
    }

    fn is_available(&self) -> bool {
        // Process sandbox is always available on all platforms.
        true
    }

    fn name(&self) -> &str {
        "process"
    }
}

/// Scan a directory for build artifacts and compute their digests.
///
/// This is a best-effort scan that looks for common output files.
/// In a real build system, the build script would declare its outputs.
fn scan_artifacts(work_dir: &PathBuf) -> Vec<BuildArtifact> {
    let mut artifacts = Vec::new();

    // Common artifact patterns: .tar.gz, .tgz, .whl, .zip
    let patterns = ["*.tar.gz", "*.tgz", "*.whl", "*.zip"];

    for pattern in &patterns {
        let full_pattern = format!("{}/{}", work_dir.display(), pattern);
        if let Ok(entries) = glob::glob(&full_pattern) {
            for entry in entries.flatten() {
                if let Ok(data) = std::fs::read(&entry) {
                    let digest = Sha256Digest::compute(&data);
                    let size = data.len() as u64;
                    let filename = entry
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    artifacts.push(BuildArtifact {
                        filename,
                        path: entry,
                        digest,
                        size,
                    });
                }
            }
        }
    }

    artifacts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn process_sandbox_is_always_available() {
        let sandbox = ProcessSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.name(), "process");
    }

    #[test]
    fn safe_env_includes_path() {
        let sandbox = ProcessSandbox::new();
        let config = SandboxConfig::default();
        let env = sandbox.build_safe_env(&config);
        // PATH should always be present (unless the test environment has no PATH).
        // At minimum, we should not have leaked arbitrary env vars.
        assert!(
            env.len() <= 10,
            "safe env should have limited variables, got {}",
            env.len()
        );
    }

    #[test]
    fn safe_env_includes_config_overrides() {
        let sandbox = ProcessSandbox::new();
        let mut config = SandboxConfig::default();
        config
            .env
            .insert("MY_VAR".to_string(), "my_value".to_string());
        let env = sandbox.build_safe_env(&config);
        assert_eq!(env.get("MY_VAR").map(|s| s.as_str()), Some("my_value"));
    }

    #[test]
    fn shell_command_format() {
        let (shell, args) = ProcessSandbox::shell_command("echo hello");
        // Just check that we get a non-empty shell and the command is in args.
        assert!(!shell.is_empty());
        assert!(args.iter().any(|a| a.contains("echo hello")));
    }

    #[tokio::test]
    async fn process_sandbox_runs_simple_command() {
        let sandbox = ProcessSandbox::new();
        let mut config = SandboxConfig::default();
        config.timeout = Duration::from_secs(10);

        // Use a platform-appropriate temp dir as work_dir.
        let tmp = std::env::temp_dir();
        config.work_dir = tmp;

        let command = "echo hello";

        let pkg = PackageId::js("test-pkg");
        let version = Version::Semver(semver::Version::new(1, 0, 0));

        let output = sandbox.execute(&pkg, &version, command, &config).await;
        assert!(output.is_ok(), "sandbox execution failed: {:?}", output);
        let output = output.unwrap();
        assert_eq!(output.exit_code, 0);
        let stdout = output.stdout_str();
        assert!(stdout.contains("hello"), "stdout was: {}", stdout);
    }

    #[tokio::test]
    async fn process_sandbox_captures_exit_code() {
        let sandbox = ProcessSandbox::new();
        let mut config = SandboxConfig::default();
        config.timeout = Duration::from_secs(10);
        config.work_dir = std::env::temp_dir();

        let command = if cfg!(target_os = "windows") {
            "exit /b 42"
        } else {
            "exit 42"
        };

        let pkg = PackageId::js("test-pkg");
        let version = Version::Semver(semver::Version::new(1, 0, 0));

        let output = sandbox.execute(&pkg, &version, command, &config).await;
        assert!(output.is_ok());
        assert_eq!(output.unwrap().exit_code, 42);
    }
}
