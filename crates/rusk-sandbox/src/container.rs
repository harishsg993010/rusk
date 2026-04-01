//! OCI container-based sandbox.
//!
//! Uses an OCI-compatible container runtime (Docker, Podman) for
//! full isolation. Requires a container runtime to be installed.
//! The container sandbox mounts the source directory as a volume
//! and runs the build command inside the container.

use crate::trait_def::{Sandbox, SandboxConfig, SandboxError, SandboxOutput};
use async_trait::async_trait;
use chrono::Utc;
use rusk_core::{PackageId, Version};
use std::process::Command as StdCommand;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Which container runtime to use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerRuntime {
    /// Docker (docker CLI).
    Docker,
    /// Podman (podman CLI).
    Podman,
}

impl ContainerRuntime {
    /// Return the CLI command name.
    pub fn command(&self) -> &str {
        match self {
            ContainerRuntime::Docker => "docker",
            ContainerRuntime::Podman => "podman",
        }
    }
}

/// A container-based sandbox that runs builds inside Docker or Podman containers.
pub struct ContainerSandbox {
    /// Which container runtime to use.
    runtime: ContainerRuntime,
    /// Container image to use for builds.
    image: String,
}

impl ContainerSandbox {
    /// Create a new container sandbox with the given runtime and image.
    pub fn new(runtime: ContainerRuntime, image: String) -> Self {
        Self { runtime, image }
    }

    /// Auto-detect an available container runtime and create a sandbox.
    ///
    /// Prefers Docker, falls back to Podman. Returns `None` if neither is available.
    pub fn auto_detect(image: String) -> Option<Self> {
        if is_runtime_available("docker") {
            Some(Self::new(ContainerRuntime::Docker, image))
        } else if is_runtime_available("podman") {
            Some(Self::new(ContainerRuntime::Podman, image))
        } else {
            None
        }
    }

    /// Build the `docker run` / `podman run` argument list.
    fn build_run_args(&self, config: &SandboxConfig, command: &str) -> Vec<String> {
        let mut args = vec!["run".to_string(), "--rm".to_string()];

        // Mount the working directory as a volume at /build inside the container.
        let host_dir = config.work_dir.display().to_string();
        args.push("-v".to_string());
        args.push(format!("{}:/build", host_dir));

        // Set the working directory inside the container.
        args.push("-w".to_string());
        args.push("/build".to_string());

        // Network isolation: disable network if not allowed.
        if !config.capabilities.network {
            args.push("--network".to_string());
            args.push("none".to_string());
        }

        // Memory limit.
        if config.max_memory_bytes > 0 {
            args.push("--memory".to_string());
            args.push(format!("{}b", config.max_memory_bytes));
        }

        // Environment variables.
        for (key, value) in &config.env {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }

        // Read-only root filesystem for better isolation (if filesystem_read is not needed).
        if !config.capabilities.filesystem_read {
            args.push("--read-only".to_string());
            // Need a writable /tmp for most build tools.
            args.push("--tmpfs".to_string());
            args.push("/tmp".to_string());
        }

        // Image name.
        args.push(self.image.clone());

        // The build command, executed via shell.
        args.push("/bin/sh".to_string());
        args.push("-c".to_string());
        args.push(command.to_string());

        args
    }
}

#[async_trait]
impl Sandbox for ContainerSandbox {
    async fn execute(
        &self,
        package: &PackageId,
        version: &Version,
        command: &str,
        config: &SandboxConfig,
    ) -> Result<SandboxOutput, SandboxError> {
        if !self.is_available() {
            return Err(SandboxError::NotAvailable(format!(
                "{} runtime not found",
                self.runtime.command()
            )));
        }

        info!(
            package = %package,
            version = %version,
            runtime = self.runtime.command(),
            image = self.image.as_str(),
            command = command,
            "executing build in container sandbox"
        );

        let run_args = self.build_run_args(config, command);

        debug!(
            runtime = self.runtime.command(),
            args = ?run_args,
            "spawning container"
        );

        let started_at = Utc::now();
        let start_instant = std::time::Instant::now();

        // Spawn the container process.
        let mut child = Command::new(self.runtime.command())
            .args(&run_args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                SandboxError::Setup(format!(
                    "failed to spawn {} container: {}",
                    self.runtime.command(),
                    e
                ))
            })?;

        // Take ownership of stdout/stderr before waiting so we can
        // still drop (and thus kill) the child on timeout.
        let mut stdout_handle = child.stdout.take();
        let mut stderr_handle = child.stderr.take();

        // Enforce timeout.
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
                    "container sandbox build completed"
                );

                Ok(SandboxOutput {
                    exit_code,
                    stdout,
                    stderr,
                    duration: elapsed,
                    artifacts: Vec::new(), // Artifacts are in the mounted volume
                    started_at,
                    completed_at,
                })
            }
            Err(_) => {
                warn!(
                    timeout = ?config.timeout,
                    "container build timed out"
                );
                Err(SandboxError::Timeout { elapsed })
            }
        }
    }

    fn is_available(&self) -> bool {
        is_runtime_available(self.runtime.command())
    }

    fn name(&self) -> &str {
        match self.runtime {
            ContainerRuntime::Docker => "container:docker",
            ContainerRuntime::Podman => "container:podman",
        }
    }

    async fn prepare(&self, _config: &SandboxConfig) -> Result<(), SandboxError> {
        // Pull the image if not already present.
        info!(
            runtime = self.runtime.command(),
            image = self.image.as_str(),
            "pulling container image"
        );

        let output = Command::new(self.runtime.command())
            .args(["pull", &self.image])
            .output()
            .await
            .map_err(|e| SandboxError::Setup(format!("failed to pull image: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::Setup(format!(
                "failed to pull image {}: {}",
                self.image, stderr
            )));
        }

        Ok(())
    }
}

/// Check if a container runtime is available on the system by running `<runtime> version`.
fn is_runtime_available(runtime: &str) -> bool {
    StdCommand::new(runtime)
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::trait_def::SandboxCapabilities;

    #[test]
    fn container_runtime_command_names() {
        assert_eq!(ContainerRuntime::Docker.command(), "docker");
        assert_eq!(ContainerRuntime::Podman.command(), "podman");
    }

    #[test]
    fn sandbox_name_matches_runtime() {
        let docker_sandbox =
            ContainerSandbox::new(ContainerRuntime::Docker, "node:18".to_string());
        assert_eq!(docker_sandbox.name(), "container:docker");

        let podman_sandbox =
            ContainerSandbox::new(ContainerRuntime::Podman, "node:18".to_string());
        assert_eq!(podman_sandbox.name(), "container:podman");
    }

    #[test]
    fn build_run_args_basic() {
        let sandbox = ContainerSandbox::new(ContainerRuntime::Docker, "node:18".to_string());
        let config = SandboxConfig {
            timeout: Duration::from_secs(60),
            max_memory_bytes: 1024 * 1024 * 512,
            max_disk_bytes: 0,
            capabilities: SandboxCapabilities::default(),
            env: HashMap::new(),
            work_dir: PathBuf::from("/home/user/project"),
        };

        let args = sandbox.build_run_args(&config, "npm install");

        assert!(args.contains(&"run".to_string()));
        assert!(args.contains(&"--rm".to_string()));
        assert!(args.contains(&"--network".to_string())); // network is off by default
        assert!(args.contains(&"none".to_string()));
        assert!(args.contains(&"node:18".to_string()));
        assert!(args.contains(&"npm install".to_string()));
    }

    #[test]
    fn build_run_args_with_network() {
        let sandbox = ContainerSandbox::new(ContainerRuntime::Docker, "python:3.11".to_string());
        let config = SandboxConfig {
            timeout: Duration::from_secs(60),
            max_memory_bytes: 0,
            max_disk_bytes: 0,
            capabilities: SandboxCapabilities::permissive(),
            env: {
                let mut env = HashMap::new();
                env.insert("NODE_ENV".to_string(), "production".to_string());
                env
            },
            work_dir: PathBuf::from("/build"),
        };

        let args = sandbox.build_run_args(&config, "pip install .");

        // Network should NOT be restricted since capabilities.network = true
        assert!(!args
            .windows(2)
            .any(|w| w[0] == "--network" && w[1] == "none"));
        // Env var should be passed
        assert!(args.contains(&"NODE_ENV=production".to_string()));
    }
}
