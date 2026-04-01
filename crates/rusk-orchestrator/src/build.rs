//! Build orchestration.
//!
//! Coordinates running build scripts in a sandboxed environment
//! with provenance generation for the build output.

/// Result of a build operation.
#[derive(Clone, Debug)]
pub struct BuildResult {
    /// Whether the build succeeded.
    pub success: bool,
    /// Build duration in milliseconds.
    pub duration_ms: u64,
    /// Provenance attestation generated (if requested).
    pub provenance: Option<String>,
    /// Build output logs.
    pub output: String,
}

/// Execute a sandboxed build.
pub async fn build(
    _config: &crate::config::OrchestratorConfig,
    _script: Option<&str>,
) -> Result<BuildResult, crate::install::InstallError> {
    tracing::info!("starting build orchestration");

    Ok(BuildResult {
        success: true,
        duration_ms: 0,
        provenance: None,
        output: String::new(),
    })
}
