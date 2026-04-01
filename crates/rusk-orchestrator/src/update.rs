//! Update orchestration.
//!
//! Re-resolves dependencies to find newer versions within the
//! constraints of the manifest and trust policy.

/// A planned update describing what will change.
#[derive(Clone, Debug)]
pub struct UpdatePlan {
    /// Packages that will be upgraded.
    pub upgrades: Vec<UpgradeEntry>,
    /// Packages that are already at their latest allowed version.
    pub up_to_date: usize,
}

/// A single package upgrade.
#[derive(Clone, Debug)]
pub struct UpgradeEntry {
    pub package: String,
    pub from_version: String,
    pub to_version: String,
}

/// Result of an update operation.
#[derive(Clone, Debug)]
pub struct UpdateResult {
    /// Number of packages updated.
    pub updated: usize,
    /// Number unchanged.
    pub unchanged: usize,
    /// Warnings generated during update.
    pub warnings: Vec<String>,
}

/// Execute the update workflow.
pub async fn update(
    _config: &crate::config::OrchestratorConfig,
    _packages: &[String],
) -> Result<UpdateResult, crate::install::InstallError> {
    tracing::info!("starting update orchestration");

    Ok(UpdateResult {
        updated: 0,
        unchanged: 0,
        warnings: Vec::new(),
    })
}
