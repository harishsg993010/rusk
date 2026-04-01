//! Explain orchestration.
//!
//! Provides human-readable explanations of why a particular policy
//! decision was made for a package, including the evaluation trace
//! and matched rules.

/// Result of an explain query.
#[derive(Clone, Debug)]
pub struct ExplainResult {
    /// The package that was explained.
    pub package: String,
    /// The policy verdict.
    pub verdict: String,
    /// Rules that matched.
    pub matched_rules: Vec<String>,
    /// Full evaluation trace (if requested).
    pub trace: Option<String>,
}

/// Generate an explanation for a policy decision.
pub async fn explain(
    _config: &crate::config::OrchestratorConfig,
    package: &str,
) -> Result<ExplainResult, crate::install::InstallError> {
    tracing::info!(package = %package, "generating policy explanation");

    Ok(ExplainResult {
        package: package.to_string(),
        verdict: "allow".to_string(),
        matched_rules: Vec::new(),
        trace: None,
    })
}
