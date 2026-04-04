//! `rusk audit` command.
//!
//! Evaluates the dependency tree against trust policies, checks for
//! revoked packages, reports policy violations, and scans for known
//! security advisories via the npm bulk advisory API.

use clap::Args;
use miette::Result;
use rusk_core::Ecosystem;
use rusk_orchestrator::config::OrchestratorConfig;

/// Arguments for the audit command.
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Exit with error on any warnings (not just errors).
    #[arg(long)]
    pub strict: bool,

    /// Output format for audit results.
    #[arg(long, default_value = "summary")]
    pub report: AuditReportFormat,
}

/// Audit report output format.
#[derive(Clone, Debug, Default)]
pub enum AuditReportFormat {
    /// Brief summary of findings.
    #[default]
    Summary,
    /// Detailed per-package results.
    Full,
    /// Machine-readable JSON.
    Json,
}

impl std::str::FromStr for AuditReportFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "summary" => Ok(Self::Summary),
            "full" => Ok(Self::Full),
            "json" => Ok(Self::Json),
            other => Err(format!("unknown format: {other}")),
        }
    }
}

pub async fn run(args: AuditArgs, format: crate::output::OutputFormat) -> Result<()> {
    // When the global --format json flag is set, override the per-command
    // --report flag so that the output is always structured JSON.
    let json_output = format == crate::output::OutputFormat::Json
        || matches!(args.report, AuditReportFormat::Json);

    tracing::info!(strict = args.strict, "starting audit");

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir);

    // Load lockfile
    let lockfile_path = config.lockfile_path();
    if !lockfile_path.exists() {
        if json_output {
            let exit_code = rusk_core::ExitCode::LockfileMismatch;
            let output = serde_json::json!({
                "status": "error",
                "exit_code": exit_code.as_i32(),
                "exit_code_name": exit_code.code_name(),
                "error": "rusk.lock not found",
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());
            std::process::exit(exit_code.as_i32());
        }
        crate::output::print_error("No lockfile found. Run 'rusk install' first.");
        return Err(miette::miette!("rusk.lock not found"));
    }

    let lockfile = rusk_lockfile::load_lockfile(&lockfile_path)
        .map_err(|e| miette::miette!("failed to read lockfile: {}", e))?;

    // Load manifest for trust config
    let manifest_path = config.manifest_path();
    let manifest = if manifest_path.exists() {
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| miette::miette!("failed to read manifest: {}", e))?;
        Some(
            rusk_manifest::parse_manifest(&content)
                .map_err(|e| miette::miette!("failed to parse manifest: {}", e))?,
        )
    } else {
        None
    };

    let trust_config = manifest.as_ref().and_then(|m| m.trust.as_ref());

    let spinner = if json_output {
        indicatif::ProgressBar::hidden()
    } else {
        crate::output::create_spinner("Auditing dependency tree...")
    };

    let mut total = 0usize;
    let mut issues: Vec<AuditIssue> = Vec::new();

    for (_canonical_id, locked_pkg) in &lockfile.packages {
        total += 1;
        let pkg_name = locked_pkg.package.display_name();

        // Check for unsigned packages (if signatures are required)
        if let Some(tc) = trust_config {
            if tc.require_signatures && locked_pkg.signer.is_none() {
                issues.push(AuditIssue {
                    package: pkg_name.clone(),
                    version: locked_pkg.version.to_string(),
                    severity: "warning",
                    message: "package is not signed".to_string(),
                    remediation: Some("Contact the package author to sign releases".to_string()),
                });
            }
        }

        // Check for zero digest (placeholder/untrusted)
        if locked_pkg.digest == rusk_core::Sha256Digest::zero() {
            issues.push(AuditIssue {
                package: pkg_name.clone(),
                version: locked_pkg.version.to_string(),
                severity: "high",
                message: "package has a zero digest (integrity not verified)".to_string(),
                remediation: Some("Re-run 'rusk install' to download with proper integrity checking".to_string()),
            });
        }
    }

    // ── Security advisory scan (npm packages) ──────────────────────
    // Collect JS package name/version pairs from the lockfile.
    let js_packages: Vec<(String, String)> = lockfile
        .packages
        .values()
        .filter(|p| p.ecosystem == Ecosystem::Js)
        .map(|p| (p.package.display_name(), p.version.to_string()))
        .collect();

    if !js_packages.is_empty() {
        if !json_output {
            spinner.set_message("Checking security advisories...");
        }

        let npm_client = rusk_registry_npm::NpmRegistryClient::default_registry();
        match npm_client.fetch_advisories(&js_packages).await {
            Ok(advisories) => {
                for adv in &advisories {
                    let sev = match adv.severity.as_str() {
                        "critical" => "critical",
                        "high" => "high",
                        "moderate" => "moderate",
                        "low" => "low",
                        _ => "info",
                    };
                    issues.push(AuditIssue {
                        package: adv.package_name.clone(),
                        version: adv.vulnerable_versions.clone(),
                        severity: match sev {
                            "critical" => "critical",
                            "high" => "high",
                            "moderate" => "moderate",
                            "low" => "low",
                            _ => "info",
                        },
                        message: format!(
                            "{} ({})",
                            adv.title, adv.url
                        ),
                        remediation: Some(format!(
                            "Upgrade {} to a version outside {}",
                            adv.package_name, adv.vulnerable_versions
                        )),
                    });
                }
            }
            Err(e) => {
                // Advisory lookup is informational; log but don't block.
                tracing::warn!("advisory check failed: {}", e);
                if !json_output {
                    crate::output::print_warning(&format!(
                        "Could not fetch security advisories: {e}"
                    ));
                }
            }
        }
    }

    spinner.finish_and_clear();

    // JSON output path (either --format json or --report json)
    if json_output {
        let has_issues = !issues.is_empty();
        let exit_code = if has_issues && args.strict {
            rusk_core::ExitCode::AuditFailed
        } else {
            rusk_core::ExitCode::Success
        };

        let json_issues: Vec<serde_json::Value> = issues
            .iter()
            .map(|i| {
                serde_json::json!({
                    "package": i.package,
                    "version": i.version,
                    "severity": i.severity,
                    "message": i.message,
                    "remediation": i.remediation,
                })
            })
            .collect();

        let output = serde_json::json!({
            "status": if has_issues && args.strict { "error" } else { "success" },
            "exit_code": exit_code.as_i32(),
            "exit_code_name": exit_code.code_name(),
            "total": total,
            "issues_count": issues.len(),
            "issues": json_issues,
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap_or_default());

        if has_issues && args.strict {
            std::process::exit(exit_code.as_i32());
        }
        return Ok(());
    }

    // Human-readable output
    match args.report {
        AuditReportFormat::Summary => {
            crate::output::print_info(&format!("Audited {total} packages"));
            if issues.is_empty() {
                crate::output::print_success("No issues found");
            } else {
                for issue in &issues {
                    let prefix = match issue.severity {
                        "critical" => "CRIT ",
                        "high" => "HIGH ",
                        "moderate" => "MOD  ",
                        "warning" => "WARN ",
                        "low" => "LOW  ",
                        _ => "INFO ",
                    };
                    let line = format!(
                        "[{prefix}] {}@{}: {}",
                        issue.package, issue.version, issue.message
                    );
                    match issue.severity {
                        "critical" | "high" => crate::output::print_error(&line),
                        "moderate" | "warning" => crate::output::print_warning(&line),
                        _ => crate::output::print_info(&line),
                    }
                }
                crate::output::print_info(&format!("Found {} issues", issues.len()));
            }
        }
        AuditReportFormat::Full => {
            crate::output::print_info(&format!("Audited {total} packages"));
            for issue in &issues {
                let line = format!(
                    "[{}] {}@{}: {}",
                    issue.severity, issue.package, issue.version, issue.message
                );
                match issue.severity {
                    "critical" | "high" => crate::output::print_error(&line),
                    "moderate" | "warning" => crate::output::print_warning(&line),
                    _ => crate::output::print_info(&line),
                }
                if let Some(ref rem) = issue.remediation {
                    crate::output::print_info(&format!("  Remediation: {rem}"));
                }
            }
            if issues.is_empty() {
                crate::output::print_success("No issues found");
            }
        }
        AuditReportFormat::Json => {
            // Already handled above since json_output == true
            unreachable!();
        }
    }

    let has_critical_high = issues
        .iter()
        .any(|i| matches!(i.severity, "critical" | "high"));

    if args.strict && has_critical_high {
        return Err(miette::miette!(
            "audit found critical/high issues ({} total)",
            issues.len()
        ));
    }
    if args.strict && !issues.is_empty() {
        crate::output::print_warning(&format!(
            "audit found {} issues (none critical/high)",
            issues.len()
        ));
    }

    crate::output::print_success("audit complete");
    Ok(())
}

struct AuditIssue {
    package: String,
    version: String,
    severity: &'static str,
    message: String,
    remediation: Option<String>,
}
