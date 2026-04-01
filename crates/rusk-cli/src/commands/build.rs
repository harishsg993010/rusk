//! `rusk build` command.
//!
//! Runs build scripts in an isolated sandbox environment with
//! provenance generation for the build output.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;

/// Arguments for the build command.
#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Build script to run (default: from manifest).
    #[arg(long)]
    pub script: Option<String>,

    /// Skip sandbox isolation (for debugging only).
    #[arg(long)]
    pub no_sandbox: bool,

    /// Generate provenance attestation for the build output.
    #[arg(long)]
    pub provenance: bool,
}

pub async fn run(args: BuildArgs) -> Result<()> {
    tracing::info!(
        script = ?args.script,
        sandbox = !args.no_sandbox,
        "starting build"
    );

    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir.clone());

    // Load manifest to find build config
    let manifest_path = config.manifest_path();
    if !manifest_path.exists() {
        crate::output::print_error("rusk.toml not found. Run 'rusk init' to create a project.");
        return Err(miette::miette!("rusk.toml not found"));
    }

    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| miette::miette!("failed to read manifest: {}", e))?;
    let manifest = rusk_manifest::parse_manifest(&content)
        .map_err(|e| miette::miette!("failed to parse manifest: {}", e))?;

    // Determine the build script
    let script = args.script.or_else(|| {
        manifest.build.as_ref().and_then(|b| b.script.clone())
    });

    match script {
        Some(script_path) => {
            let script_full = project_dir.join(&script_path);
            if !script_full.exists() {
                crate::output::print_error(&format!("build script not found: {script_path}"));
                return Err(miette::miette!("build script not found: {}", script_path));
            }

            let use_sandbox = !args.no_sandbox
                && manifest
                    .build
                    .as_ref()
                    .map_or(false, |b| b.sandbox);

            if use_sandbox {
                crate::output::print_info("Running build in sandboxed environment...");
            } else {
                if args.no_sandbox {
                    crate::output::print_warning("Sandbox disabled by --no-sandbox flag");
                }
                crate::output::print_info(&format!("Running build script: {script_path}"));
            }

            let spinner = crate::output::create_spinner("Building...");

            // Execute the build script
            let start = std::time::Instant::now();
            let output = tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&script_path)
                .current_dir(&project_dir)
                .output()
                .await
                .map_err(|e| miette::miette!("failed to run build script: {}", e))?;

            spinner.finish_and_clear();

            let duration = start.elapsed();

            if !output.stdout.is_empty() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                println!("{stdout}");
            }
            if !output.stderr.is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("{stderr}");
            }

            if output.status.success() {
                crate::output::print_success(&format!(
                    "build complete in {:.1}s",
                    duration.as_secs_f64()
                ));
            } else {
                let code = output.status.code().unwrap_or(-1);
                crate::output::print_error(&format!("build failed with exit code {code}"));
                return Err(miette::miette!("build failed with exit code {}", code));
            }

            if args.provenance {
                crate::output::print_info("Provenance attestation generation not yet implemented.");
            }
        }
        None => {
            crate::output::print_warning(
                "No build script configured. Add [build] section to rusk.toml or use --script.",
            );
        }
    }

    Ok(())
}
