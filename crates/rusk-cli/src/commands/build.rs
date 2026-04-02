//! `rusk build` command.
//!
//! Runs build scripts in an isolated sandbox environment with
//! provenance generation for the build output.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;
use rusk_sandbox::{ProcessSandbox, Sandbox, SandboxConfig, SandboxCapabilities};
use std::time::Duration;

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
    let manifest = if manifest_path.exists() {
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| miette::miette!("failed to read manifest: {}", e))?;
        Some(rusk_manifest::parse_manifest(&content)
            .map_err(|e| miette::miette!("failed to parse manifest: {}", e))?)
    } else {
        None
    };

    // Determine the build script
    let script = args.script.or_else(|| {
        manifest.as_ref()
            .and_then(|m| m.build.as_ref())
            .and_then(|b| b.script.clone())
    });

    let script = match script {
        Some(s) => s,
        None => {
            crate::output::print_warning(
                "No build script configured. Add [build] section to rusk.toml or use --script.",
            );
            return Ok(());
        }
    };

    let use_sandbox = !args.no_sandbox;

    if use_sandbox {
        // Run in ProcessSandbox with restricted environment
        crate::output::print_info(&format!("Running in sandbox: {script}"));

        let sandbox = ProcessSandbox::new();

        let sandbox_config = SandboxConfig {
            timeout: Duration::from_secs(300),
            capabilities: SandboxCapabilities {
                network: false,
                filesystem_read: false,
                exec: true,
                fork: true,
            },
            work_dir: project_dir.clone(),
            ..Default::default()
        };

        crate::output::print_info("Sandbox capabilities:");
        crate::output::print_info("  network: DENIED");
        crate::output::print_info("  host filesystem: DENIED");
        crate::output::print_info("  host secrets: DENIED (env scrubbed)");

        let spinner = crate::output::create_spinner("Building (sandboxed)...");

        let pkg_id = rusk_core::PackageId::js("build");
        let version = rusk_core::Version::Semver(semver::Version::new(0, 0, 0));

        let output = sandbox.execute(
            &pkg_id,
            &version,
            &script,
            &sandbox_config,
        ).await;

        spinner.finish_and_clear();

        match output {
            Ok(result) => {
                if !result.stdout.is_empty() {
                    println!("{}", String::from_utf8_lossy(&result.stdout));
                }
                if !result.stderr.is_empty() {
                    eprintln!("{}", String::from_utf8_lossy(&result.stderr));
                }

                if result.success() {
                    crate::output::print_success(&format!(
                        "build complete in {:.1}s (sandboxed)",
                        result.duration.as_secs_f64()
                    ));
                } else {
                    crate::output::print_error(&format!(
                        "build failed with exit code {}",
                        result.exit_code
                    ));
                    return Err(miette::miette!("build failed with exit code {}", result.exit_code));
                }
            }
            Err(e) => {
                crate::output::print_error(&format!("sandbox error: {e}"));
                return Err(miette::miette!("sandbox error: {e}"));
            }
        }
    } else {
        // Run without sandbox (--no-sandbox flag)
        crate::output::print_warning("Sandbox DISABLED by --no-sandbox flag");
        crate::output::print_warning("Build script has FULL access to host secrets, filesystem, and network");
        crate::output::print_info(&format!("Running: {script}"));

        let spinner = crate::output::create_spinner("Building (unsandboxed)...");

        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&script)
            .current_dir(&project_dir)
            .output()
            .await
            .map_err(|e| miette::miette!("failed to run build script: {}", e))?;

        spinner.finish_and_clear();

        if !output.stdout.is_empty() {
            println!("{}", String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        }

        if output.status.success() {
            crate::output::print_success("build complete (unsandboxed)");
        } else {
            let code = output.status.code().unwrap_or(-1);
            crate::output::print_error(&format!("build failed with exit code {code}"));
            return Err(miette::miette!("build failed with exit code {}", code));
        }
    }

    if args.provenance {
        let pkg_id = rusk_core::PackageId::js("build");
        let version = rusk_core::Version::Semver(semver::Version::new(0, 0, 0));
        let digest = rusk_core::Sha256Digest::zero();
        let prov = rusk_sandbox::LocalProvenance::new(pkg_id, version, digest);
        crate::output::print_info(&format!("Provenance: builder={}, type=local_dev", prov.builder.builder_type));
        if let Some(ref commit) = prov.source.commit {
            crate::output::print_info(&format!("Provenance: git_commit={commit}"));
        }
    }

    Ok(())
}
