//! `rusk list` command.
//!
//! Lists installed packages with versions.
//! Reads from rusk.lock (preferred) or scans node_modules/site-packages.

use clap::Args;
use miette::Result;
use rusk_orchestrator::config::OrchestratorConfig;

/// Arguments for the list command.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Output format: text or json.
    #[arg(long, value_name = "FORMAT")]
    pub output: Option<ListFormat>,

    /// Show outdated packages (future: checks registry for newer versions).
    #[arg(long = "output")]
    pub outdated: bool,
}

/// Output format specifically for the list command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListFormat {
    Text,
    Json,
}

impl std::str::FromStr for ListFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(ListFormat::Text),
            "json" => Ok(ListFormat::Json),
            other => Err(format!("unknown format: {other}")),
        }
    }
}

/// A package entry for display.
struct PackageEntry {
    name: String,
    version: String,
    ecosystem: String,
}

pub async fn run(args: ListArgs, global_format: crate::output::OutputFormat) -> Result<()> {
    let project_dir = std::env::current_dir()
        .map_err(|e| miette::miette!("failed to get current directory: {}", e))?;

    let config = OrchestratorConfig::for_project(project_dir);
    let lockfile_path = config.lockfile_path();

    let mut packages: Vec<PackageEntry> = Vec::new();

    if lockfile_path.exists() {
        // Preferred: read from rusk.lock
        let lockfile = rusk_lockfile::load_lockfile(&lockfile_path)
            .map_err(|e| miette::miette!("failed to read lockfile: {}", e))?;

        for (_key, locked_pkg) in &lockfile.packages {
            packages.push(PackageEntry {
                name: locked_pkg.package.display_name(),
                version: locked_pkg.version.to_string(),
                ecosystem: locked_pkg.ecosystem.to_string(),
            });
        }
    } else {
        // Fallback: scan node_modules/ and site-packages/
        let node_modules = config.node_modules_path();
        if node_modules.exists() {
            if let Ok(entries) = std::fs::read_dir(&node_modules) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') {
                        continue;
                    }
                    // Try to read version from package.json
                    let pkg_json = entry.path().join("package.json");
                    let version = if pkg_json.exists() {
                        std::fs::read_to_string(&pkg_json)
                            .ok()
                            .and_then(|content| {
                                serde_json::from_str::<serde_json::Value>(&content).ok()
                            })
                            .and_then(|v| v["version"].as_str().map(String::from))
                            .unwrap_or_else(|| "unknown".to_string())
                    } else {
                        "unknown".to_string()
                    };
                    packages.push(PackageEntry {
                        name,
                        version,
                        ecosystem: "js".to_string(),
                    });
                }
            }
        }

        let site_packages = config.site_packages_path();
        if site_packages.exists() {
            if let Ok(entries) = std::fs::read_dir(&site_packages) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".dist-info") {
                        // Parse name-version.dist-info
                        let without_suffix = name.strip_suffix(".dist-info").unwrap_or(&name);
                        if let Some((pkg_name, version)) = without_suffix.rsplit_once('-') {
                            packages.push(PackageEntry {
                                name: pkg_name.to_string(),
                                version: version.to_string(),
                                ecosystem: "python".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Sort by ecosystem then name for consistent output
    packages.sort_by(|a, b| a.ecosystem.cmp(&b.ecosystem).then(a.name.cmp(&b.name)));

    if args.outdated {
        crate::output::print_warning(
            &"--outdated is not yet implemented; showing all packages"
                .replace("warning: ", ""),
        );
    }

    // Determine output format: command-specific --format takes priority,
    // then fall back to the global --format flag.
    let use_json = match args.output {
        Some(ListFormat::Json) => true,
        Some(ListFormat::Text) => false,
        None => global_format == crate::output::OutputFormat::Json,
    };

    if use_json {
        let entries: Vec<serde_json::Value> = packages
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "version": p.version,
                    "ecosystem": p.ecosystem,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).unwrap_or_default()
        );
    } else if packages.is_empty() {
        crate::output::print_info("No packages installed.");
    } else {
        // Print table header
        println!("{:<24} {:<12} {}", "Package", "Version", "Ecosystem");
        println!("{}", "-".repeat(50));
        for pkg in &packages {
            println!("{:<24} {:<12} {}", pkg.name, pkg.version, pkg.ecosystem);
        }
        println!();
        crate::output::print_info(&format!("{} packages total", packages.len()));
    }

    Ok(())
}
