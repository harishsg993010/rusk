//! `rusk config` command.
//!
//! View and modify rusk configuration settings.

use clap::Args;
use miette::Result;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Arguments for the config command.
#[derive(Debug, Args)]
pub struct ConfigArgs {
    /// Configuration key to get or set.
    pub key: Option<String>,

    /// Value to set (if omitted, prints the current value).
    pub value: Option<String>,

    /// List all configuration values.
    #[arg(long)]
    pub list: bool,

    /// Reset configuration to defaults.
    #[arg(long)]
    pub reset: bool,
}

pub async fn run(args: ConfigArgs) -> Result<()> {
    let config = crate::cli_config::CliConfig::load();
    let config_path = default_config_path();

    if args.list {
        tracing::info!("listing all configuration");
        crate::output::print_info(&format!("Config file: {}", config_path.display()));
        println!();

        let values = config_values(&config);
        for (key, value) in &values {
            println!("  {key} = {value}");
        }

        return Ok(());
    }

    if args.reset {
        tracing::info!("resetting configuration to defaults");
        // Remove the config file if it exists
        if config_path.exists() {
            std::fs::remove_file(&config_path)
                .map_err(|e| miette::miette!("failed to remove config file: {}", e))?;
            crate::output::print_success("configuration reset to defaults");
        } else {
            crate::output::print_info("no config file to reset (using defaults)");
        }
        return Ok(());
    }

    match (&args.key, &args.value) {
        (Some(key), Some(value)) => {
            tracing::info!(key = %key, value = %value, "setting configuration");

            // Load existing config file or create new one
            let mut config_map = load_config_map(&config_path);
            config_map.insert(key.clone(), value.clone());
            save_config_map(&config_path, &config_map)?;

            crate::output::print_success(&format!("set {key} = {value}"));
        }
        (Some(key), None) => {
            tracing::info!(key = %key, "reading configuration");
            let values = config_values(&config);
            if let Some(value) = values.get(key.as_str()) {
                println!("{key} = {value}");
            } else {
                let config_map = load_config_map(&config_path);
                if let Some(value) = config_map.get(key) {
                    println!("{key} = {value}");
                } else {
                    crate::output::print_warning(&format!("unknown config key: {key}"));
                    crate::output::print_info("Available keys:");
                    for k in config_values(&config).keys() {
                        crate::output::print_info(&format!("  {k}"));
                    }
                }
            }
        }
        (None, _) => {
            crate::output::print_warning("specify a key or use --list");
        }
    }

    Ok(())
}

fn config_values(config: &crate::cli_config::CliConfig) -> BTreeMap<&'static str, String> {
    let mut values = BTreeMap::new();
    values.insert(
        "cache_dir",
        config
            .cache_dir
            .as_ref()
            .map_or_else(|| "(default)".to_string(), |p| p.display().to_string()),
    );
    values.insert(
        "max_concurrent_downloads",
        config
            .max_concurrent_downloads
            .map_or("(default: 16)".to_string(), |n| n.to_string()),
    );
    values.insert(
        "default_registry",
        config
            .default_registry
            .as_deref()
            .unwrap_or("https://registry.npmjs.org")
            .to_string(),
    );
    values.insert("color", config.color.to_string());
    values.insert("progress", config.progress.to_string());
    values
}

fn default_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| {
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string())
        });
        PathBuf::from(base).join("rusk").join("config.toml")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let base = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(base)
            .join(".config")
            .join("rusk")
            .join("config.toml")
    }
}

fn load_config_map(path: &PathBuf) -> BTreeMap<String, String> {
    if !path.exists() {
        return BTreeMap::new();
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return BTreeMap::new(),
    };
    match toml::from_str::<BTreeMap<String, String>>(&content) {
        Ok(map) => map,
        Err(_) => BTreeMap::new(),
    }
}

fn save_config_map(path: &PathBuf, map: &BTreeMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("failed to create config directory: {}", e))?;
    }
    let content = toml::to_string_pretty(map)
        .map_err(|e| miette::miette!("failed to serialize config: {}", e))?;
    std::fs::write(path, content)
        .map_err(|e| miette::miette!("failed to write config file: {}", e))?;
    Ok(())
}
