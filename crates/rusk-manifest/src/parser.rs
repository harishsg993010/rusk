//! Manifest parsing.
//!
//! Reads and parses rusk.toml files from disk or strings.

use crate::schema::Manifest;
use std::path::Path;
use tracing::{debug, instrument};

/// Error type for manifest parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("manifest file not found: {0}")]
    NotFound(std::path::PathBuf),

    #[error("failed to read manifest: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Parse a manifest from a TOML string.
///
/// This is the core parsing function. It deserializes the TOML content
/// into a `Manifest` struct.
///
/// # Errors
///
/// Returns `ParseError::Toml` if the string is not valid TOML or does
/// not conform to the manifest schema.
pub fn parse_manifest(content: &str) -> Result<Manifest, ParseError> {
    let manifest: Manifest = toml::from_str(content)?;
    Ok(manifest)
}

/// Load and parse a manifest from a file path.
///
/// Reads the file at `path` and parses it as a rusk.toml manifest.
///
/// # Errors
///
/// - `ParseError::NotFound` if the file doesn't exist
/// - `ParseError::Io` on read failure
/// - `ParseError::Toml` on parse failure
#[instrument(fields(path = %path.display()))]
pub fn load_manifest(path: &Path) -> Result<Manifest, ParseError> {
    if !path.exists() {
        return Err(ParseError::NotFound(path.to_path_buf()));
    }
    debug!("loading manifest from {}", path.display());
    let content = std::fs::read_to_string(path)?;
    parse_manifest(&content)
}

/// Find and load a manifest by searching upward from a directory.
///
/// Looks for `rusk.toml` starting from `start_dir` and walking up
/// to parent directories until the root is reached.
pub fn find_manifest(start_dir: &Path) -> Result<(std::path::PathBuf, Manifest), ParseError> {
    let mut current = start_dir.to_path_buf();
    loop {
        let candidate = current.join("rusk.toml");
        if candidate.exists() {
            let manifest = load_manifest(&candidate)?;
            return Ok((candidate, manifest));
        }
        if !current.pop() {
            break;
        }
    }
    Err(ParseError::NotFound(start_dir.join("rusk.toml")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::Ecosystem;

    #[test]
    fn parse_minimal_manifest() {
        let toml_str = r#"
[package]
name = "test-pkg"
ecosystem = "js"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        assert_eq!(manifest.package.name, "test-pkg");
        assert_eq!(manifest.package.ecosystem, Ecosystem::Js);
        assert!(manifest.js_dependencies.is_none());
    }

    #[test]
    fn parse_full_manifest() {
        let toml_str = r#"
[package]
name = "full-app"
version = "1.0.0"
ecosystem = "js"
description = "A full test app"
authors = ["Test Author <test@example.com>"]
license = "MIT"

[js_dependencies.dependencies]
express = "^4.18.0"

[js_dependencies.dev_dependencies]
jest = "^29.0.0"

[trust]
require_signatures = true
require_provenance = true

[build]
script = "build.sh"
sandbox = true
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        assert_eq!(manifest.package.name, "full-app");
        assert_eq!(manifest.package.version, Some("1.0.0".to_string()));

        let js = manifest.js_dependencies.unwrap();
        assert_eq!(js.dependencies.len(), 1);
        assert_eq!(js.dev_dependencies.len(), 1);

        let trust = manifest.trust.unwrap();
        assert!(trust.require_signatures);
        assert!(trust.require_provenance);

        let build = manifest.build.unwrap();
        assert_eq!(build.script, Some("build.sh".to_string()));
        assert!(build.sandbox);
    }

    #[test]
    fn parse_error_on_invalid_toml() {
        let result = parse_manifest("this is not valid toml {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn parse_error_on_missing_required_fields() {
        // Missing ecosystem
        let result = parse_manifest("[package]\nname = \"test\"");
        assert!(result.is_err());
    }

    #[test]
    fn load_nonexistent_file() {
        let result = load_manifest(Path::new("/nonexistent/rusk.toml"));
        assert!(matches!(result, Err(ParseError::NotFound(_))));
    }
}
