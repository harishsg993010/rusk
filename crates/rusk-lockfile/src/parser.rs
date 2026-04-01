//! Lockfile parsing.
//!
//! Reads and parses rusk.lock files from disk or strings.

use crate::schema::Lockfile;
use std::path::Path;
use tracing::{debug, instrument};

/// Error type for lockfile parsing.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("lockfile not found: {0}")]
    NotFound(std::path::PathBuf),

    #[error("failed to read lockfile: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("unsupported lockfile version: {version} (supported: {supported})")]
    UnsupportedVersion { version: u32, supported: u32 },
}

/// The current lockfile format version we support.
pub const CURRENT_VERSION: u32 = 1;

/// Parse a lockfile from a TOML string.
pub fn parse_lockfile(content: &str) -> Result<Lockfile, ParseError> {
    let lockfile: Lockfile = toml::from_str(content)?;

    if lockfile.version > CURRENT_VERSION {
        return Err(ParseError::UnsupportedVersion {
            version: lockfile.version,
            supported: CURRENT_VERSION,
        });
    }

    Ok(lockfile)
}

/// Load and parse a lockfile from a file path.
#[instrument(fields(path = %path.display()))]
pub fn load_lockfile(path: &Path) -> Result<Lockfile, ParseError> {
    if !path.exists() {
        return Err(ParseError::NotFound(path.to_path_buf()));
    }
    debug!("loading lockfile from {}", path.display());
    let content = std::fs::read_to_string(path)?;
    parse_lockfile(&content)
}

/// Find a lockfile by looking for `rusk.lock` in the given directory.
pub fn find_lockfile(dir: &Path) -> Option<std::path::PathBuf> {
    let candidate = dir.join("rusk.lock");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_lockfile() {
        let toml_str = r#"
version = 1
updated_at = "2024-01-01T00:00:00Z"

[packages]
"#;
        let lf = parse_lockfile(toml_str).unwrap();
        assert_eq!(lf.version, 1);
        assert_eq!(lf.package_count(), 0);
    }

    #[test]
    fn reject_future_version() {
        let toml_str = r#"
version = 99
updated_at = "2024-01-01T00:00:00Z"

[packages]
"#;
        let err = parse_lockfile(toml_str).unwrap_err();
        assert!(matches!(err, ParseError::UnsupportedVersion { .. }));
    }

    #[test]
    fn parse_invalid_toml() {
        assert!(parse_lockfile("{{not valid}}").is_err());
    }

    #[test]
    fn load_nonexistent() {
        let result = load_lockfile(Path::new("/nonexistent/rusk.lock"));
        assert!(matches!(result, Err(ParseError::NotFound(_))));
    }
}
