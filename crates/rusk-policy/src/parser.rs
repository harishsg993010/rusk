//! Policy file parser.
//!
//! Parses policy files from TOML or JSON format into the AST representation.
//! Supports the rusk policy DSL syntax.

use crate::ast::PolicyFile;
use std::path::Path;

/// Error during policy parsing.
#[derive(Debug, thiserror::Error)]
pub enum PolicyParseError {
    #[error("IO error reading policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid policy syntax: {0}")]
    Syntax(String),
}

/// Parse a policy file from a JSON string.
pub fn parse_policy_json(json: &str) -> Result<PolicyFile, PolicyParseError> {
    serde_json::from_str(json).map_err(PolicyParseError::Json)
}

/// Load and parse a policy file from disk.
pub fn load_policy_file(path: &Path) -> Result<PolicyFile, PolicyParseError> {
    let content = std::fs::read_to_string(path)?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("json");

    match ext {
        "json" => parse_policy_json(&content),
        other => Err(PolicyParseError::Syntax(format!(
            "unsupported policy file format: .{other}"
        ))),
    }
}
