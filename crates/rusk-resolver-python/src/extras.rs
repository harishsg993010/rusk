//! Python extras handling.
//!
//! Manages PEP 508 extras (optional dependency groups) for Python packages.
//! When a package is installed with extras (e.g., `requests[security]`),
//! additional dependencies from that extra group are included.

use std::collections::HashMap;

/// An extras specification from a Python package.
#[derive(Clone, Debug)]
pub struct ExtrasSpec {
    /// Package name.
    pub package: String,
    /// Map from extra name to the additional dependencies it requires.
    pub extras: HashMap<String, Vec<ExtraDependency>>,
}

/// A dependency that is part of an extras group.
#[derive(Clone, Debug)]
pub struct ExtraDependency {
    /// Dependency package name.
    pub name: String,
    /// Version specifier.
    pub specifier: String,
    /// Additional environment markers.
    pub markers: Option<String>,
}

/// Parse extras from a PEP 508 requirement string.
///
/// E.g., "requests[security,socks]>=2.0" -> package="requests", extras=["security","socks"]
pub fn parse_extras_from_requirement(req: &str) -> (String, Vec<String>) {
    if let Some(bracket_start) = req.find('[') {
        if let Some(bracket_end) = req[bracket_start..].find(']') {
            let name = req[..bracket_start].trim().to_string();
            let extras_str = &req[bracket_start + 1..bracket_start + bracket_end];
            let extras: Vec<String> = extras_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            return (name, extras);
        }
    }

    // No extras
    let name = req.split(['>', '<', '=', '!', ';', ' '])
        .next()
        .unwrap_or(req)
        .trim()
        .to_string();
    (name, Vec::new())
}

/// Resolve which extra dependencies should be included based on requested extras.
pub fn resolve_extras<'a>(
    spec: &'a ExtrasSpec,
    requested_extras: &[String],
) -> Vec<&'a ExtraDependency> {
    let mut deps = Vec::new();
    for extra_name in requested_extras {
        if let Some(extra_deps) = spec.extras.get(extra_name) {
            deps.extend(extra_deps.iter());
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_with_extras() {
        let (name, extras) = parse_extras_from_requirement("requests[security,socks]>=2.0");
        assert_eq!(name, "requests");
        assert_eq!(extras, vec!["security", "socks"]);
    }

    #[test]
    fn parse_without_extras() {
        let (name, extras) = parse_extras_from_requirement("requests>=2.0");
        assert_eq!(name, "requests");
        assert!(extras.is_empty());
    }
}
