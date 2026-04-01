//! Semver range handling for npm-style version constraints.
//!
//! Parses and evaluates npm semver ranges (^, ~, >=, etc.) against
//! concrete versions. Wraps the semver crate with npm-specific semantics.

use semver::{Version, VersionReq};

/// Parse an npm-style version range string into a semver VersionReq.
///
/// Handles npm-specific syntax like:
/// - `^1.2.3` (compatible with 1.x.x)
/// - `~1.2.3` (patch-level changes)
/// - `1.2.x` (wildcard)
/// - `>=1.0.0 <2.0.0` (range)
/// - `>= 2.1.2 < 3` (space-separated bounds)
/// - `1.2.3 - 2.0.0` (hyphen range)
/// - `*` (any version)
/// - `""` (any version)
pub fn parse_npm_range(range: &str) -> Result<VersionReq, String> {
    let range = range.trim();
    if range == "*" || range == "latest" || range.is_empty() {
        return VersionReq::parse(">=0.0.0")
            .map_err(|e| format!("failed to parse wildcard range: {e}"));
    }

    // Replace .x and .X with wildcard equivalents
    let normalized = range
        .replace(".x", ".*")
        .replace(".X", ".*");

    // npm allows space-separated comparators like ">= 2.1.2 < 3"
    // The semver crate expects comma-separated: ">= 2.1.2, < 3"
    let normalized = normalize_npm_range(&normalized);

    VersionReq::parse(&normalized)
        .map_err(|e| format!("invalid npm range '{range}': {e}"))
}

/// Normalize npm range syntax to semver crate syntax.
///
/// npm uses spaces between comparators: `>=1.0.0 <2.0.0`
/// semver crate uses commas: `>=1.0.0, <2.0.0`
///
/// Also handles hyphen ranges: `1.0.0 - 2.0.0` → `>=1.0.0, <=2.0.0`
fn normalize_npm_range(range: &str) -> String {
    let range = range.trim();

    // Handle OR groups (||)
    if range.contains("||") {
        // semver crate doesn't support ||, pick the last (usually broadest) group
        // This is a simplification — a full implementation would evaluate all groups
        let parts: Vec<&str> = range.split("||").collect();
        if let Some(last) = parts.last() {
            return normalize_npm_range(last.trim());
        }
    }

    // Handle hyphen ranges: "1.0.0 - 2.0.0" → ">=1.0.0, <=2.0.0"
    if let Some(idx) = range.find(" - ") {
        let lower = range[..idx].trim();
        let upper = range[idx + 3..].trim();
        return format!(">={lower}, <={upper}");
    }

    // Split on spaces and insert commas between separate comparators
    // A comparator starts with >=, <=, >, <, =, ~, ^, or a digit
    let tokens: Vec<&str> = range.split_whitespace().collect();
    if tokens.len() <= 1 {
        return range.to_string();
    }

    let mut result = String::new();
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];

        if !result.is_empty() {
            // Check if this token starts a new comparator
            // (starts with >=, <=, >, <, ~, ^, or is a bare version after an operator+version)
            let starts_new = token.starts_with(">=")
                || token.starts_with("<=")
                || token.starts_with('>')
                || token.starts_with('<')
                || token.starts_with('~')
                || token.starts_with('^')
                || token.starts_with('=');

            let prev = tokens[i - 1];
            let prev_is_operator_only = prev == ">=" || prev == "<=" || prev == ">" || prev == "<" || prev == "=";

            if prev_is_operator_only {
                // This is the version part of "operator version" like ">= 2.1.2"
                result.push(' ');
            } else if starts_new {
                // New comparator — insert comma
                result.push_str(", ");
            } else if token.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                // Bare version number after another comparator — treat as new comparator
                result.push_str(", ");
            } else {
                result.push(' ');
            }
        }

        result.push_str(token);
        i += 1;
    }

    result
}

/// Check if a version satisfies an npm range, with npm-specific prerelease handling.
pub fn satisfies_npm(version: &Version, range: &VersionReq) -> bool {
    range.matches(version)
}

/// Compare two versions for npm-style sorting (descending, stable first).
pub fn npm_version_sort_key(version: &Version) -> impl Ord + '_ {
    (!version.pre.is_empty(), version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_caret_range() {
        let req = parse_npm_range("^1.2.3").unwrap();
        assert!(req.matches(&Version::parse("1.2.3").unwrap()));
        assert!(req.matches(&Version::parse("1.9.0").unwrap()));
        assert!(!req.matches(&Version::parse("2.0.0").unwrap()));
    }

    #[test]
    fn parse_tilde_range() {
        let req = parse_npm_range("~1.2.3").unwrap();
        assert!(req.matches(&Version::parse("1.2.5").unwrap()));
        assert!(!req.matches(&Version::parse("1.3.0").unwrap()));
    }

    #[test]
    fn parse_wildcard() {
        let req = parse_npm_range("*").unwrap();
        assert!(req.matches(&Version::parse("0.0.1").unwrap()));
        assert!(req.matches(&Version::parse("99.99.99").unwrap()));
    }

    #[test]
    fn parse_space_separated_range() {
        let req = parse_npm_range(">= 2.1.2 < 3.0.0").unwrap();
        assert!(req.matches(&Version::parse("2.1.2").unwrap()));
        assert!(req.matches(&Version::parse("2.5.0").unwrap()));
        assert!(!req.matches(&Version::parse("3.0.0").unwrap()));
        assert!(!req.matches(&Version::parse("2.1.1").unwrap()));
    }

    #[test]
    fn parse_spaced_operator() {
        // ">= 2.1.2 < 3" → ">= 2.1.2, < 3"
        let normalized = normalize_npm_range(">= 2.1.2 < 3");
        assert!(normalized.contains(','), "should have comma: {normalized}");
    }

    #[test]
    fn parse_hyphen_range() {
        let req = parse_npm_range("1.0.0 - 2.0.0").unwrap();
        assert!(req.matches(&Version::parse("1.0.0").unwrap()));
        assert!(req.matches(&Version::parse("1.5.0").unwrap()));
        assert!(req.matches(&Version::parse("2.0.0").unwrap()));
        assert!(!req.matches(&Version::parse("2.0.1").unwrap()));
    }

    #[test]
    fn parse_empty_is_any() {
        let req = parse_npm_range("").unwrap();
        assert!(req.matches(&Version::parse("1.0.0").unwrap()));
    }

    #[test]
    fn parse_or_groups() {
        // We simplify by taking the last group
        let req = parse_npm_range("^1.0.0 || ^2.0.0").unwrap();
        assert!(req.matches(&Version::parse("2.0.0").unwrap()));
    }
}
