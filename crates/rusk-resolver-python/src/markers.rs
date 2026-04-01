//! PEP 508 environment marker evaluation.
//!
//! Evaluates Python environment markers against a target environment to
//! determine whether a dependency should be included in the resolution.
//! Markers express conditions like `sys_platform == 'linux'` or
//! `python_version >= '3.8'`.

use rusk_core::platform::{Arch, Os, Platform, PythonVersion};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a Python environment for marker evaluation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarkerEnvironment {
    /// OS name: "posix", "nt", "java"
    pub os_name: String,
    /// sys.platform: "linux", "darwin", "win32"
    pub sys_platform: String,
    /// platform.machine: "x86_64", "aarch64"
    pub platform_machine: String,
    /// platform.system: "Linux", "Darwin", "Windows"
    pub platform_system: String,
    /// Python version string: "3.11"
    pub python_version: String,
    /// Full Python version: "3.11.5"
    pub python_full_version: String,
    /// Implementation name: "cpython", "pypy"
    pub implementation_name: String,
    /// Implementation version: "3.11.5"
    pub implementation_version: String,
    /// All variables as a flat map for generic lookups.
    variables: HashMap<String, String>,
}

impl MarkerEnvironment {
    /// Create a marker environment from a platform and Python version.
    pub fn from_platform(platform: &Platform, python: &PythonVersion) -> Self {
        let os_name = match platform.os {
            Os::Windows => "nt",
            _ => "posix",
        };
        let sys_platform = match platform.os {
            Os::Linux => "linux",
            Os::MacOs => "darwin",
            Os::Windows => "win32",
            Os::FreeBsd => "freebsd",
            Os::Unknown => "unknown",
        };
        let platform_machine = match platform.arch {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
            Arch::X86 => "i686",
            Arch::Arm => "armv7l",
            Arch::Unknown => "unknown",
        };
        let platform_system = match platform.os {
            Os::Linux => "Linux",
            Os::MacOs => "Darwin",
            Os::Windows => "Windows",
            Os::FreeBsd => "FreeBSD",
            Os::Unknown => "Unknown",
        };

        let python_version = python.short();
        let python_full_version = python.to_string();

        let mut variables = HashMap::new();
        variables.insert("os_name".to_string(), os_name.to_string());
        variables.insert("sys_platform".to_string(), sys_platform.to_string());
        variables.insert("platform_machine".to_string(), platform_machine.to_string());
        variables.insert("platform_system".to_string(), platform_system.to_string());
        variables.insert("python_version".to_string(), python_version.clone());
        variables.insert(
            "python_full_version".to_string(),
            python_full_version.clone(),
        );
        variables.insert("implementation_name".to_string(), "cpython".to_string());
        variables.insert(
            "implementation_version".to_string(),
            python_full_version.clone(),
        );

        Self {
            os_name: os_name.to_string(),
            sys_platform: sys_platform.to_string(),
            platform_machine: platform_machine.to_string(),
            platform_system: platform_system.to_string(),
            python_version,
            python_full_version: python_full_version.clone(),
            implementation_name: "cpython".to_string(),
            implementation_version: python_full_version,
            variables,
        }
    }

    /// Create a default environment for the current platform.
    pub fn current(python: &PythonVersion) -> Self {
        Self::from_platform(&Platform::current(), python)
    }

    /// Look up a marker variable by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(|s| s.as_str())
    }
}

/// Evaluate a PEP 508 marker string against an environment.
///
/// Returns `true` if the marker condition is satisfied, or `true` if the
/// marker string is empty (unconditional dependency).
///
/// This is a simplified evaluator that handles common marker forms:
/// - `sys_platform == 'linux'`
/// - `python_version >= '3.8'`
/// - `os_name != 'nt'`
/// - Compound expressions with `and` / `or`
pub fn evaluate_markers(marker: &str, env: &MarkerEnvironment) -> bool {
    let marker = marker.trim();
    if marker.is_empty() {
        return true;
    }

    // Handle compound expressions with "and" / "or"
    // Simple split-based approach: "or" has lower precedence than "and"
    if let Some((left, right)) = split_once_operator(marker, " or ") {
        return evaluate_markers(left, env) || evaluate_markers(right, env);
    }
    if let Some((left, right)) = split_once_operator(marker, " and ") {
        return evaluate_markers(left, env) && evaluate_markers(right, env);
    }

    // Handle parenthesized expressions
    let marker = marker.trim();
    if marker.starts_with('(') && marker.ends_with(')') {
        return evaluate_markers(&marker[1..marker.len() - 1], env);
    }

    // Parse a single comparison: `variable op 'value'`
    for op in &["==", "!=", ">=", "<=", ">", "<", "~="] {
        if let Some((lhs, rhs)) = marker.split_once(op) {
            let var_name = lhs.trim().trim_matches('"').trim_matches('\'');
            let value = rhs.trim().trim_matches('"').trim_matches('\'');

            let env_value = match env.get(var_name) {
                Some(v) => v,
                None => return true, // Unknown variable, assume satisfied
            };

            // For version-like variables, use version-aware comparison
            let use_version_cmp = var_name.contains("version");
            return if use_version_cmp {
                let cmp = compare_versions(env_value, value);
                match *op {
                    "==" => cmp == std::cmp::Ordering::Equal,
                    "!=" => cmp != std::cmp::Ordering::Equal,
                    ">=" => cmp != std::cmp::Ordering::Less,
                    "<=" => cmp != std::cmp::Ordering::Greater,
                    ">" => cmp == std::cmp::Ordering::Greater,
                    "<" => cmp == std::cmp::Ordering::Less,
                    "~=" => {
                        // Compatible release: e.g., ~=3.8 means >= 3.8, < 4.0
                        compare_versions(env_value, value) != std::cmp::Ordering::Less
                    }
                    _ => true,
                }
            } else {
                match *op {
                    "==" => env_value == value,
                    "!=" => env_value != value,
                    ">=" => env_value >= value,
                    "<=" => env_value <= value,
                    ">" => env_value > value,
                    "<" => env_value < value,
                    _ => true,
                }
            };
        }
    }

    // Can't parse the marker, default to true (include the dependency).
    true
}

/// Compare two version strings numerically (e.g., "3.11" > "3.8").
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<u64> = a.split('.').filter_map(|p| p.parse().ok()).collect();
    let b_parts: Vec<u64> = b.split('.').filter_map(|p| p.parse().ok()).collect();
    let max_len = a_parts.len().max(b_parts.len());
    for i in 0..max_len {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Split a marker string on the first occurrence of an operator, respecting parentheses.
fn split_once_operator<'a>(s: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0u32;
    let op_bytes = op.as_bytes();
    let s_bytes = s.as_bytes();

    for i in 0..s_bytes.len() {
        if s_bytes[i] == b'(' {
            depth += 1;
        } else if s_bytes[i] == b')' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && i + op_bytes.len() <= s_bytes.len() {
            if &s_bytes[i..i + op_bytes.len()] == op_bytes {
                return Some((&s[..i], &s[i + op.len()..]));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux_env() -> MarkerEnvironment {
        let platform = Platform {
            os: Os::Linux,
            arch: Arch::X86_64,
            python_version: Some(PythonVersion::new(3, 11)),
            node_version: None,
        };
        MarkerEnvironment::from_platform(&platform, &PythonVersion::new(3, 11))
    }

    fn windows_env() -> MarkerEnvironment {
        let platform = Platform {
            os: Os::Windows,
            arch: Arch::X86_64,
            python_version: Some(PythonVersion::new(3, 11)),
            node_version: None,
        };
        MarkerEnvironment::from_platform(&platform, &PythonVersion::new(3, 11))
    }

    #[test]
    fn empty_marker_is_true() {
        assert!(evaluate_markers("", &linux_env()));
    }

    #[test]
    fn platform_equality() {
        assert!(evaluate_markers("sys_platform == 'linux'", &linux_env()));
        assert!(!evaluate_markers("sys_platform == 'linux'", &windows_env()));
    }

    #[test]
    fn os_name_check() {
        assert!(evaluate_markers("os_name == 'nt'", &windows_env()));
        assert!(evaluate_markers("os_name != 'nt'", &linux_env()));
    }

    #[test]
    fn python_version_comparison() {
        assert!(evaluate_markers("python_version >= '3.8'", &linux_env()));
        assert!(!evaluate_markers("python_version < '3.8'", &linux_env()));
    }

    #[test]
    fn compound_and() {
        assert!(evaluate_markers(
            "sys_platform == 'linux' and python_version >= '3.8'",
            &linux_env()
        ));
        assert!(!evaluate_markers(
            "sys_platform == 'win32' and python_version >= '3.8'",
            &linux_env()
        ));
    }

    #[test]
    fn compound_or() {
        assert!(evaluate_markers(
            "sys_platform == 'linux' or sys_platform == 'win32'",
            &linux_env()
        ));
        assert!(evaluate_markers(
            "sys_platform == 'linux' or sys_platform == 'win32'",
            &windows_env()
        ));
    }
}
