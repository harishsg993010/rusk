//! Wheel filename parsing and compatibility checking.
//!
//! Parses Python wheel filenames per PEP 427 and checks platform compatibility.
//! Wheel filename format: `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`

use serde::{Deserialize, Serialize};
use std::fmt;

/// Parsed wheel filename tags.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WheelTags {
    /// Distribution name (normalized).
    pub name: String,
    /// Version string.
    pub version: String,
    /// Optional build tag.
    pub build: Option<String>,
    /// Python tag(s) (e.g., "py3", "cp311").
    pub python_tags: Vec<String>,
    /// ABI tag(s) (e.g., "none", "cp311").
    pub abi_tags: Vec<String>,
    /// Platform tag(s) (e.g., "any", "manylinux_2_17_x86_64").
    pub platform_tags: Vec<String>,
}

/// Error parsing a wheel filename.
#[derive(Debug, thiserror::Error)]
pub enum WheelParseError {
    #[error("invalid wheel filename: {0}")]
    InvalidFilename(String),
    #[error("missing required component in wheel filename: {component}")]
    MissingComponent { component: String },
}

impl WheelTags {
    /// Parse a wheel filename into its component tags.
    ///
    /// Filename format: `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl`
    pub fn parse(filename: &str) -> Result<Self, WheelParseError> {
        let basename = filename
            .strip_suffix(".whl")
            .ok_or_else(|| WheelParseError::InvalidFilename(filename.to_string()))?;

        let parts: Vec<&str> = basename.split('-').collect();

        // At minimum: name-version-python-abi-platform (5 parts)
        // With build tag: name-version-build-python-abi-platform (6 parts)
        if parts.len() < 5 {
            return Err(WheelParseError::InvalidFilename(filename.to_string()));
        }

        let (name, version, build, python_str, abi_str, platform_str) = if parts.len() >= 6 {
            // Has build tag.
            (
                parts[0],
                parts[1],
                Some(parts[2].to_string()),
                parts[3],
                parts[4],
                parts[5],
            )
        } else {
            (parts[0], parts[1], None, parts[2], parts[3], parts[4])
        };

        Ok(Self {
            name: name.replace('_', "-").to_lowercase(),
            version: version.to_string(),
            build,
            python_tags: python_str.split('.').map(String::from).collect(),
            abi_tags: abi_str.split('.').map(String::from).collect(),
            platform_tags: platform_str.split('.').map(String::from).collect(),
        })
    }

    /// Check if this wheel is a universal wheel (pure Python, any platform).
    pub fn is_universal(&self) -> bool {
        self.python_tags.iter().any(|t| t.starts_with("py"))
            && self.abi_tags.iter().any(|t| t == "none")
            && self.platform_tags.iter().any(|t| t == "any")
    }

    /// Check if this wheel is pure Python (no C extensions).
    pub fn is_pure_python(&self) -> bool {
        self.abi_tags.iter().all(|t| t == "none")
            && self.platform_tags.iter().all(|t| t == "any")
    }

    /// Check if this wheel is compatible with the given Python version and platform.
    ///
    /// A simplified compatibility check. For full accuracy, the caller should
    /// build the complete compatibility tag list per PEP 425.
    pub fn is_compatible(
        &self,
        python_version: (u32, u32),
        os: &str,
        arch: &str,
    ) -> bool {
        let python_ok = self.python_tags.iter().any(|tag| {
            // "py3" matches any Python 3.x
            if tag == "py3" && python_version.0 == 3 {
                return true;
            }
            // "py2.py3" is handled because we check each tag individually
            if tag == "py2" && python_version.0 == 2 {
                return true;
            }
            // "cp311" matches CPython 3.11
            if let Some(rest) = tag.strip_prefix("cp") {
                if let Ok(ver_num) = rest.parse::<u32>() {
                    let major = ver_num / 100;
                    let minor = ver_num % 100;
                    if major == 0 {
                        // Single digit: "cp3" = Python 3.x
                        return ver_num == python_version.0;
                    }
                    return major == python_version.0 && minor == python_version.1;
                }
                // "cp3" style
                if let Ok(major) = rest.parse::<u32>() {
                    return major == python_version.0;
                }
            }
            false
        });

        let platform_ok = self.platform_tags.iter().any(|tag| {
            if tag == "any" {
                return true;
            }
            // Check OS match.
            let os_match = match os {
                "linux" => {
                    tag.starts_with("linux")
                        || tag.starts_with("manylinux")
                        || tag.starts_with("musllinux")
                }
                "macos" | "darwin" => tag.starts_with("macosx"),
                "windows" | "win32" => tag.starts_with("win"),
                _ => false,
            };
            if !os_match {
                return false;
            }
            // Check arch match (simplified).
            match arch {
                "x86_64" | "amd64" => {
                    tag.contains("x86_64") || tag.contains("amd64") || tag.contains("universal")
                }
                "aarch64" | "arm64" => {
                    tag.contains("aarch64") || tag.contains("arm64") || tag.contains("universal")
                }
                "x86" | "i686" => tag.contains("i686") || tag.contains("x86") || tag.contains("win32"),
                _ => false,
            }
        });

        python_ok && platform_ok
    }
}

impl fmt::Display for WheelTags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let python = self.python_tags.join(".");
        let abi = self.abi_tags.join(".");
        let platform = self.platform_tags.join(".");
        match &self.build {
            Some(b) => write!(f, "{}-{}-{}-{}-{}-{}.whl", self.name, self.version, b, python, abi, platform),
            None => write!(f, "{}-{}-{}-{}-{}.whl", self.name, self.version, python, abi, platform),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_universal_wheel() {
        let tags = WheelTags::parse("requests-2.31.0-py3-none-any.whl").unwrap();
        assert_eq!(tags.name, "requests");
        assert_eq!(tags.version, "2.31.0");
        assert!(tags.build.is_none());
        assert_eq!(tags.python_tags, vec!["py3"]);
        assert_eq!(tags.abi_tags, vec!["none"]);
        assert_eq!(tags.platform_tags, vec!["any"]);
        assert!(tags.is_universal());
        assert!(tags.is_pure_python());
    }

    #[test]
    fn parse_platform_wheel() {
        let tags =
            WheelTags::parse("numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl")
                .unwrap();
        assert_eq!(tags.name, "numpy");
        assert_eq!(tags.version, "1.26.0");
        assert_eq!(tags.python_tags, vec!["cp311"]);
        assert_eq!(tags.abi_tags, vec!["cp311"]);
        assert!(!tags.is_universal());
        assert!(!tags.is_pure_python());
    }

    #[test]
    fn parse_with_build_tag() {
        let tags = WheelTags::parse("foo-1.0-1-py3-none-any.whl").unwrap();
        assert_eq!(tags.name, "foo");
        assert_eq!(tags.version, "1.0");
        assert_eq!(tags.build, Some("1".to_string()));
    }

    #[test]
    fn compatibility_universal() {
        let tags = WheelTags::parse("requests-2.31.0-py3-none-any.whl").unwrap();
        assert!(tags.is_compatible((3, 11), "linux", "x86_64"));
        assert!(tags.is_compatible((3, 9), "macos", "aarch64"));
        assert!(tags.is_compatible((3, 12), "windows", "x86_64"));
    }

    #[test]
    fn compatibility_platform_specific() {
        let tags =
            WheelTags::parse("numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.whl").unwrap();
        assert!(tags.is_compatible((3, 11), "linux", "x86_64"));
        assert!(!tags.is_compatible((3, 11), "macos", "x86_64"));
        assert!(!tags.is_compatible((3, 11), "linux", "aarch64"));
        assert!(!tags.is_compatible((3, 10), "linux", "x86_64"));
    }

    #[test]
    fn invalid_filename() {
        assert!(WheelTags::parse("not-a-wheel.tar.gz").is_err());
        assert!(WheelTags::parse("too-few.whl").is_err());
    }
}
