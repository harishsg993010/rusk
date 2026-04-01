//! Wheel tag compatibility.
//!
//! Handles PEP 425 wheel tags (python-abi-platform) to determine
//! which wheel files are compatible with the target environment.

/// A parsed wheel tag (python_tag-abi_tag-platform_tag).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WheelTag {
    /// Python implementation and version (e.g., "cp311", "py3").
    pub python: String,
    /// ABI tag (e.g., "cp311", "abi3", "none").
    pub abi: String,
    /// Platform tag (e.g., "manylinux_2_17_x86_64", "macosx_11_0_arm64", "any").
    pub platform: String,
}

impl WheelTag {
    /// Parse a wheel tag string like "cp311-cp311-manylinux_2_17_x86_64".
    pub fn parse(tag: &str) -> Option<Self> {
        let parts: Vec<&str> = tag.split('-').collect();
        if parts.len() != 3 {
            return None;
        }
        Some(Self {
            python: parts[0].to_string(),
            abi: parts[1].to_string(),
            platform: parts[2].to_string(),
        })
    }

    /// Check if this tag is a "pure Python" wheel (platform-independent).
    pub fn is_pure_python(&self) -> bool {
        self.python.starts_with("py") && self.abi == "none" && self.platform == "any"
    }

    /// Check if this is a universal wheel (py2.py3-none-any).
    pub fn is_universal(&self) -> bool {
        (self.python == "py2.py3" || self.python == "py3")
            && self.abi == "none"
            && self.platform == "any"
    }
}

/// Priority score for tag compatibility (higher is more specific/preferred).
pub fn tag_priority(tag: &WheelTag) -> u32 {
    let mut score = 0;

    // Prefer platform-specific over any
    if tag.platform != "any" {
        score += 100;
    }

    // Prefer specific ABI over none
    if tag.abi != "none" {
        score += 50;
    }

    // Prefer cpython over generic py
    if tag.python.starts_with("cp") {
        score += 25;
    }

    score
}

/// Generate the compatible tags for the current platform.
pub fn compatible_tags(python_version: (u32, u32)) -> Vec<WheelTag> {
    let (major, minor) = python_version;
    let mut tags = Vec::new();

    // Most specific: cpXY-cpXY-<platform>
    let cp_tag = format!("cp{major}{minor}");
    let platform = current_platform_tag();

    tags.push(WheelTag {
        python: cp_tag.clone(),
        abi: cp_tag.clone(),
        platform: platform.clone(),
    });

    // cpXY-abi3-<platform>
    tags.push(WheelTag {
        python: cp_tag.clone(),
        abi: "abi3".to_string(),
        platform: platform.clone(),
    });

    // cpXY-none-<platform>
    tags.push(WheelTag {
        python: cp_tag,
        abi: "none".to_string(),
        platform: platform.clone(),
    });

    // py3-none-<platform>
    tags.push(WheelTag {
        python: format!("py{major}"),
        abi: "none".to_string(),
        platform,
    });

    // py3-none-any (pure Python, least specific)
    tags.push(WheelTag {
        python: format!("py{major}"),
        abi: "none".to_string(),
        platform: "any".to_string(),
    });

    tags
}

/// Get the current platform tag.
fn current_platform_tag() -> String {
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "manylinux_2_17_x86_64".to_string()
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "manylinux_2_17_aarch64".to_string()
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "macosx_10_9_x86_64".to_string()
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "macosx_11_0_arm64".to_string()
    } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
        "win_amd64".to_string()
    } else {
        "any".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wheel_tag() {
        let tag = WheelTag::parse("cp311-cp311-manylinux_2_17_x86_64").unwrap();
        assert_eq!(tag.python, "cp311");
        assert_eq!(tag.abi, "cp311");
        assert!(!tag.is_pure_python());
    }

    #[test]
    fn pure_python_tag() {
        let tag = WheelTag::parse("py3-none-any").unwrap();
        assert!(tag.is_pure_python());
        assert!(tag.is_universal());
    }

    #[test]
    fn tag_priority_ordering() {
        let specific = WheelTag::parse("cp311-cp311-manylinux_2_17_x86_64").unwrap();
        let pure = WheelTag::parse("py3-none-any").unwrap();
        assert!(tag_priority(&specific) > tag_priority(&pure));
    }
}
