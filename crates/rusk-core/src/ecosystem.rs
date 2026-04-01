use serde::{Deserialize, Serialize};
use std::fmt;

/// Package ecosystem identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    /// JavaScript / TypeScript (npm registry)
    Js,
    /// Python (PyPI registry)
    Python,
}

impl Ecosystem {
    /// Default registry URL for this ecosystem.
    pub fn default_registry_url(&self) -> &'static str {
        match self {
            Ecosystem::Js => "https://registry.npmjs.org",
            Ecosystem::Python => "https://pypi.org",
        }
    }

    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Ecosystem::Js => "JavaScript/TypeScript",
            Ecosystem::Python => "Python",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::Js => write!(f, "js"),
            Ecosystem::Python => write!(f, "python"),
        }
    }
}

impl std::str::FromStr for Ecosystem {
    type Err = EcosystemError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "js" | "javascript" | "typescript" | "ts" => Ok(Ecosystem::Js),
            "python" | "py" => Ok(Ecosystem::Python),
            other => Err(EcosystemError::Unknown(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EcosystemError {
    #[error("unknown ecosystem: {0}")]
    Unknown(String),
}
