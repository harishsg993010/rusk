use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

/// Normalized registry URL.
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct RegistryUrl(Url);

impl RegistryUrl {
    /// Create from URL string.
    pub fn parse(s: &str) -> Result<Self, url::ParseError> {
        let url = Url::parse(s)?;
        Ok(Self(url))
    }

    /// Default npm registry.
    pub fn npm_default() -> Self {
        Self(Url::parse("https://registry.npmjs.org").unwrap())
    }

    /// Default PyPI registry.
    pub fn pypi_default() -> Self {
        Self(Url::parse("https://pypi.org").unwrap())
    }

    /// Get the host portion.
    pub fn host(&self) -> &str {
        self.0.host_str().unwrap_or("unknown")
    }

    /// Join a path to this registry URL.
    pub fn join(&self, path: &str) -> Result<Url, url::ParseError> {
        self.0.join(path)
    }

    /// Get the inner URL.
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    /// Check if this is a known public registry.
    pub fn is_public(&self) -> bool {
        let host = self.host();
        host == "registry.npmjs.org"
            || host == "pypi.org"
            || host == "files.pythonhosted.org"
    }
}

impl fmt::Debug for RegistryUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for RegistryUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.host())
    }
}

/// Registry classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryKind {
    /// Public registry (npm, PyPI)
    Public,
    /// Internal/enterprise registry
    Internal,
    /// Local registry (for testing)
    Local,
}
