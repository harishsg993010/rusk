//! HTTP proxy configuration for enterprise environments.
//!
//! Supports HTTPS proxy, SOCKS5 proxy, proxy authentication,
//! and no-proxy bypass lists.

use serde::{Deserialize, Serialize};

/// Proxy configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// HTTPS proxy URL.
    pub https_proxy: Option<String>,
    /// HTTP proxy URL (fallback if HTTPS not set).
    pub http_proxy: Option<String>,
    /// Hosts/domains to bypass the proxy for.
    pub no_proxy: Vec<String>,
    /// Proxy authentication.
    pub auth: Option<ProxyAuth>,
}

/// Proxy authentication credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

impl ProxyConfig {
    /// Create from environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY).
    pub fn from_env() -> Option<Self> {
        let https_proxy = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .ok();
        let http_proxy = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .ok();

        if https_proxy.is_none() && http_proxy.is_none() {
            return None;
        }

        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Some(Self {
            https_proxy,
            http_proxy,
            no_proxy,
            auth: None,
        })
    }

    /// Check if a given host should bypass the proxy.
    pub fn should_bypass(&self, host: &str) -> bool {
        self.no_proxy.iter().any(|pattern| {
            if pattern == "*" {
                true
            } else if pattern.starts_with('.') {
                host.ends_with(pattern)
            } else {
                host == pattern || host.ends_with(&format!(".{pattern}"))
            }
        })
    }

    /// Get the effective proxy URL for a given scheme.
    pub fn proxy_url_for(&self, scheme: &str) -> Option<&str> {
        match scheme {
            "https" => self
                .https_proxy
                .as_deref()
                .or(self.http_proxy.as_deref()),
            "http" => self.http_proxy.as_deref(),
            _ => None,
        }
    }
}
