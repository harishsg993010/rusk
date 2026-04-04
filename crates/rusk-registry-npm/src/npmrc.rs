//! .npmrc configuration file parser.
//!
//! Parses `.npmrc` files to extract auth tokens for private registries.
//! Supports both project-level and home directory `.npmrc` files.

/// Parsed .npmrc configuration.
#[derive(Clone, Debug, Default)]
pub struct NpmrcConfig {
    /// Registry auth entries found in the file.
    pub entries: Vec<NpmrcEntry>,
}

/// A single registry auth entry from .npmrc.
#[derive(Clone, Debug)]
pub struct NpmrcEntry {
    /// Registry hostname (e.g., "registry.npmjs.org").
    pub registry: String,
    /// Bearer auth token, if present.
    pub auth_token: Option<String>,
    /// Basic auth username, if present.
    pub username: Option<String>,
    /// Basic auth password (base64), if present.
    pub password: Option<String>,
}

/// Parse the contents of an `.npmrc` file into an `NpmrcConfig`.
///
/// Supports the following formats:
/// - `//registry.npmjs.org/:_authToken=npm_xxxxx`
/// - `//my-registry.com/:_authToken=${NPM_TOKEN}` (env var expansion)
/// - Comments starting with `#` or `;`
pub fn parse_npmrc(content: &str) -> NpmrcConfig {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.contains(":_authToken=") {
            // //registry/:_authToken=TOKEN
            let parts: Vec<&str> = line.splitn(2, ":_authToken=").collect();
            if parts.len() == 2 {
                let registry = parts[0]
                    .trim_start_matches('/')
                    .trim_end_matches('/');
                let mut token = parts[1].to_string();

                // Expand env vars: ${NPM_TOKEN} -> env value
                token = expand_env_vars(&token);

                entries.push(NpmrcEntry {
                    registry: registry.to_string(),
                    auth_token: Some(token),
                    username: None,
                    password: None,
                });
            }
        }
    }

    NpmrcConfig { entries }
}

/// Find an auth token for a given registry URL.
///
/// Searches through the parsed `.npmrc` entries and returns the first
/// matching auth token for a registry whose hostname appears in the URL.
pub fn find_token_for_registry(config: &NpmrcConfig, registry_url: &str) -> Option<String> {
    for entry in &config.entries {
        if registry_url.contains(&entry.registry) {
            return entry.auth_token.clone();
        }
    }
    None
}

/// Expand environment variable references in a string.
///
/// Handles the `${VAR_NAME}` syntax used in .npmrc files.
fn expand_env_vars(value: &str) -> String {
    let mut result = value.to_string();

    // Handle ${VAR_NAME} pattern
    while let Some(start) = result.find("${") {
        if let Some(end) = result[start..].find('}') {
            let var_name = &result[start + 2..start + end];
            let var_value = std::env::var(var_name).unwrap_or_default();
            result = format!("{}{}{}", &result[..start], var_value, &result[start + end + 1..]);
        } else {
            break;
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_npmrc() {
        let content = r#"
//registry.npmjs.org/:_authToken=npm_abc123
# This is a comment
; This is also a comment
"#;
        let config = parse_npmrc(content);
        assert_eq!(config.entries.len(), 1);
        assert_eq!(config.entries[0].registry, "registry.npmjs.org");
        assert_eq!(
            config.entries[0].auth_token.as_deref(),
            Some("npm_abc123")
        );
    }

    #[test]
    fn parse_multiple_registries() {
        let content = r#"
//registry.npmjs.org/:_authToken=npm_abc123
//my-private-registry.com/:_authToken=secret_token
"#;
        let config = parse_npmrc(content);
        assert_eq!(config.entries.len(), 2);
        assert_eq!(config.entries[0].registry, "registry.npmjs.org");
        assert_eq!(config.entries[1].registry, "my-private-registry.com");
    }

    #[test]
    fn find_token_for_known_registry() {
        let content = "//registry.npmjs.org/:_authToken=npm_abc123\n";
        let config = parse_npmrc(content);
        let token = find_token_for_registry(&config, "https://registry.npmjs.org/");
        assert_eq!(token, Some("npm_abc123".to_string()));
    }

    #[test]
    fn find_token_for_unknown_registry() {
        let content = "//registry.npmjs.org/:_authToken=npm_abc123\n";
        let config = parse_npmrc(content);
        let token = find_token_for_registry(&config, "https://other-registry.com/");
        assert_eq!(token, None);
    }

    #[test]
    fn parse_empty_npmrc() {
        let config = parse_npmrc("");
        assert!(config.entries.is_empty());
    }

    #[test]
    fn parse_comments_only() {
        let content = "# just a comment\n; another comment\n";
        let config = parse_npmrc(content);
        assert!(config.entries.is_empty());
    }

    #[test]
    fn expand_env_var_in_token() {
        std::env::set_var("TEST_NPMRC_TOKEN", "expanded_value");
        let content = "//registry.npmjs.org/:_authToken=${TEST_NPMRC_TOKEN}\n";
        let config = parse_npmrc(content);
        assert_eq!(
            config.entries[0].auth_token.as_deref(),
            Some("expanded_value")
        );
        std::env::remove_var("TEST_NPMRC_TOKEN");
    }
}
