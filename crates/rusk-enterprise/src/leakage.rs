//! Internal package leakage prevention.
//!
//! Validates that internal packages (from enterprise registries) do not
//! leak into external contexts: public registries, open-source projects,
//! or shared lockfiles.

use crate::config::EnterpriseConfig;
use rusk_core::{PackageId, RegistryUrl};
use tracing::{info, warn};

/// Error type for leakage validation.
#[derive(Debug, thiserror::Error)]
pub enum LeakageError {
    #[error("internal package leakage detected: {package} from internal registry would be exposed to {context}")]
    LeakageDetected { package: String, context: String },
    #[error("multiple leakage violations detected: {count} packages")]
    MultipleLeakages { count: usize, details: Vec<String> },
}

/// A package reference to validate for leakage.
#[derive(Clone, Debug)]
pub struct PackageRef {
    /// Package identity.
    pub package: PackageId,
    /// Which registry this package comes from.
    pub registry: RegistryUrl,
}

/// Validate that no internal packages would leak to external contexts.
///
/// This checks all packages in a resolved graph against the enterprise
/// configuration to ensure that packages from internal registries are
/// not referenced in contexts where they would be inaccessible.
pub fn validate_no_internal_leakage(
    config: &EnterpriseConfig,
    packages: &[PackageRef],
    target_context: &str,
) -> Result<(), LeakageError> {
    let mut violations = Vec::new();

    for pkg_ref in packages {
        if is_internal_package(config, &pkg_ref.package, &pkg_ref.registry) {
            warn!(
                package = %pkg_ref.package,
                registry = %pkg_ref.registry,
                context = target_context,
                "internal package would leak to external context"
            );
            violations.push(format!(
                "{} (from {})",
                pkg_ref.package.display_name(),
                pkg_ref.registry
            ));
        }
    }

    if violations.is_empty() {
        info!(
            packages = packages.len(),
            context = target_context,
            "no internal package leakage detected"
        );
        Ok(())
    } else if violations.len() == 1 {
        Err(LeakageError::LeakageDetected {
            package: violations.into_iter().next().unwrap(),
            context: target_context.to_string(),
        })
    } else {
        let count = violations.len();
        Err(LeakageError::MultipleLeakages {
            count,
            details: violations,
        })
    }
}

/// Check if a package is from an internal registry.
fn is_internal_package(
    config: &EnterpriseConfig,
    package: &PackageId,
    registry: &RegistryUrl,
) -> bool {
    // A package is internal if its registry matches any configured internal registry
    for internal_reg in &config.registries {
        if !internal_reg.is_internal {
            continue;
        }
        // Check if the registry URL matches
        if internal_reg.url == *registry {
            return true;
        }
        // Check if the package namespace matches
        if let Some(ns) = &package.namespace {
            if internal_reg.namespaces.iter().any(|n| n == ns) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InternalRegistryConfig;
    use rusk_core::Ecosystem;

    fn test_config() -> EnterpriseConfig {
        let mut config = EnterpriseConfig::new("test-org");
        config.registries.push(InternalRegistryConfig {
            name: "internal-npm".to_string(),
            url: RegistryUrl::parse("https://npm.internal.example.com").unwrap(),
            ecosystem: Ecosystem::Js,
            auth_required: true,
            auth_token_env: Some("INTERNAL_NPM_TOKEN".to_string()),
            is_internal: true,
            namespaces: vec!["@internal".to_string()],
        });
        config
    }

    #[test]
    fn no_leakage_with_public_packages() {
        let config = test_config();
        let packages = vec![PackageRef {
            package: PackageId::js("express"),
            registry: RegistryUrl::npm_default(),
        }];
        assert!(validate_no_internal_leakage(&config, &packages, "public").is_ok());
    }

    #[test]
    fn detects_internal_package_leakage() {
        let config = test_config();
        let packages = vec![PackageRef {
            package: PackageId::js("@internal/utils"),
            registry: RegistryUrl::parse("https://npm.internal.example.com").unwrap(),
        }];
        assert!(validate_no_internal_leakage(&config, &packages, "public").is_err());
    }
}
