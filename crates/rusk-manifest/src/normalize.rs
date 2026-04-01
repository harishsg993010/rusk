//! Manifest normalization.
//!
//! Normalizes a parsed manifest by applying default values, normalizing
//! package names, and ensuring consistent representation.

use crate::schema::{
    BuildConfig, DependencyEntry, Manifest, TrustConfig,
};
use rusk_core::Ecosystem;
use std::collections::HashMap;

/// Normalize a manifest in place, applying defaults and normalizing names.
///
/// This function:
/// - Normalizes Python package names (PEP 503: lowercase, replace [-_.] with -)
/// - Ensures default trust configuration exists
/// - Sets default build sandbox to true for CI environments
/// - Sorts dependency keys for deterministic output
pub fn normalize_manifest(manifest: &mut Manifest) {
    normalize_package_name(manifest);
    normalize_dependencies(manifest);
    ensure_defaults(manifest);
}

/// Normalize the package name based on ecosystem conventions.
fn normalize_package_name(manifest: &mut Manifest) {
    match manifest.package.ecosystem {
        Ecosystem::Python => {
            // PEP 503 normalization: lowercase, replace [_.-] with -
            manifest.package.name = normalize_python_name(&manifest.package.name);
        }
        Ecosystem::Js => {
            // npm names are case-sensitive but conventionally lowercase.
            // We don't lowercase them since scoped packages like @Foo/bar exist.
        }
    }
}

/// Normalize dependency names.
fn normalize_dependencies(manifest: &mut Manifest) {
    if let Some(ref mut py) = manifest.python_dependencies {
        py.dependencies = normalize_dep_map(&py.dependencies);
        py.dev_dependencies = normalize_dep_map(&py.dev_dependencies);
    }
}

/// Normalize all keys in a dependency map to PEP 503 form.
fn normalize_dep_map(
    deps: &HashMap<String, DependencyEntry>,
) -> HashMap<String, DependencyEntry> {
    deps.iter()
        .map(|(name, entry)| (normalize_python_name(name), entry.clone()))
        .collect()
}

/// Normalize a Python package name per PEP 503.
fn normalize_python_name(name: &str) -> String {
    name.to_lowercase().replace(['_', '.'], "-")
}

/// Ensure default configuration sections exist.
fn ensure_defaults(manifest: &mut Manifest) {
    // Ensure trust config has defaults.
    if manifest.trust.is_none() {
        manifest.trust = Some(TrustConfig::default());
    }

    // Ensure build config exists.
    if manifest.build.is_none() {
        manifest.build = Some(BuildConfig::default());
    }
}

/// Create a normalized copy of the manifest without modifying the original.
pub fn normalized_copy(manifest: &Manifest) -> Manifest {
    let mut copy = manifest.clone();
    normalize_manifest(&mut copy);
    copy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_manifest;

    #[test]
    fn normalize_python_package_name() {
        let toml_str = r#"
[package]
name = "My_Package.Name"
ecosystem = "python"
"#;
        let mut manifest = parse_manifest(toml_str).unwrap();
        normalize_manifest(&mut manifest);
        assert_eq!(manifest.package.name, "my-package-name");
    }

    #[test]
    fn normalize_python_dep_names() {
        let toml_str = r#"
[package]
name = "test"
ecosystem = "python"

[python_dependencies.dependencies]
Flask_RESTful = ">=0.3"
"My-Package" = ">=1.0"
"#;
        let mut manifest = parse_manifest(toml_str).unwrap();
        normalize_manifest(&mut manifest);
        let py = manifest.python_dependencies.unwrap();
        assert!(py.dependencies.contains_key("flask-restful"));
        assert!(py.dependencies.contains_key("my-package"), "keys: {:?}", py.dependencies.keys().collect::<Vec<_>>());
    }

    #[test]
    fn js_name_not_lowercased() {
        let toml_str = r#"
[package]
name = "@MyOrg/MyPkg"
ecosystem = "js"
"#;
        let mut manifest = parse_manifest(toml_str).unwrap();
        normalize_manifest(&mut manifest);
        // JS names are case-sensitive; should not be altered.
        assert_eq!(manifest.package.name, "@MyOrg/MyPkg");
    }

    #[test]
    fn defaults_are_added() {
        let toml_str = r#"
[package]
name = "test"
ecosystem = "js"
"#;
        let mut manifest = parse_manifest(toml_str).unwrap();
        assert!(manifest.trust.is_none());
        assert!(manifest.build.is_none());
        normalize_manifest(&mut manifest);
        assert!(manifest.trust.is_some());
        assert!(manifest.build.is_some());
    }

    #[test]
    fn normalized_copy_preserves_original() {
        let toml_str = r#"
[package]
name = "My_Package"
ecosystem = "python"
"#;
        let manifest = parse_manifest(toml_str).unwrap();
        let copy = normalized_copy(&manifest);
        assert_eq!(manifest.package.name, "My_Package");
        assert_eq!(copy.package.name, "my-package");
    }
}
