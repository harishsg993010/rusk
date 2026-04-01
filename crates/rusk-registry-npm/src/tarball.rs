//! npm tarball URL construction.
//!
//! Constructs download URLs for npm package tarballs following the npm
//! registry convention: `<registry>/<name>/-/<name>-<version>.tgz`

use rusk_core::{PackageId, RegistryUrl, Version};
use url::Url;

/// Construct the expected tarball URL for an npm package version.
///
/// The npm registry convention is:
/// - Unscoped: `https://registry.npmjs.org/<name>/-/<name>-<version>.tgz`
/// - Scoped: `https://registry.npmjs.org/<@scope/name>/-/<name>-<version>.tgz`
///
/// Note: the actual URL from the registry metadata may differ (e.g., for
/// mirrors or private registries). This function constructs the canonical form.
pub fn tarball_url(
    registry: &RegistryUrl,
    package: &PackageId,
    version: &Version,
) -> Result<Url, url::ParseError> {
    let display_name = package.display_name();
    let bare_name = &package.name;
    let version_str = version.to_string();

    // Build the path: /<display_name>/-/<bare_name>-<version>.tgz
    let path = format!("{display_name}/-/{bare_name}-{version_str}.tgz");
    registry.join(&path)
}

/// Extract the package name and version from a tarball URL.
///
/// Attempts to parse URLs of the form:
/// `<registry>/<optional-scope/name>/-/<name>-<version>.tgz`
///
/// Returns `(name, version_string)` on success, or `None` if the URL
/// doesn't match the expected pattern.
pub fn parse_tarball_url(url: &Url) -> Option<(String, String)> {
    let path = url.path();
    // Find the `/-/` separator.
    let tarball_part = path.rsplit("/-/").next()?;
    // Strip .tgz suffix.
    let without_ext = tarball_part.strip_suffix(".tgz")?;
    // Split on the last '-' to separate name from version.
    // This handles names that contain hyphens.
    let dash_pos = without_ext.rfind('-')?;
    let name = &without_ext[..dash_pos];
    let version = &without_ext[dash_pos + 1..];

    if name.is_empty() || version.is_empty() {
        return None;
    }

    Some((name.to_string(), version.to_string()))
}

/// Check if a tarball URL points to the expected registry.
pub fn is_registry_tarball(url: &Url, registry: &RegistryUrl) -> bool {
    url.host_str() == Some(registry.host())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::{PackageId, RegistryUrl, Version};

    #[test]
    fn unscoped_tarball_url() {
        let registry = RegistryUrl::npm_default();
        let pkg = PackageId::js("express");
        let version = Version::Semver(semver::Version::new(4, 18, 2));
        let url = tarball_url(&registry, &pkg, &version).unwrap();
        assert_eq!(
            url.as_str(),
            "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
        );
    }

    #[test]
    fn scoped_tarball_url() {
        let registry = RegistryUrl::npm_default();
        let pkg = PackageId::js("@babel/core");
        let version = Version::Semver(semver::Version::new(7, 23, 0));
        let url = tarball_url(&registry, &pkg, &version).unwrap();
        assert!(url.as_str().contains("@babel/core/-/core-7.23.0.tgz"));
    }

    #[test]
    fn parse_standard_url() {
        let url = Url::parse(
            "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
        )
        .unwrap();
        let (name, version) = parse_tarball_url(&url).unwrap();
        assert_eq!(name, "express");
        assert_eq!(version, "4.18.2");
    }

    #[test]
    fn parse_scoped_url() {
        let url = Url::parse(
            "https://registry.npmjs.org/@babel/core/-/core-7.23.0.tgz",
        )
        .unwrap();
        let (name, version) = parse_tarball_url(&url).unwrap();
        assert_eq!(name, "core");
        assert_eq!(version, "7.23.0");
    }

    #[test]
    fn registry_check() {
        let url = Url::parse(
            "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
        )
        .unwrap();
        let registry = RegistryUrl::npm_default();
        assert!(is_registry_tarball(&url, &registry));

        let other = RegistryUrl::pypi_default();
        assert!(!is_registry_tarball(&url, &other));
    }
}
