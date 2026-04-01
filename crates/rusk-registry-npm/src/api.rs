//! npm registry API client implementation.
//!
//! Implements the `RegistryClient` trait for the npm registry protocol.

use crate::metadata::{NpmPackument, NpmVersionMeta};
use crate::tarball;
use async_trait::async_trait;
use rusk_core::{Ecosystem, PackageId, RegistryUrl, Sha256Digest, Version};
use rusk_registry::{
    ArtifactInfo, ArtifactType, DependencyKind, DependencySpec, PackageMetadata, RegistryClient,
    RegistryError, VersionMetadata,
};
use rusk_tuf::SignedMetadata;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use tracing::{debug, instrument};

/// npm registry client implementing the `RegistryClient` trait.
pub struct NpmRegistryClient {
    registry_url: RegistryUrl,
    http: reqwest::Client,
}

impl NpmRegistryClient {
    /// Create a new client for the given registry URL.
    pub fn new(registry_url: RegistryUrl) -> Self {
        Self {
            registry_url,
            http: reqwest::Client::builder()
                .user_agent("rusk/0.1.0")
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Create a new client with a custom reqwest client (for testing/proxies).
    pub fn with_http_client(registry_url: RegistryUrl, http: reqwest::Client) -> Self {
        Self { registry_url, http }
    }

    /// Create a client for the default npm registry (registry.npmjs.org).
    pub fn default_registry() -> Self {
        Self::new(RegistryUrl::npm_default())
    }

    /// Encode a package name for use in a registry URL path.
    ///
    /// Scoped packages like `@scope/name` must be URL-encoded as `@scope%2Fname`
    /// to form a valid single path segment in the npm registry API.
    fn encode_package_name(package: &PackageId) -> String {
        let display = package.display_name();
        if display.starts_with('@') {
            // Scoped: encode the `/` between scope and name.
            display.replacen('/', "%2F", 1)
        } else {
            display
        }
    }

    /// Fetch the raw packument document from the registry.
    #[instrument(skip(self), fields(registry = %self.registry_url))]
    pub async fn fetch_packument(
        &self,
        package: &PackageId,
    ) -> Result<NpmPackument, RegistryError> {
        let encoded_name = Self::encode_package_name(package);
        let url = format!("{}/{}", self.registry_url.as_url(), encoded_name);
        debug!(url = %url, "fetching npm packument");

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| RegistryError::Network(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::PackageNotFound(
                package.display_name(),
            ));
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            return Err(RegistryError::RateLimited {
                retry_after_secs: retry_after,
            });
        }
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Err(RegistryError::AuthRequired(
                self.registry_url.host().to_string(),
            ));
        }
        if !status.is_success() {
            return Err(RegistryError::InvalidResponse(format!(
                "HTTP {} from {}",
                status, url
            )));
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| RegistryError::InvalidResponse(format!("error reading response body: {e}")))?;

        serde_json::from_slice::<NpmPackument>(&body)
            .map_err(|e| {
                // Include position info for debugging
                RegistryError::InvalidResponse(format!(
                    "error decoding JSON for {}: {} (at byte {})",
                    encoded_name, e, e.column()
                ))
            })
    }

    /// Convert an npm version document into a unified VersionMetadata.
    fn convert_version(
        package: &PackageId,
        npm_ver: &NpmVersionMeta,
    ) -> Option<VersionMetadata> {
        let version = semver::Version::parse(&npm_ver.version).ok()?;
        let version = Version::Semver(version);

        let mut artifacts = Vec::new();
        if !npm_ver.dist.tarball.is_empty() {
            let url = url::Url::parse(&npm_ver.dist.tarball).ok()?;
            // Try to parse integrity (sha512) or fall back to shasum (sha1).
            let sha256 = npm_ver
                .dist
                .integrity
                .as_ref()
                .and_then(|i| parse_integrity_sha256(i));

            artifacts.push(ArtifactInfo {
                filename: format!("{}-{}.tgz", package.name, npm_ver.version),
                url,
                sha256,
                artifact_type: ArtifactType::NpmTarball,
                size: npm_ver.dist.unpacked_size,
                requires_python: None,
            });
        }

        let mut dependencies = Vec::new();
        for (name, req) in &npm_ver.dependencies {
            dependencies.push(DependencySpec {
                name: name.clone(),
                requirement: req.clone(),
                kind: DependencyKind::Normal,
                ecosystem: Ecosystem::Js,
            });
        }
        for (name, req) in &npm_ver.dev_dependencies {
            dependencies.push(DependencySpec {
                name: name.clone(),
                requirement: req.clone(),
                kind: DependencyKind::Dev,
                ecosystem: Ecosystem::Js,
            });
        }
        for (name, req) in &npm_ver.peer_dependencies {
            let kind = if npm_ver
                .peer_dependencies_meta
                .get(name)
                .map_or(false, |m| m.optional)
            {
                DependencyKind::Optional
            } else {
                DependencyKind::Peer
            };
            dependencies.push(DependencySpec {
                name: name.clone(),
                requirement: req.clone(),
                kind,
                ecosystem: Ecosystem::Js,
            });
        }
        for (name, req) in &npm_ver.optional_dependencies {
            dependencies.push(DependencySpec {
                name: name.clone(),
                requirement: req.clone(),
                kind: DependencyKind::Optional,
                ecosystem: Ecosystem::Js,
            });
        }

        let yanked = npm_ver.is_deprecated();
        let yank_reason = npm_ver.deprecated.clone();

        Some(VersionMetadata {
            package: package.clone(),
            version,
            artifacts,
            dependencies,
            yanked,
            yank_reason,
            published_at: None,
        })
    }
}

/// Try to extract a SHA-256 digest from a Subresource Integrity string.
/// npm typically uses sha512, so this may return None.
fn parse_integrity_sha256(integrity: &str) -> Option<Sha256Digest> {
    for part in integrity.split_whitespace() {
        if let Some(b64) = part.strip_prefix("sha256-") {
            let decoded = base64_decode(b64)?;
            if decoded.len() == 32 {
                let arr: [u8; 32] = decoded.try_into().ok()?;
                return Some(Sha256Digest(arr));
            }
        }
    }
    None
}

/// Simple base64 decoder (no external dependency needed for this small use).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn decode_char(c: u8) -> Option<u8> {
        CHARS.iter().position(|&b| b == c).map(|p| p as u8)
    }

    let input: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut output = Vec::new();
    let mut i = 0;
    while i + 1 < input.len() {
        let a = decode_char(input[i])?;
        let b = decode_char(input[i + 1])?;
        let c = if i + 2 < input.len() {
            decode_char(input[i + 2])?
        } else {
            0
        };
        let d = if i + 3 < input.len() {
            decode_char(input[i + 3])?
        } else {
            0
        };

        output.push((a << 2) | (b >> 4));
        if i + 2 < input.len() {
            output.push(((b & 0x0F) << 4) | (c >> 2));
        }
        if i + 3 < input.len() {
            output.push(((c & 0x03) << 6) | d);
        }
        i += 4;
    }
    Some(output)
}

#[async_trait]
impl RegistryClient for NpmRegistryClient {
    #[instrument(skip(self), fields(package = %package.display_name()))]
    async fn fetch_package_metadata(
        &self,
        package: &PackageId,
    ) -> Result<PackageMetadata, RegistryError> {
        let packument = self.fetch_packument(package).await?;

        let mut versions = Vec::new();
        let mut version_metadata = HashMap::new();

        for (ver_str, npm_ver) in &packument.versions {
            if let Some(meta) = Self::convert_version(package, npm_ver) {
                versions.push(meta.version.clone());
                version_metadata.insert(ver_str.clone(), meta);
            }
        }
        versions.sort();

        let dist_tags = packument.dist_tags.clone();

        Ok(PackageMetadata {
            package: package.clone(),
            description: packument.description.clone(),
            versions,
            version_metadata,
            dist_tags,
        })
    }

    #[instrument(skip(self), fields(package = %package.display_name(), version = %version))]
    async fn fetch_version_metadata(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<VersionMetadata, RegistryError> {
        let encoded_name = NpmRegistryClient::encode_package_name(package);
        let url = format!(
            "{}/{}/{}",
            self.registry_url.as_url(),
            encoded_name,
            version
        );
        debug!(url = %url, "fetching npm version metadata");

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| RegistryError::Network(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(RegistryError::VersionNotFound {
                package: package.display_name(),
                version: version.to_string(),
            });
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            return Err(RegistryError::RateLimited {
                retry_after_secs: retry_after,
            });
        }
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Err(RegistryError::AuthRequired(
                self.registry_url.host().to_string(),
            ));
        }
        if !status.is_success() {
            return Err(RegistryError::InvalidResponse(format!(
                "HTTP {} from {}",
                status, url
            )));
        }

        let npm_ver: NpmVersionMeta = response
            .json()
            .await
            .map_err(|e| RegistryError::InvalidResponse(e.to_string()))?;

        Self::convert_version(package, &npm_ver).ok_or_else(|| {
            RegistryError::InvalidResponse(format!(
                "failed to parse version metadata for {}@{}",
                package.display_name(),
                version
            ))
        })
    }

    fn artifact_url(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<url::Url, RegistryError> {
        tarball::tarball_url(&self.registry_url, package, version)
            .map_err(|e| RegistryError::InvalidResponse(e.to_string()))
    }

    async fn fetch_tuf_metadata(
        &self,
        _role: &str,
    ) -> Result<Option<SignedMetadata<JsonValue>>, RegistryError> {
        // npm does not currently support TUF.
        Ok(None)
    }

    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Js
    }

    fn registry_url(&self) -> &RegistryUrl {
        &self.registry_url
    }
}
