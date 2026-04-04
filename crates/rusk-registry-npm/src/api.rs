//! npm registry API client implementation.
//!
//! Implements the `RegistryClient` trait for the npm registry protocol.

use crate::metadata::{
    NpmAttestations, NpmKeysResponse, NpmPackument, NpmRegistryKey, NpmSignature, NpmVersionMeta,
};
use crate::tarball;
use async_trait::async_trait;
use base64::Engine as _;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey};
use rusk_core::{Ecosystem, PackageId, RegistryUrl, Sha256Digest, Version};
use rusk_registry::{
    ArtifactInfo, ArtifactType, DependencyKind, DependencySpec, PackageMetadata, RegistryClient,
    RegistryError, VersionMetadata,
};
use rusk_tuf::SignedMetadata;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, instrument, warn};

/// npm registry client implementing the `RegistryClient` trait.
pub struct NpmRegistryClient {
    registry_url: RegistryUrl,
    http: reqwest::Client,
    /// Optional Bearer auth token for private registries (from .npmrc).
    auth_token: Option<String>,
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
            auth_token: None,
        }
    }

    /// Create a new client with a custom reqwest client (for testing/proxies).
    pub fn with_http_client(registry_url: RegistryUrl, http: reqwest::Client) -> Self {
        Self {
            registry_url,
            http,
            auth_token: None,
        }
    }

    /// Create a client for the default npm registry (registry.npmjs.org).
    pub fn default_registry() -> Self {
        Self::new(RegistryUrl::npm_default())
    }

    /// Set an auth token for private registry access.
    ///
    /// The token will be sent as a Bearer token in the Authorization header
    /// for all subsequent requests.
    pub fn with_auth(mut self, token: Option<String>) -> Self {
        self.auth_token = token;
        self
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

        let mut req = self
            .http
            .get(&url)
            .header("Accept", "application/json");
        if let Some(ref token) = self.auth_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req
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

    /// Fetch the public signing keys published by the npm registry.
    ///
    /// These keys are used to verify ECDSA signatures on package tarballs.
    /// Endpoint: `{registry_url}/-/npm/v1/keys`
    #[instrument(skip(self), fields(registry = %self.registry_url))]
    pub async fn fetch_registry_keys(&self) -> Result<Vec<NpmRegistryKey>, RegistryError> {
        let url = format!("{}/-/npm/v1/keys", self.registry_url.as_url());
        debug!(url = %url, "fetching npm registry keys");

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| RegistryError::Network(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(RegistryError::InvalidResponse(format!(
                "HTTP {} from {}",
                status, url
            )));
        }

        let keys_response: NpmKeysResponse = response
            .json()
            .await
            .map_err(|e| RegistryError::InvalidResponse(format!("error decoding keys: {e}")))?;

        debug!(count = keys_response.keys.len(), "fetched npm registry keys");
        Ok(keys_response.keys)
    }

    /// Verify an npm ECDSA-P256 signature for a package version.
    ///
    /// The signed message is `{package_name}@{version}:{integrity}`.
    /// The signature is verified against the registry key matching `signature.keyid`.
    pub fn verify_signature(
        package_name: &str,
        version: &str,
        integrity: &str,
        signature: &NpmSignature,
        registry_keys: &[NpmRegistryKey],
    ) -> Result<bool, String> {
        // 1. Find the matching key
        let key = registry_keys
            .iter()
            .find(|k| k.keyid == signature.keyid)
            .ok_or_else(|| {
                format!(
                    "no registry key found matching keyid {}",
                    signature.keyid
                )
            })?;

        // 2. Verify the key is an ECDSA P-256 key
        if key.keytype != "ecdsa-sha2-nistp256" {
            return Err(format!("unsupported key type: {}", key.keytype));
        }

        // 3. Construct the signed message: "{name}@{version}:{integrity}"
        let message = format!("{package_name}@{version}:{integrity}");

        // 4. Base64-decode the public key (SPKI / DER format)
        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_key_bytes = b64
            .decode(&key.key)
            .map_err(|e| format!("failed to base64-decode public key: {e}"))?;

        // 5. Parse the public key as a P-256 verifying key (SPKI DER)
        let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes)
            .or_else(|_| {
                // Try parsing as SPKI DER
                use p256::pkcs8::DecodePublicKey;
                VerifyingKey::from_public_key_der(&pub_key_bytes)
            })
            .map_err(|e| format!("failed to parse public key: {e}"))?;

        // 6. Decode the signature (base64)
        let sig_bytes = b64
            .decode(&signature.sig)
            .or_else(|_| {
                // Fall back to hex decoding
                hex::decode(&signature.sig)
                    .map_err(|e| base64::DecodeError::InvalidByte(0, e.to_string().as_bytes()[0]))
            })
            .map_err(|e| format!("failed to decode signature: {e}"))?;

        // 7. Parse as a DER-encoded ECDSA signature
        let ecdsa_sig = P256Signature::from_der(&sig_bytes)
            .or_else(|_| P256Signature::from_slice(&sig_bytes))
            .map_err(|e| format!("failed to parse ECDSA signature: {e}"))?;

        // 8. Verify: ECDSA-P256 signs over the raw message bytes (not hashed)
        //    npm uses the raw message for verification
        match verifying_key.verify(message.as_bytes(), &ecdsa_sig) {
            Ok(()) => Ok(true),
            Err(_) => {
                // Also try with SHA-256 hash of the message
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let hash = hasher.finalize();
                let hash_sig = P256Signature::from_der(&sig_bytes)
                    .or_else(|_| P256Signature::from_slice(&sig_bytes))
                    .map_err(|e| format!("failed to parse ECDSA signature: {e}"))?;
                match verifying_key.verify(&hash, &hash_sig) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }

    /// Fetch provenance attestations for a specific package version.
    ///
    /// Endpoint: `{registry_url}/-/npm/v1/attestations/{name}@{version}`
    #[instrument(skip(self), fields(registry = %self.registry_url))]
    pub async fn fetch_attestations(
        &self,
        package_name: &str,
        version: &str,
    ) -> Result<Option<NpmAttestations>, RegistryError> {
        // URL-encode scoped package names for the attestation endpoint
        let encoded_name = if package_name.starts_with('@') {
            package_name.replacen('/', "%2F", 1)
        } else {
            package_name.to_string()
        };
        let url = format!(
            "{}/-/npm/v1/attestations/{}@{}",
            self.registry_url.as_url(),
            encoded_name,
            version
        );
        debug!(url = %url, "fetching npm attestations");

        let response = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| RegistryError::Network(e.to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(RegistryError::InvalidResponse(format!(
                "HTTP {} from {}",
                status, url
            )));
        }

        let attestations: NpmAttestations = response
            .json()
            .await
            .map_err(|e| {
                RegistryError::InvalidResponse(format!("error decoding attestations: {e}"))
            })?;

        Ok(Some(attestations))
    }

    /// Convert a raw `NpmPackument` into a unified `PackageMetadata`.
    ///
    /// This is the same logic used internally by `fetch_package_metadata`,
    /// exposed for callers that need both the raw packument and the unified
    /// metadata (e.g., to extract npm-specific signature data).
    pub fn packument_to_metadata(
        package: &PackageId,
        packument: &NpmPackument,
    ) -> PackageMetadata {
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

        PackageMetadata {
            package: package.clone(),
            description: packument.description.clone(),
            versions,
            version_metadata,
            dist_tags,
        }
    }

    /// Fetch security advisories for a set of packages from the npm bulk advisory API.
    ///
    /// POSTs to `https://registry.npmjs.org/-/npm/v1/security/advisories/bulk`
    /// with a JSON body mapping package names to arrays of installed versions.
    /// Returns a flat list of [`Advisory`] objects for any known vulnerabilities.
    ///
    /// Network errors are returned as `RegistryError::Network` so callers can
    /// treat audit failures as non-fatal.
    #[instrument(skip(self, packages), fields(count = packages.len()))]
    pub async fn fetch_advisories(
        &self,
        packages: &[(String, String)], // (name, version) pairs
    ) -> Result<Vec<Advisory>, RegistryError> {
        // Build the request body: { "pkg": ["1.0.0"], "other": ["2.3.4"] }
        let mut body: HashMap<String, Vec<String>> = HashMap::new();
        for (name, version) in packages {
            body.entry(name.clone())
                .or_default()
                .push(version.clone());
        }

        let url = format!(
            "{}/-/npm/v1/security/advisories/bulk",
            self.registry_url.as_url()
        );
        debug!(url = %url, "fetching npm security advisories");

        let response = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| RegistryError::Network(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(RegistryError::InvalidResponse(format!(
                "HTTP {} from {}",
                status, url
            )));
        }

        let raw: serde_json::Value = response
            .json()
            .await
            .map_err(|e| RegistryError::InvalidResponse(format!("error decoding advisories: {e}")))?;

        let mut advisories = Vec::new();

        // The response is a JSON object keyed by advisory ID (numeric string).
        // Each value is an advisory object.
        if let Some(obj) = raw.as_object() {
            for (_key, value) in obj {
                let id = value.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let title = value
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let severity = value
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("moderate")
                    .to_string();
                let url_str = value
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let vulnerable_versions = value
                    .get("vulnerable_versions")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_string();
                let package_name = value
                    .get("module_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                advisories.push(Advisory {
                    id,
                    title,
                    severity,
                    url: url_str,
                    vulnerable_versions,
                    package_name,
                });
            }
        }

        Ok(advisories)
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

/// A security advisory returned by the npm bulk advisory endpoint.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Advisory {
    /// Advisory ID from the npm registry.
    pub id: u64,
    /// Human-readable title describing the vulnerability.
    pub title: String,
    /// Severity level: "critical", "high", "moderate", or "low".
    pub severity: String,
    /// URL to the full advisory details.
    pub url: String,
    /// Semver range of versions affected (e.g. "<2.1.4").
    pub vulnerable_versions: String,
    /// Name of the affected package.
    pub package_name: String,
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

        let mut req = self
            .http
            .get(&url)
            .header("Accept", "application/json");
        if let Some(ref token) = self.auth_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req
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
