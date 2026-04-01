//! npm-specific metadata types.
//!
//! These types model the npm registry JSON API responses (the "packument"
//! format and individual version documents).

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// Custom deserializer for Optional<String> that tolerates booleans, numbers, etc.
fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::String(s) => Ok(Some(s)),
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Bool(false) => Ok(None),
        serde_json::Value::Bool(true) => Ok(Some("true".to_string())),
        serde_json::Value::Number(n) => Ok(Some(n.to_string())),
        _ => Ok(None),
    }
}

/// Custom deserializer for dependency maps that tolerates non-string values.
/// Some old npm packages have `{"dep": false}` or `{"dep": null}` instead of strings.
fn deserialize_dep_map<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: HashMap<String, serde_json::Value> = HashMap::deserialize(deserializer)?;
    let mut result = HashMap::new();
    for (key, value) in raw {
        match value {
            serde_json::Value::String(s) => { result.insert(key, s); }
            serde_json::Value::Bool(_) | serde_json::Value::Null => { /* skip */ }
            serde_json::Value::Number(n) => { result.insert(key, n.to_string()); }
            _ => { /* skip arrays/objects */ }
        }
    }
    Ok(result)
}

/// Custom deserializer for engines field that can be a map or a bare string.
fn deserialize_engines<'de, D>(deserializer: D) -> Result<Option<HashMap<String, String>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    struct EnginesVisitor;

    impl<'de> de::Visitor<'de> for EnginesVisitor {
        type Value = Option<HashMap<String, String>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a map, a string, an array, or null")
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let mut map = HashMap::new();
            map.insert("node".to_string(), v.to_string());
            Ok(Some(map))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            let mut map = HashMap::new();
            map.insert("node".to_string(), v);
            Ok(Some(map))
        }

        fn visit_seq<S: de::SeqAccess<'de>>(self, mut _seq: S) -> Result<Self::Value, S::Error> {
            // Some old packages have engines as an array — skip it
            while _seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(None)
        }

        fn visit_map<M: de::MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
            let mut map = HashMap::new();
            while let Some((key, value)) = access.next_entry::<String, String>()? {
                map.insert(key, value);
            }
            Ok(if map.is_empty() { None } else { Some(map) })
        }
    }

    deserializer.deserialize_any(EnginesVisitor)
}

/// Full npm package document ("packument") as returned by `GET /<package>`.
///
/// This is a large document containing all versions and metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmPackument {
    /// Package name (may include scope like "@scope/name").
    pub name: String,
    /// Description from the latest version.
    #[serde(default)]
    pub description: Option<String>,
    /// Dist-tags mapping (e.g., "latest" => "1.2.3").
    #[serde(rename = "dist-tags", default)]
    pub dist_tags: HashMap<String, String>,
    /// All version documents keyed by version string.
    #[serde(default)]
    pub versions: HashMap<String, NpmVersionMeta>,
    /// Last-modified time, if available.
    #[serde(default)]
    pub time: HashMap<String, String>,
}

/// Metadata for a single npm version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmVersionMeta {
    /// Package name.
    #[serde(default)]
    pub name: String,
    /// Version string.
    #[serde(default)]
    pub version: String,
    /// Description of this version.
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub description: Option<String>,
    /// Production dependencies: name => semver range.
    /// Some old packages have non-string values (boolean false), so we tolerate that.
    #[serde(default, deserialize_with = "deserialize_dep_map")]
    pub dependencies: HashMap<String, String>,
    /// Development dependencies.
    #[serde(rename = "devDependencies", default, deserialize_with = "deserialize_dep_map")]
    pub dev_dependencies: HashMap<String, String>,
    /// Peer dependencies.
    #[serde(rename = "peerDependencies", default, deserialize_with = "deserialize_dep_map")]
    pub peer_dependencies: HashMap<String, String>,
    /// Optional dependencies.
    #[serde(rename = "optionalDependencies", default, deserialize_with = "deserialize_dep_map")]
    pub optional_dependencies: HashMap<String, String>,
    /// Peer dependency metadata (which peers are optional).
    #[serde(rename = "peerDependenciesMeta", default)]
    pub peer_dependencies_meta: HashMap<String, PeerDepMeta>,
    /// Distribution metadata.
    #[serde(default)]
    pub dist: NpmDist,
    /// Node engines constraint (can be a map or sometimes a bare string in old packages).
    #[serde(default, deserialize_with = "deserialize_engines")]
    pub engines: Option<HashMap<String, String>>,
    /// Whether this version is deprecated (can be string message or boolean false).
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub deprecated: Option<String>,
    /// Has install scripts.
    #[serde(rename = "hasInstallScript", default)]
    pub has_install_script: Option<bool>,
    /// Catch-all for unknown fields that npm adds over time.
    #[serde(flatten)]
    pub _extra: HashMap<String, serde_json::Value>,
}

/// Peer dependency metadata entry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerDepMeta {
    #[serde(default)]
    pub optional: bool,
}

/// Distribution metadata for an npm version.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NpmDist {
    /// URL to the tarball.
    #[serde(default)]
    pub tarball: String,
    /// SHA-1 hex digest (legacy).
    #[serde(default)]
    pub shasum: String,
    /// Subresource integrity string (e.g., "sha512-...").
    #[serde(default)]
    pub integrity: Option<String>,
    /// Number of files in the tarball.
    #[serde(rename = "fileCount", default)]
    pub file_count: Option<u32>,
    /// Unpacked size in bytes.
    #[serde(rename = "unpackedSize", default)]
    pub unpacked_size: Option<u64>,
    /// npm signature, if present.
    #[serde(default)]
    pub signatures: Option<Vec<NpmSignature>>,
}

/// npm package signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmSignature {
    pub keyid: String,
    pub sig: String,
}

/// Response from the npm registry keys endpoint (`/-/npm/v1/keys`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmKeysResponse {
    pub keys: Vec<NpmRegistryKey>,
}

/// A public signing key published by the npm registry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmRegistryKey {
    /// Key identifier (e.g. "SHA256:...").
    pub keyid: String,
    /// Key type (e.g. "ecdsa-sha2-nistp256").
    pub keytype: String,
    /// Signature scheme (e.g. "ecdsa-sha2-nistp256").
    pub scheme: String,
    /// Base64-encoded public key (DER / SPKI).
    pub key: String,
    /// Optional expiration date (ISO 8601 or null).
    pub expires: Option<String>,
}

/// Response from the npm attestations endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmAttestations {
    pub attestations: Vec<NpmAttestation>,
}

/// A single attestation entry (Sigstore bundle).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NpmAttestation {
    /// Predicate type URI (e.g. "https://slsa.dev/provenance/v1").
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Sigstore bundle (opaque JSON).
    #[serde(default)]
    pub bundle: serde_json::Value,
}

impl NpmPackument {
    /// Get the version string for a given dist-tag (e.g., "latest").
    pub fn dist_tag_version(&self, tag: &str) -> Option<&str> {
        self.dist_tags.get(tag).map(|s| s.as_str())
    }

    /// Get publication time for a version, if recorded.
    pub fn published_at(&self, version: &str) -> Option<&str> {
        self.time.get(version).map(|s| s.as_str())
    }

    /// Check if a version has been deprecated.
    pub fn is_deprecated(&self, version: &str) -> bool {
        self.versions
            .get(version)
            .and_then(|v| v.deprecated.as_ref())
            .is_some()
    }
}

impl NpmVersionMeta {
    /// Whether this version has any install scripts (preinstall, install, postinstall).
    pub fn has_scripts(&self) -> bool {
        self.has_install_script.unwrap_or(false)
    }

    /// Whether this version is deprecated.
    pub fn is_deprecated(&self) -> bool {
        self.deprecated.is_some()
    }

    /// Total number of declared dependencies (all kinds).
    pub fn total_dep_count(&self) -> usize {
        self.dependencies.len()
            + self.dev_dependencies.len()
            + self.peer_dependencies.len()
            + self.optional_dependencies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_packument() {
        let json = r#"{
            "name": "express",
            "description": "Fast web framework",
            "dist-tags": { "latest": "4.18.2" },
            "versions": {
                "4.18.2": {
                    "name": "express",
                    "version": "4.18.2",
                    "dependencies": { "accepts": "~1.3.8" },
                    "dist": {
                        "tarball": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                        "shasum": "abc123"
                    }
                }
            },
            "time": {
                "4.18.2": "2022-10-08T20:00:00.000Z"
            }
        }"#;
        let doc: NpmPackument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.name, "express");
        assert_eq!(doc.dist_tag_version("latest"), Some("4.18.2"));
        let v = doc.versions.get("4.18.2").unwrap();
        assert_eq!(v.dependencies.len(), 1);
        assert!(!v.dist.tarball.is_empty());
    }

    #[test]
    fn deprecated_detection() {
        let meta = NpmVersionMeta {
            name: "old-pkg".to_string(),
            version: "1.0.0".to_string(),
            description: None,
            dependencies: HashMap::new(),
            dev_dependencies: HashMap::new(),
            peer_dependencies: HashMap::new(),
            optional_dependencies: HashMap::new(),
            peer_dependencies_meta: HashMap::new(),
            dist: NpmDist::default(),
            engines: None,
            deprecated: Some("Use new-pkg instead".to_string()),
            has_install_script: None,
        };
        assert!(meta.is_deprecated());
    }
}
