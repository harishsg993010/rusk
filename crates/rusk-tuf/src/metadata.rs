use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Errors specific to TUF metadata parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum TufMetadataError {
    #[error("metadata has expired at {expiry}")]
    Expired { expiry: DateTime<Utc> },

    #[error("version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u64, actual: u64 },

    #[error("unknown role: {0}")]
    UnknownRole(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// TUF role types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TufRole {
    Root,
    Timestamp,
    Snapshot,
    Targets,
}

impl TufRole {
    /// Return the canonical filename for this role.
    pub fn filename(&self) -> &'static str {
        match self {
            TufRole::Root => "root.json",
            TufRole::Timestamp => "timestamp.json",
            TufRole::Snapshot => "snapshot.json",
            TufRole::Targets => "targets.json",
        }
    }

    /// Parse a role from its string name.
    pub fn from_name(name: &str) -> Result<Self, TufMetadataError> {
        match name {
            "root" => Ok(TufRole::Root),
            "timestamp" => Ok(TufRole::Timestamp),
            "snapshot" => Ok(TufRole::Snapshot),
            "targets" => Ok(TufRole::Targets),
            other => Err(TufMetadataError::UnknownRole(other.to_string())),
        }
    }
}

impl fmt::Display for TufRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TufRole::Root => write!(f, "root"),
            TufRole::Timestamp => write!(f, "timestamp"),
            TufRole::Snapshot => write!(f, "snapshot"),
            TufRole::Targets => write!(f, "targets"),
        }
    }
}

/// A cryptographic signature in TUF metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TufSignature {
    /// Hex-encoded key ID (typically the SHA-256 of the public key canonical form).
    pub keyid: String,
    /// Hex-encoded signature bytes.
    pub sig: String,
}

impl TufSignature {
    /// Decode the raw signature bytes from hex.
    pub fn sig_bytes(&self) -> Result<Vec<u8>, TufMetadataError> {
        hex::decode(&self.sig).map_err(|e| {
            TufMetadataError::MissingField(format!("invalid signature hex: {e}"))
        })
    }
}

/// Supported key types in TUF metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TufKeyType {
    Ed25519,
    EcdsaSha2Nistp256,
    Rsa,
}

/// Supported signature schemes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TufKeyScheme {
    Ed25519,
    EcdsaSha2Nistp256,
    RsassaPssSha256,
}

/// A public key definition in TUF metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TufKey {
    pub keytype: TufKeyType,
    pub scheme: TufKeyScheme,
    pub keyval: TufKeyValue,
}

/// The value portion of a TUF key (public key material).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TufKeyValue {
    /// Hex-encoded public key bytes.
    pub public: String,
}

impl TufKey {
    /// Compute the canonical key ID (SHA-256 of canonical JSON representation).
    pub fn key_id(&self) -> String {
        // Per TUF spec, key ID is the hex digest of the canonical JSON of the key.
        let canonical = serde_json::json!({
            "keytype": self.keytype,
            "scheme": self.scheme,
            "keyval": {
                "public": self.keyval.public,
            }
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        let digest = rusk_core::Sha256Digest::compute(&bytes);
        digest.to_hex()
    }

    /// Decode the raw public key bytes from hex.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, TufMetadataError> {
        hex::decode(&self.keyval.public).map_err(|e| {
            TufMetadataError::MissingField(format!("invalid public key hex: {e}"))
        })
    }
}

/// Role definition specifying threshold and authorized key IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoleDefinition {
    /// Minimum number of valid signatures required.
    pub threshold: u32,
    /// Key IDs authorized to sign this role.
    pub keyids: Vec<String>,
}

impl RoleDefinition {
    /// Check whether a given key ID is authorized for this role.
    pub fn is_authorized(&self, key_id: &str) -> bool {
        self.keyids.iter().any(|k| k == key_id)
    }
}

/// Metadata about a referenced metadata file (used in timestamp/snapshot).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetaFileInfo {
    /// Expected length in bytes.
    pub length: Option<u64>,
    /// Map of hash algorithm name to hex digest.
    pub hashes: HashMap<String, String>,
    /// Expected version number of the referenced metadata.
    pub version: u64,
}

impl MetaFileInfo {
    /// Verify that the given bytes match the expected hashes.
    pub fn verify_hashes(&self, data: &[u8]) -> bool {
        for (algo, expected_hex) in &self.hashes {
            match algo.as_str() {
                "sha256" => {
                    let computed = rusk_core::Sha256Digest::compute(data);
                    if computed.to_hex() != *expected_hex {
                        return false;
                    }
                }
                _ => {
                    // Unknown algorithm - we skip it per the TUF spec
                    // (client MUST verify all hashes it understands)
                    tracing::warn!(algorithm = %algo, "skipping unknown hash algorithm");
                }
            }
        }
        true
    }

    /// Verify the length constraint if present.
    pub fn verify_length(&self, data: &[u8]) -> bool {
        match self.length {
            Some(expected) => data.len() as u64 == expected,
            None => true,
        }
    }
}

/// Information about a target file in the targets metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Expected length in bytes.
    pub length: u64,
    /// Map of hash algorithm name to hex digest.
    pub hashes: HashMap<String, String>,
    /// Optional custom metadata attached to this target.
    #[serde(default)]
    pub custom: Option<serde_json::Value>,
}

impl TargetInfo {
    /// Verify that downloaded target bytes match expected hashes and length.
    pub fn verify(&self, data: &[u8]) -> bool {
        if data.len() as u64 != self.length {
            return false;
        }
        for (algo, expected_hex) in &self.hashes {
            match algo.as_str() {
                "sha256" => {
                    let computed = rusk_core::Sha256Digest::compute(data);
                    if computed.to_hex() != *expected_hex {
                        return false;
                    }
                }
                _ => {
                    tracing::warn!(algorithm = %algo, "skipping unknown hash algorithm in target");
                }
            }
        }
        true
    }
}

/// A delegated role within the targets delegation hierarchy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DelegatedRole {
    /// Name of the delegated role.
    pub name: String,
    /// Key IDs authorized to sign this delegated role.
    pub keyids: Vec<String>,
    /// Signature threshold.
    pub threshold: u32,
    /// If true, stop searching after this delegation (regardless of match).
    #[serde(default)]
    pub terminating: bool,
    /// Target path patterns this delegation covers (glob-style).
    pub paths: Vec<String>,
}

impl DelegatedRole {
    /// Check if a target path matches any of this delegation's path patterns.
    pub fn matches_path(&self, target_path: &str) -> bool {
        self.paths.iter().any(|pattern| {
            // Simple glob matching: "*" matches everything, otherwise prefix match
            if pattern == "*" {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix("/*") {
                target_path.starts_with(prefix)
            } else {
                target_path == pattern
            }
        })
    }
}

/// Delegations block within targets metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delegations {
    /// Keys used by delegated roles.
    pub keys: HashMap<String, TufKey>,
    /// Ordered list of delegated roles.
    pub roles: Vec<DelegatedRole>,
}

/// Signed metadata envelope: wraps any role metadata with signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMetadata<T> {
    /// The signatures over the canonical JSON of `signed`.
    pub signatures: Vec<TufSignature>,
    /// The role metadata payload.
    pub signed: T,
}

impl<T: Serialize> SignedMetadata<T> {
    /// Serialize the `signed` field to canonical JSON bytes for signature verification.
    pub fn canonical_signed_bytes(&self) -> Result<Vec<u8>, TufMetadataError> {
        serde_json::to_vec(&self.signed).map_err(TufMetadataError::Json)
    }
}

/// Common fields shared by all role metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonMetadata {
    /// Metadata spec version.
    #[serde(rename = "spec_version")]
    pub spec_version: String,
    /// Metadata version number (monotonically increasing).
    pub version: u64,
    /// Expiration timestamp.
    pub expires: DateTime<Utc>,
}

impl CommonMetadata {
    /// Check whether this metadata has expired relative to the given time.
    pub fn is_expired_at(&self, now: &DateTime<Utc>) -> bool {
        self.expires < *now
    }
}

/// Root role metadata: defines the keys and thresholds for all top-level roles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RootMetadata {
    #[serde(flatten)]
    pub common: CommonMetadata,

    /// Whether this root file is consistent-snapshot enabled.
    #[serde(default)]
    pub consistent_snapshot: bool,

    /// All known keys, keyed by key ID.
    pub keys: HashMap<String, TufKey>,

    /// Role definitions: maps role name to its threshold + authorized key IDs.
    pub roles: HashMap<String, RoleDefinition>,
}

impl RootMetadata {
    /// Get the role definition for a specific TUF role.
    pub fn role_definition(&self, role: TufRole) -> Option<&RoleDefinition> {
        self.roles.get(&role.to_string())
    }

    /// Look up a key by its ID.
    pub fn key(&self, key_id: &str) -> Option<&TufKey> {
        self.keys.get(key_id)
    }

    /// Validate internal consistency: all role keyids reference known keys.
    pub fn validate(&self) -> Result<(), TufMetadataError> {
        for (role_name, role_def) in &self.roles {
            for kid in &role_def.keyids {
                if !self.keys.contains_key(kid) {
                    return Err(TufMetadataError::MissingField(format!(
                        "role '{}' references unknown key ID '{}'",
                        role_name, kid
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Timestamp role metadata: points to the current snapshot metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimestampMetadata {
    #[serde(flatten)]
    pub common: CommonMetadata,

    /// Information about the snapshot metadata file.
    pub meta: HashMap<String, MetaFileInfo>,
}

impl TimestampMetadata {
    /// Get the snapshot metadata file info.
    pub fn snapshot_meta(&self) -> Option<&MetaFileInfo> {
        self.meta.get("snapshot.json")
    }
}

/// Snapshot role metadata: maps all metadata files to their expected versions and hashes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    #[serde(flatten)]
    pub common: CommonMetadata,

    /// Information about each tracked metadata file.
    pub meta: HashMap<String, MetaFileInfo>,
}

impl SnapshotMetadata {
    /// Get the expected version for a given metadata file.
    pub fn expected_version(&self, filename: &str) -> Option<u64> {
        self.meta.get(filename).map(|m| m.version)
    }
}

/// Targets role metadata: lists all target files and optional delegations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetsMetadata {
    #[serde(flatten)]
    pub common: CommonMetadata,

    /// Target files, keyed by target path.
    pub targets: HashMap<String, TargetInfo>,

    /// Optional delegations to sub-roles.
    #[serde(default)]
    pub delegations: Option<Delegations>,
}

impl TargetsMetadata {
    /// Look up info for a specific target path.
    pub fn target(&self, path: &str) -> Option<&TargetInfo> {
        self.targets.get(path)
    }

    /// Check if this targets metadata has delegations.
    pub fn has_delegations(&self) -> bool {
        self.delegations
            .as_ref()
            .map_or(false, |d| !d.roles.is_empty())
    }
}

/// Use hex crate for decoding (re-exported through rusk-core's dependency chain).
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
        ::hex::decode(s).map_err(|_| HexError)
    }

    #[derive(Debug)]
    pub struct HexError;

    impl std::fmt::Display for HexError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "hex decode error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_filenames() {
        assert_eq!(TufRole::Root.filename(), "root.json");
        assert_eq!(TufRole::Timestamp.filename(), "timestamp.json");
        assert_eq!(TufRole::Snapshot.filename(), "snapshot.json");
        assert_eq!(TufRole::Targets.filename(), "targets.json");
    }

    #[test]
    fn role_roundtrip() {
        for role in &[TufRole::Root, TufRole::Timestamp, TufRole::Snapshot, TufRole::Targets] {
            let name = role.to_string();
            let parsed = TufRole::from_name(&name).unwrap();
            assert_eq!(*role, parsed);
        }
    }

    #[test]
    fn role_definition_authorized() {
        let rd = RoleDefinition {
            threshold: 2,
            keyids: vec!["abc123".to_string(), "def456".to_string()],
        };
        assert!(rd.is_authorized("abc123"));
        assert!(!rd.is_authorized("zzz999"));
    }

    #[test]
    fn delegated_role_path_matching() {
        let dr = DelegatedRole {
            name: "delegated".to_string(),
            keyids: vec![],
            threshold: 1,
            terminating: false,
            paths: vec!["packages/*".to_string(), "special-target".to_string()],
        };
        assert!(dr.matches_path("packages/foo"));
        assert!(dr.matches_path("special-target"));
        assert!(!dr.matches_path("other/bar"));
    }

    #[test]
    fn meta_file_info_length_check() {
        let mfi = MetaFileInfo {
            length: Some(5),
            hashes: HashMap::new(),
            version: 1,
        };
        assert!(mfi.verify_length(b"hello"));
        assert!(!mfi.verify_length(b"hi"));

        let mfi_no_len = MetaFileInfo {
            length: None,
            hashes: HashMap::new(),
            version: 1,
        };
        assert!(mfi_no_len.verify_length(b"anything"));
    }

    #[test]
    fn common_metadata_expiry() {
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let now = chrono::Utc::now();

        let expired = CommonMetadata {
            spec_version: "1.0.31".to_string(),
            version: 1,
            expires: past,
        };
        assert!(expired.is_expired_at(&now));

        let valid = CommonMetadata {
            spec_version: "1.0.31".to_string(),
            version: 1,
            expires: future,
        };
        assert!(!valid.is_expired_at(&now));
    }
}
