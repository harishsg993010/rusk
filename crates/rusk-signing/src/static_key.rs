//! Static key signature verification.
//!
//! Handles verification against pre-configured static public keys,
//! used for packages signed with long-lived keys (as opposed to
//! keyless/Sigstore signing).

use crate::verifier::{SignatureAlgorithm, SigningError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A configured static public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaticKey {
    /// Human-readable key name/label.
    pub name: String,
    /// The algorithm this key uses.
    pub algorithm: SignatureAlgorithm,
    /// Hex-encoded public key bytes.
    pub public_key_hex: String,
    /// Optional expiration date.
    pub expires: Option<String>,
    /// Package scopes this key is authorized for.
    pub scopes: Vec<String>,
}

/// A registry of static keys for verification.
#[derive(Clone, Debug, Default)]
pub struct StaticKeyRegistry {
    keys: HashMap<String, StaticKey>,
}

impl StaticKeyRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a key to the registry.
    pub fn add_key(&mut self, key: StaticKey) {
        self.keys.insert(key.name.clone(), key);
    }

    /// Look up a key by name.
    pub fn get(&self, name: &str) -> Option<&StaticKey> {
        self.keys.get(name)
    }

    /// Find keys authorized for a given package scope.
    pub fn keys_for_scope(&self, scope: &str) -> Vec<&StaticKey> {
        self.keys
            .values()
            .filter(|k| k.scopes.iter().any(|s| scope.starts_with(s) || s == "*"))
            .collect()
    }

    /// Number of registered keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
