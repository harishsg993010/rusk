use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::fmt;

/// SHA-256 digest, the primary content-addressing hash.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Sha256Digest(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl Sha256Digest {
    /// Compute SHA-256 digest of data.
    pub fn compute(data: &[u8]) -> Self {
        let hash = sha2::Sha256::digest(data);
        Self(hash.into())
    }

    /// Create from hex string.
    pub fn from_hex(s: &str) -> Result<Self, DigestError> {
        let bytes = hex::decode(s).map_err(|_| DigestError::InvalidHex)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DigestError::InvalidLength { expected: 32 })?;
        Ok(Self(arr))
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Zero digest (used as placeholder/sentinel).
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// First two hex characters, used for sharded directory layout.
    pub fn shard_prefix(&self) -> String {
        hex::encode(&self.0[..1])
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", &self.to_hex()[..16])
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

/// BLAKE3 digest for fast hashing.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Blake3Digest(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl Blake3Digest {
    pub fn compute(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(*hash.as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, DigestError> {
        let bytes = hex::decode(s).map_err(|_| DigestError::InvalidHex)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| DigestError::InvalidLength { expected: 32 })?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for Blake3Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:{}", &self.to_hex()[..16])
    }
}

impl fmt::Display for Blake3Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:{}", self.to_hex())
    }
}

/// Digest algorithm selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum DigestAlgorithm {
    Sha256,
    Blake3,
}

/// Algorithm-agnostic digest.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct AnyDigest {
    pub algorithm: DigestAlgorithm,
    pub bytes: Vec<u8>,
}

impl AnyDigest {
    pub fn sha256(digest: Sha256Digest) -> Self {
        Self {
            algorithm: DigestAlgorithm::Sha256,
            bytes: digest.0.to_vec(),
        }
    }

    pub fn as_sha256(&self) -> Option<Sha256Digest> {
        if self.algorithm == DigestAlgorithm::Sha256 && self.bytes.len() == 32 {
            let arr: [u8; 32] = self.bytes[..32].try_into().ok()?;
            Some(Sha256Digest(arr))
        } else {
            None
        }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("invalid digest length: expected {expected} bytes")]
    InvalidLength { expected: usize },
}

/// Serde helper for fixed-size byte arrays as hex.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_roundtrip() {
        let data = b"hello world";
        let digest = Sha256Digest::compute(data);
        let hex = digest.to_hex();
        let parsed = Sha256Digest::from_hex(&hex).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn sha256_known_value() {
        let digest = Sha256Digest::compute(b"hello world");
        assert_eq!(
            digest.to_hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn blake3_roundtrip() {
        let data = b"hello world";
        let digest = Blake3Digest::compute(data);
        let hex = digest.to_hex();
        let parsed = Blake3Digest::from_hex(&hex).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn shard_prefix() {
        let digest = Sha256Digest::compute(b"test");
        let prefix = digest.shard_prefix();
        assert_eq!(prefix.len(), 2);
    }
}
