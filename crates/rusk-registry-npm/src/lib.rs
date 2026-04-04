//! npm registry client for rusk.
//!
//! Implements the npm registry protocol to fetch package metadata,
//! version listings, and tarball URLs. Translates npm-specific types
//! into the unified `rusk-registry` metadata types.
//!
//! # Modules
//!
//! - `api` - `NpmRegistryClient` implementing `RegistryClient`
//! - `metadata` - npm-specific wire types (NpmPackument, NpmVersionMeta, NpmDist)
//! - `tarball` - Tarball URL construction and parsing

pub mod api;
pub mod metadata;
pub mod npmrc;
pub mod tarball;

pub use api::{Advisory, NpmRegistryClient};
pub use metadata::{
    NpmAttestation, NpmAttestations, NpmDist, NpmKeysResponse, NpmPackument, NpmRegistryKey,
    NpmSignature, NpmVersionMeta,
};
pub use npmrc::{find_token_for_registry, parse_npmrc, NpmrcConfig, NpmrcEntry};
