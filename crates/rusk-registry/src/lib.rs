//! Registry client abstraction for rusk.
//!
//! Provides traits and types for interacting with package registries
//! (npm, PyPI) in a unified manner. Registry-specific implementations
//! live in `rusk-registry-npm` and `rusk-registry-pypi`.
//!
//! # Modules
//!
//! - `client` - The `RegistryClient` trait and error types
//! - `metadata` - Unified metadata types (PackageMetadata, VersionMetadata, etc.)
//! - `cache` - In-memory metadata cache with TTL

pub mod cache;
pub mod client;
pub mod metadata;

pub use cache::MetadataCache;
pub use client::{RegistryClient, RegistryError};
pub use metadata::{
    ArtifactInfo, ArtifactType, DependencyKind, DependencySpec, PackageMetadata, VersionMetadata,
};
