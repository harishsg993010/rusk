//! PyPI registry client for rusk.
//!
//! Implements the PyPI JSON API and Simple Repository API to fetch
//! package metadata, version listings, and wheel/sdist URLs. Translates
//! PyPI-specific types into the unified `rusk-registry` metadata types.
//!
//! # Modules
//!
//! - `api` - `PypiRegistryClient` implementing `RegistryClient`
//! - `metadata` - PyPI-specific wire types (PypiPackageIndex, PypiFile)
//! - `wheel` - Wheel filename parsing and compatibility checking
//! - `sdist` - Source distribution types and utilities

pub mod api;
pub mod metadata;
pub mod sdist;
pub mod wheel;

pub use api::PypiRegistryClient;
pub use metadata::{
    PypiAttestationBundle, PypiFile, PypiPackageIndex, PypiProvenance, PypiPublisher,
};
pub use wheel::WheelTags;
