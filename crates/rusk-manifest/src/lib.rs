//! Manifest parser for rusk project files.
//!
//! Parses, validates, and normalizes rusk.toml project manifests.
//!
//! # Modules
//!
//! - `schema` - All manifest types (Manifest, PackageMetadata, dependencies, etc.)
//! - `parser` - Loading and parsing rusk.toml files
//! - `validate` - Semantic validation beyond TOML structure
//! - `normalize` - Name normalization and default application

pub mod normalize;
pub mod parser;
pub mod schema;
pub mod validate;
pub mod workspace;

pub use normalize::normalize_manifest;
pub use parser::{find_manifest, load_manifest, parse_manifest, ParseError};
pub use schema::{
    BuildConfig, DependencyEntry, JsDependencies, Manifest, PackageMetadata, PythonDependencies,
    RegistryConfig, TrustConfig, WorkspaceConfig,
};
pub use validate::{validate_manifest, ValidationError, ValidationIssue, ValidationSeverity};
