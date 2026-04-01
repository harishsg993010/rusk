//! SLSA provenance predicate support.
//!
//! Parses and validates SLSA (Supply-chain Levels for Software Artifacts)
//! provenance predicates from in-toto attestations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SLSA provenance predicate (v1.0).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlsaPredicate {
    /// Build definition.
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    /// Run details.
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

/// SLSA build definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildDefinition {
    /// Build type URI (e.g., "https://slsa.dev/provenance/v1").
    #[serde(rename = "buildType")]
    pub build_type: String,
    /// External parameters that influenced the build.
    #[serde(rename = "externalParameters")]
    pub external_parameters: serde_json::Value,
    /// Internal parameters controlled by the builder.
    #[serde(rename = "internalParameters", default)]
    pub internal_parameters: serde_json::Value,
    /// Resolved dependencies used in the build.
    #[serde(rename = "resolvedDependencies", default)]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

/// SLSA run details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunDetails {
    /// Builder identity.
    pub builder: BuilderInfo,
    /// Build metadata.
    #[serde(default)]
    pub metadata: Option<BuildMetadata>,
}

/// Builder information in SLSA provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuilderInfo {
    /// Builder ID URI.
    pub id: String,
    /// Builder version.
    #[serde(default)]
    pub version: Option<HashMap<String, String>>,
}

/// Build metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildMetadata {
    /// Invocation ID.
    #[serde(rename = "invocationId", default)]
    pub invocation_id: Option<String>,
    /// When the build started.
    #[serde(rename = "startedOn", default)]
    pub started_on: Option<String>,
    /// When the build finished.
    #[serde(rename = "finishedOn", default)]
    pub finished_on: Option<String>,
}

/// A resource descriptor (used for dependencies and subjects).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceDescriptor {
    /// URI identifying the resource.
    #[serde(default)]
    pub uri: Option<String>,
    /// Digests of the resource.
    #[serde(default)]
    pub digest: HashMap<String, String>,
    /// Resource name.
    #[serde(default)]
    pub name: Option<String>,
}

/// SLSA build levels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum SlsaLevel {
    /// No provenance.
    L0,
    /// Provenance exists (but may not be signed).
    L1,
    /// Hosted, signed provenance from a known builder.
    L2,
    /// Hardened build platform with non-falsifiable provenance.
    L3,
}

/// Determine the SLSA level from a provenance predicate.
pub fn assess_slsa_level(predicate: &SlsaPredicate) -> SlsaLevel {
    // L1: provenance exists
    if predicate.build_definition.build_type.is_empty() {
        return SlsaLevel::L0;
    }

    // L2: known builder with hosted build
    let builder_id = &predicate.run_details.builder.id;
    let is_known_builder = builder_id.contains("github.com/actions")
        || builder_id.contains("gitlab.com")
        || builder_id.contains("cloud.google.com/build");

    if !is_known_builder {
        return SlsaLevel::L1;
    }

    // L3 requires additional platform hardening guarantees
    // that cannot be determined from the predicate alone
    SlsaLevel::L2
}
