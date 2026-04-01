use crate::attestation::{AttestationError, InTotoStatement};
use chrono::{DateTime, Utc};
use rusk_core::{BuilderIdentity, Sha256Digest};
use serde::{Deserialize, Serialize};
use url::Url;

/// Errors during provenance normalization.
#[derive(Debug, thiserror::Error)]
pub enum NormalizeError {
    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid source URI: {0}")]
    InvalidSourceUri(String),

    #[error("unsupported predicate type: {0}")]
    UnsupportedPredicateType(String),

    #[error("attestation error: {0}")]
    Attestation(#[from] AttestationError),
}

/// A subject (artifact) in the normalized provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenanceSubject {
    /// Artifact name/path.
    pub name: String,
    /// SHA-256 digest of the artifact.
    pub sha256: Sha256Digest,
}

/// Source code repository information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenanceSource {
    /// Full repository URI (e.g., "https://github.com/owner/repo").
    pub repository_url: Url,
    /// Git reference (e.g., "refs/heads/main", "refs/tags/v1.0.0").
    pub git_ref: Option<String>,
    /// Git commit SHA.
    pub commit_sha: Option<String>,
}

/// Build system identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenanceBuilder {
    /// The builder identity for verification.
    pub identity: BuilderIdentity,
    /// Builder version string if available.
    pub version: Option<String>,
}

/// Build configuration details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvBuildConfig {
    /// Build command or entrypoint.
    pub command: Option<String>,
    /// Environment variables (non-sensitive).
    pub environment: std::collections::HashMap<String, String>,
    /// Whether the build was performed in a hermetic environment.
    pub hermetic: bool,
    /// Whether the build is reproducible.
    pub reproducible: bool,
}

impl Default for ProvBuildConfig {
    fn default() -> Self {
        Self {
            command: None,
            environment: std::collections::HashMap::new(),
            hermetic: false,
            reproducible: false,
        }
    }
}

/// A build input material (dependency or tool).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvMaterial {
    /// URI of the material.
    pub uri: String,
    /// Digest of the material (if available).
    pub digest: Option<Sha256Digest>,
}

/// Additional metadata about the provenance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvMetadata {
    /// When the build started.
    pub build_started: Option<DateTime<Utc>>,
    /// When the build finished.
    pub build_finished: Option<DateTime<Utc>>,
    /// SLSA build level achieved (0-4).
    pub slsa_level: Option<u8>,
    /// Raw predicate type for reference.
    pub predicate_type: String,
}

/// Ecosystem-agnostic normalized provenance extracted from an in-toto statement.
///
/// This flattens the varying SLSA predicate formats into a uniform structure
/// that downstream policy evaluation can reason about.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NormalizedProvenance {
    /// The artifacts this provenance covers.
    pub subjects: Vec<ProvenanceSubject>,
    /// Source code origin.
    pub source: Option<ProvenanceSource>,
    /// The builder that produced the artifact.
    pub builder: ProvenanceBuilder,
    /// Build configuration.
    pub build_config: ProvBuildConfig,
    /// Input materials consumed by the build.
    pub materials: Vec<ProvMaterial>,
    /// Additional metadata.
    pub metadata: ProvMetadata,
}

impl NormalizedProvenance {
    /// Normalize an in-toto statement into our canonical representation.
    pub fn from_statement(statement: &InTotoStatement) -> Result<Self, NormalizeError> {
        // Extract subjects.
        let subjects = normalize_subjects(statement)?;

        // Extract builder identity.
        let builder_id = statement
            .slsa_builder_id()
            .ok_or_else(|| NormalizeError::MissingField("builder.id".to_string()))?;

        let builder_type = infer_builder_type(&builder_id);
        let builder = ProvenanceBuilder {
            identity: BuilderIdentity {
                builder_type,
                builder_id: builder_id.clone(),
            },
            version: extract_builder_version(&statement.predicate),
        };

        // Extract source.
        let source = normalize_source(statement);

        // Extract build config.
        let build_config = normalize_build_config(statement);

        // Extract materials.
        let materials = normalize_materials(statement);

        // Extract metadata.
        let metadata = ProvMetadata {
            build_started: statement.build_timestamp(),
            build_finished: extract_build_finished(&statement.predicate),
            slsa_level: infer_slsa_level(statement),
            predicate_type: statement.predicate_type.clone(),
        };

        Ok(NormalizedProvenance {
            subjects,
            source,
            builder,
            build_config,
            materials,
            metadata,
        })
    }

    /// Check if this provenance covers a specific artifact digest.
    pub fn covers_digest(&self, digest: &Sha256Digest) -> bool {
        self.subjects.iter().any(|s| s.sha256 == *digest)
    }
}

fn normalize_subjects(statement: &InTotoStatement) -> Result<Vec<ProvenanceSubject>, NormalizeError> {
    let mut subjects = Vec::new();
    for s in &statement.subject {
        let sha256_hex = s.digest.get("sha256").ok_or_else(|| {
            NormalizeError::MissingField(format!("subject '{}' missing sha256 digest", s.name))
        })?;
        let sha256 = Sha256Digest::from_hex(sha256_hex).map_err(|e| {
            NormalizeError::MissingField(format!("invalid sha256 for '{}': {e}", s.name))
        })?;
        subjects.push(ProvenanceSubject {
            name: s.name.clone(),
            sha256,
        });
    }
    Ok(subjects)
}

fn normalize_source(statement: &InTotoStatement) -> Option<ProvenanceSource> {
    let uri = statement.slsa_source_uri()?;

    // Parse "git+https://github.com/owner/repo@refs/heads/main" format.
    let clean_uri = uri.strip_prefix("git+").unwrap_or(&uri);
    let (repo_url_str, git_ref) = if let Some((url_part, ref_part)) = clean_uri.split_once('@') {
        (url_part, Some(ref_part.to_string()))
    } else {
        (clean_uri, None)
    };

    let repository_url = Url::parse(repo_url_str).ok()?;

    // Try to extract commit SHA from the predicate.
    let commit_sha = statement
        .predicate
        .get("buildDefinition")
        .and_then(|bd| bd.get("resolvedDependencies"))
        .and_then(|deps| deps.as_array())
        .and_then(|arr| arr.first())
        .and_then(|dep| dep.get("digest"))
        .and_then(|d| d.get("sha1"))
        .and_then(|s| s.as_str())
        .or_else(|| {
            statement
                .predicate
                .get("materials")
                .and_then(|m| m.as_array())
                .and_then(|arr| arr.first())
                .and_then(|mat| mat.get("digest"))
                .and_then(|d| d.get("sha1"))
                .and_then(|s| s.as_str())
        })
        .map(|s| s.to_string());

    Some(ProvenanceSource {
        repository_url,
        git_ref,
        commit_sha,
    })
}

fn normalize_build_config(statement: &InTotoStatement) -> ProvBuildConfig {
    let hermetic = statement
        .predicate
        .get("runDetails")
        .and_then(|rd| rd.get("metadata"))
        .and_then(|m| m.get("invocationId"))
        .is_some();

    ProvBuildConfig {
        command: None,
        environment: std::collections::HashMap::new(),
        hermetic,
        reproducible: false,
    }
}

fn normalize_materials(statement: &InTotoStatement) -> Vec<ProvMaterial> {
    // SLSA v1: predicate.buildDefinition.resolvedDependencies
    let deps = statement
        .predicate
        .get("buildDefinition")
        .and_then(|bd| bd.get("resolvedDependencies"))
        .and_then(|deps| deps.as_array())
        .or_else(|| {
            // SLSA v0.2: predicate.materials
            statement
                .predicate
                .get("materials")
                .and_then(|m| m.as_array())
        });

    match deps {
        Some(arr) => arr
            .iter()
            .filter_map(|dep| {
                let uri = dep.get("uri").and_then(|u| u.as_str())?.to_string();
                let digest = dep
                    .get("digest")
                    .and_then(|d| d.get("sha256"))
                    .and_then(|h| h.as_str())
                    .and_then(|hex| Sha256Digest::from_hex(hex).ok());
                Some(ProvMaterial { uri, digest })
            })
            .collect(),
        None => Vec::new(),
    }
}

fn infer_builder_type(builder_id: &str) -> String {
    if builder_id.contains("github.com") {
        "github-actions".to_string()
    } else if builder_id.contains("gitlab") {
        "gitlab-ci".to_string()
    } else if builder_id.contains("cloud.google.com") || builder_id.contains("cloudbuild") {
        "google-cloud-build".to_string()
    } else {
        "unknown".to_string()
    }
}

fn extract_builder_version(predicate: &serde_json::Value) -> Option<String> {
    predicate
        .get("runDetails")
        .and_then(|rd| rd.get("builder"))
        .and_then(|b| b.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn extract_build_finished(predicate: &serde_json::Value) -> Option<DateTime<Utc>> {
    let ts_str = predicate
        .get("runDetails")
        .and_then(|rd| rd.get("metadata"))
        .and_then(|m| m.get("finishedOn"))
        .and_then(|t| t.as_str())
        .or_else(|| {
            predicate
                .get("metadata")
                .and_then(|m| m.get("buildFinishedOn"))
                .and_then(|t| t.as_str())
        })?;
    ts_str.parse().ok()
}

fn infer_slsa_level(statement: &InTotoStatement) -> Option<u8> {
    // Try to get from predicate metadata.
    statement
        .predicate
        .get("buildDefinition")
        .and_then(|bd| bd.get("buildType"))
        .and_then(|bt| bt.as_str())
        .and_then(|bt| {
            if bt.contains("/v1") {
                Some(3) // SLSA v1 build types are typically L3
            } else {
                Some(2)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::InTotoSubject;
    use std::collections::HashMap;

    fn make_slsa_v1_statement() -> InTotoStatement {
        let digest_hex = Sha256Digest::compute(b"artifact").to_hex();
        InTotoStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject: vec![InTotoSubject {
                name: "pkg-1.0.0.tar.gz".to_string(),
                digest: {
                    let mut m = HashMap::new();
                    m.insert("sha256".to_string(), digest_hex);
                    m
                },
            }],
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            predicate: serde_json::json!({
                "buildDefinition": {
                    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                    "resolvedDependencies": [{
                        "uri": "git+https://github.com/owner/repo@refs/tags/v1.0.0",
                        "digest": { "sha1": "abc123" }
                    }]
                },
                "runDetails": {
                    "builder": {
                        "id": "https://github.com/actions/runner",
                        "version": "2.310.0"
                    },
                    "metadata": {
                        "startedOn": "2024-01-15T10:00:00Z",
                        "finishedOn": "2024-01-15T10:05:00Z",
                        "invocationId": "run-12345"
                    }
                }
            }),
        }
    }

    #[test]
    fn normalize_slsa_v1() {
        let statement = make_slsa_v1_statement();
        let normalized = NormalizedProvenance::from_statement(&statement).unwrap();

        assert_eq!(normalized.subjects.len(), 1);
        assert_eq!(normalized.subjects[0].name, "pkg-1.0.0.tar.gz");
        assert_eq!(normalized.builder.identity.builder_type, "github-actions");
        assert!(normalized.builder.version.is_some());
        assert!(normalized.source.is_some());

        let source = normalized.source.unwrap();
        assert!(source.repository_url.as_str().contains("owner/repo"));
        assert_eq!(source.commit_sha, Some("abc123".to_string()));
        assert!(normalized.metadata.build_started.is_some());
        assert!(normalized.metadata.build_finished.is_some());
    }

    #[test]
    fn covers_digest() {
        let statement = make_slsa_v1_statement();
        let normalized = NormalizedProvenance::from_statement(&statement).unwrap();

        let artifact_digest = Sha256Digest::compute(b"artifact");
        assert!(normalized.covers_digest(&artifact_digest));

        let other_digest = Sha256Digest::compute(b"other");
        assert!(!normalized.covers_digest(&other_digest));
    }

    #[test]
    fn infer_github_actions_builder() {
        assert_eq!(
            infer_builder_type("https://github.com/actions/runner"),
            "github-actions"
        );
        assert_eq!(
            infer_builder_type("https://gitlab.com/ci/runner"),
            "gitlab-ci"
        );
        assert_eq!(
            infer_builder_type("https://example.com/builder"),
            "unknown"
        );
    }
}
