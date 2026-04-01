//! Workspace manifest support.
//!
//! Handles multi-package workspaces where a root rusk.toml defines
//! multiple member packages with shared configuration.

use std::path::{Path, PathBuf};

/// A workspace definition from the root rusk.toml.
#[derive(Clone, Debug)]
pub struct Workspace {
    /// Root directory of the workspace.
    pub root: PathBuf,
    /// Member package directories (relative to root).
    pub members: Vec<String>,
    /// Shared dependency overrides.
    pub shared_dependencies: Vec<SharedDependency>,
}

/// A shared dependency constraint across workspace members.
#[derive(Clone, Debug)]
pub struct SharedDependency {
    /// Package name.
    pub name: String,
    /// Version constraint shared across all members.
    pub version: String,
}

/// Discover workspace members by resolving glob patterns.
pub fn discover_members(root: &Path, patterns: &[String]) -> Vec<PathBuf> {
    let mut members = Vec::new();

    for pattern in patterns {
        let full_pattern = root.join(pattern).join("rusk.toml");
        if let Ok(entries) = glob::glob(&full_pattern.to_string_lossy()) {
            for entry in entries.flatten() {
                if let Some(parent) = entry.parent() {
                    members.push(parent.to_path_buf());
                }
            }
        }
    }

    members.sort();
    members.dedup();
    members
}

/// Validate that all workspace members exist and have valid manifests.
pub fn validate_workspace(workspace: &Workspace) -> Vec<String> {
    let mut errors = Vec::new();

    for member in &workspace.members {
        let member_path = workspace.root.join(member);
        if !member_path.exists() {
            errors.push(format!("workspace member directory not found: {member}"));
            continue;
        }

        let manifest = member_path.join("rusk.toml");
        if !manifest.exists() {
            errors.push(format!("workspace member missing rusk.toml: {member}"));
        }
    }

    errors
}
