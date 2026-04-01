//! Workspace resolution support.
//!
//! Handles resolving dependencies across multiple packages in a workspace
//! (monorepo), ensuring consistent versions across all workspace members.

use rusk_core::PackageId;
use std::collections::HashMap;

/// A workspace member with its own dependencies.
#[derive(Clone, Debug)]
pub struct WorkspaceMember {
    /// Package identity.
    pub package: PackageId,
    /// Direct dependencies of this member.
    pub dependencies: Vec<String>,
    /// Path to this member's manifest.
    pub manifest_path: String,
}

/// Workspace resolution context that tracks cross-member dependency sharing.
#[derive(Clone, Debug, Default)]
pub struct WorkspaceContext {
    /// All workspace members.
    pub members: Vec<WorkspaceMember>,
    /// Shared constraints across all members (version must be the same everywhere).
    pub shared_constraints: HashMap<String, String>,
}

impl WorkspaceContext {
    /// Create a new empty workspace context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a workspace member.
    pub fn add_member(&mut self, member: WorkspaceMember) {
        self.members.push(member);
    }

    /// Get all unique dependencies across the workspace.
    pub fn all_dependencies(&self) -> Vec<&str> {
        let mut deps: Vec<&str> = self
            .members
            .iter()
            .flat_map(|m| m.dependencies.iter().map(|d| d.as_str()))
            .collect();
        deps.sort();
        deps.dedup();
        deps
    }

    /// Number of workspace members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
}
