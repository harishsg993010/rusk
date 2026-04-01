use crate::metadata::{Delegations, TargetsMetadata, TargetInfo, TufKey};
use std::collections::HashMap;

/// Errors during delegation tree resolution.
#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("maximum delegation depth ({max_depth}) exceeded")]
    MaxDepthExceeded { max_depth: usize },

    #[error("delegation cycle detected involving role '{0}'")]
    CycleDetected(String),

    #[error("delegated role '{0}' not found")]
    RoleNotFound(String),

    #[error("target '{0}' not found in any delegation")]
    TargetNotFound(String),
}

/// A resolved delegation: the target info and the chain of roles that led to it.
#[derive(Clone, Debug)]
pub struct ResolvedDelegation {
    /// The target information found.
    pub target: TargetInfo,
    /// The chain of role names traversed to find this target (from root targets to leaf).
    pub delegation_chain: Vec<String>,
    /// The keys that were authorized at each level.
    pub authorized_keys: Vec<Vec<String>>,
}

/// Visitor callback used during delegation tree traversal.
///
/// Implementors provide the actual metadata loading (from local store or network)
/// for delegated roles on demand.
pub trait DelegationVisitor {
    /// Load the targets metadata for the given delegated role name.
    fn load_delegated_targets(
        &self,
        role_name: &str,
    ) -> Result<TargetsMetadata, DelegationError>;
}

/// The delegation tree resolver: walks the TUF delegation hierarchy to find
/// target information.
pub struct DelegationTree {
    /// Maximum delegation depth to prevent unbounded recursion.
    max_depth: usize,
}

impl DelegationTree {
    /// Create a new delegation tree resolver with the given maximum depth.
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Create with default max depth of 32.
    pub fn default_depth() -> Self {
        Self { max_depth: 32 }
    }

    /// Resolve a target path starting from the top-level targets metadata.
    ///
    /// Walks the delegation hierarchy using depth-first search, respecting
    /// terminating delegations and path patterns.
    pub fn resolve(
        &self,
        target_path: &str,
        top_level_targets: &TargetsMetadata,
        visitor: &dyn DelegationVisitor,
    ) -> Result<ResolvedDelegation, DelegationError> {
        // First check the top-level targets.
        if let Some(target) = top_level_targets.target(target_path) {
            return Ok(ResolvedDelegation {
                target: target.clone(),
                delegation_chain: vec!["targets".to_string()],
                authorized_keys: vec![],
            });
        }

        // Walk delegations if present.
        let delegations = match &top_level_targets.delegations {
            Some(d) => d,
            None => return Err(DelegationError::TargetNotFound(target_path.to_string())),
        };

        let mut visited = std::collections::HashSet::new();
        visited.insert("targets".to_string());

        let mut chain = vec!["targets".to_string()];
        let mut key_chain = Vec::new();

        self.walk_delegations(
            target_path,
            delegations,
            visitor,
            &mut visited,
            &mut chain,
            &mut key_chain,
            0,
        )
    }

    fn walk_delegations(
        &self,
        target_path: &str,
        delegations: &Delegations,
        visitor: &dyn DelegationVisitor,
        visited: &mut std::collections::HashSet<String>,
        chain: &mut Vec<String>,
        key_chain: &mut Vec<Vec<String>>,
        depth: usize,
    ) -> Result<ResolvedDelegation, DelegationError> {
        if depth >= self.max_depth {
            return Err(DelegationError::MaxDepthExceeded {
                max_depth: self.max_depth,
            });
        }

        for role in &delegations.roles {
            // Check if this delegation covers the target path.
            if !role.matches_path(target_path) {
                continue;
            }

            // Cycle detection.
            if visited.contains(&role.name) {
                return Err(DelegationError::CycleDetected(role.name.clone()));
            }
            visited.insert(role.name.clone());
            chain.push(role.name.clone());
            key_chain.push(role.keyids.clone());

            // Load the delegated targets metadata.
            match visitor.load_delegated_targets(&role.name) {
                Ok(delegated_targets) => {
                    // Check if the target is directly listed.
                    if let Some(target) = delegated_targets.target(target_path) {
                        return Ok(ResolvedDelegation {
                            target: target.clone(),
                            delegation_chain: chain.clone(),
                            authorized_keys: key_chain.clone(),
                        });
                    }

                    // Recurse into sub-delegations.
                    if let Some(sub_delegations) = &delegated_targets.delegations {
                        match self.walk_delegations(
                            target_path,
                            sub_delegations,
                            visitor,
                            visited,
                            chain,
                            key_chain,
                            depth + 1,
                        ) {
                            Ok(resolved) => return Ok(resolved),
                            Err(DelegationError::TargetNotFound(_)) => {
                                // Continue to next delegation.
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                Err(DelegationError::RoleNotFound(_)) => {
                    tracing::debug!(role = %role.name, "delegated role metadata not available");
                }
                Err(e) => return Err(e),
            }

            chain.pop();
            key_chain.pop();
            visited.remove(&role.name);

            // If this delegation is terminating, stop searching further
            // delegations at this level.
            if role.terminating {
                tracing::debug!(
                    role = %role.name,
                    target = %target_path,
                    "terminating delegation reached"
                );
                break;
            }
        }

        Err(DelegationError::TargetNotFound(target_path.to_string()))
    }

    /// Collect all keys authorized for a delegation chain (flattened).
    pub fn collect_authorized_keys<'a>(
        &self,
        delegations: &'a Delegations,
        role_name: &str,
    ) -> HashMap<&'a str, &'a TufKey> {
        let mut result = HashMap::new();
        if let Some(role) = delegations.roles.iter().find(|r| r.name == role_name) {
            for kid in &role.keyids {
                if let Some(key) = delegations.keys.get(kid.as_str()) {
                    result.insert(kid.as_str(), key);
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::*;
    use std::collections::HashMap;

    struct MockVisitor {
        metadata: HashMap<String, TargetsMetadata>,
    }

    impl DelegationVisitor for MockVisitor {
        fn load_delegated_targets(
            &self,
            role_name: &str,
        ) -> Result<TargetsMetadata, DelegationError> {
            self.metadata
                .get(role_name)
                .cloned()
                .ok_or_else(|| DelegationError::RoleNotFound(role_name.to_string()))
        }
    }

    fn make_target_info() -> TargetInfo {
        let mut hashes = HashMap::new();
        hashes.insert(
            "sha256".to_string(),
            "abcdef".to_string(),
        );
        TargetInfo {
            length: 100,
            hashes,
            custom: None,
        }
    }

    #[test]
    fn resolve_in_top_level() {
        let mut targets = HashMap::new();
        targets.insert("pkg/foo-1.0.0.tar.gz".to_string(), make_target_info());

        let top_level = TargetsMetadata {
            common: CommonMetadata {
                spec_version: "1.0.31".to_string(),
                version: 1,
                expires: chrono::Utc::now() + chrono::Duration::hours(24),
            },
            targets,
            delegations: None,
        };

        let tree = DelegationTree::default_depth();
        let visitor = MockVisitor {
            metadata: HashMap::new(),
        };

        let resolved = tree.resolve("pkg/foo-1.0.0.tar.gz", &top_level, &visitor).unwrap();
        assert_eq!(resolved.target.length, 100);
        assert_eq!(resolved.delegation_chain, vec!["targets"]);
    }

    #[test]
    fn resolve_via_delegation() {
        let mut delegated_targets = HashMap::new();
        delegated_targets.insert("packages/bar-2.0.0.whl".to_string(), make_target_info());

        let delegated_meta = TargetsMetadata {
            common: CommonMetadata {
                spec_version: "1.0.31".to_string(),
                version: 1,
                expires: chrono::Utc::now() + chrono::Duration::hours(24),
            },
            targets: delegated_targets,
            delegations: None,
        };

        let top_level = TargetsMetadata {
            common: CommonMetadata {
                spec_version: "1.0.31".to_string(),
                version: 1,
                expires: chrono::Utc::now() + chrono::Duration::hours(24),
            },
            targets: HashMap::new(),
            delegations: Some(Delegations {
                keys: HashMap::new(),
                roles: vec![DelegatedRole {
                    name: "packages-delegated".to_string(),
                    keyids: vec![],
                    threshold: 1,
                    terminating: false,
                    paths: vec!["packages/*".to_string()],
                }],
            }),
        };

        let mut visitor_map = HashMap::new();
        visitor_map.insert("packages-delegated".to_string(), delegated_meta);
        let visitor = MockVisitor {
            metadata: visitor_map,
        };

        let tree = DelegationTree::default_depth();
        let resolved = tree
            .resolve("packages/bar-2.0.0.whl", &top_level, &visitor)
            .unwrap();
        assert_eq!(resolved.delegation_chain, vec!["targets", "packages-delegated"]);
    }

    #[test]
    fn target_not_found() {
        let top_level = TargetsMetadata {
            common: CommonMetadata {
                spec_version: "1.0.31".to_string(),
                version: 1,
                expires: chrono::Utc::now() + chrono::Duration::hours(24),
            },
            targets: HashMap::new(),
            delegations: None,
        };

        let tree = DelegationTree::default_depth();
        let visitor = MockVisitor {
            metadata: HashMap::new(),
        };

        let result = tree.resolve("missing/target", &top_level, &visitor);
        assert!(matches!(result, Err(DelegationError::TargetNotFound(_))));
    }
}
