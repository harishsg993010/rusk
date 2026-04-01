//! Resolved dependency graph types.
//!
//! Represents the output of the resolution process: a directed acyclic graph
//! of resolved packages with exact versions and edges annotated with
//! dependency type and conditions.

use indexmap::IndexMap;
use rusk_core::{Ecosystem, PackageId, Sha256Digest, TrustClass, Version};
use serde::{Deserialize, Serialize};

/// The complete resolved dependency graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedGraph {
    /// All resolved nodes keyed by their canonical package ID.
    pub nodes: IndexMap<String, ResolvedNode>,
    /// All edges in the graph.
    pub edges: Vec<DependencyEdge>,
    /// The root package ID (the user's project).
    pub root: String,
    /// Ecosystem this graph was resolved for.
    pub ecosystem: Ecosystem,
}

impl ResolvedGraph {
    /// Create a new empty graph with the given root.
    pub fn new(root: PackageId, ecosystem: Ecosystem) -> Self {
        let root_key = root.canonical();
        let root_node = ResolvedNode {
            package: root,
            version: Version::root(),
            digest: None,
            trust_class: TrustClass::TrustedRelease,
            depth: 0,
        };
        let mut nodes = IndexMap::new();
        nodes.insert(root_key.clone(), root_node);
        Self {
            nodes,
            edges: Vec::new(),
            root: root_key,
            ecosystem,
        }
    }

    /// Add a resolved node to the graph.
    pub fn add_node(&mut self, node: ResolvedNode) {
        let key = node.package.canonical();
        self.nodes.insert(key, node);
    }

    /// Add an edge between two nodes.
    pub fn add_edge(&mut self, edge: DependencyEdge) {
        self.edges.push(edge);
    }

    /// Get a node by its canonical key.
    pub fn get_node(&self, key: &str) -> Option<&ResolvedNode> {
        self.nodes.get(key)
    }

    /// Return the total number of resolved packages (excluding root).
    pub fn package_count(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }

    /// Iterate over all direct dependencies of a node.
    pub fn direct_deps(&self, key: &str) -> Vec<&ResolvedNode> {
        self.edges
            .iter()
            .filter(|e| e.from == key)
            .filter_map(|e| self.nodes.get(&e.to))
            .collect()
    }

    /// Compute the maximum depth of the graph.
    pub fn max_depth(&self) -> u32 {
        self.nodes.values().map(|n| n.depth).max().unwrap_or(0)
    }

    /// Find all nodes with no dependents (leaf packages).
    pub fn leaf_nodes(&self) -> Vec<&ResolvedNode> {
        let targets: std::collections::HashSet<&str> =
            self.edges.iter().map(|e| e.to.as_str()).collect();
        let sources: std::collections::HashSet<&str> =
            self.edges.iter().map(|e| e.from.as_str()).collect();
        self.nodes
            .iter()
            .filter(|(key, _)| targets.contains(key.as_str()) && !sources.contains(key.as_str()))
            .map(|(_, node)| node)
            .collect()
    }

    /// Topological sort of the graph (dependencies before dependents).
    pub fn topological_order(&self) -> Vec<&str> {
        let mut in_degree: IndexMap<&str, usize> = IndexMap::new();
        for key in self.nodes.keys() {
            in_degree.insert(key.as_str(), 0);
        }
        for edge in &self.edges {
            *in_degree.entry(edge.to.as_str()).or_insert(0) += 1;
        }

        let mut queue: Vec<&str> = in_degree
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&key, _)| key)
            .collect();

        let mut order = Vec::new();
        while let Some(node) = queue.pop() {
            order.push(node);
            for edge in &self.edges {
                if edge.from == node {
                    if let Some(deg) = in_degree.get_mut(edge.to.as_str()) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push(edge.to.as_str());
                        }
                    }
                }
            }
        }
        order
    }
}

/// A single resolved package in the graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvedNode {
    /// The package identity.
    pub package: PackageId,
    /// Exact resolved version.
    pub version: Version,
    /// Content digest, if known (populated after download).
    pub digest: Option<Sha256Digest>,
    /// Trust classification for this package.
    pub trust_class: TrustClass,
    /// Depth in the dependency tree (0 = root, 1 = direct dep).
    pub depth: u32,
}

/// An edge in the dependency graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Canonical key of the source (dependent) package.
    pub from: String,
    /// Canonical key of the target (dependency) package.
    pub to: String,
    /// Type of dependency relationship.
    pub dep_type: DependencyType,
    /// Condition under which this dependency is needed.
    pub condition: DependencyCondition,
}

/// Type of dependency relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyType {
    /// Normal runtime dependency.
    Normal,
    /// Development-only dependency.
    Dev,
    /// Build-time dependency.
    Build,
    /// Optional/feature-gated dependency.
    Optional,
    /// Peer dependency (npm concept).
    Peer,
}

/// Condition under which a dependency is activated.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DependencyCondition {
    /// Always needed.
    Always,
    /// Only on certain platforms.
    Platform {
        os: Option<String>,
        arch: Option<String>,
    },
    /// Only when a feature is enabled.
    Feature { feature: String },
    /// Python environment markers (PEP 508).
    PythonMarker { marker: String },
}

impl Default for DependencyCondition {
    fn default() -> Self {
        DependencyCondition::Always
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_has_root() {
        let root = PackageId::js("my-app");
        let graph = ResolvedGraph::new(root.clone(), Ecosystem::Js);
        assert_eq!(graph.package_count(), 0);
        assert!(graph.get_node(&root.canonical()).is_some());
    }

    #[test]
    fn add_nodes_and_edges() {
        let root = PackageId::js("my-app");
        let mut graph = ResolvedGraph::new(root.clone(), Ecosystem::Js);

        let dep = PackageId::js("express");
        graph.add_node(ResolvedNode {
            package: dep.clone(),
            version: Version::Semver(semver::Version::new(4, 18, 2)),
            digest: None,
            trust_class: TrustClass::TrustedRelease,
            depth: 1,
        });
        graph.add_edge(DependencyEdge {
            from: root.canonical(),
            to: dep.canonical(),
            dep_type: DependencyType::Normal,
            condition: DependencyCondition::Always,
        });

        assert_eq!(graph.package_count(), 1);
        assert_eq!(graph.direct_deps(&root.canonical()).len(), 1);
    }

    #[test]
    fn topological_sort() {
        let root = PackageId::js("app");
        let mut graph = ResolvedGraph::new(root.clone(), Ecosystem::Js);

        let a = PackageId::js("a");
        let b = PackageId::js("b");

        graph.add_node(ResolvedNode {
            package: a.clone(),
            version: Version::Semver(semver::Version::new(1, 0, 0)),
            digest: None,
            trust_class: TrustClass::Unverified,
            depth: 1,
        });
        graph.add_node(ResolvedNode {
            package: b.clone(),
            version: Version::Semver(semver::Version::new(1, 0, 0)),
            digest: None,
            trust_class: TrustClass::Unverified,
            depth: 2,
        });

        graph.add_edge(DependencyEdge {
            from: root.canonical(),
            to: a.canonical(),
            dep_type: DependencyType::Normal,
            condition: DependencyCondition::Always,
        });
        graph.add_edge(DependencyEdge {
            from: a.canonical(),
            to: b.canonical(),
            dep_type: DependencyType::Normal,
            condition: DependencyCondition::Always,
        });

        let order = graph.topological_order();
        let root_pos = order.iter().position(|&k| k == root.canonical()).unwrap();
        let a_pos = order.iter().position(|&k| k == a.canonical()).unwrap();
        let b_pos = order.iter().position(|&k| k == b.canonical()).unwrap();
        assert!(root_pos < a_pos);
        assert!(a_pos < b_pos);
    }
}
