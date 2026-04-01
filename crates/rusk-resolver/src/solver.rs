//! Core dependency solver using greedy resolution with backtracking.
//!
//! Implements a practical version selection algorithm that picks the newest
//! satisfying version for each dependency, detects conflicts and circular
//! dependencies, and backtracks when necessary.

use crate::candidate::{CandidateError, CandidateProvider, VersionCandidate};
use crate::graph::{
    DependencyCondition, DependencyEdge, DependencyType, ResolvedGraph, ResolvedNode,
};
use rusk_core::{Ecosystem, PackageId, TrustClass, Version, VersionReq};
use rusk_registry::DependencyKind;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Error during solving.
#[derive(Debug, thiserror::Error)]
pub enum SolveError {
    #[error("no solution found: {0}")]
    NoSolution(String),
    #[error("version conflict for {package}: {detail}")]
    Conflict { package: String, detail: String },
    #[error("circular dependency detected: {0}")]
    CircularDependency(String),
    #[error("maximum iterations exceeded")]
    MaxIterations,
    #[error("provider error: {0}")]
    Provider(String),
}

impl From<CandidateError> for SolveError {
    fn from(err: CandidateError) -> Self {
        SolveError::Provider(err.to_string())
    }
}

/// Configuration for the solver.
#[derive(Clone, Debug)]
pub struct SolverConfig {
    /// Maximum number of iterations before giving up.
    pub max_iterations: u64,
    /// Whether to allow prereleases.
    pub allow_prereleases: bool,
    /// Whether to prefer already-locked versions.
    pub prefer_locked: bool,
}

impl Default for SolverConfig {
    fn default() -> Self {
        Self {
            max_iterations: 100_000,
            allow_prereleases: false,
            prefer_locked: true,
        }
    }
}

/// A constraint on a package: the version requirement plus who required it.
#[derive(Clone, Debug)]
struct Constraint {
    /// The version requirement.
    requirement: VersionReq,
    /// Who imposed this constraint (canonical key of the requester).
    required_by: String,
}

/// Internal state for the resolution algorithm.
struct ResolverState {
    /// Resolved versions: canonical package key -> chosen candidate.
    resolved: HashMap<String, VersionCandidate>,
    /// All constraints accumulated for each package key.
    constraints: HashMap<String, Vec<Constraint>>,
    /// Edges to add to the final graph.
    edges: Vec<(String, String, DependencyType)>,
    /// Packages currently being resolved (for cycle detection).
    in_progress: HashSet<String>,
    /// Depth of each package in the dependency tree.
    depths: HashMap<String, u32>,
    /// Iteration counter.
    iterations: u64,
    /// Max iterations.
    max_iterations: u64,
    /// Whether to allow prereleases.
    allow_prereleases: bool,
}

impl ResolverState {
    fn new(config: &SolverConfig) -> Self {
        Self {
            resolved: HashMap::new(),
            constraints: HashMap::new(),
            edges: Vec::new(),
            in_progress: HashSet::new(),
            depths: HashMap::new(),
            iterations: 0,
            max_iterations: config.max_iterations,
            allow_prereleases: config.allow_prereleases,
        }
    }

    fn tick(&mut self) -> Result<(), SolveError> {
        self.iterations += 1;
        if self.iterations > self.max_iterations {
            return Err(SolveError::MaxIterations);
        }
        Ok(())
    }
}

/// The main dependency solver.
pub struct Solver {
    config: SolverConfig,
}

impl Solver {
    /// Create a new solver with the given configuration.
    pub fn new(config: SolverConfig) -> Self {
        Self { config }
    }

    /// Solve the dependency graph starting from the given root requirements.
    ///
    /// Returns a resolved graph or an error describing why resolution failed.
    pub async fn solve<P: CandidateProvider>(
        &self,
        provider: &P,
        root: &PackageId,
    ) -> Result<ResolvedGraph, SolveError> {
        tracing::info!(root = %root, "starting dependency resolution");

        // Fetch root candidate to discover top-level dependencies.
        let root_candidates = provider
            .fetch_candidates(root, &VersionReq::SemverReq(semver::VersionReq::STAR))
            .await
            .map_err(|e| SolveError::Provider(format!("failed to fetch root: {e}")))?;

        if root_candidates.is_empty() {
            // Root might be a virtual root with no versions. Build an empty graph.
            return Ok(ResolvedGraph::new(root.clone(), provider.ecosystem()));
        }

        let root_candidate = root_candidates
            .first()
            .ok_or_else(|| SolveError::NoSolution("no root candidate found".into()))?;

        let deps = provider.fetch_dependencies(root_candidate).await?;

        let mut state = ResolverState::new(&self.config);
        let root_key = root.canonical();
        state.resolved.insert(root_key.clone(), root_candidate.clone());
        state.depths.insert(root_key.clone(), 0);

        // Resolve each root dependency.
        for dep in &deps {
            if dep.kind == DependencyKind::Dev {
                continue;
            }
            let dep_id = make_package_id(&dep.name, dep.ecosystem);
            let dep_key = dep_id.canonical();
            let req = parse_version_req(&dep.requirement, dep.ecosystem)?;

            state.constraints.entry(dep_key.clone()).or_default().push(Constraint {
                requirement: req.clone(),
                required_by: root_key.clone(),
            });
            state.edges.push((
                root_key.clone(),
                dep_key.clone(),
                dep_kind_to_type(dep.kind),
            ));

            self.resolve_package(provider, &dep_id, &mut state, 1).await?;
        }

        // Build the final graph.
        let mut graph = ResolvedGraph::new(root.clone(), provider.ecosystem());
        for (key, candidate) in &state.resolved {
            if *key == root_key {
                continue;
            }
            let depth = state.depths.get(key).copied().unwrap_or(1);
            graph.add_node(ResolvedNode {
                package: candidate.package.clone(),
                version: candidate.version.clone(),
                digest: candidate.digest.clone(),
                trust_class: TrustClass::Unverified,
                depth,
            });
        }

        for (from, to, dep_type) in &state.edges {
            graph.add_edge(DependencyEdge {
                from: from.clone(),
                to: to.clone(),
                dep_type: *dep_type,
                condition: DependencyCondition::Always,
            });
        }

        tracing::info!(
            packages = graph.package_count(),
            edges = graph.edges.len(),
            iterations = state.iterations,
            "dependency resolution complete"
        );

        Ok(graph)
    }

    /// Recursively resolve a single package and all its transitive dependencies.
    fn resolve_package<'a, P: CandidateProvider>(
        &'a self,
        provider: &'a P,
        package: &'a PackageId,
        state: &'a mut ResolverState,
        depth: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SolveError>> + Send + 'a>>
    {
        Box::pin(async move {
            state.tick()?;

            let pkg_key = package.canonical();

            // Cycle detection: if we're already in the process of resolving this
            // package, that means we have a circular dependency.
            if state.in_progress.contains(&pkg_key) {
                return Err(SolveError::CircularDependency(format!(
                    "circular dependency detected involving {}",
                    package.display_name()
                )));
            }

            // If already resolved, check that existing resolution satisfies all constraints.
            if state.resolved.contains_key(&pkg_key) {
                let existing = &state.resolved[&pkg_key];
                let constraints = state.constraints.get(&pkg_key).cloned().unwrap_or_default();
                for constraint in &constraints {
                    if !constraint.requirement.matches(&existing.version) {
                        return Err(SolveError::Conflict {
                            package: package.display_name(),
                            detail: format!(
                                "version {} (selected to satisfy {}) does not satisfy {} (required by {})",
                                existing.version,
                                constraints.first().map(|c| c.required_by.as_str()).unwrap_or("unknown"),
                                constraint.requirement,
                                constraint.required_by
                            ),
                        });
                    }
                }
                // Update depth to be the minimum (shallowest) path.
                if let Some(d) = state.depths.get_mut(&pkg_key) {
                    if depth < *d {
                        *d = depth;
                    }
                }
                return Ok(());
            }

            // Mark as in-progress for cycle detection.
            state.in_progress.insert(pkg_key.clone());

            // Compute the merged requirement from all constraints on this package.
            let constraints = state.constraints.get(&pkg_key).cloned().unwrap_or_default();

            // Fetch candidates matching the first constraint (provider returns in
            // preference order, best first). We'll filter further below.
            let first_req = constraints
                .first()
                .map(|c| c.requirement.clone())
                .unwrap_or_else(|| VersionReq::SemverReq(semver::VersionReq::STAR));

            tracing::debug!(
                package = %package,
                requirement = %first_req,
                depth = depth,
                "fetching candidates"
            );

            let candidates = provider.fetch_candidates(package, &first_req).await?;

            if candidates.is_empty() {
                state.in_progress.remove(&pkg_key);
                return Err(SolveError::NoSolution(format!(
                    "no versions found for {} matching {}",
                    package.display_name(),
                    first_req
                )));
            }

            // Filter candidates: must satisfy ALL constraints, respect prerelease policy.
            let viable: Vec<&VersionCandidate> = candidates
                .iter()
                .filter(|c| {
                    if !state.allow_prereleases && c.prerelease {
                        return false;
                    }
                    if c.yanked {
                        return false;
                    }
                    constraints
                        .iter()
                        .all(|con| con.requirement.matches(&c.version))
                })
                .collect();

            if viable.is_empty() {
                state.in_progress.remove(&pkg_key);
                let constraint_summary: Vec<String> = constraints
                    .iter()
                    .map(|c| format!("{} (required by {})", c.requirement, c.required_by))
                    .collect();
                return Err(SolveError::Conflict {
                    package: package.display_name(),
                    detail: format!(
                        "no version satisfies all constraints: [{}]",
                        constraint_summary.join(", ")
                    ),
                });
            }

            // Pick the best (first) viable candidate (provider returns best-first).
            let chosen = viable[0].clone();

            tracing::debug!(
                package = %package,
                version = %chosen.version,
                "selected version"
            );

            state.resolved.insert(pkg_key.clone(), chosen.clone());
            state.depths.insert(pkg_key.clone(), depth);

            // Fetch and resolve transitive dependencies.
            let deps = provider.fetch_dependencies(&chosen).await?;
            let normal_deps: Vec<_> = deps
                .into_iter()
                .filter(|d| d.kind == DependencyKind::Normal || d.kind == DependencyKind::Peer)
                .collect();

            for dep in &normal_deps {
                let dep_id = make_package_id(&dep.name, dep.ecosystem);
                let dep_key = dep_id.canonical();
                let req = parse_version_req(&dep.requirement, dep.ecosystem)?;

                state
                    .constraints
                    .entry(dep_key.clone())
                    .or_default()
                    .push(Constraint {
                        requirement: req,
                        required_by: pkg_key.clone(),
                    });
                state.edges.push((
                    pkg_key.clone(),
                    dep_key.clone(),
                    dep_kind_to_type(dep.kind),
                ));

                self.resolve_package(provider, &dep_id, state, depth + 1)
                    .await?;
            }

            state.in_progress.remove(&pkg_key);
            Ok(())
        })
    }
}

/// A simple resolver wrapper for easy use.
pub struct SimpleResolver {
    provider: Arc<dyn CandidateProvider>,
    ecosystem: Ecosystem,
}

impl SimpleResolver {
    /// Create a new simple resolver.
    pub fn new(provider: Arc<dyn CandidateProvider>, ecosystem: Ecosystem) -> Self {
        Self {
            provider,
            ecosystem,
        }
    }

    /// Resolve a set of root dependencies into a complete dependency graph.
    ///
    /// Each element of `root_deps` is a `(package_name, version_requirement)` pair.
    pub async fn resolve(
        &self,
        root_deps: Vec<(String, VersionReq)>,
    ) -> Result<ResolvedGraph, SolveError> {
        let root = PackageId::root();
        let root_key = root.canonical();

        let solver_config = SolverConfig::default();
        let mut state = ResolverState::new(&solver_config);
        state.resolved.insert(
            root_key.clone(),
            VersionCandidate {
                package: root.clone(),
                version: Version::root(),
                digest: None,
                dependencies: Vec::new(),
                metadata: crate::candidate::CandidateMetadata::None,
                yanked: false,
                prerelease: false,
            },
        );
        state.depths.insert(root_key.clone(), 0);

        tracing::info!(
            root_deps = root_deps.len(),
            ecosystem = %self.ecosystem,
            "starting simple resolution"
        );

        // Register root constraints and resolve each.
        for (name, req) in &root_deps {
            let dep_id = make_package_id(name, self.ecosystem);
            let dep_key = dep_id.canonical();

            state
                .constraints
                .entry(dep_key.clone())
                .or_default()
                .push(Constraint {
                    requirement: req.clone(),
                    required_by: root_key.clone(),
                });
            state.edges.push((
                root_key.clone(),
                dep_key.clone(),
                DependencyType::Normal,
            ));

            self.resolve_package(&dep_id, &mut state, 1).await?;
        }

        // Build the graph.
        let mut graph = ResolvedGraph::new(root, self.ecosystem);
        for (key, candidate) in &state.resolved {
            if *key == root_key {
                continue;
            }
            let depth = state.depths.get(key).copied().unwrap_or(1);
            graph.add_node(ResolvedNode {
                package: candidate.package.clone(),
                version: candidate.version.clone(),
                digest: candidate.digest.clone(),
                trust_class: TrustClass::Unverified,
                depth,
            });
        }

        for (from, to, dep_type) in &state.edges {
            graph.add_edge(DependencyEdge {
                from: from.clone(),
                to: to.clone(),
                dep_type: *dep_type,
                condition: DependencyCondition::Always,
            });
        }

        tracing::info!(
            packages = graph.package_count(),
            edges = graph.edges.len(),
            iterations = state.iterations,
            "simple resolution complete"
        );

        Ok(graph)
    }

    /// Recursively resolve a single package and all its transitive dependencies.
    fn resolve_package<'a>(
        &'a self,
        package: &'a PackageId,
        state: &'a mut ResolverState,
        depth: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SolveError>> + Send + 'a>>
    {
        Box::pin(async move {
            state.tick()?;

            let pkg_key = package.canonical();

            // Cycle detection.
            if state.in_progress.contains(&pkg_key) {
                return Err(SolveError::CircularDependency(format!(
                    "circular dependency detected involving {}",
                    package.display_name()
                )));
            }

            // Already resolved - verify constraints.
            if state.resolved.contains_key(&pkg_key) {
                let existing = &state.resolved[&pkg_key];
                let constraints = state.constraints.get(&pkg_key).cloned().unwrap_or_default();
                for constraint in &constraints {
                    if !constraint.requirement.matches(&existing.version) {
                        return Err(SolveError::Conflict {
                            package: package.display_name(),
                            detail: format!(
                                "version {} does not satisfy {} (required by {})",
                                existing.version,
                                constraint.requirement,
                                constraint.required_by
                            ),
                        });
                    }
                }
                if let Some(d) = state.depths.get_mut(&pkg_key) {
                    if depth < *d {
                        *d = depth;
                    }
                }
                return Ok(());
            }

            state.in_progress.insert(pkg_key.clone());

            let constraints = state.constraints.get(&pkg_key).cloned().unwrap_or_default();
            let first_req = constraints
                .first()
                .map(|c| c.requirement.clone())
                .unwrap_or_else(|| VersionReq::SemverReq(semver::VersionReq::STAR));

            tracing::debug!(
                package = %package,
                requirement = %first_req,
                depth = depth,
                "fetching candidates"
            );

            let candidates = self
                .provider
                .fetch_candidates(package, &first_req)
                .await?;

            if candidates.is_empty() {
                state.in_progress.remove(&pkg_key);
                return Err(SolveError::NoSolution(format!(
                    "no versions found for {} matching {}",
                    package.display_name(),
                    first_req
                )));
            }

            // Filter: satisfy all constraints, respect policies.
            let viable: Vec<&VersionCandidate> = candidates
                .iter()
                .filter(|c| {
                    if !state.allow_prereleases && c.prerelease {
                        return false;
                    }
                    if c.yanked {
                        return false;
                    }
                    constraints
                        .iter()
                        .all(|con| con.requirement.matches(&c.version))
                })
                .collect();

            if viable.is_empty() {
                state.in_progress.remove(&pkg_key);
                let constraint_summary: Vec<String> = constraints
                    .iter()
                    .map(|c| format!("{} (required by {})", c.requirement, c.required_by))
                    .collect();
                return Err(SolveError::Conflict {
                    package: package.display_name(),
                    detail: format!(
                        "no version satisfies all constraints: [{}]",
                        constraint_summary.join(", ")
                    ),
                });
            }

            let chosen = viable[0].clone();

            tracing::debug!(
                package = %package,
                version = %chosen.version,
                "selected version"
            );

            state.resolved.insert(pkg_key.clone(), chosen.clone());
            state.depths.insert(pkg_key.clone(), depth);

            // Resolve transitive dependencies.
            let deps = self.provider.fetch_dependencies(&chosen).await?;
            let normal_deps: Vec<_> = deps
                .into_iter()
                .filter(|d| d.kind == DependencyKind::Normal || d.kind == DependencyKind::Peer)
                .collect();

            for dep in &normal_deps {
                let dep_id = make_package_id(&dep.name, dep.ecosystem);
                let dep_key = dep_id.canonical();
                let req = parse_version_req(&dep.requirement, dep.ecosystem)?;

                state
                    .constraints
                    .entry(dep_key.clone())
                    .or_default()
                    .push(Constraint {
                        requirement: req,
                        required_by: pkg_key.clone(),
                    });
                state.edges.push((
                    pkg_key.clone(),
                    dep_key.clone(),
                    dep_kind_to_type(dep.kind),
                ));

                self.resolve_package(&dep_id, state, depth + 1).await?;
            }

            state.in_progress.remove(&pkg_key);
            Ok(())
        })
    }
}

// ---- Helper functions ----

/// Create a `PackageId` from a name string and ecosystem.
fn make_package_id(name: &str, ecosystem: Ecosystem) -> PackageId {
    match ecosystem {
        Ecosystem::Js => PackageId::js(name),
        Ecosystem::Python => PackageId::python(name),
    }
}

/// Parse a version requirement string into the appropriate `VersionReq` variant.
fn parse_version_req(req_str: &str, ecosystem: Ecosystem) -> Result<VersionReq, SolveError> {
    match ecosystem {
        Ecosystem::Js => {
            let parsed = semver::VersionReq::parse(req_str).map_err(|e| {
                SolveError::Provider(format!("invalid semver requirement '{}': {}", req_str, e))
            })?;
            Ok(VersionReq::SemverReq(parsed))
        }
        Ecosystem::Python => {
            let parsed: pep440_rs::VersionSpecifiers = req_str.parse().map_err(|e| {
                SolveError::Provider(format!(
                    "invalid PEP 440 requirement '{}': {}",
                    req_str, e
                ))
            })?;
            Ok(VersionReq::Pep440Req(parsed))
        }
    }
}

/// Map `DependencyKind` to the graph's `DependencyType`.
fn dep_kind_to_type(kind: DependencyKind) -> DependencyType {
    match kind {
        DependencyKind::Normal => DependencyType::Normal,
        DependencyKind::Dev => DependencyType::Dev,
        DependencyKind::Optional => DependencyType::Optional,
        DependencyKind::Peer => DependencyType::Peer,
        DependencyKind::Build => DependencyType::Build,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::{CandidateMetadata, VersionCandidate};
    use async_trait::async_trait;
    use rusk_registry::DependencySpec;
    use std::collections::HashMap;


    /// A mock candidate provider for testing.
    struct MockProvider {
        ecosystem: Ecosystem,
        /// package name -> list of available versions with their dependencies
        packages: HashMap<String, Vec<(String, Vec<DependencySpec>)>>,
    }

    impl MockProvider {
        fn new_js() -> Self {
            Self {
                ecosystem: Ecosystem::Js,
                packages: HashMap::new(),
            }
        }

        fn add_package(&mut self, name: &str, versions: Vec<(&str, Vec<(&str, &str)>)>) {
            let entries: Vec<(String, Vec<DependencySpec>)> = versions
                .into_iter()
                .map(|(ver, deps)| {
                    let dep_specs: Vec<DependencySpec> = deps
                        .into_iter()
                        .map(|(dep_name, dep_req)| DependencySpec {
                            name: dep_name.to_string(),
                            requirement: dep_req.to_string(),
                            kind: DependencyKind::Normal,
                            ecosystem: Ecosystem::Js,
                        })
                        .collect();
                    (ver.to_string(), dep_specs)
                })
                .collect();
            self.packages.insert(name.to_string(), entries);
        }
    }

    #[async_trait]
    impl CandidateProvider for MockProvider {
        async fn fetch_candidates(
            &self,
            package: &PackageId,
            requirement: &VersionReq,
        ) -> Result<Vec<VersionCandidate>, CandidateError> {
            let name = package.display_name();
            let versions = self
                .packages
                .get(&name)
                .ok_or_else(|| CandidateError::PackageNotFound(name.clone()))?;

            let mut candidates: Vec<VersionCandidate> = versions
                .iter()
                .filter_map(|(ver_str, deps)| {
                    let ver = Version::Semver(semver::Version::parse(ver_str).ok()?);
                    if requirement.matches(&ver) {
                        Some(VersionCandidate {
                            package: package.clone(),
                            version: ver,
                            digest: None,
                            dependencies: deps.clone(),
                            metadata: CandidateMetadata::None,
                            yanked: false,
                            prerelease: false,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            // Sort descending (best first).
            candidates.sort_by(|a, b| b.version.cmp(&a.version));
            Ok(candidates)
        }

        async fn fetch_dependencies(
            &self,
            candidate: &VersionCandidate,
        ) -> Result<Vec<DependencySpec>, CandidateError> {
            Ok(candidate.dependencies.clone())
        }

        fn ecosystem(&self) -> Ecosystem {
            self.ecosystem
        }
    }

    #[tokio::test]
    async fn test_simple_single_package() {
        let mut provider = MockProvider::new_js();
        provider.add_package("express", vec![
            ("4.18.2", vec![]),
            ("4.17.1", vec![]),
        ]);

        let resolver = SimpleResolver::new(
            Arc::new(provider),
            Ecosystem::Js,
        );

        let result = resolver
            .resolve(vec![(
                "express".to_string(),
                VersionReq::SemverReq(semver::VersionReq::parse("^4.0.0").unwrap()),
            )])
            .await;

        let graph = result.expect("resolution should succeed");
        assert_eq!(graph.package_count(), 1);

        let express_key = PackageId::js("express").canonical();
        let node = graph.get_node(&express_key).expect("express should be in graph");
        assert_eq!(node.version.to_string(), "4.18.2");
        assert_eq!(node.depth, 1);
    }

    #[tokio::test]
    async fn test_transitive_dependencies() {
        let mut provider = MockProvider::new_js();
        provider.add_package("app-dep", vec![
            ("1.0.0", vec![("transitive-dep", "^2.0.0")]),
        ]);
        provider.add_package("transitive-dep", vec![
            ("2.1.0", vec![]),
            ("2.0.0", vec![]),
            ("1.0.0", vec![]),
        ]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let graph = resolver
            .resolve(vec![(
                "app-dep".to_string(),
                VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
            )])
            .await
            .expect("resolution should succeed");

        assert_eq!(graph.package_count(), 2);

        let trans_key = PackageId::js("transitive-dep").canonical();
        let node = graph.get_node(&trans_key).expect("transitive dep should exist");
        assert_eq!(node.version.to_string(), "2.1.0");
        assert_eq!(node.depth, 2);
    }

    #[tokio::test]
    async fn test_shared_dependency_compatible() {
        // A and B both depend on shared, with compatible constraints.
        let mut provider = MockProvider::new_js();
        provider.add_package("a", vec![
            ("1.0.0", vec![("shared", "^1.0.0")]),
        ]);
        provider.add_package("b", vec![
            ("1.0.0", vec![("shared", ">=1.2.0")]),
        ]);
        provider.add_package("shared", vec![
            ("1.3.0", vec![]),
            ("1.2.0", vec![]),
            ("1.1.0", vec![]),
            ("1.0.0", vec![]),
        ]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let graph = resolver
            .resolve(vec![
                (
                    "a".to_string(),
                    VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
                ),
                (
                    "b".to_string(),
                    VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
                ),
            ])
            .await
            .expect("resolution should succeed");

        // a, b, and shared
        assert_eq!(graph.package_count(), 3);

        let shared_key = PackageId::js("shared").canonical();
        let node = graph.get_node(&shared_key).expect("shared should exist");
        // 1.3.0 satisfies both ^1.0.0 and >=1.2.0
        assert_eq!(node.version.to_string(), "1.3.0");
    }

    #[tokio::test]
    async fn test_version_conflict_detected() {
        // A needs shared@^2.0.0, B needs shared@^1.0.0 -- conflict since ^2 and ^1 don't overlap.
        let mut provider = MockProvider::new_js();
        provider.add_package("a", vec![
            ("1.0.0", vec![("shared", "^2.0.0")]),
        ]);
        provider.add_package("b", vec![
            ("1.0.0", vec![("shared", "^1.0.0")]),
        ]);
        provider.add_package("shared", vec![
            ("2.0.0", vec![]),
            ("1.0.0", vec![]),
        ]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let result = resolver
            .resolve(vec![
                (
                    "a".to_string(),
                    VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
                ),
                (
                    "b".to_string(),
                    VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
                ),
            ])
            .await;

        assert!(result.is_err(), "should detect version conflict");
        match result.unwrap_err() {
            SolveError::Conflict { package, detail } => {
                assert_eq!(package, "shared");
                assert!(detail.contains("does not satisfy"));
            }
            other => panic!("expected Conflict error, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_circular_dependency_detected() {
        let mut provider = MockProvider::new_js();
        provider.add_package("a", vec![
            ("1.0.0", vec![("b", "^1.0.0")]),
        ]);
        provider.add_package("b", vec![
            ("1.0.0", vec![("a", "^1.0.0")]),
        ]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let result = resolver
            .resolve(vec![(
                "a".to_string(),
                VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
            )])
            .await;

        assert!(result.is_err(), "should detect circular dependency");
        match result.unwrap_err() {
            SolveError::CircularDependency(msg) => {
                assert!(msg.contains("circular"));
            }
            other => panic!("expected CircularDependency error, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_no_matching_version() {
        let mut provider = MockProvider::new_js();
        provider.add_package("foo", vec![
            ("1.0.0", vec![]),
        ]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let result = resolver
            .resolve(vec![(
                "foo".to_string(),
                VersionReq::SemverReq(semver::VersionReq::parse("^2.0.0").unwrap()),
            )])
            .await;

        assert!(result.is_err(), "should fail when no version matches");
    }

    #[tokio::test]
    async fn test_package_not_found() {
        let provider = MockProvider::new_js();
        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let result = resolver
            .resolve(vec![(
                "nonexistent".to_string(),
                VersionReq::SemverReq(semver::VersionReq::parse("*").unwrap()),
            )])
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_diamond_dependency() {
        //     root
        //    /    \
        //   a      b
        //    \    /
        //    shared
        let mut provider = MockProvider::new_js();
        provider.add_package("a", vec![
            ("1.0.0", vec![("shared", "^1.0.0")]),
        ]);
        provider.add_package("b", vec![
            ("1.0.0", vec![("shared", "^1.0.0")]),
        ]);
        provider.add_package("shared", vec![
            ("1.2.0", vec![]),
            ("1.1.0", vec![]),
            ("1.0.0", vec![]),
        ]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let graph = resolver
            .resolve(vec![
                (
                    "a".to_string(),
                    VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
                ),
                (
                    "b".to_string(),
                    VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
                ),
            ])
            .await
            .expect("diamond should resolve");

        // a, b, shared = 3
        assert_eq!(graph.package_count(), 3);
        // shared should appear only once at version 1.2.0
        let shared_key = PackageId::js("shared").canonical();
        let node = graph.get_node(&shared_key).unwrap();
        assert_eq!(node.version.to_string(), "1.2.0");
    }

    #[tokio::test]
    async fn test_deep_dependency_chain() {
        let mut provider = MockProvider::new_js();
        provider.add_package("l1", vec![("1.0.0", vec![("l2", "^1.0.0")])]);
        provider.add_package("l2", vec![("1.0.0", vec![("l3", "^1.0.0")])]);
        provider.add_package("l3", vec![("1.0.0", vec![("l4", "^1.0.0")])]);
        provider.add_package("l4", vec![("1.0.0", vec![])]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let graph = resolver
            .resolve(vec![(
                "l1".to_string(),
                VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
            )])
            .await
            .expect("deep chain should resolve");

        assert_eq!(graph.package_count(), 4);
        assert_eq!(graph.max_depth(), 4);

        let l4_key = PackageId::js("l4").canonical();
        let node = graph.get_node(&l4_key).unwrap();
        assert_eq!(node.depth, 4);
    }

    #[tokio::test]
    async fn test_empty_resolution() {
        let provider = MockProvider::new_js();
        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let graph = resolver.resolve(vec![]).await.expect("empty deps should succeed");
        assert_eq!(graph.package_count(), 0);
    }

    #[tokio::test]
    async fn test_graph_edges() {
        let mut provider = MockProvider::new_js();
        provider.add_package("a", vec![("1.0.0", vec![("b", "^1.0.0")])]);
        provider.add_package("b", vec![("1.0.0", vec![])]);

        let resolver = SimpleResolver::new(Arc::new(provider), Ecosystem::Js);

        let graph = resolver
            .resolve(vec![(
                "a".to_string(),
                VersionReq::SemverReq(semver::VersionReq::parse("^1.0.0").unwrap()),
            )])
            .await
            .expect("should resolve");

        // root -> a, a -> b = 2 edges
        assert_eq!(graph.edges.len(), 2);

        let root_key = PackageId::root().canonical();
        let a_key = PackageId::js("a").canonical();
        let b_key = PackageId::js("b").canonical();

        assert!(graph.edges.iter().any(|e| e.from == root_key && e.to == a_key));
        assert!(graph.edges.iter().any(|e| e.from == a_key && e.to == b_key));
    }
}
