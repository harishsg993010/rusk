//! Shared dependency resolver framework for rusk.
//!
//! Provides the core resolution algorithm, resolved graph types, candidate
//! provider abstraction, and trust-aware candidate filtering. Ecosystem-specific
//! resolvers (JS, Python) implement the `CandidateProvider` trait.

pub mod graph;
pub mod candidate;
pub mod trust_filter;
pub mod solver;
pub mod incompatibility;
pub mod partial_solution;
pub mod lockfile_reuse;
pub mod workspace;

pub use graph::{ResolvedGraph, ResolvedNode, DependencyEdge, DependencyType, DependencyCondition};
pub use candidate::{CandidateProvider, VersionCandidate, CandidateMetadata};
pub use trust_filter::TrustAwareCandidateFilter;
pub use solver::{Solver, SolverConfig, SolveError, SimpleResolver};
pub use lockfile_reuse::LockfileStrategy;
pub use workspace::WorkspaceContext;
