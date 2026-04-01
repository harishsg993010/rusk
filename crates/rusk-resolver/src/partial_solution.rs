//! Partial solution tracking during resolution.
//!
//! Maintains the current state of version assignments as the solver
//! makes decisions and propagates constraints.

use rusk_core::{PackageId, Version};
use std::collections::HashMap;

/// An assignment in the partial solution.
#[derive(Clone, Debug)]
pub struct Assignment {
    /// The package being assigned.
    pub package: PackageId,
    /// The assigned version.
    pub version: Version,
    /// Decision level at which this assignment was made.
    pub decision_level: u32,
    /// Whether this was a decision (vs. a propagation).
    pub is_decision: bool,
}

/// Tracks the current partial solution during resolution.
#[derive(Clone, Debug)]
pub struct PartialSolution {
    /// Current assignments, keyed by package ID.
    assignments: HashMap<PackageId, Assignment>,
    /// The decision trail (ordered list of assignments for backtracking).
    trail: Vec<Assignment>,
    /// Current decision level.
    decision_level: u32,
}

impl PartialSolution {
    /// Create a new empty partial solution.
    pub fn new() -> Self {
        Self {
            assignments: HashMap::new(),
            trail: Vec::new(),
            decision_level: 0,
        }
    }

    /// Make a decision: assign a version to a package.
    pub fn decide(&mut self, package: PackageId, version: Version) {
        self.decision_level += 1;
        let assignment = Assignment {
            package: package.clone(),
            version,
            decision_level: self.decision_level,
            is_decision: true,
        };
        self.assignments.insert(package, assignment.clone());
        self.trail.push(assignment);
    }

    /// Propagate: assign a version as a consequence of constraints.
    pub fn propagate(&mut self, package: PackageId, version: Version) {
        let assignment = Assignment {
            package: package.clone(),
            version,
            decision_level: self.decision_level,
            is_decision: false,
        };
        self.assignments.insert(package, assignment.clone());
        self.trail.push(assignment);
    }

    /// Backtrack to the given decision level, undoing all assignments above it.
    pub fn backtrack_to(&mut self, level: u32) {
        self.trail.retain(|a| a.decision_level <= level);
        self.assignments.clear();
        for a in &self.trail {
            self.assignments.insert(a.package.clone(), a.clone());
        }
        self.decision_level = level;
    }

    /// Get the current version assigned to a package, if any.
    pub fn get(&self, package: &PackageId) -> Option<&Version> {
        self.assignments.get(package).map(|a| &a.version)
    }

    /// Check if a package has been assigned a version.
    pub fn is_assigned(&self, package: &PackageId) -> bool {
        self.assignments.contains_key(package)
    }

    /// Current decision level.
    pub fn decision_level(&self) -> u32 {
        self.decision_level
    }

    /// Number of assigned packages.
    pub fn len(&self) -> usize {
        self.assignments.len()
    }

    /// Whether no packages are assigned.
    pub fn is_empty(&self) -> bool {
        self.assignments.is_empty()
    }

    /// Iterate over all current assignments.
    pub fn iter(&self) -> impl Iterator<Item = (&PackageId, &Assignment)> {
        self.assignments.iter()
    }
}

impl Default for PartialSolution {
    fn default() -> Self {
        Self::new()
    }
}
