//! Incompatibility tracking for the solver.
//!
//! Records why certain version combinations are incompatible, enabling
//! the solver to learn from conflicts and avoid revisiting them.

use rusk_core::{PackageId, Version, VersionReq};
use std::collections::HashMap;

/// A term in an incompatibility (a package with a version constraint).
#[derive(Clone, Debug)]
pub struct Term {
    /// The package this term refers to.
    pub package: PackageId,
    /// The version constraint (positive = "must be in range", negative = "must not be in range").
    pub constraint: VersionReq,
    /// Whether this term is positive (package IS in range) or negative (package is NOT in range).
    pub positive: bool,
}

/// An incompatibility records a set of terms that cannot all be true simultaneously.
///
/// For example: "if package A is at version ^1.0 AND package B is at version ^2.0,
/// then there is a conflict because A@1.0 requires B@^1.0".
#[derive(Clone, Debug)]
pub struct Incompatibility {
    /// The terms that form this incompatibility.
    pub terms: Vec<Term>,
    /// Why this incompatibility exists.
    pub cause: IncompatibilityCause,
}

/// The reason an incompatibility was created.
#[derive(Clone, Debug)]
pub enum IncompatibilityCause {
    /// Directly from a package's dependency declaration.
    Dependency {
        package: PackageId,
        version: Version,
    },
    /// Root project requires this.
    Root,
    /// Derived from conflict analysis during solving.
    Derived {
        /// The two incompatibilities that were combined.
        lhs: Box<Incompatibility>,
        rhs: Box<Incompatibility>,
    },
    /// Package does not exist at the given version.
    PackageNotFound {
        package: PackageId,
    },
}

impl Incompatibility {
    /// Create a root incompatibility (the project's direct requirements).
    pub fn root(package: PackageId, constraint: VersionReq) -> Self {
        Self {
            terms: vec![Term {
                package,
                constraint,
                positive: true,
            }],
            cause: IncompatibilityCause::Root,
        }
    }

    /// Create a dependency incompatibility.
    pub fn dependency(
        depender: PackageId,
        depender_version: Version,
        dependency: PackageId,
        dependency_constraint: VersionReq,
    ) -> Self {
        Self {
            terms: vec![
                Term {
                    package: depender.clone(),
                    constraint: VersionReq::SemverReq(semver::VersionReq::STAR),
                    positive: true,
                },
                Term {
                    package: dependency,
                    constraint: dependency_constraint,
                    positive: false,
                },
            ],
            cause: IncompatibilityCause::Dependency {
                package: depender,
                version: depender_version,
            },
        }
    }

    /// Number of terms in this incompatibility.
    pub fn len(&self) -> usize {
        self.terms.len()
    }

    /// Whether this incompatibility has no terms.
    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }
}
