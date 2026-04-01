//! Python ecosystem resolver for rusk.
//!
//! Implements the `CandidateProvider` trait for the Python ecosystem,
//! translating PyPI registry metadata into resolver candidates and
//! evaluating PEP 508 environment markers.

pub mod provider;
pub mod markers;
pub mod pep440;
pub mod wheel_tags;
pub mod extras;

pub use provider::PythonCandidateProvider;
pub use markers::{MarkerEnvironment, evaluate_markers};
pub use wheel_tags::{WheelTag, compatible_tags};
pub use extras::{ExtrasSpec, parse_extras_from_requirement};
