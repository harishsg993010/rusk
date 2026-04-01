//! Content-Addressed Storage (CAS) for rusk.
//!
//! Stores package artifacts by their SHA-256 digest in a sharded directory layout.
//! Supports memory-mapped reads, integrity verification, and garbage collection.

pub mod store;
pub mod index;
pub mod gc;
pub mod integrity;
pub mod layout;

pub use store::{CasStore, CasEntry, WriteOutcome};
pub use index::{CasIndex, IndexEntry};
pub use gc::{GarbageCollector, GcPlan, GcStats};
pub use integrity::{IntegrityChecker, IntegrityReport};
pub use layout::{StoreLayout, ShardPath};

#[cfg(test)]
mod adversarial_tests;
