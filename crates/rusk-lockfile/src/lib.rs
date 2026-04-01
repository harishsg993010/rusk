//! Lockfile engine for rusk deterministic installs.
//!
//! Manages the rusk.lock file, which records exact resolved versions,
//! digests, and dependency graph structure for reproducible installs.
//!
//! # Modules
//!
//! - `schema` - Lockfile types (Lockfile, LockedPackage, LockedDependency, etc.)
//! - `parser` - Loading and parsing rusk.lock files
//! - `writer` - Deterministic lockfile serialization
//! - `integrity` - Integrity hash computation and verification
//! - `diff` - Lockfile diffing for change detection

pub mod diff;
pub mod integrity;
pub mod parser;
pub mod schema;
pub mod writer;
pub mod binary;

pub use diff::{diff_lockfiles, DiffChange, DiffEntry, LockfileDiff};
pub use integrity::{compute_integrity_root, stamp_integrity, verify_integrity, IntegrityError};
pub use parser::{load_lockfile, parse_lockfile, ParseError};
pub use schema::{
    LockedDependency, LockedPackage, LockedSignerRef, Lockfile,
};
pub use writer::{save_lockfile, write_lockfile, WriteError};
