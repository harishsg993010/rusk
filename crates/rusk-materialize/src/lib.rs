//! Shared materialization framework for rusk.
//!
//! Handles the physical installation of resolved packages: planning the
//! file layout, choosing link strategies, performing atomic directory
//! swaps, and tracking installation state.

pub mod planner;
pub mod linker;
pub mod atomic;
pub mod state;

pub use planner::{MaterializationPlan, MaterializationEntry, FileType};
pub use linker::{LinkStrategy, detect_link_strategy};
pub use atomic::atomic_swap;
pub use state::InstallState;
