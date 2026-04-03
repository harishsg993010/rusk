//! Workflow orchestration for rusk.
//!
//! Coordinates all rusk subsystems (resolution, download, materialization,
//! policy evaluation, etc.) into high-level workflows like install, update,
//! verify, and audit.

pub mod install;
pub mod update;
pub mod verify;
pub mod audit;
pub mod build;
pub mod publish;
pub mod explain;
pub mod config;
pub mod reporting;

pub use install::{run_install, InstallResult, InstallError};
pub use update::UpdateResult;
pub use verify::VerifyResult;
pub use audit::{AuditResult, AuditFinding};
pub use build::BuildResult;
pub use publish::PublishResult;
pub use explain::ExplainResult;
pub use config::OrchestratorConfig;
