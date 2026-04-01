//! Build sandbox for rusk.
//!
//! Provides an abstraction for running package build steps in isolated
//! environments. The sandbox trait allows different implementations
//! (container-based, process-based, etc.) while the provenance generator
//! records build metadata for supply chain security.

pub mod trait_def;
pub mod linux;
pub mod container;
pub mod process;
pub mod provenance_gen;

pub use trait_def::{Sandbox, SandboxConfig, SandboxCapabilities, SandboxOutput, BuildArtifact, SandboxError};
pub use provenance_gen::LocalProvenance;
pub use process::ProcessSandbox;
pub use container::{ContainerSandbox, ContainerRuntime};
pub use linux::{LinuxSandbox, new_linux_sandbox};
