//! Enterprise features for rusk.
//!
//! Provides enterprise-specific functionality: internal registry configuration,
//! package leakage prevention, air-gapped bundle support, organizational
//! policy controls, proxy configuration, and audit export.

pub mod config;
pub mod internal_registry;
pub mod org_policy;
pub mod airgap;
pub mod proxy;
pub mod leakage;
pub mod audit_export;

pub use config::{EnterpriseConfig, InternalRegistryConfig, PackageControls};
pub use internal_registry::InternalRegistry;
pub use org_policy::{OrgPolicy, OrgPolicyEvaluator};
pub use airgap::AirGapBundle;
pub use proxy::{ProxyConfig, ProxyAuth};
pub use leakage::validate_no_internal_leakage;
pub use audit_export::{AuditExporter, AuditRecord, ExportFormat};
