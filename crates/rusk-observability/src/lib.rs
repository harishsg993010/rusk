//! Observability infrastructure for rusk.
//!
//! Provides unified tracing setup, metrics collection, diagnostics reporting,
//! and structured output for both human-readable and machine-readable formats.

pub mod tracing_setup;
pub mod metrics;
pub mod diagnostics;
pub mod report;

pub use tracing_setup::{init_tracing, TracingConfig, OutputFormat};
pub use metrics::{MetricsCollector, OperationMetrics, TimingMetrics};
pub use diagnostics::{DiagnosticsEmitter, DiagnosticEvent};
pub use report::{Report, ReportBuilder, ReportFormat};
