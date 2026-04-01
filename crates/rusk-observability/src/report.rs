//! Structured report generation.
//!
//! Builds final reports for CLI output, combining operation metrics,
//! diagnostic events, and timing data into human-readable or JSON output.

use crate::diagnostics::DiagnosticEvent;
use crate::metrics::OperationMetrics;
use serde::{Deserialize, Serialize};

/// Output format for reports.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReportFormat {
    /// Human-readable text for terminal display.
    #[default]
    Text,
    /// Machine-readable JSON.
    Json,
}

/// A structured report summarizing an operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    /// Operation name (e.g., "install", "audit").
    pub operation: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Aggregate metrics.
    pub metrics: OperationMetrics,
    /// Diagnostic events emitted during the operation.
    pub diagnostics: Vec<DiagnosticEvent>,
    /// Total wall-clock time in milliseconds.
    pub total_time_ms: u64,
}

impl Report {
    /// Render the report as a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Render the report as human-readable text.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let status = if self.success { "success" } else { "failed" };
        out.push_str(&format!("{} {}\n", self.operation, status));
        out.push_str(&format!(
            "resolved {} | downloaded {} ({} bytes) | materialized {}\n",
            self.metrics.packages_resolved,
            self.metrics.packages_downloaded,
            self.metrics.bytes_downloaded,
            self.metrics.packages_materialized,
        ));
        out.push_str(&format!(
            "cache: {} hits, {} misses\n",
            self.metrics.cache_hits, self.metrics.cache_misses
        ));
        out.push_str(&format!("total time: {}ms\n", self.total_time_ms));

        if !self.diagnostics.is_empty() {
            out.push_str(&format!("\n{} diagnostics:\n", self.diagnostics.len()));
            for diag in &self.diagnostics {
                out.push_str(&format!(
                    "  [{:?}] {}: {}\n",
                    diag.severity, diag.code, diag.message
                ));
            }
        }
        out
    }

    /// Render using the specified format.
    pub fn render(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Text => self.to_text(),
            ReportFormat::Json => self.to_json(),
        }
    }
}

/// Builder for constructing a `Report`.
pub struct ReportBuilder {
    operation: String,
    success: bool,
    metrics: OperationMetrics,
    diagnostics: Vec<DiagnosticEvent>,
    total_time_ms: u64,
}

impl ReportBuilder {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            success: true,
            metrics: OperationMetrics::default(),
            diagnostics: Vec::new(),
            total_time_ms: 0,
        }
    }

    pub fn success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn metrics(mut self, metrics: OperationMetrics) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn diagnostics(mut self, diagnostics: Vec<DiagnosticEvent>) -> Self {
        self.diagnostics = diagnostics;
        self
    }

    pub fn total_time_ms(mut self, ms: u64) -> Self {
        self.total_time_ms = ms;
        self
    }

    pub fn build(self) -> Report {
        Report {
            operation: self.operation,
            success: self.success,
            metrics: self.metrics,
            diagnostics: self.diagnostics,
            total_time_ms: self.total_time_ms,
        }
    }
}
