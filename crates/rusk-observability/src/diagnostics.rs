//! Diagnostics event emission.
//!
//! Provides a structured way to emit diagnostic events (warnings, errors, info)
//! during rusk operations. These events feed into both the CLI output and
//! machine-readable JSON reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity level for diagnostic events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// A structured diagnostic event emitted during an operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    /// Unique event code (e.g., "RUSK-001").
    pub code: String,
    /// Severity level.
    pub severity: DiagnosticSeverity,
    /// Human-readable summary.
    pub message: String,
    /// Optional detailed explanation.
    pub detail: Option<String>,
    /// Actionable hints for the user.
    pub hints: Vec<String>,
    /// When the event was emitted.
    pub timestamp: DateTime<Utc>,
    /// Associated package, if any.
    pub package: Option<String>,
}

impl DiagnosticEvent {
    /// Create a new info-level diagnostic.
    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: DiagnosticSeverity::Info,
            message: message.into(),
            detail: None,
            hints: Vec::new(),
            timestamp: Utc::now(),
            package: None,
        }
    }

    /// Create a new warning-level diagnostic.
    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: DiagnosticSeverity::Warning,
            message: message.into(),
            detail: None,
            hints: Vec::new(),
            timestamp: Utc::now(),
            package: None,
        }
    }

    /// Create a new error-level diagnostic.
    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity: DiagnosticSeverity::Error,
            message: message.into(),
            detail: None,
            hints: Vec::new(),
            timestamp: Utc::now(),
            package: None,
        }
    }

    /// Attach a detail string.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach a hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }

    /// Attach a package name.
    pub fn with_package(mut self, package: impl Into<String>) -> Self {
        self.package = Some(package.into());
        self
    }
}

/// Collects diagnostic events during an operation.
#[derive(Clone, Debug, Default)]
pub struct DiagnosticsEmitter {
    events: Vec<DiagnosticEvent>,
}

impl DiagnosticsEmitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a diagnostic event.
    pub fn emit(&mut self, event: DiagnosticEvent) {
        tracing::event!(
            tracing::Level::INFO,
            code = %event.code,
            severity = ?event.severity,
            message = %event.message,
            "diagnostic"
        );
        self.events.push(event);
    }

    /// Get all collected events.
    pub fn events(&self) -> &[DiagnosticEvent] {
        &self.events
    }

    /// Get events filtered by severity.
    pub fn errors(&self) -> Vec<&DiagnosticEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == DiagnosticSeverity::Error)
            .collect()
    }

    /// Get events filtered by severity.
    pub fn warnings(&self) -> Vec<&DiagnosticEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == DiagnosticSeverity::Warning)
            .collect()
    }

    /// Returns true if any error-level diagnostics were emitted.
    pub fn has_errors(&self) -> bool {
        self.events
            .iter()
            .any(|e| e.severity == DiagnosticSeverity::Error)
    }
}
