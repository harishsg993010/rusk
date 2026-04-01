use std::fmt;

/// Top-level rusk error type.
#[derive(Debug, thiserror::Error)]
pub enum RuskError {
    #[error("manifest error: {0}")]
    Manifest(String),

    #[error("lockfile error: {0}")]
    Lockfile(String),

    #[error("resolver error: {0}")]
    Resolver(String),

    #[error("trust error: {0}")]
    Trust(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("CAS error: {0}")]
    Cas(String),

    #[error("materialization error: {0}")]
    Materialize(String),

    #[error("sandbox error: {0}")]
    Sandbox(String),

    #[error("enterprise error: {0}")]
    Enterprise(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

/// Error severity level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// Error classification for structured handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Trust verification failure (signatures, provenance, etc.)
    TrustFailure,
    /// Policy evaluation denied the operation
    PolicyDenied,
    /// Network connectivity or HTTP error
    Network,
    /// Content-addressed store corruption
    CasCorruption,
    /// Signature verification failed
    SignatureInvalid,
    /// Provenance binding failed
    ProvenanceInvalid,
    /// Artifact or signer has been revoked
    Revoked,
    /// Lockfile does not match expected state
    LockfileMismatch,
    /// Manifest parsing or validation error
    ManifestInvalid,
    /// File system error during materialization
    MaterializationFailed,
    /// Build sandbox error
    SandboxFailed,
    /// Audit finding
    AuditFinding,
}

/// Structured diagnostic for user-facing error output.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub detail: String,
    pub hints: Vec<String>,
    pub machine_readable: serde_json::Value,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {}: {}", self.code, self.severity_label(), self.message)?;
        if !self.detail.is_empty() {
            writeln!(f, "  {}", self.detail)?;
        }
        for hint in &self.hints {
            writeln!(f, "  hint: {}", hint)?;
        }
        Ok(())
    }
}

impl Diagnostic {
    fn severity_label(&self) -> &'static str {
        match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}
