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

/// Machine-parseable exit codes for CI integration.
/// Each category has a distinct code so CI can branch on specific failures.
///
/// These codes are **stable** -- CI scripts depend on them.
/// Do not renumber existing variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    GeneralError = 1,
    ResolutionFailed = 10,
    DownloadFailed = 11,
    PolicyDenied = 20,
    SignatureMissing = 21,
    ProvenanceDropped = 22,
    RevocationHit = 23,
    CasCorruption = 30,
    LockfileMismatch = 31,
    MaterializationFailed = 40,
    ManifestError = 50,
    SandboxFailed = 60,
    AuditFailed = 70,
    VerificationFailed = 71,
}

impl ExitCode {
    /// Return the numeric exit code.
    pub fn as_i32(&self) -> i32 {
        *self as i32
    }

    /// Return the snake_case name of this exit code for JSON output.
    pub fn code_name(&self) -> &'static str {
        match self {
            ExitCode::Success => "success",
            ExitCode::GeneralError => "general_error",
            ExitCode::ResolutionFailed => "resolution_failed",
            ExitCode::DownloadFailed => "download_failed",
            ExitCode::PolicyDenied => "policy_denied",
            ExitCode::SignatureMissing => "signature_missing",
            ExitCode::ProvenanceDropped => "provenance_dropped",
            ExitCode::RevocationHit => "revocation_hit",
            ExitCode::CasCorruption => "cas_corruption",
            ExitCode::LockfileMismatch => "lockfile_mismatch",
            ExitCode::MaterializationFailed => "materialization_failed",
            ExitCode::ManifestError => "manifest_error",
            ExitCode::SandboxFailed => "sandbox_failed",
            ExitCode::AuditFailed => "audit_failed",
            ExitCode::VerificationFailed => "verification_failed",
        }
    }

    /// Return all defined exit codes for documentation purposes.
    pub fn all() -> &'static [ExitCode] {
        &[
            ExitCode::Success,
            ExitCode::GeneralError,
            ExitCode::ResolutionFailed,
            ExitCode::DownloadFailed,
            ExitCode::PolicyDenied,
            ExitCode::SignatureMissing,
            ExitCode::ProvenanceDropped,
            ExitCode::RevocationHit,
            ExitCode::CasCorruption,
            ExitCode::LockfileMismatch,
            ExitCode::MaterializationFailed,
            ExitCode::ManifestError,
            ExitCode::SandboxFailed,
            ExitCode::AuditFailed,
            ExitCode::VerificationFailed,
        ]
    }

    /// Human-readable description for the exit code.
    pub fn description(&self) -> &'static str {
        match self {
            ExitCode::Success => "Operation completed successfully",
            ExitCode::GeneralError => "Unclassified error",
            ExitCode::ResolutionFailed => "Dependency resolution failed",
            ExitCode::DownloadFailed => "Artifact download failed",
            ExitCode::PolicyDenied => "Trust policy denied the operation",
            ExitCode::SignatureMissing => "Required signature is missing",
            ExitCode::ProvenanceDropped => "Provenance attestation was dropped",
            ExitCode::RevocationHit => "Package or signer has been revoked",
            ExitCode::CasCorruption => "Content-addressed store integrity failure",
            ExitCode::LockfileMismatch => "Lockfile does not match expected state",
            ExitCode::MaterializationFailed => "Failed to materialize packages on disk",
            ExitCode::ManifestError => "Manifest parsing or validation error",
            ExitCode::SandboxFailed => "Build sandbox error",
            ExitCode::AuditFailed => "Audit found policy violations",
            ExitCode::VerificationFailed => "Verification of installed packages failed",
        }
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code_name(), self.as_i32())
    }
}
