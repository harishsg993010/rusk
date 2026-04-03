//! Anomaly reporting for security events.
//!
//! When rusk detects a security anomaly during install (provenance dropped,
//! signature missing, CAS corruption, revocation hit, etc.), it can
//! optionally POST a structured JSON report to a configured webhook URL.
//!
//! Reporting is fire-and-forget: failures are logged but never block the
//! install flow.

use serde::Serialize;
use chrono::{DateTime, Utc};

/// A structured report describing a security anomaly detected during install.
#[derive(Clone, Debug, Serialize)]
pub struct AnomalyReport {
    /// When the anomaly was detected.
    pub timestamp: DateTime<Utc>,
    /// Project directory where the install is running.
    pub project: String,
    /// Classification of the anomaly.
    pub anomaly_type: AnomalyType,
    /// Package name that triggered the anomaly.
    pub package: String,
    /// Package version that triggered the anomaly.
    pub version: String,
    /// Human-readable description of what happened.
    pub detail: String,
    /// Severity level.
    pub severity: Severity,
    /// Hostname of the machine running the install.
    pub hostname: String,
}

/// Classification of security anomalies.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Package previously had provenance attestation but now does not.
    ProvenanceDropped,
    /// Provenance publisher, repository, or workflow changed.
    ProvenanceChanged,
    /// Package has no signature and signatures are required.
    SignatureMissing,
    /// Package signature failed verification.
    SignatureInvalid,
    /// Package or artifact has been revoked.
    RevocationHit,
    /// CAS blob is corrupted (digest mismatch on re-read).
    CasCorruption,
    /// Downloaded content does not match expected digest.
    DigestMismatch,
    /// Package published by an unauthorized identity.
    UnauthorizedPublisher,
}

/// Severity level for anomaly reports.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Immediate action required (e.g., revocation hit, provenance dropped).
    Critical,
    /// Serious issue that should be investigated (e.g., signature invalid).
    High,
    /// Notable issue (e.g., provenance changed).
    Medium,
    /// Informational (e.g., signature missing but not required).
    Low,
}

/// Return the hostname of the current machine, or "unknown" on failure.
pub fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Send an anomaly report to the configured webhook URL.
///
/// This is fire-and-forget: failures are logged at warn level but never
/// propagate as errors. The HTTP POST has a 5-second timeout to avoid
/// stalling the install on unresponsive endpoints.
pub async fn report_anomaly(report_url: String, report: AnomalyReport) {
    let client = reqwest::Client::new();
    match client
        .post(&report_url)
        .json(&report)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) => {
            tracing::info!(
                status = %resp.status(),
                anomaly = ?report.anomaly_type,
                "anomaly report sent"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to send anomaly report (non-blocking)"
            );
        }
    }
}
