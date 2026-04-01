use crate::{BuilderIdentity, SignerIdentity};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Trust classification for an artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// Published via trusted CI pipeline with full provenance.
    TrustedRelease,
    /// Built locally for development use only.
    LocalDev,
    /// Under quarantine period (new or suspicious).
    Quarantined,
    /// No verification performed or insufficient verification.
    Unverified,
}

/// Collected trust verification state for a single artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustState {
    pub digest_verified: bool,
    pub signature: SignatureState,
    pub provenance: ProvenanceState,
    pub transparency: TransparencyState,
    pub revocation: RevocationState,
    pub policy_verdict: PolicyVerdict,
    pub trust_class: TrustClass,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignatureState {
    Verified {
        signer: SignerIdentity,
        timestamp: DateTime<Utc>,
    },
    NotRequired,
    Missing,
    Invalid(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProvenanceState {
    Verified(VerifiedProvenanceRef),
    NotRequired,
    Missing,
    Invalid(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedProvenanceRef {
    pub builder: BuilderIdentity,
    pub source_repo: String,
    pub commit: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransparencyState {
    Verified {
        checkpoint: String,
        timestamp: DateTime<Utc>,
    },
    NotRequired,
    Stale {
        last_seen: DateTime<Utc>,
    },
    Missing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RevocationState {
    Clear,
    Revoked { reason: String, epoch: u64 },
    Yanked { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyVerdict {
    Allow {
        matched_rules: Vec<String>,
    },
    Deny {
        reason: String,
        matched_rules: Vec<String>,
    },
    RequireApproval {
        reason: String,
    },
    Quarantine {
        reason: String,
        duration: Duration,
    },
    Warn {
        warnings: Vec<String>,
    },
}

/// Result of a verification operation.
#[derive(Clone, Debug)]
pub enum VerificationResult {
    /// All checks passed.
    Verified(TrustState),
    /// One or more checks failed.
    Failed {
        trust_state: TrustState,
        failures: Vec<String>,
    },
}
