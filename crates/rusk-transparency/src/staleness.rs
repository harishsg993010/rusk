use crate::checkpoint::TransparencyCheckpoint;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Errors from freshness checking.
#[derive(Debug, thiserror::Error)]
pub enum FreshnessError {
    #[error("no checkpoint available for log '{log_origin}'")]
    NoCheckpoint { log_origin: String },

    #[error("checkpoint from log '{log_origin}' is stale: last seen {last_seen}, max age {max_age}")]
    Stale {
        log_origin: String,
        last_seen: DateTime<Utc>,
        max_age: String,
    },
}

/// Policy controlling how fresh transparency data must be.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FreshnessPolicy {
    /// Maximum age of a checkpoint before it is considered stale.
    /// Defaults to 24 hours.
    pub max_checkpoint_age: Duration,

    /// Whether to treat staleness as an error (hard fail) or a warning.
    pub strict: bool,
}

impl FreshnessPolicy {
    /// Create a strict policy with the given maximum age.
    pub fn strict(max_age: Duration) -> Self {
        Self {
            max_checkpoint_age: max_age,
            strict: true,
        }
    }

    /// Create a permissive policy that only warns on staleness.
    pub fn warn_only(max_age: Duration) -> Self {
        Self {
            max_checkpoint_age: max_age,
            strict: false,
        }
    }
}

impl Default for FreshnessPolicy {
    fn default() -> Self {
        Self {
            max_checkpoint_age: Duration::hours(24),
            strict: false,
        }
    }
}

/// The result of a freshness check.
#[derive(Clone, Debug)]
pub enum FreshnessResult {
    /// The checkpoint is fresh enough.
    Fresh {
        /// Age of the checkpoint.
        age: Duration,
        /// The checkpoint that was checked.
        checkpoint_origin: String,
    },
    /// The checkpoint is stale but policy allows it as a warning.
    StaleWarning {
        /// Age of the checkpoint.
        age: Duration,
        /// Maximum allowed age.
        max_age: Duration,
        /// The checkpoint that was checked.
        checkpoint_origin: String,
    },
    /// The checkpoint is stale and policy is strict.
    StaleError {
        /// Age of the checkpoint.
        age: Duration,
        /// Maximum allowed age.
        max_age: Duration,
        /// The checkpoint that was checked.
        checkpoint_origin: String,
    },
}

impl FreshnessResult {
    /// Whether this result represents a passing check (fresh or warning).
    pub fn is_acceptable(&self) -> bool {
        matches!(self, FreshnessResult::Fresh { .. } | FreshnessResult::StaleWarning { .. })
    }

    /// Whether this result is a hard failure.
    pub fn is_error(&self) -> bool {
        matches!(self, FreshnessResult::StaleError { .. })
    }

    /// Whether the checkpoint was stale at all (warning or error).
    pub fn is_stale(&self) -> bool {
        !matches!(self, FreshnessResult::Fresh { .. })
    }
}

/// Check whether a transparency checkpoint is fresh enough per the given policy.
///
/// Compares the checkpoint's timestamp against `now` and the policy's maximum age.
pub fn check_freshness(
    checkpoint: &TransparencyCheckpoint,
    policy: &FreshnessPolicy,
    now: &DateTime<Utc>,
) -> FreshnessResult {
    let age = *now - checkpoint.timestamp;

    if age <= policy.max_checkpoint_age {
        tracing::debug!(
            origin = %checkpoint.origin,
            age_secs = age.num_seconds(),
            "checkpoint is fresh"
        );
        FreshnessResult::Fresh {
            age,
            checkpoint_origin: checkpoint.origin.clone(),
        }
    } else if policy.strict {
        tracing::warn!(
            origin = %checkpoint.origin,
            age_secs = age.num_seconds(),
            max_age_secs = policy.max_checkpoint_age.num_seconds(),
            "checkpoint is stale (strict policy)"
        );
        FreshnessResult::StaleError {
            age,
            max_age: policy.max_checkpoint_age,
            checkpoint_origin: checkpoint.origin.clone(),
        }
    } else {
        tracing::warn!(
            origin = %checkpoint.origin,
            age_secs = age.num_seconds(),
            max_age_secs = policy.max_checkpoint_age.num_seconds(),
            "checkpoint is stale (warning)"
        );
        FreshnessResult::StaleWarning {
            age,
            max_age: policy.max_checkpoint_age,
            checkpoint_origin: checkpoint.origin.clone(),
        }
    }
}

/// Check freshness for multiple checkpoints, returning the worst result.
///
/// If all checkpoints are fresh, returns `Fresh`. If any are stale, returns
/// the worst (error > warning).
pub fn check_freshness_all(
    checkpoints: &[TransparencyCheckpoint],
    policy: &FreshnessPolicy,
    now: &DateTime<Utc>,
) -> Vec<FreshnessResult> {
    checkpoints
        .iter()
        .map(|cp| check_freshness(cp, policy, now))
        .collect()
}

/// Determine the latest checkpoint from a list, by timestamp.
pub fn latest_checkpoint(checkpoints: &[TransparencyCheckpoint]) -> Option<&TransparencyCheckpoint> {
    checkpoints.iter().max_by_key(|cp| cp.timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusk_core::Sha256Digest;
    use url::Url;

    fn make_checkpoint(age: Duration) -> TransparencyCheckpoint {
        TransparencyCheckpoint {
            log_url: Url::parse("https://rekor.example.com").unwrap(),
            origin: "rekor.example.com".to_string(),
            tree_size: 1000,
            root_hash: Sha256Digest::zero(),
            timestamp: Utc::now() - age,
            signature_hex: String::new(),
            log_public_key_hex: String::new(),
        }
    }

    #[test]
    fn fresh_checkpoint() {
        let cp = make_checkpoint(Duration::hours(1));
        let policy = FreshnessPolicy::default(); // 24h
        let result = check_freshness(&cp, &policy, &Utc::now());
        assert!(result.is_acceptable());
        assert!(!result.is_stale());
    }

    #[test]
    fn stale_warning() {
        let cp = make_checkpoint(Duration::hours(48));
        let policy = FreshnessPolicy::warn_only(Duration::hours(24));
        let result = check_freshness(&cp, &policy, &Utc::now());
        assert!(result.is_acceptable()); // Warning is acceptable.
        assert!(result.is_stale());
    }

    #[test]
    fn stale_error() {
        let cp = make_checkpoint(Duration::hours(48));
        let policy = FreshnessPolicy::strict(Duration::hours(24));
        let result = check_freshness(&cp, &policy, &Utc::now());
        assert!(result.is_error());
        assert!(!result.is_acceptable());
    }

    #[test]
    fn check_multiple() {
        let fresh = make_checkpoint(Duration::hours(1));
        let stale = make_checkpoint(Duration::hours(48));
        let policy = FreshnessPolicy::strict(Duration::hours(24));

        let results = check_freshness_all(&[fresh, stale], &policy, &Utc::now());
        assert_eq!(results.len(), 2);
        assert!(results[0].is_acceptable());
        assert!(results[1].is_error());
    }

    #[test]
    fn latest_checkpoint_selection() {
        let old = make_checkpoint(Duration::hours(48));
        let new = make_checkpoint(Duration::hours(1));
        let checkpoints = [old.clone(), new.clone()];
        let latest = latest_checkpoint(&checkpoints).unwrap();
        assert!(latest.timestamp > old.timestamp);
    }
}
