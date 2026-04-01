//! Retry strategies for transient HTTP failures.
//!
//! Provides configurable retry policies with exponential backoff and jitter.
//! Classifies errors as retriable (network timeouts, 5xx) or permanent
//! (4xx, digest mismatch).

use crate::manager::TransportError;
use std::time::Duration;

/// Retry strategy configuration.
#[derive(Clone, Debug)]
pub struct RetryStrategy {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Base delay between retries.
    pub base_delay: Duration,
    /// Maximum delay cap.
    pub max_delay: Duration,
    /// Backoff multiplier applied per attempt.
    pub backoff_factor: f64,
    /// Whether to add random jitter to prevent thundering herd.
    pub jitter: bool,
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            backoff_factor: 2.0,
            jitter: true,
        }
    }
}

impl RetryStrategy {
    /// Create a strategy that never retries.
    pub fn no_retries() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }

    /// Create an aggressive retry strategy for flaky networks.
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(60),
            backoff_factor: 2.0,
            jitter: true,
        }
    }

    /// Compute the delay for the given attempt number (1-based).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }

        let base_ms = self.base_delay.as_millis() as f64;
        let delay_ms = base_ms * self.backoff_factor.powi(attempt as i32 - 1);
        let capped_ms = delay_ms.min(self.max_delay.as_millis() as f64);

        let final_ms = if self.jitter {
            // Simple deterministic "jitter" based on attempt number.
            // In production you'd use a real RNG, but this avoids a dependency.
            let jitter_factor = 0.5 + 0.5 * ((attempt as f64 * 1.618033988) % 1.0);
            capped_ms * jitter_factor
        } else {
            capped_ms
        };

        Duration::from_millis(final_ms as u64)
    }
}

/// Determine whether a transport error is retriable.
///
/// Network errors and server errors (5xx) are retriable.
/// Client errors (4xx), digest mismatches, and IO errors are not.
pub fn is_retriable(error: &TransportError) -> bool {
    match error {
        TransportError::Http { message, .. } => {
            // Retry server errors and timeouts, not client errors
            message.contains("HTTP 5")
                || message.contains("timeout")
                || message.contains("connection")
                || message.contains("reset")
        }
        TransportError::Reqwest(e) => e.is_timeout() || e.is_connect(),
        TransportError::DigestMismatch { .. } => false,
        TransportError::RetriesExhausted { .. } => false,
        TransportError::Io(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_strategy_has_sane_values() {
        let s = RetryStrategy::default();
        assert_eq!(s.max_retries, 3);
        assert!(s.base_delay.as_millis() > 0);
        assert!(s.max_delay > s.base_delay);
    }

    #[test]
    fn no_retries_means_zero() {
        let s = RetryStrategy::no_retries();
        assert_eq!(s.max_retries, 0);
    }

    #[test]
    fn delay_increases_with_attempts() {
        let s = RetryStrategy {
            jitter: false,
            ..RetryStrategy::default()
        };
        let d1 = s.delay_for_attempt(1);
        let d2 = s.delay_for_attempt(2);
        let d3 = s.delay_for_attempt(3);
        assert!(d2 > d1);
        assert!(d3 > d2);
    }

    #[test]
    fn delay_capped_at_max() {
        let s = RetryStrategy {
            max_retries: 100,
            max_delay: Duration::from_secs(5),
            jitter: false,
            ..RetryStrategy::default()
        };
        let d = s.delay_for_attempt(100);
        assert!(d <= Duration::from_secs(5));
    }

    #[test]
    fn server_errors_are_retriable() {
        let err = TransportError::Http {
            url: "http://example.com".to_string(),
            message: "HTTP 502 Bad Gateway".to_string(),
        };
        assert!(is_retriable(&err));
    }

    #[test]
    fn digest_mismatch_not_retriable() {
        let err = TransportError::DigestMismatch {
            url: "http://example.com".to_string(),
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert!(!is_retriable(&err));
    }
}
