use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Errors from epoch management.
#[derive(Debug, thiserror::Error)]
pub enum EpochError {
    #[error("epoch {attempted} is not monotonically increasing from {current}")]
    NonMonotonic { current: u64, attempted: u64 },

    #[error("epoch {0} is in the future")]
    FutureEpoch(u64),
}

/// A revocation epoch marker.
///
/// Epochs provide a monotonically increasing counter that allows clients
/// to know whether their revocation data is up-to-date and enables the
/// signature cache to invalidate entries efficiently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct Epoch {
    /// The epoch number (monotonically increasing).
    pub number: u64,
    /// When this epoch was created.
    pub created_at: DateTime<Utc>,
}

impl Epoch {
    /// Create a new epoch.
    pub fn new(number: u64) -> Self {
        Self {
            number,
            created_at: Utc::now(),
        }
    }

    /// The zero epoch (initial state before any revocations).
    pub fn zero() -> Self {
        Self {
            number: 0,
            created_at: DateTime::UNIX_EPOCH,
        }
    }
}

impl std::fmt::Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch-{}", self.number)
    }
}

/// Manages epoch state and enforces monotonic advancement.
///
/// The epoch manager tracks the current epoch and provides methods to
/// advance it when new revocation bundles are received.
#[derive(Debug)]
pub struct EpochManager {
    /// The current epoch.
    current: Epoch,
    /// History of epoch transitions (for auditing).
    history: Vec<EpochTransition>,
    /// Maximum number of history entries to keep.
    max_history: usize,
}

/// A record of an epoch transition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochTransition {
    /// The epoch we transitioned from.
    pub from: u64,
    /// The epoch we transitioned to.
    pub to: u64,
    /// When the transition happened.
    pub transitioned_at: DateTime<Utc>,
    /// Number of new revocation entries in this epoch.
    pub new_entries: usize,
}

impl EpochManager {
    /// Create a new epoch manager starting from epoch 0.
    pub fn new() -> Self {
        Self {
            current: Epoch::zero(),
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Create an epoch manager starting from a specific epoch.
    pub fn from_epoch(epoch: Epoch) -> Self {
        Self {
            current: epoch,
            history: Vec::new(),
            max_history: 1000,
        }
    }

    /// Get the current epoch.
    pub fn current(&self) -> &Epoch {
        &self.current
    }

    /// Get the current epoch number.
    pub fn current_number(&self) -> u64 {
        self.current.number
    }

    /// Advance to a new epoch.
    ///
    /// The new epoch number must be strictly greater than the current one.
    /// Returns the new epoch.
    pub fn advance(
        &mut self,
        new_epoch_number: u64,
        new_entries: usize,
    ) -> Result<&Epoch, EpochError> {
        if new_epoch_number <= self.current.number {
            return Err(EpochError::NonMonotonic {
                current: self.current.number,
                attempted: new_epoch_number,
            });
        }

        let transition = EpochTransition {
            from: self.current.number,
            to: new_epoch_number,
            transitioned_at: Utc::now(),
            new_entries,
        };

        self.history.push(transition);

        // Trim history if needed.
        if self.history.len() > self.max_history {
            let drain_count = self.history.len() - self.max_history;
            self.history.drain(..drain_count);
        }

        self.current = Epoch::new(new_epoch_number);

        tracing::info!(
            epoch = new_epoch_number,
            new_entries = new_entries,
            "epoch advanced"
        );

        Ok(&self.current)
    }

    /// Advance to the next sequential epoch (current + 1).
    pub fn advance_next(&mut self, new_entries: usize) -> Result<&Epoch, EpochError> {
        let next = self.current.number + 1;
        self.advance(next, new_entries)
    }

    /// Check if a given epoch number is current.
    pub fn is_current(&self, epoch_number: u64) -> bool {
        self.current.number == epoch_number
    }

    /// Check if a given epoch number is stale (behind current).
    pub fn is_stale(&self, epoch_number: u64) -> bool {
        epoch_number < self.current.number
    }

    /// Get the epoch transition history.
    pub fn history(&self) -> &[EpochTransition] {
        &self.history
    }

    /// Number of epoch transitions recorded.
    pub fn transition_count(&self) -> usize {
        self.history.len()
    }

    /// Total number of revocation entries across all recorded transitions.
    pub fn total_historical_entries(&self) -> usize {
        self.history.iter().map(|t| t.new_entries).sum()
    }
}

impl Default for EpochManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_display() {
        let epoch = Epoch::new(42);
        assert_eq!(epoch.to_string(), "epoch-42");
    }

    #[test]
    fn epoch_ordering() {
        let e1 = Epoch::new(1);
        let e2 = Epoch::new(2);
        assert!(e1 < e2);
    }

    #[test]
    fn monotonic_advance() {
        let mut mgr = EpochManager::new();
        assert_eq!(mgr.current_number(), 0);

        mgr.advance(1, 5).unwrap();
        assert_eq!(mgr.current_number(), 1);

        mgr.advance(2, 3).unwrap();
        assert_eq!(mgr.current_number(), 2);

        // Cannot go backwards.
        assert!(mgr.advance(1, 0).is_err());

        // Cannot stay at same epoch.
        assert!(mgr.advance(2, 0).is_err());
    }

    #[test]
    fn advance_next() {
        let mut mgr = EpochManager::new();
        mgr.advance_next(10).unwrap();
        assert_eq!(mgr.current_number(), 1);
        mgr.advance_next(5).unwrap();
        assert_eq!(mgr.current_number(), 2);
    }

    #[test]
    fn staleness_check() {
        let mut mgr = EpochManager::new();
        mgr.advance(5, 0).unwrap();

        assert!(mgr.is_stale(3));
        assert!(mgr.is_current(5));
        assert!(!mgr.is_stale(5));
        assert!(!mgr.is_stale(6));
    }

    #[test]
    fn history_tracking() {
        let mut mgr = EpochManager::new();
        mgr.advance(1, 10).unwrap();
        mgr.advance(2, 5).unwrap();
        mgr.advance(3, 3).unwrap();

        assert_eq!(mgr.transition_count(), 3);
        assert_eq!(mgr.total_historical_entries(), 18);

        let history = mgr.history();
        assert_eq!(history[0].from, 0);
        assert_eq!(history[0].to, 1);
        assert_eq!(history[0].new_entries, 10);
    }

    #[test]
    fn history_trimming() {
        let mut mgr = EpochManager::new();
        mgr.max_history = 5;

        for i in 1..=10 {
            mgr.advance(i, 1).unwrap();
        }

        assert!(mgr.history().len() <= 5);
        assert_eq!(mgr.current_number(), 10);
    }

    #[test]
    fn from_existing_epoch() {
        let epoch = Epoch::new(100);
        let mgr = EpochManager::from_epoch(epoch);
        assert_eq!(mgr.current_number(), 100);
        assert_eq!(mgr.transition_count(), 0);
    }
}
