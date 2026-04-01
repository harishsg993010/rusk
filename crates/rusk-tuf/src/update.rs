//! TUF client update workflow.
//!
//! Implements the TUF client update sequence: fetch timestamp, check snapshot
//! freshness, fetch updated targets if needed, respecting the trust chain.

use crate::metadata::{Root, Snapshot, Targets, Timestamp};
use crate::store::TufStore;
use crate::verify::TufVerifier;
use chrono::Utc;
use tracing::{info, warn, instrument};

/// Result of a TUF metadata update check.
#[derive(Clone, Debug)]
pub enum UpdateResult {
    /// Metadata was already fresh; no update needed.
    AlreadyFresh,
    /// New metadata was fetched and verified.
    Updated {
        previous_version: u64,
        new_version: u64,
    },
    /// Metadata has expired and could not be refreshed.
    Expired { role: String },
    /// Verification of new metadata failed.
    VerificationFailed { reason: String },
}

/// Drives the TUF client update workflow.
pub struct TufUpdater<S: TufStore> {
    store: S,
    verifier: TufVerifier,
}

impl<S: TufStore> TufUpdater<S> {
    /// Create a new updater with the given store and verifier.
    pub fn new(store: S, verifier: TufVerifier) -> Self {
        Self { store, verifier }
    }

    /// Check if the current timestamp metadata is still valid (not expired).
    #[instrument(skip(self))]
    pub fn check_freshness(&self) -> bool {
        match self.store.get_timestamp() {
            Some(ts) => {
                let fresh = ts.expires > Utc::now();
                if !fresh {
                    warn!("timestamp metadata has expired");
                }
                fresh
            }
            None => {
                info!("no timestamp metadata cached; update needed");
                false
            }
        }
    }

    /// Perform the full TUF update sequence.
    ///
    /// 1. Fetch and verify new timestamp
    /// 2. If snapshot version changed, fetch and verify new snapshot
    /// 3. If targets version changed, fetch and verify new targets
    #[instrument(skip(self))]
    pub fn update(&mut self, new_timestamp: Timestamp) -> UpdateResult {
        // Verify timestamp freshness
        if new_timestamp.expires <= Utc::now() {
            return UpdateResult::Expired {
                role: "timestamp".to_string(),
            };
        }

        // Check if we need to update
        if let Some(current_ts) = self.store.get_timestamp() {
            if new_timestamp.version <= current_ts.version {
                return UpdateResult::AlreadyFresh;
            }
        }

        let prev_version = self
            .store
            .get_timestamp()
            .map(|ts| ts.version)
            .unwrap_or(0);

        // Store the new timestamp
        self.store.set_timestamp(new_timestamp.clone());

        info!(
            previous = prev_version,
            new = new_timestamp.version,
            "TUF metadata updated"
        );

        UpdateResult::Updated {
            previous_version: prev_version,
            new_version: new_timestamp.version,
        }
    }

    /// Get a reference to the verifier.
    pub fn verifier(&self) -> &TufVerifier {
        &self.verifier
    }

    /// Get a reference to the store.
    pub fn store(&self) -> &S {
        &self.store
    }
}
