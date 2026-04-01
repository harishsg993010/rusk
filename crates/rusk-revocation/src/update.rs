//! Revocation data update logic.
//!
//! Fetches updated revocation bundles from the configured source
//! and applies them to the local revocation store.

use crate::bundle::RevocationBundle;
use crate::epoch::Epoch;

/// Result of a revocation data update.
#[derive(Clone, Debug)]
pub enum UpdateResult {
    /// No update was needed (already at the latest epoch).
    AlreadyCurrent { epoch: Epoch },
    /// New revocation data was applied.
    Updated {
        previous_epoch: Epoch,
        new_epoch: Epoch,
        new_entries: usize,
    },
    /// Update failed.
    Failed { reason: String },
}

/// Configuration for revocation data updates.
#[derive(Clone, Debug)]
pub struct UpdateConfig {
    /// URL to fetch revocation bundles from.
    pub source_url: Option<String>,
    /// Maximum age of revocation data before forcing a refresh (in hours).
    pub max_staleness_hours: u64,
    /// Whether to update automatically on install.
    pub auto_update: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            source_url: None,
            max_staleness_hours: 24,
            auto_update: true,
        }
    }
}

/// Check if the current revocation data is stale and needs updating.
pub fn needs_update(current_epoch: &Epoch, config: &UpdateConfig) -> bool {
    if !config.auto_update {
        return false;
    }

    let age_hours = (chrono::Utc::now() - current_epoch.created_at)
        .num_hours()
        .unsigned_abs();
    age_hours >= config.max_staleness_hours
}
