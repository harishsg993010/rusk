//! Atomic directory swap.
//!
//! Provides an atomic swap operation for replacing a target directory with
//! a newly-prepared directory. The swap is performed as rename operations
//! to minimize the window during which the target is in an inconsistent state.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, info, instrument};

/// Atomically swap `new_dir` into `target`, moving the old `target` to a
/// backup location and then removing it.
///
/// The sequence is:
/// 1. Rename `target` -> `target.old` (if target exists)
/// 2. Rename `new_dir` -> `target`
/// 3. Remove `target.old`
///
/// If step 2 fails, we attempt to roll back by renaming `target.old` back.
#[instrument(skip_all, fields(target = %target.display(), new_dir = %new_dir.display()))]
pub fn atomic_swap(new_dir: &Path, target: &Path) -> io::Result<()> {
    let backup = backup_path(target);

    // Step 1: Move existing target out of the way
    let had_existing = if target.exists() {
        // Remove any stale backup from a previous failed swap
        if backup.exists() {
            debug!("removing stale backup at {}", backup.display());
            fs::remove_dir_all(&backup)?;
        }
        fs::rename(target, &backup)?;
        true
    } else {
        false
    };

    // Step 2: Move new directory into place
    match fs::rename(new_dir, target) {
        Ok(()) => {
            info!("atomic swap complete: {} -> {}", new_dir.display(), target.display());
        }
        Err(e) => {
            // Rollback: restore the backup
            if had_existing {
                debug!("swap failed, rolling back");
                let _ = fs::rename(&backup, target);
            }
            return Err(e);
        }
    }

    // Step 3: Clean up the backup
    if had_existing && backup.exists() {
        debug!("cleaning up backup at {}", backup.display());
        // Best-effort cleanup; don't fail the swap if cleanup fails
        if let Err(e) = fs::remove_dir_all(&backup) {
            tracing::warn!(
                error = %e,
                backup = %backup.display(),
                "failed to clean up backup directory"
            );
        }
    }

    Ok(())
}

/// Compute the backup path for a given target.
fn backup_path(target: &Path) -> PathBuf {
    let mut backup = target.to_path_buf();
    let name = target
        .file_name()
        .map(|n| format!("{}.old", n.to_string_lossy()))
        .unwrap_or_else(|| ".old".to_string());
    backup.set_file_name(name);
    backup
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_path_appends_old() {
        let target = Path::new("/tmp/node_modules");
        let backup = backup_path(target);
        assert_eq!(backup, PathBuf::from("/tmp/node_modules.old"));
    }

    #[test]
    fn swap_new_into_nonexistent_target() {
        let dir = tempfile::tempdir().unwrap();
        let new_dir = dir.path().join("new");
        let target = dir.path().join("target");

        fs::create_dir(&new_dir).unwrap();
        fs::write(new_dir.join("test.txt"), b"hello").unwrap();

        atomic_swap(&new_dir, &target).unwrap();

        assert!(target.exists());
        assert!(!new_dir.exists());
        assert_eq!(fs::read_to_string(target.join("test.txt")).unwrap(), "hello");
    }

    #[test]
    fn swap_replaces_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let new_dir = dir.path().join("new");
        let target = dir.path().join("target");

        // Create existing target
        fs::create_dir(&target).unwrap();
        fs::write(target.join("old.txt"), b"old").unwrap();

        // Create new directory
        fs::create_dir(&new_dir).unwrap();
        fs::write(new_dir.join("new.txt"), b"new").unwrap();

        atomic_swap(&new_dir, &target).unwrap();

        assert!(target.join("new.txt").exists());
        assert!(!target.join("old.txt").exists());
    }
}
