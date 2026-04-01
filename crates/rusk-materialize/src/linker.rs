//! Link strategy detection and execution.
//!
//! Determines the optimal strategy for placing package files: hard links
//! (sharing inodes with CAS), reflinks (CoW on supported filesystems),
//! or full copies (universal fallback). Hard links are preferred as they
//! save both disk space and IO time.

use std::fs;
use std::io;
use std::path::Path;
use tracing::{debug, info};

/// Strategy for placing files from the CAS into the target directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LinkStrategy {
    /// Hard links: share inodes with CAS, zero-copy, saves disk space.
    Hardlink,
    /// Reflinks (copy-on-write): available on Btrfs, APFS, XFS.
    Reflink,
    /// Full copy: always works, but uses the most IO and disk space.
    Copy,
}

impl LinkStrategy {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            LinkStrategy::Hardlink => "hard link (shared inodes)",
            LinkStrategy::Reflink => "reflink (copy-on-write)",
            LinkStrategy::Copy => "full copy",
        }
    }
}

/// Detect the best available link strategy for the given source and target.
///
/// Attempts hard link first, then reflink, falling back to copy.
/// The detection writes and removes a temporary test file.
pub fn detect_link_strategy(cas_root: &Path, target_dir: &Path) -> LinkStrategy {
    // Ensure target dir exists for the test
    if fs::create_dir_all(target_dir).is_err() {
        debug!("cannot create target dir, falling back to copy");
        return LinkStrategy::Copy;
    }

    // Create a temp file in the CAS root to test linking
    let test_source = cas_root.join(".link_test_src");
    let test_target = target_dir.join(".link_test_dst");

    // Clean up any leftover test files
    let _ = fs::remove_file(&test_source);
    let _ = fs::remove_file(&test_target);

    if fs::write(&test_source, b"link_test").is_err() {
        debug!("cannot write test file in CAS root, falling back to copy");
        return LinkStrategy::Copy;
    }

    // Try hard link
    let strategy = if fs::hard_link(&test_source, &test_target).is_ok() {
        let _ = fs::remove_file(&test_target);
        info!("hard links supported between CAS and target");
        LinkStrategy::Hardlink
    } else {
        debug!("hard links not supported, trying reflink");
        // Try reflink (platform-specific, not available in std)
        // Fall back to copy for now
        info!("using full copy strategy");
        LinkStrategy::Copy
    };

    // Clean up test files
    let _ = fs::remove_file(&test_source);
    let _ = fs::remove_file(&test_target);

    strategy
}

/// Create a hard link from `source` to `target`.
pub fn hardlink(source: &Path, target: &Path) -> io::Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::hard_link(source, target)
}

/// Copy a file from `source` to `target`.
pub fn copy_file(source: &Path, target: &Path) -> io::Result<u64> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, target)
}

/// Place a file using the given strategy.
pub fn place_file(strategy: LinkStrategy, source: &Path, target: &Path) -> io::Result<()> {
    match strategy {
        LinkStrategy::Hardlink => hardlink(source, target),
        LinkStrategy::Reflink => {
            // Reflink not yet implemented; fall back to copy
            copy_file(source, target)?;
            Ok(())
        }
        LinkStrategy::Copy => {
            copy_file(source, target)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_strategy_descriptions() {
        assert!(LinkStrategy::Hardlink.description().contains("hard link"));
        assert!(LinkStrategy::Copy.description().contains("copy"));
    }
}
