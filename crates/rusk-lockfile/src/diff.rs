//! Lockfile diffing.
//!
//! Compares two lockfiles and produces a structured diff showing which
//! packages were added, removed, or changed.

use crate::schema::Lockfile;
use rusk_core::Version;

/// A diff between two lockfiles.
#[derive(Clone, Debug)]
pub struct LockfileDiff {
    /// Packages added in the new lockfile.
    pub added: Vec<DiffEntry>,
    /// Packages removed from the old lockfile.
    pub removed: Vec<DiffEntry>,
    /// Packages that changed version or digest.
    pub changed: Vec<DiffChange>,
    /// Total number of differences.
    pub total_changes: usize,
}

/// A single added or removed package.
#[derive(Clone, Debug)]
pub struct DiffEntry {
    /// Canonical package ID.
    pub canonical_id: String,
    /// Version.
    pub version: Version,
    /// Whether it's a dev dependency.
    pub dev: bool,
}

/// A changed package (version update or digest change).
#[derive(Clone, Debug)]
pub struct DiffChange {
    /// Canonical package ID.
    pub canonical_id: String,
    /// Old version.
    pub old_version: Version,
    /// New version.
    pub new_version: Version,
    /// Whether the digest changed (may also change with version).
    pub digest_changed: bool,
    /// Whether dev status changed.
    pub dev_changed: bool,
}

/// Compute the diff between two lockfiles.
///
/// `old` is the previous lockfile, `new` is the updated lockfile.
/// Returns a structured diff showing all changes.
pub fn diff_lockfiles(old: &Lockfile, new: &Lockfile) -> LockfileDiff {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    // Find added and changed packages.
    for (id, new_pkg) in &new.packages {
        match old.packages.get(id) {
            None => {
                added.push(DiffEntry {
                    canonical_id: id.clone(),
                    version: new_pkg.version.clone(),
                    dev: new_pkg.dev,
                });
            }
            Some(old_pkg) => {
                if old_pkg.version != new_pkg.version
                    || old_pkg.digest != new_pkg.digest
                    || old_pkg.dev != new_pkg.dev
                {
                    changed.push(DiffChange {
                        canonical_id: id.clone(),
                        old_version: old_pkg.version.clone(),
                        new_version: new_pkg.version.clone(),
                        digest_changed: old_pkg.digest != new_pkg.digest,
                        dev_changed: old_pkg.dev != new_pkg.dev,
                    });
                }
            }
        }
    }

    // Find removed packages.
    for (id, old_pkg) in &old.packages {
        if !new.packages.contains_key(id) {
            removed.push(DiffEntry {
                canonical_id: id.clone(),
                version: old_pkg.version.clone(),
                dev: old_pkg.dev,
            });
        }
    }

    // Sort for deterministic output.
    added.sort_by(|a, b| a.canonical_id.cmp(&b.canonical_id));
    removed.sort_by(|a, b| a.canonical_id.cmp(&b.canonical_id));
    changed.sort_by(|a, b| a.canonical_id.cmp(&b.canonical_id));

    let total_changes = added.len() + removed.len() + changed.len();

    LockfileDiff {
        added,
        removed,
        changed,
        total_changes,
    }
}

impl LockfileDiff {
    /// Whether there are no changes.
    pub fn is_empty(&self) -> bool {
        self.total_changes == 0
    }

    /// Format the diff as a human-readable summary.
    pub fn summary(&self) -> String {
        if self.is_empty() {
            return "No changes.".to_string();
        }

        let mut out = String::new();

        if !self.added.is_empty() {
            out.push_str(&format!("Added {} package(s):\n", self.added.len()));
            for entry in &self.added {
                let dev_marker = if entry.dev { " (dev)" } else { "" };
                out.push_str(&format!(
                    "  + {} @ {}{}\n",
                    entry.canonical_id, entry.version, dev_marker
                ));
            }
        }

        if !self.removed.is_empty() {
            out.push_str(&format!("Removed {} package(s):\n", self.removed.len()));
            for entry in &self.removed {
                out.push_str(&format!("  - {} @ {}\n", entry.canonical_id, entry.version));
            }
        }

        if !self.changed.is_empty() {
            out.push_str(&format!("Changed {} package(s):\n", self.changed.len()));
            for change in &self.changed {
                let detail = if change.digest_changed && change.old_version == change.new_version {
                    " (digest changed)"
                } else {
                    ""
                };
                out.push_str(&format!(
                    "  ~ {} {} -> {}{}\n",
                    change.canonical_id, change.old_version, change.new_version, detail
                ));
            }
        }

        out.push_str(&format!(
            "\nTotal: {} addition(s), {} removal(s), {} update(s)\n",
            self.added.len(),
            self.removed.len(),
            self.changed.len()
        ));

        out
    }
}

impl std::fmt::Display for LockfileDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;
    use rusk_core::*;

    fn make_pkg(name: &str, major: u64, minor: u64, patch: u64) -> LockedPackage {
        LockedPackage {
            package: PackageId::js(name),
            version: Version::Semver(semver::Version::new(major, minor, patch)),
            ecosystem: Ecosystem::Js,
            digest: Sha256Digest::compute(
                format!("{}-{}.{}.{}", name, major, minor, patch).as_bytes(),
            ),
            source_url: None,
            dependencies: vec![],
            dev: false,
            signer: None,
            provenance: None,
            resolved_by: None,
        }
    }

    #[test]
    fn empty_diff() {
        let lf = Lockfile::new();
        let diff = diff_lockfiles(&lf, &lf);
        assert!(diff.is_empty());
        assert_eq!(diff.total_changes, 0);
    }

    #[test]
    fn detect_additions() {
        let old = Lockfile::new();
        let mut new = Lockfile::new();
        new.add_package(make_pkg("express", 4, 18, 2));

        let diff = diff_lockfiles(&old, &new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.changed.len(), 0);
    }

    #[test]
    fn detect_removals() {
        let mut old = Lockfile::new();
        old.add_package(make_pkg("express", 4, 18, 2));
        let new = Lockfile::new();

        let diff = diff_lockfiles(&old, &new);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.changed.len(), 0);
    }

    #[test]
    fn detect_version_change() {
        let mut old = Lockfile::new();
        old.add_package(make_pkg("express", 4, 18, 1));
        let mut new = Lockfile::new();
        new.add_package(make_pkg("express", 4, 18, 2));

        let diff = diff_lockfiles(&old, &new);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(
            diff.changed[0].old_version.to_string(),
            "4.18.1"
        );
        assert_eq!(
            diff.changed[0].new_version.to_string(),
            "4.18.2"
        );
    }

    #[test]
    fn summary_output() {
        let old = Lockfile::new();
        let mut new = Lockfile::new();
        new.add_package(make_pkg("express", 4, 18, 2));
        new.add_package(make_pkg("lodash", 4, 17, 21));

        let diff = diff_lockfiles(&old, &new);
        let summary = diff.summary();
        assert!(summary.contains("Added 2 package(s)"));
        assert!(summary.contains("express"));
        assert!(summary.contains("lodash"));
    }

    #[test]
    fn identical_lockfiles_no_diff() {
        let mut lf = Lockfile::new();
        lf.add_package(make_pkg("express", 4, 18, 2));
        lf.add_package(make_pkg("lodash", 4, 17, 21));

        let diff = diff_lockfiles(&lf, &lf);
        assert!(diff.is_empty());
    }
}
