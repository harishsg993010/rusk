//! Lockfile integrity verification.
//!
//! Computes and verifies an integrity hash over all locked packages,
//! ensuring the lockfile hasn't been tampered with.

use crate::schema::Lockfile;
use rusk_core::Sha256Digest;
use sha2::{Digest, Sha256};

/// Compute the integrity root hash for a lockfile.
///
/// The integrity hash is a SHA-256 digest computed over all locked packages
/// in deterministic (sorted) order. Each package contributes its canonical
/// ID, version string, and artifact digest to the hash.
///
/// This produces a single hash that changes whenever any package in the
/// lockfile changes, making it suitable for tamper detection.
pub fn compute_integrity_root(lockfile: &Lockfile) -> Sha256Digest {
    let mut hasher = Sha256::new();

    // Hash the lockfile version.
    hasher.update(lockfile.version.to_le_bytes());

    // Hash each package in deterministic order (BTreeMap guarantees this).
    for (canonical_id, pkg) in &lockfile.packages {
        // Delimiter between entries.
        hasher.update(b"\x00");
        // Canonical ID.
        hasher.update(canonical_id.as_bytes());
        hasher.update(b"\x01");
        // Version.
        hasher.update(pkg.version.to_string().as_bytes());
        hasher.update(b"\x01");
        // Artifact digest.
        hasher.update(&pkg.digest.0);
        hasher.update(b"\x01");
        // Dev flag.
        hasher.update(&[pkg.dev as u8]);
        hasher.update(b"\x01");
        // Dependencies (sorted within each package).
        let mut dep_ids: Vec<&str> = pkg
            .dependencies
            .iter()
            .map(|d| d.canonical_id.as_str())
            .collect();
        dep_ids.sort();
        for dep_id in dep_ids {
            hasher.update(dep_id.as_bytes());
            hasher.update(b"\x02");
        }
    }

    let result = hasher.finalize();
    Sha256Digest(result.into())
}

/// Verify the integrity of a lockfile against its stored integrity hash.
///
/// Returns `Ok(())` if the integrity matches, or an error describing the mismatch.
pub fn verify_integrity(lockfile: &Lockfile) -> Result<(), IntegrityError> {
    let stored = match &lockfile.integrity {
        Some(hex) => Sha256Digest::from_hex(hex)
            .map_err(|_| IntegrityError::InvalidStoredHash(hex.clone()))?,
        None => return Err(IntegrityError::NoIntegrityHash),
    };

    let computed = compute_integrity_root(lockfile);

    if stored == computed {
        Ok(())
    } else {
        Err(IntegrityError::Mismatch {
            expected: stored.to_hex(),
            actual: computed.to_hex(),
        })
    }
}

/// Stamp a lockfile with its current integrity hash.
///
/// This should be called after all modifications are complete and before
/// writing to disk.
pub fn stamp_integrity(lockfile: &mut Lockfile) {
    let hash = compute_integrity_root(lockfile);
    lockfile.integrity = Some(hash.to_hex());
}

/// Error type for integrity verification.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("lockfile has no integrity hash")]
    NoIntegrityHash,

    #[error("invalid stored integrity hash: {0}")]
    InvalidStoredHash(String),

    #[error("integrity mismatch: expected {expected}, got {actual}")]
    Mismatch { expected: String, actual: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::*;
    use rusk_core::*;

    fn make_lockfile() -> Lockfile {
        let mut lf = Lockfile::new();
        lf.add_package(LockedPackage {
            package: PackageId::js("express"),
            version: Version::Semver(semver::Version::new(4, 18, 2)),
            ecosystem: Ecosystem::Js,
            digest: Sha256Digest::compute(b"express-4.18.2"),
            source_url: None,
            dependencies: vec![],
            dev: false,
            signer: None,
            resolved_by: None,
        });
        lf.add_package(LockedPackage {
            package: PackageId::js("lodash"),
            version: Version::Semver(semver::Version::new(4, 17, 21)),
            ecosystem: Ecosystem::Js,
            digest: Sha256Digest::compute(b"lodash-4.17.21"),
            source_url: None,
            dependencies: vec![],
            dev: false,
            signer: None,
            resolved_by: None,
        });
        lf
    }

    #[test]
    fn integrity_hash_is_deterministic() {
        let lf = make_lockfile();
        let h1 = compute_integrity_root(&lf);
        let h2 = compute_integrity_root(&lf);
        assert_eq!(h1, h2);
    }

    #[test]
    fn integrity_changes_on_modification() {
        let lf1 = make_lockfile();
        let h1 = compute_integrity_root(&lf1);

        let mut lf2 = make_lockfile();
        lf2.packages
            .get_mut(&PackageId::js("express").canonical())
            .unwrap()
            .digest = Sha256Digest::compute(b"different content");
        let h2 = compute_integrity_root(&lf2);

        assert_ne!(h1, h2);
    }

    #[test]
    fn stamp_and_verify() {
        let mut lf = make_lockfile();
        stamp_integrity(&mut lf);
        assert!(lf.integrity.is_some());
        verify_integrity(&lf).unwrap();
    }

    #[test]
    fn verify_detects_tamper() {
        let mut lf = make_lockfile();
        stamp_integrity(&mut lf);

        // Tamper with a digest.
        lf.packages
            .get_mut(&PackageId::js("express").canonical())
            .unwrap()
            .digest = Sha256Digest::zero();

        let result = verify_integrity(&lf);
        assert!(matches!(result, Err(IntegrityError::Mismatch { .. })));
    }

    #[test]
    fn verify_no_hash() {
        let lf = make_lockfile();
        let result = verify_integrity(&lf);
        assert!(matches!(result, Err(IntegrityError::NoIntegrityHash)));
    }

    #[test]
    fn empty_lockfile_has_stable_hash() {
        let lf1 = Lockfile::new();
        let lf2 = Lockfile::new();
        assert_eq!(
            compute_integrity_root(&lf1),
            compute_integrity_root(&lf2)
        );
    }
}
