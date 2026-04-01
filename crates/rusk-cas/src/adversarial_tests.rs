//! Adversarial security tests for CAS integrity, digest verification, and
//! revocation cache invalidation.
//!
//! These tests simulate corruption, deduplication races, epoch-based cache
//! invalidation, and revocation-state persistence scenarios that a supply-chain
//! attacker or bitrot condition might trigger.

use crate::store::{CasStore, WriteOutcome};
use crate::integrity::IntegrityChecker;
use crate::layout::StoreLayout;
use rusk_core::Sha256Digest;

// ---------------------------------------------------------------------------
// CAS Corruption Tests
// ---------------------------------------------------------------------------

/// Write data to CAS, then try to read it back using a *different* digest.
/// The store must return `None` because the wrong key maps to a path that
/// does not exist.
#[test]
fn test_cas_rejects_wrong_digest() {
    let dir = tempfile::tempdir().unwrap();
    let store = CasStore::open(dir.path()).unwrap();

    let data = b"legitimate package content";
    let outcome = store.write(data).unwrap();
    let real_digest = match outcome {
        WriteOutcome::Written { digest, .. } => digest,
        WriteOutcome::AlreadyExists { digest } => digest,
    };

    // Fabricate a different digest (SHA-256 of completely different data).
    let wrong_digest = Sha256Digest::compute(b"attacker-controlled garbage");
    assert_ne!(real_digest, wrong_digest, "precondition: digests must differ");

    // Reading with the wrong digest must yield None.
    let result = store.read(&wrong_digest).unwrap();
    assert!(
        result.is_none(),
        "CAS must not return data for a digest that was never written"
    );
}

/// Verify that CAS writes are atomic: the blob appears at its final path only
/// after the write completes (no partially-written files are visible).
///
/// We confirm atomicity by checking that the blob path does not exist before
/// the write, exists after the write, and contains the full expected content.
#[test]
fn test_cas_atomic_write_no_partial_reads() {
    let dir = tempfile::tempdir().unwrap();
    let store = CasStore::open(dir.path()).unwrap();

    let data = b"atomic write payload -- no partial reads allowed";
    let digest = Sha256Digest::compute(data);

    // Before write: blob must not exist.
    assert!(
        !store.contains(&digest),
        "blob must not exist before write"
    );

    // Perform the write.
    let outcome = store.write(data).unwrap();
    assert!(
        matches!(outcome, WriteOutcome::Written { .. }),
        "first write should succeed"
    );

    // After write: blob must exist and be complete.
    let read_back = store.read(&digest).unwrap().expect("blob must exist after write");
    assert_eq!(
        read_back.as_slice(),
        data,
        "read-back must match original data exactly (no partial content)"
    );
}

/// Writing the same data twice must return `AlreadyExists` on the second
/// attempt and must not corrupt the stored blob.
#[test]
fn test_cas_duplicate_write_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let store = CasStore::open(dir.path()).unwrap();

    let data = b"duplicate content test";

    // First write.
    let first = store.write(data).unwrap();
    let digest = match &first {
        WriteOutcome::Written { digest, .. } => *digest,
        other => panic!("expected Written, got {:?}", other),
    };

    // Second write of identical data.
    let second = store.write(data).unwrap();
    match &second {
        WriteOutcome::AlreadyExists { digest: d2 } => {
            assert_eq!(*d2, digest, "AlreadyExists digest must match first write");
        }
        other => panic!("expected AlreadyExists, got {:?}", other),
    }

    // Data on disk must still be intact.
    let read_back = store.read(&digest).unwrap().expect("blob must still exist");
    assert_eq!(read_back.as_slice(), data);
}

/// Simulate on-disk corruption: write valid data, overwrite the blob file with
/// garbage, then read it back. The current implementation does NOT re-verify the
/// hash on read, so the caller gets corrupted bytes.
///
/// This test documents the known limitation and shows that the `IntegrityChecker`
/// is the correct mechanism for detecting this scenario.
#[test]
fn test_cas_corrupt_blob_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let store = CasStore::open(dir.path()).unwrap();

    let data = b"original valid content";
    let outcome = store.write(data).unwrap();
    let digest = match outcome {
        WriteOutcome::Written { digest, .. } => digest,
        WriteOutcome::AlreadyExists { digest } => digest,
    };

    // Locate the blob on disk and overwrite it with garbage.
    let layout = StoreLayout::new(dir.path().to_path_buf());
    let blob_path = layout.blob_path(&digest);
    let garbage = b"CORRUPTED DATA -- attacker or bitrot";
    std::fs::write(&blob_path, garbage).unwrap();

    // read() returns whatever is on disk -- no re-verification.
    let read_back = store.read(&digest).unwrap().expect("file still exists");
    assert_eq!(
        read_back.as_slice(),
        garbage,
        "KNOWN LIMITATION: CAS read() does not re-verify digest; returns corrupted bytes"
    );

    // IntegrityChecker correctly detects the corruption.
    let checker = IntegrityChecker::new(layout);
    let result = checker.check_blob(&digest).unwrap();
    assert!(
        !result.valid,
        "IntegrityChecker must detect the corruption"
    );
}

/// Identical content from two "different packages" must produce the same digest
/// and map to the same path on disk (content-addressed deduplication).
#[test]
fn test_cas_content_addressed_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let store = CasStore::open(dir.path()).unwrap();

    let shared_content = b"shared library bytes -- identical across packages";

    // "Package A" writes the content.
    let outcome_a = store.write(shared_content).unwrap();
    let digest_a = match &outcome_a {
        WriteOutcome::Written { digest, .. } => *digest,
        WriteOutcome::AlreadyExists { digest } => *digest,
    };

    // "Package B" writes the exact same content.
    let outcome_b = store.write(shared_content).unwrap();
    let digest_b = match &outcome_b {
        WriteOutcome::AlreadyExists { digest } => *digest,
        other => panic!("expected AlreadyExists for duplicate content, got {:?}", other),
    };

    assert_eq!(digest_a, digest_b, "same content must produce same digest");

    // Both map to the same path.
    let layout = StoreLayout::new(dir.path().to_path_buf());
    assert_eq!(
        layout.blob_path(&digest_a),
        layout.blob_path(&digest_b),
        "same digest must resolve to the same filesystem path"
    );
}

/// Two distinct byte sequences must produce different digests and be stored
/// at separate paths.
#[test]
fn test_cas_different_content_different_digest() {
    let dir = tempfile::tempdir().unwrap();
    let store = CasStore::open(dir.path()).unwrap();

    let data_a = b"package-alpha version 1.0.0";
    let data_b = b"package-beta version 2.0.0";

    let outcome_a = store.write(data_a).unwrap();
    let outcome_b = store.write(data_b).unwrap();

    let digest_a = match outcome_a {
        WriteOutcome::Written { digest, .. } => digest,
        WriteOutcome::AlreadyExists { digest } => digest,
    };
    let digest_b = match outcome_b {
        WriteOutcome::Written { digest, .. } => digest,
        WriteOutcome::AlreadyExists { digest } => digest,
    };

    assert_ne!(digest_a, digest_b, "different content must yield different digests");

    let layout = StoreLayout::new(dir.path().to_path_buf());
    assert_ne!(
        layout.blob_path(&digest_a),
        layout.blob_path(&digest_b),
        "different digests must map to different paths"
    );

    // Each blob reads back correctly.
    assert_eq!(store.read(&digest_a).unwrap().unwrap().as_slice(), data_a);
    assert_eq!(store.read(&digest_b).unwrap().unwrap().as_slice(), data_b);
}

// ---------------------------------------------------------------------------
// Digest Verification Tests
// ---------------------------------------------------------------------------

/// Verify SHA-256 against NIST test vectors.
///   - empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
///   - "abc":        ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
///   - "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
///                   248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
#[test]
fn test_sha256_known_vectors() {
    // Vector 1: empty string
    let d_empty = Sha256Digest::compute(b"");
    assert_eq!(
        d_empty.to_hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 of empty string must match NIST vector"
    );

    // Vector 2: "abc"
    let d_abc = Sha256Digest::compute(b"abc");
    assert_eq!(
        d_abc.to_hex(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 of 'abc' must match NIST vector"
    );

    // Vector 3: the 448-bit NIST test message
    let d_long = Sha256Digest::compute(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
    assert_eq!(
        d_long.to_hex(),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "SHA-256 of 448-bit NIST message must match"
    );
}

/// Compute digest of data A and data B, verify they do not match.
#[test]
fn test_digest_mismatch_detection() {
    let digest_a = Sha256Digest::compute(b"trusted artifact");
    let digest_b = Sha256Digest::compute(b"tampered artifact");

    assert_ne!(
        digest_a, digest_b,
        "digests of different inputs must differ"
    );

    // Explicitly check byte-level inequality.
    assert_ne!(digest_a.0, digest_b.0);
}

/// `Sha256Digest::zero()` is a 32-byte all-zero sentinel. Verify it never
/// matches the digest of any real (non-empty) content, and also does not
/// match the empty-string digest.
#[test]
fn test_zero_digest_is_sentinel() {
    let zero = Sha256Digest::zero();

    // Must not match the empty-string hash.
    let empty_hash = Sha256Digest::compute(b"");
    assert_ne!(
        zero, empty_hash,
        "zero digest must not equal SHA-256 of empty string"
    );

    // Must not match arbitrary content.
    let content_hash = Sha256Digest::compute(b"any content at all");
    assert_ne!(zero, content_hash);

    // The underlying bytes must all be zero.
    assert!(zero.0.iter().all(|&b| b == 0));
}

/// Generate several distinct byte sequences, compute their digests, convert
/// to hex, parse back, and verify round-trip equality.
#[test]
fn test_digest_hex_roundtrip_fuzz() {
    // Use a simple PRNG-like iteration to avoid pulling in rand as a dependency.
    let mut seed: u64 = 0xDEAD_BEEF_CAFE_BABE;
    for i in 0u32..100 {
        // Mix the seed to produce pseudo-random bytes.
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64);
        let bytes = seed.to_le_bytes();

        let digest = Sha256Digest::compute(&bytes);
        let hex_str = digest.to_hex();

        // Hex string must be exactly 64 characters (256 bits / 4 bits per hex char).
        assert_eq!(hex_str.len(), 64, "hex representation must be 64 chars");

        // Round-trip.
        let parsed = Sha256Digest::from_hex(&hex_str)
            .expect("valid hex must parse back successfully");
        assert_eq!(
            digest, parsed,
            "round-trip through hex must preserve digest (iteration {})",
            i
        );
    }
}

// ---------------------------------------------------------------------------
// Revocation Cache Invalidation Tests
// ---------------------------------------------------------------------------

/// Insert an entry into `SignatureCache` at epoch 1, advance to epoch 2,
/// and verify the old entry is no longer returned.
#[test]
fn test_revocation_epoch_invalidates_signature_cache() {
    use rusk_signing::cache::SignatureCache;
    use rusk_signing::verifier::{SignatureAlgorithm, VerifiedSignature};
    use rusk_core::SignerIdentity;

    let cache = SignatureCache::new(100, 1);

    let digest = Sha256Digest::compute(b"cached-artifact");
    let verified = VerifiedSignature {
        signer: SignerIdentity {
            issuer: "https://accounts.example.com".to_string(),
            subject: "alice@example.com".to_string(),
            fingerprint: None,
        },
        algorithm: SignatureAlgorithm::Ed25519,
        timestamp: chrono::Utc::now(),
        artifact_digest: digest,
    };

    cache.insert(digest, verified.clone());
    assert!(
        cache.get(&digest).is_some(),
        "entry at current epoch must be retrievable"
    );

    // Advance to epoch 2.
    let new_epoch = cache.advance_epoch();
    assert_eq!(new_epoch, 2);

    // Old entry must be gone (lazy invalidation on access).
    assert!(
        cache.get(&digest).is_none(),
        "entry from epoch 1 must be invalidated after advancing to epoch 2"
    );
}

/// Verify that a signer starts as clear, becomes blocked after adding a
/// signer revocation, and the check reflects this immediately.
#[test]
fn test_revoked_signer_blocks_after_update() {
    use rusk_revocation::bundle::{RevocationBundle, RevocationEntry};
    use rusk_revocation::check::RevocationChecker;
    use rusk_revocation::store::RevocationState;
    use rusk_core::SignerIdentity;

    let mut state = RevocationState::new();
    let signer = SignerIdentity {
        issuer: "https://accounts.google.com".to_string(),
        subject: "compromised@example.com".to_string(),
        fingerprint: None,
    };

    // Before revocation: signer is clear.
    let checker = RevocationChecker::new(&state);
    assert!(
        checker.check_signer(&signer).is_clear(),
        "signer must be clear before any revocation"
    );

    // Add signer revocation.
    let mut bundle = RevocationBundle::new(1);
    bundle.add_entry(RevocationEntry::Signer {
        issuer: signer.issuer.clone(),
        subject: signer.subject.clone(),
        reason: "key compromise detected".to_string(),
        revoked_at: chrono::Utc::now(),
    });
    state.apply_bundle(&bundle).unwrap();

    // After revocation: signer must be blocked.
    let checker = RevocationChecker::new(&state);
    assert!(
        checker.check_signer(&signer).is_revoked(),
        "signer must be revoked after applying revocation bundle"
    );
}

/// Add an artifact digest to the revocation set and verify that
/// `check_artifact` returns a revoked result.
#[test]
fn test_revoked_artifact_blocks_install() {
    use rusk_revocation::bundle::{RevocationBundle, RevocationEntry};
    use rusk_revocation::check::RevocationChecker;
    use rusk_revocation::store::RevocationState;

    let malicious_data = b"malicious payload injected via supply chain attack";
    let digest = Sha256Digest::compute(malicious_data);

    let mut state = RevocationState::new();
    let mut bundle = RevocationBundle::new(1);
    bundle.add_entry(RevocationEntry::Artifact {
        digest,
        reason: "contains cryptocurrency miner".to_string(),
        revoked_at: chrono::Utc::now(),
    });
    state.apply_bundle(&bundle).unwrap();

    let checker = RevocationChecker::new(&state);
    let result = checker.check_artifact(&digest);
    assert!(
        result.is_revoked(),
        "artifact in revocation set must be blocked"
    );

    // A different, legitimate artifact must still be clear.
    let legit_digest = Sha256Digest::compute(b"legitimate package");
    assert!(
        checker.check_artifact(&legit_digest).is_clear(),
        "non-revoked artifact must pass"
    );
}

/// Applying a revocation bundle whose epoch is <= the current epoch must be
/// rejected with a `StaleEpoch` error.
#[test]
fn test_stale_epoch_rejected() {
    use rusk_revocation::bundle::{RevocationBundle, RevocationEntry};
    use rusk_revocation::store::RevocationState;

    let mut state = RevocationState::new();

    // Apply epoch 5.
    let mut bundle5 = RevocationBundle::new(5);
    bundle5.add_entry(RevocationEntry::Artifact {
        digest: Sha256Digest::compute(b"x"),
        reason: "test".to_string(),
        revoked_at: chrono::Utc::now(),
    });
    state.apply_bundle(&bundle5).unwrap();
    assert_eq!(state.epoch, 5);

    // Try to apply epoch 3 (stale, less than current).
    let bundle3 = RevocationBundle::new(3);
    let err = state.apply_bundle(&bundle3);
    assert!(
        err.is_err(),
        "bundle with epoch 3 must be rejected when current epoch is 5"
    );

    // Try to apply epoch 5 (equal to current).
    let bundle5_dup = RevocationBundle::new(5);
    let err = state.apply_bundle(&bundle5_dup);
    assert!(
        err.is_err(),
        "bundle with epoch equal to current must be rejected"
    );

    // Epoch 6 must be accepted.
    let bundle6 = RevocationBundle::new(6);
    assert!(
        state.apply_bundle(&bundle6).is_ok(),
        "bundle with epoch > current must be accepted"
    );
    assert_eq!(state.epoch, 6);
}

/// Persist `RevocationState` to a JSON file, reload it, and verify that all
/// revocation entries survive the round-trip.
#[test]
fn test_revocation_state_persists_across_reload() {
    use rusk_revocation::bundle::{RevocationBundle, RevocationEntry};
    use rusk_revocation::store::RevocationState;

    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("revocation_state.json");

    // Build a state with several revocation types.
    let mut state = RevocationState::new();
    let mut bundle = RevocationBundle::new(42);

    bundle.add_entry(RevocationEntry::Signer {
        issuer: "https://issuer.example".to_string(),
        subject: "evil@example.com".to_string(),
        reason: "compromised key".to_string(),
        revoked_at: chrono::Utc::now(),
    });
    bundle.add_entry(RevocationEntry::Artifact {
        digest: Sha256Digest::compute(b"bad-artifact"),
        reason: "malware".to_string(),
        revoked_at: chrono::Utc::now(),
    });
    bundle.add_entry(RevocationEntry::PackageVersion {
        ecosystem: "npm".to_string(),
        package_name: "evil-lib".to_string(),
        version: "0.9.9".to_string(),
        reason: "supply chain attack".to_string(),
        revoked_at: chrono::Utc::now(),
    });

    state.apply_bundle(&bundle).unwrap();

    // Persist.
    state.save_to_file(&state_path).unwrap();

    // Reload.
    let loaded = RevocationState::load_from_file(&state_path).unwrap();

    // Verify all fields survived.
    assert_eq!(loaded.epoch, 42);
    assert!(loaded.is_signer_revoked("https://issuer.example", "evil@example.com"));
    assert!(loaded.is_artifact_revoked(&Sha256Digest::compute(b"bad-artifact")));
    assert!(loaded.is_version_revoked("npm", "evil-lib", "0.9.9"));
    assert_eq!(loaded.total_revocations(), state.total_revocations());

    // Items that were never revoked must remain clear.
    assert!(!loaded.is_signer_revoked("https://issuer.example", "good@example.com"));
    assert!(!loaded.is_artifact_revoked(&Sha256Digest::compute(b"good-artifact")));
}

/// Add a yanked package version to the revocation set and verify that
/// `check_version` returns a revoked result.
#[test]
fn test_yanked_version_excluded() {
    use rusk_revocation::bundle::{RevocationBundle, RevocationEntry};
    use rusk_revocation::check::RevocationChecker;
    use rusk_revocation::store::RevocationState;

    let mut state = RevocationState::new();
    let mut bundle = RevocationBundle::new(1);
    bundle.add_entry(RevocationEntry::PackageVersion {
        ecosystem: "python".to_string(),
        package_name: "left-pad-py".to_string(),
        version: "1.2.3".to_string(),
        reason: "yanked: author request".to_string(),
        revoked_at: chrono::Utc::now(),
    });
    state.apply_bundle(&bundle).unwrap();

    let checker = RevocationChecker::new(&state);

    // Yanked version must be blocked.
    assert!(
        checker.check_version("python", "left-pad-py", "1.2.3").is_revoked(),
        "yanked version must be reported as revoked"
    );

    // Other versions of the same package must be clear.
    assert!(
        checker.check_version("python", "left-pad-py", "1.2.4").is_clear(),
        "non-yanked version must pass"
    );

    // Same version in a different ecosystem must be clear.
    assert!(
        checker.check_version("npm", "left-pad-py", "1.2.3").is_clear(),
        "version in a different ecosystem must not be affected"
    );
}
