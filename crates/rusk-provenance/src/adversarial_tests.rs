//! Adversarial security tests for rusk provenance, signing, TUF, transparency,
//! and DSSE subsystems.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal base64 encoder for test payloads (avoids pulling in a base64 crate).
fn simple_base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Build a "good" provenance baseline. Tests mutate individual fields to
/// introduce the specific adversarial condition under test.
fn baseline_provenance() -> crate::normalize::NormalizedProvenance {
    use crate::normalize::*;
    use rusk_core::{BuilderIdentity, Sha256Digest};
    use url::Url;

    NormalizedProvenance {
        subjects: vec![ProvenanceSubject {
            name: "pkg-1.0.0.tar.gz".to_string(),
            sha256: Sha256Digest::compute(b"artifact"),
        }],
        source: Some(ProvenanceSource {
            repository_url: Url::parse("https://github.com/owner/repo").unwrap(),
            git_ref: Some("refs/tags/v1.0.0".to_string()),
            commit_sha: Some("abc123def456".to_string()),
        }),
        builder: ProvenanceBuilder {
            identity: BuilderIdentity {
                builder_type: "github-actions".to_string(),
                builder_id: "https://github.com/actions/runner".to_string(),
            },
            version: Some("2.310.0".to_string()),
        },
        build_config: ProvBuildConfig {
            command: None,
            environment: HashMap::new(),
            hermetic: true,
            reproducible: true,
        },
        materials: vec![ProvMaterial {
            uri: "git+https://github.com/owner/repo".to_string(),
            digest: Some(Sha256Digest::compute(b"dep")),
        }],
        metadata: ProvMetadata {
            build_started: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
            build_finished: Some(chrono::Utc::now()),
            slsa_level: Some(3),
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
        },
    }
}

// ===========================================================================
// 1-5: Provenance Tests
// ===========================================================================

/// 1. Subject digest in the provenance does not match the artifact digest the
///    consumer expects. This catches the case where an attacker swaps an
///    attestation from one package onto a different artifact.
#[test]
fn test_subject_digest_mismatch() {
    use rusk_core::Sha256Digest;

    let aaa = Sha256Digest::from_hex(&"aa".repeat(32)).unwrap();
    let bbb = Sha256Digest::from_hex(&"bb".repeat(32)).unwrap();

    let mut prov = baseline_provenance();
    prov.subjects = vec![crate::normalize::ProvenanceSubject {
        name: "pkg.tar.gz".to_string(),
        sha256: aaa,
    }];

    assert!(
        !prov.covers_digest(&bbb),
        "provenance with subject digest aaa... must NOT match artifact digest bbb..."
    );
}

/// 2. Provenance with no source information should be flagged as NoSourceInfo.
#[test]
fn test_no_source_repo_flagged() {
    use crate::risk::{compute_risk_flags, RiskFlag};

    let mut prov = baseline_provenance();
    prov.source = None;

    let flags = compute_risk_flags(&prov);
    assert!(
        flags.contains(&RiskFlag::NoSourceInfo),
        "missing source must trigger NoSourceInfo, got: {:?}",
        flags
    );
}

/// 3. A non-hermetic build environment should be flagged.
#[test]
fn test_non_hermetic_flagged() {
    use crate::risk::{compute_risk_flags, RiskFlag};

    let mut prov = baseline_provenance();
    prov.build_config.hermetic = false;

    let flags = compute_risk_flags(&prov);
    assert!(
        flags.contains(&RiskFlag::NonHermeticBuild),
        "non-hermetic build must be flagged, got: {:?}",
        flags
    );
}

/// 4. An unknown builder type should be flagged.
#[test]
fn test_unknown_builder_flagged() {
    use crate::risk::{compute_risk_flags, RiskFlag};

    let mut prov = baseline_provenance();
    prov.builder.identity.builder_type = "unknown".to_string();
    prov.builder.identity.builder_id = "https://unknown-system.example.com/build".to_string();

    let flags = compute_risk_flags(&prov);
    assert!(
        flags.contains(&RiskFlag::UnknownBuilder),
        "unknown builder type must be flagged, got: {:?}",
        flags
    );
}

/// 5. A mutable source reference (branch, not tag) should be flagged.
#[test]
fn test_mutable_ref_flagged() {
    use crate::risk::{compute_risk_flags, RiskFlag};

    let mut prov = baseline_provenance();
    prov.source.as_mut().unwrap().git_ref = Some("refs/heads/main".to_string());

    let flags = compute_risk_flags(&prov);
    assert!(
        flags.contains(&RiskFlag::MutableSourceRef),
        "mutable branch ref must trigger MutableSourceRef, got: {:?}",
        flags
    );
}

// ===========================================================================
// 6-8: Signing Tests
// ===========================================================================

/// 6. Wildcard subject pattern in IdentityMatcher should match.
#[test]
fn test_identity_wildcard_match() {
    use rusk_core::SignerIdentity;
    use rusk_signing::IdentityMatcher;

    let mut matcher = IdentityMatcher::new();
    // The IdentityMatcher supports trailing `*` wildcard. "*@corp.com" is a
    // literal pattern (no trailing wildcard), so instead we use a pattern that
    // exploits trailing-star: we want any subject ending in "@corp.com".
    // Since IdentityMatcher only supports trailing `*`, we set up a rule that
    // matches "user@corp.com" via a prefix glob.
    matcher.add_rule(None, "*".to_string());

    let user = SignerIdentity {
        issuer: "https://idp.corp.com".to_string(),
        subject: "user@corp.com".to_string(),
        fingerprint: None,
    };
    assert!(
        matcher.matches(&user),
        "wildcard '*' must match 'user@corp.com'"
    );

    // Now test a more targeted trailing-star pattern
    let mut matcher2 = IdentityMatcher::new();
    matcher2.add_rule(None, "user@corp*".to_string());

    assert!(
        matcher2.matches(&user),
        "wildcard 'user@corp*' must match 'user@corp.com'"
    );

    let evil = SignerIdentity {
        issuer: "https://idp.evil.com".to_string(),
        subject: "user@evil.com".to_string(),
        fingerprint: None,
    };
    assert!(
        !matcher2.matches(&evil),
        "wildcard 'user@corp*' must NOT match 'user@evil.com'"
    );
}

/// 7. Exact subject mismatch should not match.
#[test]
fn test_identity_exact_mismatch() {
    use rusk_core::SignerIdentity;
    use rusk_signing::IdentityMatcher;

    let mut matcher = IdentityMatcher::new();
    matcher.add_rule(None, "a@b.com".to_string());

    let mismatched = SignerIdentity {
        issuer: "https://issuer.example.com".to_string(),
        subject: "c@b.com".to_string(),
        fingerprint: None,
    };
    assert!(
        !matcher.matches(&mismatched),
        "exact rule 'a@b.com' must NOT match 'c@b.com'"
    );
}

/// 8. SignatureCache entries from a prior epoch must be treated as a miss after
///    the epoch advances.
#[test]
fn test_signature_cache_epoch_invalidation() {
    use rusk_core::{Sha256Digest, SignerIdentity};
    use rusk_signing::cache::SignatureCache;
    use rusk_signing::verifier::{SignatureAlgorithm, VerifiedSignature};

    let cache = SignatureCache::new(100, 1); // start at epoch 1
    let digest = Sha256Digest::compute(b"cached-artifact");

    let verified = VerifiedSignature {
        signer: SignerIdentity {
            issuer: "test-issuer".to_string(),
            subject: "test@example.com".to_string(),
            fingerprint: None,
        },
        algorithm: SignatureAlgorithm::Ed25519,
        timestamp: chrono::Utc::now(),
        artifact_digest: digest,
    };

    cache.insert(digest, verified);
    assert!(cache.get(&digest).is_some(), "entry must be present at epoch 1");

    // Advance to epoch 2
    cache.advance_epoch();
    assert_eq!(cache.current_epoch(), 2);
    assert!(
        cache.get(&digest).is_none(),
        "entry from epoch 1 must be a miss at epoch 2"
    );
}

// ===========================================================================
// 9-11: TUF Tests
// ===========================================================================

/// 9. Expired CommonMetadata must be detected.
#[test]
fn test_tuf_expired_metadata_detected() {
    use rusk_tuf::metadata::CommonMetadata;

    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    let meta = CommonMetadata {
        spec_version: "1.0.31".to_string(),
        version: 1,
        expires: past,
    };

    assert!(
        meta.is_expired_at(&chrono::Utc::now()),
        "metadata with past expiry must be detected as expired"
    );
}

/// 10. DelegatedRole path matching: prefix match and negative case.
#[test]
fn test_tuf_delegation_path_match() {
    use rusk_tuf::DelegatedRole;

    let role = DelegatedRole {
        name: "react-team".to_string(),
        keyids: vec![],
        threshold: 1,
        terminating: false,
        paths: vec!["packages/react/*".to_string()],
    };

    assert!(
        role.matches_path("packages/react/index.js"),
        "packages/react/* must match packages/react/index.js"
    );
    assert!(
        !role.matches_path("packages/vue/index.js"),
        "packages/react/* must NOT match packages/vue/index.js"
    );
}

/// 11. TufRole canonical filenames.
#[test]
fn test_tuf_role_filenames() {
    use rusk_tuf::TufRole;

    assert_eq!(TufRole::Root.filename(), "root.json");
    assert_eq!(TufRole::Timestamp.filename(), "timestamp.json");
    assert_eq!(TufRole::Snapshot.filename(), "snapshot.json");
    assert_eq!(TufRole::Targets.filename(), "targets.json");
}

// ===========================================================================
// 12-16: Transparency Tests
// ===========================================================================

/// 12. Build a 4-leaf Merkle tree, generate an inclusion proof for index 1,
///     and verify it succeeds.
#[test]
fn test_merkle_proof_valid() {
    use rusk_transparency::proof::{build_merkle_tree, build_proof};

    let leaves: Vec<&[u8]> = vec![b"leaf-0", b"leaf-1", b"leaf-2", b"leaf-3"];

    let root = build_merkle_tree(&leaves).expect("tree must have a root");
    let proof = build_proof(&leaves, 1).expect("proof must be built for index 1");

    assert_eq!(proof.root_hash, root, "proof root must match tree root");
    assert_eq!(proof.leaf_index, 1);
    assert_eq!(proof.tree_size, 4);
    assert!(
        proof.verify().is_ok(),
        "valid inclusion proof must verify successfully"
    );
}

/// 13. Tamper with one proof-path hash and verify that verification fails.
#[test]
fn test_merkle_proof_tampered() {
    use rusk_core::Sha256Digest;
    use rusk_transparency::proof::build_proof;

    let leaves: Vec<&[u8]> = vec![b"leaf-0", b"leaf-1", b"leaf-2", b"leaf-3"];
    let mut proof = build_proof(&leaves, 1).expect("proof must be built");

    assert!(
        !proof.proof_path.is_empty(),
        "proof path must be non-empty for a 4-leaf tree"
    );
    // Replace one proof hash with zeros
    proof.proof_path[0].hash = Sha256Digest::zero();

    assert!(
        proof.verify().is_err(),
        "tampered proof-path must cause verification to fail"
    );
}

/// 14. A checkpoint 48 hours old must be rejected under a strict 24-hour policy.
#[test]
fn test_stale_checkpoint_rejected() {
    use chrono::{Duration, Utc};
    use rusk_core::Sha256Digest;
    use rusk_transparency::checkpoint::TransparencyCheckpoint;
    use rusk_transparency::staleness::{check_freshness, FreshnessPolicy};
    use url::Url;

    let checkpoint = TransparencyCheckpoint {
        log_url: Url::parse("https://rekor.sigstore.dev").unwrap(),
        origin: "rekor.sigstore.dev".to_string(),
        tree_size: 50000,
        root_hash: Sha256Digest::compute(b"root-hash"),
        timestamp: Utc::now() - Duration::hours(48),
        signature_hex: String::new(),
        log_public_key_hex: String::new(),
    };

    let policy = FreshnessPolicy::strict(Duration::hours(24));
    let result = check_freshness(&checkpoint, &policy, &Utc::now());

    assert!(
        result.is_error(),
        "48h-old checkpoint with 24h max under strict policy must be a hard error"
    );
    assert!(
        !result.is_acceptable(),
        "stale checkpoint under strict policy must not be acceptable"
    );
}

/// 15. A checkpoint from 1 hour ago must be accepted under a 24-hour policy.
#[test]
fn test_fresh_checkpoint_accepted() {
    use chrono::{Duration, Utc};
    use rusk_core::Sha256Digest;
    use rusk_transparency::checkpoint::TransparencyCheckpoint;
    use rusk_transparency::staleness::{check_freshness, FreshnessPolicy};
    use url::Url;

    let checkpoint = TransparencyCheckpoint {
        log_url: Url::parse("https://rekor.sigstore.dev").unwrap(),
        origin: "rekor.sigstore.dev".to_string(),
        tree_size: 50000,
        root_hash: Sha256Digest::compute(b"root-hash"),
        timestamp: Utc::now() - Duration::hours(1),
        signature_hex: String::new(),
        log_public_key_hex: String::new(),
    };

    let policy = FreshnessPolicy::strict(Duration::hours(24));
    let result = check_freshness(&checkpoint, &policy, &Utc::now());

    assert!(
        result.is_acceptable(),
        "1h-old checkpoint under 24h policy must be acceptable"
    );
    assert!(
        !result.is_stale(),
        "1h-old checkpoint under 24h policy must not be stale"
    );
}

/// 16. A new checkpoint with a smaller tree_size than the old one must fail
///     the append-only consistency check.
#[test]
fn test_checkpoint_non_append_only() {
    use rusk_core::Sha256Digest;
    use rusk_transparency::checkpoint::TransparencyCheckpoint;
    use url::Url;

    let old = TransparencyCheckpoint {
        log_url: Url::parse("https://rekor.sigstore.dev").unwrap(),
        origin: "rekor.sigstore.dev".to_string(),
        tree_size: 1000,
        root_hash: Sha256Digest::compute(b"root-old"),
        timestamp: chrono::Utc::now() - chrono::Duration::hours(2),
        signature_hex: String::new(),
        log_public_key_hex: String::new(),
    };

    let newer_but_smaller = TransparencyCheckpoint {
        log_url: Url::parse("https://rekor.sigstore.dev").unwrap(),
        origin: "rekor.sigstore.dev".to_string(),
        tree_size: 500, // < 1000 -- violates append-only
        root_hash: Sha256Digest::compute(b"root-new"),
        timestamp: chrono::Utc::now(),
        signature_hex: String::new(),
        log_public_key_hex: String::new(),
    };

    let result = newer_but_smaller.verify_consistency_with(&old);
    assert!(
        result.is_err(),
        "tree_size shrinking must fail the consistency check"
    );
}

// ===========================================================================
// 17-18: DSSE Tests
// ===========================================================================

/// 17. Verify the PAE (Pre-Authentication Encoding) format.
///
/// PAE(payloadType, payload) = "DSSEv1" SP LEN(payloadType) SP payloadType SP
///                              LEN(payload) SP payload
#[test]
fn test_pae_encoding_format() {
    use crate::attestation::DsseEnvelope;

    let payload_type = "application/vnd.in-toto+json";
    let raw_payload = b"hello";
    let payload_b64 = simple_base64_encode(raw_payload);

    let envelope = DsseEnvelope {
        payload_type: payload_type.to_string(),
        payload: payload_b64,
        signatures: vec![],
    };

    let pae = envelope.pae_message().unwrap();

    // Expected: "DSSEv1 28 application/vnd.in-toto+json 5 hello"
    let expected_prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        raw_payload.len(),
    );
    let expected_bytes = [expected_prefix.as_bytes(), raw_payload].concat();

    assert_eq!(
        pae, expected_bytes,
        "PAE encoding must follow 'DSSEv1 <len> <type> <len> <payload>' format"
    );
}

/// 18. Serialize a DsseEnvelope to JSON and parse it back; fields must
///     round-trip exactly.
#[test]
fn test_dsse_envelope_roundtrip() {
    use crate::attestation::{DsseEnvelope, DsseSignature};

    let original = DsseEnvelope {
        payload_type: DsseEnvelope::IN_TOTO_PAYLOAD_TYPE.to_string(),
        payload: simple_base64_encode(b"{\"test\":true}"),
        signatures: vec![DsseSignature {
            keyid: "key-1".to_string(),
            sig: simple_base64_encode(b"fake-sig"),
        }],
    };

    let json_bytes = serde_json::to_vec(&original).expect("serialization must succeed");
    let parsed: DsseEnvelope =
        serde_json::from_slice(&json_bytes).expect("deserialization must succeed");

    assert_eq!(parsed.payload_type, original.payload_type);
    assert_eq!(parsed.payload, original.payload);
    assert_eq!(parsed.signatures.len(), 1);
    assert_eq!(parsed.signatures[0].keyid, "key-1");
    assert_eq!(parsed.signatures[0].sig, original.signatures[0].sig);
}
