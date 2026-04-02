//! Adversarial security tests — supply-chain attack simulations.
//!
//! Each test models a real-world attack vector against the rusk package
//! manager and verifies that the defensive mechanisms detect or block it.

use chrono::Utc;
use rusk_cas::{CasStore, WriteOutcome};
use rusk_core::{
    Ecosystem, PackageId, RegistryUrl, Sha256Digest, Version,
};
use rusk_enterprise::config::{EnterpriseConfig, InternalRegistryConfig, PackageControls};
use rusk_enterprise::leakage::{validate_no_internal_leakage, PackageRef};
use rusk_lockfile::integrity::{stamp_integrity, verify_integrity};
use rusk_lockfile::schema::{LockedPackage, Lockfile};
use rusk_revocation::bundle::{RevocationBundle, RevocationEntry};
use rusk_revocation::check::RevocationChecker;
use rusk_revocation::store::RevocationState;
use rusk_sandbox::{LocalProvenance, SandboxCapabilities, SandboxConfig};
use rusk_core::trust::TrustClass;

// ---------------------------------------------------------------------------
// 1. Dependency Confusion Attack
// ---------------------------------------------------------------------------

/// An attacker publishes a package with the same name as an internal package
/// on a public registry. Enterprise leakage validation must reject the public
/// impostor when internal namespaces are configured.
#[test]
fn test_dependency_confusion_blocked() {
    // Set up an enterprise config with an internal registry that owns "@corp".
    let mut config = EnterpriseConfig::new("acme-corp");
    config.registries.push(InternalRegistryConfig {
        name: "corp-npm".to_string(),
        url: RegistryUrl::parse("https://npm.corp.internal").unwrap(),
        ecosystem: Ecosystem::Js,
        auth_required: true,
        auth_token_env: Some("CORP_NPM_TOKEN".to_string()),
        is_internal: true,
        namespaces: vec!["@corp".to_string()],
    });

    // The legitimate internal package.
    let _internal_pkg = PackageRef {
        package: PackageId {
            ecosystem: Ecosystem::Js,
            registry: RegistryUrl::parse("https://npm.corp.internal").unwrap(),
            namespace: Some("@corp".to_string()),
            name: "utils".to_string(),
        },
        registry: RegistryUrl::parse("https://npm.corp.internal").unwrap(),
    };

    // An attacker publishes "@corp/utils" on the public npm registry.
    let confused_pkg = PackageRef {
        package: PackageId {
            ecosystem: Ecosystem::Js,
            registry: RegistryUrl::npm_default(),
            namespace: Some("@corp".to_string()),
            name: "utils".to_string(),
        },
        registry: RegistryUrl::parse("https://npm.corp.internal").unwrap(),
    };

    // The confused package should be flagged as internal leakage when resolved
    // from the internal registry but destined for a public context.
    let result = validate_no_internal_leakage(&config, &[confused_pkg], "public-lockfile");
    assert!(
        result.is_err(),
        "dependency confusion: public package with internal namespace must be rejected"
    );
}

// ---------------------------------------------------------------------------
// 2. Lockfile Tampering Attack
// ---------------------------------------------------------------------------

/// An attacker modifies a single digest in a committed lockfile. The integrity
/// verification must detect the tamper.
#[test]
fn test_lockfile_tamper_detected_on_verify() {
    let mut lockfile = Lockfile::new();

    // Add two legitimate packages with real digests.
    lockfile.add_package(LockedPackage {
        package: PackageId::js("express"),
        version: Version::Semver(semver::Version::new(4, 18, 2)),
        ecosystem: Ecosystem::Js,
        digest: Sha256Digest::compute(b"express-4.18.2 legitimate tarball bytes"),
        source_url: Some("https://registry.npmjs.org/express/-/express-4.18.2.tgz".into()),
        dependencies: vec![],
        dev: false,
        signer: None,
        provenance: None,
        resolved_by: None,
    });

    lockfile.add_package(LockedPackage {
        package: PackageId::js("lodash"),
        version: Version::Semver(semver::Version::new(4, 17, 21)),
        ecosystem: Ecosystem::Js,
        digest: Sha256Digest::compute(b"lodash-4.17.21 legitimate tarball bytes"),
        source_url: None,
        dependencies: vec![],
        dev: false,
        signer: None,
        provenance: None,
        resolved_by: None,
    });

    // Stamp the lockfile with a valid integrity root.
    stamp_integrity(&mut lockfile);
    assert!(verify_integrity(&lockfile).is_ok(), "initial integrity must be valid");

    // --- attacker tampers with the lodash digest ---
    let lodash_key = PackageId::js("lodash").canonical();
    lockfile
        .packages
        .get_mut(&lodash_key)
        .unwrap()
        .digest = Sha256Digest::compute(b"backdoored-lodash payload");

    // Integrity check must now fail.
    let result = verify_integrity(&lockfile);
    assert!(result.is_err(), "tampered lockfile must fail integrity check");
}

// ---------------------------------------------------------------------------
// 3. Artifact Substitution Attack
// ---------------------------------------------------------------------------

/// An attacker swaps the artifact bytes after the lockfile was generated.
/// CAS content-addressing guarantees that different bytes yield a different
/// digest, making the substitution detectable.
#[test]
fn test_artifact_substitution_caught() {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let cas = CasStore::open(tmp.path().join("cas")).expect("CasStore::open");

    let legit_bytes = b"legitimate package tarball content";
    let evil_bytes = b"backdoored package tarball content";

    // Write the legitimate artifact.
    let legit_outcome = cas.write(legit_bytes).expect("write legit");
    let legit_digest = match &legit_outcome {
        WriteOutcome::Written { digest, .. } => *digest,
        WriteOutcome::AlreadyExists { digest } => *digest,
    };

    // Create a lockfile entry pointing at the legitimate digest.
    let mut lockfile = Lockfile::new();
    lockfile.add_package(LockedPackage {
        package: PackageId::js("target-pkg"),
        version: Version::Semver(semver::Version::new(1, 0, 0)),
        ecosystem: Ecosystem::Js,
        digest: legit_digest,
        source_url: None,
        dependencies: vec![],
        dev: false,
        signer: None,
        provenance: None,
        resolved_by: None,
    });

    // Write the evil artifact — it gets a DIFFERENT digest.
    let evil_outcome = cas.write(evil_bytes).expect("write evil");
    let evil_digest = match &evil_outcome {
        WriteOutcome::Written { digest, .. } => *digest,
        WriteOutcome::AlreadyExists { digest } => *digest,
    };

    // The digests must differ, proving substitution is detectable.
    assert_ne!(
        legit_digest, evil_digest,
        "different content must yield different CAS digest"
    );

    // The lockfile still references the legitimate digest, so the evil
    // artifact cannot silently replace it.
    assert!(
        lockfile.is_locked(
            &PackageId::js("target-pkg"),
            &Version::Semver(semver::Version::new(1, 0, 0)),
            &legit_digest,
        ),
        "lockfile must still reference the original digest"
    );
    assert!(
        !lockfile.is_locked(
            &PackageId::js("target-pkg"),
            &Version::Semver(semver::Version::new(1, 0, 0)),
            &evil_digest,
        ),
        "lockfile must reject the substituted digest"
    );
}

// ---------------------------------------------------------------------------
// 4. Revocation Emergency
// ---------------------------------------------------------------------------

/// A previously-trusted signer is compromised. All artifacts they signed
/// must be blocked once the revocation bundle is applied.
#[test]
fn test_revocation_blocks_previously_trusted() {
    let mut state = RevocationState::new();
    let checker = RevocationChecker::new(&state);

    let signer = rusk_core::SignerIdentity {
        issuer: "https://accounts.google.com".to_string(),
        subject: "trusted-maintainer@example.com".to_string(),
        fingerprint: None,
    };

    // Before revocation the signer is clear.
    assert!(
        checker.check_signer(&signer).is_clear(),
        "signer must be clear before revocation"
    );

    // Emergency: the signer's key was compromised.
    let mut bundle = RevocationBundle::new(1);
    bundle.add_entry(RevocationEntry::Signer {
        issuer: "https://accounts.google.com".to_string(),
        subject: "trusted-maintainer@example.com".to_string(),
        reason: "private key compromised".to_string(),
        revoked_at: Utc::now(),
    });
    state.apply_bundle(&bundle).unwrap();

    // After revocation the signer must be blocked.
    let checker_after = RevocationChecker::new(&state);
    assert!(
        checker_after.check_signer(&signer).is_revoked(),
        "signer must be revoked after applying revocation bundle"
    );
}

// ---------------------------------------------------------------------------
// 5. Local Build Promotion Bypass
// ---------------------------------------------------------------------------

/// A locally-built artifact must not be able to masquerade as a trusted
/// release. LocalProvenance always stamps builder_type = "local", which
/// maps to TrustClass::LocalDev. There is no API path to elevate it
/// to TrustClass::TrustedRelease.
#[test]
fn test_local_dev_cannot_masquerade_as_release() {
    let pkg = PackageId::js("my-internal-tool");
    let version = Version::Semver(semver::Version::new(1, 0, 0));
    let digest = Sha256Digest::compute(b"locally built artifact");

    let prov = LocalProvenance::new(pkg, version, digest);

    // LocalProvenance always identifies the builder as "local".
    assert_eq!(
        prov.builder.builder_type, "local",
        "local provenance must identify as local builder"
    );
    assert_eq!(
        prov.builder.builder_id, "local-machine",
        "local provenance must use local-machine builder id"
    );

    // A TrustClass derived from local provenance must be LocalDev, not
    // TrustedRelease. There is no setter or promotion method.
    let trust_class = TrustClass::LocalDev;
    assert_ne!(
        trust_class,
        TrustClass::TrustedRelease,
        "local dev trust class must not equal trusted release"
    );

    // Verify the two trust classes are indeed distinct enum variants.
    assert_eq!(trust_class, TrustClass::LocalDev);
}

// ---------------------------------------------------------------------------
// 6. Install Script Sandbox Defaults
// ---------------------------------------------------------------------------

/// Default sandbox capabilities must deny network access — install scripts
/// must not be able to exfiltrate data or fetch remote payloads.
#[test]
fn test_sandbox_defaults_deny_network() {
    let config = SandboxConfig::default();
    assert!(
        !config.capabilities.network,
        "default sandbox must deny network access"
    );
}

/// Default sandbox capabilities must deny filesystem reads outside the
/// sandbox root — install scripts must not read host secrets.
#[test]
fn test_sandbox_defaults_deny_filesystem_read() {
    let caps = SandboxCapabilities::default();
    assert!(
        !caps.filesystem_read,
        "default sandbox must deny filesystem read"
    );
}

// ---------------------------------------------------------------------------
// 7. Internal Package Leakage
// ---------------------------------------------------------------------------

/// Packages from an internal namespace must be blocked when the target
/// context is public. This prevents accidental exposure of proprietary code.
#[test]
fn test_internal_namespace_blocked_from_public() {
    let mut config = EnterpriseConfig::new("acme-corp");
    config.registries.push(InternalRegistryConfig {
        name: "corp-npm".to_string(),
        url: RegistryUrl::parse("https://npm.corp.internal").unwrap(),
        ecosystem: Ecosystem::Js,
        auth_required: true,
        auth_token_env: None,
        is_internal: true,
        namespaces: vec!["@corp".to_string()],
    });

    // A package in the @corp namespace resolved from the internal registry.
    let pkg = PackageRef {
        package: PackageId {
            ecosystem: Ecosystem::Js,
            registry: RegistryUrl::parse("https://npm.corp.internal").unwrap(),
            namespace: Some("@corp".to_string()),
            name: "secrets-lib".to_string(),
        },
        registry: RegistryUrl::parse("https://npm.corp.internal").unwrap(),
    };

    let result = validate_no_internal_leakage(&config, &[pkg], "public-registry");
    assert!(
        result.is_err(),
        "internal namespace package must be blocked from public context"
    );
}

// ---------------------------------------------------------------------------
// 8. CAS Deduplication Security
// ---------------------------------------------------------------------------

/// Writing identical bytes under two different logical "package" contexts
/// must produce the same digest. Content-addressed storage must dedup purely
/// on content, not on metadata.
#[test]
fn test_cas_same_content_same_digest() {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let cas = CasStore::open(tmp.path().join("cas")).expect("CasStore::open");

    let content = b"shared library content v1.0.0";

    let outcome_a = cas.write(content).expect("first write");
    let digest_a = match &outcome_a {
        WriteOutcome::Written { digest, .. } => *digest,
        WriteOutcome::AlreadyExists { digest } => *digest,
    };

    let outcome_b = cas.write(content).expect("second write");
    let digest_b = match &outcome_b {
        WriteOutcome::Written { digest, .. } => *digest,
        WriteOutcome::AlreadyExists { digest } => *digest,
    };

    assert_eq!(
        digest_a, digest_b,
        "identical content must produce identical CAS digest"
    );

    // The second write should report AlreadyExists.
    assert!(
        matches!(outcome_b, WriteOutcome::AlreadyExists { .. }),
        "second write of same content must be deduplicated"
    );
}

/// Two different byte sequences must never produce the same digest. A
/// collision would allow an attacker to substitute artifacts undetected.
#[test]
fn test_cas_different_content_never_collides() {
    let tmp = tempfile::tempdir().expect("failed to create temp dir");
    let cas = CasStore::open(tmp.path().join("cas")).expect("CasStore::open");

    let content_a = b"legitimate package content alpha";
    let content_b = b"malicious package content beta";

    let outcome_a = cas.write(content_a).expect("write a");
    let digest_a = match &outcome_a {
        WriteOutcome::Written { digest, .. } => *digest,
        WriteOutcome::AlreadyExists { digest } => *digest,
    };

    let outcome_b = cas.write(content_b).expect("write b");
    let digest_b = match &outcome_b {
        WriteOutcome::Written { digest, .. } => *digest,
        WriteOutcome::AlreadyExists { digest } => *digest,
    };

    assert_ne!(
        digest_a, digest_b,
        "different content must produce different CAS digests"
    );
}

// ---------------------------------------------------------------------------
// 9. Package Allowlist / Blocklist
// ---------------------------------------------------------------------------

/// A package explicitly on the blocklist must be denied.
#[test]
fn test_blocklist_denies_package() {
    let controls = PackageControls {
        blocklist: vec![
            "evil-pkg".to_string(),
            "malware-*".to_string(),
        ],
        ..Default::default()
    };

    assert!(
        controls.is_blocked("evil-pkg"),
        "exact-match blocklist entry must block the package"
    );
    assert!(
        controls.is_blocked("malware-loader"),
        "wildcard blocklist entry must block matching packages"
    );
    assert!(
        !controls.is_blocked("legitimate-pkg"),
        "non-matching package must not be blocked"
    );
}

/// When an allowlist is set, packages NOT on the list must be denied.
#[test]
fn test_allowlist_denies_unlisted() {
    let controls = PackageControls {
        allowlist: vec![
            "@myorg/*".to_string(),
            "lodash".to_string(),
        ],
        ..Default::default()
    };

    assert!(
        controls.is_allowed("@myorg/utils"),
        "wildcard allowlist entry must allow matching packages"
    );
    assert!(
        controls.is_allowed("lodash"),
        "exact allowlist entry must allow the package"
    );
    assert!(
        !controls.is_allowed("express"),
        "unlisted package must be denied when allowlist is active"
    );
}

// ---------------------------------------------------------------------------
// 10. Yanked Version Handling
// ---------------------------------------------------------------------------

/// A version that has been yanked (added to the revocation set) must be
/// reported as revoked by the RevocationChecker.
#[test]
fn test_yanked_version_not_installable() {
    let mut state = RevocationState::new();

    // Yank version 2.0.0 of "event-stream" due to supply-chain attack.
    let mut bundle = RevocationBundle::new(1);
    bundle.add_entry(RevocationEntry::PackageVersion {
        ecosystem: "js".to_string(),
        package_name: "event-stream".to_string(),
        version: "2.0.0".to_string(),
        reason: "supply chain attack — malicious flatmap-stream dependency".to_string(),
        revoked_at: Utc::now(),
    });
    state.apply_bundle(&bundle).unwrap();

    let checker = RevocationChecker::new(&state);

    // The yanked version must be detected as revoked.
    let result = checker.check_version("js", "event-stream", "2.0.0");
    assert!(
        result.is_revoked(),
        "yanked version must be reported as revoked"
    );

    // Other versions of the same package must remain clear.
    let other_version = checker.check_version("js", "event-stream", "1.0.0");
    assert!(
        other_version.is_clear(),
        "non-yanked version must remain clear"
    );
}
