# rusk — Production-Grade Supply-Chain-Secure Multi-Ecosystem Package Manager

## Complete Design & Implementation Specification

---

# 1. Executive Summary

rusk is a supply-chain-secure, high-performance package manager written in Rust that natively supports both JavaScript/TypeScript (npm registry) and Python (PyPI registry) ecosystems through a unified core architecture. It provides content-addressed storage, cryptographic verification, provenance tracking, policy-driven trust, and lockfile-first reproducible installs.

**Core architecture principle**: One trusted core, ecosystem adapters on top.

The system is built around a content-addressed store (CAS) that deduplicates all artifacts globally. Every artifact entering the system passes through a verification pipeline that checks digests, signatures, provenance, transparency proofs, revocation status, and policy compliance before the artifact is committed to the store. The resolver is trust-aware — trust evaluation is not bolted on after resolution but integrated into candidate selection. Materialization (node_modules for JS, site-packages for Python) uses hardlinks/reflinks from the CAS, making repeat installs near-instant.

**Key differentiators over existing tools**:
- **vs npm/yarn**: Content-addressed global cache, signature verification, provenance verification, policy engine, no arbitrary script execution by default
- **vs pnpm**: Adds provenance, transparency, policy engine, multi-ecosystem support
- **vs Bun**: Adds full trust chain, provenance, policy engine, Python support; matches speed via CAS + hardlinks + parallel fetch
- **vs pip/pipx**: Orders-of-magnitude faster, lockfile-first, content-addressed, full trust chain
- **vs uv**: Adds JS/TS support, full TUF trust chain, policy engine, provenance verification, transparency log integration
- **vs cargo**: Multi-ecosystem, external-registry trust model (cargo trusts crates.io implicitly)

**Inspired by**:
- **uv**: PubGrub-based resolution, Rust async HTTP client, wheel cache strategy, build isolation, flat lockfile format
- **Bun**: Binary lockfile for speed, global cache with hardlinks, parallel manifest+tarball fetch, connection reuse
- **pnpm**: Virtual store with CAS-backed hardlinks, content-addressed global store
- **TUF**: Trust delegation, threshold signing, rollback/freeze protection
- **Sigstore**: Keyless signing, transparency logs, OIDC-bound identities
- **SLSA**: Provenance levels, builder attestation, hermetic builds

---

# 2. Product Goals

1. **Unified multi-ecosystem**: Install JS/TS and Python packages from a single tool with shared infrastructure
2. **Secure by default**: Default-deny trust model; no artifact enters the dependency graph without verification
3. **Extremely fast**: Warm-cache installs in <100ms for medium projects; cold installs competitive with Bun/uv
4. **Reproducible**: Lockfile-first execution; bit-for-bit identical installs across machines
5. **Offline-first**: After initial fetch, all operations work fully offline from local CAS
6. **Auditable**: Every trust decision is explainable; full audit trail of what was verified and why
7. **Enterprise-ready**: Internal registries, air-gapped mode, org policy bundles, central revocation feeds
8. **Developer-friendly**: Clear CLI UX, fast feedback, actionable error messages

---

# 3. Security Goals

1. No artifact is installed without digest verification against the lockfile or resolved manifest
2. No artifact is installed without valid signature verification (when signatures are available)
3. No provenance claim is accepted without cryptographic verification of the attestation envelope
4. Policy evaluation gates every artifact before materialization
5. Revocation is checked before every install/update operation
6. Transparency proof freshness is enforced per configurable policy
7. Install scripts are disabled by default; gated by explicit policy allow
8. Internal packages cannot leak into public resolution
9. Public packages cannot shadow internal namespace
10. Cache corruption is detected and rejected; corrupted entries are evicted
11. TUF metadata freshness prevents freeze and rollback attacks
12. All network-fetched metadata is verified before use

---

# 4. Threat Model

## 4.1 Threats Mitigated

### Transport-layer attacks
- **Mirror/CDN tampering**: All artifacts verified by digest against signed metadata. Blob transport is untrusted; only availability matters.
- **Artifact substitution in transit**: Streaming hash verification; artifact committed to CAS only after digest match.
- **Same-version different-bytes attack**: Lockfile pins exact digest per version. CAS is keyed by digest. If registry serves different bytes for same version, digest mismatch is detected.

### Metadata attacks
- **Rollback attacks**: TUF version counters; client rejects metadata with version <= last seen.
- **Freeze attacks**: TUF timestamp expiration; client rejects stale timestamp metadata.
- **Mix-and-match metadata attacks**: TUF snapshot metadata binds target metadata versions together; inconsistent combinations detected.
- **Registry compromise without root compromise**: TUF offline root is stored locally; online keys can be rotated but cannot override root without threshold of root key holders.

### Supply-chain attacks
- **Dependency confusion**: Manifest specifies allowed registries/namespaces per package. Internal packages marked explicitly. Public resolution blocked for internal names.
- **Namespace confusion**: Policy rules restrict allowed namespaces. Registry-qualified package names prevent cross-registry confusion.
- **Cache poisoning**: CAS is content-addressed; corrupt entries detected by digest on read. Unverified content never enters CAS.
- **Hidden transitive dependency swaps**: Lockfile pins entire transitive closure with digests. Any change detected.
- **Unauthorized publisher attack**: Signer identity verified against policy-defined allowed signers per package.
- **CI token abuse**: Provenance binds artifact to specific builder/workflow identity; policy can require specific builder identities.
- **Install script malware**: Scripts disabled by default; require explicit policy allow per package.
- **Unsigned binary injection**: Policy can require signatures; unsigned artifacts denied by default in strict mode.
- **Silent signer rotation**: Transparency log records signer events; unexpected rotation flagged.
- **Stale transparency state**: Checkpoint freshness enforced; policy configurable minimum freshness.

### Internal/enterprise attacks
- **Internal package leakage into public resolution**: Source restrictions per package; internal-only packages blocked from public registry resolution.
- **Public package shadowing of internal names**: Namespace priority rules; internal registry checked first for internal namespaces.
- **Malicious blob storage with honest metadata**: Blob digest verified against signed metadata; honest metadata + malicious blob = digest mismatch.

### Builder/signer attacks
- **Unexpected builder identity changes**: Provenance records builder identity; policy enforces allowed builders.
- **Unexpected signer identity changes**: Transparency log + policy enforce expected signer identity continuity.
- **Provenance/source mismatch**: Provenance statement includes source repo + commit; policy can require specific repos.
- **Policy bypass through local/manual artifacts**: Local builds marked with `local_dev` trust class; denied for production by default.

## 4.2 Threats NOT Fully Solved

- **Malicious maintainers**: A legitimate maintainer with valid signing keys can publish malicious code that passes all verification. Mitigation: quarantine periods, community reporting, anomaly detection (out of scope for v1).
- **Malicious commits**: Valid commits to a legitimate repo. Mitigation: code review processes (external to package manager).
- **Perfect CI compromise**: If a builder is fully compromised and produces valid attestations with stolen keys, the provenance is technically valid. Mitigation: transparency logs detect anomalous builder activity; key rotation limits blast radius.
- **Endpoint compromise**: If the developer's machine is compromised, the attacker has full access. Out of scope.
- **Verifier bugs**: Bugs in rusk's own verification code. Mitigation: extensive testing, fuzzing, formal verification of critical paths where feasible.
- **Correctly signed malicious code**: A package maintainer who goes rogue. Policy quarantine periods and community revocation are partial mitigations.

---

# 5. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          CLI Layer                           │
│  rusk install | update | verify | audit | build | publish   │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                     Orchestrator Layer                        │
│  Coordinates: resolve → verify → fetch → materialize         │
└──┬──────────┬──────────┬──────────┬──────────┬──────────┬───┘
   │          │          │          │          │          │
┌──▼───┐ ┌───▼───┐ ┌───▼───┐ ┌───▼───┐ ┌───▼───┐ ┌───▼────┐
│Manif-│ │Resolv-│ │Trust  │ │Trans- │ │Mater- │ │Build   │
│est   │ │er     │ │Engine │ │port   │ │ializ- │ │Sandbox │
│Parser│ │       │ │       │ │       │ │er     │ │        │
└──┬───┘ └───┬───┘ └───┬───┘ └───┬───┘ └───┬───┘ └───┬────┘
   │         │         │         │         │         │
   │    ┌────▼────┐    │    ┌────▼────┐    │         │
   │    │ JS      │    │    │Download │    │         │
   │    │ Adapter │    │    │Manager  │    │         │
   │    ├─────────┤    │    └────┬────┘    │         │
   │    │ Python  │    │         │         │         │
   │    │ Adapter │    │         │         │         │
   │    └─────────┘    │         │         │         │
   │                   │         │         │         │
┌──▼───────────────────▼─────────▼─────────▼─────────▼───────┐
│                    Core Services Layer                       │
├────────┬────────┬────────┬─────────┬─────────┬─────────────┤
│  CAS   │ TUF    │Signing │Transpar-│Proven-  │ Policy      │
│ Store  │ Client │Verifier│ency Log │ance     │ Engine      │
│        │        │        │Client   │Verifier │             │
├────────┴────────┴────────┴─────────┴─────────┴─────────────┤
│                  Lockfile Engine                             │
├────────────────────────────────────────────────────────────────┤
│                  Revocation Engine                            │
├────────────────────────────────────────────────────────────────┤
│                  Observability (tracing + metrics)            │
└──────────────────────────────────────────────────────────────┘
```

### Layer responsibilities:

- **CLI Layer**: Argument parsing, user interaction, output formatting. Thin; delegates to orchestrator.
- **Orchestrator Layer**: Sequences operations (resolve → verify → fetch → materialize). Manages the overall workflow state machine.
- **Ecosystem Adapters**: JS adapter handles npm registry protocol, semver, node_modules layout. Python adapter handles PyPI, PEP 440, wheels, site-packages.
- **Core Services**: Shared infrastructure that both ecosystems use. CAS, trust, signing, transparency, provenance, policy, lockfile, revocation.
- **Observability**: Cross-cutting tracing and metrics throughout all layers.

---

# 6. End-to-End Workflows

## 6.1 `rusk install` (from lockfile)

```
1. Parse rusk.toml manifest
2. Parse rusk.lock lockfile
3. Validate lockfile integrity (root digest)
4. Update revocation state (fetch latest bundles, update epoch)
5. For each package in lockfile:
   a. Check CAS for artifact by digest → if present, mark as cached
   b. If not cached, add to download queue
6. Fetch missing artifacts (parallel, streaming hash verification)
7. For each artifact (cached or freshly fetched):
   a. Verify digest matches lockfile pin
   b. Verify signature (if required by policy)
   c. Verify provenance (if required by policy)
   d. Check transparency proof freshness (if required)
   e. Check revocation status
   f. Evaluate policy
   g. If any check fails → halt with actionable error
8. Plan materialization tree
9. Atomically materialize (hardlink/reflink from CAS)
10. Write install state file
11. Emit install trace / report
```

## 6.2 `rusk install` (initial resolve, no lockfile)

```
1. Parse rusk.toml manifest
2. Update TUF metadata (fetch timestamp → snapshot → targets)
3. Update revocation state
4. Build dependency graph:
   a. For each direct dependency:
      - Fetch registry metadata (TUF-verified)
      - Generate candidates (version × registry × source)
      - Filter by policy (allowed registries, namespaces, signers)
      - Feed to solver
   b. Solver produces resolved graph
5. For each resolved package:
   a. Fetch artifact (streaming digest verification)
   b. Commit to CAS
   c. Verify signature
   d. Verify provenance
   e. Check transparency
   f. Check revocation
   g. Evaluate policy
6. Compute lockfile (deterministic serialization)
7. Write rusk.lock
8. Plan materialization tree
9. Atomically materialize
10. Write install state
```

## 6.3 `rusk update [packages...]`

```
1. Parse manifest + existing lockfile
2. Identify update subgraph (packages to update + their dependents)
3. Refresh TUF metadata
4. Refresh revocation state
5. Re-resolve update subgraph while preserving rest of lockfile
6. For new/changed packages: fetch → verify → policy check
7. Compute updated lockfile
8. Write rusk.lock
9. Re-materialize changed subtree
```

## 6.4 `rusk verify`

```
1. Parse lockfile
2. Refresh revocation state
3. For each package in lockfile:
   a. Verify CAS artifact digest matches lockfile
   b. Re-verify signature
   c. Re-verify provenance
   d. Check transparency freshness
   e. Check revocation status
   f. Re-evaluate policy
4. Verify materialized files match CAS (spot-check or full)
5. Emit verification report
```

## 6.5 `rusk audit`

```
1. Parse lockfile
2. For each package: collect trust state (signer, provenance, policy verdict, transparency)
3. Check for known vulnerabilities (advisory DB integration)
4. Check for policy warnings
5. Emit structured audit report (JSON or human-readable)
```

---

# 7. Rust Workspace Structure

```
rusk/
├── Cargo.toml                    # workspace root
├── Cargo.lock
├── crates/
│   ├── rusk-cli/                 # CLI binary crate
│   ├── rusk-core/                # Core types, IDs, digests, errors
│   ├── rusk-manifest/            # rusk.toml parser + types
│   ├── rusk-lockfile/            # rusk.lock parser + writer
│   ├── rusk-cas/                 # Content-addressed store
│   ├── rusk-resolver/            # Shared resolver framework
│   ├── rusk-resolver-js/         # JS/TS ecosystem resolver adapter
│   ├── rusk-resolver-python/     # Python ecosystem resolver adapter
│   ├── rusk-registry/            # Registry client abstraction
│   ├── rusk-registry-npm/        # npm registry client
│   ├── rusk-registry-pypi/       # PyPI registry client
│   ├── rusk-transport/           # HTTP download manager
│   ├── rusk-tuf/                 # TUF metadata verification
│   ├── rusk-signing/             # Signature verification
│   ├── rusk-transparency/        # Transparency log client
│   ├── rusk-provenance/          # Provenance/attestation verification
│   ├── rusk-policy/              # Policy engine + DSL
│   ├── rusk-revocation/          # Revocation subsystem
│   ├── rusk-materialize/         # File layout materialization
│   ├── rusk-materialize-js/      # node_modules materializer
│   ├── rusk-materialize-python/  # site-packages materializer
│   ├── rusk-sandbox/             # Build sandbox abstraction
│   ├── rusk-orchestrator/        # Workflow orchestration
│   ├── rusk-observability/       # Tracing, metrics, diagnostics
│   └── rusk-enterprise/          # Enterprise/internal registry mode
├── tests/                        # Integration tests
│   ├── fixtures/                 # Test fixtures
│   └── e2e/                      # End-to-end tests
├── docs/                         # Documentation
└── benches/                      # Benchmarks
```

### Dependency graph (simplified):

```
rusk-cli
  └─ rusk-orchestrator
       ├─ rusk-manifest
       ├─ rusk-lockfile
       ├─ rusk-resolver
       │   ├─ rusk-resolver-js
       │   └─ rusk-resolver-python
       ├─ rusk-registry
       │   ├─ rusk-registry-npm
       │   └─ rusk-registry-pypi
       ├─ rusk-transport
       ├─ rusk-tuf
       ├─ rusk-signing
       ├─ rusk-transparency
       ├─ rusk-provenance
       ├─ rusk-policy
       ├─ rusk-revocation
       ├─ rusk-cas
       ├─ rusk-materialize
       │   ├─ rusk-materialize-js
       │   └─ rusk-materialize-python
       ├─ rusk-sandbox
       └─ rusk-enterprise

rusk-core (depended on by ALL crates)
rusk-observability (depended on by ALL crates)
```

---

# 8. Crate-by-Crate Responsibilities

## 8.1 `rusk-core`

**Purpose**: Shared types, ID wrappers, digest types, error infrastructure.

**Modules**:
- `digest.rs` — `Sha256Digest`, `Blake3Digest`, `DigestAlgorithm`, `AnyDigest`
- `id.rs` — `PackageId`, `VersionId`, `ArtifactId`, `SignerIdentity`, `BuilderIdentity`
- `ecosystem.rs` — `Ecosystem` enum (Js, Python), ecosystem-qualified types
- `error.rs` — `RuskError`, `ErrorKind`, diagnostic infrastructure
- `version.rs` — Version abstraction that wraps semver (JS) and PEP 440 (Python)
- `trust.rs` — `TrustClass` enum, `VerificationResult`
- `registry.rs` — `RegistryUrl`, `RegistryKind` (Public, Internal)
- `platform.rs` — `Platform`, `Os`, `Arch`, `PythonVersion`, `NodeVersion`

**Key types**:
```rust
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Sha256Digest([u8; 32]);

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Blake3Digest([u8; 32]);

pub enum DigestAlgorithm { Sha256, Blake3 }

pub struct AnyDigest {
    pub algorithm: DigestAlgorithm,
    pub bytes: Vec<u8>,
}

pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub registry: RegistryUrl,
    pub namespace: Option<String>,  // npm scope or PyPI namespace
    pub name: String,
}

pub struct ArtifactId {
    pub package: PackageId,
    pub version: Version,
    pub digest: Sha256Digest,
}

pub enum Ecosystem { Js, Python }

pub enum TrustClass {
    TrustedRelease,
    LocalDev,
    Quarantined,
    Unverified,
}

pub struct SignerIdentity {
    pub issuer: String,        // e.g., "https://accounts.google.com"
    pub subject: String,       // e.g., "user@example.com"
    pub fingerprint: Option<String>,
}

pub struct BuilderIdentity {
    pub builder_type: String,  // e.g., "github-actions"
    pub builder_id: String,    // e.g., "https://github.com/actions/runner"
}
```

## 8.2 `rusk-manifest`

**Purpose**: Parse, validate, and normalize `rusk.toml` manifest files.

**Modules**:
- `parser.rs` — TOML parsing into raw AST
- `schema.rs` — Manifest schema types
- `validate.rs` — Validation rules
- `normalize.rs` — Normalization (defaults, workspace inheritance)
- `workspace.rs` — Workspace discovery and merging

**Public API**:
```rust
pub fn parse_manifest(path: &Path) -> Result<Manifest, ManifestError>;
pub fn parse_workspace(root: &Path) -> Result<Workspace, ManifestError>;
```

## 8.3 `rusk-lockfile`

**Purpose**: Read, write, update, and verify `rusk.lock` files.

**Modules**:
- `parser.rs` — Lockfile deserialization
- `writer.rs` — Deterministic serialization
- `integrity.rs` — Root digest computation and verification
- `diff.rs` — Lockfile diffing for partial updates
- `binary.rs` — Optional binary lockfile format for speed (inspired by Bun's bun.lockb)

## 8.4 `rusk-cas`

**Purpose**: Global content-addressed store for all artifacts.

**Modules**:
- `store.rs` — Core CAS operations (put, get, has, delete)
- `index.rs` — Memory-mapped index for fast lookups
- `gc.rs` — Garbage collection
- `integrity.rs` — Corruption detection and repair
- `layout.rs` — On-disk directory structure

## 8.5 `rusk-resolver`

**Purpose**: Shared resolver framework; ecosystem adapters plug in.

**Modules**:
- `solver.rs` — PubGrub-based SAT solver core
- `graph.rs` — Dependency graph types
- `candidate.rs` — Candidate generation and filtering
- `trust_filter.rs` — Trust-aware candidate pruning
- `lockfile_reuse.rs` — Lockfile-guided resolution
- `workspace.rs` — Workspace-aware resolution

## 8.6 `rusk-resolver-js`

**Purpose**: JS/TS-specific resolution logic.

**Modules**:
- `semver.rs` — npm semver range parsing and matching
- `peer.rs` — Peer dependency resolution
- `optional.rs` — Optional dependency handling
- `features.rs` — npm "features" / conditional exports

## 8.7 `rusk-resolver-python`

**Purpose**: Python-specific resolution logic.

**Modules**:
- `pep440.rs` — PEP 440 version parsing and comparison
- `markers.rs` — Environment/dependency marker evaluation
- `wheel_tags.rs` — Wheel tag compatibility checking
- `extras.rs` — Python extras handling

## 8.8 `rusk-registry`

**Purpose**: Registry client abstraction.

**Modules**:
- `client.rs` — `RegistryClient` trait
- `metadata.rs` — Package metadata types
- `cache.rs` — Metadata cache layer

## 8.9 `rusk-registry-npm`

**Purpose**: npm registry protocol client.

**Modules**:
- `api.rs` — npm registry API client
- `metadata.rs` — npm packument parser
- `tarball.rs` — npm tarball URL resolution

## 8.10 `rusk-registry-pypi`

**Purpose**: PyPI registry protocol client.

**Modules**:
- `api.rs` — PyPI Simple API + JSON API client
- `metadata.rs` — PyPI metadata parser
- `wheel.rs` — Wheel filename parser
- `sdist.rs` — Source distribution handler

## 8.11 `rusk-transport`

**Purpose**: HTTP download manager with parallel fetch, streaming verification.

**Modules**:
- `client.rs` — HTTP client (reqwest-based)
- `planner.rs` — Download planning and scheduling
- `stream.rs` — Streaming download with hash verification
- `retry.rs` — Retry strategy
- `mirror.rs` — Mirror racing

## 8.12 `rusk-tuf`

**Purpose**: TUF metadata verification.

**Modules**:
- `metadata.rs` — TUF metadata types (Root, Targets, Snapshot, Timestamp)
- `verify.rs` — Verification algorithm
- `update.rs` — Metadata update sequence
- `store.rs` — Local TUF state storage
- `delegation.rs` — Delegation tree handling

## 8.13 `rusk-signing`

**Purpose**: Artifact signature verification.

**Modules**:
- `verifier.rs` — Signature verification trait and implementations
- `keyless.rs` — Sigstore-style keyless verification
- `static_key.rs` — Traditional key-based verification
- `identity.rs` — Signer identity extraction and validation
- `cache.rs` — Verification result cache

## 8.14 `rusk-transparency`

**Purpose**: Transparency log client.

**Modules**:
- `client.rs` — Log client (Rekor-compatible)
- `proof.rs` — Inclusion proof verification
- `checkpoint.rs` — Checkpoint verification and caching
- `staleness.rs` — Freshness checking

## 8.15 `rusk-provenance`

**Purpose**: Provenance attestation parsing and verification.

**Modules**:
- `attestation.rs` — In-toto attestation envelope parsing
- `normalize.rs` — Normalization to internal provenance model
- `verify.rs` — Provenance verification pipeline
- `bundle.rs` — Verified provenance bundle
- `risk.rs` — Risk flag computation

## 8.16 `rusk-policy`

**Purpose**: Policy engine with declarative DSL.

**Modules**:
- `ast.rs` — Policy AST
- `parser.rs` — Policy DSL parser
- `compiler.rs` — AST → IR compiler
- `ir.rs` — Intermediate representation
- `evaluator.rs` — Policy evaluator
- `explain.rs` — Explanation trace generator
- `cache.rs` — Policy verdict cache
- `builtins.rs` — Built-in predicates

## 8.17 `rusk-revocation`

**Purpose**: Revocation checking and enforcement.

**Modules**:
- `bundle.rs` — Revocation bundle types
- `store.rs` — Local revocation state
- `update.rs` — Revocation feed update
- `check.rs` — Revocation checking functions
- `epoch.rs` — Epoch management

## 8.18 `rusk-materialize`

**Purpose**: Shared materialization framework.

**Modules**:
- `planner.rs` — Install tree planning
- `linker.rs` — Hardlink/reflink/copy strategy
- `atomic.rs` — Atomic swap-in and rollback
- `state.rs` — Install state tracking

## 8.19 `rusk-materialize-js`

**Purpose**: node_modules layout materialization.

**Modules**:
- `layout.rs` — node_modules tree computation (hoisted or isolated)
- `virtual_store.rs` — pnpm-style virtual store
- `bin_shims.rs` — Binary shim generation
- `peer_layout.rs` — Peer dependency layout handling

## 8.20 `rusk-materialize-python`

**Purpose**: Python site-packages materialization.

**Modules**:
- `venv.rs` — Virtual environment management
- `wheel_install.rs` — Wheel unpacking and installation
- `dist_info.rs` — dist-info directory generation
- `scripts.rs` — Entry point script generation

## 8.21 `rusk-sandbox`

**Purpose**: Build isolation for source builds.

**Modules**:
- `trait.rs` — `Sandbox` trait
- `container.rs` — Container-based sandbox
- `namespace.rs` — Linux namespace sandbox
- `process.rs` — Process-level sandbox (Windows/macOS fallback)
- `provenance_gen.rs` — Local provenance generation

## 8.22 `rusk-orchestrator`

**Purpose**: Workflow orchestration; sequences subsystem calls.

**Modules**:
- `install.rs` — Install flow
- `update.rs` — Update flow
- `verify.rs` — Verify flow
- `audit.rs` — Audit flow
- `build.rs` — Build flow
- `publish.rs` — Publish flow
- `state_machine.rs` — Workflow state management

## 8.23 `rusk-observability`

**Purpose**: Structured logging, tracing, metrics.

**Modules**:
- `tracing.rs` — Tracing span setup
- `metrics.rs` — Counter/histogram/gauge types
- `diagnostics.rs` — Machine-readable diagnostic output
- `report.rs` — Audit/verification report generation

## 8.24 `rusk-enterprise`

**Purpose**: Enterprise features.

**Modules**:
- `internal_registry.rs` — Internal registry configuration
- `org_policy.rs` — Organization policy layering
- `airgap.rs` — Air-gapped sync bundles
- `proxy.rs` — Cache proxy configuration
- `audit_export.rs` — Enterprise audit reporting

---

# 9. Core Domain Model

## 9.1 Package Identity

```rust
/// Fully-qualified package identity, unique across ecosystems and registries
pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub registry: RegistryUrl,
    pub namespace: Option<String>,
    pub name: String,
}

/// Registry URL, normalized
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct RegistryUrl(Url);

impl PackageId {
    /// Canonical string form: "js:npmjs.org/@scope/name" or "py:pypi.org/requests"
    pub fn canonical(&self) -> String;
}
```

## 9.2 Version

```rust
/// Unified version type that wraps ecosystem-specific versions
pub enum Version {
    Semver(semver::Version),        // JS: npm semver
    Pep440(pep440::Version),        // Python: PEP 440
}

/// Version requirement/constraint
pub enum VersionReq {
    SemverReq(semver::VersionReq),
    Pep440Req(pep440::VersionSpecifiers),
}
```

## 9.3 Artifact

```rust
/// A specific artifact (file) for a package version
pub struct Artifact {
    pub id: ArtifactId,
    pub digest: Sha256Digest,
    pub size: u64,
    pub artifact_type: ArtifactType,
    pub metadata_digest: Sha256Digest,
    pub download_url: Url,
}

pub enum ArtifactType {
    NpmTarball,
    PythonWheel { tags: WheelTags },
    PythonSdist,
}

pub struct WheelTags {
    pub python: Vec<String>,
    pub abi: Vec<String>,
    pub platform: Vec<String>,
}
```

## 9.4 Dependency Graph Node

```rust
/// A resolved node in the dependency graph
pub struct ResolvedNode {
    pub package: PackageId,
    pub version: Version,
    pub artifact: ArtifactId,
    pub digest: Sha256Digest,
    pub dependencies: Vec<DependencyEdge>,
    pub trust_state: TrustState,
}

pub struct DependencyEdge {
    pub target: PackageId,
    pub version_req: VersionReq,
    pub dep_type: DependencyType,
    pub condition: Option<DependencyCondition>,
}

pub enum DependencyType {
    Normal,
    Dev,
    Optional,
    Peer,       // JS only
    PeerOptional, // JS only
    Build,      // Python build deps
}

pub enum DependencyCondition {
    JsPlatform(JsPlatformCondition),
    PythonMarker(MarkerExpression),
}
```

## 9.5 Trust State

```rust
/// Collected trust verification state for a single artifact
pub struct TrustState {
    pub digest_verified: bool,
    pub signature: SignatureState,
    pub provenance: ProvenanceState,
    pub transparency: TransparencyState,
    pub revocation: RevocationState,
    pub policy_verdict: PolicyVerdict,
    pub trust_class: TrustClass,
}

pub enum SignatureState {
    Verified { signer: SignerIdentity, timestamp: DateTime<Utc> },
    NotRequired,
    Missing,
    Invalid(SignatureError),
}

pub enum ProvenanceState {
    Verified(VerifiedProvenance),
    NotRequired,
    Missing,
    Invalid(ProvenanceError),
}

pub enum TransparencyState {
    Verified { checkpoint: CheckpointRef, timestamp: DateTime<Utc> },
    NotRequired,
    Stale { last_seen: DateTime<Utc> },
    Missing,
}

pub enum RevocationState {
    Clear,
    Revoked { reason: String, epoch: u64 },
    Yanked { reason: String },
}

pub enum PolicyVerdict {
    Allow { matched_rules: Vec<RuleId> },
    Deny { reason: String, matched_rules: Vec<RuleId> },
    RequireApproval { reason: String },
    Quarantine { reason: String, duration: Duration },
    Warn { warnings: Vec<String> },
}
```

---

# 10. Manifest Format (Multi-Ecosystem)

## 10.1 `rusk.toml` Schema Design

```toml
[package]
name = "my-project"
version = "1.0.0"
description = "Example multi-ecosystem project"
authors = ["Alice <alice@example.com>"]
license = "MIT"

# Ecosystem declarations
[ecosystems]
js = true
python = true

# JavaScript dependencies
[js.dependencies]
react = "^18.2.0"
express = "^4.18.0"

[js.dev-dependencies]
typescript = "^5.0.0"
vitest = "^1.0.0"

[js.optional-dependencies]
fsevents = { version = "^2.3.0", os = ["darwin"] }

[js.peer-dependencies]
react-dom = "^18.0.0"

# Python dependencies
[python.dependencies]
requests = ">=2.28.0"
fastapi = ">=0.100.0"

[python.dev-dependencies]
pytest = ">=7.0.0"
mypy = ">=1.0.0"

[python.optional-dependencies.ml]
torch = ">=2.0.0"
numpy = ">=1.24.0"

# Python constraints
[python.requires]
python = ">=3.10"

# Trust / Security Configuration
[trust]
policy = "default-strict"                    # Policy profile name
policy-file = ".rusk/policy.rusk-policy"     # Custom policy file

[trust.registries]
npm = { url = "https://registry.npmjs.org", tuf-root = "npm-root.json" }
pypi = { url = "https://pypi.org", tuf-root = "pypi-root.json" }
internal = { url = "https://registry.internal.corp.com", tuf-root = "corp-root.json", kind = "internal" }

# Per-package trust overrides
[trust.packages."@corp/auth"]
registry = "internal"
allowed-signers = ["corp-signer@corp.com"]
allowed-builders = ["github-actions"]

[trust.packages.requests]
allowed-signers = ["maintainer@python.org"]
require-provenance = true

# Quarantine exceptions
[trust.quarantine-exceptions]
"lodash@4.17.21" = { reason = "Legacy, audited manually", approved-by = "security@corp.com" }

# Install scripts are disabled by default
[trust.scripts]
allow = ["node-gyp", "esbuild"]   # Explicitly allowed script runners

# Workspace configuration
[workspace]
members = ["packages/*", "apps/*"]

[workspace.trust]
# Workspace-level trust config inherited by all members
policy = "default-strict"

# Build configuration
[build]
sandbox = true
python-build-backend = "auto"  # auto-detect PEP 517 backend

# Internal package markers
[internal]
namespaces = ["@corp"]
packages = ["corp-shared-utils"]

# Platform / target constraints
[target.'cfg(target_os = "linux")'.js.dependencies]
fsevents = false

# Feature flags
[features]
default = ["ssr"]
ssr = []
ml = ["python.optional-dependencies.ml"]
```

## 10.2 Manifest Rust Types

```rust
pub struct Manifest {
    pub package: PackageMetadata,
    pub ecosystems: EcosystemConfig,
    pub js: Option<JsDependencies>,
    pub python: Option<PythonDependencies>,
    pub trust: TrustConfig,
    pub workspace: Option<WorkspaceConfig>,
    pub build: BuildConfig,
    pub internal: InternalConfig,
    pub features: BTreeMap<String, Vec<String>>,
}

pub struct PackageMetadata {
    pub name: String,
    pub version: Version,
    pub description: Option<String>,
    pub authors: Vec<String>,
    pub license: Option<String>,
}

pub struct JsDependencies {
    pub dependencies: BTreeMap<String, JsVersionReq>,
    pub dev_dependencies: BTreeMap<String, JsVersionReq>,
    pub optional_dependencies: BTreeMap<String, JsOptionalDep>,
    pub peer_dependencies: BTreeMap<String, JsVersionReq>,
}

pub struct PythonDependencies {
    pub dependencies: BTreeMap<String, PyVersionReq>,
    pub dev_dependencies: BTreeMap<String, PyVersionReq>,
    pub optional_dependencies: BTreeMap<String, BTreeMap<String, PyVersionReq>>,
    pub requires: PythonRequires,
}

pub struct TrustConfig {
    pub policy: String,
    pub policy_file: Option<PathBuf>,
    pub registries: BTreeMap<String, RegistryConfig>,
    pub packages: BTreeMap<String, PackageTrustOverride>,
    pub quarantine_exceptions: BTreeMap<String, QuarantineException>,
    pub scripts: ScriptConfig,
}
```

## 10.3 Parser Implementation

Use `toml` crate for parsing. Deserialization uses `serde` with `#[serde(deny_unknown_fields)]` to reject unknown keys. Validation runs in a separate pass after deserialization:

```rust
pub fn parse_manifest(path: &Path) -> Result<Manifest, ManifestError> {
    let content = std::fs::read_to_string(path)?;
    let raw: RawManifest = toml::from_str(&content)?;
    let manifest = validate_manifest(raw)?;
    let manifest = normalize_manifest(manifest)?;
    Ok(manifest)
}
```

**Validation rules**:
- Package name must be valid for all declared ecosystems
- Version must be valid for all declared ecosystems
- All dependency names must be valid package names in their ecosystem
- All version requirements must parse correctly
- Registry URLs must be valid
- Policy file must exist if specified
- Workspace members must exist
- No duplicate dependency names within an ecosystem
- Feature references must point to existing features
- Signer identities must be syntactically valid

**Normalization rules**:
- Default registry URLs filled in (npmjs.org, pypi.org)
- Default policy set to "default-permissive" if not specified
- Empty sections removed
- Workspace-level config merged into member manifests (members can override)

---

# 11. Lockfile Format (Cross-Ecosystem)

## 11.1 `rusk.lock` Format

The lockfile uses a sorted, deterministic TOML format. This is human-readable and produces stable diffs in version control (inspired by uv.lock's readability and Cargo.lock's TOML format).

```toml
# rusk.lock — auto-generated, do not edit manually
# Integrity root: sha256:a1b2c3d4...

version = 1
integrity = "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

[[packages]]
ecosystem = "js"
name = "@scope/react"
version = "18.2.0"
registry = "https://registry.npmjs.org"
digest = "sha256:abcdef1234567890..."
metadata-digest = "sha256:fedcba0987654321..."
artifact-type = "npm-tarball"
signer = { issuer = "https://accounts.google.com", subject = "react-team@meta.com" }
provenance-digest = "sha256:1111111111111111..."
transparency-checkpoint = "rekor:12345678"

[[packages.dependencies]]
name = "loose-envify"
version = "^1.1.0"
resolved = "1.4.0"

[[packages]]
ecosystem = "python"
name = "requests"
version = "2.31.0"
registry = "https://pypi.org"
digest = "sha256:9876543210fedcba..."
metadata-digest = "sha256:abcdef1234567890..."
artifact-type = "wheel"
wheel-tags = "py3-none-any"
signer = { issuer = "https://accounts.google.com", subject = "maintainer@python.org" }
provenance-digest = "sha256:2222222222222222..."
transparency-checkpoint = "rekor:87654321"

[[packages.dependencies]]
name = "urllib3"
version = ">=1.21.1,<3"
resolved = "2.1.0"

[[packages.dependencies]]
name = "certifi"
version = ">=2017.4.17"
resolved = "2024.2.2"
```

## 11.2 Lockfile Rust Types

```rust
pub struct Lockfile {
    pub version: u32,
    pub integrity: Sha256Digest,
    pub packages: Vec<LockedPackage>,
}

pub struct LockedPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Version,
    pub registry: RegistryUrl,
    pub digest: Sha256Digest,
    pub metadata_digest: Sha256Digest,
    pub artifact_type: ArtifactType,
    pub signer: Option<LockedSignerRef>,
    pub provenance_digest: Option<Sha256Digest>,
    pub transparency_checkpoint: Option<String>,
    pub dependencies: Vec<LockedDependency>,
}

pub struct LockedSignerRef {
    pub issuer: String,
    pub subject: String,
}

pub struct LockedDependency {
    pub name: String,
    pub version_req: String,
    pub resolved: String,
}
```

## 11.3 Write/Update Algorithm

```rust
pub fn write_lockfile(graph: &ResolvedGraph) -> Result<Lockfile, LockfileError> {
    // 1. Collect all resolved nodes
    let mut packages: Vec<LockedPackage> = graph.nodes()
        .map(|node| node.to_locked_package())
        .collect();

    // 2. Sort deterministically: by (ecosystem, registry, name, version)
    packages.sort_by(|a, b| {
        a.ecosystem.cmp(&b.ecosystem)
            .then(a.registry.cmp(&b.registry))
            .then(a.name.cmp(&b.name))
            .then(a.version.cmp(&b.version))
    });

    // 3. Sort dependencies within each package
    for pkg in &mut packages {
        pkg.dependencies.sort_by(|a, b| a.name.cmp(&b.name));
    }

    // 4. Compute integrity root
    let integrity = compute_integrity_root(&packages);

    Ok(Lockfile { version: 1, integrity, packages })
}

fn compute_integrity_root(packages: &[LockedPackage]) -> Sha256Digest {
    // Merkle-tree or linear hash chain over sorted package digests
    let mut hasher = Sha256::new();
    for pkg in packages {
        hasher.update(&pkg.digest.0);
        hasher.update(&pkg.metadata_digest.0);
        if let Some(ref prov) = pkg.provenance_digest {
            hasher.update(&prov.0);
        }
    }
    Sha256Digest(hasher.finalize().into())
}
```

**Partial update algorithm**:
1. Parse existing lockfile
2. Identify packages to update (from CLI args or manifest changes)
3. Build "frozen" set = all packages NOT in update scope
4. Re-resolve only the update subgraph, keeping frozen packages pinned
5. Merge frozen + newly resolved
6. Recompute integrity root
7. Write new lockfile

**Mixed-ecosystem representation**: Both JS and Python packages live in the same `[[packages]]` array, distinguished by the `ecosystem` field. Cross-ecosystem dependencies (rare but possible, e.g., a JS build tool that invokes Python) are represented as regular dependency edges with cross-ecosystem markers.

---

# 12. Registry Metadata Model

## 12.1 Two-Layer Architecture

### Metadata layer (trusted after TUF verification):
Contains package metadata, version information, dependency specifications, artifact references, and trust-relevant data (signers, provenance references).

### Blob transport layer (untrusted except for availability):
Serves the actual package files (tarballs, wheels). Content verified by digest against metadata layer.

## 12.2 Registry Client Trait

```rust
#[async_trait]
pub trait RegistryClient: Send + Sync {
    /// Fetch metadata for a package (all versions)
    async fn fetch_package_metadata(
        &self,
        name: &str,
    ) -> Result<PackageMetadata, RegistryError>;

    /// Fetch metadata for a specific version
    async fn fetch_version_metadata(
        &self,
        name: &str,
        version: &Version,
    ) -> Result<VersionMetadata, RegistryError>;

    /// Get artifact download URL
    fn artifact_url(
        &self,
        name: &str,
        version: &Version,
        artifact_type: &ArtifactType,
    ) -> Result<Url, RegistryError>;

    /// Fetch TUF metadata
    async fn fetch_tuf_metadata(
        &self,
        role: TufRole,
    ) -> Result<SignedMetadata, RegistryError>;
}
```

## 12.3 npm Registry Client

Implements the standard npm registry protocol:

```rust
pub struct NpmRegistryClient {
    http: HttpClient,
    registry_url: RegistryUrl,
    metadata_cache: MetadataCache,
}

impl NpmRegistryClient {
    /// Fetch packument (full package document)
    /// GET /{package} with Accept: application/json
    /// For scoped: GET /@scope%2fname
    async fn fetch_packument(&self, name: &str) -> Result<NpmPackument, RegistryError> {
        let url = self.registry_url.join(name)?;
        let response = self.http.get(url)
            .header("Accept", "application/json")
            .send().await?;
        let packument: NpmPackument = response.json().await?;
        Ok(packument)
    }
}

pub struct NpmPackument {
    pub name: String,
    pub dist_tags: BTreeMap<String, String>,
    pub versions: BTreeMap<String, NpmVersionMeta>,
    pub time: BTreeMap<String, DateTime<Utc>>,
}

pub struct NpmVersionMeta {
    pub name: String,
    pub version: String,
    pub dependencies: BTreeMap<String, String>,
    pub dev_dependencies: BTreeMap<String, String>,
    pub peer_dependencies: BTreeMap<String, String>,
    pub optional_dependencies: BTreeMap<String, String>,
    pub dist: NpmDist,
}

pub struct NpmDist {
    pub tarball: Url,
    pub shasum: String,          // SHA-1 (legacy)
    pub integrity: Option<String>,  // Subresource Integrity (SHA-512)
    pub signatures: Vec<NpmSignature>,
    pub attestations: Option<NpmAttestations>,
}
```

## 12.4 PyPI Registry Client

Implements PEP 503 Simple API and PEP 691 JSON API:

```rust
pub struct PypiRegistryClient {
    http: HttpClient,
    registry_url: RegistryUrl,
    metadata_cache: MetadataCache,
}

impl PypiRegistryClient {
    /// Fetch package index page
    /// GET /simple/{package}/ with Accept: application/vnd.pypi.simple.v1+json
    async fn fetch_package_index(&self, name: &str) -> Result<PypiPackageIndex, RegistryError> {
        let normalized = normalize_pypi_name(name);
        let url = self.registry_url.join(&format!("simple/{}/", normalized))?;
        let response = self.http.get(url)
            .header("Accept", "application/vnd.pypi.simple.v1+json")
            .send().await?;
        let index: PypiPackageIndex = response.json().await?;
        Ok(index)
    }
}

pub struct PypiPackageIndex {
    pub name: String,
    pub files: Vec<PypiFile>,
}

pub struct PypiFile {
    pub filename: String,
    pub url: Url,
    pub hashes: BTreeMap<String, String>,  // {"sha256": "..."}
    pub requires_python: Option<String>,
    pub yanked: Option<String>,
    pub dist_info_metadata: Option<bool>,  // PEP 658
    pub provenance: Option<Url>,           // attestation bundle URL
}
```

## 12.5 Metadata Cache

```rust
pub struct MetadataCache {
    /// On-disk cache directory
    cache_dir: PathBuf,
    /// In-memory LRU
    lru: Mutex<LruCache<CacheKey, Arc<CachedMetadata>>>,
}

pub struct CacheKey {
    pub registry: RegistryUrl,
    pub package_name: String,
    pub etag: Option<String>,
}

pub struct CachedMetadata {
    pub data: Vec<u8>,
    pub etag: Option<String>,
    pub fetched_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
```

**Cache invalidation**: ETags for HTTP conditional requests. TUF timestamp metadata provides an upper bound on freshness. Forced refresh on `rusk update`.

---

# 13. TUF-Style Trust Chain Design

## 13.1 Architecture

rusk implements a TUF-inspired trust chain. Each registry can have its own TUF root. The client maintains local trusted state per registry.

### Role hierarchy:
```
Root (offline, threshold-signed)
├── Timestamp (online, short-lived)
├── Snapshot (online, binds target metadata versions)
└── Targets (online or delegated)
    ├── Delegated: namespace/@scope/* → scope-targets
    ├── Delegated: namespace/package-a → package-a-targets
    └── ...
```

## 13.2 TUF Metadata Types

```rust
pub struct SignedMetadata {
    pub signed: serde_json::Value,  // canonical JSON
    pub signatures: Vec<TufSignature>,
}

pub struct TufSignature {
    pub keyid: String,
    pub sig: Vec<u8>,
}

pub struct RootMetadata {
    pub spec_version: String,
    pub version: u64,
    pub expires: DateTime<Utc>,
    pub keys: BTreeMap<String, TufKey>,
    pub roles: BTreeMap<String, RoleDefinition>,
    pub consistent_snapshot: bool,
}

pub struct RoleDefinition {
    pub keyids: Vec<String>,
    pub threshold: u32,
}

pub struct TimestampMetadata {
    pub spec_version: String,
    pub version: u64,
    pub expires: DateTime<Utc>,
    pub snapshot: MetaFileInfo,
}

pub struct SnapshotMetadata {
    pub spec_version: String,
    pub version: u64,
    pub expires: DateTime<Utc>,
    pub meta: BTreeMap<String, MetaFileInfo>,
}

pub struct TargetsMetadata {
    pub spec_version: String,
    pub version: u64,
    pub expires: DateTime<Utc>,
    pub targets: BTreeMap<String, TargetInfo>,
    pub delegations: Option<Delegations>,
}

pub struct TargetInfo {
    pub length: u64,
    pub hashes: BTreeMap<String, String>,
    pub custom: Option<TargetCustom>,
}

pub struct TargetCustom {
    pub signers: Vec<SignerIdentity>,
    pub provenance_required: bool,
}

pub struct Delegations {
    pub keys: BTreeMap<String, TufKey>,
    pub roles: Vec<DelegatedRole>,
}

pub struct DelegatedRole {
    pub name: String,
    pub keyids: Vec<String>,
    pub threshold: u32,
    pub paths: Vec<String>,           // glob patterns
    pub terminating: bool,
}

pub struct TufKey {
    pub keytype: String,
    pub scheme: String,
    pub keyval: KeyValue,
}

pub struct MetaFileInfo {
    pub version: u64,
    pub length: Option<u64>,
    pub hashes: BTreeMap<String, String>,
}
```

## 13.3 Verification Algorithm

```rust
pub struct TufVerifier {
    trusted_root: RootMetadata,
    local_store: TufLocalStore,
}

impl TufVerifier {
    /// Full TUF metadata update sequence
    pub async fn update(
        &mut self,
        client: &dyn RegistryClient,
    ) -> Result<TargetsMetadata, TufError> {
        // 1. Check root rotation
        let new_root = self.update_root(client).await?;

        // 2. Fetch timestamp
        let timestamp = client.fetch_tuf_metadata(TufRole::Timestamp).await?;
        let timestamp = self.verify_timestamp(&timestamp)?;

        // 3. Check timestamp freshness
        if timestamp.expires < Utc::now() {
            return Err(TufError::ExpiredTimestamp);
        }

        // 4. Rollback check
        if let Some(prev) = self.local_store.get_timestamp_version()? {
            if timestamp.version < prev {
                return Err(TufError::RollbackAttack {
                    role: "timestamp",
                    previous: prev,
                    received: timestamp.version,
                });
            }
        }

        // 5. Fetch snapshot (version from timestamp)
        let snapshot = client.fetch_tuf_metadata(TufRole::Snapshot).await?;
        let snapshot = self.verify_snapshot(&snapshot, &timestamp)?;

        // 6. Snapshot rollback check
        if let Some(prev) = self.local_store.get_snapshot_version()? {
            if snapshot.version < prev {
                return Err(TufError::RollbackAttack {
                    role: "snapshot",
                    previous: prev,
                    received: snapshot.version,
                });
            }
        }

        // 7. Fetch targets (version from snapshot)
        let targets = client.fetch_tuf_metadata(TufRole::Targets).await?;
        let targets = self.verify_targets(&targets, &snapshot)?;

        // 8. Persist new state
        self.local_store.store_timestamp(timestamp.version)?;
        self.local_store.store_snapshot(snapshot.version)?;
        self.local_store.store_targets(&targets)?;

        Ok(targets)
    }

    fn verify_timestamp(&self, signed: &SignedMetadata) -> Result<TimestampMetadata, TufError> {
        let role_def = self.trusted_root.roles.get("timestamp")
            .ok_or(TufError::MissingRole("timestamp"))?;
        verify_signatures(signed, &self.trusted_root.keys, role_def)?;
        let meta: TimestampMetadata = serde_json::from_value(signed.signed.clone())?;
        Ok(meta)
    }

    fn verify_signatures(
        signed: &SignedMetadata,
        keys: &BTreeMap<String, TufKey>,
        role: &RoleDefinition,
    ) -> Result<(), TufError> {
        let canonical = canonicalize_json(&signed.signed)?;
        let mut valid_sigs = 0u32;
        for sig in &signed.signatures {
            if role.keyids.contains(&sig.keyid) {
                if let Some(key) = keys.get(&sig.keyid) {
                    if verify_ed25519(key, &canonical, &sig.sig) {
                        valid_sigs += 1;
                    }
                }
            }
        }
        if valid_sigs < role.threshold {
            return Err(TufError::InsufficientSignatures {
                required: role.threshold,
                found: valid_sigs,
            });
        }
        Ok(())
    }
}
```

## 13.4 Root Rotation

```rust
async fn update_root(&mut self, client: &dyn RegistryClient) -> Result<(), TufError> {
    let current_version = self.trusted_root.version;
    loop {
        let next_version = current_version + 1;
        match client.fetch_tuf_metadata(TufRole::Root).await {
            Ok(signed) => {
                // Verify with CURRENT root's root keys (threshold)
                let role_def = self.trusted_root.roles.get("root").unwrap();
                verify_signatures(&signed, &self.trusted_root.keys, role_def)?;

                let new_root: RootMetadata = serde_json::from_value(signed.signed.clone())?;

                // ALSO verify with NEW root's root keys (threshold)
                let new_role_def = new_root.roles.get("root").unwrap();
                verify_signatures(&signed, &new_root.keys, new_role_def)?;

                // Version must be exactly next
                if new_root.version != next_version {
                    return Err(TufError::NonSequentialRoot);
                }

                // Check expiration
                if new_root.expires < Utc::now() {
                    return Err(TufError::ExpiredRoot);
                }

                self.trusted_root = new_root;
                self.local_store.store_root(&self.trusted_root)?;
            }
            Err(RegistryError::NotFound) => break, // No more root versions
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
```

## 13.5 Local TUF State Storage

```
~/.rusk/tuf/
├── npmjs.org/
│   ├── root.json          # Current trusted root
│   ├── timestamp.json     # Last verified timestamp
│   ├── snapshot.json       # Last verified snapshot
│   └── targets/           # Delegated targets
│       ├── @scope.json
│       └── ...
├── pypi.org/
│   ├── root.json
│   ├── timestamp.json
│   ├── snapshot.json
│   └── targets/
└── internal.corp.com/
    └── ...
```

## 13.6 Testing

- Unit tests: signature verification with known-good and known-bad inputs
- Integration tests: full update sequence with mock registry
- Rollback/freeze tests: verify rejection of stale/rolled-back metadata
- Root rotation tests: single and multi-step rotation
- Threshold tests: verify threshold enforcement
- Delegation tests: namespace delegation resolution
- Expiration tests: verify expiration enforcement

---

# 14. Artifact Signing Model

## 14.1 Design

rusk supports two signing modes:

1. **Keyless signing** (Sigstore-style): Signer authenticates via OIDC, ephemeral key generated, certificate binds OIDC identity to public key, artifact signed, certificate and signature recorded in transparency log.

2. **Static key signing**: Traditional keypair signing. Key registered in TUF targets metadata.

## 14.2 Signature Object

```rust
pub struct ArtifactSignature {
    pub algorithm: SignatureAlgorithm,
    pub signature_bytes: Vec<u8>,
    pub signer: SignerProof,
    pub signed_digest: Sha256Digest,
    pub timestamp: DateTime<Utc>,
}

pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    RsaPkcs1v15Sha256,
}

pub enum SignerProof {
    /// Keyless: includes certificate chain back to Fulcio root
    Certificate {
        certificate: Vec<u8>,    // DER-encoded
        chain: Vec<Vec<u8>>,     // Certificate chain
        transparency_entry: Option<TransparencyRef>,
    },
    /// Static key: key ID references TUF key
    StaticKey {
        key_id: String,
    },
}

pub struct TransparencyRef {
    pub log_id: String,
    pub entry_index: u64,
    pub inclusion_proof: InclusionProof,
}
```

## 14.3 Verification Interface

```rust
#[async_trait]
pub trait SignatureVerifier: Send + Sync {
    async fn verify(
        &self,
        artifact_digest: &Sha256Digest,
        signature: &ArtifactSignature,
        policy_context: &PolicyContext,
    ) -> Result<VerifiedSignature, SignatureError>;
}

pub struct VerifiedSignature {
    pub signer_identity: SignerIdentity,
    pub verified_at: DateTime<Utc>,
    pub proof_type: ProofType,
}

pub enum ProofType {
    KeylessCertificate,
    StaticKey,
}
```

## 14.4 Keyless Verification Implementation

```rust
pub struct KeylessVerifier {
    fulcio_root: Certificate,
    rekor_client: RekorClient,
    cert_cache: SignatureCache,
}

impl KeylessVerifier {
    async fn verify_keyless(
        &self,
        digest: &Sha256Digest,
        sig: &ArtifactSignature,
    ) -> Result<VerifiedSignature, SignatureError> {
        let cert_proof = match &sig.signer {
            SignerProof::Certificate { certificate, chain, transparency_entry } => {
                // 1. Verify certificate chain to Fulcio root
                let cert = X509Certificate::from_der(certificate)?;
                verify_cert_chain(&cert, chain, &self.fulcio_root)?;

                // 2. Check certificate was valid at signing time
                if !cert.is_valid_at(sig.timestamp) {
                    return Err(SignatureError::CertificateExpired);
                }

                // 3. Verify signature with certificate's public key
                let public_key = cert.public_key()?;
                verify_raw_signature(&public_key, &sig.signature_bytes, digest, sig.algorithm)?;

                // 4. Extract signer identity from certificate SAN
                let identity = extract_signer_identity(&cert)?;

                // 5. Verify transparency log entry if present
                if let Some(tl_ref) = transparency_entry {
                    self.verify_transparency_entry(tl_ref, digest, &sig.signature_bytes).await?;
                }

                VerifiedSignature {
                    signer_identity: identity,
                    verified_at: Utc::now(),
                    proof_type: ProofType::KeylessCertificate,
                }
            }
            _ => return Err(SignatureError::WrongProofType),
        };

        Ok(cert_proof)
    }
}
```

## 14.5 Verification Result Cache

```rust
pub struct SignatureCache {
    /// Cache key: (artifact_digest, signature_digest) → VerifiedSignature
    cache: DashMap<(Sha256Digest, Sha256Digest), CachedVerification>,
    /// Invalidated by revocation epoch changes
    revocation_epoch: AtomicU64,
}

pub struct CachedVerification {
    pub result: VerifiedSignature,
    pub cached_at: DateTime<Utc>,
    pub revocation_epoch: u64,
}

impl SignatureCache {
    pub fn get(
        &self,
        artifact_digest: &Sha256Digest,
        sig_digest: &Sha256Digest,
        current_epoch: u64,
    ) -> Option<VerifiedSignature> {
        self.cache.get(&(*artifact_digest, *sig_digest))
            .filter(|cached| cached.revocation_epoch == current_epoch)
            .map(|cached| cached.result.clone())
    }
}
```

---

# 15. Transparency Log Model

## 15.1 Design

rusk integrates with Sigstore Rekor-compatible transparency logs. The transparency log provides:
- Append-only record of signing events
- Inclusion proofs for individual entries
- Signed checkpoints (tree heads) for consistency
- Public auditability of signer activity

## 15.2 Data Model

```rust
pub struct TransparencyCheckpoint {
    pub tree_size: u64,
    pub root_hash: Sha256Digest,
    pub signatures: Vec<CheckpointSignature>,
    pub timestamp: DateTime<Utc>,
}

pub struct CheckpointSignature {
    pub key_id: String,
    pub signature: Vec<u8>,
}

pub struct InclusionProof {
    pub log_index: u64,
    pub tree_size: u64,
    pub hashes: Vec<Sha256Digest>,
    pub root_hash: Sha256Digest,
    pub checkpoint: TransparencyCheckpoint,
}

pub struct TransparencyEntry {
    pub log_index: u64,
    pub body: TransparencyBody,
    pub integrated_time: DateTime<Utc>,
    pub inclusion_proof: InclusionProof,
}

pub enum TransparencyBody {
    HashedRekord {
        artifact_hash: Sha256Digest,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    },
    Dsse {
        envelope: DsseEnvelope,
        public_key: Vec<u8>,
    },
}
```

## 15.3 Verification Flow

```rust
pub struct TransparencyVerifier {
    log_public_keys: Vec<TransparencyLogKey>,
    checkpoint_cache: CheckpointCache,
}

impl TransparencyVerifier {
    pub fn verify_inclusion(
        &self,
        entry: &TransparencyEntry,
    ) -> Result<VerifiedTransparency, TransparencyError> {
        // 1. Verify checkpoint signature
        let checkpoint = &entry.inclusion_proof.checkpoint;
        self.verify_checkpoint_signatures(checkpoint)?;

        // 2. Verify inclusion proof (Merkle tree path)
        verify_merkle_inclusion(
            entry.log_index,
            entry.inclusion_proof.tree_size,
            &entry.inclusion_proof.hashes,
            &self.compute_leaf_hash(entry),
            &entry.inclusion_proof.root_hash,
        )?;

        // 3. Verify root hash matches checkpoint
        if entry.inclusion_proof.root_hash != checkpoint.root_hash {
            return Err(TransparencyError::RootHashMismatch);
        }

        // 4. Check checkpoint freshness
        if let Some(cached) = self.checkpoint_cache.get_latest()? {
            if checkpoint.tree_size < cached.tree_size {
                return Err(TransparencyError::StaleCheckpoint);
            }
        }

        // 5. Cache checkpoint
        self.checkpoint_cache.update(checkpoint)?;

        Ok(VerifiedTransparency {
            log_index: entry.log_index,
            integrated_time: entry.integrated_time,
            checkpoint_timestamp: checkpoint.timestamp,
        })
    }
}

fn verify_merkle_inclusion(
    index: u64,
    tree_size: u64,
    proof_hashes: &[Sha256Digest],
    leaf_hash: &Sha256Digest,
    expected_root: &Sha256Digest,
) -> Result<(), TransparencyError> {
    let mut current = *leaf_hash;
    let mut idx = index;
    let mut size = tree_size;
    let mut proof_idx = 0;

    while size > 1 {
        if proof_idx >= proof_hashes.len() {
            return Err(TransparencyError::InvalidInclusionProof);
        }
        if idx % 2 == 0 {
            // Current is left child
            current = hash_children(&current, &proof_hashes[proof_idx]);
        } else {
            // Current is right child
            current = hash_children(&proof_hashes[proof_idx], &current);
        }
        idx /= 2;
        size = (size + 1) / 2;
        proof_idx += 1;
    }

    if current != *expected_root {
        return Err(TransparencyError::InclusionProofFailed);
    }
    Ok(())
}
```

## 15.4 Checkpoint Cache

```rust
pub struct CheckpointCache {
    cache_dir: PathBuf,  // ~/.rusk/transparency/
}

// On disk:
// ~/.rusk/transparency/
// ├── rekor/
// │   ├── latest_checkpoint.json
// │   └── known_checkpoints/
// │       ├── 1000.json
// │       ├── 2000.json
// │       └── ...
```

## 15.5 Staleness Detection

Policy can configure maximum allowed checkpoint age:

```rust
pub fn check_freshness(
    checkpoint: &TransparencyCheckpoint,
    max_age: Duration,
) -> Result<(), TransparencyError> {
    let age = Utc::now() - checkpoint.timestamp;
    if age > max_age {
        return Err(TransparencyError::StaleCheckpoint {
            age,
            max_age,
        });
    }
    Ok(())
}
```

---

# 16. Provenance and Attestation Model

## 16.1 Design

Provenance binds an artifact to its source code, build process, and builder identity. rusk normalizes various upstream attestation formats (SLSA, npm provenance, PyPI attestations) into a single internal representation.

## 16.2 Internal Provenance Model

```rust
/// Normalized provenance statement
pub struct NormalizedProvenance {
    pub subjects: Vec<ProvenanceSubject>,
    pub source: ProvenanceSource,
    pub builder: ProvenanceBuilder,
    pub build_config: ProvBuildConfig,
    pub materials: Vec<ProvMaterial>,
    pub metadata: ProvMetadata,
}

pub struct ProvenanceSubject {
    pub name: String,
    pub digest: Sha256Digest,
}

pub struct ProvenanceSource {
    pub repository: Url,
    pub ref_name: Option<String>,   // branch or tag
    pub commit: String,              // full commit hash
    pub is_verified: bool,
}

pub struct ProvenanceBuilder {
    pub id: BuilderIdentity,
    pub version: Option<String>,
    pub builder_dependencies: Vec<ProvMaterial>,
}

pub struct ProvBuildConfig {
    pub workflow: Option<String>,
    pub workflow_ref: Option<String>,
    pub invocation_id: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub hermetic: bool,
    pub reproducible: bool,
}

pub struct ProvMaterial {
    pub uri: String,
    pub digest: Option<Sha256Digest>,
}

pub struct ProvMetadata {
    pub build_started: Option<DateTime<Utc>>,
    pub build_finished: Option<DateTime<Utc>>,
    pub completeness: ProvenanceCompleteness,
    pub slsa_level: Option<u8>,
}

pub struct ProvenanceCompleteness {
    pub parameters: bool,
    pub environment: bool,
    pub materials: bool,
}
```

## 16.3 Attestation Envelope Parsing

rusk accepts in-toto/DSSE envelopes:

```rust
pub struct DsseEnvelope {
    pub payload_type: String,    // "application/vnd.in-toto+json"
    pub payload: Vec<u8>,        // base64-decoded
    pub signatures: Vec<DsseSignature>,
}

pub struct DsseSignature {
    pub keyid: Option<String>,
    pub sig: Vec<u8>,
}

pub fn parse_attestation(raw: &[u8]) -> Result<ParsedAttestation, ProvenanceError> {
    let envelope: DsseEnvelope = serde_json::from_slice(raw)?;

    if envelope.payload_type != "application/vnd.in-toto+json" {
        return Err(ProvenanceError::UnsupportedPayloadType(envelope.payload_type));
    }

    let statement: InTotoStatement = serde_json::from_slice(&envelope.payload)?;

    match statement.predicate_type.as_str() {
        "https://slsa.dev/provenance/v1" => {
            let pred: SlsaProvenanceV1 = serde_json::from_value(statement.predicate)?;
            Ok(ParsedAttestation::SlsaV1 { envelope, statement, predicate: pred })
        }
        "https://github.com/npm/attestation/tree/main/specs/publish/v0.1" => {
            let pred: NpmPublishAttestation = serde_json::from_value(statement.predicate)?;
            Ok(ParsedAttestation::NpmPublish { envelope, statement, predicate: pred })
        }
        other => Err(ProvenanceError::UnsupportedPredicateType(other.to_string())),
    }
}
```

## 16.4 Verification Pipeline

```rust
pub struct ProvenanceVerifier {
    signature_verifier: Arc<dyn SignatureVerifier>,
    transparency_verifier: Arc<TransparencyVerifier>,
    revocation_checker: Arc<RevocationChecker>,
}

impl ProvenanceVerifier {
    pub async fn verify(
        &self,
        artifact_digest: &Sha256Digest,
        raw_attestation: &[u8],
        policy_ctx: &PolicyContext,
    ) -> Result<VerifiedProvenance, ProvenanceError> {
        // 1. Parse attestation envelope
        let parsed = parse_attestation(raw_attestation)?;

        // 2. Verify envelope signatures
        let envelope = parsed.envelope();
        for sig in &envelope.signatures {
            self.signature_verifier.verify_raw(
                &envelope.payload,
                sig,
                policy_ctx,
            ).await?;
        }

        // 3. Verify transparency entry if required
        if policy_ctx.requires_transparency() {
            let tl_entry = parsed.transparency_entry()
                .ok_or(ProvenanceError::MissingTransparencyEntry)?;
            self.transparency_verifier.verify_inclusion(tl_entry)?;
        }

        // 4. Check signer/builder revocation
        let signer = parsed.signer_identity()?;
        self.revocation_checker.check_signer(&signer)?;

        let builder = parsed.builder_identity()?;
        self.revocation_checker.check_builder(&builder)?;

        // 5. Normalize to internal model
        let normalized = normalize_provenance(&parsed)?;

        // 6. Verify subject digest matches artifact digest
        let subject_match = normalized.subjects.iter()
            .any(|s| &s.digest == artifact_digest);
        if !subject_match {
            return Err(ProvenanceError::SubjectDigestMismatch {
                expected: *artifact_digest,
                found: normalized.subjects.iter().map(|s| s.digest).collect(),
            });
        }

        // 7. Compute risk flags
        let risk_flags = compute_risk_flags(&normalized);

        // 8. Build verified bundle
        Ok(VerifiedProvenance {
            normalized,
            risk_flags,
            signer_identity: signer,
            builder_identity: builder,
            verified_at: Utc::now(),
        })
    }
}

fn compute_risk_flags(prov: &NormalizedProvenance) -> Vec<RiskFlag> {
    let mut flags = Vec::new();
    if !prov.build_config.hermetic {
        flags.push(RiskFlag::NonHermeticBuild);
    }
    if !prov.build_config.reproducible {
        flags.push(RiskFlag::NonReproducibleBuild);
    }
    if !prov.metadata.completeness.materials {
        flags.push(RiskFlag::IncompleteMaterials);
    }
    if prov.source.ref_name.is_none() {
        flags.push(RiskFlag::NoSourceRef);
    }
    flags
}

pub enum RiskFlag {
    NonHermeticBuild,
    NonReproducibleBuild,
    IncompleteMaterials,
    NoSourceRef,
    UnknownBuilder,
    NoSlsaLevel,
    LowSlsaLevel,
}
```

## 16.5 Cache Strategy

Verified provenance bundles are cached in CAS keyed by attestation digest:
```
~/.rusk/cas/provenance/
├── sha256/
│   ├── ab/
│   │   └── abcdef1234...  # Serialized VerifiedProvenance
│   └── ...
```

Cache invalidation: revocation epoch change invalidates all cached provenance for revoked signers/builders.

---

# 17. Policy Engine Design

## 17.1 Architecture

The policy engine is a declarative rule evaluator. It receives a `PolicyContext` for each artifact and evaluates all applicable rules to produce a `PolicyVerdict`.

```
┌─────────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Policy File │ ──→ │  Parser  │ ──→ │ Compiler │ ──→ │    IR    │
│ (.ruskpol)  │     │          │     │          │     │          │
└─────────────┘     └──────────┘     └──────────┘     └────┬─────┘
                                                           │
                    ┌──────────┐     ┌──────────┐          │
                    │ Verdict  │ ←── │Evaluator │ ←────────┘
                    │          │     │          │ ←── PolicyContext
                    └──────────┘     └──────────┘
```

## 17.2 Policy Context

```rust
/// All information available during policy evaluation for one artifact
pub struct PolicyContext {
    pub artifact: ArtifactInfo,
    pub signature: Option<VerifiedSignature>,
    pub provenance: Option<VerifiedProvenance>,
    pub transparency: Option<VerifiedTransparency>,
    pub revocation: RevocationState,
    pub graph: GraphContext,
    pub install_mode: InstallMode,
}

pub struct ArtifactInfo {
    pub package: PackageId,
    pub version: Version,
    pub ecosystem: Ecosystem,
    pub registry: RegistryUrl,
    pub namespace: Option<String>,
    pub digest: Sha256Digest,
    pub artifact_type: ArtifactType,
    pub first_seen: Option<DateTime<Utc>>,
    pub age: Option<Duration>,
}

pub struct GraphContext {
    pub depth: u32,                        // 0 = direct dep
    pub dependents: Vec<PackageId>,        // who depends on this
    pub is_build_dep: bool,
    pub is_dev_dep: bool,
    pub has_install_scripts: bool,
    pub total_transitive_deps: u32,
}

pub enum InstallMode {
    Production,
    Development,
    CI,
    Offline,
}
```

## 17.3 Policy AST

```rust
pub struct PolicyFile {
    pub rules: Vec<Rule>,
    pub defaults: DefaultAction,
}

pub struct Rule {
    pub name: String,
    pub description: Option<String>,
    pub priority: i32,              // Higher = evaluated first
    pub condition: Expr,
    pub action: Action,
    pub reason: Option<String>,
}

pub enum Action {
    Allow,
    Deny,
    RequireApproval,
    Quarantine { duration: Duration },
    Warn,
}

pub enum Expr {
    // Literals
    Bool(bool),
    String(String),
    Int(i64),

    // Variables
    Var(String),       // e.g., "package.name", "signer.subject"

    // Comparison
    Eq(Box<Expr>, Box<Expr>),
    NotEq(Box<Expr>, Box<Expr>),
    Lt(Box<Expr>, Box<Expr>),
    Gt(Box<Expr>, Box<Expr>),
    Lte(Box<Expr>, Box<Expr>),
    Gte(Box<Expr>, Box<Expr>),

    // Logical
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),

    // Set operations
    In(Box<Expr>, Box<Expr>),        // value in set
    Contains(Box<Expr>, Box<Expr>),  // set contains value

    // Pattern matching
    Glob(Box<Expr>, String),         // value matches glob pattern

    // Built-in predicates
    Predicate(PredicateCall),
}

pub struct PredicateCall {
    pub name: String,
    pub args: Vec<Expr>,
}

pub enum DefaultAction {
    Allow,
    Deny,
}
```

## 17.4 Compiled IR

```rust
/// Compiled policy rule for fast evaluation
pub struct CompiledPolicy {
    pub rules: Vec<CompiledRule>,
    pub default_action: Action,
    pub digest: Sha256Digest,    // For cache keying
}

pub struct CompiledRule {
    pub name: String,
    pub priority: i32,
    pub condition: CompiledExpr,
    pub action: Action,
    pub reason: Option<String>,
}

pub enum CompiledExpr {
    Const(bool),
    VarLookup(VarPath),
    Eq(Box<CompiledExpr>, Box<CompiledExpr>),
    And(Vec<CompiledExpr>),  // Flattened for short-circuit
    Or(Vec<CompiledExpr>),
    Not(Box<CompiledExpr>),
    InSet(Box<CompiledExpr>, HashSet<String>),
    GlobMatch(Box<CompiledExpr>, glob::Pattern),
    BuiltinPredicate(BuiltinId, Vec<CompiledExpr>),
}

pub struct VarPath {
    pub segments: Vec<String>,   // e.g., ["package", "name"]
}
```

## 17.5 Evaluator

```rust
pub struct PolicyEvaluator {
    compiled: CompiledPolicy,
    cache: PolicyVerdictCache,
}

impl PolicyEvaluator {
    pub fn evaluate(
        &self,
        ctx: &PolicyContext,
        revocation_epoch: u64,
    ) -> PolicyVerdict {
        // Check cache first
        let cache_key = PolicyCacheKey {
            policy_digest: self.compiled.digest,
            artifact_digest: ctx.artifact.digest,
            revocation_epoch,
        };
        if let Some(cached) = self.cache.get(&cache_key) {
            return cached;
        }

        // Evaluate rules in priority order (highest first)
        let mut matched_rules = Vec::new();
        let mut warnings = Vec::new();
        let mut verdict = None;

        for rule in &self.compiled.rules {
            let result = self.eval_expr(&rule.condition, ctx);
            if result {
                matched_rules.push(rule.name.clone());
                match &rule.action {
                    Action::Deny => {
                        // Deny always wins (highest precedence action)
                        let v = PolicyVerdict::Deny {
                            reason: rule.reason.clone()
                                .unwrap_or_else(|| format!("Denied by rule '{}'", rule.name)),
                            matched_rules: matched_rules.clone(),
                        };
                        self.cache.put(cache_key, v.clone());
                        return v;
                    }
                    Action::Warn => {
                        warnings.push(rule.reason.clone()
                            .unwrap_or_else(|| format!("Warning from rule '{}'", rule.name)));
                    }
                    Action::RequireApproval if verdict.is_none() => {
                        verdict = Some(PolicyVerdict::RequireApproval {
                            reason: rule.reason.clone()
                                .unwrap_or_else(|| "Approval required".to_string()),
                        });
                    }
                    Action::Quarantine { duration } if verdict.is_none() => {
                        verdict = Some(PolicyVerdict::Quarantine {
                            reason: rule.reason.clone()
                                .unwrap_or_else(|| "Quarantined".to_string()),
                            duration: *duration,
                        });
                    }
                    Action::Allow if verdict.is_none() => {
                        verdict = Some(PolicyVerdict::Allow {
                            matched_rules: matched_rules.clone(),
                        });
                    }
                    _ => {}
                }
            }
        }

        let result = match verdict {
            Some(v) => v,
            None => {
                // No rule matched, use default
                match self.compiled.default_action {
                    Action::Allow => PolicyVerdict::Allow { matched_rules: vec![] },
                    Action::Deny => PolicyVerdict::Deny {
                        reason: "No matching policy rule; default deny".to_string(),
                        matched_rules: vec![],
                    },
                    _ => unreachable!(),
                }
            }
        };

        self.cache.put(cache_key, result.clone());
        result
    }

    fn eval_expr(&self, expr: &CompiledExpr, ctx: &PolicyContext) -> bool {
        match expr {
            CompiledExpr::Const(b) => *b,
            CompiledExpr::VarLookup(path) => {
                // Resolve variable from context, treat as truthy/falsy
                ctx.resolve_var(path).is_truthy()
            }
            CompiledExpr::Eq(left, right) => {
                let l = self.eval_value(left, ctx);
                let r = self.eval_value(right, ctx);
                l == r
            }
            CompiledExpr::And(exprs) => {
                exprs.iter().all(|e| self.eval_expr(e, ctx))
            }
            CompiledExpr::Or(exprs) => {
                exprs.iter().any(|e| self.eval_expr(e, ctx))
            }
            CompiledExpr::Not(e) => !self.eval_expr(e, ctx),
            CompiledExpr::InSet(e, set) => {
                let val = self.eval_string(e, ctx);
                set.contains(&val)
            }
            CompiledExpr::GlobMatch(e, pattern) => {
                let val = self.eval_string(e, ctx);
                pattern.matches(&val)
            }
            CompiledExpr::BuiltinPredicate(id, args) => {
                evaluate_builtin(*id, args, ctx, self)
            }
        }
    }
}
```

## 17.6 Policy Verdict Cache

```rust
pub struct PolicyVerdictCache {
    cache: DashMap<PolicyCacheKey, PolicyVerdict>,
}

pub struct PolicyCacheKey {
    pub policy_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub revocation_epoch: u64,
}

// Invalidation: revocation epoch change invalidates all entries with old epoch.
// Policy file change changes policy_digest, creating new cache namespace.
```

---

# 18. Policy Language Grammar and Semantics

## 18.1 Grammar (EBNF sketch)

```ebnf
policy_file  = { rule } ;
rule         = "rule" IDENT "{" rule_body "}" ;
rule_body    = { attribute } ;
attribute    = "description" "=" STRING
             | "priority" "=" INT
             | "when" "=" expr
             | "action" "=" action_value
             | "reason" "=" STRING ;
action_value = "allow" | "deny" | "require_approval"
             | "quarantine" "(" duration ")"
             | "warn" ;
duration     = INT ("h" | "d" | "w") ;

expr         = or_expr ;
or_expr      = and_expr { "||" and_expr } ;
and_expr     = not_expr { "&&" not_expr } ;
not_expr     = "!" not_expr | comparison ;
comparison   = primary [ comp_op primary ] ;
comp_op      = "==" | "!=" | "<" | ">" | "<=" | ">=" | "in" | "contains" | "matches" ;
primary      = "(" expr ")"
             | var_path
             | STRING
             | INT
             | BOOL
             | "[" [ expr { "," expr } ] "]"   (* set literal *)
             | predicate_call ;
var_path     = IDENT { "." IDENT } ;
predicate_call = IDENT "(" [ expr { "," expr } ] ")" ;
```

## 18.2 Example Policy File

```
# .rusk/policy.ruskpol

default deny

rule allow_signed_public {
    description = "Allow packages with valid signatures from public registries"
    priority = 100
    when = signature.verified && registry.kind == "public"
    action = allow
}

rule require_provenance_for_critical {
    description = "Critical packages must have verified provenance"
    priority = 200
    when = package.name in ["react", "express", "requests", "fastapi"]
           && !provenance.verified
    action = deny
    reason = "Critical package requires verified provenance"
}

rule deny_install_scripts {
    description = "Deny packages with install scripts unless explicitly allowed"
    priority = 300
    when = graph.has_install_scripts && !(package.name in trust.allowed_scripts)
    action = deny
    reason = "Install scripts are not allowed by default"
}

rule quarantine_new_packages {
    description = "Quarantine packages first seen less than 7 days ago"
    priority = 50
    when = artifact.age < 7d
    action = quarantine(7d)
    reason = "New package under quarantine period"
}

rule deny_deep_transitive {
    description = "Warn about deeply nested transitive dependencies"
    priority = 10
    when = graph.depth > 10
    action = warn
    reason = "Deep transitive dependency chain"
}

rule deny_internal_from_public {
    description = "Never resolve internal packages from public registries"
    priority = 1000
    when = package.namespace in internal.namespaces && registry.kind == "public"
    action = deny
    reason = "Internal package must not come from public registry"
}

rule deny_revoked {
    description = "Deny revoked artifacts"
    priority = 999
    when = revocation.is_revoked
    action = deny
    reason = "Artifact or signer has been revoked"
}

rule allow_local_dev {
    description = "Allow local dev builds in development mode"
    priority = 80
    when = trust_class == "local_dev" && install_mode == "development"
    action = allow
}

rule deny_local_in_prod {
    description = "Deny local dev builds in production"
    priority = 500
    when = trust_class == "local_dev" && install_mode == "production"
    action = deny
    reason = "Local dev builds not allowed in production"
}
```

## 18.3 Semantics

- **Evaluation order**: Rules sorted by priority descending. First `deny` match short-circuits.
- **Deny precedence**: A `deny` at any priority level overrides all `allow` rules.
- **Default action**: Applied when no rule condition matches.
- **Explanation**: Every verdict includes the list of matched rule names and reasons.
- **Type system**: Variables are dynamically typed. String, Int, Bool, Duration, Set. Type errors in conditions evaluate to `false` (fail-closed).

## 18.4 Built-in Predicates

```rust
pub enum BuiltinId {
    HasSignature,           // has_signature()
    HasProvenance,          // has_provenance()
    HasTransparency,        // has_transparency()
    IsHermeticBuild,        // is_hermetic_build()
    IsReproducibleBuild,    // is_reproducible_build()
    SignerMatches,          // signer_matches("pattern")
    BuilderMatches,         // builder_matches("pattern")
    SourceRepoMatches,      // source_repo_matches("pattern")
    AgeGreaterThan,         // age_gt(7d)
    DepthGreaterThan,       // depth_gt(5)
    TransitiveCountGt,      // transitive_count_gt(100)
    IsBuildDep,             // is_build_dep()
    IsDevDep,               // is_dev_dep()
    HasCap,                 // has_capability("network")
}
```

---

# 19. Revocation Architecture

## 19.1 Design

Revocation is a core subsystem, not an afterthought. Every trust decision checks revocation state. Revocation state is maintained per-registry with global merge.

## 19.2 Revocation Bundle Schema

```rust
pub struct RevocationBundle {
    pub version: u64,
    pub epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub entries: Vec<RevocationEntry>,
    pub signature: Vec<u8>,           // Signed by revocation authority
    pub signer_key_id: String,
}

pub enum RevocationEntry {
    Signer {
        identity: SignerIdentity,
        revoked_at: DateTime<Utc>,
        reason: String,
    },
    Builder {
        identity: BuilderIdentity,
        revoked_at: DateTime<Utc>,
        reason: String,
    },
    Artifact {
        digest: Sha256Digest,
        package: PackageId,
        version: Version,
        revoked_at: DateTime<Utc>,
        reason: String,
    },
    Provenance {
        provenance_digest: Sha256Digest,
        revoked_at: DateTime<Utc>,
        reason: String,
    },
    PackageVersion {
        package: PackageId,
        version: Version,
        yanked_at: DateTime<Utc>,
        reason: String,
    },
}
```

## 19.3 Local State Model

```rust
pub struct RevocationState {
    pub epoch: u64,
    pub last_updated: DateTime<Utc>,
    pub revoked_signers: HashSet<SignerIdentity>,
    pub revoked_builders: HashSet<BuilderIdentity>,
    pub revoked_artifacts: HashSet<Sha256Digest>,
    pub revoked_provenance: HashSet<Sha256Digest>,
    pub yanked_versions: HashSet<(PackageId, Version)>,
}

// Stored at: ~/.rusk/revocation/
// ├── npmjs.org/
// │   ├── state.json       # Current merged state
// │   └── bundles/
// │       ├── epoch_001.json
// │       └── epoch_002.json
// ├── pypi.org/
// │   └── ...
// └── enterprise/
//     └── ...
```

## 19.4 Update Flow

```rust
impl RevocationChecker {
    pub async fn update(&mut self, client: &dyn RegistryClient) -> Result<(), RevocationError> {
        // 1. Fetch latest revocation bundle
        let bundle = client.fetch_revocation_bundle(self.state.epoch).await?;

        // 2. Verify bundle signature
        self.verify_bundle_signature(&bundle)?;

        // 3. Verify epoch is monotonically increasing
        if bundle.epoch <= self.state.epoch {
            return Err(RevocationError::StaleBundle);
        }

        // 4. Apply entries to local state
        for entry in &bundle.entries {
            self.apply_entry(entry);
        }

        // 5. Update epoch
        self.state.epoch = bundle.epoch;
        self.state.last_updated = Utc::now();

        // 6. Persist state
        self.persist_state()?;

        // 7. Invalidate caches with old epoch
        self.invalidate_caches();

        Ok(())
    }

    pub fn check_signer(&self, signer: &SignerIdentity) -> Result<(), RevocationError> {
        if self.state.revoked_signers.contains(signer) {
            return Err(RevocationError::RevokedSigner(signer.clone()));
        }
        Ok(())
    }

    pub fn check_artifact(&self, digest: &Sha256Digest) -> Result<(), RevocationError> {
        if self.state.revoked_artifacts.contains(digest) {
            return Err(RevocationError::RevokedArtifact(*digest));
        }
        Ok(())
    }

    pub fn check_version(&self, pkg: &PackageId, version: &Version) -> Result<(), RevocationError> {
        if self.state.yanked_versions.contains(&(pkg.clone(), version.clone())) {
            return Err(RevocationError::YankedVersion(pkg.clone(), version.clone()));
        }
        Ok(())
    }
}
```

## 19.5 Enforcement Points

Revocation is checked at:
1. **Resolution**: Yanked versions excluded from candidate set
2. **Pre-fetch**: Artifact digest checked before download
3. **Post-verification**: Signer/builder checked after signature/provenance verification
4. **Install gate**: Final check before materialization
5. **Verify command**: Full re-check of all installed packages

---

# 20. Resolver and Solver Design (JS + Python)

## 20.1 Architecture

The resolver uses a PubGrub-based SAT solver (inspired by uv's approach, which itself is inspired by Dart's solver). The solver is extended with trust-aware candidate filtering.

```
┌──────────────────────────────────────────────────────────────┐
│                      Resolver                                 │
│                                                                │
│  ┌─────────┐   ┌────────────┐   ┌──────────┐   ┌──────────┐ │
│  │Candidate│──→│Trust Filter│──→│ PubGrub  │──→│ Digest   │ │
│  │Generator│   │            │   │ Solver   │   │ Closure  │ │
│  └────┬────┘   └────────────┘   └──────────┘   └──────────┘ │
│       │                                                        │
│  ┌────▼────────────────────────────────────┐                  │
│  │        Ecosystem Adapter                 │                  │
│  │  ┌──────────┐   ┌───────────────┐       │                  │
│  │  │ JS/npm   │   │ Python/PyPI   │       │                  │
│  │  │ Adapter  │   │ Adapter       │       │                  │
│  │  └──────────┘   └───────────────┘       │                  │
│  └──────────────────────────────────────────┘                  │
└──────────────────────────────────────────────────────────────┘
```

## 20.2 Solver Phases

```
Phase 1: Candidate Generation
  - Query registry for available versions
  - Apply version constraint filtering
  - Apply ecosystem-specific constraints (markers, platform, etc.)
  - Apply trust filtering (allowed registries, namespaces, signers)
  - Sort candidates by preference (newest first, prefer wheel over sdist, etc.)

Phase 2: Unit Propagation + Conflict Resolution (PubGrub)
  - Select next package to resolve
  - Pick best candidate
  - Add dependencies as new constraints
  - Propagate constraints
  - On conflict: derive root cause, add learned clause, backtrack

Phase 3: Digest Closure
  - For each resolved (package, version): fetch/verify artifact digest
  - Build complete digest-pinned graph
  - This is the lockfile-ready output
```

## 20.3 Trust-Aware Candidate Filtering

```rust
pub struct TrustAwareCandidateFilter {
    policy: Arc<PolicyEvaluator>,
    revocation: Arc<RevocationChecker>,
    manifest_trust: TrustConfig,
}

impl TrustAwareCandidateFilter {
    /// Filter candidates before they enter the solver
    pub fn filter_candidates(
        &self,
        package: &PackageId,
        candidates: Vec<VersionCandidate>,
    ) -> Vec<VersionCandidate> {
        candidates.into_iter()
            .filter(|c| {
                // 1. Check registry is allowed for this package
                if !self.is_registry_allowed(package, &c.registry) {
                    return false;
                }

                // 2. Check namespace is allowed
                if !self.is_namespace_allowed(package, &c.namespace) {
                    return false;
                }

                // 3. Check not yanked/revoked
                if self.revocation.is_yanked(package, &c.version) {
                    return false;
                }

                // 4. Check not from public registry if marked internal
                if self.is_internal(package) && c.registry.is_public() {
                    return false;
                }

                true
            })
            .collect()
    }
}
```

## 20.4 PubGrub Solver Core

```rust
/// PubGrub-based dependency resolver
pub struct PubGrubSolver {
    /// Candidate provider (ecosystem-specific)
    provider: Box<dyn CandidateProvider>,
    /// Trust filter
    trust_filter: TrustAwareCandidateFilter,
}

#[async_trait]
pub trait CandidateProvider: Send + Sync {
    /// Get available versions for a package, sorted by preference
    async fn get_candidates(
        &self,
        package: &PackageId,
    ) -> Result<Vec<VersionCandidate>, ResolverError>;

    /// Get dependencies for a specific version
    async fn get_dependencies(
        &self,
        package: &PackageId,
        version: &Version,
    ) -> Result<Vec<DependencyEdge>, ResolverError>;
}

pub struct VersionCandidate {
    pub version: Version,
    pub registry: RegistryUrl,
    pub namespace: Option<String>,
    pub artifact_digest: Option<Sha256Digest>,
    pub metadata: CandidateMetadata,
}

impl PubGrubSolver {
    pub async fn solve(
        &self,
        root_deps: &[DependencyEdge],
        lockfile: Option<&Lockfile>,
    ) -> Result<ResolvedGraph, ResolverError> {
        let mut partial_solution = PartialSolution::new();
        let mut incompatibilities = IncompatibilityStore::new();

        // Seed from lockfile if available (for partial updates)
        if let Some(lf) = lockfile {
            self.seed_from_lockfile(&mut partial_solution, lf);
        }

        // Add root dependencies
        for dep in root_deps {
            let incompat = Incompatibility::from_dependency(
                PackageId::root(),
                Version::root(),
                dep,
            );
            incompatibilities.add(incompat);
        }

        loop {
            // Unit propagation
            match self.unit_propagation(&mut partial_solution, &incompatibilities)? {
                PropagationResult::Satisfied => break,
                PropagationResult::NeedDecision(package) => {
                    // Choose version for undecided package
                    let candidates = self.provider.get_candidates(&package).await?;
                    let filtered = self.trust_filter.filter_candidates(&package, candidates);

                    if filtered.is_empty() {
                        return Err(ResolverError::NoViableCandidates(package));
                    }

                    // Pick best candidate (highest version that satisfies constraints)
                    let chosen = self.pick_candidate(&package, &filtered, &partial_solution)?;

                    // Fetch and add dependencies
                    let deps = self.provider.get_dependencies(&package, &chosen.version).await?;
                    for dep in deps {
                        let incompat = Incompatibility::from_dependency(
                            package.clone(),
                            chosen.version.clone(),
                            &dep,
                        );
                        incompatibilities.add(incompat);
                    }

                    partial_solution.decide(package, chosen);
                }
            }
        }

        // Build resolved graph
        let graph = self.build_resolved_graph(&partial_solution)?;
        Ok(graph)
    }
}
```

## 20.5 JS/TS-Specific Resolution

```rust
pub struct JsCandidateProvider {
    npm_client: NpmRegistryClient,
}

#[async_trait]
impl CandidateProvider for JsCandidateProvider {
    async fn get_candidates(&self, package: &PackageId) -> Result<Vec<VersionCandidate>, ResolverError> {
        let packument = self.npm_client.fetch_packument(&package.name).await?;

        packument.versions.iter()
            .map(|(version_str, meta)| {
                let version = semver::Version::parse(version_str)?;
                Ok(VersionCandidate {
                    version: Version::Semver(version),
                    registry: package.registry.clone(),
                    namespace: package.namespace.clone(),
                    artifact_digest: meta.dist.integrity.as_ref()
                        .and_then(|sri| parse_sri_to_digest(sri)),
                    metadata: CandidateMetadata::Js(meta.clone()),
                })
            })
            .collect()
    }

    async fn get_dependencies(&self, package: &PackageId, version: &Version) -> Result<Vec<DependencyEdge>, ResolverError> {
        let packument = self.npm_client.fetch_packument(&package.name).await?;
        let version_str = version.to_string();
        let meta = packument.versions.get(&version_str)
            .ok_or(ResolverError::VersionNotFound(package.clone(), version.clone()))?;

        let mut deps = Vec::new();

        // Normal dependencies
        for (name, req) in &meta.dependencies {
            deps.push(DependencyEdge {
                target: PackageId::js(name),
                version_req: VersionReq::SemverReq(semver::VersionReq::parse(req)?),
                dep_type: DependencyType::Normal,
                condition: None,
            });
        }

        // Peer dependencies
        for (name, req) in &meta.peer_dependencies {
            let optional = meta.peer_dependencies_meta
                .as_ref()
                .and_then(|m| m.get(name))
                .map_or(false, |m| m.optional);
            deps.push(DependencyEdge {
                target: PackageId::js(name),
                version_req: VersionReq::SemverReq(semver::VersionReq::parse(req)?),
                dep_type: if optional { DependencyType::PeerOptional } else { DependencyType::Peer },
                condition: None,
            });
        }

        // Optional dependencies
        for (name, req) in &meta.optional_dependencies {
            deps.push(DependencyEdge {
                target: PackageId::js(name),
                version_req: VersionReq::SemverReq(semver::VersionReq::parse(req)?),
                dep_type: DependencyType::Optional,
                condition: None,
            });
        }

        Ok(deps)
    }
}
```

## 20.6 Python-Specific Resolution

```rust
pub struct PythonCandidateProvider {
    pypi_client: PypiRegistryClient,
    target_python: PythonVersion,
    target_platform: Platform,
}

#[async_trait]
impl CandidateProvider for PythonCandidateProvider {
    async fn get_candidates(&self, package: &PackageId) -> Result<Vec<VersionCandidate>, ResolverError> {
        let index = self.pypi_client.fetch_package_index(&package.name).await?;

        let mut candidates = Vec::new();
        for file in &index.files {
            // Parse version from filename
            let (version, artifact_type) = parse_pypi_filename(&file.filename)?;

            // Check python version compatibility
            if let Some(ref requires_python) = file.requires_python {
                let specifiers = pep440::VersionSpecifiers::parse(requires_python)?;
                if !specifiers.contains(&self.target_python) {
                    continue;
                }
            }

            // Check wheel tag compatibility
            if let ArtifactType::PythonWheel { ref tags } = artifact_type {
                if !tags.is_compatible(&self.target_python, &self.target_platform) {
                    continue;
                }
            }

            // Skip yanked
            if file.yanked.is_some() {
                continue;
            }

            let digest = file.hashes.get("sha256")
                .and_then(|h| Sha256Digest::from_hex(h).ok());

            candidates.push(VersionCandidate {
                version: Version::Pep440(version),
                registry: package.registry.clone(),
                namespace: None,
                artifact_digest: digest,
                metadata: CandidateMetadata::Python {
                    filename: file.filename.clone(),
                    artifact_type,
                    requires_python: file.requires_python.clone(),
                },
            });
        }

        // Sort: prefer wheels over sdists, then by version descending
        candidates.sort_by(|a, b| {
            // Prefer wheels
            let a_wheel = matches!(a.metadata, CandidateMetadata::Python { artifact_type: ArtifactType::PythonWheel { .. }, .. });
            let b_wheel = matches!(b.metadata, CandidateMetadata::Python { artifact_type: ArtifactType::PythonWheel { .. }, .. });
            b_wheel.cmp(&a_wheel)
                .then(b.version.cmp(&a.version))
        });

        Ok(candidates)
    }

    async fn get_dependencies(&self, package: &PackageId, version: &Version) -> Result<Vec<DependencyEdge>, ResolverError> {
        // Try PEP 658 metadata first (fast path, inspired by uv)
        if let Ok(metadata) = self.pypi_client.fetch_pep658_metadata(package, version).await {
            return self.parse_python_deps(&metadata);
        }

        // Fall back to downloading the wheel/sdist and extracting METADATA
        let artifact = self.pypi_client.fetch_artifact(package, version).await?;
        let metadata = extract_metadata_from_artifact(&artifact)?;
        self.parse_python_deps(&metadata)
    }
}

impl PythonCandidateProvider {
    fn parse_python_deps(&self, metadata: &PythonMetadata) -> Result<Vec<DependencyEdge>, ResolverError> {
        let mut deps = Vec::new();
        for req in &metadata.requires_dist {
            let parsed = parse_pep508_requirement(req)?;

            // Evaluate environment markers
            let condition = parsed.marker.map(|m| {
                DependencyCondition::PythonMarker(m)
            });

            deps.push(DependencyEdge {
                target: PackageId::python(&parsed.name),
                version_req: VersionReq::Pep440Req(parsed.specifiers),
                dep_type: if parsed.extra.is_some() {
                    DependencyType::Optional
                } else {
                    DependencyType::Normal
                },
                condition,
            });
        }
        Ok(deps)
    }
}
```

## 20.7 Lockfile Reuse Strategy

```rust
/// Determines which packages can be reused from an existing lockfile
fn compute_reuse_set(
    lockfile: &Lockfile,
    manifest_changes: &ManifestDiff,
    update_targets: &[PackageId],
) -> HashSet<(PackageId, Version)> {
    let mut reuse = HashSet::new();

    for locked_pkg in &lockfile.packages {
        let pkg_id = locked_pkg.to_package_id();

        // Don't reuse if explicitly targeted for update
        if update_targets.contains(&pkg_id) {
            continue;
        }

        // Don't reuse if direct dependency constraint changed
        if manifest_changes.constraint_changed(&pkg_id) {
            continue;
        }

        // Reuse: pin this package at its locked version
        reuse.insert((pkg_id, locked_pkg.version.clone()));
    }

    reuse
}
```

---

# 21. Content-Addressed Store Design

## 21.1 On-Disk Layout

```
~/.rusk/cas/
├── objects/
│   ├── sha256/
│   │   ├── ab/
│   │   │   ├── abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
│   │   │   └── ab11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff
│   │   ├── cd/
│   │   └── ...
│   └── blake3/
│       └── ...  (same structure)
├── index/
│   ├── packages.idx          # Memory-mapped package→digest index
│   └── refcounts.idx         # Reference count index
├── tmp/
│   └── ...                   # Staging area for writes
└── metadata/
    ├── store_version          # CAS format version
    └── stats.json             # GC stats
```

## 21.2 Object Classes

```rust
pub enum CasObjectType {
    /// Raw artifact (tarball, wheel)
    Artifact,
    /// Package metadata blob
    Metadata,
    /// Attestation/provenance blob
    Attestation,
    /// Policy decision snapshot
    PolicySnapshot,
    /// Install tree manifest
    InstallTree,
}
```

## 21.3 CAS Core API

```rust
pub struct ContentAddressedStore {
    root: PathBuf,
    index: MemoryMappedIndex,
    lock_manager: FileLockManager,
}

impl ContentAddressedStore {
    /// Check if object exists
    pub fn has(&self, digest: &Sha256Digest) -> bool {
        self.object_path(digest).exists()
    }

    /// Read object
    pub fn get(&self, digest: &Sha256Digest) -> Result<Vec<u8>, CasError> {
        let path = self.object_path(digest);
        let data = std::fs::read(&path)?;

        // Verify integrity on read
        let actual_digest = Sha256Digest::compute(&data);
        if actual_digest != *digest {
            // Corruption detected!
            self.handle_corruption(digest, &path)?;
            return Err(CasError::CorruptObject(*digest));
        }

        Ok(data)
    }

    /// Write object with streaming verification
    pub fn put_streaming<R: Read>(
        &self,
        expected_digest: &Sha256Digest,
        reader: R,
    ) -> Result<(), CasError> {
        // 1. Write to temp file while computing hash
        let tmp_path = self.tmp_dir().join(Uuid::new_v4().to_string());
        let mut hasher = Sha256::new();
        let mut tmp_file = File::create(&tmp_path)?;
        let mut reader = reader;
        let mut buf = [0u8; 64 * 1024]; // 64KB buffer

        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
            tmp_file.write_all(&buf[..n])?;
        }
        tmp_file.sync_all()?;

        // 2. Verify digest
        let actual_digest = Sha256Digest(hasher.finalize().into());
        if actual_digest != *expected_digest {
            std::fs::remove_file(&tmp_path)?;
            return Err(CasError::DigestMismatch {
                expected: *expected_digest,
                actual: actual_digest,
            });
        }

        // 3. Atomic move to final location
        let final_path = self.object_path(expected_digest);
        if let Some(parent) = final_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Atomic rename (same filesystem)
        std::fs::rename(&tmp_path, &final_path)?;

        // 4. Update index
        self.index.insert(*expected_digest)?;

        Ok(())
    }

    /// Delete object (GC use only)
    fn delete(&self, digest: &Sha256Digest) -> Result<(), CasError> {
        let path = self.object_path(digest);
        std::fs::remove_file(&path)?;
        self.index.remove(digest)?;
        Ok(())
    }

    fn object_path(&self, digest: &Sha256Digest) -> PathBuf {
        let hex = digest.to_hex();
        self.root
            .join("objects")
            .join("sha256")
            .join(&hex[..2])
            .join(&hex)
    }
}
```

## 21.4 GC Algorithm

```rust
/// Mark-and-sweep garbage collection
pub struct CasGc {
    store: Arc<ContentAddressedStore>,
}

impl CasGc {
    pub fn collect(&self, roots: &[Sha256Digest]) -> Result<GcReport, CasError> {
        // 1. Mark phase: walk all roots and their transitive references
        let mut live = HashSet::new();
        let mut queue: VecDeque<Sha256Digest> = roots.iter().cloned().collect();

        while let Some(digest) = queue.pop_front() {
            if !live.insert(digest) {
                continue; // Already marked
            }
            // If this is an install tree manifest, extract referenced digests
            if let Ok(tree) = self.store.read_install_tree(&digest) {
                for entry in &tree.entries {
                    queue.push_back(entry.digest);
                }
            }
        }

        // 2. Sweep phase: delete objects not in live set
        let mut deleted = 0u64;
        let mut freed_bytes = 0u64;
        for digest in self.store.index.iter() {
            if !live.contains(&digest) {
                let path = self.store.object_path(&digest);
                if let Ok(meta) = std::fs::metadata(&path) {
                    freed_bytes += meta.len();
                }
                self.store.delete(&digest)?;
                deleted += 1;
            }
        }

        Ok(GcReport { deleted, freed_bytes })
    }
}
```

## 21.5 Concurrency

- **Reads**: Lock-free; integrity verified on each read.
- **Writes**: Write to tmp dir first, atomic rename to final path. Two concurrent writes of the same digest both succeed (idempotent).
- **Index**: Memory-mapped with file advisory locks for writes.
- **GC**: Requires exclusive lock; runs as a separate command (`rusk gc`).

## 21.6 Corruption Handling

```rust
fn handle_corruption(&self, digest: &Sha256Digest, path: &Path) -> Result<(), CasError> {
    // Log corruption event
    tracing::error!(
        digest = %digest,
        path = %path.display(),
        "CAS corruption detected"
    );

    // Move corrupt file to quarantine
    let quarantine_path = self.root.join("quarantine").join(digest.to_hex());
    std::fs::create_dir_all(quarantine_path.parent().unwrap())?;
    std::fs::rename(path, &quarantine_path)?;

    // Remove from index
    self.index.remove(digest)?;

    Ok(())
}
```

---

# 22. Downloader and Transport Design

## 22.1 Architecture

Inspired by Bun's approach of parallel manifest+tarball fetching and uv's streaming hash verification.

```rust
pub struct DownloadManager {
    client: reqwest::Client,
    semaphore: Arc<Semaphore>,     // Limit concurrent connections
    cas: Arc<ContentAddressedStore>,
    progress: Arc<ProgressTracker>,
}

impl DownloadManager {
    pub fn new(config: TransportConfig) -> Self {
        let client = reqwest::ClientBuilder::new()
            .pool_max_idle_per_host(config.max_idle_per_host)  // Connection reuse
            .tcp_keepalive(Duration::from_secs(30))
            .timeout(config.request_timeout)
            .build()
            .unwrap();

        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_downloads));

        Self { client, semaphore, cas: config.cas, progress: Arc::new(ProgressTracker::new()) }
    }

    /// Download multiple artifacts in parallel
    pub async fn download_batch(
        &self,
        requests: Vec<DownloadRequest>,
    ) -> Result<Vec<DownloadResult>, TransportError> {
        let mut handles = Vec::with_capacity(requests.len());

        for req in requests {
            // Skip if already in CAS
            if self.cas.has(&req.expected_digest) {
                handles.push(tokio::spawn(async move {
                    Ok(DownloadResult::Cached(req.expected_digest))
                }));
                continue;
            }

            let client = self.client.clone();
            let semaphore = self.semaphore.clone();
            let cas = self.cas.clone();
            let progress = self.progress.clone();

            handles.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await?;
                Self::download_one(&client, &cas, &progress, req).await
            }));
        }

        let results = futures::future::join_all(handles).await;
        results.into_iter()
            .map(|r| r.unwrap_or_else(|e| Err(TransportError::TaskJoin(e))))
            .collect()
    }

    async fn download_one(
        client: &reqwest::Client,
        cas: &ContentAddressedStore,
        progress: &ProgressTracker,
        req: DownloadRequest,
    ) -> Result<DownloadResult, TransportError> {
        let mut retries = 0;
        let max_retries = 3;

        loop {
            match Self::try_download(client, cas, progress, &req).await {
                Ok(result) => return Ok(result),
                Err(e) if retries < max_retries && e.is_retriable() => {
                    retries += 1;
                    let delay = Duration::from_millis(100 * 2u64.pow(retries));
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn try_download(
        client: &reqwest::Client,
        cas: &ContentAddressedStore,
        progress: &ProgressTracker,
        req: &DownloadRequest,
    ) -> Result<DownloadResult, TransportError> {
        let response = client.get(req.url.clone())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(TransportError::HttpStatus(response.status()));
        }

        let total_size = response.content_length();
        let tracker = progress.start_download(&req.name, total_size);

        // Stream response body through hasher into CAS
        let stream = response.bytes_stream();
        let reader = StreamReader::new(stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));

        // Wrap reader with progress tracking
        let reader = ProgressReader::new(reader, tracker);

        cas.put_streaming(&req.expected_digest, reader)?;

        Ok(DownloadResult::Downloaded(req.expected_digest))
    }
}

pub struct DownloadRequest {
    pub url: Url,
    pub expected_digest: Sha256Digest,
    pub name: String,
    pub size: Option<u64>,
    pub mirrors: Vec<Url>,         // Alternative URLs for racing
}

pub enum DownloadResult {
    Downloaded(Sha256Digest),
    Cached(Sha256Digest),
}
```

## 22.2 Mirror Racing

```rust
/// Race multiple mirrors, use first successful response
async fn race_mirrors(
    client: &reqwest::Client,
    urls: &[Url],
) -> Result<reqwest::Response, TransportError> {
    let futures: Vec<_> = urls.iter()
        .map(|url| {
            let client = client.clone();
            let url = url.clone();
            async move { client.get(url).send().await }
        })
        .collect();

    // Return first successful response
    let (result, _) = futures::future::select_ok(
        futures.into_iter().map(|f| Box::pin(f))
    ).await?;

    Ok(result)
}
```

## 22.3 Transport Config

```rust
pub struct TransportConfig {
    pub max_concurrent_downloads: usize,  // Default: 50 (inspired by Bun)
    pub max_idle_per_host: usize,         // Default: 10
    pub request_timeout: Duration,         // Default: 30s
    pub connect_timeout: Duration,         // Default: 10s
    pub max_retries: u32,                  // Default: 3
    pub buffer_size: usize,               // Default: 64KB
}
```

## 22.4 Offline Behavior

When CAS contains all required artifacts (all lockfile digests hit):
- No network requests made
- Metadata served from local cache
- Full install from local state
- This is the `rusk install` fast path

---

# 23. Materialization Design (node_modules + site-packages)

## 23.1 Shared Materialization Framework

```rust
pub struct MaterializationPlan {
    pub entries: Vec<MaterializationEntry>,
    pub strategy: LinkStrategy,
    pub install_state_digest: Sha256Digest,
}

pub struct MaterializationEntry {
    pub source_digest: Sha256Digest,   // CAS digest
    pub target_path: PathBuf,           // Relative to project
    pub file_type: FileType,
    pub permissions: u32,
}

pub enum LinkStrategy {
    Hardlink,
    Reflink,        // Copy-on-write (btrfs, APFS)
    Copy,           // Fallback
}

#[async_trait]
pub trait Materializer: Send + Sync {
    /// Plan materialization tree from resolved graph
    fn plan(
        &self,
        graph: &ResolvedGraph,
        project_root: &Path,
    ) -> Result<MaterializationPlan, MaterializeError>;

    /// Execute materialization
    async fn materialize(
        &self,
        plan: &MaterializationPlan,
        cas: &ContentAddressedStore,
        project_root: &Path,
    ) -> Result<(), MaterializeError>;
}
```

## 23.2 Atomic Install Swap-In

```rust
/// Atomically swap new install tree for old
fn atomic_swap(
    project_root: &Path,
    target_dir: &str,      // "node_modules" or ".venv"
    new_tree: &Path,        // Temp dir with new layout
) -> Result<(), MaterializeError> {
    let target = project_root.join(target_dir);
    let backup = project_root.join(format!(".{}.old", target_dir));

    // 1. Rename current to backup
    if target.exists() {
        std::fs::rename(&target, &backup)?;
    }

    // 2. Rename new to target
    match std::fs::rename(new_tree, &target) {
        Ok(()) => {
            // 3. Remove backup
            if backup.exists() {
                std::fs::remove_dir_all(&backup)?;
            }
            Ok(())
        }
        Err(e) => {
            // Rollback: restore backup
            if backup.exists() {
                std::fs::rename(&backup, &target)?;
            }
            Err(MaterializeError::SwapFailed(e))
        }
    }
}
```

## 23.3 JS/TS Materialization (node_modules)

```rust
pub struct JsMaterializer {
    layout_mode: JsLayoutMode,
}

pub enum JsLayoutMode {
    /// Flat node_modules with hoisting (npm-style)
    Hoisted,
    /// Virtual store with symlinks (pnpm-style, default)
    VirtualStore,
    /// Isolated (no hoisting, each package has own node_modules)
    Isolated,
}

impl JsMaterializer {
    /// Plan node_modules layout from resolved graph
    fn plan_virtual_store(
        &self,
        graph: &ResolvedGraph,
        project_root: &Path,
    ) -> Result<MaterializationPlan, MaterializeError> {
        // pnpm-style virtual store layout:
        //
        // node_modules/
        // ├── .rusk/                           # Virtual store
        // │   ├── react@18.2.0/
        // │   │   └── node_modules/
        // │   │       ├── react/               # Hardlinked from CAS
        // │   │       │   ├── index.js
        // │   │       │   └── package.json
        // │   │       └── loose-envify -> ../../loose-envify@1.4.0/node_modules/loose-envify
        // │   └── loose-envify@1.4.0/
        // │       └── node_modules/
        // │           └── loose-envify/        # Hardlinked from CAS
        // ├── react -> .rusk/react@18.2.0/node_modules/react
        // └── .bin/
        //     └── ...

        let mut entries = Vec::new();

        for node in graph.js_nodes() {
            let store_path = format!(
                "node_modules/.rusk/{}@{}/node_modules/{}",
                node.package.name, node.version, node.package.name
            );

            // Extract tarball files and create entries
            let tarball_data = graph.artifact_data(&node.artifact)?;
            let files = extract_npm_tarball(&tarball_data)?;

            for file in files {
                entries.push(MaterializationEntry {
                    source_digest: file.digest,
                    target_path: PathBuf::from(&store_path).join(&file.relative_path),
                    file_type: file.file_type,
                    permissions: file.permissions,
                });
            }

            // Create symlinks for dependencies
            for dep in &node.dependencies {
                // Symlink: store_path/node_modules/<dep_name> -> ../../<dep>@<ver>/node_modules/<dep_name>
            }
        }

        // Create top-level symlinks for direct dependencies
        for direct_dep in graph.direct_js_deps() {
            // Symlink: node_modules/<name> -> .rusk/<name>@<ver>/node_modules/<name>
        }

        // Create .bin shims
        for node in graph.js_nodes() {
            if let Some(bins) = &node.bin {
                for (bin_name, bin_path) in bins {
                    // Create shim script in node_modules/.bin/
                }
            }
        }

        Ok(MaterializationPlan {
            entries,
            strategy: detect_link_strategy(project_root),
            install_state_digest: compute_plan_digest(&entries),
        })
    }
}
```

## 23.4 Python Materialization (site-packages)

```rust
pub struct PythonMaterializer {
    python_path: PathBuf,
}

impl PythonMaterializer {
    fn plan_site_packages(
        &self,
        graph: &ResolvedGraph,
        project_root: &Path,
    ) -> Result<MaterializationPlan, MaterializeError> {
        // Layout:
        // .venv/
        // ├── bin/ (or Scripts/ on Windows)
        // │   ├── python -> /usr/bin/python3.11
        // │   ├── pip (if needed)
        // │   └── entry-point-scripts...
        // ├── lib/
        // │   └── python3.11/
        // │       └── site-packages/
        // │           ├── requests/           # Hardlinked from CAS
        // │           │   ├── __init__.py
        // │           │   └── ...
        // │           ├── requests-2.31.0.dist-info/
        // │           │   ├── METADATA
        // │           │   ├── RECORD
        // │           │   ├── INSTALLER
        // │           │   └── entry_points.txt
        // │           └── ...

        let mut entries = Vec::new();

        for node in graph.python_nodes() {
            let wheel_data = graph.artifact_data(&node.artifact)?;
            let wheel_files = unpack_wheel(&wheel_data)?;

            let site_packages = format!(
                ".venv/lib/python{}/site-packages",
                self.python_version_short()
            );

            for file in wheel_files {
                entries.push(MaterializationEntry {
                    source_digest: file.digest,
                    target_path: PathBuf::from(&site_packages).join(&file.relative_path),
                    file_type: file.file_type,
                    permissions: file.permissions,
                });
            }

            // Generate dist-info
            let dist_info = generate_dist_info(node)?;
            for file in dist_info {
                entries.push(file);
            }

            // Generate entry point scripts
            if let Some(console_scripts) = &node.entry_points {
                for (name, target) in console_scripts {
                    let script = generate_python_script(name, target, &self.python_path);
                    entries.push(MaterializationEntry {
                        source_digest: Sha256Digest::compute(script.as_bytes()),
                        target_path: PathBuf::from(".venv/bin").join(name),
                        file_type: FileType::File,
                        permissions: 0o755,
                    });
                }
            }
        }

        Ok(MaterializationPlan {
            entries,
            strategy: detect_link_strategy(project_root),
            install_state_digest: compute_plan_digest(&entries),
        })
    }
}
```

## 23.5 Install State File

After materialization, write a state file:

```rust
pub struct InstallState {
    pub installed_at: DateTime<Utc>,
    pub lockfile_digest: Sha256Digest,
    pub plan_digest: Sha256Digest,
    pub packages: Vec<InstalledPackage>,
}

// Written to: .rusk/install-state.json
```

Fast-path: if lockfile hasn't changed and install state matches, skip materialization entirely.

---

# 24. Build Sandbox Design

## 24.1 Sandbox Trait

```rust
#[async_trait]
pub trait Sandbox: Send + Sync {
    /// Execute a build in isolation
    async fn build(
        &self,
        config: SandboxConfig,
    ) -> Result<SandboxOutput, SandboxError>;
}

pub struct SandboxConfig {
    pub source_dir: PathBuf,
    pub build_command: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub capabilities: SandboxCapabilities,
    pub toolchain: ToolchainSpec,
    pub build_deps: Vec<ArtifactId>,
    pub timeout: Duration,
}

pub struct SandboxCapabilities {
    pub network: bool,          // Default: false
    pub host_secrets: bool,     // Default: false
    pub filesystem_read: Vec<PathBuf>,
    pub filesystem_write: Vec<PathBuf>,
}

pub struct SandboxOutput {
    pub artifacts: Vec<BuildArtifact>,
    pub logs: String,
    pub provenance: LocalProvenance,
    pub exit_code: i32,
}

pub struct BuildArtifact {
    pub path: PathBuf,
    pub digest: Sha256Digest,
    pub size: u64,
}
```

## 24.2 Implementation Approaches

```rust
pub enum SandboxBackend {
    /// Linux namespaces (bubblewrap-style)
    LinuxNamespace(LinuxNamespaceSandbox),
    /// Container (podman/docker)
    Container(ContainerSandbox),
    /// Process-level isolation (Windows/macOS)
    Process(ProcessSandbox),
}

pub struct LinuxNamespaceSandbox {
    // Uses unshare() syscalls to create isolated:
    // - mount namespace (tmpfs overlay)
    // - network namespace (disabled by default)
    // - PID namespace
    // - user namespace
}

pub struct ContainerSandbox {
    runtime: ContainerRuntime,  // podman or docker
    image: String,
}

pub struct ProcessSandbox {
    // Minimal isolation via:
    // - Separate user account
    // - Restricted PATH
    // - Temp directory isolation
    // - Environment scrubbing
    // Less secure than namespace/container, used as fallback
}
```

## 24.3 Local Provenance Generation

```rust
pub struct LocalProvenance {
    pub subjects: Vec<ProvenanceSubject>,
    pub builder: BuilderIdentity,
    pub source: LocalSource,
    pub build_config: LocalBuildConfig,
    pub trust_class: TrustClass,    // Always LocalDev for local builds
}

pub struct LocalSource {
    pub directory: PathBuf,
    pub git_commit: Option<String>,
    pub git_dirty: bool,
}

impl LocalProvenance {
    pub fn generate(
        config: &SandboxConfig,
        output: &SandboxOutput,
    ) -> Self {
        LocalProvenance {
            subjects: output.artifacts.iter().map(|a| ProvenanceSubject {
                name: a.path.file_name().unwrap().to_string_lossy().to_string(),
                digest: a.digest,
            }).collect(),
            builder: BuilderIdentity {
                builder_type: "local".to_string(),
                builder_id: hostname(),
            },
            source: LocalSource {
                directory: config.source_dir.clone(),
                git_commit: detect_git_commit(&config.source_dir),
                git_dirty: detect_git_dirty(&config.source_dir),
            },
            build_config: LocalBuildConfig {
                command: config.build_command.clone(),
                sandbox_type: "local_dev".to_string(),
            },
            trust_class: TrustClass::LocalDev,
        }
    }
}
```

## 24.4 Trust Tier Labeling

```rust
pub enum TrustClass {
    /// Published via trusted CI pipeline with provenance
    TrustedRelease,
    /// Built locally for development
    LocalDev,
    /// Under quarantine period
    Quarantined,
    /// No verification performed
    Unverified,
}
```

**Promotion pipeline**: To promote a `LocalDev` artifact to `TrustedRelease`:
1. Push source to repository
2. CI builds using trusted builder
3. Trusted builder produces provenance attestation
4. Artifact published to registry with provenance
5. Transparency log records the event
6. Policy now recognizes it as `TrustedRelease`

---

# 25. Install/Update/Verify/Audit Flows

## 25.1 Install Flow (Detailed)

```rust
pub async fn install(
    manifest_path: &Path,
    lockfile_path: &Path,
    config: &InstallConfig,
) -> Result<InstallReport, InstallError> {
    let span = tracing::info_span!("install");
    let _guard = span.enter();

    // === Phase 1: Parse ===
    tracing::info!("Parsing manifest");
    let manifest = parse_manifest(manifest_path)?;

    let lockfile = if lockfile_path.exists() {
        tracing::info!("Parsing lockfile");
        let lf = parse_lockfile(lockfile_path)?;

        // Validate lockfile integrity
        verify_lockfile_integrity(&lf)?;

        Some(lf)
    } else {
        None
    };

    // === Phase 2: Check install state (fast path) ===
    if let Some(ref lf) = lockfile {
        if let Ok(state) = read_install_state(&config.project_root) {
            if state.lockfile_digest == lf.integrity {
                // Check all CAS artifacts present
                let all_cached = lf.packages.iter()
                    .all(|p| config.cas.has(&p.digest));
                if all_cached {
                    tracing::info!("Install state matches lockfile, skipping");
                    return Ok(InstallReport::UpToDate);
                }
            }
        }
    }

    // === Phase 3: Update trust state ===
    tracing::info!("Updating TUF metadata");
    if !config.offline {
        for (name, registry_config) in &manifest.trust.registries {
            config.tuf_verifier.update(&registry_config.client()).await?;
        }
    }

    tracing::info!("Updating revocation state");
    if !config.offline {
        config.revocation_checker.update(&manifest.trust.registries).await?;
    }

    // === Phase 4: Resolve (if no lockfile or lockfile stale) ===
    let resolved = if let Some(ref lf) = lockfile {
        // Verify lockfile matches manifest
        if lockfile_matches_manifest(lf, &manifest) {
            graph_from_lockfile(lf)?
        } else {
            tracing::info!("Lockfile stale, re-resolving");
            resolve_fresh(&manifest, &config).await?
        }
    } else {
        tracing::info!("No lockfile, resolving from scratch");
        resolve_fresh(&manifest, &config).await?
    };

    // === Phase 5: Fetch missing artifacts ===
    let missing: Vec<DownloadRequest> = resolved.nodes()
        .filter(|n| !config.cas.has(&n.digest))
        .map(|n| DownloadRequest {
            url: n.download_url.clone(),
            expected_digest: n.digest,
            name: format!("{}@{}", n.package.name, n.version),
            size: Some(n.size),
            mirrors: n.mirrors.clone(),
        })
        .collect();

    if !missing.is_empty() {
        tracing::info!(count = missing.len(), "Fetching missing artifacts");
        config.downloader.download_batch(missing).await?;
    }

    // === Phase 6: Verify each artifact ===
    tracing::info!("Verifying artifacts");
    let mut trust_states = Vec::new();
    for node in resolved.nodes() {
        let trust_state = verify_artifact(
            &node,
            &config.signing_verifier,
            &config.provenance_verifier,
            &config.transparency_verifier,
            &config.revocation_checker,
            &config.policy_evaluator,
            &config.install_mode,
        ).await?;

        // Check policy verdict
        match &trust_state.policy_verdict {
            PolicyVerdict::Deny { reason, .. } => {
                return Err(InstallError::PolicyDenied {
                    package: node.package.clone(),
                    version: node.version.clone(),
                    reason: reason.clone(),
                });
            }
            PolicyVerdict::RequireApproval { reason } => {
                if !config.interactive {
                    return Err(InstallError::ApprovalRequired {
                        package: node.package.clone(),
                        reason: reason.clone(),
                    });
                }
                // Interactive: prompt user
                if !prompt_approval(&node, reason)? {
                    return Err(InstallError::UserDenied(node.package.clone()));
                }
            }
            PolicyVerdict::Quarantine { reason, duration } => {
                tracing::warn!(
                    package = %node.package.name,
                    reason = %reason,
                    "Package quarantined"
                );
            }
            _ => {}
        }

        trust_states.push(trust_state);
    }

    // === Phase 7: Write lockfile (if newly resolved) ===
    if lockfile.is_none() || !lockfile_matches_manifest(lockfile.as_ref().unwrap(), &manifest) {
        tracing::info!("Writing lockfile");
        let new_lockfile = write_lockfile(&resolved)?;
        write_lockfile_to_disk(&new_lockfile, lockfile_path)?;
    }

    // === Phase 8: Materialize ===
    tracing::info!("Materializing install tree");
    let plan = if manifest.ecosystems.js {
        let js_plan = config.js_materializer.plan(&resolved, &config.project_root)?;
        config.js_materializer.materialize(&js_plan, &config.cas, &config.project_root).await?;
    };
    if manifest.ecosystems.python {
        let py_plan = config.python_materializer.plan(&resolved, &config.project_root)?;
        config.python_materializer.materialize(&py_plan, &config.cas, &config.project_root).await?;
    }

    // === Phase 9: Write install state ===
    write_install_state(&config.project_root, &resolved, &trust_states)?;

    tracing::info!("Install complete");
    Ok(InstallReport::Installed {
        packages: resolved.node_count(),
        cached: resolved.cached_count(),
        downloaded: resolved.downloaded_count(),
    })
}
```

## 25.2 Verify Flow

```rust
pub async fn verify(
    lockfile_path: &Path,
    config: &VerifyConfig,
) -> Result<VerifyReport, VerifyError> {
    let lockfile = parse_lockfile(lockfile_path)?;
    verify_lockfile_integrity(&lockfile)?;

    // Refresh revocation
    if !config.offline {
        config.revocation_checker.update_all().await?;
    }

    let mut findings = Vec::new();

    for pkg in &lockfile.packages {
        // 1. Verify CAS artifact exists and matches digest
        if !config.cas.has(&pkg.digest) {
            findings.push(Finding::MissingArtifact(pkg.name.clone()));
            continue;
        }

        let data = config.cas.get(&pkg.digest)?;
        let actual = Sha256Digest::compute(&data);
        if actual != pkg.digest {
            findings.push(Finding::DigestMismatch {
                package: pkg.name.clone(),
                expected: pkg.digest,
                actual,
            });
            continue;
        }

        // 2. Re-verify signature
        // 3. Re-verify provenance
        // 4. Check transparency freshness
        // 5. Check revocation
        // 6. Re-evaluate policy
        let trust_state = reverify_artifact(pkg, config).await?;

        if let PolicyVerdict::Deny { reason, .. } = &trust_state.policy_verdict {
            findings.push(Finding::PolicyDenied {
                package: pkg.name.clone(),
                reason: reason.clone(),
            });
        }

        if matches!(trust_state.revocation, RevocationState::Revoked { .. }) {
            findings.push(Finding::Revoked {
                package: pkg.name.clone(),
            });
        }
    }

    // 7. Verify materialized files (spot check or full)
    if config.verify_materialized {
        let materialized_findings = verify_materialized_files(&config.project_root, &lockfile)?;
        findings.extend(materialized_findings);
    }

    Ok(VerifyReport { findings })
}
```

---

# 26. Enterprise and Internal Registry Mode

## 26.1 Architecture

```rust
pub struct EnterpriseConfig {
    /// Internal registries
    pub internal_registries: Vec<InternalRegistryConfig>,
    /// Organization policy layers (applied on top of project policy)
    pub org_policies: Vec<PolicyLayer>,
    /// Central revocation feed URL
    pub revocation_feed: Option<Url>,
    /// Internal trust roots
    pub internal_trust_roots: Vec<TrustRoot>,
    /// Air-gap mode
    pub airgap: bool,
    /// Package allowlist/denylist
    pub package_controls: PackageControls,
}

pub struct InternalRegistryConfig {
    pub name: String,
    pub url: RegistryUrl,
    pub tuf_root: PathBuf,
    pub namespaces: Vec<String>,       // Namespaces owned by this registry
    pub priority: u32,                  // Higher = checked first
}

pub struct PackageControls {
    pub allowlist: Option<HashSet<PackageId>>,
    pub denylist: HashSet<PackageId>,
    pub source_restrictions: BTreeMap<PackageId, Vec<RegistryUrl>>,
}
```

## 26.2 Internal Package Leakage Prevention

```rust
/// Ensure internal packages are never resolved from public registries
fn validate_no_internal_leakage(
    resolved: &ResolvedGraph,
    internal_namespaces: &[String],
    internal_registries: &[RegistryUrl],
) -> Result<(), EnterpriseError> {
    for node in resolved.nodes() {
        let is_internal_name = internal_namespaces.iter()
            .any(|ns| node.package.name.starts_with(ns));

        if is_internal_name && !internal_registries.contains(&node.package.registry) {
            return Err(EnterpriseError::InternalPackageLeakage {
                package: node.package.clone(),
                resolved_from: node.package.registry.clone(),
            });
        }
    }
    Ok(())
}
```

## 26.3 Air-Gap Sync Bundle

```rust
pub struct AirGapBundle {
    pub metadata: BundleMetadata,
    pub artifacts: Vec<(Sha256Digest, Vec<u8>)>,
    pub tuf_metadata: Vec<SignedMetadata>,
    pub revocation_bundles: Vec<RevocationBundle>,
    pub policy_bundles: Vec<PolicyFile>,
    pub signature: Vec<u8>,
}

pub async fn create_airgap_bundle(
    lockfile: &Lockfile,
    config: &AirGapConfig,
) -> Result<AirGapBundle, EnterpriseError> {
    let mut artifacts = Vec::new();

    for pkg in &lockfile.packages {
        let data = config.cas.get(&pkg.digest)?;
        artifacts.push((pkg.digest, data));
    }

    // Include all TUF metadata
    let tuf_metadata = collect_tuf_metadata(config)?;

    // Include revocation bundles
    let revocation = collect_revocation_bundles(config)?;

    Ok(AirGapBundle {
        metadata: BundleMetadata {
            created_at: Utc::now(),
            lockfile_digest: lockfile.integrity,
        },
        artifacts,
        tuf_metadata,
        revocation_bundles: revocation,
        policy_bundles: vec![],
        signature: sign_bundle(&config.signer)?,
    })
}
```

## 26.4 Policy Layering

Enterprise policies layer on top of project policies:
1. **Base**: Built-in defaults (allow signed public packages)
2. **Project**: Project's `.rusk/policy.ruskpol`
3. **Organization**: Org-level policy (fetched from central config)
4. **Emergency**: Central revocation/deny feeds

Higher layers can only add restrictions (deny rules), not relax lower-layer denials.

---

# 27. Performance Engineering Plan

## 27.1 Hot Paths

1. **Lockfile-present, all-cached install**: Parse lockfile → verify install state → skip. Target: <50ms.
2. **Lockfile-present, all artifacts in CAS**: Parse → verify → materialize via hardlinks. Target: <200ms for 500 packages.
3. **Signature verification**: Cached after first verification (keyed by artifact digest + sig digest + revocation epoch).
4. **Policy evaluation**: Cached after first evaluation (keyed by policy digest + artifact digest + revocation epoch).

## 27.2 Cold Paths

1. **Initial resolve**: Registry metadata fetch + solver. Minimize with parallel metadata fetch, PEP 658 for Python (metadata without downloading whole artifact).
2. **First download**: Parallel fetch with 50 concurrent connections, streaming verification.
3. **Provenance verification**: Certificate chain validation + transparency proof. Cache results.

## 27.3 Specific Optimizations

- **Memory-mapped CAS index**: Use `memmap2` for fast CAS lookups without syscall overhead
- **Parallel metadata fetch**: Fetch all package metadata concurrently (inspired by Bun)
- **Connection reuse**: HTTP/2 multiplexing, keep-alive pools
- **Hardlink materialization**: Near-instant file creation (no data copy)
- **Lockfile binary format**: Optional binary format for sub-millisecond parsing (inspired by Bun's bun.lockb)
- **Zero-copy deserialization**: Use `rkyv` or `zerocopy` for hot-path data structures
- **Graph memoization**: Cache dependency graph computations
- **Streaming hash**: Hash while downloading, single pass (no re-read)
- **Batch signature verification**: Batch Ed25519 verify when possible (coffin/ed25519-dalek batch API)
- **Install state fast-path**: Compare lockfile digest with last install; skip everything if unchanged

## 27.4 Benchmark Plan

```rust
// benches/install.rs
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_lockfile_parse(c: &mut Criterion) {
    // Parse a 1000-package lockfile
}

fn bench_cas_lookup(c: &mut Criterion) {
    // Look up 1000 digests in CAS
}

fn bench_policy_evaluate(c: &mut Criterion) {
    // Evaluate policy for 1000 packages
}

fn bench_signature_verify(c: &mut Criterion) {
    // Verify 100 Ed25519 signatures
}

fn bench_materialize_hardlink(c: &mut Criterion) {
    // Materialize 500-package node_modules via hardlinks
}

fn bench_full_install_warm_cache(c: &mut Criterion) {
    // Full install with all artifacts cached
}
```

**Targets**:
- Lockfile parse (1000 packages): <5ms
- CAS lookup (1000 digests): <1ms
- Policy evaluation (1000 packages, cached): <1ms
- Warm-cache install (500 packages): <100ms
- Cold install (500 packages, parallel fetch): competitive with Bun/uv

---

# 28. Caching Strategy

## 28.1 Cache Inventory

| Cache | Key | Value | Invalidation | Persistence |
|-------|-----|-------|--------------|-------------|
| Metadata cache | (registry, package, etag) | PackageMetadata | ETag / TUF freshness | Disk |
| Signature cache | (artifact_digest, sig_digest) | VerifiedSignature | Revocation epoch | Memory (DashMap) |
| Provenance cache | attestation_digest | VerifiedProvenance | Revocation epoch | CAS |
| Policy verdict cache | (policy_digest, artifact_digest, epoch) | PolicyVerdict | Policy change / revocation epoch | Memory (DashMap) |
| Transparency checkpoint | log_id | TransparencyCheckpoint | Newer checkpoint | Disk |
| TUF metadata | (registry, role) | SignedMetadata | TUF update | Disk |
| Revocation state | registry | RevocationState | Bundle update | Disk |
| CAS index | digest | existence flag | GC | Memory-mapped file |
| HTTP response cache | (url, etag) | Response bytes | ETag / expiry | Disk |
| Parsed wheel metadata | (filename, digest) | PythonMetadata | Never (content-addressed) | Disk |

## 28.2 Cache Concurrency

```rust
// All in-memory caches use DashMap for lock-free concurrent access
use dashmap::DashMap;

pub struct SignatureCache {
    cache: DashMap<(Sha256Digest, Sha256Digest), CachedVerification>,
    epoch: AtomicU64,
}

impl SignatureCache {
    pub fn get(&self, artifact: &Sha256Digest, sig: &Sha256Digest) -> Option<VerifiedSignature> {
        let current_epoch = self.epoch.load(Ordering::Acquire);
        self.cache.get(&(*artifact, *sig))
            .filter(|entry| entry.revocation_epoch == current_epoch)
            .map(|entry| entry.result.clone())
    }

    pub fn invalidate_epoch(&self, new_epoch: u64) {
        self.epoch.store(new_epoch, Ordering::Release);
        // Old entries with wrong epoch will be filtered on read
        // Actual cleanup happens lazily or on periodic sweep
    }
}
```

---

# 29. Error Handling Strategy

## 29.1 Error Hierarchy

```rust
/// Top-level error type
#[derive(thiserror::Error, Debug)]
pub enum RuskError {
    #[error("Manifest error: {0}")]
    Manifest(#[from] ManifestError),

    #[error("Lockfile error: {0}")]
    Lockfile(#[from] LockfileError),

    #[error("Resolution error: {0}")]
    Resolver(#[from] ResolverError),

    #[error("Trust error: {0}")]
    Trust(#[from] TrustError),

    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("CAS error: {0}")]
    Cas(#[from] CasError),

    #[error("Materialization error: {0}")]
    Materialize(#[from] MaterializeError),

    #[error("Sandbox error: {0}")]
    Sandbox(#[from] SandboxError),

    #[error("Enterprise error: {0}")]
    Enterprise(#[from] EnterpriseError),
}

/// Trust-specific errors
#[derive(thiserror::Error, Debug)]
pub enum TrustError {
    #[error("TUF verification failed: {0}")]
    Tuf(#[from] TufError),

    #[error("Signature verification failed: {0}")]
    Signature(#[from] SignatureError),

    #[error("Provenance verification failed: {0}")]
    Provenance(#[from] ProvenanceError),

    #[error("Transparency verification failed: {0}")]
    Transparency(#[from] TransparencyError),

    #[error("Policy denied: {reason}")]
    PolicyDenied {
        package: PackageId,
        version: Version,
        reason: String,
        matched_rules: Vec<String>,
    },

    #[error("Revoked: {0}")]
    Revocation(#[from] RevocationError),

    #[error("Digest mismatch for {package}: expected {expected}, got {actual}")]
    DigestMismatch {
        package: PackageId,
        expected: Sha256Digest,
        actual: Sha256Digest,
    },

    #[error("Lockfile integrity check failed")]
    LockfileIntegrity,
}

#[derive(thiserror::Error, Debug)]
pub enum TufError {
    #[error("Rollback attack detected: {role} version {received} < {previous}")]
    RollbackAttack { role: String, previous: u64, received: u64 },

    #[error("Expired {role} metadata")]
    Expired { role: String },

    #[error("Insufficient signatures: need {required}, have {found}")]
    InsufficientSignatures { required: u32, found: u32 },

    #[error("Missing role: {0}")]
    MissingRole(String),

    #[error("Non-sequential root version")]
    NonSequentialRoot,
}

#[derive(thiserror::Error, Debug)]
pub enum ResolverError {
    #[error("No viable candidates for {0}")]
    NoViableCandidates(PackageId),

    #[error("Version conflict: {0}")]
    VersionConflict(String),

    #[error("Dependency cycle detected: {0:?}")]
    CyclicDependency(Vec<PackageId>),

    #[error("Registry error: {0}")]
    Registry(#[from] RegistryError),

    #[error("Trust filter rejected all candidates for {0}")]
    AllCandidatesRejected(PackageId),
}
```

## 29.2 User-Facing Error Mapping

```rust
impl RuskError {
    pub fn to_diagnostic(&self) -> Diagnostic {
        match self {
            RuskError::Trust(TrustError::PolicyDenied { package, reason, matched_rules, .. }) => {
                Diagnostic {
                    severity: Severity::Error,
                    code: "POLICY_DENIED",
                    message: format!("Package {} denied by policy", package.name),
                    detail: reason.clone(),
                    hints: vec![
                        format!("Matched rules: {}", matched_rules.join(", ")),
                        "Run `rusk explain deny` for details".to_string(),
                        "Add a trust override in rusk.toml if appropriate".to_string(),
                    ],
                    machine_readable: serde_json::json!({
                        "error_code": "POLICY_DENIED",
                        "package": package.canonical(),
                        "reason": reason,
                        "rules": matched_rules,
                    }),
                }
            }
            RuskError::Trust(TrustError::DigestMismatch { package, expected, actual }) => {
                Diagnostic {
                    severity: Severity::Error,
                    code: "DIGEST_MISMATCH",
                    message: format!(
                        "Artifact integrity check failed for {}",
                        package.name
                    ),
                    detail: format!(
                        "Expected: {}\nActual: {}",
                        expected.to_hex(),
                        actual.to_hex()
                    ),
                    hints: vec![
                        "This could indicate tampering. Do NOT proceed.".to_string(),
                        "Run `rusk verify` and report this to the package maintainers.".to_string(),
                    ],
                    machine_readable: serde_json::json!({
                        "error_code": "DIGEST_MISMATCH",
                        "package": package.canonical(),
                        "expected_digest": expected.to_hex(),
                        "actual_digest": actual.to_hex(),
                    }),
                }
            }
            // ... more mappings
            _ => self.default_diagnostic(),
        }
    }
}
```

---

# 30. Observability and Telemetry

## 30.1 Tracing

Use `tracing` crate with structured spans:

```rust
// Span hierarchy:
// install
//   ├── parse_manifest
//   ├── parse_lockfile
//   ├── tuf_update
//   │   ├── fetch_timestamp
//   │   ├── verify_timestamp
//   │   ├── fetch_snapshot
//   │   └── verify_snapshot
//   ├── resolve
//   │   ├── fetch_metadata[package=react]
//   │   ├── fetch_metadata[package=express]
//   │   └── solve
//   ├── download
//   │   ├── fetch[package=react@18.2.0, size=123456]
//   │   └── fetch[package=express@4.18.0, size=234567]
//   ├── verify
//   │   ├── verify_signature[package=react@18.2.0]
//   │   ├── verify_provenance[package=react@18.2.0]
//   │   └── evaluate_policy[package=react@18.2.0]
//   └── materialize
//       ├── plan
//       └── execute
```

## 30.2 Metrics

```rust
pub struct RuskMetrics {
    pub packages_resolved: Counter,
    pub packages_downloaded: Counter,
    pub packages_cached: Counter,
    pub bytes_downloaded: Counter,
    pub signatures_verified: Counter,
    pub signature_cache_hits: Counter,
    pub policy_evaluations: Counter,
    pub policy_cache_hits: Counter,
    pub cas_reads: Counter,
    pub cas_writes: Counter,
    pub cas_corruption_detected: Counter,
    pub tuf_updates: Counter,
    pub revocation_checks: Counter,
    pub resolve_duration: Histogram,
    pub download_duration: Histogram,
    pub verify_duration: Histogram,
    pub materialize_duration: Histogram,
    pub total_install_duration: Histogram,
}
```

## 30.3 CLI Explain Modes

```
$ rusk explain deny react@18.2.0
Package: react@18.2.0
Verdict: DENIED
Reason: Critical package requires verified provenance

Matched rules:
  1. [P200] require_provenance_for_critical
     Condition: package.name in ["react", "express"] && !provenance.verified
     Result: provenance.verified = false
     Action: deny

Trust state:
  Digest: sha256:abcdef... ✓ verified
  Signature: ✓ verified (react-team@meta.com)
  Provenance: ✗ missing
  Transparency: ✓ verified (rekor:12345678)
  Revocation: ✓ clear

Suggestion: The package has a valid signature but no provenance attestation.
Contact the package maintainers to request provenance support.
```

## 30.4 Audit Report

```
$ rusk audit --format json
{
  "audit_time": "2026-03-31T12:00:00Z",
  "lockfile_integrity": "sha256:a1b2c3...",
  "revocation_epoch": 42,
  "packages": [
    {
      "name": "react",
      "version": "18.2.0",
      "ecosystem": "js",
      "trust_class": "trusted_release",
      "signature": { "verified": true, "signer": "react-team@meta.com" },
      "provenance": { "verified": false },
      "transparency": { "verified": true, "checkpoint": "rekor:12345678" },
      "revocation": "clear",
      "policy_verdict": "allow",
      "risk_flags": []
    }
  ],
  "summary": {
    "total_packages": 127,
    "signed": 120,
    "with_provenance": 45,
    "quarantined": 2,
    "warnings": 5,
    "risk_flags": 12
  }
}
```

---

# 31. Testing Strategy

## 31.1 Unit Tests

Each crate has inline unit tests for core logic:

- **rusk-core**: Digest computation, version parsing, ID normalization
- **rusk-manifest**: TOML parsing, validation rules, normalization
- **rusk-lockfile**: Serialization round-trips, integrity computation, partial updates
- **rusk-cas**: Put/get/has, corruption detection, concurrent writes
- **rusk-tuf**: Signature verification, rollback detection, expiration checks
- **rusk-signing**: Ed25519/ECDSA verification, certificate chain validation
- **rusk-transparency**: Merkle inclusion proof verification
- **rusk-provenance**: Attestation parsing, normalization, subject binding
- **rusk-policy**: Parser, compiler, evaluator, precedence rules, built-in predicates
- **rusk-revocation**: Bundle parsing, epoch management, state updates
- **rusk-resolver**: PubGrub unit propagation, conflict resolution, trust filtering

## 31.2 Integration Tests

```rust
// tests/e2e/install.rs

#[tokio::test]
async fn test_install_from_lockfile_warm_cache() {
    let fixture = TestFixture::new()
        .with_manifest("fixtures/simple-js/rusk.toml")
        .with_lockfile("fixtures/simple-js/rusk.lock")
        .with_cas_populated("fixtures/simple-js/cas/")
        .build();

    let result = rusk_orchestrator::install(&fixture.config()).await.unwrap();
    assert!(matches!(result, InstallReport::Installed { .. }));
    assert!(fixture.project_root().join("node_modules/react").exists());
}

#[tokio::test]
async fn test_install_detects_tampering() {
    let fixture = TestFixture::new()
        .with_manifest("fixtures/simple-js/rusk.toml")
        .with_lockfile("fixtures/simple-js/rusk.lock")
        .with_tampered_artifact("react", "fixtures/tampered-react.tgz")
        .build();

    let result = rusk_orchestrator::install(&fixture.config()).await;
    assert!(matches!(result, Err(InstallError::Trust(TrustError::DigestMismatch { .. }))));
}

#[tokio::test]
async fn test_revocation_blocks_install() {
    let fixture = TestFixture::new()
        .with_revoked_signer("malicious@evil.com")
        .build();

    let result = rusk_orchestrator::install(&fixture.config()).await;
    assert!(matches!(result, Err(InstallError::Trust(TrustError::Revocation(_)))));
}
```

## 31.3 Property Tests

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn lockfile_roundtrip(packages in prop::collection::vec(arb_locked_package(), 1..100)) {
        let lockfile = Lockfile {
            version: 1,
            integrity: compute_integrity_root(&packages),
            packages,
        };
        let serialized = serialize_lockfile(&lockfile).unwrap();
        let deserialized = parse_lockfile_str(&serialized).unwrap();
        assert_eq!(lockfile, deserialized);
    }

    #[test]
    fn cas_put_get_roundtrip(data in prop::collection::vec(any::<u8>(), 1..10000)) {
        let store = TempCasStore::new();
        let digest = Sha256Digest::compute(&data);
        store.put_streaming(&digest, &data[..]).unwrap();
        let retrieved = store.get(&digest).unwrap();
        assert_eq!(data, retrieved);
    }

    #[test]
    fn policy_deny_overrides_allow(
        allow_priority in 1..1000i32,
        deny_priority in 1..1000i32,
    ) {
        // Deny ALWAYS overrides allow regardless of priority
        let policy = CompiledPolicy {
            rules: vec![
                CompiledRule {
                    name: "allow_all".to_string(),
                    priority: allow_priority,
                    condition: CompiledExpr::Const(true),
                    action: Action::Allow,
                    reason: None,
                },
                CompiledRule {
                    name: "deny_all".to_string(),
                    priority: deny_priority,
                    condition: CompiledExpr::Const(true),
                    action: Action::Deny,
                    reason: Some("denied".to_string()),
                },
            ],
            default_action: Action::Allow,
            digest: Sha256Digest::zero(),
        };
        let evaluator = PolicyEvaluator::new(policy);
        let verdict = evaluator.evaluate(&test_context(), 0);
        assert!(matches!(verdict, PolicyVerdict::Deny { .. }));
    }
}
```

## 31.4 Fixture Strategy

```
tests/fixtures/
├── manifests/
│   ├── simple-js.toml
│   ├── simple-python.toml
│   ├── mixed-ecosystem.toml
│   ├── workspace.toml
│   └── enterprise.toml
├── lockfiles/
│   ├── simple-js.lock
│   ├── simple-python.lock
│   └── mixed.lock
├── registry/
│   ├── npm/                   # Mock npm registry responses
│   │   ├── react.json
│   │   └── express.json
│   └── pypi/                  # Mock PyPI responses
│       ├── requests.json
│       └── fastapi.json
├── tuf/
│   ├── root.json
│   ├── timestamp.json
│   └── snapshot.json
├── signatures/
│   ├── valid/
│   └── invalid/
├── provenance/
│   ├── valid-slsa-v1.json
│   ├── invalid-subject.json
│   └── expired-cert.json
├── policies/
│   ├── default-strict.ruskpol
│   ├── allow-all.ruskpol
│   └── deny-unsigned.ruskpol
├── revocation/
│   ├── empty-bundle.json
│   ├── revoked-signer.json
│   └── yanked-version.json
├── cas/
│   └── objects/              # Pre-populated CAS for tests
└── golden/
    ├── lockfile-output.lock  # Golden file for lockfile format
    └── audit-output.json     # Golden file for audit output
```

---

# 32. Security Hardening Checklist

1. **All network-fetched data is untrusted until verified**
   - Metadata: verified via TUF signatures
   - Artifacts: verified by digest
   - Signatures: verified by certificate chain or TUF key
   - Attestations: verified by envelope signature

2. **No arbitrary code execution during install**
   - Install scripts disabled by default
   - Build scripts run in sandbox
   - Policy must explicitly allow script execution

3. **Defense against dependency confusion**
   - Internal namespaces explicitly declared
   - Public registry blocked for internal names
   - Registry pinned per-package in lockfile

4. **Defense against rollback/freeze attacks**
   - TUF version counters
   - TUF timestamp expiration
   - Monotonic epoch for revocation

5. **CAS integrity**
   - Content addressed: corruption detectable
   - Verify-on-read
   - Write-only-after-digest-match

6. **Lockfile integrity**
   - Root digest covers entire lockfile
   - Tampering detected on parse

7. **Memory safety**
   - Rust's ownership model prevents most memory corruption
   - Fuzz critical parsers (TOML, JSON, certificate, signature)
   - Bounds checking on Merkle proof paths

8. **Secrets handling**
   - Registry tokens stored in OS keychain or env vars, never in lockfile
   - Sandbox blocks host secret access by default
   - No secrets in logs or error messages

9. **Minimum privilege**
   - No root/admin required for normal operations
   - File permissions restricted on CAS and config
   - Build sandbox drops capabilities

10. **Audit trail**
    - Every trust decision logged
    - Every policy evaluation traceable
    - Every revocation check recorded

---

# 33. Code Generation Plan

The codebase scaffold below represents the initial file structure. Each file includes its primary responsibility and key types.

Implementation order follows the dependency graph bottom-up: core types first, then infrastructure (CAS, transport), then trust (TUF, signing, provenance, policy, revocation), then ecosystem adapters (registry, resolver, materializer), then orchestrator, then CLI.

---

# 34. File-by-File Codebase Scaffold

```
crates/
├── rusk-core/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs              # Re-exports
│       ├── digest.rs           # Sha256Digest, Blake3Digest, AnyDigest
│       ├── id.rs               # PackageId, ArtifactId, SignerIdentity, BuilderIdentity
│       ├── ecosystem.rs        # Ecosystem enum, ecosystem-qualified types
│       ├── error.rs            # RuskError, ErrorKind, Diagnostic
│       ├── version.rs          # Version, VersionReq (wrapping semver + pep440)
│       ├── trust.rs            # TrustClass, TrustState, VerificationResult
│       ├── registry.rs         # RegistryUrl, RegistryKind
│       └── platform.rs         # Platform, Os, Arch, PythonVersion
│
├── rusk-manifest/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── schema.rs           # Manifest, PackageMetadata, JsDependencies, PythonDependencies
│       ├── parser.rs           # parse_manifest()
│       ├── validate.rs         # validate_manifest()
│       ├── normalize.rs        # normalize_manifest(), default filling
│       └── workspace.rs        # Workspace discovery, member merging
│
├── rusk-lockfile/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── schema.rs           # Lockfile, LockedPackage, LockedDependency
│       ├── parser.rs           # parse_lockfile()
│       ├── writer.rs           # write_lockfile(), deterministic serialization
│       ├── integrity.rs        # compute_integrity_root(), verify_integrity()
│       ├── diff.rs             # lockfile_diff(), compute_reuse_set()
│       └── binary.rs           # Optional binary format for fast path
│
├── rusk-cas/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── store.rs            # ContentAddressedStore: put, get, has, delete
│       ├── index.rs            # MemoryMappedIndex
│       ├── gc.rs               # CasGc: mark_and_sweep()
│       ├── integrity.rs        # verify_on_read(), handle_corruption()
│       └── layout.rs           # object_path(), directory structure
│
├── rusk-transport/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── client.rs           # HttpClient wrapper (reqwest)
│       ├── manager.rs          # DownloadManager: download_batch()
│       ├── stream.rs           # StreamingHashReader
│       ├── retry.rs            # RetryStrategy, is_retriable()
│       ├── mirror.rs           # race_mirrors()
│       └── progress.rs         # ProgressTracker
│
├── rusk-tuf/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── metadata.rs         # Root/Timestamp/Snapshot/TargetsMetadata
│       ├── verify.rs           # TufVerifier: verify_signatures(), verify_timestamp()
│       ├── update.rs           # update_root(), full update sequence
│       ├── store.rs            # TufLocalStore: persist/load trusted state
│       └── delegation.rs       # DelegatedRole, delegation tree resolution
│
├── rusk-signing/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── verifier.rs         # SignatureVerifier trait
│       ├── keyless.rs          # KeylessVerifier (Fulcio cert chain)
│       ├── static_key.rs       # StaticKeyVerifier (TUF key reference)
│       ├── identity.rs         # extract_signer_identity(), SignerIdentity
│       ├── certificate.rs      # X.509 cert parsing and chain validation
│       └── cache.rs            # SignatureCache
│
├── rusk-transparency/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── client.rs           # RekorClient
│       ├── proof.rs            # verify_merkle_inclusion()
│       ├── checkpoint.rs       # TransparencyCheckpoint, verify_checkpoint()
│       ├── cache.rs            # CheckpointCache
│       └── staleness.rs        # check_freshness()
│
├── rusk-provenance/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── attestation.rs      # DsseEnvelope, parse_attestation()
│       ├── normalize.rs        # NormalizedProvenance, normalize_provenance()
│       ├── verify.rs           # ProvenanceVerifier: full pipeline
│       ├── bundle.rs           # VerifiedProvenance bundle type
│       ├── risk.rs             # compute_risk_flags(), RiskFlag enum
│       ├── slsa.rs             # SLSA v1 predicate parser
│       └── npm.rs              # npm attestation parser
│
├── rusk-policy/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── ast.rs              # PolicyFile, Rule, Expr, Action
│       ├── parser.rs           # parse_policy() - pest or nom based
│       ├── compiler.rs         # compile_policy() - AST → IR
│       ├── ir.rs               # CompiledPolicy, CompiledRule, CompiledExpr
│       ├── evaluator.rs        # PolicyEvaluator: evaluate()
│       ├── context.rs          # PolicyContext, ArtifactInfo, GraphContext
│       ├── explain.rs          # generate_explanation()
│       ├── builtins.rs         # Built-in predicate implementations
│       └── cache.rs            # PolicyVerdictCache
│
├── rusk-revocation/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── bundle.rs           # RevocationBundle, RevocationEntry
│       ├── store.rs            # RevocationState, local persistence
│       ├── update.rs           # fetch and apply revocation bundles
│       ├── check.rs            # check_signer(), check_artifact(), check_version()
│       └── epoch.rs            # Epoch management, monotonic enforcement
│
├── rusk-registry/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── client.rs           # RegistryClient trait
│       ├── metadata.rs         # PackageMetadata, VersionMetadata
│       └── cache.rs            # MetadataCache
│
├── rusk-registry-npm/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── api.rs              # NpmRegistryClient: fetch_packument()
│       ├── metadata.rs         # NpmPackument, NpmVersionMeta, NpmDist
│       └── tarball.rs          # npm tarball URL construction
│
├── rusk-registry-pypi/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── api.rs              # PypiRegistryClient: fetch_package_index()
│       ├── metadata.rs         # PypiPackageIndex, PypiFile, PythonMetadata
│       ├── wheel.rs            # Wheel filename parsing, tag compatibility
│       └── sdist.rs            # Source distribution handling
│
├── rusk-resolver/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── solver.rs           # PubGrubSolver: solve()
│       ├── graph.rs            # ResolvedGraph, ResolvedNode, DependencyEdge
│       ├── candidate.rs        # CandidateProvider trait, VersionCandidate
│       ├── trust_filter.rs     # TrustAwareCandidateFilter
│       ├── incompatibility.rs  # Incompatibility, IncompatibilityStore
│       ├── partial_solution.rs # PartialSolution, decisions, assignments
│       ├── lockfile_reuse.rs   # compute_reuse_set(), seed_from_lockfile()
│       └── workspace.rs        # Workspace-aware resolution
│
├── rusk-resolver-js/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── provider.rs         # JsCandidateProvider: CandidateProvider impl
│       ├── semver.rs           # npm semver range parsing
│       ├── peer.rs             # Peer dependency handling
│       └── optional.rs         # Optional dependency handling
│
├── rusk-resolver-python/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── provider.rs         # PythonCandidateProvider: CandidateProvider impl
│       ├── pep440.rs           # PEP 440 version parsing
│       ├── markers.rs          # PEP 508 marker evaluation
│       ├── wheel_tags.rs       # Wheel tag compatibility
│       └── extras.rs           # Python extras handling
│
├── rusk-materialize/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── planner.rs          # MaterializationPlan, MaterializationEntry
│       ├── linker.rs           # hardlink(), reflink(), copy(), detect_strategy()
│       ├── atomic.rs           # atomic_swap(), rollback()
│       └── state.rs            # InstallState, read/write
│
├── rusk-materialize-js/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── layout.rs           # JsMaterializer, JsLayoutMode
│       ├── virtual_store.rs    # Virtual store layout (pnpm-style)
│       ├── hoisted.rs          # Hoisted layout (npm-style)
│       ├── bin_shims.rs        # Binary shim generation
│       └── tarball.rs          # npm tarball extraction
│
├── rusk-materialize-python/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── venv.rs             # Virtual environment creation/management
│       ├── wheel_install.rs    # Wheel unpacking and installation
│       ├── dist_info.rs        # dist-info directory generation
│       └── scripts.rs          # Entry point script generation
│
├── rusk-sandbox/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── trait_def.rs        # Sandbox trait
│       ├── linux.rs            # LinuxNamespaceSandbox
│       ├── container.rs        # ContainerSandbox
│       ├── process.rs          # ProcessSandbox (fallback)
│       └── provenance_gen.rs   # LocalProvenance generation
│
├── rusk-orchestrator/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── install.rs          # install() flow
│       ├── update.rs           # update() flow
│       ├── verify.rs           # verify() flow
│       ├── audit.rs            # audit() flow
│       ├── build.rs            # build() flow
│       ├── publish.rs          # publish() flow
│       ├── explain.rs          # explain_deny(), explain_trust()
│       └── config.rs           # OrchestratorConfig
│
├── rusk-observability/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── tracing.rs          # Tracing setup, span definitions
│       ├── metrics.rs          # RuskMetrics, counter/histogram types
│       ├── diagnostics.rs      # Diagnostic, machine-readable output
│       └── report.rs           # AuditReport, VerifyReport generation
│
├── rusk-enterprise/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── config.rs           # EnterpriseConfig
│       ├── internal_registry.rs# Internal registry handling
│       ├── org_policy.rs       # Organization policy layering
│       ├── airgap.rs           # AirGapBundle creation/consumption
│       ├── proxy.rs            # Cache proxy configuration
│       ├── leakage.rs          # Internal package leakage prevention
│       └── audit_export.rs     # Enterprise audit reporting
│
└── rusk-cli/
    ├── Cargo.toml
    └── src/
        ├── main.rs             # Entry point, clap setup
        ├── commands/
        │   ├── mod.rs
        │   ├── install.rs      # `rusk install`
        │   ├── update.rs       # `rusk update`
        │   ├── verify.rs       # `rusk verify`
        │   ├── audit.rs        # `rusk audit`
        │   ├── build.rs        # `rusk build`
        │   ├── publish.rs      # `rusk publish`
        │   ├── explain.rs      # `rusk explain`
        │   ├── gc.rs           # `rusk gc`
        │   ├── init.rs         # `rusk init`
        │   └── config.rs       # `rusk config`
        ├── output.rs           # Output formatting, progress bars
        └── config.rs           # CLI config loading
```

---

# 35. Key Rust Structs/Enums/Traits

## 35.1 Core Identity Types (rusk-core)

```rust
// --- Digests ---
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn compute(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        Self(Sha256::digest(data).into())
    }
    pub fn to_hex(&self) -> String { hex::encode(&self.0) }
    pub fn from_hex(s: &str) -> Result<Self, DigestError> {
        let bytes = hex::decode(s)?;
        Ok(Self(bytes.try_into().map_err(|_| DigestError::InvalidLength)?))
    }
    pub fn zero() -> Self { Self([0u8; 32]) }
}

// --- Package Identity ---
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PackageId {
    pub ecosystem: Ecosystem,
    pub registry: RegistryUrl,
    pub namespace: Option<String>,
    pub name: String,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum Ecosystem { Js, Python }

// --- Version ---
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Version {
    Semver(semver::Version),
    Pep440(pep440_rs::Version),
}

// --- Signer / Builder ---
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SignerIdentity {
    pub issuer: String,
    pub subject: String,
}

#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct BuilderIdentity {
    pub builder_type: String,
    pub builder_id: String,
}

// --- Trust ---
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TrustClass {
    TrustedRelease,
    LocalDev,
    Quarantined,
    Unverified,
}
```

## 35.2 Core Traits

```rust
// --- Registry Client ---
#[async_trait]
pub trait RegistryClient: Send + Sync {
    async fn fetch_package_metadata(&self, name: &str) -> Result<PackageMetadata, RegistryError>;
    async fn fetch_version_metadata(&self, name: &str, version: &Version) -> Result<VersionMetadata, RegistryError>;
    fn artifact_url(&self, name: &str, version: &Version, artifact_type: &ArtifactType) -> Result<Url, RegistryError>;
    async fn fetch_tuf_metadata(&self, role: TufRole) -> Result<SignedMetadata, RegistryError>;
    async fn fetch_revocation_bundle(&self, since_epoch: u64) -> Result<RevocationBundle, RegistryError>;
}

// --- Candidate Provider ---
#[async_trait]
pub trait CandidateProvider: Send + Sync {
    async fn get_candidates(&self, package: &PackageId) -> Result<Vec<VersionCandidate>, ResolverError>;
    async fn get_dependencies(&self, package: &PackageId, version: &Version) -> Result<Vec<DependencyEdge>, ResolverError>;
}

// --- Signature Verifier ---
#[async_trait]
pub trait SignatureVerifier: Send + Sync {
    async fn verify(&self, artifact_digest: &Sha256Digest, signature: &ArtifactSignature, policy_ctx: &PolicyContext) -> Result<VerifiedSignature, SignatureError>;
}

// --- Sandbox ---
#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn build(&self, config: SandboxConfig) -> Result<SandboxOutput, SandboxError>;
}

// --- Materializer ---
#[async_trait]
pub trait Materializer: Send + Sync {
    fn plan(&self, graph: &ResolvedGraph, project_root: &Path) -> Result<MaterializationPlan, MaterializeError>;
    async fn materialize(&self, plan: &MaterializationPlan, cas: &ContentAddressedStore, project_root: &Path) -> Result<(), MaterializeError>;
}
```

## 35.3 Major Enums

```rust
// --- Errors (each crate has its own, all convertible to RuskError) ---
#[derive(thiserror::Error, Debug)]
pub enum RuskError {
    #[error(transparent)] Manifest(#[from] ManifestError),
    #[error(transparent)] Lockfile(#[from] LockfileError),
    #[error(transparent)] Resolver(#[from] ResolverError),
    #[error(transparent)] Trust(#[from] TrustError),
    #[error(transparent)] Transport(#[from] TransportError),
    #[error(transparent)] Cas(#[from] CasError),
    #[error(transparent)] Materialize(#[from] MaterializeError),
    #[error(transparent)] Sandbox(#[from] SandboxError),
    #[error(transparent)] Enterprise(#[from] EnterpriseError),
}

// --- Artifact types ---
pub enum ArtifactType {
    NpmTarball,
    PythonWheel { tags: WheelTags },
    PythonSdist,
}

// --- Dependency types ---
pub enum DependencyType {
    Normal,
    Dev,
    Optional,
    Peer,
    PeerOptional,
    Build,
}

// --- Policy actions ---
pub enum Action {
    Allow,
    Deny,
    RequireApproval,
    Quarantine { duration: Duration },
    Warn,
}

// --- Policy verdicts ---
pub enum PolicyVerdict {
    Allow { matched_rules: Vec<String> },
    Deny { reason: String, matched_rules: Vec<String> },
    RequireApproval { reason: String },
    Quarantine { reason: String, duration: Duration },
    Warn { warnings: Vec<String> },
}

// --- Install modes ---
pub enum InstallMode {
    Production,
    Development,
    CI,
    Offline,
}

// --- Link strategy ---
pub enum LinkStrategy {
    Hardlink,
    Reflink,
    Copy,
}
```

---

# 36. Suggested Implementation Order

Phase 1: Foundation (Weeks 1-3)
1. `rusk-core` — All shared types, digests, IDs, errors
2. `rusk-cas` — Content-addressed store (put, get, has, GC)
3. `rusk-manifest` — rusk.toml parser and validator
4. `rusk-lockfile` — rusk.lock parser and writer
5. `rusk-observability` — Tracing and metrics setup

Phase 2: Transport & Registry (Weeks 3-5)
6. `rusk-transport` — HTTP download manager with parallel fetch
7. `rusk-registry` — Registry client trait
8. `rusk-registry-npm` — npm registry client
9. `rusk-registry-pypi` — PyPI registry client

Phase 3: Trust Chain (Weeks 5-8)
10. `rusk-tuf` — TUF metadata verification
11. `rusk-signing` — Signature verification (keyless + static)
12. `rusk-transparency` — Transparency log client and proof verification
13. `rusk-provenance` — Attestation parsing and verification
14. `rusk-revocation` — Revocation subsystem

Phase 4: Policy Engine (Weeks 8-10)
15. `rusk-policy` — Policy DSL parser, compiler, evaluator

Phase 5: Resolver (Weeks 10-13)
16. `rusk-resolver` — PubGrub solver with trust-aware filtering
17. `rusk-resolver-js` — JS/TS candidate provider
18. `rusk-resolver-python` — Python candidate provider

Phase 6: Materialization (Weeks 13-15)
19. `rusk-materialize` — Shared materialization framework
20. `rusk-materialize-js` — node_modules layout
21. `rusk-materialize-python` — site-packages layout

Phase 7: Build & Sandbox (Weeks 15-17)
22. `rusk-sandbox` — Build sandbox abstraction and implementations

Phase 8: Orchestration & CLI (Weeks 17-20)
23. `rusk-orchestrator` — Workflow orchestration
24. `rusk-cli` — CLI binary with all commands
25. `rusk-enterprise` — Enterprise features

Phase 9: Hardening & Performance (Weeks 20-24)
26. Performance optimization pass
27. Fuzzing critical parsers
28. Security audit
29. Documentation
30. End-to-end integration tests

---

# 37. Example CLI UX

```
$ rusk init
Created rusk.toml
Created .rusk/policy.ruskpol (default-strict)

$ rusk install
  Resolving dependencies...
  Resolved 127 packages (95 JS, 32 Python)
  Downloading 127 packages...
  ████████████████████████████████████████ 127/127

  Verifying trust chain...
  ✓ 120/127 signatures verified
  ✓ 45/127 provenance verified
  ✓ 127/127 policy checks passed
  ⚠ 7 packages without signatures (allowed by policy)
  ⚠ 2 packages quarantined (new, < 7 days old)

  Materializing...
  ✓ node_modules: 95 packages (hardlinked from CAS)
  ✓ .venv/site-packages: 32 packages (hardlinked from CAS)

  Done in 2.3s (1.8s download, 0.3s verify, 0.2s materialize)

$ rusk install  # second run, warm cache
  ✓ Up to date (0.04s)

$ rusk verify
  Verifying 127 packages...
  ✓ All digests match
  ✓ All signatures valid
  ✓ No revocations
  ✓ Policy: 127 allowed

  Verification complete in 0.8s

$ rusk audit --format human
  Audit Report
  ════════════
  Total packages: 127
  Signed: 120 (94%)
  With provenance: 45 (35%)
  Quarantined: 2
  Risk flags: 12

  Packages without signatures:
    - lodash@4.17.21 (js)
    - underscore@1.13.6 (js)
    - ...

  Quarantined packages:
    - new-package@1.0.0 (first seen 3 days ago)
    - another-new@0.1.0 (first seen 1 day ago)

$ rusk update react
  Updating react...
  react: 18.2.0 → 18.3.0
    ✓ Signature: react-team@meta.com
    ✓ Provenance: github.com/facebook/react@abc123
    ✓ Builder: github-actions

  Updated rusk.lock
  Materialized 1 package

$ rusk explain deny @evil/malware@1.0.0
  Package: @evil/malware@1.0.0
  Verdict: DENIED

  Matched rules:
    [P300] deny_install_scripts
      → Package has install scripts
      → Not in allowed scripts list

    [P200] require_provenance_for_critical
      → No provenance attestation found

  Trust state:
    Digest: sha256:... ✓
    Signature: ✗ missing
    Provenance: ✗ missing
    Transparency: ✗ not found
    Revocation: ✓ clear

$ rusk gc
  Garbage collection...
  Removed 45 unreferenced objects
  Freed 128.5 MB
```

---

# 38. Example Policy Rules

```
# Production-strict policy for a financial services company

default deny

# Allow packages signed by known good signers
rule allow_signed {
    priority = 100
    when = signature.verified
    action = allow
}

# Require provenance for any package that runs code at install time
rule require_provenance_for_scripts {
    priority = 300
    when = graph.has_install_scripts && !provenance.verified
    action = deny
    reason = "Packages with install scripts must have verified provenance"
}

# Block all packages from unknown registries
rule restrict_registries {
    priority = 500
    when = !(registry.url in ["https://registry.npmjs.org", "https://pypi.org", "https://registry.internal.corp.com"])
    action = deny
    reason = "Only approved registries are allowed"
}

# Block packages with too many transitive dependencies
rule limit_transitive {
    priority = 50
    when = graph.total_transitive_deps > 500
    action = warn
    reason = "Excessive transitive dependency count"
}

# Quarantine packages newer than 14 days
rule quarantine_new {
    priority = 60
    when = artifact.age < 14d && !quarantine_exception(package.name, package.version)
    action = quarantine(14d)
    reason = "New packages are quarantined for 14 days"
}

# Internal packages must come from internal registry
rule internal_only {
    priority = 1000
    when = package.namespace in ["@corp", "@internal"] && registry.kind != "internal"
    action = deny
    reason = "Internal packages must come from internal registry"
}

# Deny all revoked
rule deny_revoked {
    priority = 999
    when = revocation.is_revoked
    action = deny
    reason = "Package or signer has been revoked"
}

# Require specific signers for critical packages
rule critical_signers {
    priority = 400
    when = package.name == "react" && !signer_matches("*@meta.com")
    action = deny
    reason = "React must be signed by Meta employees"
}

# Allow local dev builds in development mode only
rule allow_local_dev {
    priority = 80
    when = trust_class == "local_dev" && install_mode == "development"
    action = allow
}

# Deny local dev in production
rule deny_local_prod {
    priority = 900
    when = trust_class == "local_dev" && install_mode != "development"
    action = deny
    reason = "Local dev builds cannot be used in production"
}
```

---

# 39. Example Provenance Verification Flow

```
Input: react@18.3.0 artifact + attached attestation bundle

Step 1: Parse DSSE envelope
  Envelope:
    payload_type: "application/vnd.in-toto+json"
    payload: <base64-encoded in-toto statement>
    signatures: [
      { keyid: "...", sig: <bytes> }
    ]

Step 2: Verify envelope signature
  → Extract certificate from signature
  → Verify certificate chain: leaf cert → Fulcio intermediate → Fulcio root
  → Verify cert was valid at signing timestamp
  → Verify signature over payload with cert's public key
  → Extract signer identity from cert SAN: "react-team@meta.com"
  ✓ Envelope signature verified

Step 3: Verify transparency log entry
  → Lookup Rekor entry for this signature
  → Verify Merkle inclusion proof
  → Verify checkpoint signature
  → Check checkpoint freshness (< 24h old)
  ✓ Transparency verified (rekor:12345678)

Step 4: Check revocation
  → Check signer "react-team@meta.com" not in revoked signers
  → Check builder "github-actions" not in revoked builders
  ✓ No revocations

Step 5: Parse in-toto statement
  Statement:
    _type: "https://in-toto.io/Statement/v1"
    subject: [
      { name: "react-18.3.0.tgz", digest: { sha256: "abcdef..." } }
    ]
    predicateType: "https://slsa.dev/provenance/v1"
    predicate: {
      buildDefinition: {
        buildType: "https://github.com/slsa-framework/slsa-github-generator/generic@v1"
        externalParameters: { workflow: ".github/workflows/publish.yml" }
        internalParameters: { ... }
        resolvedDependencies: [ ... ]
      }
      runDetails: {
        builder: { id: "https://github.com/actions/runner" }
        metadata: {
          invocationId: "https://github.com/facebook/react/actions/runs/12345"
          startedOn: "2026-03-30T10:00:00Z"
          finishedOn: "2026-03-30T10:05:00Z"
        }
      }
    }

Step 6: Normalize to internal model
  NormalizedProvenance:
    subjects: [{ name: "react-18.3.0.tgz", digest: sha256:abcdef... }]
    source: { repository: "https://github.com/facebook/react", commit: "abc123def", ref: "v18.3.0" }
    builder: { type: "github-actions", id: "https://github.com/actions/runner" }
    build_config: { workflow: ".github/workflows/publish.yml", hermetic: true, reproducible: false }
    metadata: { slsa_level: 3, completeness: { parameters: true, environment: true, materials: true } }

Step 7: Verify subject digest binding
  → Artifact digest: sha256:abcdef...
  → Subject digest: sha256:abcdef...
  → Match: ✓

Step 8: Compute risk flags
  → hermetic: true ✓
  → reproducible: false → RiskFlag::NonReproducibleBuild
  → materials complete: true ✓

Step 9: Build verified provenance bundle
  VerifiedProvenance {
    normalized: <above>,
    risk_flags: [NonReproducibleBuild],
    signer_identity: SignerIdentity { issuer: "accounts.google.com", subject: "react-team@meta.com" },
    builder_identity: BuilderIdentity { type: "github-actions", id: "https://github.com/actions/runner" },
    verified_at: "2026-03-31T12:00:00Z",
  }

Step 10: Cache in CAS
  → Keyed by attestation digest
  → Valid until revocation epoch changes
```

---

# 40. Example End-to-End Install Trace

```
[2026-03-31T12:00:00.000Z] INFO  install: Starting install
[2026-03-31T12:00:00.001Z] INFO  install::manifest: Parsing rusk.toml
[2026-03-31T12:00:00.003Z] INFO  install::manifest: Manifest parsed: 5 JS deps, 3 Python deps
[2026-03-31T12:00:00.003Z] INFO  install::lockfile: Parsing rusk.lock
[2026-03-31T12:00:00.005Z] INFO  install::lockfile: Lockfile parsed: 127 packages, integrity verified
[2026-03-31T12:00:00.005Z] INFO  install::state: Checking install state
[2026-03-31T12:00:00.006Z] INFO  install::state: Lockfile changed since last install, proceeding

[2026-03-31T12:00:00.006Z] INFO  install::tuf: Updating TUF metadata for npmjs.org
[2026-03-31T12:00:00.006Z] INFO  install::tuf: Updating TUF metadata for pypi.org
[2026-03-31T12:00:00.150Z] INFO  install::tuf: npmjs.org: timestamp v42 (fresh), snapshot v41
[2026-03-31T12:00:00.180Z] INFO  install::tuf: pypi.org: timestamp v38 (fresh), snapshot v37

[2026-03-31T12:00:00.180Z] INFO  install::revocation: Updating revocation state
[2026-03-31T12:00:00.250Z] INFO  install::revocation: Revocation state updated, epoch 15, 0 new entries

[2026-03-31T12:00:00.250Z] INFO  install::cas: Checking CAS for 127 artifacts
[2026-03-31T12:00:00.252Z] INFO  install::cas: 120 cached, 7 missing

[2026-03-31T12:00:00.252Z] INFO  install::download: Fetching 7 artifacts
[2026-03-31T12:00:00.252Z] DEBUG install::download: fetch new-package@1.0.0 from https://registry.npmjs.org/new-package/-/new-package-1.0.0.tgz (45KB)
[2026-03-31T12:00:00.252Z] DEBUG install::download: fetch another-new@0.1.0 from https://registry.npmjs.org/another-new/-/another-new-0.1.0.tgz (12KB)
[2026-03-31T12:00:00.252Z] DEBUG install::download: fetch updated-py@2.0.0 from https://files.pythonhosted.org/packages/.../updated_py-2.0.0-py3-none-any.whl (89KB)
... (4 more)
[2026-03-31T12:00:00.850Z] INFO  install::download: All 7 artifacts downloaded (total 234KB in 0.6s)
[2026-03-31T12:00:00.850Z] INFO  install::download: All digests verified during streaming

[2026-03-31T12:00:00.850Z] INFO  install::verify: Verifying trust chain for 127 packages
[2026-03-31T12:00:00.851Z] DEBUG install::verify: react@18.3.0: sig=cached(hit) prov=cached(hit) policy=cached(hit)
[2026-03-31T12:00:00.851Z] DEBUG install::verify: express@4.18.2: sig=cached(hit) prov=cached(hit) policy=cached(hit)
... (118 more cache hits)
[2026-03-31T12:00:00.860Z] DEBUG install::verify: new-package@1.0.0: sig=verify(ok) prov=missing(allowed) policy=evaluate(quarantine)
[2026-03-31T12:00:00.870Z] DEBUG install::verify: another-new@0.1.0: sig=verify(ok) prov=missing(allowed) policy=evaluate(quarantine)
... (5 more fresh verifications)
[2026-03-31T12:00:00.900Z] INFO  install::verify: 127/127 verified. 120 sig verified, 45 prov verified, 2 quarantined
[2026-03-31T12:00:00.900Z] WARN  install::verify: 2 packages quarantined (< 7 days old)

[2026-03-31T12:00:00.900Z] INFO  install::materialize: Planning materialization
[2026-03-31T12:00:00.910Z] INFO  install::materialize::js: Planning node_modules (virtual store mode)
[2026-03-31T12:00:00.920Z] INFO  install::materialize::python: Planning .venv/site-packages
[2026-03-31T12:00:00.925Z] INFO  install::materialize: Strategy: hardlink (supported)

[2026-03-31T12:00:00.925Z] INFO  install::materialize: Materializing...
[2026-03-31T12:00:01.050Z] INFO  install::materialize::js: node_modules: 95 packages, 2847 files hardlinked
[2026-03-31T12:00:01.120Z] INFO  install::materialize::python: site-packages: 32 packages, 891 files hardlinked
[2026-03-31T12:00:01.125Z] INFO  install::materialize: Atomic swap completed

[2026-03-31T12:00:01.125Z] INFO  install::state: Writing install state
[2026-03-31T12:00:01.130Z] INFO  install: Install complete: 127 packages (120 cached, 7 downloaded) in 1.13s

Summary:
  Packages: 127 (95 JS, 32 Python)
  Downloaded: 7 (234KB)
  Cached: 120
  Signatures: 120 verified, 7 unsigned (allowed)
  Provenance: 45 verified
  Policy: 125 allowed, 2 quarantined
  Time: 1.13s (download: 0.60s, verify: 0.05s, materialize: 0.23s)
```

---

# Appendix A: Cargo.toml (Workspace Root)

```toml
[workspace]
resolver = "2"
members = [
    "crates/rusk-core",
    "crates/rusk-manifest",
    "crates/rusk-lockfile",
    "crates/rusk-cas",
    "crates/rusk-transport",
    "crates/rusk-tuf",
    "crates/rusk-signing",
    "crates/rusk-transparency",
    "crates/rusk-provenance",
    "crates/rusk-policy",
    "crates/rusk-revocation",
    "crates/rusk-registry",
    "crates/rusk-registry-npm",
    "crates/rusk-registry-pypi",
    "crates/rusk-resolver",
    "crates/rusk-resolver-js",
    "crates/rusk-resolver-python",
    "crates/rusk-materialize",
    "crates/rusk-materialize-js",
    "crates/rusk-materialize-python",
    "crates/rusk-sandbox",
    "crates/rusk-orchestrator",
    "crates/rusk-observability",
    "crates/rusk-enterprise",
    "crates/rusk-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.75"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"

# Crypto
sha2 = "0.10"
blake3 = "1"
ed25519-dalek = { version = "2", features = ["batch"] }
p256 = "0.13"
x509-cert = "0.2"

# Async
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", features = ["stream", "json", "rustls-tls"] }
futures = "0.3"
async-trait = "0.1"

# Data structures
dashmap = "5"
lru = "0.12"
indexmap = { version = "2", features = ["serde"] }

# CLI
clap = { version = "4", features = ["derive"] }
indicatif = "0.17"
console = "0.15"

# Observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Testing
proptest = "1"
tempfile = "3"
wiremock = "0.6"

# Error handling
thiserror = "1"
anyhow = "1"
miette = { version = "7", features = ["fancy"] }

# Misc
url = { version = "2", features = ["serde"] }
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
hex = "0.4"
glob = "0.3"
semver = { version = "1", features = ["serde"] }
pep440_rs = "0.6"
pep508_rs = "0.6"
memmap2 = "0.9"
```

---

# Appendix B: Key Algorithm References

## PubGrub Resolution Algorithm

The PubGrub algorithm (used by Dart's pub, uv, and adapted here) works as follows:

1. **Incompatibilities**: Express constraints as "impossible combinations". E.g., "if A@1.0 is selected, B must be >=2.0" becomes the incompatibility {A@1.0, B@<2.0}.

2. **Unit propagation**: Repeatedly apply incompatibilities:
   - If an incompatibility has all but one term satisfied, the remaining term must be negated
   - This is analogous to BCP in SAT solving

3. **Decision**: When no more propagation is possible, choose a package and pick the best version

4. **Conflict resolution**: When an incompatibility is fully satisfied (conflict):
   - Derive a new incompatibility from the conflict (resolution rule)
   - Add it to the incompatibility store
   - Backtrack to the decision level where the new incompatibility becomes unit

Advantages over traditional backtracking:
- Learns from conflicts (no-goods)
- Produces precise error messages
- Polynomial behavior in practice

## Merkle Inclusion Proof Verification

Used for transparency log proofs:

```
For tree of size N, verify leaf at index I:
1. Start with leaf hash
2. For each level:
   - If index is even: combine with right sibling
   - If index is odd: combine with left sibling
   - Move to parent
3. Final hash should equal root hash
```

## TUF Update Sequence

```
1. Root rotation check (fetch root.json version N+1, N+2, ... until 404)
2. Fetch timestamp.json
   - Verify signature with root's timestamp key
   - Verify version > previous
   - Verify not expired
3. Fetch snapshot.json (version specified in timestamp)
   - Verify signature with root's snapshot key
   - Verify version > previous
   - Verify not expired
4. Fetch targets.json (version specified in snapshot)
   - Verify signature with root's targets key
   - Verify version matches snapshot reference
   - Verify not expired
5. Follow delegations as needed for package-specific targets
```

---

# Appendix C: On-Disk Layout Summary

```
~/.rusk/                              # Global rusk directory
├── cas/                              # Content-addressed store
│   ├── objects/sha256/{ab}/{hash}    # Artifact blobs
│   ├── index/                        # Memory-mapped indexes
│   ├── tmp/                          # Staging area
│   └── quarantine/                   # Corrupted objects
├── tuf/                              # TUF state per registry
│   ├── npmjs.org/
│   │   ├── root.json
│   │   ├── timestamp.json
│   │   └── snapshot.json
│   └── pypi.org/
├── transparency/                     # Transparency log state
│   └── rekor/
│       └── latest_checkpoint.json
├── revocation/                       # Revocation state per registry
│   ├── npmjs.org/state.json
│   └── pypi.org/state.json
├── cache/                            # Metadata and HTTP cache
│   ├── npm/                          # npm packument cache
│   ├── pypi/                         # PyPI index cache
│   └── http/                         # Generic HTTP response cache
└── config.toml                       # Global rusk config

<project>/                            # Per-project files
├── rusk.toml                         # Manifest
├── rusk.lock                         # Lockfile
├── .rusk/
│   ├── policy.ruskpol                # Project policy file
│   ├── install-state.json            # Current install state
│   └── trust-roots/                  # Project-specific trust roots
├── node_modules/                     # JS materialization
│   ├── .rusk/                        # Virtual store
│   │   └── {name}@{ver}/
│   ├── {direct-dep} -> .rusk/...     # Symlinks
│   └── .bin/                         # Binary shims
└── .venv/                            # Python materialization
    ├── bin/
    └── lib/pythonX.Y/site-packages/
```

---

This specification covers all 40 required sections with design and implementation detail for each subsystem. The architecture is designed for a unified core with ecosystem-specific adapters, strong supply-chain security by default, and high performance through content-addressed caching and parallel operations.

**Key architectural decisions**:
1. PubGrub solver with trust-aware filtering (from uv)
2. CAS with hardlinks for instant re-installs (from pnpm/Bun)
3. Parallel HTTP fetch with streaming verification (from Bun/uv)
4. TUF-based registry trust (new for package managers)
5. Integrated policy engine with declarative DSL (new)
6. Provenance verification normalized across ecosystems (new)
7. Revocation as a core primitive, not afterthought (new)
8. Virtual store layout for JS, venv for Python, shared CAS (new)

---

# Appendix D: Detailed Analysis of Bun's Architecture (Informing rusk Design)

This appendix documents Bun's internal package manager architecture, studied to inform rusk's JS/TS subsystem design. Key patterns adopted and adapted:

## D.1 Bun's Resolution Architecture

Bun uses flat ID tables (`PackageID = u32`, `DependencyID = u32`) with a `Behavior` bitfield to classify dependency types. For rusk, we adopt the flat ID table approach for the resolver's internal representation, but wrap it in typed `PackageId` / `DependencyEdge` structs for safety. The bitfield approach is used internally within `rusk-resolver` for fast graph operations.

**Peer dependency handling**: Bun tracks peers with a `Behavior` bitfield distinguishing `peer`, `optional_peer`, and combinations. The `hoistDependency` function walks up the tree to find the highest position for a package. In isolated mode, Bun computes a `PeerHash` (u64) per store entry encoding which peer versions are active, so the same package with different peer contexts gets distinct store entries. rusk adopts the `PeerHash` concept for the virtual store materializer.

**Key learning for rusk**: Bun's resolution flow interleaves manifest fetch and tarball download — as soon as a manifest resolves and a version is picked, the tarball download starts immediately. rusk must implement the same pipelining in `rusk-transport`, scheduling tarball fetches as soon as the resolver commits a version decision, rather than waiting for full resolution.

## D.2 Bun's Caching Model

- **Global cache**: `~/.bun/install/cache/` organized by `<name>/<version>/`. rusk uses a content-addressed layout (by digest) instead, which provides deduplication across versions that share identical content and enables integrity verification.
- **Manifest cache**: Two-level cache with HTTP conditional requests (`If-None-Match`, `If-Modified-Since`). rusk adopts this pattern in `rusk-registry` with ETag-based conditional requests.
- **Temp directory**: Bun ensures the temp directory is on the same filesystem as the cache for atomic `rename()`. rusk adopts this critical detail — `~/.rusk/cas/tmp/` must be on the same filesystem as `~/.rusk/cas/objects/`.

## D.3 Bun's Installation Layout

Bun supports two modes:
- **Hoisted** (npm-style): Default for non-workspace projects. Tree builder walks up trying to place packages as high as possible.
- **Isolated** (pnpm-style): Default for workspaces. Virtual store at `node_modules/.bun/` with hardlinks from global cache and symlinks for dependency resolution.

rusk adopts the isolated/virtual store approach as default (stored in `node_modules/.rusk/`), with hoisted mode as an option. Key insight from Bun: the `early_dedupe` map that collapses leaf nodes reduces node count by >50% (Bun's source notes: "pnpm repo: 772,471 nodes → 314,022 nodes with this map"). rusk must implement equivalent early deduplication in `rusk-materialize-js`.

## D.4 Bun's Transport Optimizations

- **DNS prefetching**: Bun prefetches DNS for registry hostname before loading the lockfile. rusk should do the same in `rusk-transport` — start DNS resolution for all configured registries immediately on CLI startup.
- **Network deduplication**: `DedupeMap` prevents duplicate HTTP requests. rusk's `DownloadManager` uses a `DashMap` keyed by URL for the same purpose.
- **Abbreviated metadata**: Bun requests `application/vnd.npm.install-v1+json` (npm's abbreviated metadata format) by default. rusk's npm client should do the same, falling back to full metadata only when needed.
- **Throttling**: Dynamic throttle that reduces concurrent requests on network errors. rusk should implement adaptive concurrency in `rusk-transport`.

## D.5 Bun's Lockfile Design

- **Binary format** (`bun.lockb`): Struct-of-arrays (SoA) layout for cache-friendly scanning. Header includes a meta hash for fast staleness detection. Extension blocks use magic 8-byte tags.
- **Text format** (`bun.lock`): JSON-based, human-readable, diffable. Workspaces section + packages section.

rusk uses TOML for the text lockfile (more natural for Rust ecosystem, better for inline comments). The optional binary format in `rusk-lockfile/binary.rs` should adopt Bun's SoA approach with magic-tagged extension blocks for forward compatibility. The meta hash concept is adopted as the `integrity` root digest.

## D.6 Bun's Lifecycle Script Security

Bun only runs lifecycle scripts for packages listed in `trustedDependencies`. This is the same approach rusk takes — scripts disabled by default, gated by policy `trust.scripts.allow` list. Bun also has a `postinstall_optimizer` that bypasses scripts for known packages (esbuild, sharp) by directly linking platform-specific native binaries. rusk can implement similar optimizations as policy-driven fast paths.

## D.7 Performance Patterns Adopted from Bun

| Bun Pattern | rusk Adaptation |
|-------------|-----------------|
| DNS prefetch before lockfile parse | Start DNS resolution for all registries on CLI startup |
| Parallel manifest + tarball interleaving | Pipeline tarball fetches as resolver commits versions |
| SoA binary lockfile | Optional binary lockfile format using SoA layout |
| DedupeMap for network requests | DashMap-based request deduplication in DownloadManager |
| clonefile → hardlink → copy fallback | reflink → hardlink → copy fallback in materializer |
| early_dedupe map for virtual store | Early leaf deduplication in JS materialization planner |
| Abbreviated npm metadata | Request `application/vnd.npm.install-v1+json` by default |
| .bun-tag for install verification | install-state.json with plan digest for fast skip |

---

# Appendix E: Detailed Analysis of uv's Architecture (Informing rusk Design)

This appendix documents uv's internal architecture, studied to inform rusk's Python subsystem design.

## E.1 uv's Resolution Architecture

uv uses a PubGrub-based solver (via the `pubgrub` crate, with custom extensions). The resolver is implemented as an async state machine that interleaves dependency fetching with solving. Key components:
- **ResolverProvider**: Abstracts package metadata fetching (from registry or local cache)
- **ForkState**: Handles marker-driven resolution forks — when different Python versions or platforms require different dependency versions, uv forks the resolution state
- **PreReleaseStrategy**: Configurable per-package prerelease handling

rusk adopts the PubGrub approach with the same `CandidateProvider` abstraction. The fork-state concept is important for Python's environment markers — rusk must handle this in `rusk-resolver-python`.

## E.2 uv's Caching Model

uv uses a multi-layer cache at `~/.cache/uv/`:
- **wheels-v4/**: Built wheels, keyed by `{name}-{version}-{tags}`
- **built-wheels-v4/**: Wheels built from source distributions
- **simple-v13/**: Cached Simple API responses (registry metadata)
- **archive-v0/**: Extracted wheel archives

Cache keys incorporate content hashes for integrity. Cache entries are reflinked when possible. rusk's CAS subsumes all of these caches into a single content-addressed store with object type tags.

## E.3 uv's Transport

uv uses `reqwest` with:
- Connection pooling and HTTP/2 when available
- Conditional requests with ETags for registry metadata
- Streaming downloads with progress reporting
- Retry with exponential backoff

rusk adopts the same `reqwest`-based client with identical HTTP/2 and conditional request patterns.

## E.4 uv's Build Isolation

uv implements PEP 517/518 build isolation:
1. Create a temporary virtual environment
2. Install build dependencies (from `[build-system].requires` in pyproject.toml)
3. Invoke the build backend (`build_wheel` or `build_sdist`)
4. Capture the output wheel

rusk's `rusk-sandbox` uses a stronger isolation model (namespace/container), but the PEP 517/518 flow is the same. For Python source builds, rusk must implement the same build backend invocation protocol.

## E.5 uv's Lockfile

`uv.lock` is a TOML-like format (actually a custom format using `toml-edit`) that records:
- Package name, version, source
- Dependencies with markers
- Wheel URLs and hashes
- Optional dependencies and extras

rusk adopts TOML for the lockfile, with similar structure but extended for multi-ecosystem support and trust metadata.

## E.6 Performance Patterns Adopted from uv

| uv Pattern | rusk Adaptation |
|------------|-----------------|
| PubGrub solver with async provider | Same architecture in rusk-resolver |
| PEP 658 metadata fast-path | Fetch wheel METADATA without downloading full wheel |
| Fork-state for marker resolution | Marker-driven resolution forks in rusk-resolver-python |
| Wheel tag compatibility prefiltering | Early filtering of incompatible wheels before solver |
| Streaming hash verification on download | Same in rusk-transport StreamingHashReader |
| Conditional HTTP requests for metadata | ETag-based conditional requests in rusk-registry |
