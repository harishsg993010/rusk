# Architecture

## Workspace structure

rusk is a 25-crate Rust workspace. Each crate has a single, clear responsibility.

```
rusk/
├── Cargo.toml                    # workspace root
├── crates/
│   ├── rusk-cli/                 # CLI binary (clap arg parsing, output formatting)
│   ├── rusk-core/                # Core types: Sha256Digest, PackageId, Version, Ecosystem
│   ├── rusk-manifest/            # rusk.toml / package.json / pyproject.toml parser
│   ├── rusk-lockfile/            # rusk.lock reader and writer
│   ├── rusk-cas/                 # Content-addressed store (SHA-256 keyed)
│   ├── rusk-transport/           # Parallel HTTP downloads with streaming hash verification
│   ├── rusk-registry/            # Registry client abstraction (trait)
│   ├── rusk-registry-npm/        # npm registry client (metadata, tarballs, advisories)
│   ├── rusk-registry-pypi/       # PyPI registry client (Simple API, wheel discovery)
│   ├── rusk-resolver/            # Dependency resolver framework (conflict/cycle detection)
│   ├── rusk-resolver-js/         # JS-specific resolution (semver, npm semantics)
│   ├── rusk-resolver-python/     # Python-specific resolution (PEP 440, wheel filtering)
│   ├── rusk-materialize/         # File layout abstraction + install state tracking
│   ├── rusk-materialize-js/      # node_modules materializer (hoisted + isolated)
│   ├── rusk-materialize-python/  # site-packages materializer (wheels, .dist-info)
│   ├── rusk-tuf/                 # TUF metadata verification (rollback/freeze protection)
│   ├── rusk-signing/             # Signature verification (ECDSA-P256, Ed25519, keyless)
│   ├── rusk-transparency/        # Transparency log client (checkpoint verification)
│   ├── rusk-provenance/          # SLSA provenance attestation parsing and verification
│   ├── rusk-policy/              # Trust policy engine with declarative rules
│   ├── rusk-revocation/          # Signer/artifact revocation with epoch tracking
│   ├── rusk-sandbox/             # Build isolation (process-level, env scrubbing)
│   ├── rusk-orchestrator/        # Wires everything together (install, update, verify flows)
│   ├── rusk-observability/       # Tracing setup, structured logging, metrics
│   └── rusk-enterprise/          # Internal registries, air-gap bundles, SBOM export
├── tests/                        # Integration and end-to-end tests
├── benches/                      # Benchmarks
└── docs/                         # This documentation
```

---

## Dependency graph

```
rusk-cli
  └── rusk-orchestrator
       ├── rusk-manifest
       ├── rusk-lockfile
       ├── rusk-resolver
       │   ├── rusk-resolver-js
       │   └── rusk-resolver-python
       ├── rusk-registry
       │   ├── rusk-registry-npm
       │   └── rusk-registry-pypi
       ├── rusk-transport
       ├── rusk-tuf
       ├── rusk-signing
       ├── rusk-transparency
       ├── rusk-provenance
       ├── rusk-policy
       ├── rusk-revocation
       ├── rusk-cas
       ├── rusk-materialize
       │   ├── rusk-materialize-js
       │   └── rusk-materialize-python
       ├── rusk-sandbox
       └── rusk-enterprise

rusk-core         (depended on by ALL crates)
rusk-observability (depended on by ALL crates)
```

The CLI is a thin shell. It parses arguments, initializes tracing, and dispatches to the orchestrator. All real logic lives in library crates.

---

## Core types

**`Sha256Digest`** -- a `[u8; 32]` wrapper. Used everywhere: lockfile entries, CAS keys, verification results. Has `from_hex`, `to_hex`, `compute(&[u8])`, and a `zero()` sentinel for unverified packages.

**`PackageId`** -- identifies a package across ecosystems. Contains `ecosystem` (Js or Python), `registry`, optional `namespace` (npm scope), and `name`.

**`Version`** -- wraps either a semver `Version` (for JS) or a PEP 440 version (for Python) behind a common interface.

**`Ecosystem`** -- an enum: `Js` or `Python`. Drives registry selection, resolution strategy, and materialization target.

**`ExitCode`** -- 13 structured exit codes (see [CI/CD](ci-cd.md)). Each has `as_i32()`, `code_name()`, and `description()`.

---

## Install flow

The core operation, `rusk install`, follows this pipeline:

```
1. Parse manifest
   - Detect manifest type: rusk.toml, package.json, pyproject.toml, requirements.txt
   - Normalize into internal Manifest struct

2. Parse lockfile (if exists)
   - Load rusk.lock
   - Validate lockfile integrity (root digest)

3. Resolve
   - If no lockfile: full resolution from manifest constraints
   - If lockfile exists and not --frozen: incremental resolution
   - If --frozen: skip resolution, use lockfile as-is
   - Resolution produces a dependency graph with exact versions

4. Download
   - For each resolved package: check CAS for existing blob
   - Queue missing blobs for parallel download
   - Stream-hash each download (SHA-256 computed during transfer)

5. Verify
   For each artifact (cached or freshly downloaded):
   a. SHA-256 digest matches lockfile pin
   b. Signature verification (if required by policy)
   c. Provenance attestation (if required by policy)
   d. Transparency log proof (if required by policy)
   e. Revocation check
   f. Policy engine evaluation
   g. Any failure -> halt with structured exit code

6. Materialize
   - JS: extract tarballs, link into node_modules/ (hoisted or isolated)
   - Python: extract wheels, link into .venv/lib/site-packages/
   - Uses hardlinks from the CAS extracted-package cache

7. Write state
   - Write/update rusk.lock with digests, signatures, provenance
   - Write install state file (.rusk/install-state.json)
```

---

## CAS design

The content-addressed store is a directory tree under `.rusk/cas/`. Blobs are stored in shard directories based on the first two hex characters of their SHA-256 digest:

```
.rusk/cas/
├── a1/
│   └── a101155c3cbdfb1e...    # full hex digest as filename
├── 7b/
│   └── 7b75c105719...
└── ...
```

**Write path:** Compute SHA-256 while streaming the download. Write to a temp file. Rename into the shard directory. The rename is atomic on most filesystems, so a partial download never pollutes the store.

**Read path:** Read the blob, recompute SHA-256, compare to the expected digest. If they don't match, the blob is corrupt -- delete it and re-download. This is the verify-on-read guarantee.

**Extracted cache:** After a blob is verified, its contents (tarball or wheel) are extracted into a parallel cache directory. Future installs hardlink from the extracted cache instead of re-extracting. If the CAS blob is found corrupt, the extracted cache entry is evicted too.

---

## Three-tier caching

**No-op (fastest, ~0.17s):** Lockfile exists, install state exists, all materialized directories are present and up to date. rusk checks the state file, confirms nothing changed, and returns immediately.

**Warm cache (~1.0s):** Lockfile exists, all blobs are in the CAS, but materialized directories need rebuilding (e.g., after `rm -rf node_modules`). rusk verifies each CAS blob, hardlinks from the extracted cache. Zero network.

**Cold install (~5s):** No lockfile or missing blobs. Full resolution, parallel downloads, streaming hash verification, CAS commit, extraction, and materialization.

Every tier verifies integrity. There's no "trust the cache" shortcut.

---

## Security pipeline

On every install, each artifact passes through this pipeline before reaching your project:

```
┌─────────┐     ┌──────────┐     ┌───────────┐     ┌────────────┐     ┌──────────┐     ┌────────┐
│   TUF   │ --> │ Signing  │ --> │Provenance │ --> │Transparency│ --> │Revocation│ --> │ Policy │
│ metadata│     │ verify   │     │  verify   │     │  log check │     │  check   │     │ engine │
└─────────┘     └──────────┘     └───────────┘     └────────────┘     └──────────┘     └────────┘
```

1. **TUF** -- verify registry metadata freshness (no rollback, no freeze)
2. **Signing** -- verify cryptographic signature (npm ECDSA, PyPI PEP 740 attestations)
3. **Provenance** -- verify build attestation (SLSA provenance, builder identity)
4. **Transparency** -- verify inclusion in transparency log (checkpoint freshness)
5. **Revocation** -- check if artifact or signer has been revoked (epoch-based)
6. **Policy** -- evaluate user-defined trust rules (require_signatures, trusted_signers, etc.)

Each stage can produce a pass, warning, or failure. The policy engine makes the final decision based on the configured trust requirements.

The pipeline is the same for both JS and Python packages. The only ecosystem-specific parts are the signature format (npm ECDSA vs PyPI attestation bundles) and the registry protocol.
