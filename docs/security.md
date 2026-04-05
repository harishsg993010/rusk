# Security

## Threat model

rusk is designed to protect against supply-chain attacks at the package manager layer. Here's what it mitigates and what it doesn't.

### Attacks rusk stops

**Transport-layer tampering.** Every artifact is hashed with SHA-256 during download. If a CDN, mirror, or MITM serves modified bytes, the digest won't match and the install aborts. Blob transport is treated as untrusted -- only availability matters, not integrity.

**Same-version different-bytes.** The lockfile pins the exact digest for every version. If a registry silently replaces an artifact with different bytes for the same version string, rusk detects the mismatch.

**Cache poisoning.** The CAS (content-addressed store) keys every blob by its SHA-256 hash. Corrupt or injected entries are detected on read by recomputing the hash.

**Unauthorized publisher.** Signer identity is verified against policy-defined allowed signers. If a different key signs a release, the policy engine catches it.

**CI token abuse.** Provenance binds an artifact to a specific builder and workflow identity. Policy can require specific builder identities.

**Dependency confusion.** Manifest specifies allowed registries and namespaces per package. Internal packages can be locked to internal registries only.

**Silent upgrades.** The lockfile pins the entire transitive closure. `rusk install` never upgrades anything -- you have to explicitly run `rusk update`.

**Install script malware.** Lifecycle scripts are disabled by default. Build scripts run in a sandbox that blocks network access and scrubs secrets from the environment.

**Rollback and freeze attacks.** TUF metadata includes version counters and timestamps. The client rejects stale or rolled-back metadata.

### Attacks rusk does NOT fully solve

**Malicious maintainers.** A legitimate maintainer with valid signing keys can publish malicious code that passes all verification. rusk can detect when the publisher changes, but not when the original publisher goes rogue.

**Compromised CI with valid attestations.** If a build system is fully compromised and produces valid attestations with stolen keys, the provenance is technically correct. Transparency logs can detect anomalous builder activity after the fact.

**Endpoint compromise.** If your development machine is compromised, the attacker has full access. Out of scope for a package manager.

**Runtime exploits.** Python `.pth` files execute on interpreter startup. rusk prevents the malicious package from being installed, but if it's already in site-packages, the damage is done at runtime.

---

## SHA-256 digest verification

Every artifact is hashed during download using SHA-256. The computed digest is compared against the lockfile entry before the blob is committed to the CAS. If the hashes don't match, the install stops immediately.

```
$ rusk verify --detailed
  OK  ms@2.1.3 (sha256:a101155c3cbdfb1e...)
  OK  express@4.21.2 (sha256:7b75c105719...)
Verified 70/70 packages: 70 passed, 0 failed
```

This runs on every install, not just the first one. Even cached packages are verified on read.

---

## CAS verify-on-read

The content-addressed store doesn't trust its own contents. On every warm-cache install, rusk reads each blob from disk, recomputes the SHA-256, and compares it to the expected digest before using the extracted package. A corrupted blob is caught and the extracted cache entry is evicted:

```
$ echo "CORRUPTED" > .rusk/cas/a1/a101155c...
$ rusk install
error: CAS integrity failed for ms@2.1.3: digest mismatch
  (expected sha256:a101155c..., got sha256:3398b5c2...)
```

---

## npm ECDSA signature verification

rusk fetches the npm registry's ECDSA-P256 signing keys and verifies the cryptographic signature on every package. This confirms the artifact was signed by npm's infrastructure, not just that the bytes match a hash.

```
npm ECDSA signature verified, package: express, keyid: SHA256:DhQ8wR5APBvFHLF/+Tc+...
npm ECDSA signature verified, package: axios, keyid: SHA256:DhQ8wR5APBvFHLF/+Tc+...
```

With `require_signatures = true` in your trust config, unsigned packages are blocked.

---

## PyPI PEP 740 attestation verification

rusk fetches PEP 740 attestation bundles from PyPI's Integrity API and verifies Trusted Publisher identity. This confirms the artifact was built by a specific CI workflow in a specific repository.

```
PyPI attestation bundle verified, package: litellm, publisher: GitHub,
  repository: BerriAI/project-releaser, workflow: publish-litellm.yml
PyPI attestation bundle verified, package: idna, publisher: GitHub,
  repository: kjd/idna, workflow: deploy.yml
```

---

## Provenance change detection

rusk stores provenance metadata in the lockfile. When you run `rusk update`, it compares old and new provenance and flags anomalies:

- **PROVENANCE DROPPED** -- package had attestation, update doesn't
- **PUBLISHER CHANGED** -- different CI system
- **SOURCE REPOSITORY CHANGED** -- different repo (fork attack)
- **BUILD WORKFLOW CHANGED** -- different pipeline

These are the signals that would have caught the litellm attack, where a malicious version was uploaded directly to PyPI without going through the normal GitHub Actions release process.

---

## Revocation checking

rusk maintains a revocation list for artifacts and signer identities. On every install and update, it fetches the latest revocation bundles and checks whether any installed package or signing key has been revoked. Revocation uses epoch-based cache invalidation -- the client tracks which epoch it last checked and fetches only newer entries.

---

## Policy engine

Three commands expose the policy engine:

**`rusk audit`** evaluates the entire dependency tree against trust policy and scans for known security advisories via the npm bulk advisory API. With `--strict`, any issue (missing signatures, known vulnerabilities) causes a non-zero exit code.

**`rusk verify`** checks that installed packages match their lockfile digests. It reads each blob from the CAS, recomputes the hash, and compares. With `--strict`, missing signatures or provenance also fail.

**`rusk explain <package>`** shows exactly why a specific package was allowed or blocked. With `--trace`, it prints the full evaluation chain: load config, look up package, check each requirement, final verdict. Useful for debugging CI failures.

---

## Build sandbox

`rusk build` runs build scripts in an isolated process with restricted capabilities:

- **Network access: denied.** Build scripts cannot phone home.
- **Host filesystem: denied.** Only the project directory is accessible.
- **Environment variables: scrubbed.** No AWS keys, npm tokens, SSH keys, or other secrets leak into the build process.

Use `--no-sandbox` only for debugging. The sandbox is the last line of defense against build-time attacks.

---

## Anomaly reporting webhook

Configure `report_url` in the `[trust]` section to receive fire-and-forget HTTP POST notifications when rusk detects a security anomaly:

```toml
[trust]
report_url = "https://hooks.slack.com/services/T.../B.../xxx"
```

rusk sends a JSON payload for these events:
- Provenance dropped or changed
- Signature missing or invalid
- Revocation hit
- CAS corruption

```json
{
  "timestamp": "2026-03-31T12:00:00Z",
  "anomaly_type": "provenance_dropped",
  "package": "litellm",
  "version": "1.82.8",
  "severity": "critical",
  "detail": "package previously had attestation but update does not",
  "hostname": "ci-runner-07"
}
```

Reports never block the install. They're informational, sent asynchronously. Compatible with Slack webhooks, PagerDuty, Datadog, or any endpoint that accepts JSON.

---

## Security advisory scanning

`rusk audit` queries the npm bulk advisory API to check for known vulnerabilities in JS packages. Advisories are shown alongside trust policy violations in the audit report:

```
[HIGH] lodash@4.17.20: Prototype Pollution (https://github.com/advisories/GHSA-...)
  Remediation: Upgrade lodash to a version outside <=4.17.20
```

Advisory scanning is informational -- it logs a warning but doesn't block the install by default. Use `--strict` to gate on it.

---

## The litellm case study

On March 24, 2026, a threat actor published malicious versions of `litellm` to PyPI. The package contained a `.pth` file that executed on every Python process startup, stealing credentials and installing a persistent backdoor. The malicious versions were uploaded directly to PyPI, bypassing the normal GitHub Actions release process.

rusk would have stopped this at multiple independent layers:

1. **Lockfile pins** prevent silent upgrades -- `rusk install` doesn't upgrade unless you run `rusk update`
2. **Digest changes** are visible in version control during code review
3. **Provenance verification** detects the missing CI attestation (no GitHub Actions build, no release tag)
4. **Signature policy** catches unauthorized publishers
5. **Build sandbox** limits blast radius for install-time code execution

No single layer is perfect. But stacking five layers means the attacker has to beat all of them. See the [README](../README.md#case-study-how-rusk-would-have-stopped-the-litellm-compromise) for the full walkthrough.
