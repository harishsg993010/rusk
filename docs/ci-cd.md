# CI/CD Integration

rusk is designed for CI pipelines. Every command returns structured exit codes and supports JSON output.

---

## Exit codes

| Code | Name | Meaning |
|------|------|---------|
| 0 | `success` | Everything passed |
| 10 | `resolution_failed` | Dependency resolution error |
| 11 | `download_failed` | Artifact download error |
| 20 | `policy_denied` | Trust policy blocked the install |
| 21 | `signature_missing` | Required signature not found |
| 22 | `provenance_dropped` | Package lost its attestation |
| 23 | `revocation_hit` | Package or signer was revoked |
| 30 | `cas_corruption` | Content-addressed store integrity failure |
| 31 | `lockfile_mismatch` | Lockfile doesn't match manifest |
| 40 | `materialization_failed` | Failed to extract/link packages |
| 50 | `manifest_error` | Invalid manifest file |
| 70 | `audit_failed` | Audit found policy violations |
| 71 | `verification_failed` | Installed packages don't match lockfile |

Print the full table at any time:

```bash
rusk --exit-codes
rusk --exit-codes --format json
```

Use these in CI scripts to distinguish between "resolution failed" and "security policy blocked the install":

```bash
rusk install --frozen
case $? in
  0)  echo "ok" ;;
  20) echo "BLOCKED by trust policy" ; exit 1 ;;
  31) echo "lockfile out of date -- run rusk install locally" ; exit 1 ;;
  *)  echo "install failed" ; exit 1 ;;
esac
```

---

## JSON output

Every command supports `--format json`. Output goes to stdout; progress messages go to stderr.

### install

```bash
$ rusk install --format json
```

```json
{
  "status": "success",
  "exit_code": 0,
  "resolved": 70,
  "downloaded": 0,
  "cached": 70,
  "materialized": 0,
  "elapsed_ms": 170
}
```

### verify

```bash
$ rusk verify --format json
```

```json
{
  "status": "success",
  "exit_code": 0,
  "total": 70,
  "verified": 70,
  "failed": 0,
  "warnings": 0,
  "failures": []
}
```

### audit

```bash
$ rusk audit --strict --format json
```

```json
{
  "status": "error",
  "exit_code": 70,
  "exit_code_name": "audit_failed",
  "total": 70,
  "issues_count": 2,
  "issues": [
    {
      "package": "ms",
      "version": "2.1.3",
      "severity": "warning",
      "message": "package is not signed",
      "remediation": "Contact the package author to sign releases"
    },
    {
      "package": "lodash",
      "version": "4.17.20",
      "severity": "high",
      "message": "Prototype Pollution (https://github.com/advisories/GHSA-...)",
      "remediation": "Upgrade lodash to a version outside <=4.17.20"
    }
  ]
}
```

---

## Frozen lockfile mode

Use `--frozen` to fail if the lockfile is out of date instead of silently updating it. This is what you want in CI:

```bash
rusk install --frozen
```

If the manifest has changed since the lockfile was generated, rusk exits with code 31 (`lockfile_mismatch`) instead of re-resolving. This ensures CI installs are reproducible.

---

## Anomaly webhook

Configure a webhook to receive alerts when rusk detects security anomalies:

```toml
[trust]
require_signatures = true
require_provenance = true
report_url = "https://hooks.slack.com/services/T.../B.../xxx"
```

The report is sent as a fire-and-forget HTTP POST and never blocks the install. The JSON payload includes:

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

Compatible with Slack, PagerDuty, Datadog, or any endpoint that accepts JSON POST requests.

---

## GitHub Actions example

```yaml
name: CI
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install rusk
        run: |
          curl -fsSL https://github.com/harishsg993010/rusk/releases/latest/download/rusk-Linux-x86_64 -o rusk
          chmod +x rusk
          sudo mv rusk /usr/local/bin/

      - name: Install dependencies (frozen)
        run: rusk install --frozen

      - name: Verify integrity
        run: rusk verify --strict

      - name: Security audit
        run: rusk audit --strict --format json

      - name: Run tests
        run: rusk run node --test
```

Key points:
- `--frozen` ensures the lockfile matches the manifest exactly. If someone added a dependency but forgot to commit the updated lockfile, CI fails.
- `rusk verify --strict` confirms installed packages match their lockfile digests.
- `rusk audit --strict` gates on trust policy and known vulnerabilities. Exits 70 if anything fails.

### Caching

Cache the CAS directory to speed up CI installs:

```yaml
      - name: Cache rusk CAS
        uses: actions/cache@v4
        with:
          path: .rusk/cas
          key: rusk-cas-${{ hashFiles('rusk.lock') }}
          restore-keys: rusk-cas-
```

With a warm cache, `rusk install` takes about 1 second for a typical project.

---

## Docker example

```dockerfile
FROM rust:1.75 AS build
RUN cargo install rusk-cli

FROM node:20-slim
COPY --from=build /usr/local/cargo/bin/rusk /usr/local/bin/rusk

WORKDIR /app
COPY rusk.toml rusk.lock package.json ./

# Frozen install: fail if lockfile is stale
RUN rusk install --frozen --production

COPY . .
CMD ["node", "server.js"]
```

Or with a pre-built binary:

```dockerfile
FROM node:20-slim

RUN curl -fsSL https://github.com/harishsg993010/rusk/releases/latest/download/rusk-Linux-x86_64 \
    -o /usr/local/bin/rusk && chmod +x /usr/local/bin/rusk

WORKDIR /app
COPY rusk.toml rusk.lock package.json ./
RUN rusk install --frozen --production

COPY . .
CMD ["node", "server.js"]
```

---

## Strict audit mode for CI gates

Use `rusk audit --strict` as a CI gate. It fails (exit code 70) on any finding -- missing signatures, known vulnerabilities, zero digests:

```bash
# Gate: block the deploy if audit finds anything
rusk audit --strict --format json > audit-results.json
if [ $? -ne 0 ]; then
  echo "Audit failed. See audit-results.json for details."
  cat audit-results.json
  exit 1
fi
```

Combine with a webhook to get Slack notifications:

```toml
[trust]
require_signatures = true
require_provenance = true
report_url = "https://hooks.slack.com/services/T.../B.../xxx"
```

If the audit passes, the JSON output looks like:

```json
{
  "status": "success",
  "exit_code": 0,
  "total": 70,
  "issues_count": 0,
  "issues": []
}
```
