# Commands Reference

All commands support `--format json` for machine-readable output and `-v` / `-vv` / `-vvv` for increasing verbosity.

Run `rusk --exit-codes` to print the full table of structured exit codes (see [CI/CD](ci-cd.md)).

---

## install

Resolve, download, verify, and materialize dependencies.

```
rusk install [OPTIONS] [PACKAGES...]
```

| Flag | Description |
|------|-------------|
| `--frozen` | Fail if lockfile is out of date instead of updating it |
| `--production` | Skip dev dependencies |
| `--lockfile-only` | Install exactly what the lockfile says, skip resolution |
| `--format json` | JSON output |

**Examples:**

```bash
# Standard install
rusk install

# CI mode: fail if lockfile is stale
rusk install --frozen

# Production deploy: skip devDependencies
rusk install --production

# JSON output for scripting
rusk install --format json
```

**Output (text):**
```
Installed 70 packages (70 cached) in 1.0s
  Materialized JS packages to node_modules/
```

**Output (JSON):**
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

---

## add

Add packages to the manifest and install them.

```
rusk add <PACKAGES...> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `-D`, `--dev` | Add as a dev dependency |
| `--ecosystem <js\|python>` | Force ecosystem (auto-detected if omitted) |

rusk auto-detects the ecosystem from the package spec format and existing manifest files.

**Examples:**

```bash
# npm-style
rusk add express@^4.21.0
rusk add vitest@^1.0.0 -D

# pip-style
rusk add "requests>=2.28.0"
rusk add "flask>=3.0.0"

# Bare name (latest version)
rusk add lodash

# Force ecosystem when ambiguous
rusk add six --ecosystem python
```

rusk validates that the package spec matches the target ecosystem. If you write `rusk add "requests>=2.28"` in a JS project, it warns you.

---

## remove

Remove packages from the manifest, lockfile, and disk.

```
rusk remove <PACKAGES...>
```

**Examples:**

```bash
rusk remove lodash
rusk remove express cors
```

Removes from whichever manifest exists (rusk.toml, package.json, pyproject.toml, or requirements.txt), deletes the entry from rusk.lock, and removes the package directory from node_modules/ or site-packages/.

---

## update

Re-resolve dependencies and update the lockfile.

```
rusk update [PACKAGES...] [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--major` | Allow major version updates |
| `--dry-run` | Show what would change without modifying anything |

**Examples:**

```bash
# Update everything
rusk update

# Update specific packages
rusk update express lodash

# Preview changes
rusk update --dry-run
```

---

## lock

Resolve dependencies and write `rusk.lock` without installing.

```
rusk lock [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--production` | Only lock production dependencies |

**Example:**

```bash
rusk lock
# Locked 70 packages to rusk.lock in 3.2s
```

Useful when you want to generate or update the lockfile without materializing packages to disk.

---

## sync

Install from lockfile and remove extraneous packages.

```
rusk sync [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--frozen` | Fail if lockfile is out of date |
| `--production` | Skip dev dependencies |

**Example:**

```bash
rusk sync
# Synced 70 packages in 1.1s
#   Removed 3 extraneous packages
```

Like `rusk install`, but also deletes any packages in node_modules/ or site-packages/ that are not in the lockfile.

---

## run

Run a command with ecosystem environment variables set.

```
rusk run <COMMAND> [ARGS...]
```

For JS projects, sets `NODE_PATH`. For Python projects, sets `PYTHONPATH`. Auto-detects from the manifest or file extension.

**Examples:**

```bash
# Explicit runtime
rusk run node server.js
rusk run python app.py

# Auto-detected from extension
rusk run server.js          # runs with node
rusk run app.py             # runs with python
rusk run app.ts             # runs via npx tsx

# Arbitrary command
rusk run some-binary --flag
```

---

## list

List installed packages.

```
rusk list [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--output json` | JSON output |

**Output (text):**
```
Package                  Version      Ecosystem
--------------------------------------------------
accepts                  1.3.8        js
body-parser              1.20.2       js
express                  4.21.2       js
...
70 packages total
```

**Output (JSON):**
```json
[
  { "name": "express", "version": "4.21.2", "ecosystem": "js" },
  { "name": "ms", "version": "2.1.3", "ecosystem": "js" }
]
```

---

## tree

Display the dependency tree.

```
rusk tree [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--depth <N>` | Maximum nesting depth (0 = direct deps only) |
| `--output json` | JSON output |

**Output (text):**
```
express@4.21.2
├── accepts@1.3.8
│   ├── mime-types@2.1.35
│   │   └── mime-db@1.52.0
│   └── negotiator@0.6.3
├── body-parser@1.20.2
│   ├── bytes@3.1.2
│   ├── content-type@1.0.5
...
```

**Example:**

```bash
# Direct dependencies only
rusk tree --depth 0

# Full tree as JSON
rusk tree --output json
```

---

## verify

Check that installed packages match their lockfile digests.

```
rusk verify [PACKAGES...] [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--strict` | Fail on missing signatures or provenance |
| `--detailed` | Show per-package verification results |

**Example:**

```bash
$ rusk verify --detailed
  OK  ms@2.1.3 (sha256:a101155c3cbdfb1e...)
  OK  express@4.21.2 (sha256:7b75c105719...)
Verified 70/70 packages: 70 passed, 0 failed
```

**JSON output:**
```json
{
  "status": "success",
  "total": 70,
  "verified": 70,
  "failed": 0,
  "warnings": 0,
  "failures": []
}
```

---

## audit

Evaluate the trust policy and scan for known vulnerabilities.

```
rusk audit [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--strict` | Exit with error on any warnings (not just errors) |
| `--report <FORMAT>` | `summary` (default), `full`, or `json` |
| `--format json` | Equivalent to `--report json` |

**Examples:**

```bash
# Quick summary
rusk audit

# Full detail with remediations
rusk audit --report full

# CI gate: fail on any issue
rusk audit --strict

# Machine-readable
rusk audit --format json
```

**Output (strict mode, text):**
```
Audited 70 packages
[WARN] ms@2.1.3: package is not signed
error: audit found 1 issue
```

**Output (JSON):**
```json
{
  "status": "error",
  "exit_code": 70,
  "total": 70,
  "issues_count": 1,
  "issues": [
    {
      "package": "ms",
      "version": "2.1.3",
      "severity": "warning",
      "message": "package is not signed",
      "remediation": "Contact the package author to sign releases"
    }
  ]
}
```

---

## explain

Show why a package was allowed or blocked by the policy engine.

```
rusk explain <PACKAGE> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--trace` | Show the full evaluation trace |

**Example:**

```bash
$ rusk explain express --trace
Package: express@4.21.2
Ecosystem: js
Digest: sha256:7b75c105719...

Policy evaluation:
  - Signatures not required by policy
  + Package has valid digest

Verdict: ALLOW - package is trusted

Full evaluation trace:
  1. Load trust config from rusk.toml
  2. Look up express@4.21.2 in lockfile
  3. Check signature requirement: not required
  4. Check provenance requirement: not required
  5. Check digest integrity: OK
  6. Final verdict: ALLOW
```

---

## init

Create a new rusk project.

```
rusk init [PATH] [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--ecosystem <js\|python>` | Ecosystem (default: js) |
| `--name <NAME>` | Project name (default: directory name) |
| `--with-policy` | Generate a starter rusk-policy.toml |

**Examples:**

```bash
# JS project in current directory
rusk init --ecosystem js

# Python project in a new directory
rusk init my-lib --ecosystem python --name my-lib

# With a trust policy template
rusk init --ecosystem js --with-policy
```

Creates `rusk.toml`, `.rusk/` directory, and optionally `rusk-policy.toml`.

---

## migrate

Import dependencies from a foreign lockfile.

```
rusk migrate [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--from <npm\|yarn\|pnpm>` | Source format (auto-detected if omitted) |

**Examples:**

```bash
# Auto-detect
rusk migrate

# Explicit source
rusk migrate --from yarn
```

Auto-detection order: `package-lock.json` > `yarn.lock` > `pnpm-lock.yaml`.

Generates a `rusk.toml` with all dependencies pinned to the versions from the foreign lockfile. Run `rusk install` afterwards to create `rusk.lock`.

---

## patch

Modify an installed package and save the changes as a patch.

```
rusk patch <PACKAGE> [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--commit` | Generate a diff and save it as a patch file |

**Workflow:**

```bash
# Step 1: Copy the package for editing
rusk patch express
# Package copied to .rusk/patches/express/

# Step 2: Edit files in .rusk/patches/express/
# (make your changes)

# Step 3: Commit the patch
rusk patch express --commit
# Patch saved to patches/express.patch
```

The patch is recorded in `[js_dependencies.patched_dependencies]` in rusk.toml so future installs re-apply it.

---

## link

Register or consume local package symlinks for development.

```
rusk link [PACKAGE]
```

**Workflow:**

```bash
# In the library directory: register it
cd my-library/
rusk link
# Registered my-library -> /home/user/my-library

# In the consuming project: link it
cd my-app/
rusk link my-library
# Linked my-library -> /home/user/my-library
```

Creates a symlink (junction on Windows) in node_modules/ pointing to the registered path.

---

## venv

Create a Python virtual environment.

```
rusk venv [PATH] [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--python <INTERPRETER>` | Python interpreter to use (e.g., python3.11) |

**Examples:**

```bash
# Default: creates .venv/
rusk venv

# Custom path
rusk venv myenv

# Specific Python version
rusk venv --python python3.11
```

---

## gc

Clean up unreferenced blobs from the content-addressed store.

```
rusk gc [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be deleted without deleting |
| `--verify` | Run integrity verification on remaining blobs |

**Example:**

```bash
$ rusk gc --dry-run
CAS store: 142 blobs, 48.3 MB total
Referenced: 70 blobs
Unreferenced: 72 blobs (23.1 MB)
gc dry-run complete: would reclaim 23.1 MB

$ rusk gc
gc complete: deleted 72 blobs, reclaimed 23.1 MB
```

---

## config

View or modify rusk configuration.

```
rusk config [KEY] [VALUE] [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--list` | List all configuration values |
| `--reset` | Reset to defaults |

**Examples:**

```bash
# List all config
rusk config --list

# Read a value
rusk config cache_dir

# Set a value
rusk config max_concurrent_downloads 32

# Reset to defaults
rusk config --reset
```

Config file location:
- Linux/macOS: `~/.config/rusk/config.toml`
- Windows: `%LOCALAPPDATA%\rusk\config.toml`

Available keys: `cache_dir`, `max_concurrent_downloads`, `default_registry`, `color`, `progress`.

---

## build

Run build scripts in a sandboxed environment.

```
rusk build [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--script <SCRIPT>` | Build script to run (default: from manifest `[build]`) |
| `--no-sandbox` | Skip sandbox isolation (for debugging only) |
| `--provenance` | Generate provenance attestation for the build output |

**Example:**

```bash
$ rusk build
Running in sandbox: npm run build
Sandbox capabilities:
  network: DENIED
  host filesystem: DENIED
  host secrets: DENIED (env scrubbed)
build complete in 4.2s (sandboxed)
```

The sandbox strips environment variables (no AWS keys, no npm tokens leak into build scripts), blocks network access, and restricts filesystem reads.

---

## publish

Validate and publish a package to a registry.

```
rusk publish [OPTIONS]
```

| Flag | Description |
|------|-------------|
| `--registry <URL>` | Target registry URL |
| `--dry-run` | Validate without publishing |
| `--sign` | Sign the artifact |

**Example:**

```bash
# Validate the package
rusk publish --dry-run
# publish dry-run complete: my-app@0.1.0 is valid

# Publish (not yet supported for most registries)
rusk publish
```

Note: Full publish support requires registry-specific API integration. Use `npm publish` or `twine upload` for now. The `--dry-run` mode is useful for validating your manifest.

---

## python list

Discover Python installations on the system.

```
rusk python list
```

**Output:**
```
Python 3.12.1           /usr/bin/python3.12 (default)
Python 3.11.9           /usr/bin/python3.11
Python 3.10.14          /usr/bin/python3.10
```

On Windows, also queries the `py` launcher.

---

## python find

Find a Python interpreter matching a version constraint.

```
rusk python find <VERSION>
```

**Example:**

```bash
$ rusk python find 3.11
Found Python 3.11.9 at /usr/bin/python3.11
```

---

## python pin

Write a `.python-version` file.

```
rusk python pin <VERSION>
```

**Example:**

```bash
$ rusk python pin 3.12
Pinned Python version to 3.12 (wrote .python-version)
```

---

## tool run

Run a Python CLI tool in an isolated virtual environment.

```
rusk tool run <PACKAGE> [ARGS...]
```

**Example:**

```bash
rusk tool run black --check .
rusk tool run ruff check src/
rusk tool run mypy src/
```

The tool's venv is cached at `~/.rusk/tools/<package>/`. First run creates the venv and installs the package; subsequent runs reuse it.

---

## tool install

Persistently install a Python CLI tool.

```
rusk tool install <PACKAGE>
```

**Example:**

```bash
$ rusk tool install black
Installed 'black' to ~/.rusk/bin/black
  Make sure ~/.rusk/bin is on your PATH
```

---

## tool uninstall

Remove a previously installed tool.

```
rusk tool uninstall <PACKAGE>
```

---

## tool list

List installed tools.

```
rusk tool list
```

**Output:**
```
TOOL                 PATH
------------------------------------------------------------
black                ~/.rusk/tools/black (installed)
ruff                 ~/.rusk/tools/ruff (installed)
```

---

## x

Shorthand for `rusk tool run`.

```
rusk x <PACKAGE> [ARGS...]
```

**Example:**

```bash
# These are equivalent:
rusk x black --check .
rusk tool run black --check .
```
