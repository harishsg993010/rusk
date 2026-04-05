# Getting Started

## Installation

### Binary download

Download a prebuilt binary from GitHub releases:

```bash
curl -fsSL https://github.com/harishsg993010/rusk/releases/latest/download/rusk-$(uname -s)-$(uname -m) -o rusk
chmod +x rusk && sudo mv rusk /usr/local/bin/
```

Binaries are available for Linux, macOS, and Windows on both x86_64 and aarch64. See [SECURITY.md](../SECURITY.md) for how to verify the download with minisign.

### cargo install

```bash
cargo install rusk-cli
```

This also registers `cargo rusk` as a subcommand.

### Build from source

Requires Rust 1.75 or later.

```bash
git clone https://github.com/harishsg993010/rusk.git
cd rusk
cargo build --release -p rusk-cli
```

The binary lands at `target/release/rusk` (about 8 MB stripped).

---

## First JavaScript project

```bash
mkdir my-app && cd my-app

# Create a rusk.toml with JS defaults
rusk init --ecosystem js --name my-app

# Add packages
rusk add express@^4.21.0
rusk add vitest@^1.0.0 -D

# Install everything (resolve, download, verify, materialize)
rusk install

# Run your app
rusk run node server.js
```

After `rusk install`, you'll have:
- `rusk.lock` -- lockfile pinning every transitive dependency with SHA-256 digests
- `node_modules/` -- packages materialized via hardlinks from the CAS
- `.rusk/cas/` -- content-addressed store

---

## First Python project

```bash
mkdir my-lib && cd my-lib

# Create a rusk.toml with Python defaults
rusk init --ecosystem python --name my-lib

# Add packages
rusk add "flask>=3.0.0"
rusk add "requests>=2.28.0"

# Create a virtual environment and install
rusk venv
rusk install

# Run your app
rusk run python app.py
```

After install, packages land in `.venv/lib/site-packages/`. The same CAS and lockfile are used for both ecosystems.

---

## Drop into an existing project

rusk auto-detects manifest files. No `rusk.toml` required.

```bash
# Existing Express app
cd my-express-app/           # has package.json
rusk install                 # just works

# Existing Flask app
cd my-flask-app/             # has requirements.txt
rusk install                 # just works

# Existing modern Python library
cd my-modern-lib/            # has pyproject.toml
rusk install                 # just works
```

Detection order: `rusk.toml` > `package.json` > `pyproject.toml` > `requirements.txt`.

When you run `rusk add` in a project with an existing manifest, rusk writes to that manifest directly. `rusk add lodash` in a directory with `package.json` adds to `package.json`. `rusk add "flask>=3.0"` in a directory with `requirements.txt` appends to `requirements.txt`.

---

## Basic trust configuration

By default, rusk verifies SHA-256 digests on every artifact but does not require signatures or provenance. To tighten the policy, add a `[trust]` section to `rusk.toml`:

```toml
[trust]
require_signatures = true
require_provenance = false
```

With `require_signatures = true`, `rusk audit --strict` will fail if any package is unsigned:

```
$ rusk audit --strict
[WARN] ms@2.1.3: package is not signed
error: audit found 1 issue
```

To require provenance attestations (catches attacks like the litellm compromise):

```toml
[trust]
require_signatures = true
require_provenance = true
```

Generate a starter policy file during init:

```bash
rusk init --ecosystem js --with-policy
```

This creates `rusk-policy.toml` alongside `rusk.toml`. See [Configuration](configuration.md) for the full schema and [Security](security.md) for what each setting protects against.
