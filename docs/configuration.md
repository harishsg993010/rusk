# Configuration

## rusk.toml

The primary manifest file. Here's a complete example showing all fields:

```toml
[package]
name = "my-app"
version = "0.1.0"
ecosystem = "js"                      # "js" or "python"
description = "My application"
authors = ["Your Name <you@example.com>"]
license = "MIT"
repository = "https://github.com/user/my-app"
homepage = "https://my-app.dev"
keywords = ["web", "api"]

# ──────────────────────────────────────
# JavaScript dependencies
# ──────────────────────────────────────

[js_dependencies.dependencies]
express = "^4.21.0"
cors = "^2.8.5"
lodash = { version = "^4.17.21", optional = true }

# Git dependency
my-lib = { version = "*", git = "https://github.com/user/my-lib", branch = "main" }

[js_dependencies.dev_dependencies]
vitest = "^1.0.0"

[js_dependencies.peer_dependencies]
react = "^18.0.0"

[js_dependencies.optional_dependencies]
fsevents = "^2.3.0"

# Override a transitive dependency's version
[js_dependencies.overrides]
semver = "7.6.0"

# Patches applied after install
[js_dependencies.patched_dependencies]
express = "patches/express.patch"

# Registry and layout
# registry_url = "https://registry.npmjs.org"  # default
# node_linker = "hoisted"                       # "hoisted" (default) or "isolated"

# ──────────────────────────────────────
# Python dependencies
# ──────────────────────────────────────

[python_dependencies]
requires_python = ">=3.9"
# index_url = "https://pypi.org/simple/"        # default
# extra_index_urls = ["https://download.pytorch.org/whl/cpu"]

[python_dependencies.dependencies]
flask = ">=3.0.0"
requests = { version = ">=2.28.0", features = ["security"] }

[python_dependencies.dev_dependencies]
pytest = ">=7.0"

[python_dependencies.extras]
dev = ["pytest>=7.0", "black"]
docs = ["sphinx>=7.0"]

# ──────────────────────────────────────
# Trust policy
# ──────────────────────────────────────

[trust]
require_signatures = false             # Require cryptographic signatures
require_provenance = false             # Require build provenance attestations
require_transparency = false           # Require transparency log inclusion
report_url = ""                        # Webhook URL for anomaly reports
trusted_signers = []                   # Allowed signer identities
trusted_builders = []                  # Allowed builder identities (for provenance)
# quarantine_hours = 72                # Hold new packages for N hours
# policy = "rusk-policy.toml"          # Path to external policy file

# ──────────────────────────────────────
# Build configuration
# ──────────────────────────────────────

[build]
script = "npm run build"
sandbox = true
env = { NODE_ENV = "production" }
pre_build = ["rusk install --production"]
post_build = ["echo done"]

# ──────────────────────────────────────
# Custom registries
# ──────────────────────────────────────

[registries.internal]
url = "https://npm.internal.company.com"
registry_type = "public"               # "public" or "internal"
auth_token_env = "INTERNAL_NPM_TOKEN"  # Environment variable holding the token
tuf = false

# ──────────────────────────────────────
# Workspace (monorepo)
# ──────────────────────────────────────

[workspace]
members = ["packages/*"]
exclude = ["packages/internal-only"]
shared_dependencies = { lodash = "^4.17.21" }
```

---

## [package] section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Package name |
| `version` | string | no | Package version |
| `ecosystem` | `"js"` or `"python"` | yes | Primary ecosystem |
| `description` | string | no | Human-readable description |
| `authors` | string[] | no | Author names/emails |
| `license` | string | no | SPDX license identifier |
| `repository` | string | no | Source repository URL |
| `homepage` | string | no | Project homepage URL |
| `keywords` | string[] | no | Discovery keywords |

---

## [js_dependencies] section

### dependencies / dev_dependencies / peer_dependencies / optional_dependencies

Each is a table mapping package names to version specifiers. Values can be:

**Simple string:**
```toml
express = "^4.21.0"
```

**Detailed entry:**
```toml
my-lib = { version = "^1.0.0", git = "https://github.com/user/my-lib", branch = "main" }
lodash = { version = "^4.17.21", optional = true }
```

Detailed entry fields:
- `version` (required) -- version requirement
- `registry` -- override registry for this dependency
- `optional` -- treat as optional (warn instead of fail on resolution errors)
- `features` -- features/extras to enable
- `git` -- Git repository URL
- `branch` -- Git branch
- `tag` -- Git tag

### registry_url

Override the npm registry URL for this project. Default: `https://registry.npmjs.org`.

### overrides

Force specific versions of transitive dependencies. Same concept as npm overrides or yarn resolutions.

```toml
[js_dependencies.overrides]
semver = "7.6.0"
```

### patched_dependencies

Map package names to patch files. Patches are applied after install. Create patches with `rusk patch`.

```toml
[js_dependencies.patched_dependencies]
express = "patches/express.patch"
```

### node_linker

Controls node_modules layout:
- `"hoisted"` (default) -- flat node_modules, compatible with most tools
- `"isolated"` -- pnpm-style virtual store with symlinks, stricter correctness

---

## [python_dependencies] section

### dependencies / dev_dependencies

Same format as JS dependencies, but version strings follow PEP 440:

```toml
[python_dependencies.dependencies]
flask = ">=3.0.0"
requests = ">=2.28,<3"
numpy = "==1.26.4"
```

### extras

Optional dependency groups, matching pyproject.toml `[project.optional-dependencies]`:

```toml
[python_dependencies.extras]
dev = ["pytest>=7.0", "black"]
docs = ["sphinx>=7.0", "sphinx-rtd-theme"]
```

### requires_python

Minimum Python version:

```toml
requires_python = ">=3.9"
```

### index_url

Override the primary PyPI index. Default: `https://pypi.org/simple/`.

```toml
index_url = "https://pypi.internal.company.com/simple/"
```

### extra_index_urls

Additional indexes to search. Useful for packages hosted outside PyPI:

```toml
extra_index_urls = ["https://download.pytorch.org/whl/cpu"]
```

---

## [trust] section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `require_signatures` | bool | `false` | Require cryptographic signatures on all packages |
| `require_provenance` | bool | `false` | Require build provenance attestations |
| `require_transparency` | bool | `false` | Require transparency log inclusion proof |
| `report_url` | string | `""` | Webhook URL for anomaly reports (fire-and-forget HTTP POST) |
| `trusted_signers` | string[] | `[]` | Allowed signer identities |
| `trusted_builders` | string[] | `[]` | Allowed builder identities |
| `quarantine_hours` | int | none | Hold new packages for N hours before allowing install |
| `policy` | string | none | Path to external policy file |

See [Security](security.md) for what each setting protects against.

---

## [build] section

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `script` | string | none | Build command to run |
| `sandbox` | bool | `false` | Run in sandboxed environment |
| `env` | table | `{}` | Environment variables passed to the build |
| `pre_build` | string[] | `[]` | Commands to run before the build |
| `post_build` | string[] | `[]` | Commands to run after the build |

---

## .npmrc auth tokens

rusk reads `.npmrc` files for registry authentication, supporting environment variable expansion:

```ini
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
//npm.internal.company.com/:_authToken=${INTERNAL_NPM_TOKEN}
```

Lookup order: project `.npmrc` > user `~/.npmrc`.

---

## Environment variables

| Variable | Description |
|----------|-------------|
| `RUSK_CACHE_DIR` | Override the global cache directory |
| `NO_COLOR` | Disable colored output (any value) |
| `RUSK_LOG` | Set log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `NPM_TOKEN` | npm registry auth token |
| `INTERNAL_NPM_TOKEN` | (example) Custom registry auth token, referenced from `.npmrc` |

The global config file (`rusk config --list`) can also set `cache_dir`, `max_concurrent_downloads`, `default_registry`, `color`, and `progress`.
