# Ecosystems

rusk handles JavaScript and Python from a single tool. Both ecosystems share the same CAS, lockfile, verification pipeline, and policy engine. The only ecosystem-specific parts are the registry clients and the file layout materializers.

---

## JavaScript / TypeScript

### npm registry support

rusk speaks the npm registry protocol. It fetches package metadata and tarballs from `https://registry.npmjs.org` by default. Override with `registry_url` in `[js_dependencies]` or with a custom `[registries]` entry.

### node_modules layout

Two modes, controlled by `node_linker` in `[js_dependencies]`:

**Hoisted (default):** Flat node_modules, same as npm. All packages at the top level. Compatible with virtually all JS tooling.

**Isolated:** pnpm-style virtual store with symlinks. Each package only sees its declared dependencies. Catches undeclared dependency usage. Set it with:

```toml
[js_dependencies]
node_linker = "isolated"
```

### package.json auto-detection

If a directory has `package.json` but no `rusk.toml`, rusk reads dependencies directly from `package.json`. `rusk add` writes back to `package.json`. No migration required.

### Git dependencies

```toml
[js_dependencies.dependencies]
my-lib = { version = "*", git = "https://github.com/user/my-lib", branch = "main" }
my-fork = { version = "*", git = "https://github.com/user/my-fork", tag = "v1.2.0" }
```

Also supports the shorthand `github:user/repo` format.

### Optional and peer dependencies

Optional dependencies use warn-and-skip semantics. If resolution or download fails for an optional dependency, rusk logs a warning and continues.

Peer dependencies are declared in `[js_dependencies.peer_dependencies]` and resolved against the consumer's dependency tree.

### Binary shims

Packages that declare `bin` entries in their package.json get executables linked into `node_modules/.bin/`. These are available when you run commands via `rusk run`.

### Lifecycle scripts

**Disabled by default.** npm's `preinstall`, `install`, `postinstall`, `prepare` scripts do not run unless explicitly allowed. This prevents install-time code execution attacks. If you need lifecycle scripts, run them through `rusk build` with sandbox isolation.

### .npmrc auth

rusk reads `.npmrc` for registry authentication tokens with environment variable expansion:

```ini
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
//npm.internal.company.com/:_authToken=${INTERNAL_NPM_TOKEN}
```

Lookup order: project `.npmrc` > user `~/.npmrc`.

### Overrides

Force a specific version of a transitive dependency:

```toml
[js_dependencies.overrides]
semver = "7.6.0"
```

This is equivalent to npm's `overrides` or yarn's `resolutions`.

### Patching

Modify an installed package and save the diff:

```bash
rusk patch express           # copy to .rusk/patches/express/
# edit files...
rusk patch express --commit  # save patches/express.patch
```

The patch is recorded in `[js_dependencies.patched_dependencies]` and re-applied on future installs.

---

## Python

### PyPI registry support

rusk fetches packages from `https://pypi.org/simple/` using the PEP 503 Simple Repository API. Override with `index_url` in `[python_dependencies]`.

### Custom index URLs

Add extra indexes for packages hosted outside PyPI. Common use case -- PyTorch CPU wheels:

```toml
[python_dependencies]
index_url = "https://pypi.org/simple/"
extra_index_urls = ["https://download.pytorch.org/whl/cpu"]

[python_dependencies.dependencies]
torch = ">=2.0"
```

### PEP 503 Simple API support

rusk implements the PEP 503 Simple Repository API for discovering package versions and downloading artifacts. Compatible with PyPI, Artifactory, devpi, and any compliant index.

### Wheel platform filtering

rusk selects the correct wheel for your platform by matching:

- **OS:** Linux (manylinux), macOS, Windows
- **Architecture:** x86_64, aarch64
- **Python version:** cp39, cp310, cp311, cp312, etc.

If no matching wheel is found, rusk falls back to source distributions when available.

### .venv/lib/site-packages layout

Python packages are materialized into `.venv/lib/site-packages/` using hardlinks from the CAS. This is the standard layout that Python expects. The `.venv` is a real virtual environment -- you can activate it and use it with any Python tool.

### requirements.txt support

rusk reads `requirements.txt` directly:

```
flask>=3.0.0
requests>=2.28.0,<3
gunicorn>=21.0
```

`rusk add "new-package>=1.0"` appends to the file. `rusk remove old-package` removes the matching line.

### pyproject.toml support

rusk reads PEP 621 `[project.dependencies]` and `[project.optional-dependencies]` from `pyproject.toml`. It also understands Poetry-style `[tool.poetry.dependencies]`.

```toml
[project]
name = "my-lib"
requires-python = ">=3.9"
dependencies = [
    "flask>=3.0.0",
    "requests>=2.28.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.0", "black"]
```

### Virtual environment creation

```bash
rusk venv                    # creates .venv/ with default python3
rusk venv --python 3.11      # specific version
rusk venv myenv              # custom path
```

### Tool management

Run Python CLI tools without installing them into your project:

```bash
# One-off execution (cached venv)
rusk x black --check .
rusk x ruff check src/

# Persistent install to ~/.rusk/bin/
rusk tool install black
rusk tool install ruff

# List and remove
rusk tool list
rusk tool uninstall black
```

Tool venvs are isolated from your project. Each tool gets its own venv at `~/.rusk/tools/<package>/`.

---

## Mixed projects

A single `rusk.toml` can declare both JS and Python dependencies:

```toml
[package]
name = "full-stack-app"
version = "0.1.0"
ecosystem = "js"                # primary ecosystem

[js_dependencies.dependencies]
express = "^4.21.0"
cors = "^2.8.5"

[python_dependencies]
requires_python = ">=3.11"

[python_dependencies.dependencies]
flask = ">=3.0.0"
celery = ">=5.3.0"
```

`rusk install` resolves and installs both ecosystems. JS packages go to `node_modules/`, Python packages go to `.venv/lib/site-packages/`. Both share the same CAS, lockfile, and security pipeline.

`rusk add` uses the primary ecosystem by default. Override with `--ecosystem`:

```bash
rusk add lodash               # goes to js_dependencies (primary is js)
rusk add "redis>=5.0" --ecosystem python  # goes to python_dependencies
```
