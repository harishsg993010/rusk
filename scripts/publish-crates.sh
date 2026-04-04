#!/bin/bash
# Publish all rusk crates to crates.io in dependency order.
# Run this after rate limit resets.
# Usage: bash scripts/publish-crates.sh

set -e

DELAY=10  # seconds between publishes to avoid rate limits

publish() {
    local crate=$1
    echo "=== Publishing $crate ==="
    if cargo publish -p "$crate" 2>&1 | grep -q "already uploaded"; then
        echo "  SKIP (already published)"
    else
        echo "  Published"
    fi
    sleep $DELAY
}

# Already published: rusk-core, rusk-observability, rusk-tuf, rusk-signing, rusk-revocation

# Layer 2: depend only on rusk-core
publish rusk-cas
publish rusk-transparency
publish rusk-manifest
publish rusk-lockfile
publish rusk-sandbox

# Layer 3: depend on layer 2
publish rusk-registry
publish rusk-policy
publish rusk-provenance
publish rusk-transport
publish rusk-materialize

# Layer 4: depend on layer 3
publish rusk-registry-npm
publish rusk-registry-pypi
publish rusk-resolver
publish rusk-materialize-js
publish rusk-materialize-python

# Layer 5: depend on layer 4
publish rusk-resolver-js
publish rusk-resolver-python
publish rusk-enterprise

# Layer 6: depends on everything
publish rusk-orchestrator

# Layer 7: the CLI binary
publish rusk-cli

echo ""
echo "=== All crates published ==="
echo "Users can now run: cargo install rusk-cli"
