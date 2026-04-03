#!/bin/bash
# Sign release binaries with minisign
# Usage: ./scripts/sign-release.sh <binary-path>
#
# This produces a .minisig signature file alongside the binary.
# The public key is published at:
#   - This repository's SECURITY.md
#   - https://keys.openpgp.org (for independent verification)
#   - The rusk crates.io package metadata

set -euo pipefail

BINARY="$1"
if [ -z "$BINARY" ]; then
    echo "Usage: $0 <binary-path>"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "Error: file not found: $BINARY"
    exit 1
fi

# Sign with minisign (ed25519-based, like signify)
if command -v minisign &> /dev/null; then
    minisign -Sm "$BINARY" -t "rusk release $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Signed: ${BINARY}.minisig"
else
    echo "minisign not found. Install: https://jedisct1.github.io/minisign/"
    echo "Falling back to sha256sum only..."
fi

# Always produce a SHA-256 checksum
sha256sum "$BINARY" > "${BINARY}.sha256"
echo "Checksum: ${BINARY}.sha256"
