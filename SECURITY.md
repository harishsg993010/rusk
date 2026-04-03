# Verifying rusk releases

## Why not just trust GitHub releases?

Any repository admin can modify release assets and update the checksum file
to match a modified binary. The SHA-256 file sitting next to the binary on
GitHub proves nothing if the attacker has repo write access.

## How to verify

rusk releases are signed with minisign (Ed25519). The public key is:

    RWQ... (placeholder - generated on first release)

This key is published in three independent locations:
1. This file (SECURITY.md) in the repository
2. The rusk crate on crates.io (immutable after publish)
3. https://keys.openpgp.org

To verify a downloaded binary:

    minisign -Vm rusk-Linux-x86_64 -P RWQ...

If the signature is valid, the binary has not been tampered with since
the maintainer signed it, regardless of what happened to the GitHub release.

## Reporting vulnerabilities

If you find a security issue in rusk, please email security@rusk.dev
or open a GitHub security advisory.
