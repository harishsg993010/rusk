use rusk_core::Sha256Digest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors during Merkle inclusion proof verification.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("proof verification failed: computed root {computed} does not match expected {expected}")]
    RootMismatch { computed: String, expected: String },

    #[error("invalid proof: leaf index {index} out of range for tree of size {tree_size}")]
    IndexOutOfRange { index: u64, tree_size: u64 },

    #[error("invalid proof: expected {expected} hashes, got {actual}")]
    WrongPathLength { expected: usize, actual: usize },

    #[error("empty proof")]
    EmptyProof,
}

/// Which side of the Merkle path a sibling hash is on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathDirection {
    Left,
    Right,
}

/// A single step in the Merkle inclusion proof path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathEntry {
    /// The sibling hash at this tree level.
    pub hash: Sha256Digest,
    /// Which side the sibling is on (determines hash ordering).
    pub direction: PathDirection,
}

/// A Merkle tree inclusion proof demonstrating that a leaf is part of a
/// committed tree with a known root hash.
///
/// This follows the RFC 6962 style used by transparency logs (Certificate
/// Transparency, Sigstore Rekor, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Index of the leaf in the tree (0-based).
    pub leaf_index: u64,
    /// Total number of leaves in the tree at the time of this proof.
    pub tree_size: u64,
    /// The expected root hash of the Merkle tree.
    pub root_hash: Sha256Digest,
    /// The hash of the leaf entry.
    pub leaf_hash: Sha256Digest,
    /// Sibling hashes along the path from the leaf to the root.
    pub proof_path: Vec<PathEntry>,
}

impl InclusionProof {
    /// Verify this inclusion proof: recompute the root from the leaf and path,
    /// then compare against the expected root hash.
    pub fn verify(&self) -> Result<(), ProofError> {
        verify_merkle_inclusion(
            &self.leaf_hash,
            self.leaf_index,
            self.tree_size,
            &self.proof_path,
            &self.root_hash,
        )
    }
}

/// Verify a Merkle inclusion proof.
///
/// Starting from `leaf_hash`, walk up the tree using the provided `proof_path`,
/// hashing siblings together at each level. The final computed hash must match
/// `expected_root`.
///
/// At each level, the domain separator byte `0x01` is prepended to internal
/// node hashes (per RFC 6962), while leaf hashes use `0x00`.
pub fn verify_merkle_inclusion(
    leaf_hash: &Sha256Digest,
    leaf_index: u64,
    tree_size: u64,
    proof_path: &[PathEntry],
    expected_root: &Sha256Digest,
) -> Result<(), ProofError> {
    if tree_size == 0 {
        return Err(ProofError::EmptyProof);
    }

    if leaf_index >= tree_size {
        return Err(ProofError::IndexOutOfRange {
            index: leaf_index,
            tree_size,
        });
    }

    // Verify expected path length: for a tree of size N, the path should be
    // at most ceil(log2(N)) entries.
    let max_path_len = if tree_size <= 1 {
        0
    } else {
        (64 - (tree_size - 1).leading_zeros()) as usize
    };
    if proof_path.len() > max_path_len {
        return Err(ProofError::WrongPathLength {
            expected: max_path_len,
            actual: proof_path.len(),
        });
    }

    // Walk up the tree, combining hashes at each level.
    let mut current_hash = *leaf_hash;

    for entry in proof_path {
        current_hash = hash_internal_node(&current_hash, &entry.hash, entry.direction);
    }

    if current_hash != *expected_root {
        return Err(ProofError::RootMismatch {
            computed: current_hash.to_hex(),
            expected: expected_root.to_hex(),
        });
    }

    Ok(())
}

/// Hash a leaf value with the `0x00` domain separator per RFC 6962.
pub fn hash_leaf(data: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update([0x00]); // Leaf node domain separator
    hasher.update(data);
    let result = hasher.finalize();
    Sha256Digest(result.into())
}

/// Hash two child nodes into a parent node with the `0x01` domain separator.
///
/// `direction` indicates where `sibling` is relative to `current`:
/// - `Left`: sibling is the left child, current is the right child
/// - `Right`: sibling is the right child, current is the left child
fn hash_internal_node(
    current: &Sha256Digest,
    sibling: &Sha256Digest,
    direction: PathDirection,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update([0x01]); // Internal node domain separator
    match direction {
        PathDirection::Left => {
            hasher.update(sibling.0);
            hasher.update(current.0);
        }
        PathDirection::Right => {
            hasher.update(current.0);
            hasher.update(sibling.0);
        }
    }
    let result = hasher.finalize();
    Sha256Digest(result.into())
}

/// Build a simple Merkle tree from a list of leaf data and return the root hash.
///
/// This is a utility for testing; production trees would be maintained by the
/// transparency log server.
pub fn build_merkle_tree(leaves: &[&[u8]]) -> Option<Sha256Digest> {
    if leaves.is_empty() {
        return None;
    }

    let mut current_level: Vec<Sha256Digest> = leaves.iter().map(|l| hash_leaf(l)).collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let parent = hash_internal_node(
                    &current_level[i],
                    &current_level[i + 1],
                    PathDirection::Right,
                );
                next_level.push(parent);
            } else {
                // Odd node: promote to next level.
                next_level.push(current_level[i]);
            }
            i += 2;
        }
        current_level = next_level;
    }

    Some(current_level[0])
}

/// Build a Merkle tree and generate an inclusion proof for the leaf at `index`.
pub fn build_proof(leaves: &[&[u8]], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() || leaves.is_empty() {
        return None;
    }

    let leaf_hash = hash_leaf(leaves[index]);
    let mut current_level: Vec<Sha256Digest> = leaves.iter().map(|l| hash_leaf(l)).collect();
    let mut proof_path = Vec::new();
    let mut current_index = index;

    while current_level.len() > 1 {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        if sibling_index < current_level.len() {
            let direction = if current_index % 2 == 0 {
                PathDirection::Right
            } else {
                PathDirection::Left
            };
            proof_path.push(PathEntry {
                hash: current_level[sibling_index],
                direction,
            });
        }

        // Build next level.
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let parent = hash_internal_node(
                    &current_level[i],
                    &current_level[i + 1],
                    PathDirection::Right,
                );
                next_level.push(parent);
            } else {
                next_level.push(current_level[i]);
            }
            i += 2;
        }

        current_index /= 2;
        current_level = next_level;
    }

    let root_hash = current_level[0];

    Some(InclusionProof {
        leaf_index: index as u64,
        tree_size: leaves.len() as u64,
        root_hash,
        leaf_hash,
        proof_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_tree() {
        let root = build_merkle_tree(&[b"hello"]).unwrap();
        let leaf = hash_leaf(b"hello");
        assert_eq!(root, leaf);
    }

    #[test]
    fn two_leaf_tree() {
        let root = build_merkle_tree(&[b"a", b"b"]).unwrap();
        let ha = hash_leaf(b"a");
        let hb = hash_leaf(b"b");
        let expected = hash_internal_node(&ha, &hb, PathDirection::Right);
        assert_eq!(root, expected);
    }

    #[test]
    fn proof_verification_two_leaves() {
        let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1"];

        let proof = build_proof(&leaves, 0).unwrap();
        assert!(proof.verify().is_ok());

        let proof1 = build_proof(&leaves, 1).unwrap();
        assert!(proof1.verify().is_ok());
    }

    #[test]
    fn proof_verification_four_leaves() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];

        for i in 0..4 {
            let proof = build_proof(&leaves, i).unwrap();
            assert!(
                proof.verify().is_ok(),
                "proof failed for leaf index {i}"
            );
        }
    }

    #[test]
    fn proof_verification_odd_tree() {
        let leaves: Vec<&[u8]> = vec![b"x", b"y", b"z"];

        for i in 0..3 {
            let proof = build_proof(&leaves, i).unwrap();
            assert!(
                proof.verify().is_ok(),
                "proof failed for leaf index {i}"
            );
        }
    }

    #[test]
    fn tampered_proof_fails() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let mut proof = build_proof(&leaves, 1).unwrap();

        // Tamper with the root hash.
        proof.root_hash = Sha256Digest::zero();

        assert!(proof.verify().is_err());
    }

    #[test]
    fn out_of_range_index() {
        let result = verify_merkle_inclusion(
            &Sha256Digest::zero(),
            10,
            5,
            &[],
            &Sha256Digest::zero(),
        );
        assert!(matches!(result, Err(ProofError::IndexOutOfRange { .. })));
    }

    #[test]
    fn leaf_hash_domain_separation() {
        // Leaf hash should differ from raw SHA-256 due to domain separator.
        let data = b"test";
        let leaf = hash_leaf(data);
        let raw = Sha256Digest::compute(data);
        assert_ne!(leaf, raw);
    }
}
