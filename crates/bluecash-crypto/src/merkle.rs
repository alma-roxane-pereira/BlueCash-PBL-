//! RFC 6962 / RFC 9162 Merkle tree, as used by the mint's public audit log.
//!
//! `API_CONTRACT.md` fixes the construction:
//!
//! > RFC 6962/9162: leaf = SHA256(0x00‖data), node = SHA256(0x01‖left‖right),
//! > split at the largest power of two < n
//!
//! The distinct `0x00` / `0x01` prefixes are what stop a leaf being reinterpreted
//! as an interior node (second-preimage resistance). They are mandatory, not
//! decorative, and a library default "hash the two children" tree does **not**
//! satisfy this — which is why the tree is implemented here rather than taken
//! from `rs_merkle`.
//!
//! Note the split rule: the left subtree holds the largest power of two
//! *strictly less than* `n`, so trees are left-heavy and **not** padded to a
//! power of two. This differs from many Merkle implementations.
//!
//! Reference implementations this must match byte for byte:
//! * `Merkle` in `core/Merkle.kt`
//! * `leaf_hash` / `node_hash` / `_split` / `mth` / `audit_path` in `reference-server/server.py`

use crate::sha256;

/// A node hash: the SHA-256 output width.
pub type Hash = [u8; 32];

/// Why a Merkle operation could not be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleError {
    /// The tree has no leaves. RFC 6962 defines the empty-tree hash as
    /// `SHA256("")`, but neither reference implementation uses it: the Kotlin
    /// `Merkle.root` requires a non-empty list and `server.py` returns `""`.
    /// Rather than invent a third behaviour, the empty case is rejected.
    EmptyTree,
    /// The requested leaf index is outside `0..tree_size`.
    IndexOutOfRange {
        /// The index that was requested.
        index: usize,
        /// The number of leaves in the tree.
        size: usize,
    },
}

impl core::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyTree => write!(f, "merkle tree has no leaves"),
            Self::IndexOutOfRange { index, size } => {
                write!(f, "leaf index {index} out of range for tree of size {size}")
            }
        }
    }
}

impl std::error::Error for MerkleError {}

/// Hashes raw leaf data: `SHA256(0x00 ‖ data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    sha256(&[&[0x00], data])
}

/// Combines two child hashes: `SHA256(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[0x01], left, right])
}

/// The largest power of two strictly less than `n`. Requires `n >= 2`.
///
/// Mirrors `_split` in Python and `split` in Kotlin, which both start at `k = 1`
/// and double while `k * 2 < n`.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2, "split is only defined for n >= 2");
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// The Merkle Tree Hash of already-hashed leaves (RFC 6962 `MTH`).
fn mth(hashes: &[Hash]) -> Hash {
    if hashes.len() == 1 {
        return hashes[0];
    }
    let k = split(hashes.len());
    node_hash(&mth(&hashes[..k]), &mth(&hashes[k..]))
}

/// The audit path for leaf `m` among already-hashed leaves.
fn audit_path(m: usize, hashes: &[Hash]) -> Vec<Hash> {
    if hashes.len() == 1 {
        return Vec::new();
    }
    let k = split(hashes.len());
    if m < k {
        let mut path = audit_path(m, &hashes[..k]);
        path.push(mth(&hashes[k..]));
        path
    } else {
        let mut path = audit_path(m - k, &hashes[k..]);
        path.push(mth(&hashes[..k]));
        path
    }
}

/// The Merkle root over `leaves`, which are **raw, unhashed** leaf data.
///
/// # Errors
///
/// Returns [`MerkleError::EmptyTree`] if `leaves` is empty.
pub fn root(leaves: &[impl AsRef<[u8]>]) -> Result<Hash, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    let hashes: Vec<Hash> = leaves.iter().map(|d| leaf_hash(d.as_ref())).collect();
    Ok(mth(&hashes))
}

/// The inclusion proof for the leaf at `index`, over **raw, unhashed** leaf data.
///
/// The returned path runs from the sibling nearest the leaf outward to the
/// sibling nearest the root, which is the order [`verify_inclusion`] expects and
/// the order the mint returns from `/mint/issue`.
///
/// # Errors
///
/// Returns [`MerkleError::EmptyTree`] if `leaves` is empty, or
/// [`MerkleError::IndexOutOfRange`] if `index >= leaves.len()`.
pub fn proof(leaves: &[impl AsRef<[u8]>], index: usize) -> Result<Vec<Hash>, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyTree);
    }
    if index >= leaves.len() {
        return Err(MerkleError::IndexOutOfRange {
            index,
            size: leaves.len(),
        });
    }
    let hashes: Vec<Hash> = leaves.iter().map(|d| leaf_hash(d.as_ref())).collect();
    Ok(audit_path(index, &hashes))
}

/// Verifies an inclusion proof per RFC 9162 section 2.1.3.2.
///
/// `leaf_data` is the raw (unhashed) leaf. Returns `false` rather than erroring
/// on any malformed input, so a caller can treat it as a plain predicate — this
/// matches `Merkle.verifyInclusion` in Kotlin, which the Android client uses to
/// decide whether to accept a freshly minted token.
///
/// This is deliberately a standalone walk rather than a rebuild of the tree: a
/// verifier holds only its own leaf, the proof, the index and the tree size.
pub fn verify_inclusion(
    leaf_data: &[u8],
    index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    if tree_size == 0 || index >= tree_size {
        return false;
    }

    let mut fnode = index;
    let mut snode = tree_size - 1;
    let mut r = leaf_hash(leaf_data);

    for p in proof {
        if snode == 0 {
            // Proof is longer than the tree is deep.
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }

    // The proof must be exactly long enough: snode reaches 0 at the root.
    snode == 0 && constant_time_eq(&r, root)
}

/// Compares two hashes without an early exit.
///
/// Mirrors the Kotlin use of `MessageDigest.isEqual`. A Merkle root is public,
/// so this is defence in depth rather than a strict requirement.
fn constant_time_eq(a: &Hash, b: &Hash) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `leaf-0`, `leaf-1`, ... matching the generator in `tests/gen_vectors.py`.
    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
    }

    #[test]
    fn domain_separation_prefixes_are_distinct() {
        // A leaf must never hash the same as the bare data.
        assert_ne!(leaf_hash(b""), sha256(&[b""]));
        assert_eq!(leaf_hash(b""), sha256(&[&[0x00][..]]));
        assert_eq!(
            node_hash(&[0u8; 32], &[0u8; 32]),
            sha256(&[&[0x01][..], &[0u8; 32], &[0u8; 32]])
        );
    }

    #[test]
    fn split_is_largest_power_of_two_strictly_below_n() {
        let expected = [
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 4),
            (6, 4),
            (7, 4),
            (8, 4),
            (9, 8),
            (16, 8),
            (17, 16),
            (32, 16),
            (33, 32),
        ];
        for (n, want) in expected {
            assert_eq!(split(n), want, "split({n})");
        }
    }

    #[test]
    fn single_leaf_root_is_the_leaf_hash_with_no_node_hashing() {
        let l = leaves(1);
        assert_eq!(root(&l).unwrap(), leaf_hash(b"leaf-0"));
        assert!(proof(&l, 0).unwrap().is_empty());
    }

    #[test]
    fn two_leaf_root_is_one_node_hash() {
        let l = leaves(2);
        assert_eq!(
            root(&l).unwrap(),
            node_hash(&leaf_hash(b"leaf-0"), &leaf_hash(b"leaf-1"))
        );
    }

    #[test]
    fn round_trip_every_leaf_for_sizes_1_to_17() {
        for size in 1..=17 {
            let l = leaves(size);
            let r = root(&l).unwrap();
            for i in 0..size {
                let p = proof(&l, i).unwrap();
                assert!(
                    verify_inclusion(&l[i], i, size, &p, &r),
                    "leaf {i} of {size} failed to verify"
                );
            }
        }
    }

    #[test]
    fn verification_rejects_tampering() {
        let size = 11;
        let l = leaves(size);
        let r = root(&l).unwrap();
        let p = proof(&l, 5).unwrap();

        assert!(verify_inclusion(&l[5], 5, size, &p, &r));

        // Wrong leaf data.
        assert!(!verify_inclusion(b"leaf-X", 5, size, &p, &r));
        // Wrong index.
        assert!(!verify_inclusion(&l[5], 6, size, &p, &r));
        // Index out of range.
        assert!(!verify_inclusion(&l[5], size, size, &p, &r));
        // Corrupted root.
        let mut bad_root = r;
        bad_root[0] ^= 1;
        assert!(!verify_inclusion(&l[5], 5, size, &p, &bad_root));
        // Corrupted proof element.
        let mut bad_proof = p.clone();
        bad_proof[0][0] ^= 1;
        assert!(!verify_inclusion(&l[5], 5, size, &bad_proof, &r));
        // Truncated proof.
        assert!(!verify_inclusion(&l[5], 5, size, &p[..p.len() - 1], &r));
        // Over-long proof.
        let mut long_proof = p.clone();
        long_proof.push([0u8; 32]);
        assert!(!verify_inclusion(&l[5], 5, size, &long_proof, &r));
        // Empty tree.
        assert!(!verify_inclusion(&l[0], 0, 0, &[], &r));
    }

    /// `tree_size` is only weakly constrained by the RFC 9162 walk.
    ///
    /// The proof length pins the depth, and within the range of sizes that share
    /// that depth the left/right orientation decisions for a given leaf are
    /// identical — so a proof verifies against a band of sizes, not just the one
    /// it was produced for. For leaf 5 of an 11-leaf tree that band is 9..=16.
    ///
    /// This is **not** a porting artefact: the same behaviour was confirmed by
    /// transcribing the walk from `Merkle.kt` and running it against the
    /// reference server's hashes. It is pinned here so that if the shared
    /// algorithm ever changes, this crate notices.
    ///
    /// Security impact is limited: what binds a token is the *root*, which the
    /// client checks against the mint. An attacker cannot vary `tree_size` to
    /// forge inclusion in a tree whose root they do not control.
    #[test]
    fn tree_size_is_only_weakly_bound_matching_the_kotlin_client() {
        let size = 11;
        let l = leaves(size);
        let r = root(&l).unwrap();
        let p = proof(&l, 5).unwrap();

        let accepted: Vec<usize> = (1..=24)
            .filter(|&sz| verify_inclusion(&l[5], 5, sz, &p, &r))
            .collect();
        assert_eq!(accepted, (9..=16).collect::<Vec<_>>());
    }

    #[test]
    fn a_proof_does_not_verify_against_a_different_tree() {
        let a = leaves(8);
        let b = leaves(9);
        let p = proof(&a, 3).unwrap();
        assert!(!verify_inclusion(&a[3], 3, 9, &p, &root(&b).unwrap()));
    }

    #[test]
    fn empty_tree_is_rejected() {
        let empty: [Vec<u8>; 0] = [];
        assert_eq!(root(&empty), Err(MerkleError::EmptyTree));
        assert_eq!(proof(&empty, 0), Err(MerkleError::EmptyTree));
    }

    #[test]
    fn index_out_of_range_is_rejected() {
        let l = leaves(4);
        assert_eq!(
            proof(&l, 4),
            Err(MerkleError::IndexOutOfRange { index: 4, size: 4 })
        );
    }

    #[test]
    fn proof_length_tracks_tree_depth() {
        // Left-heavy trees: leaf 0 of a size-17 tree sits under a 16-leaf subtree,
        // so its path is 4 siblings inside that subtree plus 1 for the odd leaf.
        assert_eq!(proof(&leaves(17), 0).unwrap().len(), 5);
        assert_eq!(proof(&leaves(17), 16).unwrap().len(), 1);
        assert_eq!(proof(&leaves(8), 0).unwrap().len(), 3);
    }
}
