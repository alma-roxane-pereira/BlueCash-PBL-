//! Differential tests against the reference implementation.
//!
//! The expected values in `vectors.json` were **not** produced by this crate.
//! They come from `tests/gen_vectors.py`, which loads the pure-stdlib helper
//! block out of `reference-server/server.py` and calls those functions
//! directly. So a pass here means the Rust code agrees with the Python server
//! that the Android client was developed against — not merely with itself.
//!
//! Regenerate after any change to the reference:
//!
//! ```text
//! cd crates/bluecash-crypto
//! python -I tests/gen_vectors.py > tests/vectors.json
//! ```
//!
//! The Kotlin side is covered transitively: `reference-server/README.md` records
//! that `HttpIntegrationTest` was verified against this server and fails if the
//! two disagree on even one hash label. A direct Rust-to-Kotlin comparison still
//! needs the Gradle wrapper, which is not yet checked in.

use bluecash_crypto::{fdh, leaf_hash, node_hash, proof, root, verify_inclusion};
use num_bigint::BigUint;

const VECTORS: &str = include_str!("vectors.json");

// ---------------------------------------------------------------------------
// A minimal JSON reader.
//
// The vector file has a known, flat shape that this crate generates itself, so
// pulling in serde purely for tests would add dependencies without adding
// confidence. These helpers do straightforward string scanning and panic loudly
// on anything unexpected.
// ---------------------------------------------------------------------------

/// The text of the array named `key`, without its enclosing brackets.
fn array_body(src: &str, key: &str) -> String {
    let needle = format!("\"{key}\":");
    let start = src.find(&needle).unwrap_or_else(|| panic!("no key {key}"));
    let open = src[start..].find('[').expect("array open") + start;
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return src[open + 1..open + i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unterminated array {key}");
}

/// Split a JSON array body into its top-level `{...}` objects.
fn objects(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in body.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    out.push(body[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    out
}

/// The string value of `key` in a flat object.
fn string_field(obj: &str, key: &str) -> String {
    let needle = format!("\"{key}\":");
    let at = obj
        .find(&needle)
        .unwrap_or_else(|| panic!("no field {key} in {obj}"));
    let rest = &obj[at + needle.len()..];
    let open = rest.find('"').expect("string open");
    let close = rest[open + 1..].find('"').expect("string close");
    rest[open + 1..open + 1 + close].to_string()
}

/// The integer value of `key` in a flat object.
fn usize_field(obj: &str, key: &str) -> usize {
    let needle = format!("\"{key}\":");
    let at = obj
        .find(&needle)
        .unwrap_or_else(|| panic!("no field {key} in {obj}"));
    obj[at + needle.len()..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("field {key} is not an integer"))
}

/// All string elements of the array named `key` within an object.
fn string_array(obj: &str, key: &str) -> Vec<String> {
    let body = array_body(obj, key);
    let mut out = Vec::new();
    let mut rest = body.as_str();
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let close = after.find('"').expect("string close");
        out.push(after[..close].to_string());
        rest = &after[close + 1..];
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("expected 32 bytes")
}

/// `int_hex` in the generator emits even-length lowercase hex of a big-endian
/// integer, so parsing is a plain radix-16 read.
fn big(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).unwrap_or_else(|| panic!("bad bigint hex {s:?}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn vector_file_is_the_expected_shape() {
    assert!(
        VECTORS.contains("reference-server/server.py"),
        "vectors.json must record its provenance"
    );
    assert_eq!(objects(&array_body(VECTORS, "fdh")).len(), 10);
    assert_eq!(objects(&array_body(VECTORS, "merkle")).len(), 17);
}

#[test]
fn fdh_matches_the_reference_server() {
    let cases = objects(&array_body(VECTORS, "fdh"));
    assert!(!cases.is_empty());

    for case in &cases {
        let label = string_field(case, "label");
        let message = unhex(&string_field(case, "message_hex"));
        let n = big(&string_field(case, "n_hex"));
        let expected = big(&string_field(case, "expected_hex"));
        let k = usize_field(case, "k");

        // The contract formula, restated here so a change to either side shows up.
        assert_eq!(
            k,
            (n.bits() as usize).div_ceil(8) + 16,
            "k disagrees for case {label:?}"
        );

        let got = fdh(&message, &n);
        assert_eq!(got, expected, "FDH mismatch for case {label:?}");
        assert!(got < n, "FDH not reduced for case {label:?}");
    }

    eprintln!("FDH: {} reference cases matched", cases.len());
}

#[test]
fn merkle_primitives_match_the_reference_server() {
    let prims = &VECTORS[VECTORS.find("\"primitives\"").expect("primitives")..];

    assert_eq!(
        leaf_hash(b""),
        unhex32(&string_field(prims, "leaf_hash_empty"))
    );
    assert_eq!(
        leaf_hash(b"abc"),
        unhex32(&string_field(prims, "leaf_hash_abc"))
    );
    // The generator also records node_hash(b"", b""), but the Rust `node_hash`
    // is typed to take two 32-byte hashes, so that degenerate case cannot be
    // expressed here and is intentionally not asserted.
    assert_eq!(
        node_hash(&leaf_hash(b"a"), &leaf_hash(b"b")),
        unhex32(&string_field(prims, "node_hash_leafa_leafb"))
    );
}

#[test]
fn merkle_roots_and_proofs_match_the_reference_server() {
    let trees = objects(&array_body(VECTORS, "merkle"));
    assert_eq!(trees.len(), 17, "expected tree sizes 1..=17");

    let mut checked_proofs = 0usize;

    for tree in &trees {
        let size = usize_field(tree, "size");
        let leaves: Vec<Vec<u8>> = string_array(tree, "leaves_hex")
            .iter()
            .map(|h| unhex(h))
            .collect();
        assert_eq!(leaves.len(), size);

        // Leaf hashes.
        let expected_leaf_hashes = string_array(tree, "leaf_hashes_hex");
        for (i, leaf) in leaves.iter().enumerate() {
            assert_eq!(
                leaf_hash(leaf),
                unhex32(&expected_leaf_hashes[i]),
                "leaf hash {i} of tree size {size}"
            );
        }

        // Root.
        let expected_root = unhex32(&string_field(tree, "root_hex"));
        let got_root = root(&leaves).expect("non-empty tree");
        assert_eq!(got_root, expected_root, "root mismatch for size {size}");

        // Every inclusion proof, element by element.
        let proofs_body = array_body(tree, "proofs");
        let expected_proofs = split_nested_arrays(&proofs_body);
        assert_eq!(expected_proofs.len(), size, "proof count for size {size}");

        for (index, expected) in expected_proofs.iter().enumerate() {
            let got = proof(&leaves, index).expect("valid index");
            assert_eq!(
                got.len(),
                expected.len(),
                "proof length for leaf {index} of size {size}"
            );
            for (step, want) in expected.iter().enumerate() {
                assert_eq!(
                    got[step],
                    unhex32(want),
                    "proof element {step} for leaf {index} of size {size}"
                );
            }

            // The Rust verifier must accept the reference proof against the
            // reference root — the property the Android client actually relies on.
            let reference_proof: Vec<[u8; 32]> = expected.iter().map(|h| unhex32(h)).collect();
            assert!(
                verify_inclusion(
                    &leaves[index],
                    index,
                    size,
                    &reference_proof,
                    &expected_root
                ),
                "verifier rejected the reference proof for leaf {index} of size {size}"
            );
            checked_proofs += 1;
        }
    }

    assert_eq!(checked_proofs, 153, "1+2+...+17 proofs");
    eprintln!("Merkle: 17 trees, {checked_proofs} reference proofs matched");
}

/// Split the body of an array-of-arrays into its inner string lists.
fn split_nested_arrays(body: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in body.char_indices() {
        match c {
            '[' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            ']' => {
                depth -= 1;
                if depth == 0 {
                    let inner = &body[start..=i];
                    let mut items = Vec::new();
                    let mut rest = inner;
                    while let Some(open) = rest.find('"') {
                        let after = &rest[open + 1..];
                        let close = after.find('"').expect("string close");
                        items.push(after[..close].to_string());
                        rest = &after[close + 1..];
                    }
                    out.push(items);
                }
            }
            _ => {}
        }
    }
    out
}
