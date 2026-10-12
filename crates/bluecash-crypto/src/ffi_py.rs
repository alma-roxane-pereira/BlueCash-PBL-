//! Python bindings (PyO3) for the BlueCash cryptographic core.
//!
//! Exposed so the FastAPI mint can call the same compiled code the protocol is
//! specified against, instead of maintaining a second Python implementation of
//! the same maths.
//!
//! # Interface conventions
//!
//! * Big integers cross the boundary as native Python `int` (PyO3's `num-bigint`
//!   conversion). Hex encoding is `API_CONTRACT.md`'s wire format, not an
//!   internal one, so the backend converts at the HTTP edge rather than here —
//!   that keeps padding and odd-length-hex bugs out of the crypto layer.
//! * Byte strings cross as `bytes`.
//! * Invalid input raises `ValueError` with a specific message. Predicate
//!   functions (`*_verify`, `is_element`) return `False` instead of raising, so
//!   a malformed signature is a failed check rather than a 500.
//!
//! # Secret handling
//!
//! Nothing here returns or logs private key material except where the caller
//! explicitly asks for it (`ed25519_generate_seed`, `random_scalar`). No type
//! carries a `__repr__` that could print a seed into a traceback or a log line.
//!
//! This module is compiled only with the `python` feature.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use num_bigint::BigUint;

// Modules are aliased because several PyO3 function names (`blind`, `commit`,
// `fdh`) would otherwise collide with the module paths they call into.
use crate::blind as blind_mod;
use crate::ed25519 as ed25519_mod;
use crate::fdh as fdh_mod;
use crate::merkle as merkle_mod;
use crate::rng as rng_mod;
use crate::shares as shares_mod;

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn value_err<E: core::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Converts a Python-supplied hash to the fixed 32-byte form.
fn hash32(label: &str, b: &[u8]) -> PyResult<[u8; 32]> {
    <[u8; 32]>::try_from(b).map_err(|_| {
        PyValueError::new_err(format!("{label} must be exactly 32 bytes, got {}", b.len()))
    })
}

// ---------------------------------------------------------------------------
// Full-domain hash
// ---------------------------------------------------------------------------

/// fdh(message: bytes, n: int) -> int
///
/// The full-domain hash from `API_CONTRACT.md`: expands SHA-256 in counter mode
/// under the label `BCFDH|v1|` and reduces modulo `n`.
#[pyfunction]
fn fdh(message: &[u8], n: BigUint) -> PyResult<BigUint> {
    if n == BigUint::ZERO {
        return Err(PyValueError::new_err("modulus must be non-zero"));
    }
    Ok(fdh_mod::fdh(message, &n))
}

// ---------------------------------------------------------------------------
// RSA blind signatures
// ---------------------------------------------------------------------------

/// blind(message: bytes, n: int, e: int) -> tuple[int, int]
///
/// Returns `(blinded_message, r)`. `r` is the secret blinding factor and must be
/// kept by the caller until the mint responds; it is never sent to the mint.
#[pyfunction]
fn blind(message: &[u8], n: BigUint, e: BigUint) -> PyResult<(BigUint, BigUint)> {
    let b = blind_mod::blind(message, &n, &e).map_err(value_err)?;
    Ok((b.blinded_message, b.r))
}

/// blind_with(message: bytes, n: int, e: int, r: int) -> tuple[int, int]
///
/// Deterministic variant taking a caller-supplied blinding factor. Intended for
/// tests and for reproducing a known blinding; production callers want `blind`.
#[pyfunction]
fn blind_with(message: &[u8], n: BigUint, e: BigUint, r: BigUint) -> PyResult<(BigUint, BigUint)> {
    let b = blind_mod::blind_with(message, &n, &e, r).map_err(value_err)?;
    Ok((b.blinded_message, b.r))
}

/// sign_blinded(blinded: int, n: int, d: int) -> int
///
/// Mint side: `blinded^d mod n`. The mint learns nothing about the message.
#[pyfunction]
fn sign_blinded(blinded: BigUint, n: BigUint, d: BigUint) -> PyResult<BigUint> {
    blind_mod::sign_blinded(&blinded, &n, &d).map_err(value_err)
}

/// unblind(blind_sig: int, r: int, n: int) -> int
#[pyfunction]
fn unblind(blind_sig: BigUint, r: BigUint, n: BigUint) -> PyResult<BigUint> {
    blind_mod::unblind(&blind_sig, &r, &n).map_err(value_err)
}

/// blind_verify(message: bytes, sig: int, n: int, e: int) -> bool
///
/// `sig^e mod n == fdh(message, n)`. Returns `False` for out-of-range input
/// rather than raising.
#[pyfunction]
fn blind_verify(message: &[u8], sig: BigUint, n: BigUint, e: BigUint) -> bool {
    if n == BigUint::ZERO {
        return false;
    }
    blind_mod::verify(message, &sig, &n, &e)
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// ed25519_generate_seed() -> bytes
///
/// A fresh 32-byte private seed from OS randomness. Secret material.
#[pyfunction]
fn ed25519_generate_seed(py: Python<'_>) -> Py<PyBytes> {
    PyBytes::new(py, &ed25519_mod::generate_seed()).unbind()
}

/// ed25519_public_key(seed: bytes) -> bytes
#[pyfunction]
fn ed25519_public_key(py: Python<'_>, seed: &[u8]) -> PyResult<Py<PyBytes>> {
    let seed = hash32("seed", seed)?;
    Ok(PyBytes::new(py, &ed25519_mod::public_key(&seed)).unbind())
}

/// ed25519_sign(seed: bytes, message: bytes) -> bytes
#[pyfunction]
fn ed25519_sign(py: Python<'_>, seed: &[u8], message: &[u8]) -> PyResult<Py<PyBytes>> {
    let seed = hash32("seed", seed)?;
    Ok(PyBytes::new(py, &ed25519_mod::sign(&seed, message)).unbind())
}

/// ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool
///
/// Returns `False` for a wrong, malformed or wrong-length signature or key.
#[pyfunction]
fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    ed25519_mod::verify(public_key, message, signature)
}

// ---------------------------------------------------------------------------
// Feldman-committed shares
// ---------------------------------------------------------------------------

fn group() -> shares_mod::Group {
    shares_mod::Group::new()
}

/// group_p() -> int — the RFC 3526 group-14 prime.
#[pyfunction]
fn group_p() -> BigUint {
    group().p
}

/// group_q() -> int — the prime subgroup order, (p-1)/2.
#[pyfunction]
fn group_q() -> BigUint {
    group().q
}

/// group_g() -> int — the generator, 2.
#[pyfunction]
fn group_g() -> BigUint {
    group().g
}

/// commit(a: int) -> int — the public commitment `g^a mod p`.
#[pyfunction]
fn commit(a: BigUint) -> BigUint {
    group().commit(&a)
}

/// is_element(v: int) -> bool — is `v` in the prime-order subgroup?
#[pyfunction]
fn is_element(v: BigUint) -> bool {
    group().is_element(&v)
}

/// random_scalar() -> int — a uniform scalar in [1, q). Secret material.
#[pyfunction]
fn random_scalar() -> BigUint {
    group().random_scalar()
}

/// challenge_x(token_id: str, n_ctx: str) -> int
///
/// The spend coordinate, bound to the token and spend context:
/// `SHA256("BCSHARE|v1|{token_id}|{n_ctx}")`, never zero.
#[pyfunction]
fn challenge_x(token_id: &str, n_ctx: &str) -> BigUint {
    group().challenge_x(token_id, n_ctx)
}

/// eval_share(a0: int, a1: int, x: int) -> int — `a0 + a1*x mod q`.
#[pyfunction]
fn eval_share(a0: BigUint, a1: BigUint, x: BigUint) -> BigUint {
    group().eval_share(&a0, &a1, &x)
}

/// verify_share(c0: int, c1: int, x: int, y: int) -> bool
///
/// Checks `g^y == c0 * c1^x (mod p)` — that the revealed point lies on the line
/// the token commits to. Returns `False` on any out-of-range input.
#[pyfunction]
fn verify_share(c0: BigUint, c1: BigUint, x: BigUint, y: BigUint) -> bool {
    group().verify_share(&c0, &c1, &x, &y)
}

/// recover_secret(x1: int, y1: int, x2: int, y2: int) -> int | None
///
/// Recovers the payer's identity secret `a0` from two distinct spends of one
/// token. Returns `None` when the coordinates coincide mod q, which carries no
/// information — that is the same-context replay case, not fraud.
#[pyfunction]
fn recover_secret(x1: BigUint, y1: BigUint, x2: BigUint, y2: BigUint) -> Option<BigUint> {
    group().recover_secret(&x1, &y1, &x2, &y2)
}

// ---------------------------------------------------------------------------
// Merkle (RFC 6962)
// ---------------------------------------------------------------------------

/// merkle_leaf_hash(data: bytes) -> bytes — `SHA256(0x00 || data)`.
#[pyfunction]
fn merkle_leaf_hash(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, &merkle_mod::leaf_hash(data)).unbind()
}

/// merkle_node_hash(left: bytes, right: bytes) -> bytes — `SHA256(0x01 || l || r)`.
#[pyfunction]
fn merkle_node_hash(py: Python<'_>, left: &[u8], right: &[u8]) -> PyResult<Py<PyBytes>> {
    let l = hash32("left", left)?;
    let r = hash32("right", right)?;
    Ok(PyBytes::new(py, &merkle_mod::node_hash(&l, &r)).unbind())
}

/// merkle_root(leaves: Sequence[bytes]) -> bytes
///
/// Raises `ValueError` on an empty tree: the two reference implementations
/// disagree there, so this crate refuses rather than inventing a third answer.
#[pyfunction]
fn merkle_root(py: Python<'_>, leaves: Vec<Vec<u8>>) -> PyResult<Py<PyBytes>> {
    let root = merkle_mod::root(&leaves).map_err(value_err)?;
    Ok(PyBytes::new(py, &root).unbind())
}

/// merkle_proof(leaves: Sequence[bytes], index: int) -> list[bytes]
///
/// The audit path for `index`, ordered from the sibling nearest the leaf
/// outward — the order `/mint/issue` returns and `merkle_verify_inclusion`
/// expects.
#[pyfunction]
fn merkle_proof(py: Python<'_>, leaves: Vec<Vec<u8>>, index: usize) -> PyResult<Vec<Py<PyBytes>>> {
    let path = merkle_mod::proof(&leaves, index).map_err(value_err)?;
    Ok(path.iter().map(|h| PyBytes::new(py, h).unbind()).collect())
}

/// merkle_verify_inclusion(leaf: bytes, index: int, tree_size: int,
///                         proof: Sequence[bytes], root: bytes) -> bool
///
/// RFC 9162 section 2.1.3.2. `leaf` is the raw, unhashed leaf. Returns `False`
/// on malformed input rather than raising, so a bad proof is a failed check.
#[pyfunction]
fn merkle_verify_inclusion(
    leaf: &[u8],
    index: usize,
    tree_size: usize,
    proof: Vec<Vec<u8>>,
    root: &[u8],
) -> bool {
    let Ok(root) = <[u8; 32]>::try_from(root) else {
        return false;
    };
    let mut path = Vec::with_capacity(proof.len());
    for p in &proof {
        match <[u8; 32]>::try_from(p.as_slice()) {
            Ok(h) => path.push(h),
            Err(_) => return false,
        }
    }
    merkle_mod::verify_inclusion(leaf, index, tree_size, &path, &root)
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// random_bytes(n: int) -> bytes — OS randomness. Secret material.
#[pyfunction]
fn random_bytes(py: Python<'_>, n: usize) -> Py<PyBytes> {
    PyBytes::new(py, &rng_mod::bytes(n)).unbind()
}

/// The `bluecash_crypto` extension module.
#[pymodule]
fn bluecash_crypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__doc__", "BlueCash Protocol cryptographic core (Rust).")?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    m.add_function(wrap_pyfunction!(fdh, m)?)?;

    m.add_function(wrap_pyfunction!(blind, m)?)?;
    m.add_function(wrap_pyfunction!(blind_with, m)?)?;
    m.add_function(wrap_pyfunction!(sign_blinded, m)?)?;
    m.add_function(wrap_pyfunction!(unblind, m)?)?;
    m.add_function(wrap_pyfunction!(blind_verify, m)?)?;

    m.add_function(wrap_pyfunction!(ed25519_generate_seed, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;

    m.add_function(wrap_pyfunction!(group_p, m)?)?;
    m.add_function(wrap_pyfunction!(group_q, m)?)?;
    m.add_function(wrap_pyfunction!(group_g, m)?)?;
    m.add_function(wrap_pyfunction!(commit, m)?)?;
    m.add_function(wrap_pyfunction!(is_element, m)?)?;
    m.add_function(wrap_pyfunction!(random_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(challenge_x, m)?)?;
    m.add_function(wrap_pyfunction!(eval_share, m)?)?;
    m.add_function(wrap_pyfunction!(verify_share, m)?)?;
    m.add_function(wrap_pyfunction!(recover_secret, m)?)?;

    m.add_function(wrap_pyfunction!(merkle_leaf_hash, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_node_hash, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_root, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_proof, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_verify_inclusion, m)?)?;

    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;

    Ok(())
}
