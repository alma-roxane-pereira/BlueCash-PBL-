//! Double-spend detection: a 2-of-n secret share with Feldman commitments.
//!
//! Each token carries a secret line `P(x) = a0 + a1*x (mod Q)`, where `a0` is the
//! owner's long-term identity secret and `a1` is fresh per token. The public
//! commitments `c0 = g^a0` and `c1 = g^a1` are baked into the mint-signed token.
//! Every spend reveals exactly one point `(x, y = P(x))`, with `x` derived from
//! the spend context:
//!
//! * one point alone reveals nothing about `a0` — `a1` is uniform, so `y` is too;
//! * a merchant can still check the point lies on the committed line,
//!   `g^y == c0 * c1^x`, without learning `a0`;
//! * **two** points from two different spends of the same token determine the
//!   line, which recovers `a0` and so identifies the double-spender.
//!
//! That is the whole offline-double-spend story: nobody is watching, but spending
//! twice is self-incriminating.
//!
//! # Group
//!
//! The 2048-bit safe prime from RFC 3526 group 14, working in the subgroup of
//! quadratic residues, which has prime order `Q = (P-1)/2` and generator `g = 2`.
//!
//! Reference implementations this must match:
//! * `Group` in `core/FeldmanShare.kt`
//! * the group block and `/settlement/uploadBatch` in `reference-server/server.py`
//!
//! # Relationship to the proposal
//!
//! The proposal names Shamir secret sharing via the `sharks` crate. This is
//! Shamir over a 2048-bit prime field *plus* Feldman commitments for public
//! verifiability — strictly more than `sharks` provides, and incompatible with
//! its GF(256) byte-wise construction. See the project docs for the recorded
//! deviation.

use num_bigint::{BigInt, BigUint, Sign};
use num_integer::{ExtendedGcd, Integer};
use num_traits::One;

use crate::{rng, sha256};

/// The RFC 3526 group-14 prime, `P`.
///
/// Identical to the literal in `FeldmanShare.kt` and to the value `server.py`
/// derives at runtime from Machin's formula.
const P_HEX: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74\
                     020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437\
                     4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed\
                     ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05\
                     98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb\
                     9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b\
                     e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718\
                     3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff";

/// Domain-separation label for the spend challenge.
const SHARE_LABEL: &str = "BCSHARE|v1|";

/// The protocol group: prime `p`, subgroup order `q`, generator `g`.
#[derive(Debug, Clone)]
pub struct Group {
    /// The 2048-bit safe prime.
    pub p: BigUint,
    /// The prime subgroup order, `(p-1)/2`.
    pub q: BigUint,
    /// The generator, `2`.
    pub g: BigUint,
}

impl Default for Group {
    fn default() -> Self {
        Self::new()
    }
}

impl Group {
    /// The RFC 3526 group-14 parameters.
    pub fn new() -> Self {
        let p = BigUint::parse_bytes(P_HEX.as_bytes(), 16).expect("P_HEX is valid hex");
        let q = (&p - BigUint::one()) >> 1u32;
        Self {
            p,
            q,
            g: BigUint::from(2u8),
        }
    }

    /// A fresh random scalar in `[1, q)`, for `a0` or `a1`.
    pub fn random_scalar(&self) -> BigUint {
        rng::scalar_below(&self.q)
    }

    /// The public commitment to a scalar: `g^a mod p`.
    pub fn commit(&self, a: &BigUint) -> BigUint {
        self.g.modpow(a, &self.p)
    }

    /// Is `v` in the prime-order subgroup, i.e. a quadratic residue mod `p`?
    ///
    /// Uses the Jacobi symbol, matching `Group.isElement` in Kotlin. For a safe
    /// prime this agrees with the Euler test `v^q == 1 mod p` that `server.py`
    /// uses; [`Self::is_element_by_euler`] implements that form and the tests
    /// assert the two agree.
    pub fn is_element(&self, v: &BigUint) -> bool {
        if v <= &BigUint::one() || v >= &(&self.p - BigUint::one()) {
            return false;
        }
        jacobi(v, &self.p) == 1
    }

    /// The subgroup test as `server.py` writes it: `2 <= v <= p-2` and `v^q == 1`.
    pub fn is_element_by_euler(&self, v: &BigUint) -> bool {
        if v <= &BigUint::one() || v >= &(&self.p - BigUint::one()) {
            return false;
        }
        v.modpow(&self.q, &self.p).is_one()
    }

    /// The x-coordinate for a spend, bound to the token and the spend context.
    ///
    /// `SHA256("BCSHARE|v1|{token_id}|{n_ctx}")` read as a big-endian integer,
    /// with zero mapped to one so the coordinate is never the secret itself.
    /// Binding `x` to the context is what stops a payer choosing a coordinate
    /// that would leak nothing, or reusing one to avoid detection.
    pub fn challenge_x(&self, token_id: &str, n_ctx: &str) -> BigUint {
        let digest = sha256(&[format!("{SHARE_LABEL}{token_id}|{n_ctx}").as_bytes()]);
        let x = BigUint::from_bytes_be(&digest);
        if x.is_zero_value() {
            BigUint::one()
        } else {
            x
        }
    }

    /// Evaluates the line: `y = a0 + a1*x mod q`.
    pub fn eval_share(&self, a0: &BigUint, a1: &BigUint, x: &BigUint) -> BigUint {
        (a0 + a1 * x) % &self.q
    }

    /// Checks that `(x, y)` lies on the line committed to by `(c0, c1)`.
    ///
    /// Verifies `g^y == c0 * c1^x (mod p)` after range-checking everything. This
    /// is what a merchant runs offline, before accepting a token, with no access
    /// to the mint and no knowledge of `a0`.
    pub fn verify_share(&self, c0: &BigUint, c1: &BigUint, x: &BigUint, y: &BigUint) -> bool {
        if !self.is_element(c0) || !self.is_element(c1) {
            return false;
        }
        if x.is_zero_value() || y >= &self.q {
            return false;
        }
        let lhs = self.g.modpow(y, &self.p);
        let rhs = (c0 * c1.modpow(x, &self.p)) % &self.p;
        lhs == rhs
    }

    /// Recovers the identity secret `a0` from two distinct points on the line.
    ///
    /// `a1 = (y2-y1)/(x2-x1) mod q`, then `a0 = y1 - a1*x1 mod q`. Returns `None`
    /// if the coordinates coincide mod `q`, which carries no information.
    ///
    /// Matches `Group.recoverSecret` in Kotlin and the interpolation in
    /// `/settlement/uploadBatch`.
    pub fn recover_secret(
        &self,
        x1: &BigUint,
        y1: &BigUint,
        x2: &BigUint,
        y2: &BigUint,
    ) -> Option<BigUint> {
        let q = BigInt::from(self.q.clone());
        let (x1, y1) = (BigInt::from(x1.clone()), BigInt::from(y1.clone()));
        let (x2, y2) = (BigInt::from(x2.clone()), BigInt::from(y2.clone()));

        let dx = (&x2 - &x1).mod_floor(&q);
        if dx.is_zero_value() {
            return None;
        }
        let dx_inv = mod_inverse_bigint(&dx, &q)?;
        let a1 = ((&y2 - &y1).mod_floor(&q) * dx_inv).mod_floor(&q);
        let a0 = (&y1 - a1 * &x1).mod_floor(&q);
        a0.to_biguint()
    }
}

/// Zero test, kept short at the call sites above.
trait IsZero {
    fn is_zero_value(&self) -> bool;
}
impl IsZero for BigUint {
    fn is_zero_value(&self) -> bool {
        *self == BigUint::ZERO
    }
}
impl IsZero for BigInt {
    fn is_zero_value(&self) -> bool {
        self.sign() == Sign::NoSign
    }
}

fn mod_inverse_bigint(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let ExtendedGcd { gcd, x, .. } = a.extended_gcd(m);
    if !gcd.is_one() {
        return None;
    }
    Some(x.mod_floor(m))
}

/// The Jacobi symbol `(a/n)` for odd `n > 0`.
///
/// A direct port of `Group.jacobi` in `FeldmanShare.kt`, including its loop
/// structure, so the two cannot drift.
pub fn jacobi(a: &BigUint, n: &BigUint) -> i32 {
    let mut a = a % n;
    let mut n = n.clone();
    let mut result = 1i32;

    let two = BigUint::from(2u8);
    let three = BigUint::from(3u8);
    let four = BigUint::from(4u8);
    let five = BigUint::from(5u8);
    let eight = BigUint::from(8u8);

    while !a.is_zero_value() {
        while a.is_even() {
            a /= &two;
            let r = &n % &eight;
            if r == three || r == five {
                result = -result;
            }
        }
        core::mem::swap(&mut a, &mut n);
        if &a % &four == three && &n % &four == three {
            result = -result;
        }
        a %= &n;
    }

    if n.is_one() {
        result
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_parameters_are_as_specified() {
        let gr = Group::new();
        assert_eq!(gr.p.bits(), 2048, "P must be 2048 bits");
        assert_eq!(gr.q.bits(), 2047, "Q = (P-1)/2");
        assert_eq!(gr.g, BigUint::from(2u8));
        // Safe prime: P = 2Q + 1.
        assert_eq!(&gr.q * BigUint::from(2u8) + BigUint::one(), gr.p);
        // The generator must itself be in the subgroup.
        assert!(gr.is_element(&gr.g));
    }

    #[test]
    fn jacobi_matches_known_values() {
        // Textbook values for (a/n) with small odd n.
        let cases = [
            (1u32, 3u32, 1i32),
            (2, 3, -1),
            (4, 3, 1),
            (1, 5, 1),
            (2, 5, -1),
            (3, 5, -1),
            (4, 5, 1),
            (5, 5, 0),
            (1001, 9907, -1),
            (19, 45, 1),
            (8, 21, -1),
            (5, 21, 1),
        ];
        for (a, n, want) in cases {
            assert_eq!(
                jacobi(&BigUint::from(a), &BigUint::from(n)),
                want,
                "jacobi({a}/{n})"
            );
        }
    }

    #[test]
    fn jacobi_and_euler_subgroup_tests_agree() {
        // Kotlin uses the Jacobi symbol; server.py uses v^Q == 1. For a safe
        // prime these must coincide, and a disagreement would be an interop bug.
        let gr = Group::new();
        for _ in 0..12 {
            let s = gr.random_scalar();
            let v = gr.commit(&s); // always a QR
            assert!(gr.is_element(&v));
            assert!(gr.is_element_by_euler(&v));
        }
        // Non-residues must be rejected by both. g^s * (a known non-residue):
        // P-1 has Jacobi symbol -1 for a safe prime P with P = 3 mod 4.
        for v in [BigUint::ZERO, BigUint::one(), gr.p.clone() - BigUint::one()] {
            assert!(!gr.is_element(&v), "accepted {v}");
            assert!(!gr.is_element_by_euler(&v));
        }
    }

    #[test]
    fn challenge_x_is_bound_to_token_and_context() {
        let gr = Group::new();
        let a = gr.challenge_x("tok1", "ctx-a");
        assert_eq!(a, gr.challenge_x("tok1", "ctx-a"), "deterministic");
        assert_ne!(a, gr.challenge_x("tok1", "ctx-b"), "context matters");
        assert_ne!(a, gr.challenge_x("tok2", "ctx-a"), "token matters");
        // Never zero, and 256 bits wide at most.
        assert!(a > BigUint::ZERO);
        assert!(a.bits() <= 256);
    }

    #[test]
    fn challenge_x_label_is_exactly_the_contract_string() {
        let gr = Group::new();
        let expected = BigUint::from_bytes_be(&sha256(&[b"BCSHARE|v1|tokenA|ctxB"]));
        assert_eq!(gr.challenge_x("tokenA", "ctxB"), expected);
    }

    #[test]
    fn a_single_share_verifies_against_the_commitments() {
        let gr = Group::new();
        let (a0, a1) = (gr.random_scalar(), gr.random_scalar());
        let (c0, c1) = (gr.commit(&a0), gr.commit(&a1));
        let x = gr.challenge_x("tok", "shop-a");
        let y = gr.eval_share(&a0, &a1, &x);
        assert!(gr.verify_share(&c0, &c1, &x, &y));
    }

    #[test]
    fn two_shares_of_the_same_token_recover_the_identity_secret() {
        // The core double-spend property.
        let gr = Group::new();
        let (a0, a1) = (gr.random_scalar(), gr.random_scalar());
        let (c0, c1) = (gr.commit(&a0), gr.commit(&a1));

        let x1 = gr.challenge_x("tok", "shop-a");
        let y1 = gr.eval_share(&a0, &a1, &x1);
        let x2 = gr.challenge_x("tok", "shop-b");
        let y2 = gr.eval_share(&a0, &a1, &x2);

        assert!(gr.verify_share(&c0, &c1, &x1, &y1));
        assert!(gr.verify_share(&c0, &c1, &x2, &y2));

        let recovered = gr.recover_secret(&x1, &y1, &x2, &y2).expect("recoverable");
        assert_eq!(recovered, a0, "must recover the identity secret");
        // And the recovered secret must match the published commitment, which is
        // how the server maps it back to a credential.
        assert_eq!(gr.commit(&recovered), c0);
    }

    #[test]
    fn one_share_alone_does_not_determine_the_secret() {
        // With a1 unknown and uniform, the same (x, y) is consistent with every
        // candidate a0: for any a0' there is an a1' completing the line. Show
        // that explicitly rather than asserting an absence.
        let gr = Group::new();
        let (a0, a1) = (gr.random_scalar(), gr.random_scalar());
        let x = gr.challenge_x("tok", "only-spend");
        let y = gr.eval_share(&a0, &a1, &x);

        let other_a0 = gr.random_scalar();
        let x_inv = {
            let q = BigInt::from(gr.q.clone());
            mod_inverse_bigint(&BigInt::from(x.clone()).mod_floor(&q), &q)
                .unwrap()
                .to_biguint()
                .unwrap()
        };
        // a1' = (y - a0') / x  mod q
        let diff = (&gr.q + &y - (&other_a0 % &gr.q)) % &gr.q;
        let other_a1 = (diff * x_inv) % &gr.q;
        assert_eq!(
            gr.eval_share(&other_a0, &other_a1, &x),
            y,
            "a different a0 explains the same single share"
        );
    }

    #[test]
    fn repeating_the_same_context_reveals_nothing_new() {
        // Spending twice in the SAME context gives the same point, so the
        // coordinates coincide and recovery must fail.
        let gr = Group::new();
        let (a0, a1) = (gr.random_scalar(), gr.random_scalar());
        let x = gr.challenge_x("tok", "same-shop");
        let y = gr.eval_share(&a0, &a1, &x);
        assert_eq!(gr.recover_secret(&x, &y, &x, &y), None);
    }

    #[test]
    fn verify_share_rejects_bad_inputs() {
        let gr = Group::new();
        let (a0, a1) = (gr.random_scalar(), gr.random_scalar());
        let (c0, c1) = (gr.commit(&a0), gr.commit(&a1));
        let x = gr.challenge_x("tok", "shop");
        let y = gr.eval_share(&a0, &a1, &x);

        assert!(gr.verify_share(&c0, &c1, &x, &y));
        // Wrong y.
        assert!(!gr.verify_share(&c0, &c1, &x, &((&y + BigUint::one()) % &gr.q)));
        // Wrong x (a point from a different context).
        assert!(!gr.verify_share(&c0, &c1, &gr.challenge_x("tok", "elsewhere"), &y));
        // Commitments swapped.
        assert!(!gr.verify_share(&c1, &c0, &x, &y));
        // y out of range.
        assert!(!gr.verify_share(&c0, &c1, &x, &gr.q.clone()));
        // x zero.
        assert!(!gr.verify_share(&c0, &c1, &BigUint::ZERO, &y));
        // Commitments outside the subgroup.
        assert!(!gr.verify_share(&BigUint::one(), &c1, &x, &y));
        assert!(!gr.verify_share(&c0, &BigUint::ZERO, &x, &y));
    }

    #[test]
    fn a_share_from_another_token_does_not_verify() {
        let gr = Group::new();
        let (a0, a1) = (gr.random_scalar(), gr.random_scalar());
        let (c0, c1) = (gr.commit(&a0), gr.commit(&a1));
        // Same owner, different token means a different a1.
        let other_a1 = gr.random_scalar();
        let x = gr.challenge_x("tok", "shop");
        let y_other = gr.eval_share(&a0, &other_a1, &x);
        assert!(!gr.verify_share(&c0, &c1, &x, &y_other));
    }

    #[test]
    fn eval_share_is_reduced_mod_q() {
        let gr = Group::new();
        let big = &gr.q - BigUint::one();
        let y = gr.eval_share(&big, &big, &big);
        assert!(y < gr.q);
    }
}
