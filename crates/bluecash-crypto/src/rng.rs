//! Secure randomness, drawn straight from the OS.
//!
//! Deliberately thin: the crate needs random bytes in three places (Ed25519
//! seeds, RSA blinding factors, share coefficients) and nothing else, so it
//! depends on `getrandom` rather than pulling in the `rand` crate and its
//! version tree.

use num_bigint::BigUint;

/// Fills `buf` with cryptographically secure OS randomness.
///
/// # Panics
///
/// Panics if the OS entropy source fails. There is no safe fallback for a
/// cryptographic key, so failing loudly is correct.
pub fn fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS randomness unavailable");
}

/// Returns `n` secure random bytes.
pub fn bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    fill(&mut v);
    v
}

/// A uniform random integer in `[1, modulus)`.
///
/// Draws 64 bits more than the modulus before reducing, so the modulo bias is
/// negligible — the same technique as `Group.randomScalar` in `FeldmanShare.kt`,
/// which uses `BigInteger(Q.bitLength() + 64, rnd).mod(Q)`. Zero is rejected and
/// redrawn, since a zero scalar would be a degenerate secret.
///
/// # Panics
///
/// Panics if `modulus` is less than 2.
pub fn scalar_below(modulus: &BigUint) -> BigUint {
    assert!(modulus > &BigUint::from(1u8), "modulus must be at least 2");
    let extra_bytes = (modulus.bits() as usize).div_ceil(8) + 8;
    loop {
        let candidate = BigUint::from_bytes_be(&bytes(extra_bytes)) % modulus;
        if candidate != BigUint::ZERO {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_returns_the_requested_length() {
        assert_eq!(bytes(0).len(), 0);
        assert_eq!(bytes(32).len(), 32);
    }

    #[test]
    fn successive_draws_differ() {
        // A fixed generator would make every key in the system identical, so this
        // is worth asserting even though it is a weak statistical check.
        assert_ne!(bytes(32), bytes(32));
    }

    #[test]
    fn scalars_are_in_range_and_nonzero() {
        let q = BigUint::from(1_000_003u32);
        for _ in 0..200 {
            let s = scalar_below(&q);
            assert!(s > BigUint::ZERO && s < q);
        }
    }

    #[test]
    fn small_modulus_still_terminates() {
        let two = BigUint::from(2u8);
        for _ in 0..50 {
            assert_eq!(scalar_below(&two), BigUint::from(1u8));
        }
    }
}
