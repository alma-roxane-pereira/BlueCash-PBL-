//! Chaum-style RSA blind signatures with a full-domain hash.
//!
//! The wallet *blinds* a token message so the mint can sign it without seeing
//! it; the mint signs the blinded value; the wallet *unblinds* to get an
//! ordinary RSA signature on the original message. The mint cannot later link
//! the signature it sees in settlement to the issuance it performed — that
//! unlinkability is what makes the cash offline-spendable and private.
//!
//! `API_CONTRACT.md` fixes the parameters: RSA-2048, `e = 65537`, full-domain
//! hash as implemented in [`crate::fdh`]. A signature `s` over `message` is
//! valid iff `s^e mod n == FDH(message, n)`.
//!
//! Reference implementations this must match:
//! * `RsaBlind` in `core/RsaBlind.kt` (client: blind, unblind, verify)
//! * `/mint/issue` in `reference-server/server.py` (mint: `pow(m, d, n)`)
//!
//! # What this module does not do
//!
//! It performs no padding check beyond the FDH, and no RSA key generation. The
//! mint's private exponent is supplied by the caller, which keeps key custody
//! (HSM, file, env) a backend concern rather than a crypto-core one.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;

use crate::{fdh::fdh, rng};

/// Why a blind-signature operation could not be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindError {
    /// The modulus is too small to be a usable RSA modulus.
    ModulusTooSmall,
    /// A value that must lie in `(0, n)` did not.
    OutOfRange,
    /// The blinding factor had no inverse mod `n`, so unblinding is impossible.
    /// With a proper RSA modulus this means the factor shared a factor with `n`.
    NotInvertible,
}

impl core::fmt::Display for BlindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ModulusTooSmall => write!(f, "RSA modulus is too small"),
            Self::OutOfRange => write!(f, "value out of range for this modulus"),
            Self::NotInvertible => write!(f, "blinding factor is not invertible mod n"),
        }
    }
}

impl std::error::Error for BlindError {}

/// A blinded message together with the secret blinding factor that produced it.
///
/// `r` must be kept by the wallet until the mint responds: without it the
/// signature cannot be unblinded and the token is lost. It must never be sent
/// to the mint, or the blinding is undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blinded {
    /// The value to send to the mint: `FDH(message) * r^e mod n`.
    pub blinded_message: BigUint,
    /// The secret blinding factor. Keep private.
    pub r: BigUint,
}

/// Blinds `message` for signing under the public key `(n, e)`.
///
/// Draws a fresh random `r` coprime to `n` and returns `FDH(message) * r^e mod n`.
/// Mirrors `RsaBlind.blind`, which rejects `r < 2` and any `r` sharing a factor
/// with `n`.
///
/// # Errors
///
/// Returns [`BlindError::ModulusTooSmall`] if `n < 4`, which leaves no room to
/// draw a blinding factor.
pub fn blind(message: &[u8], n: &BigUint, e: &BigUint) -> Result<Blinded, BlindError> {
    if n < &BigUint::from(4u8) {
        return Err(BlindError::ModulusTooSmall);
    }
    let m = fdh(message, n);
    let r = random_blinding_factor(n);
    Ok(Blinded {
        blinded_message: (&m * r.modpow(e, n)) % n,
        r,
    })
}

/// Blinds `message` with a caller-supplied `r`.
///
/// Exists so tests can reproduce a known blinding deterministically. Production
/// callers should use [`blind`], which draws `r` from the OS.
///
/// # Errors
///
/// Returns [`BlindError::OutOfRange`] if `r` is not in `[2, n)`, or
/// [`BlindError::NotInvertible`] if `gcd(r, n) != 1`.
pub fn blind_with(
    message: &[u8],
    n: &BigUint,
    e: &BigUint,
    r: BigUint,
) -> Result<Blinded, BlindError> {
    if r < BigUint::from(2u8) || &r >= n {
        return Err(BlindError::OutOfRange);
    }
    if !r.gcd(n).is_one() {
        return Err(BlindError::NotInvertible);
    }
    let m = fdh(message, n);
    Ok(Blinded {
        blinded_message: (&m * r.modpow(e, n)) % n,
        r,
    })
}

/// Mint side: raises the blinded value to the private exponent, `blinded^d mod n`.
///
/// The mint learns nothing about the message. It is signing a uniformly random
/// looking value, which is exactly why issuance must be authorised some other
/// way — in this protocol by the device credential checked in `/mint/issue`.
///
/// # Errors
///
/// Returns [`BlindError::OutOfRange`] unless `0 < blinded < n`, matching the
/// `require` in `RsaBlind.signBlinded` and the range check in `server.py`.
pub fn sign_blinded(blinded: &BigUint, n: &BigUint, d: &BigUint) -> Result<BigUint, BlindError> {
    if blinded == &BigUint::ZERO || blinded >= n {
        return Err(BlindError::OutOfRange);
    }
    Ok(blinded.modpow(d, n))
}

/// Removes the blinding: `blind_sig * r^-1 mod n`.
///
/// # Errors
///
/// Returns [`BlindError::NotInvertible`] if `r` has no inverse mod `n`.
pub fn unblind(blind_sig: &BigUint, r: &BigUint, n: &BigUint) -> Result<BigUint, BlindError> {
    let r_inv = mod_inverse(r, n).ok_or(BlindError::NotInvertible)?;
    Ok((blind_sig * r_inv) % n)
}

/// Verifies an unblinded signature: `sig^e mod n == FDH(message, n)`.
///
/// Returns `false` on any out-of-range input rather than erroring, so callers
/// can treat it as a predicate. Matches `RsaBlind.verify` and `verify_token` in
/// `server.py`, both of which reject `sig <= 0` and `sig >= n` before the modpow.
pub fn verify(message: &[u8], sig: &BigUint, n: &BigUint, e: &BigUint) -> bool {
    if sig == &BigUint::ZERO || sig >= n {
        return false;
    }
    sig.modpow(e, n) == fdh(message, n)
}

/// A random `r` in `[2, n)` with `gcd(r, n) = 1`.
fn random_blinding_factor(n: &BigUint) -> BigUint {
    loop {
        let r = rng::scalar_below(n);
        if r >= BigUint::from(2u8) && r.gcd(n).is_one() {
            return r;
        }
    }
}

/// Modular inverse via the extended Euclidean algorithm on signed integers.
///
/// `num-bigint`'s `BigUint` has no `modinv`, and the signed `modpow(-1)` trick
/// used in Python is not available here, so this is explicit.
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_integer::ExtendedGcd;

    let a = BigInt::from(a.clone());
    let m_i = BigInt::from(m.clone());
    let ExtendedGcd { gcd, x, .. } = a.extended_gcd(&m_i);
    if !gcd.is_one() {
        return None;
    }
    // x may be negative; bring it back into [0, m).
    let inv = ((x % &m_i) + &m_i) % &m_i;
    inv.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small but real RSA key, so the full round trip can run in a unit test.
    /// p = 61, q = 53, n = 3233, e = 17, d = 413.
    const SMALL_N: u32 = 3233;
    const SMALL_E: u32 = 17;
    const SMALL_D: u32 = 413;

    fn small() -> (BigUint, BigUint, BigUint) {
        (
            BigUint::from(SMALL_N),
            BigUint::from(SMALL_E),
            BigUint::from(SMALL_D),
        )
    }

    #[test]
    fn small_key_is_a_valid_rsa_key() {
        // Sanity: e*d == 1 mod lambda(n), so plain sign/verify must round-trip.
        let (n, e, d) = small();
        let m = BigUint::from(42u32);
        assert_eq!(m.modpow(&d, &n).modpow(&e, &n), m);
    }

    #[test]
    fn blind_sign_unblind_verify_round_trip() {
        let (n, e, d) = small();
        let msg = b"BCTOKEN|v1|d100|tok1|0a|0b";

        let b = blind(msg, &n, &e).unwrap();
        let bs = sign_blinded(&b.blinded_message, &n, &d).unwrap();
        let sig = unblind(&bs, &b.r, &n).unwrap();

        assert!(verify(msg, &sig, &n, &e), "unblinded signature must verify");
    }

    #[test]
    fn unblinded_signature_equals_a_direct_signature() {
        // The whole point: the mint never saw the message, yet the result is
        // indistinguishable from a signature it could have produced directly.
        let (n, e, d) = small();
        let msg = b"direct-vs-blinded";
        let direct = fdh(msg, &n).modpow(&d, &n);

        let b = blind_with(msg, &n, &e, BigUint::from(7u32)).unwrap();
        let sig = unblind(&sign_blinded(&b.blinded_message, &n, &d).unwrap(), &b.r, &n).unwrap();

        assert_eq!(sig, direct);
    }

    #[test]
    fn blinding_hides_the_message_from_the_mint() {
        let (n, e, _) = small();
        let msg = b"secret";
        let m = fdh(msg, &n);
        // Two blindings of the same message differ, and neither equals the digest.
        let a = blind(msg, &n, &e).unwrap();
        let b = blind(msg, &n, &e).unwrap();
        assert_ne!(a.blinded_message, m);
        assert_ne!(b.blinded_message, m);
        assert_ne!(a.blinded_message, b.blinded_message, "r must be fresh");
    }

    #[test]
    fn verification_rejects_a_tampered_message_or_signature() {
        let (n, e, d) = small();
        let msg = b"original";
        let b = blind(msg, &n, &e).unwrap();
        let sig = unblind(&sign_blinded(&b.blinded_message, &n, &d).unwrap(), &b.r, &n).unwrap();

        assert!(verify(msg, &sig, &n, &e));
        assert!(!verify(b"tampered", &sig, &n, &e));
        assert!(!verify(msg, &(&sig + BigUint::from(1u8)), &n, &e));
        // Out-of-range signatures are refused outright.
        assert!(!verify(msg, &BigUint::ZERO, &n, &e));
        assert!(!verify(msg, &n.clone(), &n, &e));
        assert!(!verify(msg, &(n.clone() + BigUint::from(1u8)), &n, &e));
    }

    #[test]
    fn wrong_blinding_factor_does_not_unblind() {
        let (n, e, d) = small();
        let msg = b"mismatched-r";
        let b = blind_with(msg, &n, &e, BigUint::from(7u32)).unwrap();
        let bs = sign_blinded(&b.blinded_message, &n, &d).unwrap();
        let wrong = unblind(&bs, &BigUint::from(11u32), &n).unwrap();
        assert!(!verify(msg, &wrong, &n, &e));
    }

    #[test]
    fn sign_blinded_enforces_its_range() {
        let (n, _, d) = small();
        assert_eq!(
            sign_blinded(&BigUint::ZERO, &n, &d),
            Err(BlindError::OutOfRange)
        );
        assert_eq!(
            sign_blinded(&n.clone(), &n, &d),
            Err(BlindError::OutOfRange)
        );
        assert!(sign_blinded(&BigUint::from(1u8), &n, &d).is_ok());
    }

    #[test]
    fn blind_with_rejects_bad_factors() {
        let (n, e) = (BigUint::from(SMALL_N), BigUint::from(SMALL_E));
        assert_eq!(
            blind_with(b"m", &n, &e, BigUint::from(1u8)),
            Err(BlindError::OutOfRange)
        );
        assert_eq!(
            blind_with(b"m", &n, &e, n.clone()),
            Err(BlindError::OutOfRange)
        );
        // 61 divides n = 3233, so it has no inverse.
        assert_eq!(
            blind_with(b"m", &n, &e, BigUint::from(61u32)),
            Err(BlindError::NotInvertible)
        );
    }

    #[test]
    fn tiny_modulus_is_refused() {
        let e = BigUint::from(3u8);
        assert_eq!(
            blind(b"m", &BigUint::from(3u8), &e),
            Err(BlindError::ModulusTooSmall)
        );
    }

    #[test]
    fn mod_inverse_agrees_with_definition() {
        let m = BigUint::from(3233u32);
        for a in [2u32, 7, 11, 100, 3000] {
            let a = BigUint::from(a);
            if let Some(inv) = mod_inverse(&a, &m) {
                assert_eq!((&a * &inv) % &m, BigUint::from(1u8), "inverse of {a}");
            }
        }
        // 61 | 3233, so no inverse exists.
        assert_eq!(mod_inverse(&BigUint::from(61u32), &m), None);
    }
}
