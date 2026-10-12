//! Ed25519 signing and verification (RFC 8032).
//!
//! Used for three things in the protocol, all over the `|`-separated UTF-8
//! strings defined in `API_CONTRACT.md`:
//!
//! * the device proves ownership of its identity key (`BCREG`, `BCISSUE`, `BCSPEND`)
//! * the merchant signs receipts (`BCRECEIPT`)
//! * the mint signs device credentials (`BCCRED`)
//!
//! Reference implementations this must match:
//! * `Ed25519` in `core/Crypto.kt` — BouncyCastle `Ed25519Signer`
//! * `ed_verify` / `ED.sign` in `reference-server/server.py` — `cryptography`
//!
//! All three are plain RFC 8032 Ed25519 over 32-byte seeds, 32-byte public keys
//! and 64-byte signatures, so interoperability rests on the standard rather than
//! on anything protocol-specific. The differential tests confirm it rather than
//! assume it.
//!
//! # Malleability
//!
//! `ed25519-dalek` rejects non-canonical signatures and small-order public keys
//! by default, which is stricter than some implementations. That is the safer
//! direction — this crate never accepts a signature the client would reject.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::rng;

/// Length of an Ed25519 private seed.
pub const SEED_LEN: usize = 32;
/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Why an Ed25519 operation could not be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519Error {
    /// A byte string had the wrong length for what it was meant to be.
    BadLength {
        /// What was expected.
        expected: usize,
        /// What was supplied.
        got: usize,
    },
    /// The bytes were the right length but not a valid public key.
    InvalidPublicKey,
}

impl core::fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLength { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            Self::InvalidPublicKey => write!(f, "not a valid ed25519 public key"),
        }
    }
}

impl std::error::Error for Ed25519Error {}

/// Generates a fresh 32-byte private seed from OS randomness.
pub fn generate_seed() -> [u8; SEED_LEN] {
    let mut seed = [0u8; SEED_LEN];
    rng::fill(&mut seed);
    seed
}

/// Derives the 32-byte public key for a private `seed`.
///
/// Matches `Ed25519.publicKey(seed)` in Kotlin and
/// `Ed25519PrivateKey.from_private_bytes(seed).public_key()` in Python.
pub fn public_key(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Signs `message` with the private `seed`, returning a 64-byte signature.
pub fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> [u8; SIGNATURE_LEN] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Verifies a signature over `message` under `public_key`.
///
/// Returns `false` for a wrong signature, a malformed signature, or a public key
/// that is not a valid curve point — never panics and never errors, so callers
/// can use it as a predicate. This mirrors `Ed25519.verify` in Kotlin, which
/// catches every exception and returns `false`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk_bytes) = <[u8; PUBLIC_KEY_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; SIGNATURE_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
    vk.verify_strict(message, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

/// A device or mint identity: a private seed and its derived public key.
///
/// The seed is the secret. Nothing here persists it — key custody belongs to the
/// backend (and to Android Keystore on the client side).
#[derive(Clone)]
pub struct Keypair {
    seed: [u8; SEED_LEN],
    public: [u8; PUBLIC_KEY_LEN],
}

impl Keypair {
    /// Generates a new keypair from OS randomness.
    pub fn generate() -> Self {
        Self::from_seed(generate_seed())
    }

    /// Reconstructs a keypair from a stored private seed.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self {
            public: public_key(&seed),
            seed,
        }
    }

    /// Reconstructs from a seed of unchecked length.
    ///
    /// # Errors
    ///
    /// Returns [`Ed25519Error::BadLength`] unless exactly 32 bytes are supplied.
    pub fn from_seed_slice(seed: &[u8]) -> Result<Self, Ed25519Error> {
        let seed = <[u8; SEED_LEN]>::try_from(seed).map_err(|_| Ed25519Error::BadLength {
            expected: SEED_LEN,
            got: seed.len(),
        })?;
        Ok(Self::from_seed(seed))
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// The private seed. Handle as secret material.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }

    /// Signs `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        sign(&self.seed, message)
    }
}

impl core::fmt::Debug for Keypair {
    /// Prints the public key only, so a stray log line cannot leak the seed.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &hex(&self.public))
            .field("seed", &"<redacted>")
            .finish()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 section 7.1, TEST 1.
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_SIG: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    #[test]
    fn matches_rfc8032_test_vector_1() {
        // Empty message. Pins this crate to the standard, independently of the
        // other two implementations.
        assert_eq!(hex(&public_key(&RFC8032_SEED)), RFC8032_PUBLIC);
        assert_eq!(hex(&sign(&RFC8032_SEED, b"")), RFC8032_SIG);
        assert!(verify(
            &public_key(&RFC8032_SEED),
            b"",
            &sign(&RFC8032_SEED, b"")
        ));
    }

    #[test]
    fn matches_rfc8032_test_vector_2() {
        // RFC 8032 7.1 TEST 2: a one-byte message.
        let seed: [u8; 32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        assert_eq!(
            hex(&public_key(&seed)),
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        );
        assert_eq!(
            hex(&sign(&seed, &[0x72])),
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        );
    }

    #[test]
    fn sign_verify_round_trip_on_protocol_strings() {
        let kp = Keypair::generate();
        for msg in [
            &b"BCREG|v1|aabb|0c|1700000000000"[..],
            b"BCSPEND|v1|tok1|ctx-shop-a|100",
            b"BCRECEIPT|v1|r1|tok1|ctx|0a|0b|100|m1|1700000000000",
            b"",
        ] {
            let sig = kp.sign(msg);
            assert!(verify(kp.public_key(), msg, &sig), "failed for {msg:?}");
        }
    }

    #[test]
    fn verification_rejects_wrong_inputs() {
        let kp = Keypair::generate();
        let other = Keypair::generate();
        let msg = b"BCSPEND|v1|tok|ctx|100";
        let sig = kp.sign(msg);

        assert!(verify(kp.public_key(), msg, &sig));
        // Wrong message.
        assert!(!verify(kp.public_key(), b"BCSPEND|v1|tok|ctx|999", &sig));
        // Wrong key.
        assert!(!verify(other.public_key(), msg, &sig));
        // Flipped bit in the signature.
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(!verify(kp.public_key(), msg, &bad));
        // Malformed lengths return false rather than panicking.
        assert!(!verify(&[0u8; 31], msg, &sig));
        assert!(!verify(kp.public_key(), msg, &sig[..63]));
        assert!(!verify(&[], msg, &[]));
    }

    #[test]
    fn signing_is_deterministic() {
        // Ed25519 is deterministic: the same seed and message always give the
        // same signature. The client relies on this for reproducible receipts.
        let kp = Keypair::generate();
        assert_eq!(kp.sign(b"same"), kp.sign(b"same"));
    }

    #[test]
    fn keypair_from_seed_round_trips() {
        let seed = generate_seed();
        let a = Keypair::from_seed(seed);
        let b = Keypair::from_seed_slice(&seed).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.seed(), &seed);
    }

    #[test]
    fn bad_seed_length_is_an_error() {
        assert_eq!(
            Keypair::from_seed_slice(&[0u8; 16]).unwrap_err(),
            Ed25519Error::BadLength {
                expected: 32,
                got: 16
            }
        );
    }

    #[test]
    fn debug_does_not_leak_the_seed() {
        let kp = Keypair::from_seed(RFC8032_SEED);
        let shown = format!("{kp:?}");
        assert!(shown.contains("<redacted>"));
        assert!(!shown.contains(&hex(&RFC8032_SEED)));
    }

    #[test]
    fn distinct_keypairs_are_generated() {
        assert_ne!(
            Keypair::generate().public_key(),
            Keypair::generate().public_key()
        );
    }
}
