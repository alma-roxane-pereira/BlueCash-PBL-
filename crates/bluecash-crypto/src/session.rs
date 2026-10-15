//! Session setup for the BLE payment channel: X25519, HKDF-SHA256 and AES-256-GCM.
//!
//! This closes the one gap in the crate where the protocol had a single
//! implementation and nothing to check it against. The Android client performs
//! the whole handshake in `SecureChannel.kt`, `Hkdf.kt` and `Crypto.kt`; this
//! module is the same construction in Rust, so the mint (and the tests) can
//! derive and verify a session rather than take the client's word for it.
//!
//! # The handshake
//!
//! Payer and merchant exchange ephemeral X25519 public keys under a
//! commit-then-reveal, then both compute:
//!
//! ```text
//! transcript = SHA256("BCHS|v1|" ‖ epk_payer ‖ epk_merchant)
//! p2m        = HKDF(ikm = shared, salt = transcript, info = "bluecash payer->merchant", 32)
//! m2p        = HKDF(ikm = shared, salt = transcript, info = "bluecash merchant->payer", 32)
//! sas        = HKDF(ikm = shared, salt = transcript, info = "bluecash sas", 4) as u32 % 10^6
//! ```
//!
//! The transcript binds *both* ephemeral keys, so a man in the middle who swaps
//! either one derives different keys and shows a different six-digit code on
//! each side — which is what the users compare out of band.
//!
//! # Byte-compatibility
//!
//! Every label, length and byte order here matches the Kotlin client exactly:
//! the `|v1|` labels, the HKDF info strings, the four-byte big-endian SAS, the
//! 12-byte nonce holding a big-endian counter in its *last* eight bytes, and the
//! AAD `bluecash-v1`. Changing any of them silently breaks interoperability, so
//! the tests pin them as literals rather than deriving them from the constants.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::rng;
use crate::sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation prefix for the handshake transcript.
const TRANSCRIPT_LABEL: &[u8] = b"BCHS|v1|";
/// HKDF `info` for the payer-to-merchant direction.
const INFO_P2M: &[u8] = b"bluecash payer->merchant";
/// HKDF `info` for the merchant-to-payer direction.
const INFO_M2P: &[u8] = b"bluecash merchant->payer";
/// HKDF `info` for the short authentication string.
const INFO_SAS: &[u8] = b"bluecash sas";
/// Additional authenticated data on every record. Not secret; it binds the
/// ciphertext to this protocol version.
const AAD: &[u8] = b"bluecash-v1";

/// Length of an X25519 key, a session key and the transcript hash.
pub const KEY_LEN: usize = 32;
/// AES-GCM nonce length, in bytes.
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length, in bytes (128-bit tag).
pub const TAG_LEN: usize = 16;

/// Everything that can go wrong establishing or using a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// A key or transcript was not exactly [`KEY_LEN`] bytes.
    BadKeyLength {
        /// Which value was wrong.
        what: &'static str,
        /// The length that was supplied.
        got: usize,
    },
    /// The requested HKDF output length is outside `1..=255*32`.
    BadOutputLength(usize),
    /// The X25519 agreement produced an all-zero shared secret, which means the
    /// peer sent a low-order point. BouncyCastle's `agree()` throws here too;
    /// continuing would give an attacker a key they already know.
    NonContributoryKeyExchange,
    /// Decryption failed: the record was tampered with, replayed, dropped or
    /// delivered out of order. GCM cannot tell these apart, and the session must
    /// be abandoned in all four cases.
    DecryptionFailed,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadKeyLength { what, got } => {
                write!(f, "{what} must be exactly {KEY_LEN} bytes, got {got}")
            }
            Self::BadOutputLength(n) => {
                write!(f, "hkdf output length {n} is outside 1..=8160")
            }
            Self::NonContributoryKeyExchange => {
                write!(f, "x25519 agreement produced an all-zero shared secret")
            }
            Self::DecryptionFailed => write!(
                f,
                "record failed authentication (tampered, replayed or out of order)"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

fn fixed(what: &'static str, b: &[u8]) -> Result<[u8; KEY_LEN], SessionError> {
    <[u8; KEY_LEN]>::try_from(b).map_err(|_| SessionError::BadKeyLength { what, got: b.len() })
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869)
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // RFC 5869 section 2.2: an absent salt is HashLen zero bytes. The Kotlin
    // `Hkdf` makes the same substitution before constructing the Mac, so an
    // empty salt must not be passed through as an empty HMAC key.
    let zeros = [0u8; 32];
    let key = if key.is_empty() { &zeros[..] } else { key };
    // Fully qualified: `aes_gcm::KeyInit` is also in scope and offers the
    // same constructor name.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// HKDF-SHA256 extract-then-expand (RFC 5869).
///
/// `length` is capped at `255 * 32` because the expand step counts in a single
/// byte. An empty `salt` is treated as 32 zero bytes, matching both RFC 5869 and
/// the Kotlin implementation.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, SessionError> {
    if length == 0 || length > 255 * 32 {
        return Err(SessionError::BadOutputLength(length));
    }
    let prk = hmac_sha256(salt, ikm);

    let mut out = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < length {
        let mut block = Vec::with_capacity(t.len() + info.len() + 1);
        block.extend_from_slice(&t);
        block.extend_from_slice(info);
        block.push(counter);

        let next = hmac_sha256(&prk, &block);
        t.clear();
        t.extend_from_slice(&next);
        out.extend_from_slice(&next);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    Ok(out)
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

/// An ephemeral X25519 keypair. One per payment; never written to storage.
///
/// The secret is zeroized when the keypair is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKeypair {
    secret: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
}

impl EphemeralKeypair {
    /// Generates a fresh keypair from OS randomness.
    pub fn generate() -> Self {
        let mut secret = [0u8; KEY_LEN];
        rng::fill(&mut secret);
        let public = x25519_public(&secret);
        Self { secret, public }
    }

    /// Rebuilds a keypair from a known secret, for test vectors.
    pub fn from_secret(secret: [u8; KEY_LEN]) -> Self {
        let public = x25519_public(&secret);
        Self { secret, public }
    }

    /// The public key to send to the peer.
    pub fn public(&self) -> [u8; KEY_LEN] {
        self.public
    }

    /// The X25519 shared secret with `peer_public`.
    ///
    /// Returns [`SessionError::NonContributoryKeyExchange`] if the peer sent a
    /// low-order point, which would otherwise yield a shared secret the
    /// attacker already knows.
    pub fn agree(&self, peer_public: &[u8]) -> Result<[u8; KEY_LEN], SessionError> {
        x25519_agree(&self.secret, peer_public)
    }
}

impl core::fmt::Debug for EphemeralKeypair {
    /// Prints the public key only: a derived `Debug` would put the secret into
    /// any log line or panic message that formats this type.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralKeypair")
            .field("public", &hex_prefix(&self.public))
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The first four bytes of `b` in hex: enough to tell two keys apart in a log,
/// not enough to be useful to anyone reading it.
fn hex_prefix(b: &[u8]) -> String {
    b.iter().take(4).map(|x| format!("{x:02x}")).collect()
}

/// The X25519 public key for a 32-byte secret (clamped per RFC 7748).
pub fn x25519_public(secret: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let sk = x25519_dalek::StaticSecret::from(*secret);
    x25519_dalek::PublicKey::from(&sk).to_bytes()
}

/// Raw X25519 agreement, rejecting an all-zero result.
pub fn x25519_agree(
    secret: &[u8; KEY_LEN],
    peer_public: &[u8],
) -> Result<[u8; KEY_LEN], SessionError> {
    let peer = fixed("peer public key", peer_public)?;
    let sk = x25519_dalek::StaticSecret::from(*secret);
    let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
    if !shared.was_contributory() {
        return Err(SessionError::NonContributoryKeyExchange);
    }
    Ok(shared.to_bytes())
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// The keys and short code derived from one handshake.
///
/// `send_key` and `recv_key` are assigned by role, so the two sides of a session
/// hold the same pair in opposite order.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Key for records this side sends.
    pub send_key: [u8; KEY_LEN],
    /// Key for records this side receives.
    pub recv_key: [u8; KEY_LEN],
    /// Six-digit short authentication string, compared out of band.
    pub sas: String,
    /// The handshake transcript hash, signed by both sides to authenticate.
    pub transcript: [u8; KEY_LEN],
}

impl core::fmt::Debug for SessionKeys {
    /// Deliberately omits both keys; see [`EphemeralKeypair`]'s `Debug`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("sas", &self.sas)
            .field("transcript", &hex_prefix(&self.transcript))
            .finish_non_exhaustive()
    }
}

/// The handshake transcript: `SHA256("BCHS|v1|" ‖ epk_payer ‖ epk_merchant)`.
///
/// The payer's key always comes first, whichever side is computing it.
pub fn transcript(epk_payer: &[u8], epk_merchant: &[u8]) -> [u8; 32] {
    sha256(&[TRANSCRIPT_LABEL, epk_payer, epk_merchant])
}

/// Derives both directional keys and the SAS from a completed key exchange.
///
/// `is_payer` selects which directional key becomes `send_key`. Mirrors
/// `Handshake.derive` in `SecureChannel.kt`.
pub fn derive_session_keys(
    shared: &[u8],
    epk_payer: &[u8],
    epk_merchant: &[u8],
    is_payer: bool,
) -> Result<SessionKeys, SessionError> {
    let transcript = transcript(epk_payer, epk_merchant);

    let p2m = fixed(
        "derived key",
        &hkdf_sha256(shared, &transcript, INFO_P2M, KEY_LEN)?,
    )?;
    let m2p = fixed(
        "derived key",
        &hkdf_sha256(shared, &transcript, INFO_M2P, KEY_LEN)?,
    )?;

    let sas_bytes = hkdf_sha256(shared, &transcript, INFO_SAS, 4)?;
    let v = u32::from_be_bytes([sas_bytes[0], sas_bytes[1], sas_bytes[2], sas_bytes[3]]);
    let sas = format!("{:06}", v % 1_000_000);

    let (send_key, recv_key) = if is_payer { (p2m, m2p) } else { (m2p, p2m) };
    Ok(SessionKeys {
        send_key,
        recv_key,
        sas,
        transcript,
    })
}

/// The message each side signs with its long-term key to authenticate the
/// handshake: `"BCAUTH|v1|{role}|" ‖ transcript`.
pub fn auth_message(role: &str, transcript: &[u8]) -> Vec<u8> {
    let mut out = format!("BCAUTH|v1|{role}|").into_bytes();
    out.extend_from_slice(transcript);
    out
}

// ---------------------------------------------------------------------------
// The record layer
// ---------------------------------------------------------------------------

/// The 12-byte nonce for message `counter`: zeros, then the counter big-endian
/// in the last eight bytes.
pub fn nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Encrypts one record at an explicit counter.
///
/// The stateless form of [`SecureChannel::seal`], for callers that track the
/// counter themselves -- the Python bindings, and tests that need to produce a
/// record at a chosen position. Reusing a counter under one key is fatal to
/// GCM, so a caller that uses this owns that invariant.
pub fn seal_at(key: &[u8; KEY_LEN], counter: u64, plain: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce(counter)),
            Payload {
                msg: plain,
                aad: AAD,
            },
        )
        .expect("AES-GCM encryption of a BLE-sized record cannot fail")
}

/// Decrypts one record at an explicit counter.
///
/// The stateless form of [`SecureChannel::open`].
pub fn open_at(
    key: &[u8; KEY_LEN],
    counter: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SessionError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce(counter)),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| SessionError::DecryptionFailed)
}

/// AES-256-GCM over the BLE link, with an implicit message counter as the nonce.
///
/// Because the counter is never transmitted, a replayed, dropped, reordered or
/// modified record simply fails authentication. The session must be abandoned
/// on the first failure rather than resynchronised: a receiver that searched
/// for a matching counter would accept replays.
///
/// Both keys are zeroized when the channel is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureChannel {
    send_key: [u8; KEY_LEN],
    recv_key: [u8; KEY_LEN],
    send_ctr: u64,
    recv_ctr: u64,
}

impl SecureChannel {
    /// Opens a channel over an already-derived pair of keys.
    pub fn new(send_key: [u8; KEY_LEN], recv_key: [u8; KEY_LEN]) -> Self {
        Self {
            send_key,
            recv_key,
            send_ctr: 0,
            recv_ctr: 0,
        }
    }

    /// Opens a channel from the output of [`derive_session_keys`].
    pub fn from_keys(keys: &SessionKeys) -> Self {
        Self::new(keys.send_key, keys.recv_key)
    }

    /// Encrypts the next outbound record and advances the send counter.
    pub fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let out = seal_at(&self.send_key, self.send_ctr, plain);
        self.send_ctr += 1;
        out
    }

    /// Decrypts the next inbound record, advancing the receive counter only on
    /// success — so a rejected record leaves the channel exactly where it was.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
        let out = open_at(&self.recv_key, self.recv_ctr, ciphertext)?;
        self.recv_ctr += 1;
        Ok(out)
    }

    /// Number of records sent so far.
    pub fn sent(&self) -> u64 {
        self.send_ctr
    }

    /// Number of records accepted so far.
    pub fn received(&self) -> u64 {
        self.recv_ctr
    }
}
