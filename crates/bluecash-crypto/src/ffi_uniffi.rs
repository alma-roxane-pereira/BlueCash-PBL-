//! UniFFI bindings: the session crypto, for the Android client.
//!
//! The client currently implements the handshake a second time, in Kotlin over
//! BouncyCastle and the JCE. The two agree byte for byte — `SessionVectorTests`
//! in `CoreTests.kt` pins them to vectors from this crate — but agreeing is not
//! the same as being one implementation. This module is the path to collapsing
//! them into one, so the protocol has a single place where a change can be made.
//!
//! The first slice is the session layer, chosen because it is self-contained:
//! it takes bytes and returns bytes, holds no Android state, and touches none
//! of the key storage that `DeviceIdentityStore` owns. The blind signatures,
//! Merkle proofs and share scheme can follow the same route once this one is
//! proved on a device.
//!
//! # What this is not
//!
//! Scaffolding alone does not mean Android calls Rust. That needs the `.so`
//! cross-compiled for each ABI, packaged into `jniLibs`, loaded through JNA at
//! runtime, and actually exercised. Until then the Kotlin implementation is
//! still the one doing the work.
//!
//! Compiled only with the `uniffi-bindings` feature.

use crate::session;

/// Errors crossing the FFI boundary.
///
/// A flat enum, not a wrapper around [`session::SessionError`]: the Kotlin side
/// gets one exception type per failure it can actually act on, and the variants
/// carry no key material, because an exception message ends up in a log.
#[derive(Debug, uniffi::Error)]
pub enum SessionFfiError {
    /// A key was not 32 bytes.
    BadKeyLength {
        /// Which input was wrong.
        what: String,
        /// The length supplied.
        got: u32,
    },

    /// The requested HKDF output length is outside `1..=8160`.
    BadOutputLength {
        /// The length requested.
        length: u64,
    },

    /// The peer sent a low-order point. Abandon the session: continuing would
    /// use a shared secret the attacker already knows.
    NonContributoryKeyExchange,

    /// The record failed authentication — tampered with, replayed, reordered or
    /// truncated. GCM cannot distinguish these, and all four mean the same
    /// thing: stop using this session.
    DecryptionFailed,
}

// Written out rather than derived: the crate has no `thiserror` dependency and
// the other error types here are hand-written too.
impl core::fmt::Display for SessionFfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadKeyLength { what, got } => {
                write!(f, "{what} must be exactly 32 bytes, got {got}")
            }
            Self::BadOutputLength { length } => {
                write!(f, "hkdf output length {length} is outside 1..=8160")
            }
            Self::NonContributoryKeyExchange => {
                write!(f, "x25519 agreement produced an all-zero shared secret")
            }
            Self::DecryptionFailed => write!(f, "record failed authentication"),
        }
    }
}

impl std::error::Error for SessionFfiError {}

impl From<session::SessionError> for SessionFfiError {
    fn from(e: session::SessionError) -> Self {
        match e {
            session::SessionError::BadKeyLength { what, got } => Self::BadKeyLength {
                what: what.to_string(),
                got: got as u32,
            },
            session::SessionError::BadOutputLength(length) => Self::BadOutputLength {
                length: length as u64,
            },
            session::SessionError::NonContributoryKeyExchange => Self::NonContributoryKeyExchange,
            session::SessionError::DecryptionFailed => Self::DecryptionFailed,
        }
    }
}

/// The result of a handshake: both directional keys, the transcript and the
/// six-digit short authentication string.
///
/// A record rather than an object with methods, so the keys cross the boundary
/// once and the Kotlin side owns them. There is no `Display`, so no generated
/// `toString` can print a key into a log line.
#[derive(uniffi::Record)]
pub struct SessionKeysFfi {
    /// Key for records this side sends.
    pub send_key: Vec<u8>,
    /// Key for records this side receives.
    pub recv_key: Vec<u8>,
    /// The handshake transcript hash, signed by both sides.
    pub transcript: Vec<u8>,
    /// Six digits, compared out of band by the two users.
    pub sas: String,
}

fn key32(what: &'static str, b: &[u8]) -> Result<[u8; 32], SessionFfiError> {
    <[u8; 32]>::try_from(b).map_err(|_| SessionFfiError::BadKeyLength {
        what: what.to_string(),
        got: b.len() as u32,
    })
}

/// HKDF-SHA256 (RFC 5869). An empty `salt` means 32 zero bytes.
#[uniffi::export]
pub fn hkdf_sha256(
    ikm: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    length: u32,
) -> Result<Vec<u8>, SessionFfiError> {
    Ok(session::hkdf_sha256(&ikm, &salt, &info, length as usize)?)
}

/// The X25519 public key for a 32-byte secret, clamped per RFC 7748.
#[uniffi::export]
pub fn x25519_public_key(secret: Vec<u8>) -> Result<Vec<u8>, SessionFfiError> {
    let secret = key32("secret", &secret)?;
    Ok(session::x25519_public(&secret).to_vec())
}

/// X25519 agreement, rejecting a low-order peer key.
#[uniffi::export]
pub fn x25519_agree(secret: Vec<u8>, peer_public: Vec<u8>) -> Result<Vec<u8>, SessionFfiError> {
    let secret = key32("secret", &secret)?;
    Ok(session::x25519_agree(&secret, &peer_public)?.to_vec())
}

/// `SHA256("BCHS|v1|" + epk_payer + epk_merchant)`. The payer's key is first,
/// whichever side computes it.
#[uniffi::export]
pub fn session_transcript(epk_payer: Vec<u8>, epk_merchant: Vec<u8>) -> Vec<u8> {
    session::transcript(&epk_payer, &epk_merchant).to_vec()
}

/// Derives both directional keys and the SAS. `is_payer` decides which key is
/// this side's send key.
#[uniffi::export]
pub fn derive_session_keys(
    shared: Vec<u8>,
    epk_payer: Vec<u8>,
    epk_merchant: Vec<u8>,
    is_payer: bool,
) -> Result<SessionKeysFfi, SessionFfiError> {
    let keys = session::derive_session_keys(&shared, &epk_payer, &epk_merchant, is_payer)?;
    Ok(SessionKeysFfi {
        send_key: keys.send_key.to_vec(),
        recv_key: keys.recv_key.to_vec(),
        transcript: keys.transcript.to_vec(),
        sas: keys.sas,
    })
}

/// `"BCAUTH|v1|{role}|" + transcript`, signed by each side's long-term key.
#[uniffi::export]
pub fn session_auth_message(role: String, transcript: Vec<u8>) -> Vec<u8> {
    session::auth_message(&role, &transcript)
}

/// The 12-byte AES-GCM nonce for a message index.
#[uniffi::export]
pub fn session_nonce(counter: u64) -> Vec<u8> {
    session::nonce(counter).to_vec()
}

/// Seals one AES-256-GCM record at an explicit counter.
///
/// The counter is a parameter rather than hidden state, so two callers cannot
/// share a key and silently reuse a nonce — which would break GCM outright.
#[uniffi::export]
pub fn session_seal(
    send_key: Vec<u8>,
    counter: u64,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, SessionFfiError> {
    let key = key32("send_key", &send_key)?;
    Ok(session::seal_at(&key, counter, &plaintext))
}

/// Opens one record. Fails if it was tampered with, replayed, truncated, or
/// sealed under a different key or counter.
#[uniffi::export]
pub fn session_open(
    recv_key: Vec<u8>,
    counter: u64,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, SessionFfiError> {
    let key = key32("recv_key", &recv_key)?;
    Ok(session::open_at(&key, counter, &ciphertext)?)
}
