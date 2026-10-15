//! Tests for the BLE session layer.
//!
//! Three kinds of check, in order of how much they are worth:
//!
//! 1. **RFC 5869 test vectors.** HKDF-SHA256 is checked against the published
//!    vectors, not against this crate's own output. If these pass, the KDF is
//!    the real one.
//! 2. **Pinned protocol constants.** The labels, lengths and byte orders are
//!    asserted as literals copied from `SecureChannel.kt`. A refactor that
//!    renames a label still breaks interoperability with the phones, and only
//!    a literal catches that.
//! 3. **Properties of the handshake.** That the two sides agree, that a man in
//!    the middle does not, and that the record layer rejects everything it is
//!    supposed to.

use bluecash_crypto::session::{
    auth_message, derive_session_keys, hkdf_sha256, nonce, transcript, x25519_agree, x25519_public,
    EphemeralKeypair, SecureChannel, SessionError,
};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector is valid hex")
}

// ---------------------------------------------------------------------------
// 1. RFC 5869 Appendix A -- the official HKDF-SHA256 vectors
// ---------------------------------------------------------------------------

#[test]
fn rfc5869_test_case_1() {
    let okm = hkdf_sha256(
        &h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        &h("000102030405060708090a0b0c"),
        &h("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )
    .unwrap();
    assert_eq!(
        hex::encode(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

#[test]
fn rfc5869_test_case_2_long_inputs_and_multiple_blocks() {
    let ikm: String = (0u8..=0x4f).map(|b| format!("{b:02x}")).collect();
    let salt: String = (0x60u8..=0xaf).map(|b| format!("{b:02x}")).collect();
    let info: String = (0xb0u8..=0xff).map(|b| format!("{b:02x}")).collect();

    let okm = hkdf_sha256(&h(&ikm), &h(&salt), &h(&info), 82).unwrap();
    assert_eq!(
        hex::encode(okm),
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );
}

#[test]
fn rfc5869_test_case_3_empty_salt_and_info() {
    // The case that matters most here: the Kotlin `Hkdf` substitutes 32 zero
    // bytes for an empty salt, and this vector is what proves that is correct.
    let okm = hkdf_sha256(
        &h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
        &[],
        &[],
        42,
    )
    .unwrap();
    assert_eq!(
        hex::encode(okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn an_explicitly_zero_salt_matches_an_empty_one() {
    let ikm = b"shared secret";
    assert_eq!(
        hkdf_sha256(ikm, &[], b"info", 32).unwrap(),
        hkdf_sha256(ikm, &[0u8; 32], b"info", 32).unwrap()
    );
}

#[test]
fn output_length_is_bounded() {
    assert_eq!(
        hkdf_sha256(b"ikm", b"salt", b"info", 0),
        Err(SessionError::BadOutputLength(0))
    );
    assert!(hkdf_sha256(b"ikm", b"salt", b"info", 255 * 32).is_ok());
    assert_eq!(
        hkdf_sha256(b"ikm", b"salt", b"info", 255 * 32 + 1),
        Err(SessionError::BadOutputLength(255 * 32 + 1))
    );
}

#[test]
fn truncation_is_a_prefix_not_a_separate_derivation() {
    let long = hkdf_sha256(b"ikm", b"salt", b"info", 64).unwrap();
    let short = hkdf_sha256(b"ikm", b"salt", b"info", 20).unwrap();
    assert_eq!(&long[..20], &short[..]);
}

#[test]
fn a_different_info_gives_an_unrelated_key() {
    let a = hkdf_sha256(b"ikm", b"salt", b"bluecash payer->merchant", 32).unwrap();
    let b = hkdf_sha256(b"ikm", b"salt", b"bluecash merchant->payer", 32).unwrap();
    assert_ne!(a, b);
}

// ---------------------------------------------------------------------------
// 2. Pinned protocol constants
// ---------------------------------------------------------------------------

#[test]
fn the_transcript_label_is_bchs_v1() {
    use sha2::{Digest, Sha256};
    let epk_p = [0x11u8; 32];
    let epk_m = [0x22u8; 32];

    let mut expected = Sha256::new();
    expected.update(b"BCHS|v1|");
    expected.update(epk_p);
    expected.update(epk_m);

    assert_eq!(transcript(&epk_p, &epk_m), expected.finalize().as_slice());
}

#[test]
fn the_transcript_is_ordered_payer_then_merchant() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    assert_ne!(transcript(&a, &b), transcript(&b, &a));
}

#[test]
fn the_auth_message_is_bcauth_v1_role_transcript() {
    let t = [0xabu8; 32];
    let mut expected = b"BCAUTH|v1|payer|".to_vec();
    expected.extend_from_slice(&t);
    assert_eq!(auth_message("payer", &t), expected);
    assert_ne!(auth_message("payer", &t), auth_message("merchant", &t));
}

#[test]
fn the_nonce_is_a_big_endian_counter_in_the_last_eight_bytes() {
    assert_eq!(nonce(0), [0u8; 12]);
    assert_eq!(
        nonce(1),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        "counter must be big-endian, right-aligned"
    );
    assert_eq!(
        nonce(0x0102_0304_0506_0708),
        [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}

#[test]
fn the_sas_is_six_digits_zero_padded() {
    // Exercised over many handshakes because the padding only shows up when the
    // value happens to be small, which is roughly one time in ten.
    let mut saw_leading_zero = false;
    for _ in 0..400 {
        let payer = EphemeralKeypair::generate();
        let merchant = EphemeralKeypair::generate();
        let shared = payer.agree(&merchant.public()).unwrap();
        let keys = derive_session_keys(&shared, &payer.public(), &merchant.public(), true).unwrap();

        assert_eq!(keys.sas.len(), 6, "sas was {:?}", keys.sas);
        assert!(keys.sas.chars().all(|c| c.is_ascii_digit()));
        saw_leading_zero |= keys.sas.starts_with('0');
    }
    assert!(saw_leading_zero, "no short value appeared in 400 draws");
}

#[test]
fn the_sas_is_the_four_byte_prefix_reduced() {
    // Reproduces `Handshake.derive`'s arithmetic independently of the function
    // under test, so a change to either byte order or modulus is caught.
    let shared = [0x5au8; 32];
    let epk_p = [0x01u8; 32];
    let epk_m = [0x02u8; 32];

    let raw = hkdf_sha256(&shared, &transcript(&epk_p, &epk_m), b"bluecash sas", 4).unwrap();
    let v = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);

    let keys = derive_session_keys(&shared, &epk_p, &epk_m, true).unwrap();
    assert_eq!(keys.sas, format!("{:06}", v % 1_000_000));
}

// ---------------------------------------------------------------------------
// 3. The handshake
// ---------------------------------------------------------------------------

/// A completed handshake between two fresh parties.
fn handshake() -> (bluecash_crypto::SessionKeys, bluecash_crypto::SessionKeys) {
    let payer = EphemeralKeypair::generate();
    let merchant = EphemeralKeypair::generate();

    let (pp, mp) = (payer.public(), merchant.public());
    let payer_shared = payer.agree(&mp).unwrap();
    let merchant_shared = merchant.agree(&pp).unwrap();
    assert_eq!(payer_shared, merchant_shared, "x25519 did not agree");

    (
        derive_session_keys(&payer_shared, &pp, &mp, true).unwrap(),
        derive_session_keys(&merchant_shared, &pp, &mp, false).unwrap(),
    )
}

#[test]
fn both_sides_derive_the_same_session() {
    let (payer, merchant) = handshake();

    assert_eq!(payer.sas, merchant.sas);
    assert_eq!(payer.transcript, merchant.transcript);
    // Mirrored, not identical: each side's send key is the other's receive key.
    assert_eq!(payer.send_key, merchant.recv_key);
    assert_eq!(payer.recv_key, merchant.send_key);
    assert_ne!(payer.send_key, payer.recv_key);
}

#[test]
fn a_swapped_ephemeral_key_changes_the_short_code() {
    // The property the whole SAS comparison rests on: if a relay substitutes
    // its own key on one side, the two users read out different numbers.
    let payer = EphemeralKeypair::generate();
    let merchant = EphemeralKeypair::generate();
    let attacker = EphemeralKeypair::generate();

    let honest = derive_session_keys(
        &payer.agree(&merchant.public()).unwrap(),
        &payer.public(),
        &merchant.public(),
        true,
    )
    .unwrap();

    // What the merchant computes when the attacker sat in the middle.
    let relayed = derive_session_keys(
        &merchant.agree(&attacker.public()).unwrap(),
        &attacker.public(),
        &merchant.public(),
        false,
    )
    .unwrap();

    assert_ne!(honest.sas, relayed.sas);
    assert_ne!(honest.transcript, relayed.transcript);
    assert_ne!(honest.send_key, relayed.recv_key);
}

#[test]
fn a_low_order_peer_key_is_rejected() {
    // The all-zero point has order 1: every secret agrees to the same zero
    // shared secret, so a session built on it is attacker-readable.
    let me = EphemeralKeypair::generate();
    assert_eq!(
        me.agree(&[0u8; 32]),
        Err(SessionError::NonContributoryKeyExchange)
    );
}

#[test]
fn a_peer_key_of_the_wrong_length_is_rejected() {
    let me = EphemeralKeypair::generate();
    match me.agree(&[0x09u8; 31]) {
        Err(SessionError::BadKeyLength { got, .. }) => assert_eq!(got, 31),
        other => panic!("expected a length error, got {other:?}"),
    }
}

#[test]
fn x25519_matches_rfc7748_section_6_1() {
    // Alice and Bob from RFC 7748, so the curve arithmetic is checked against
    // the specification rather than against itself.
    let alice_sk: [u8; 32] = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .try_into()
        .unwrap();
    let bob_sk: [u8; 32] = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        .try_into()
        .unwrap();

    assert_eq!(
        hex::encode(x25519_public(&alice_sk)),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(x25519_public(&bob_sk)),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );

    let expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert_eq!(
        hex::encode(x25519_agree(&alice_sk, &x25519_public(&bob_sk)).unwrap()),
        expected
    );
    assert_eq!(
        hex::encode(x25519_agree(&bob_sk, &x25519_public(&alice_sk)).unwrap()),
        expected
    );
}

// ---------------------------------------------------------------------------
// 3b. The record layer
// ---------------------------------------------------------------------------

/// The two ends of one session's record layer.
fn channels() -> (SecureChannel, SecureChannel) {
    let (payer, merchant) = handshake();
    (
        SecureChannel::from_keys(&payer),
        SecureChannel::from_keys(&merchant),
    )
}

#[test]
fn a_sealed_record_opens_on_the_other_side() {
    let (mut payer, mut merchant) = channels();
    let sealed = payer.seal(b"BCSPEND|v1|abc|ctx|10");
    assert_eq!(merchant.open(&sealed).unwrap(), b"BCSPEND|v1|abc|ctx|10");
}

#[test]
fn the_ciphertext_carries_a_sixteen_byte_tag_and_hides_the_plaintext() {
    let (mut payer, _) = channels();
    let plain = b"BCSPEND|v1|abc|ctx|10";
    let sealed = payer.seal(plain);

    assert_eq!(sealed.len(), plain.len() + 16);
    assert!(
        !sealed.windows(7).any(|w| w == b"BCSPEND"),
        "plaintext visible in ciphertext"
    );
}

#[test]
fn many_records_stay_in_step() {
    let (mut payer, mut merchant) = channels();
    for i in 0..50u32 {
        let msg = format!("record {i}");
        assert_eq!(
            merchant.open(&payer.seal(msg.as_bytes())).unwrap(),
            msg.as_bytes()
        );
    }
    assert_eq!(payer.sent(), 50);
    assert_eq!(merchant.received(), 50);
}

#[test]
fn the_same_plaintext_twice_gives_different_ciphertext() {
    // The counter nonce must advance; repeating a GCM nonce under one key leaks
    // the XOR of the plaintexts and, worse, the authentication subkey.
    let (mut payer, _) = channels();
    assert_ne!(payer.seal(b"pay 10"), payer.seal(b"pay 10"));
}

#[test]
fn a_replayed_record_is_rejected() {
    let (mut payer, mut merchant) = channels();
    let sealed = payer.seal(b"pay 10");

    assert!(merchant.open(&sealed).is_ok());
    assert_eq!(merchant.open(&sealed), Err(SessionError::DecryptionFailed));
}

#[test]
fn a_reordered_record_is_rejected() {
    let (mut payer, mut merchant) = channels();
    let first = payer.seal(b"first");
    let second = payer.seal(b"second");

    assert_eq!(merchant.open(&second), Err(SessionError::DecryptionFailed));
    // And the receiver has not moved on, so the real first record still opens.
    assert_eq!(merchant.open(&first).unwrap(), b"first");
}

#[test]
fn a_dropped_record_desynchronises_the_channel() {
    let (mut payer, mut merchant) = channels();
    let _lost = payer.seal(b"lost in transit");
    let delivered = payer.seal(b"arrived");

    assert_eq!(
        merchant.open(&delivered),
        Err(SessionError::DecryptionFailed),
        "a gap must abort the session, not be silently skipped"
    );
}

#[test]
fn a_modified_record_is_rejected() {
    let (mut payer, mut merchant) = channels();
    let mut sealed = payer.seal(b"pay 10");
    sealed[0] ^= 0x01;
    assert_eq!(merchant.open(&sealed), Err(SessionError::DecryptionFailed));
}

#[test]
fn a_record_with_a_flipped_tag_bit_is_rejected() {
    let (mut payer, mut merchant) = channels();
    let mut sealed = payer.seal(b"pay 10");
    let last = sealed.len() - 1;
    sealed[last] ^= 0x80;
    assert_eq!(merchant.open(&sealed), Err(SessionError::DecryptionFailed));
}

#[test]
fn a_truncated_record_is_rejected() {
    let (mut payer, mut merchant) = channels();
    let sealed = payer.seal(b"pay 10");
    assert_eq!(
        merchant.open(&sealed[..sealed.len() - 1]),
        Err(SessionError::DecryptionFailed)
    );
    assert_eq!(merchant.open(&[]), Err(SessionError::DecryptionFailed));
}

#[test]
fn a_record_from_a_different_session_is_rejected() {
    let (mut payer_a, _) = channels();
    let (_, mut merchant_b) = channels();
    let sealed = payer_a.seal(b"pay 10");
    assert_eq!(
        merchant_b.open(&sealed),
        Err(SessionError::DecryptionFailed)
    );
}

#[test]
fn a_record_sent_back_in_the_wrong_direction_is_rejected() {
    // The directional keys exist for this: a merchant cannot be made to accept
    // its own message reflected by a relay.
    let (mut payer, mut merchant) = channels();
    let sealed = merchant.seal(b"receipt");
    assert_eq!(merchant.open(&sealed), Err(SessionError::DecryptionFailed));
    assert!(payer.open(&sealed).is_ok());
}

#[test]
fn a_rejected_record_does_not_advance_the_receiver() {
    let (mut payer, mut merchant) = channels();
    let mut tampered = payer.seal(b"first");
    tampered[0] ^= 0xff;

    assert!(merchant.open(&tampered).is_err());
    assert_eq!(merchant.received(), 0);
}

#[test]
fn an_empty_plaintext_round_trips() {
    let (mut payer, mut merchant) = channels();
    let sealed = payer.seal(b"");
    assert_eq!(sealed.len(), 16);
    assert_eq!(merchant.open(&sealed).unwrap(), b"");
}

#[test]
fn a_full_size_ble_record_round_trips() {
    let (mut payer, mut merchant) = channels();
    let big = vec![0x5a; 512];
    assert_eq!(merchant.open(&payer.seal(&big)).unwrap(), big);
}

#[test]
fn secrets_do_not_appear_in_debug_output() {
    // A panic or a log line formats these types; neither may print key material.
    let kp = EphemeralKeypair::generate();
    let rendered = format!("{kp:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let (payer, _) = handshake();
    let rendered = format!("{payer:?}");
    assert!(
        !rendered.contains(&hex::encode(payer.send_key)),
        "{rendered}"
    );
    assert!(
        !rendered.contains(&hex::encode(payer.recv_key)),
        "{rendered}"
    );
}

// ---------------------------------------------------------------------------
// 4. Differential vectors for the Android client
// ---------------------------------------------------------------------------

/// Prints the vectors asserted by `sessionCryptoMatchesTheRustCore` in
/// `CoreTests.kt`. Ignored by default; run it only to regenerate them:
///
/// ```text
/// cargo test --test session -- --ignored --nocapture print_kotlin_vectors
/// ```
///
/// The two implementations are independent (dalek and BouncyCastle, RustCrypto
/// and the JCE), so agreeing on these values is the only evidence that a phone
/// and the mint can actually talk to each other.
#[test]
#[ignore = "generator, not an assertion"]
fn print_kotlin_vectors() {
    let payer_sk = [0x11u8; 32];
    let merchant_sk = [0x22u8; 32];

    let payer = EphemeralKeypair::from_secret(payer_sk);
    let merchant = EphemeralKeypair::from_secret(merchant_sk);
    let (pp, mp) = (payer.public(), merchant.public());
    let shared = payer.agree(&mp).unwrap();

    let keys = derive_session_keys(&shared, &pp, &mp, true).unwrap();
    let mut channel = SecureChannel::from_keys(&keys);

    println!("payerSk      {}", hex::encode(payer_sk));
    println!("merchantSk   {}", hex::encode(merchant_sk));
    println!("payerPub     {}", hex::encode(pp));
    println!("merchantPub  {}", hex::encode(mp));
    println!("shared       {}", hex::encode(shared));
    println!("transcript   {}", hex::encode(keys.transcript));
    println!("p2m          {}", hex::encode(keys.send_key));
    println!("m2p          {}", hex::encode(keys.recv_key));
    println!("sas          {}", keys.sas);
    println!(
        "authPayer    {}",
        hex::encode(auth_message("payer", &keys.transcript))
    );
    println!(
        "record0      {}",
        hex::encode(channel.seal(b"BCSPEND|v1|t|c|10"))
    );
    println!(
        "record1      {}",
        hex::encode(channel.seal(b"BCSPEND|v1|t|c|10"))
    );
}
