//! Differential tests for the Task B primitives.
//!
//! The expected values in `vectors_b.json` were **not** produced by this crate.
//! `tests/gen_vectors_b.py` derives them from the compatibility references:
//!
//! * group parameters, `challenge_x`, `is_element`, `fdh` — executed out of
//!   `reference-server/server.py`
//! * RSA moduli and private exponents — parsed from the Android client's
//!   `DemoMintKeys.kt`, so the blind-signature vectors use the very keys the
//!   client's `SimulatedMint` signs with
//! * Ed25519 signatures — produced by `cryptography`, the library `server.py` uses
//!
//! Regenerate after any change to either reference:
//!
//! ```text
//! cd crates/bluecash-crypto
//! ../../.venv/Scripts/python.exe tests/gen_vectors_b.py > tests/vectors_b.json
//! ```

mod common;

use common::{big, bool_field, string_field, unhex, unhex32};

use bluecash_crypto::{blind, ed25519, shares::Group};
use num_bigint::BigUint;

const VECTORS: &str = include_str!("vectors_b.json");

#[test]
fn vector_file_records_its_provenance() {
    assert!(VECTORS.contains("reference-server/server.py"));
    assert!(VECTORS.contains("DemoMintKeys.kt"));
}

#[test]
fn group_parameters_match_the_reference_server() {
    // server.py derives P at runtime from Machin's formula; this crate embeds the
    // RFC 3526 literal. They must be the same number.
    let gr = Group::new();
    let group = &VECTORS[VECTORS.find("\"group\"").expect("group")..];
    assert_eq!(gr.p, big(&string_field(group, "p_hex")), "prime P");
    assert_eq!(gr.q, big(&string_field(group, "q_hex")), "order Q");
}

#[test]
fn rsa_blind_signatures_match_the_reference() {
    let cases = common::objects(&common::array_body(VECTORS, "blind"));
    assert_eq!(cases.len(), 9);

    for case in &cases {
        let label = string_field(case, "label");
        let n = big(&string_field(case, "n_hex"));
        let e = big(&string_field(case, "e_hex"));
        let d = big(&string_field(case, "d_hex"));
        let msg = unhex(&string_field(case, "message_hex"));
        let r = big(&string_field(case, "r_hex"));

        let want_blinded = big(&string_field(case, "blinded_hex"));
        let want_blind_sig = big(&string_field(case, "blind_sig_hex"));
        let want_sig = big(&string_field(case, "sig_hex"));

        // 1. Blinding with the same r must produce the same blinded value.
        let b = blind::blind_with(&msg, &n, &e, r.clone())
            .unwrap_or_else(|err| panic!("blind_with failed for {label}: {err}"));
        assert_eq!(b.blinded_message, want_blinded, "blinded value for {label}");

        // 2. Mint-side signing must match pow(blinded, d, n).
        let bs = blind::sign_blinded(&b.blinded_message, &n, &d).expect("sign");
        assert_eq!(bs, want_blind_sig, "blind signature for {label}");

        // 3. Unblinding must match the reference's sig.
        let sig = blind::unblind(&bs, &r, &n).expect("unblind");
        assert_eq!(sig, want_sig, "unblinded signature for {label}");

        // 4. And the result must verify — the property the merchant checks.
        assert!(
            blind::verify(&msg, &sig, &n, &e),
            "signature from the reference did not verify for {label}"
        );
    }

    eprintln!("blind: {} reference cases matched", cases.len());
}

#[test]
fn this_crate_verifies_signatures_produced_by_the_reference() {
    // The asymmetric direction that matters in production: the mint (Python)
    // signs, the verifier (this crate, via the backend) checks.
    let cases = common::objects(&common::array_body(VECTORS, "blind"));
    for case in &cases {
        let n = big(&string_field(case, "n_hex"));
        let e = big(&string_field(case, "e_hex"));
        let msg = unhex(&string_field(case, "message_hex"));
        let sig = big(&string_field(case, "sig_hex"));
        assert!(blind::verify(&msg, &sig, &n, &e));
        // A one-bit change must be rejected.
        assert!(!blind::verify(&msg, &(&sig + BigUint::from(1u8)), &n, &e));
    }
}

#[test]
fn ed25519_matches_the_reference_library() {
    let cases = common::objects(&common::array_body(VECTORS, "ed25519"));
    assert_eq!(cases.len(), 18);

    for case in &cases {
        let seed = unhex32(&string_field(case, "seed_hex"));
        let want_pub = unhex32(&string_field(case, "public_hex"));
        let msg = unhex(&string_field(case, "message_hex"));
        let want_sig = unhex(&string_field(case, "signature_hex"));

        // Public key derivation must agree.
        assert_eq!(ed25519::public_key(&seed), want_pub, "public key");

        // Ed25519 is deterministic, so the signature bytes must match exactly.
        assert_eq!(
            ed25519::sign(&seed, &msg).to_vec(),
            want_sig,
            "signature bytes"
        );

        // And this crate must verify the reference's signature.
        assert!(
            ed25519::verify(&want_pub, &msg, &want_sig),
            "failed to verify a signature made by `cryptography`"
        );
    }

    eprintln!("ed25519: {} reference cases matched", cases.len());
}

#[test]
fn challenge_x_matches_the_reference_server() {
    let cases = common::objects(&common::array_body(VECTORS, "challenge_x"));
    assert_eq!(cases.len(), 6);
    let gr = Group::new();

    for case in &cases {
        let token_id = string_field(case, "token_id");
        let n_ctx = string_field(case, "n_ctx");
        let want = big(&string_field(case, "x_hex"));
        assert_eq!(
            gr.challenge_x(&token_id, &n_ctx),
            want,
            "challenge_x({token_id:?}, {n_ctx:?})"
        );
    }
}

#[test]
fn subgroup_membership_matches_the_reference_server() {
    // server.py tests v^Q == 1; FeldmanShare.kt uses the Jacobi symbol. Both
    // forms in this crate must agree with the Python answer.
    let cases = common::objects(&common::array_body(VECTORS, "is_element"));
    assert_eq!(cases.len(), 8);
    let gr = Group::new();

    for case in &cases {
        let v = big(&string_field(case, "v_hex"));
        let want = bool_field(case, "expected");
        assert_eq!(gr.is_element_by_euler(&v), want, "euler test for {v}");
        assert_eq!(gr.is_element(&v), want, "jacobi test for {v}");
    }
}

#[test]
fn share_evaluation_and_recovery_match_the_reference_server() {
    let cases = common::objects(&common::array_body(VECTORS, "shares"));
    assert_eq!(cases.len(), 4);
    let gr = Group::new();

    for case in &cases {
        let a0 = big(&string_field(case, "a0_hex"));
        let a1 = big(&string_field(case, "a1_hex"));
        let c0 = big(&string_field(case, "c0_hex"));
        let c1 = big(&string_field(case, "c1_hex"));
        let x1 = big(&string_field(case, "x1_hex"));
        let y1 = big(&string_field(case, "y1_hex"));
        let x2 = big(&string_field(case, "x2_hex"));
        let y2 = big(&string_field(case, "y2_hex"));
        let want_a0 = big(&string_field(case, "recovered_a0_hex"));

        // Commitments.
        assert_eq!(gr.commit(&a0), c0, "c0 = g^a0");
        assert_eq!(gr.commit(&a1), c1, "c1 = g^a1");

        // Share evaluation.
        assert_eq!(gr.eval_share(&a0, &a1, &x1), y1, "y1");
        assert_eq!(gr.eval_share(&a0, &a1, &x2), y2, "y2");

        // Offline verification of each point against the commitments.
        assert!(gr.verify_share(&c0, &c1, &x1, &y1), "share 1 must verify");
        assert!(gr.verify_share(&c0, &c1, &x2, &y2), "share 2 must verify");

        // Double-spend recovery, matching /settlement/uploadBatch.
        let recovered = gr
            .recover_secret(&x1, &y1, &x2, &y2)
            .expect("two distinct points must be recoverable");
        assert_eq!(recovered, want_a0, "recovered a0");
        // The server maps the recovered secret back to a credential via g^a0.
        assert_eq!(gr.commit(&recovered), c0, "g^recovered must equal c0");
    }

    eprintln!("shares: {} reference cases matched", cases.len());
}

#[test]
fn recovery_order_does_not_matter() {
    // The settlement server may see the two receipts in either order.
    let cases = common::objects(&common::array_body(VECTORS, "shares"));
    let gr = Group::new();
    for case in &cases {
        let x1 = big(&string_field(case, "x1_hex"));
        let y1 = big(&string_field(case, "y1_hex"));
        let x2 = big(&string_field(case, "x2_hex"));
        let y2 = big(&string_field(case, "y2_hex"));
        assert_eq!(
            gr.recover_secret(&x1, &y1, &x2, &y2),
            gr.recover_secret(&x2, &y2, &x1, &y1)
        );
    }
}
