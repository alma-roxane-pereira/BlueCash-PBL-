//! Full-domain hash used by the RSA blind-signature scheme.
//!
//! `API_CONTRACT.md` fixes the construction exactly:
//!
//! > **FDH(message, n)**: `k = ceil(bitlen(n)/8) + 16` bytes; output = concatenation of
//! > `SHA256("BCFDH|v1|" ‖ message ‖ ctr)` for `ctr = 0,1,2…` (ctr as 2-byte big-endian),
//! > truncated to `k` bytes, read as a big-endian integer, `mod n`.
//!
//! The 16 extra bytes beyond the modulus width make the modulo bias negligible,
//! which is why `k` is computed from the modulus rather than fixed.
//!
//! Reference implementations this must match byte for byte:
//! * `RsaBlind.fdh` in `core/RsaBlind.kt`
//! * `fdh` in `reference-server/server.py`

use num_bigint::BigUint;

use crate::sha256;

/// Domain-separation label. Part of the signed pre-image; changing it breaks
/// every signature the Android client and reference server have ever produced.
const LABEL: &[u8] = b"BCFDH|v1|";

/// Bytes of slack added past the modulus width to make the modulo bias negligible.
const SLACK_BYTES: usize = 16;

/// Hashes `message` to an integer in `[0, n)`.
///
/// # Panics
///
/// Panics if `n` is zero, which has no valid reduction. Callers pass an RSA
/// modulus, so this indicates a programming error rather than bad input.
///
/// # Examples
///
/// ```
/// use num_bigint::BigUint;
/// let n = BigUint::from(257u32);
/// assert!(bluecash_crypto::fdh(b"abc", &n) < n);
/// ```
pub fn fdh(message: &[u8], n: &BigUint) -> BigUint {
    assert!(n > &BigUint::ZERO, "FDH modulus must be non-zero");

    let k = output_len(n);
    let mut out = Vec::with_capacity(k + 32);
    let mut ctr: u16 = 0;

    while out.len() < k {
        // `ctr` as 2 bytes big-endian, matching `ctr.to_bytes(2, "big")` in Python
        // and `byteArrayOf((ctr ushr 8).toByte(), ctr.toByte())` in Kotlin.
        out.extend_from_slice(&sha256(&[LABEL, message, &ctr.to_be_bytes()]));
        // Both references let the counter grow without bound, but k is at most a few
        // hundred bytes, so wrapping is unreachable. Fail loudly rather than repeat a block.
        ctr = ctr.checked_add(1).expect("FDH counter overflowed 16 bits");
    }

    out.truncate(k);
    BigUint::from_bytes_be(&out) % n
}

/// `k = ceil(bitlen(n)/8) + 16`, the number of hash bytes consumed before reduction.
///
/// Matches `(n.bit_length() + 7) // 8 + 16` in Python and
/// `(n.bitLength() + 7) / 8 + 16` in Kotlin.
fn output_len(n: &BigUint) -> usize {
    (n.bits() as usize).div_ceil(8) + SLACK_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n_2048() -> BigUint {
        // The d100 demo modulus; 2048 bits exactly.
        BigUint::parse_bytes(
            b"bb594eb490e85059ca019d4c5afa0f77f05bd341519a7de829b728e3b8cdc53e\
              ba61babbfe9424c7e8bb876f36a4349bb792749b94001013ae24d938534d0ff93\
              cc3695b0f2409bc018b5d2d3279746a918d35363402e86fbc343957607d36645f\
              d230944896227cabed8cdbbe91d7916f6e71a15ccfba9cdd2d5337b8de2597e9d\
              08bb7f9116ca556d27ef5f2ed7272890f8ed60b2e815a40986f9b05b7435e44e0\
              4acc3d2805878ba841b5cd3f0d4fac6133ee2d2070bd18eb26f776dad7cacbf3a\
              8fd77184a52f91118ce0f2f26f25e385bd253139bb494c96ac2e53cdddfcf74de\
              29193a81f8f164080a870c2f6d41644b65a8418e182c1f9bdf36f86c53"
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<u8>>()
                .as_slice(),
            16,
        )
        .unwrap()
    }

    #[test]
    fn output_length_follows_the_contract_formula() {
        assert_eq!(n_2048().bits(), 2048);
        // 2048 bits -> 256 bytes + 16 slack.
        assert_eq!(output_len(&n_2048()), 272);
        // Exact byte boundaries.
        assert_eq!(output_len(&BigUint::from(255u32)), 1 + 16); // 8 bits
        assert_eq!(output_len(&BigUint::from(256u32)), 2 + 16); // 9 bits
        assert_eq!(output_len(&BigUint::from(65535u32)), 2 + 16); // 16 bits
        assert_eq!(output_len(&BigUint::from(65536u32)), 3 + 16); // 17 bits
    }

    #[test]
    fn result_is_always_reduced_below_the_modulus() {
        for n in [3u32, 257, 0x1FFFF, u32::MAX] {
            let n = BigUint::from(n);
            for msg in [&b""[..], b"abc", &[0xffu8; 100][..]] {
                assert!(fdh(msg, &n) < n, "not reduced for n={n}");
            }
        }
    }

    #[test]
    fn counter_is_two_bytes_big_endian() {
        // k = 272 needs ceil(272/32) = 9 blocks, so counters 0..=8 are consumed.
        // Rebuild the expected stream explicitly and compare.
        let n = n_2048();
        let msg = b"counter-encoding";
        let mut expect = Vec::new();
        for ctr in 0u16..9 {
            expect.extend_from_slice(&sha256(&[LABEL, msg, &ctr.to_be_bytes()]));
        }
        expect.truncate(272);
        assert_eq!(fdh(msg, &n), BigUint::from_bytes_be(&expect) % &n);

        // A one-byte counter would make blocks 0 and 256 collide; confirm the
        // high byte is actually present by checking block 1's pre-image.
        assert_eq!(1u16.to_be_bytes(), [0x00, 0x01]);
        assert_eq!(258u16.to_be_bytes(), [0x01, 0x02]);
    }

    #[test]
    fn distinct_messages_give_distinct_digests() {
        let n = n_2048();
        assert_ne!(fdh(b"a", &n), fdh(b"b", &n));
        assert_ne!(fdh(b"", &n), fdh(b"\x00", &n));
    }

    #[test]
    fn is_deterministic() {
        let n = n_2048();
        assert_eq!(fdh(b"repeat me", &n), fdh(b"repeat me", &n));
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn zero_modulus_panics() {
        fdh(b"abc", &BigUint::ZERO);
    }
}
