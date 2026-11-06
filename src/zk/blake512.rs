//! BLAKE-512, the SHA-3 finalist (not BLAKE2), which Semaphore v4 derives
//! an identity's scalar with.
//!
//! Written out rather than taken from `blake-hash`: that crate always runs
//! through `ppv-lite86`, whose portable fallback — the one ARM gets — leaves
//! an operation BLAKE-512 needs unimplemented and panics. This is the
//! specification's straightforward form; the tests hold it to the
//! specification's vectors.

/// SHA-512's initial value, which BLAKE-512 shares.
const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// The first digits of pi.
const C: [u64; 16] = [
    0x243f_6a88_85a3_08d3,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
    0x4528_21e6_38d0_1377,
    0xbe54_66cf_34e9_0c6c,
    0xc0ac_29b7_c97c_50dd,
    0x3f84_d5b5_b547_0917,
    0x9216_d5d9_8979_fb1b,
    0xd131_0ba6_98df_b5ac,
    0x2ffd_72db_d01a_dfb7,
    0xb8e1_afed_6a26_7e96,
    0xba7c_9045_f12c_7f99,
    0x24a1_9947_b391_6cf7,
    0x0801_f2e2_858e_fc16,
    0x6369_20d8_7157_4e69,
];

/// The message word order of each round.
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const ROUNDS: usize = 16;
const BLOCK: usize = 128;

/// BLAKE-512 of `message`, with no salt.
pub(crate) fn blake512(message: &[u8]) -> [u8; 64] {
    let mut h = IV;
    let bits = u128::try_from(message.len()).unwrap_or(u128::MAX) * 8;

    let mut blocks = message.chunks_exact(BLOCK);
    let mut compressed: u128 = 0;
    for block in &mut blocks {
        compressed += BLOCK as u128 * 8;
        compress(&mut h, block, compressed);
    }

    // Padding: a one bit after the message, a one bit just before the
    // length, the length in 128 bits. A block that holds no message bits is
    // compressed with a counter of zero.
    let rest = blocks.remainder();
    let mut tail = [0u8; 2 * BLOCK];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let counter = if rest.is_empty() { 0 } else { bits };
    if rest.len() < BLOCK - 16 {
        tail[BLOCK - 17] |= 0x01;
        tail[BLOCK - 16..BLOCK].copy_from_slice(&bits.to_be_bytes());
        compress(&mut h, &tail[..BLOCK], counter);
    } else {
        tail[2 * BLOCK - 17] |= 0x01;
        tail[2 * BLOCK - 16..].copy_from_slice(&bits.to_be_bytes());
        compress(&mut h, &tail[..BLOCK], counter);
        compress(&mut h, &tail[BLOCK..], 0);
    }

    let mut out = [0u8; 64];
    for (bytes, word) in out.chunks_exact_mut(8).zip(h) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[allow(clippy::cast_possible_truncation, reason = "the counter's halves")]
fn compress(h: &mut [u64; 8], block: &[u8], counter: u128) {
    let mut m = [0u64; 16];
    for (word, bytes) in m.iter_mut().zip(block.chunks_exact(8)) {
        let mut b = [0u8; 8];
        b.copy_from_slice(bytes);
        *word = u64::from_be_bytes(b);
    }
    let (t0, t1) = (counter as u64, (counter >> 64) as u64);

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..12].copy_from_slice(&C[..4]);
    v[12] = t0 ^ C[4];
    v[13] = t0 ^ C[5];
    v[14] = t1 ^ C[6];
    v[15] = t1 ^ C[7];

    for round in 0..ROUNDS {
        let s = &SIGMA[round % 10];
        g(&mut v, &m, s, 0, [0, 4, 8, 12]);
        g(&mut v, &m, s, 1, [1, 5, 9, 13]);
        g(&mut v, &m, s, 2, [2, 6, 10, 14]);
        g(&mut v, &m, s, 3, [3, 7, 11, 15]);
        g(&mut v, &m, s, 4, [0, 5, 10, 15]);
        g(&mut v, &m, s, 5, [1, 6, 11, 12]);
        g(&mut v, &m, s, 6, [2, 7, 8, 13]);
        g(&mut v, &m, s, 7, [3, 4, 9, 14]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[allow(clippy::many_single_char_names, reason = "the specification's names")]
fn g(v: &mut [u64; 16], m: &[u64; 16], s: &[usize; 16], i: usize, [a, b, c, d]: [usize; 4]) {
    let (x, y) = (s[2 * i], s[2 * i + 1]);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[x] ^ C[y]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(25);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[y] ^ C[x]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(11);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        crate::hex::lower(bytes)
    }

    /// The specification's two examples: one zero byte, and 144 zero bytes,
    /// which spills the padding into a block of its own.
    #[test]
    fn matches_the_specification() {
        assert_eq!(
            hex(&blake512(&[0])),
            "97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4\
             ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3"
        );
        assert_eq!(
            hex(&blake512(&[0; 144])),
            "313717d608e9cf758dcb1eb0f0c3cf9fc150b2d500fb33f51c52afc99d358a2f\
             1374b8a38bba7974e7f6ef79cab16f22ce1e649d6e01ad9589c213045d545dde"
        );
    }

    /// Every padding case — empty, short, the last length that fits one
    /// block, the first that does not, a whole block, more — against the
    /// implementation identities were derived with until now.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn matches_blake_hash() {
        use blake_hash::Digest as _;
        for len in [
            0usize, 1, 55, 110, 111, 112, 127, 128, 129, 239, 240, 256, 1000,
        ] {
            let message: Vec<u8> = (0..len)
                .map(|i| u8::try_from((i * 31 + 7) % 256).unwrap_or(0))
                .collect();
            let expected = blake_hash::Blake512::digest(&message);
            assert_eq!(blake512(&message)[..], expected[..], "length {len}");
        }
    }
}
