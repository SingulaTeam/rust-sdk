//! A slot's day, proved anonymously.

use std::fmt;

use sha3::{Digest as _, Keccak256};

use super::{Encoder, Kind};
use crate::id::Epoch;

/// A right's nullifier: the same for one slot all day, and different every
/// day, so it names the slot's day and nothing that links two days.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier(pub [u8; 32]);

impl fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nullifier(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        write!(f, ")")
    }
}

/// The scope tag of a right: `3`, apart from session (`cp << 96 | …`) and
/// permission (`2 << 128 | …`) scopes, so no other proof passes for one.
const RIGHT_DOMAIN: u8 = 3;

/// The scope a right for `window` is proved under, as 32 bytes big-endian:
/// `3 << 128 | window << 64`. One identity — one slot — has exactly one
/// nullifier per window.
#[must_use]
pub fn right_scope(window: Epoch) -> [u8; 32] {
    let mut be = [0; 32];
    be[15] = RIGHT_DOMAIN;
    be[16..24].copy_from_slice(&window.0.to_be_bytes());
    be
}

/// The message a right is proved with, binding its key into the proof:
/// `keccak256("singula-right-v1" ‖ scope ‖ x ‖ y) >> 8`, as 32 bytes
/// big-endian.
///
/// # Security
///
/// The message is a public input of the proof, so nobody can take a
/// client's proof and attach a key of their own.
#[must_use]
pub fn right_message(window: Epoch, key: &([u8; 32], [u8; 32])) -> [u8; 32] {
    let hash: [u8; 32] = Keccak256::new()
        .chain_update(b"singula-right-v1")
        .chain_update(right_scope(window))
        .chain_update(key.0)
        .chain_update(key.1)
        .finalize()
        .into();
    // Shifted right by one byte, so the value fits the proof's field.
    let mut out = [0; 32];
    out[1..].copy_from_slice(&hash[..31]);
    out
}

/// A slot's day: a membership proof, against one of the window's subscriber
/// tree states, whose message binds a [`RightKey`](super::RightKey).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Right {
    /// The day.
    pub window: Epoch,
    /// Which of the window's tree states the proof is against: 0 for the
    /// tree at the day's start, `k` for the tree right after the day's
    /// `k`-th new subscriber.
    pub state_index: u32,
    /// The proof's nullifier.
    pub nullifier: Nullifier,
    /// The right key, `x` and `y`.
    pub key: ([u8; 32], [u8; 32]),
    /// The Groth16 proof as Semaphore packs it, in Ethereum calldata order.
    pub points: [[u8; 32]; 8],
}

impl Right {
    /// A right from its parts: a proof made for its window and key, against
    /// tree state `state_index`.
    #[must_use]
    pub const fn new(
        window: Epoch,
        state_index: u32,
        nullifier: Nullifier,
        key: ([u8; 32], [u8; 32]),
        points: [[u8; 32]; 8],
    ) -> Self {
        Self {
            window,
            state_index,
            nullifier,
            key,
            points,
        }
    }

    /// The canonical encoding a Control Plane takes.
    ///
    /// ```text
    /// 0x01 ‖ window ‖ state index (u32) ‖ nullifier ‖ x ‖ y ‖ points (8 × 32)
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::default();
        e.u8(Kind::Right as u8)
            .u64(self.window.0)
            .u32(self.state_index)
            .bytes(&self.nullifier.0)
            .bytes(&self.key.0)
            .bytes(&self.key.1);
        for p in &self.points {
            e.bytes(p);
        }
        e.into_bytes()
    }
}
