//! The shared journal: what a session on a daily right signs, and how a
//! client checks that the Control Planes recorded it.
//!
//! A subscriber's slot buys one session at a time, every day. Each day the
//! client proves, anonymously, that its slot is paid — a [`Right`] — and
//! delegates the day to a P-256 [`RightKey`] bound into that proof. While a
//! session runs, the client signs a [`Ping`] every few minutes: the session's
//! seconds so far. The Control Planes keep every right and ping in one
//! journal, and once a day pay each node for the seconds its sessions carried.
//!
//! The client signs no time. Each Control Plane that stores a ping attests
//! when it first did, and the ping's time is the median of a strict majority
//! of them ([`Attestation`], [`Versions`]). The answer to a ping carries those
//! attestations; checking them is how a client knows its ping reached the
//! journal rather than one Control Plane's word for it — and when to move to
//! another.
//!
//! Who counts towards a majority is read from the chain, never taken from a
//! Control Plane: [`RegistryVersion`] is the Control Plane set as of the block
//! that last changed it, and each attestation names the version it was made
//! under.
//!
//! # Wire formats
//!
//! Everything here is encoded and hashed exactly as the Control Planes do
//! (`internal/ledger` in singula-star): fixed-width big-endian integers and
//! 32-byte field elements, each signed message behind a tag that names it
//! and its version. The tests check every format against a fixture of real
//! proofs and signatures made by an independent implementation.

mod attestation;
mod key;
mod ping;
mod registry;
mod right;
mod status;

pub use attestation::Attestation;
pub use key::{RightKey, RightKeyError, open_digest};
pub use ping::{Ping, SignedPing};
pub use registry::{
    AckError, Committed, RegistryVersion, RegistryVersionId, VERSION_GRACE, Versions, VersionsError,
};
pub use right::{Nullifier, Right, right_message, right_scope};
pub use status::{CloseReason, SessionStatus};

use sha3::{Digest as _, Keccak256};

/// What every signature in the journal is bound to: the chain and the
/// journal's domain. A ping or attestation made for one network, or one
/// settlement contract, means nothing on another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct JournalParams {
    /// The chain the protocol runs on.
    pub chain_id: u64,
    /// The journal's domain; [`DEFAULT_DOMAIN`] on every network today.
    pub domain: [u8; 32],
}

/// `keccak256("singula-ledger-v1")`: the domain the Control Planes use.
pub const DEFAULT_DOMAIN: [u8; 32] = [
    0xfb, 0xe5, 0x0a, 0x1f, 0x4d, 0xd3, 0x54, 0xe3, 0xbe, 0xc3, 0x1d, 0x04, 0xef, 0x7f, 0xac, 0x47,
    0x3a, 0x5c, 0x9f, 0x93, 0x8d, 0x82, 0xb4, 0xfc, 0x31, 0x9b, 0x54, 0x64, 0xac, 0xbd, 0xd6, 0xa1,
];

impl JournalParams {
    /// The journal on chain `chain_id`, under [`DEFAULT_DOMAIN`].
    #[must_use]
    pub const fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            domain: DEFAULT_DOMAIN,
        }
    }

    /// The same journal under another domain: for test networks and
    /// fixtures.
    #[must_use]
    pub const fn with_domain(mut self, domain: [u8; 32]) -> Self {
        self.domain = domain;
        self
    }
}

/// The canonical encoding, built up field by field.
#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn tagged(tag: &str) -> Self {
        Self(tag.as_bytes().to_vec())
    }

    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn i64(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }

    fn params(&mut self, p: JournalParams) -> &mut Self {
        self.u64(p.chain_id).bytes(&p.domain)
    }

    fn keccak(&self) -> [u8; 32] {
        Keccak256::digest(&self.0).into()
    }

    fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// How an event is tagged in its canonical encoding.
#[derive(Clone, Copy)]
#[repr(u8)]
enum Kind {
    Right = 1,
    Ping = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_domain_is_the_control_planes() {
        assert_eq!(
            DEFAULT_DOMAIN,
            <[u8; 32]>::from(Keccak256::digest(b"singula-ledger-v1"))
        );
    }
}
