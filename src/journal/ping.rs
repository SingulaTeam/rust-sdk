//! A session's checkpoint.

use sha2::{Digest as _, Sha256};

use super::right::Nullifier;
use super::{Encoder, JournalParams, Kind};
use crate::id::{Epoch, SessionId, StarId};

/// A session's checkpoint: session `session` of the day's right, on node
/// `node`, has carried `total` seconds so far.
///
/// The total counts from zero in every session and, past midnight, from
/// zero again under the new day's right. The client signs no time: each
/// Control Plane that stores the ping attests when it first did.
///
/// ```text
/// signed = SHA-256("singula-ping-v1" ‖ chainId ‖ domain ‖ window ‖ nullifier ‖ session ‖ node ‖ total)
/// ```
///
/// with `window`, `node` and `total` 8 bytes big-endian and `session` the
/// UUID's 16 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ping {
    /// The day of the right the ping is made under.
    pub window: Epoch,
    /// The right's nullifier: which slot's day this is, and nothing more.
    pub nullifier: Nullifier,
    /// The session, as its node named it.
    pub session: SessionId,
    /// The node carrying the session.
    pub node: StarId,
    /// Seconds the session has carried under this right.
    pub total: u64,
}

impl Ping {
    /// A ping of session `session` on `node`, `total` seconds in, under the
    /// right `window`/`nullifier`.
    #[must_use]
    pub fn new(
        window: Epoch,
        nullifier: Nullifier,
        session: SessionId,
        node: StarId,
        total: u64,
    ) -> Self {
        Self {
            window,
            nullifier,
            session,
            node,
            total,
        }
    }

    /// What the right's key signs, and what names the ping in the journal:
    /// not the signature, which ECDSA randomises, nor the attestations,
    /// which grow.
    #[must_use]
    pub fn hash(&self, params: JournalParams) -> [u8; 32] {
        let mut e = Encoder::tagged("singula-ping-v1");
        e.params(params)
            .u64(self.window.0)
            .bytes(&self.nullifier.0)
            .bytes(&self.session.to_bytes())
            .u64(self.node.0)
            .u64(self.total);
        Sha256::digest(e.into_bytes()).into()
    }
}

/// A [`Ping`] with the right key's signature, ready for a Control Plane.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignedPing {
    /// The ping.
    pub ping: Ping,
    /// The signature's `r`, 32 bytes big-endian.
    pub r: [u8; 32],
    /// The signature's `s`, 32 bytes big-endian.
    pub s: [u8; 32],
}

impl SignedPing {
    /// The canonical encoding a Control Plane takes: the ping and its
    /// signature, and no attestations — those are the Control Planes' to add.
    ///
    /// ```text
    /// 0x02 ‖ window ‖ nullifier ‖ session ‖ node ‖ total ‖ r ‖ s ‖ attestations (u32 0)
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let p = &self.ping;
        let mut e = Encoder::default();
        e.u8(Kind::Ping as u8)
            .u64(p.window.0)
            .bytes(&p.nullifier.0)
            .bytes(&p.session.to_bytes())
            .u64(p.node.0)
            .u64(p.total)
            .bytes(&self.r)
            .bytes(&self.s)
            .u32(0);
        e.into_bytes()
    }
}
