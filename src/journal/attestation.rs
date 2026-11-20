//! A Control Plane's word that it stored a ping.

use super::registry::RegistryVersionId;
use super::{Encoder, JournalParams};
use crate::eth;
use crate::id::{Address, StarId, UnixTime};

/// Control Plane `cp`'s signed statement that it first stored a ping at
/// `received_at`, as a Control Plane of registry version `version`.
///
/// ```text
/// signed = keccak256("singula-attest-v2" ‖ chainId ‖ domain ‖ ping hash ‖ version ‖ received_at)
/// ```
///
/// signed by the Control Plane's signer key, `r ‖ s ‖ v`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attestation {
    /// The Control Plane.
    pub cp: StarId,
    /// When it first stored the ping. It gives the same time for every
    /// repeat, so a ping cannot be moved in time by sending it again.
    pub received_at: UnixTime,
    /// The registry version it attested as a member of.
    pub version: RegistryVersionId,
    /// `r ‖ s ‖ v`, with `v` 27 or 28.
    pub signature: [u8; 65],
}

impl Attestation {
    /// An attestation as a Control Plane sent it.
    #[must_use]
    pub const fn new(
        cp: StarId,
        received_at: UnixTime,
        version: RegistryVersionId,
        signature: [u8; 65],
    ) -> Self {
        Self {
            cp,
            received_at,
            version,
            signature,
        }
    }

    /// The digest the Control Plane signed for the ping hashed `ping_hash`.
    #[must_use]
    pub fn digest(&self, params: JournalParams, ping_hash: &[u8; 32]) -> [u8; 32] {
        let mut e = Encoder::tagged("singula-attest-v2");
        e.params(params)
            .bytes(ping_hash)
            .bytes(&self.version.0)
            .i64(self.received_at.0);
        e.keccak()
    }

    /// The address that signed it, for the ping hashed `ping_hash`; `None`
    /// if the signature is malformed.
    #[must_use]
    pub fn signer(&self, params: JournalParams, ping_hash: &[u8; 32]) -> Option<Address> {
        eth::recover(&self.digest(params, ping_hash), &self.signature).ok()
    }
}
