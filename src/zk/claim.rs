//! What a proof is for.

use crate::id::{Epoch, StarId};
use crate::journal::{right_message, right_scope};

use super::field::FieldElement;

/// What a proof claims, which fixes its scope and message.
///
/// A Semaphore nullifier is derived from the identity and the scope, so the
/// scope decides what one subscriber can do once: open one session per quota
/// slot at one Control Plane, or take each permission of a window anywhere. Verifiers rebuild the scope from their own state rather than
/// accepting it, so a proof made for one claim is useless for any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Claim {
    /// Admission of one session at one Control Plane.
    ///
    /// ```text
    /// scope   = control_plane << 96 | epoch << 32 | index
    /// message = index
    /// ```
    Session {
        /// The Control Plane admitting the session.
        control_plane: StarId,
        /// The epoch the session is admitted in.
        epoch: Epoch,
        /// The quota slot this session takes, below the epoch's quota.
        index: u32,
    },
    /// One of a window's permissions, from any Control Plane.
    ///
    /// ```text
    /// scope   = 2 << 128 | window << 64 | index
    /// message = scope
    /// ```
    ///
    /// Each index is taken once per window network-wide, below the issuer's
    /// published count, so a subscription's devices can each take their own
    /// and together never more than the count. The leading `2` keeps these
    /// scopes apart from every session scope, and from the whole packets
    /// once taken under `1`; the message repeats the scope so the two cannot
    /// be swapped.
    Permission {
        /// The window the permission is for.
        window: Epoch,
        /// Which of the window's permissions.
        index: u32,
    },
    /// A slot's day in the shared journal, delegated to a right key.
    ///
    /// ```text
    /// scope   = 3 << 128 | window << 64
    /// message = keccak256("singula-right-v1" ‖ scope ‖ x ‖ y) >> 8
    /// ```
    ///
    /// One slot has one nullifier a day, whatever the key; the message binds
    /// the key, so nobody can attach another to the proof. See
    /// [`journal::right_scope`](crate::journal::right_scope) and
    /// [`journal::right_message`](crate::journal::right_message).
    Right {
        /// The day.
        window: Epoch,
        /// The right key, `x` and `y`: [`RightKey::public_key`].
        ///
        /// [`RightKey::public_key`]: crate::journal::RightKey::public_key
        key: ([u8; 32], [u8; 32]),
    },
}

/// The tag that separates permission scopes from session scopes.
const PERMISSION_DOMAIN: u8 = 2;

impl Claim {
    /// The scope, as the circuit takes it: Semaphore's hash of the 256-bit value.
    pub(crate) fn scope(self) -> FieldElement {
        FieldElement::semaphore_hash(&self.raw_scope())
    }

    /// The message, as the circuit takes it.
    pub(crate) fn message(self) -> FieldElement {
        let raw = match self {
            Self::Session { index, .. } => {
                let mut be = [0; 32];
                be[28..].copy_from_slice(&index.to_be_bytes());
                be
            }
            Self::Permission { .. } => self.raw_scope(),
            Self::Right { window, key } => right_message(window, &key),
        };
        FieldElement::semaphore_hash(&raw)
    }

    /// The scope as 32 bytes big-endian, before hashing.
    fn raw_scope(self) -> [u8; 32] {
        let mut be = [0; 32];
        match self {
            Self::Session {
                control_plane,
                epoch,
                index,
            } => {
                be[12..20].copy_from_slice(&control_plane.0.to_be_bytes());
                be[20..28].copy_from_slice(&epoch.0.to_be_bytes());
                be[28..].copy_from_slice(&index.to_be_bytes());
            }
            Self::Permission { window, index } => {
                be[15] = PERMISSION_DOMAIN;
                be[16..24].copy_from_slice(&window.0.to_be_bytes());
                be[24..].copy_from_slice(&u64::from(index).to_be_bytes());
            }
            Self::Right { window, .. } => be = right_scope(window),
        }
        be
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Control Plane's `SemaphoreHash` of its own scopes and messages.
    #[test]
    fn hashes_as_the_control_plane_does() {
        let session = Claim::Session {
            control_plane: StarId(7),
            epoch: Epoch(137),
            index: 3,
        };
        assert_eq!(
            session.scope().to_string(),
            "144238274787227100379747289347751931288527938002097690447946830657197365998"
        );
        assert_eq!(
            session.message().to_string(),
            "343371210433890290056162609015838183378480827683322587048381917224414179832"
        );

        let widest = Claim::Session {
            control_plane: StarId(u64::MAX),
            epoch: Epoch(u64::MAX),
            index: u32::MAX,
        };
        assert_eq!(
            widest.scope().to_string(),
            "376146707902516935771577135936012342332698627669720736628832201399239468285"
        );

        let permission = Claim::Permission {
            window: Epoch(137),
            index: 3,
        };
        let want = "215721150169798234869930996536229829395638981024187311208781748876391599088";
        assert_eq!(permission.scope().to_string(), want);
        assert_eq!(permission.message().to_string(), want);
    }

    // The Control Plane's `SemaphoreHash(RightScope)` and
    // `SemaphoreHash(RightMessage)` for right `a` of the journal's fixture.
    #[test]
    fn a_right_hashes_as_the_control_plane_does() {
        let hex32 = |s: &str| {
            let mut out = [0; 32];
            out.copy_from_slice(&hex::decode(s).unwrap_or_default());
            out
        };
        let right = Claim::Right {
            window: Epoch(10),
            key: (
                hex32("e417ce2cc31ef29ce38c7a1e75631e8d8c8209a4f508b8e81c74d41c14ccc431"),
                hex32("0d2c42f380d728d51d87e4b26261bc4b3d4a6f5459c0b8b6d1077e19ef75c73a"),
            ),
        };
        assert_eq!(
            right.scope().to_string(),
            "447793967648333678719443863230786612109752310857686584872885604805821712085"
        );
        assert_eq!(
            right.message().to_string(),
            "52204751582231114037403491615054938693844254530108889856078236979011909626"
        );
    }

    #[test]
    fn the_first_slot_hashes_zero() {
        let first = Claim::Session {
            control_plane: StarId(7),
            epoch: Epoch(137),
            index: 0,
        };
        assert_eq!(
            first.message().to_string(),
            "72536837793382353857766664600029564596379343648020771091641483823512744933"
        );
    }
}
