//! What a proof is for.

use crate::id::Epoch;
use crate::journal::{right_message, right_scope};

use super::field::FieldElement;

/// What a proof claims, which fixes its scope and message.
///
/// A Semaphore nullifier is derived from the identity and the scope, so the
/// scope decides what one subscriber can do once: hold one right per slot a
/// day. Verifiers rebuild the scope from their own state rather than accept
/// it, so a proof made for one claim is useless for any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Claim {
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

impl Claim {
    /// The scope, as the circuit takes it: Semaphore's hash of the 256-bit value.
    pub(crate) fn scope(self) -> FieldElement {
        match self {
            Self::Right { window, .. } => FieldElement::semaphore_hash(&right_scope(window)),
        }
    }

    /// The message, as the circuit takes it.
    pub(crate) fn message(self) -> FieldElement {
        match self {
            Self::Right { window, key } => {
                FieldElement::semaphore_hash(&right_message(window, &key))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
