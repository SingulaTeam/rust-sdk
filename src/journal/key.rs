//! The key a slot delegates one day to.

use std::fmt;

use hkdf::Hkdf;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::ping::{Ping, SignedPing};
use super::{Encoder, JournalParams};
use crate::id::{Epoch, StarId};

/// The salt of the derivation, naming it and its version.
const SALT: &[u8] = b"singula-right-key-v1";

/// How many candidates the derivation tries before giving up. Each fails
/// with probability about 2⁻³², so the limit is never reached in practice;
/// it only keeps the loop finite.
const MAX_CANDIDATES: u8 = 16;

/// The P-256 key a slot's day is delegated to: bound into the day's
/// [`Right`](super::Right), it signs the session opens and pings of that day.
///
/// It is derived, not generated: every device of a subscription derives the
/// same key for the same slot and day. Two keys for one slot on one day void
/// the day's right — only the slot's owner could make a second one, and the
/// journal cannot tell which came first — so devices must never disagree.
///
/// ```text
/// prk       = HKDF-Extract(salt = "singula-right-key-v1", ikm = slot secret, 32 bytes)
/// candidate = HKDF-Expand(prk, info = chainId ‖ domain ‖ window ‖ counter, 32 bytes)
///             counter = 0, 1, …: the first candidate in [1, n − 1] is the key
/// ```
///
/// with `chainId` and `window` 8 bytes big-endian and `counter` one byte —
/// FIPS 186-5's derivation by testing candidates (A.2.2).
///
/// # Security
///
/// The key lives in memory, as the slot secret it comes from does; it is
/// wiped when dropped. A hardware keystore cannot hold it, because it would
/// generate a different key on every device.
///
/// # Examples
///
/// ```
/// # use singula::Epoch;
/// # use singula::journal::{JournalParams, RightKey};
/// let params = JournalParams::new(421_614);
/// let today = RightKey::derive(&[7; 32], params, Epoch(170))?;
/// let again = RightKey::derive(&[7; 32], params, Epoch(170))?;
/// assert_eq!(today.public_key(), again.public_key());
/// # Ok::<(), singula::journal::RightKeyError>(())
/// ```
pub struct RightKey {
    key: SigningKey,
    window: Epoch,
}

/// Why a right key could not be derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RightKeyError {
    /// No candidate was a valid scalar: in practice, never.
    #[error("no valid P-256 scalar among the derived candidates")]
    NoScalar,
}

impl RightKey {
    /// The key of the slot whose secret is `slot_secret`, for `window`.
    ///
    /// # Errors
    ///
    /// Returns [`RightKeyError::NoScalar`] if no candidate is a valid
    /// scalar, which happens with probability about 2⁻⁵¹².
    pub fn derive(
        slot_secret: &[u8; 32],
        params: JournalParams,
        window: Epoch,
    ) -> Result<Self, RightKeyError> {
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), slot_secret);
        for counter in 0..MAX_CANDIDATES {
            let mut info = Encoder::default();
            info.params(params).u64(window.0).u8(counter);
            let mut candidate = Zeroizing::new([0u8; 32]);
            hkdf.expand(&info.into_bytes(), candidate.as_mut())
                .map_err(|_| RightKeyError::NoScalar)?;
            // Rejects zero and anything at or above the group order.
            if let Ok(key) = SigningKey::from_slice(candidate.as_ref()) {
                return Ok(Self { key, window });
            }
        }
        Err(RightKeyError::NoScalar)
    }

    /// The day the key is for.
    #[must_use]
    pub const fn window(&self) -> Epoch {
        self.window
    }

    /// The public key as the journal writes it: `x` and `y`, 32 bytes each,
    /// big-endian.
    #[must_use]
    pub fn public_key(&self) -> ([u8; 32], [u8; 32]) {
        let point = self.key.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        let mut x = [0; 32];
        let mut y = [0; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        (x, y)
    }

    /// Signs `ping`.
    #[must_use]
    pub fn sign_ping(&self, params: JournalParams, ping: Ping) -> SignedPing {
        let (r, s) = self.sign(&ping.hash(params));
        SignedPing { ping, r, s }
    }

    /// The signature that opens a session at Control Plane `cp`, `r ‖ s`:
    /// over the Control Plane's single-use `challenge` and the public key
    /// the node's credentials are to be sealed to.
    ///
    /// ```text
    /// SHA-256("singula-open-v1" ‖ chainId ‖ domain ‖ challenge ‖ cp ‖ session key)
    /// ```
    ///
    /// # Security
    ///
    /// A right's proof can be copied — a client hands it to every Control
    /// Plane it uses — but this signature cannot be made without the key, and
    /// names the Control Plane and the session key, so a copied proof opens
    /// nothing.
    #[must_use]
    pub fn sign_open(
        &self,
        params: JournalParams,
        challenge: &[u8; 32],
        cp: StarId,
        session_public_key: &[u8],
    ) -> [u8; 64] {
        let (r, s) = self.sign(&open_digest(params, challenge, cp, session_public_key));
        let mut out = [0; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        out
    }

    /// ECDSA over a SHA-256 digest computed by the caller: what Android
    /// Keystore and `WebCrypto` call ECDSA-SHA256 over the digest's preimage.
    fn sign(&self, digest: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        // Signing a 32-byte prehash with a valid key does not fail.
        let signature: Signature = self
            .key
            .sign_prehash(digest)
            .unwrap_or_else(|_| unreachable!("a 32-byte prehash always signs"));
        let (r, s) = signature.split_bytes();
        (r.into(), s.into())
    }
}

/// What a right's key signs to open a session at Control Plane `cp`; see
/// [`RightKey::sign_open`].
#[must_use]
pub fn open_digest(
    params: JournalParams,
    challenge: &[u8; 32],
    cp: StarId,
    session_public_key: &[u8],
) -> [u8; 32] {
    let mut e = Encoder::tagged("singula-open-v1");
    e.params(params)
        .bytes(challenge)
        .u64(cp.0)
        .bytes(session_public_key);
    Sha256::digest(e.into_bytes()).into()
}

impl fmt::Debug for RightKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RightKey")
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARAMS: JournalParams = JournalParams::new(421_614);

    #[test]
    fn the_derivation_is_pinned() {
        // A change here changes every subscriber's key for every day, and
        // devices on the old and new derivation void each other's rights.
        // Recomputed independently from the formula in the type's docs.
        let key = RightKey::derive(&[7; 32], PARAMS, Epoch(170)).expect("derives");
        let (x, _) = key.public_key();
        assert_eq!(
            hex::encode(x),
            "c612b9ad6b58a54ea8703612fd507407cc2c0d6054fbaa6b18855c7784d68748"
        );
    }

    #[test]
    fn slots_days_and_networks_get_different_keys() {
        let key = |secret: u8, chain: u64, window: u64| {
            RightKey::derive(&[secret; 32], JournalParams::new(chain), Epoch(window))
                .expect("derives")
                .public_key()
        };
        let base = key(7, 421_614, 170);
        assert_ne!(base, key(8, 421_614, 170), "another slot");
        assert_ne!(base, key(7, 421_614, 171), "another day");
        assert_ne!(base, key(7, 42_161, 170), "another chain");
    }

    #[test]
    fn debug_shows_no_secret() {
        let key = RightKey::derive(&[7; 32], PARAMS, Epoch(170)).expect("derives");
        assert_eq!(format!("{key:?}"), "RightKey { window: Epoch(170), .. }");
    }
}
