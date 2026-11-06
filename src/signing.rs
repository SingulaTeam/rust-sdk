//! The key a session signs its reports and renewals with.
//!
//! The client sends the public half when it opens a session, and the Control
//! Plane checks every [`Checkpoint`] and [`Renewal`] for that session against
//! it. The key is generated for the one session and never stored, so the
//! signatures say nothing about who the client is — only that each came from
//! whoever opened the session.
//!
//! [`Checkpoint`]: crate::Checkpoint
//! [`Renewal`]: crate::Renewal

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;

use crate::digest::Digest;

/// One session's Ed25519 signing key.
///
/// The secret is wiped from memory when the key is dropped.
///
/// # Examples
///
/// ```
/// # use singula::{CheckpointKey, Checkpoint, SessionId, UnixTime};
/// let key = CheckpointKey::generate();
/// let public = key.public_key(); // goes into the session request
///
/// let session: SessionId = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f".parse()?;
/// let report = Checkpoint {
///     session: &session,
///     bytes_up: 0,
///     bytes_down: 0,
///     timestamp: UnixTime::now(),
///     nonce: b"from the control plane",
/// };
/// let signature = key.sign(&report.digest());
/// # let _ = (public, signature);
/// # Ok::<(), singula::SessionIdError>(())
/// ```
pub struct CheckpointKey(SigningKey);

impl CheckpointKey {
    /// A fresh key from the operating system's random number generator.
    #[must_use]
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// The public key to send with the session request.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs `digest`.
    ///
    /// The digest itself is the Ed25519 message; it is not hashed again,
    /// because the Control Plane verifies over the same 32 bytes.
    #[must_use]
    pub fn sign(&self, digest: &Digest) -> Signature {
        Signature(self.0.sign(digest.as_bytes()).to_bytes())
    }
}

impl fmt::Debug for CheckpointKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckpointKey")
            .field("public", &Hex(&self.public_key()))
            .finish_non_exhaustive()
    }
}

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// The signature's bytes, as they go on the wire.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:?})", Hex(&self.0))
    }
}

/// Bytes shown as lowercase hex.
struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Verifier as _, VerifyingKey};

    use super::*;

    #[test]
    fn signs_the_digest_itself() {
        // Go's ed25519.Sign with seed 0x40, 0x41, … over these 32 bytes.
        let seed: [u8; 32] =
            hex::decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
                .expect("valid hex")
                .try_into()
                .expect("32 bytes");
        let message =
            hex::decode("493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d")
                .expect("valid hex");
        let digest = Digest::from(<[u8; 32]>::try_from(message.as_slice()).expect("32 bytes"));
        let key = CheckpointKey(SigningKey::from_bytes(&seed));
        assert_eq!(
            hex::encode(key.public_key()),
            "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"
        );
        assert_eq!(
            hex::encode(key.sign(&digest).to_bytes()),
            "f4cf6e02705efcaf8543261fb9a738fc46241957c48f26ed8ae777de509898aefc01730ca70f5e41c8210cda1e9922aa5a7d8a5f7c58e988a3201ae8e87d000e"
        );
    }

    #[test]
    fn a_signature_verifies_under_the_public_key() {
        let key = CheckpointKey::generate();
        let digest = Digest::from([7; 32]);
        let public = VerifyingKey::from_bytes(&key.public_key()).expect("a valid key");
        let signature = ed25519_dalek::Signature::from_bytes(&key.sign(&digest).to_bytes());
        assert!(public.verify(digest.as_bytes(), &signature).is_ok());
    }
}
