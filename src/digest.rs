//! The digests a session's checkpoint key signs.
//!
//! The Control Plane rebuilds each digest from the fields it receives and
//! checks the signature over its own copy, so these functions must agree with
//! it byte for byte. Each begins with a domain tag that names what is being
//! signed and its version, so a signature over one kind of message can never
//! be presented as another.
//!
//! The vectors in the tests below are pinned on the Control Plane too
//! (`checkpoint_digest_test.go`, `renewal_digest_test.go`,
//! `end_digest_test.go`); a change on either side fails both builds rather
//! than every session in production.

use std::fmt;

use sha3::{Digest as _, Keccak256};

use crate::id::{RequestId, SessionId, UnixTime};

/// A 32-byte Keccak-256 digest, the message a [`CheckpointKey`] signs.
///
/// [`CheckpointKey`]: crate::CheckpointKey
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The digest's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Digest {
    /// Lowercase hex, without a `0x` prefix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

/// A report of the traffic a session has carried so far.
///
/// The client signs one each time the Control Plane asks, with the nonce from
/// that request, so a report cannot be replayed into a later round. The byte
/// counts are cumulative over the whole session, not deltas since the last
/// report.
///
/// # Wire format
///
/// ```text
/// keccak256( "singula-cp-v1"
///          ‖ session id      (36 ASCII bytes)
///          ‖ bytes up        (u64, big-endian)
///          ‖ bytes down      (u64, big-endian)
///          ‖ timestamp       (i64, big-endian, Unix seconds)
///          ‖ nonce           (as received) )
/// ```
///
/// # Examples
///
/// ```
/// # use singula::{Checkpoint, SessionId, UnixTime};
/// let session: SessionId = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f".parse()?;
/// let digest = Checkpoint {
///     session: &session,
///     bytes_up: 1 << 20,
///     bytes_down: 50 << 20,
///     timestamp: UnixTime(1_760_000_000),
///     nonce: &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4],
/// }
/// .digest();
/// assert_eq!(
///     digest.to_string(),
///     "f898f2408d12e38b7f453e8005cbe1369b1f4e41eed64160762accabc1bc562d",
/// );
/// # Ok::<(), singula::SessionIdError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint<'a> {
    /// The session being reported on.
    pub session: &'a SessionId,
    /// Bytes sent by the client since the session opened.
    pub bytes_up: u64,
    /// Bytes received by the client since the session opened.
    pub bytes_down: u64,
    /// When the report was made.
    pub timestamp: UnixTime,
    /// The nonce from the Control Plane's request for this report.
    pub nonce: &'a [u8],
}

impl Checkpoint<'_> {
    const DOMAIN: &'static [u8] = b"singula-cp-v1";

    /// The digest to sign.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut h = Keccak256::new();
        h.update(Self::DOMAIN);
        h.update(self.session.as_str());
        h.update(self.bytes_up.to_be_bytes());
        h.update(self.bytes_down.to_be_bytes());
        h.update(self.timestamp.0.to_be_bytes());
        h.update(self.nonce);
        Digest(h.finalize().into())
    }
}

/// A request to extend a session's lease, signed by that session's key.
///
/// Because the signature, not the connection, proves who is asking, a renewal
/// can travel over any stream or short call, not only the one that opened the
/// session.
///
/// # Wire format
///
/// ```text
/// keccak256( "singula-renew-v1"
///          ‖ session id      (36 ASCII bytes)
///          ‖ 0x00
///          ‖ request id      (UTF-8, no NUL)
///          ‖ timestamp       (i64, big-endian, Unix seconds) )
/// ```
///
/// The session id has a fixed length, and the request id cannot contain a
/// NUL, so the separator keeps every pair of fields unambiguous.
///
/// # Examples
///
/// ```
/// # use singula::{Renewal, RequestId, SessionId, UnixTime};
/// let session: SessionId = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f".parse()?;
/// let request: RequestId = "req-42".parse()?;
/// let digest = Renewal {
///     session: &session,
///     request: &request,
///     timestamp: UnixTime(1_760_000_000),
/// }
/// .digest();
/// assert_eq!(
///     digest.to_string(),
///     "555f7f82abb88aecf262c14e29eb7e257e1e7cc283ac20a353df40b52af570ec",
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Renewal<'a> {
    /// The session whose lease is extended.
    pub session: &'a SessionId,
    /// The label the Control Plane will echo in its answer.
    pub request: &'a RequestId,
    /// When the renewal was asked for.
    pub timestamp: UnixTime,
}

impl Renewal<'_> {
    const DOMAIN: &'static [u8] = b"singula-renew-v1";

    /// The digest to sign.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut h = Keccak256::new();
        h.update(Self::DOMAIN);
        h.update(self.session.as_str());
        h.update([0]);
        h.update(self.request.as_str());
        h.update(self.timestamp.0.to_be_bytes());
        Digest(h.finalize().into())
    }
}

/// The end of a session, signed by that session's key.
///
/// How an anonymous client ends its session early: nothing else ties it to
/// the session across calls. Ending it frees the session's permission across
/// the network within one lease.
///
/// # Wire format
///
/// ```text
/// keccak256( "singula-end-v1"
///          ‖ session id      (36 ASCII bytes)
///          ‖ bytes up        (u64, big-endian)
///          ‖ bytes down      (u64, big-endian)
///          ‖ timestamp       (i64, big-endian, Unix seconds) )
/// ```
///
/// # Examples
///
/// ```
/// # use singula::{Ending, SessionId, UnixTime};
/// let session: SessionId = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f".parse()?;
/// let digest = Ending {
///     session: &session,
///     up: 1_000,
///     down: 2_000,
///     timestamp: UnixTime(1_760_000_000),
/// }
/// .digest();
/// assert_eq!(
///     digest.to_string(),
///     "1f9cf97a504bc1850b4823ee9ba1a1e93faeb9966622052f71c9881ece793f08",
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ending<'a> {
    /// The session that ends.
    pub session: &'a SessionId,
    /// Bytes sent over the whole session.
    pub up: u64,
    /// Bytes received over the whole session.
    pub down: u64,
    /// When the end was signed.
    pub timestamp: UnixTime,
}

impl Ending<'_> {
    const DOMAIN: &'static [u8] = b"singula-end-v1";

    /// The digest to sign.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut h = Keccak256::new();
        h.update(Self::DOMAIN);
        h.update(self.session.as_str());
        h.update(self.up.to_be_bytes());
        h.update(self.down.to_be_bytes());
        h.update(self.timestamp.0.to_be_bytes());
        Digest(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f";

    fn session() -> SessionId {
        SESSION.parse().expect("a canonical session id")
    }

    fn checkpoint<'a>(session: &'a SessionId, nonce: &'a [u8]) -> Checkpoint<'a> {
        Checkpoint {
            session,
            bytes_up: 1_048_576,
            bytes_down: 52_428_800,
            timestamp: UnixTime(1_760_000_000),
            nonce,
        }
    }

    #[test]
    fn checkpoint_matches_the_control_plane() {
        let s = session();
        let d = checkpoint(&s, &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]).digest();
        assert_eq!(
            d.to_string(),
            "f898f2408d12e38b7f453e8005cbe1369b1f4e41eed64160762accabc1bc562d"
        );
    }

    #[test]
    fn renewal_matches_the_control_plane() {
        let s = session();
        let r: RequestId = "req-42".parse().expect("a valid request id");
        let d = Renewal {
            session: &s,
            request: &r,
            timestamp: UnixTime(1_760_000_000),
        }
        .digest();
        assert_eq!(
            d.to_string(),
            "555f7f82abb88aecf262c14e29eb7e257e1e7cc283ac20a353df40b52af570ec"
        );
    }

    #[test]
    fn every_field_is_signed() {
        let s = session();
        let base = checkpoint(&s, b"nonce");
        let variants = [
            Checkpoint {
                bytes_up: 1,
                ..base
            },
            Checkpoint {
                bytes_down: 1,
                ..base
            },
            Checkpoint {
                timestamp: UnixTime(1),
                ..base
            },
            Checkpoint {
                nonce: b"other",
                ..base
            },
        ];
        for v in variants {
            assert_ne!(v.digest(), base.digest(), "{v:?}");
        }
    }
}
