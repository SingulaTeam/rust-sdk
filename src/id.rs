//! Identifiers and instants the protocol passes around.
//!
//! Each gets its own type so that a Star id cannot be handed where an epoch is
//! expected, and so that the rules a value must follow on the wire are checked
//! once, where it is made, rather than wherever it is used.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// A Star's on-chain identity in `StarRegistry` — a node or a Control Plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StarId(pub u64);

impl fmt::Display for StarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A protocol epoch: one day of served time, and also the window a packet of
/// permissions belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(pub u64);

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Seconds since the Unix epoch, as the protocol signs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(pub i64);

impl UnixTime {
    /// The current time.
    ///
    /// A clock set before 1970 reads as the epoch itself rather than as a
    /// negative time: every signed timestamp would be refused either way, and
    /// this keeps the call infallible.
    #[must_use]
    pub fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Self(i64::try_from(secs).unwrap_or(i64::MAX))
    }
}

impl fmt::Display for UnixTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A session, named by the UUID its node assigned to it.
///
/// Only the canonical lowercase hyphenated form is accepted: the id is hashed
/// into every checkpoint and renewal, so two spellings of one UUID would sign
/// different bytes and the Control Plane would refuse one of them.
///
/// ```
/// # use singula::SessionId;
/// let id: SessionId = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f".parse()?;
/// assert_eq!(id.as_str(), "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f");
/// # Ok::<(), singula::SessionIdError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

/// Why a string is not a [`SessionId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionIdError {
    /// Not 36 characters long.
    #[error("a session id is 36 characters long, this one is {0}")]
    Length(usize),
    /// A character other than a lowercase hex digit, or a hyphen out of place.
    #[error("a session id is a lowercase hyphenated UUID; character {0} is not")]
    Character(usize),
}

impl SessionId {
    /// Positions of the hyphens in `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    const HYPHENS: [usize; 4] = [8, 13, 18, 23];

    /// The id as it goes on the wire and into digests.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SessionId {
    type Err = SessionIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 36 {
            return Err(SessionIdError::Length(s.len()));
        }
        for (i, b) in s.bytes().enumerate() {
            let ok = if Self::HYPHENS.contains(&i) {
                b == b'-'
            } else {
                matches!(b, b'0'..=b'9' | b'a'..=b'f')
            };
            if !ok {
                return Err(SessionIdError::Character(i));
            }
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A client-chosen label that pairs a request with its answer.
///
/// It may be any text except one containing a NUL byte: the renewal digest
/// separates the session id from the request id with a single `0x00`, and a
/// NUL inside the request id would let two different requests hash alike.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(String);

/// Why a string is not a [`RequestId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestIdError {
    /// The id is empty.
    #[error("a request id cannot be empty")]
    Empty,
    /// The id contains a NUL byte.
    #[error("a request id cannot contain a NUL byte (found at {0})")]
    Nul(usize),
}

impl RequestId {
    /// The id as it goes on the wire and into digests.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RequestId {
    type Err = RequestIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(RequestIdError::Empty);
        }
        if let Some(at) = s.bytes().position(|b| b == 0) {
            return Err(RequestIdError::Nul(at));
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A 20-byte Ethereum address: a wallet, or the signer key a Star registered.
///
/// Parsed from `0x` followed by 40 hex digits in any case, since EIP-55
/// checksummed and lowercase spellings name the same account; shown in
/// lowercase.
///
/// ```
/// # use singula::Address;
/// let a: Address = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23".parse()?;
/// assert_eq!(a.to_string(), "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23");
/// # Ok::<(), singula::AddressError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 20]);

/// Why a string is not an [`Address`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AddressError {
    /// Not `0x` followed by 40 characters.
    #[error("an address is 0x followed by 40 hex digits")]
    Shape,
    /// A character that is not a hex digit.
    #[error("an address is hex; character {0} is not")]
    Character(usize),
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s.strip_prefix("0x").ok_or(AddressError::Shape)?.as_bytes();
        if digits.len() != 40 {
            return Err(AddressError::Shape);
        }
        let nibble = |i: usize| {
            char::from(digits[i])
                .to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
                .ok_or(AddressError::Character(i + 2))
        };
        let mut bytes = [0; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = nibble(2 * i)? << 4 | nibble(2 * i + 1)?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_canonical_uuid_is_a_session_id() {
        let id: Result<SessionId, _> = "8f14e45f-ceea-467f-a8d5-1a2b3c4d5e6f".parse();
        assert!(id.is_ok());
    }

    #[test]
    fn other_spellings_of_a_uuid_are_refused() {
        assert_eq!(
            "8F14E45F-CEEA-467F-A8D5-1A2B3C4D5E6F".parse::<SessionId>(),
            Err(SessionIdError::Character(1))
        );
        assert_eq!(
            "8f14e45fceea467fa8d51a2b3c4d5e6f".parse::<SessionId>(),
            Err(SessionIdError::Length(32))
        );
        assert_eq!(
            "8f14e45f-ceea-467f-a8d5_1a2b3c4d5e6f".parse::<SessionId>(),
            Err(SessionIdError::Character(23))
        );
    }

    #[test]
    fn a_request_id_may_not_hide_a_separator() {
        assert_eq!(
            "req\0uest".parse::<RequestId>(),
            Err(RequestIdError::Nul(3))
        );
        assert_eq!("".parse::<RequestId>(), Err(RequestIdError::Empty));
        assert!("req-42".parse::<RequestId>().is_ok());
    }

    #[test]
    fn an_address_reads_in_any_case() {
        let lower: Address = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
            .parse()
            .expect("lowercase");
        let mixed: Address = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
            .parse()
            .expect("checksummed");
        assert_eq!(lower, mixed);
        assert_eq!(lower.0[0], 0x2c);
        assert_eq!(lower.0[19], 0x23);
    }

    #[test]
    fn an_address_has_one_shape() {
        assert_eq!(
            "2c7536e3605d9c16a7a3d7b1898e529396a65c23".parse::<Address>(),
            Err(AddressError::Shape)
        );
        assert_eq!("0x2c75".parse::<Address>(), Err(AddressError::Shape));
        assert_eq!(
            "0xzc7536e3605d9c16a7a3d7b1898e529396a65c23".parse::<Address>(),
            Err(AddressError::Character(2))
        );
    }
}
