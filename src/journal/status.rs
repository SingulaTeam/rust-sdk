//! Whether a session is still open, and why it closed.

use std::fmt;

use crate::id::UnixTime;

/// Why the network closed a session on a right.
///
/// A Control Plane closes one whose pings stopped or stopped growing, or
/// that sat idle; a node closes one its Control Plane told it to, one it saw
/// carry traffic without pings recorded for it, or one whose credentials it
/// saw used from several places. Every Control Plane learns the reason, so a
/// client whose tunnel dropped can ask any of them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CloseReason {
    /// No ping was recorded for too long.
    NoPings,
    /// The day's right ended and no new one came.
    RightEnded,
    /// Pings kept coming, but their totals stopped growing while traffic
    /// flowed.
    PingsNotGrowing,
    /// No traffic for too long.
    Idle,
    /// Another session on the same slot was opened earlier and is still
    /// running: another device is using the slot.
    Overlap,
    /// The node carried traffic its Control Planes recorded no pings for.
    NodeNotGrowing,
    /// The node saw the session's credentials used from several places.
    SharedCredentials,
    /// The session reached the end of its lifetime on the node.
    Expired,
    /// The node ended it for another reason, or was told to.
    Terminated,
    /// A reason this version of the SDK does not know, as the Control Plane
    /// named it.
    Other(String),
}

impl CloseReason {
    /// The reason a Control Plane names on the wire.
    #[must_use]
    pub fn from_wire(name: &str) -> Self {
        match name {
            "no_pings" => Self::NoPings,
            "right_ended" => Self::RightEnded,
            "pings_not_growing" => Self::PingsNotGrowing,
            "idle" => Self::Idle,
            "overlap" => Self::Overlap,
            "node_not_growing" => Self::NodeNotGrowing,
            "shared_credentials" => Self::SharedCredentials,
            "expired" => Self::Expired,
            "terminated" => Self::Terminated,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The name a Control Plane uses for it on the wire.
    #[must_use]
    pub fn as_wire(&self) -> &str {
        match self {
            Self::NoPings => "no_pings",
            Self::RightEnded => "right_ended",
            Self::PingsNotGrowing => "pings_not_growing",
            Self::Idle => "idle",
            Self::Overlap => "overlap",
            Self::NodeNotGrowing => "node_not_growing",
            Self::SharedCredentials => "shared_credentials",
            Self::Expired => "expired",
            Self::Terminated => "terminated",
            Self::Other(name) => name,
        }
    }
}

impl fmt::Display for CloseReason {
    /// A plain description, for logs; applications show their own text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoPings => "no ping was recorded for too long",
            Self::RightEnded => "the day's right ended",
            Self::PingsNotGrowing => "pings stopped growing while traffic flowed",
            Self::Idle => "no traffic for too long",
            Self::Overlap => "another device is using this slot",
            Self::NodeNotGrowing => "the node saw traffic with no pings recorded for it",
            Self::SharedCredentials => "the session's credentials were used from several places",
            Self::Expired => "the session reached the end of its lifetime",
            Self::Terminated => "the node ended the session",
            Self::Other(name) => name,
        })
    }
}

/// What one Control Plane knows of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionStatus {
    /// Open: its latest committed ping, when there is one.
    Open {
        /// The latest committed ping's total.
        total: u64,
        /// When that ping was committed.
        last: Option<UnixTime>,
    },
    /// Closed, and why.
    Closed(CloseReason),
    /// This Control Plane never held it: ask another.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_reason_round_trips() {
        for name in [
            "no_pings",
            "right_ended",
            "pings_not_growing",
            "idle",
            "overlap",
            "node_not_growing",
            "shared_credentials",
            "expired",
            "terminated",
        ] {
            let reason = CloseReason::from_wire(name);
            assert!(!matches!(reason, CloseReason::Other(_)), "{name} is known");
            assert_eq!(reason.as_wire(), name);
        }
        assert_eq!(
            CloseReason::from_wire("new_reason"),
            CloseReason::Other("new_reason".to_owned())
        );
    }
}
