//! Where the client reads the time.

use crate::id::UnixTime;

/// The time the client acts on: which epoch it is, and whether a session
/// is due for renewal or past its expiry.
///
/// The system clock unless told otherwise. A device whose clock is wrong
/// can supply a corrected one — the Control Plane's, say, from
/// [`ControlPlaneClient::health`](super::ControlPlaneClient::health) — since
/// a client a day off proves for the wrong epoch and is refused.
pub trait TimeSource: Send + Sync + 'static {
    /// Now.
    fn now(&self) -> UnixTime;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTime;

impl TimeSource for SystemTime {
    fn now(&self) -> UnixTime {
        UnixTime::now()
    }
}
