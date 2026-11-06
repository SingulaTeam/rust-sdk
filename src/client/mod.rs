//! Talking to Control Planes.
//!
//! A [`ControlPlaneClient`] speaks to one Control Plane, named by its Star id
//! and reached at the endpoint it published on chain. What a client does with
//! it, in order:
//!
//! 1. [`issuer_key`](ControlPlaneClient::issuer_key) — the key this window's
//!    permissions are signed under, checked against its on-chain commitment.
//! 2. [`take_permission`](ControlPlaneClient::take_permission) — one of this
//!    window's [`Permission`]s, signed blind so the issuer cannot recognise
//!    it later. Each index once per subscription per window, network-wide.
//! 3. [`list_nodes`](ControlPlaneClient::list_nodes) — the nodes it can serve.
//! 4. [`open_session`](ControlPlaneClient::open_session) — a session on a
//!    node, admitted by a membership proof and one permission. The node's
//!    answer is checked against its signer key on chain and decrypted.
//! 5. [`report`](ControlPlaneClient::report) and
//!    [`renew`](ControlPlaneClient::renew) — while the session runs.
//!
//! Every call is its own short conversation: it opens the stream, says one
//! thing, waits for the answer and closes. Nothing is held open between
//! calls, so nothing breaks when the network underneath changes — when a
//! tunnel comes up and the next call travels through it. A session outlives
//! the call that opened it, known to the Control Plane by its checkpoint key
//! rather than by a connection.
//!
//! Anything a decision rests on — which Control Planes exist, who runs a
//! node, which key a window's permissions must be signed under — is read
//! from the chain, never taken from the Control Plane being asked.

mod account;
mod auth;
mod call;
mod connect;
mod connection;
mod governance;
mod ledger;
mod nodes;
mod permission;
mod proto;
mod relay;
mod session;
pub mod store;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;
mod time;
mod tunnel;
pub mod wallet;

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

pub use account::{Health, NetworkInfo, SubscriptionInfo};
pub use auth::{SIGN_IN_LIFETIME, WalletAuth, WalletAuthError};
pub use connect::{Access, ConnectOptions, Singula};
pub use connection::{Connection, EndReason, Event, Timing, TrafficMeter};
pub use governance::{GovernanceAction, Participant, Vote};
pub use nodes::{CountryNodes, NodeCandidate};
pub use permission::{IssuerKey, Permission};
pub use relay::{Activated, MAX_SLOTS, Minted, RELAY_DEADLINE};
pub use session::{Egress, Session, SessionRequest, Traffic};
pub use time::{SystemTime, TimeSource};
pub use tunnel::{Cover, TunnelSettings};

use crate::chain::{ChainError, ControlPlane};
use crate::id::{StarId, UnixTime};
use crate::session::OpenError;

/// The port a Control Plane listens on when its registry entry names none.
pub const DEFAULT_PORT: u16 = 443;

/// A connection to one Control Plane.
///
/// Cheap to clone; clones share the underlying connection. Nothing is dialled
/// until the first call.
#[derive(Clone)]
pub struct ControlPlaneClient {
    star: StarId,
    channel: Channel,
    timeout: Duration,
}

impl ControlPlaneClient {
    /// A client for `cp`, at the endpoint it published, over TLS.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Endpoint`] if the published host does not form
    /// a valid URL.
    pub fn new(cp: &ControlPlane) -> Result<Self, ClientError> {
        Self::with_url(cp.star, &url(cp)?)
    }

    /// A client for `cp` that connects to `addresses`, at the port it
    /// published, instead of resolving the host it published.
    ///
    /// For applications that must resolve names themselves: one with a kill
    /// switch, say, which blocks DNS while its tunnel is down yet still has
    /// to reach a Control Plane to open the next session, resolves the host
    /// beforehand and passes the answer here. TLS still verifies the
    /// certificate against the published host, so a wrong address fails to
    /// connect rather than reaching someone else.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Endpoint`] if the published host does not form
    /// a valid URL, or `addresses` is empty.
    pub fn at(cp: &ControlPlane, addresses: &[IpAddr]) -> Result<Self, ClientError> {
        if addresses.is_empty() {
            return Err(ClientError::Endpoint);
        }
        let port = cp.port.map_or(DEFAULT_PORT, u16::from);
        let addresses: Arc<[SocketAddr]> = addresses
            .iter()
            .map(|&ip| SocketAddr::new(ip, port))
            .collect();
        let connector = tower::service_fn(move |_: tonic::transport::Uri| {
            let addresses = Arc::clone(&addresses);
            async move { TcpStream::connect(&*addresses).await.map(TokioIo::new) }
        });
        let channel = endpoint(&url(cp)?)?.connect_with_connector_lazy(connector);
        Ok(Self::from_channel(cp.star, channel))
    }

    /// A client for Control Plane `star` through its front, over the
    /// connections `dial` opens: to the local entry of a tunnel engine the
    /// application runs with the settings in [`front`](crate::chain::front),
    /// say.
    ///
    /// For networks that block the endpoint. The front answers in plain
    /// HTTP/2, so `dial` must reach `star`'s front and nothing else.
    ///
    /// # Security
    ///
    /// REALITY is what authenticates the Control Plane here, in place of the
    /// TLS certificate of its endpoint: build the tunnel with the key `star`
    /// published on chain ([`ControlPlane::front`]), never with one handed
    /// over by anyone else.
    pub fn through<D, F, S>(star: StarId, dial: D) -> Self
    where
        D: Fn() -> F + Send + Sync + Clone + 'static,
        F: Future<Output = std::io::Result<S>> + Send + 'static,
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let connector = tower::service_fn(move |_: tonic::transport::Uri| {
            let dial = dial.clone();
            async move { dial().await.map(TokioIo::new) }
        });
        let channel = keep_alive(Endpoint::from_static("http://front.invalid"))
            .connect_with_connector_lazy(connector);
        Self::from_channel(star, channel)
    }

    /// A client for Control Plane `star` at `url`.
    ///
    /// Meant for development against a local Control Plane. In production use
    /// [`new`](Self::new) with an entry read from the chain: an address
    /// suggested by anyone else is a Control Plane of their choosing.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Endpoint`] unless `url` is `https`, or `http`
    /// to this machine.
    pub fn with_url(star: StarId, url: &str) -> Result<Self, ClientError> {
        Ok(Self::from_channel(star, endpoint(url)?.connect_lazy()))
    }

    /// A client for Control Plane `star` over a channel the application
    /// built: through a proxy, a tunnel's local port, or any transport tonic
    /// can carry.
    ///
    /// The SDK does not route traffic; this is where the application does.
    /// To reach the exit leg's Control Plane through the entry leg's tunnel,
    /// say, build the channel to dial through that tunnel. Pass the result
    /// to [`Singula::with_control_plane`] to have [`Singula::connect`] use it.
    ///
    /// # Security
    ///
    /// The channel decides who answers as `star`. Build it to the endpoint
    /// `star` published on chain, with TLS, and let the proxy carry the
    /// connection rather than terminate it.
    #[must_use]
    pub fn from_channel(star: StarId, channel: Channel) -> Self {
        Self {
            star,
            channel,
            timeout: call::CALL_TIMEOUT,
        }
    }

    /// Gives every call at most `timeout` instead of the default 45 seconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The Control Plane's Star id.
    #[must_use]
    pub fn star(&self) -> StarId {
        self.star
    }
}

impl fmt::Debug for ControlPlaneClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlPlaneClient")
            .field("star", &self.star)
            .finish_non_exhaustive()
    }
}

/// The trust anchors for Control Planes' certificates.
/// The URL of the endpoint `cp` published.
fn url(cp: &ControlPlane) -> Result<String, ClientError> {
    let port = cp.port.map_or(DEFAULT_PORT, u16::from);
    let host = cp.host.trim();
    // Hosts are published bare; refuse anything that would change what the
    // URL means rather than just where it points.
    if host.is_empty() || host.contains(['/', '@', '?', '#', ' ']) {
        return Err(ClientError::Endpoint);
    }
    Ok(format!("https://{host}:{port}"))
}

/// An endpoint at `url`: `https`, or `http` to this machine.
fn endpoint(url: &str) -> Result<Endpoint, ClientError> {
    let endpoint = Endpoint::from_shared(url.to_owned()).map_err(|_| ClientError::Endpoint)?;
    let local = matches!(
        endpoint.uri().host(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    );
    let endpoint = match endpoint.uri().scheme_str() {
        Some("https") => endpoint
            .tls_config(tls())
            .map_err(|_| ClientError::Endpoint)?,
        Some("http") if local => endpoint,
        _ => return Err(ClientError::Endpoint),
    };
    Ok(keep_alive(endpoint))
}

fn keep_alive(endpoint: Endpoint) -> Endpoint {
    endpoint
        .connect_timeout(Duration::from_secs(10))
        // Kept warm between calls, so a proxy in the path does not reap it.
        .http2_keep_alive_interval(Duration::from_secs(15))
        .keep_alive_timeout(Duration::from_secs(10))
}

fn tls() -> ClientTlsConfig {
    let config = ClientTlsConfig::new();
    #[cfg(feature = "native-roots")]
    let config = config.with_native_roots();
    #[cfg(not(feature = "native-roots"))]
    let config = config.with_webpki_roots();
    config
}

/// A country, as an ISO 3166-1 alpha-2 code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Country([u8; 2]);

/// Why a string is not a [`Country`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a country is two letters, as in ISO 3166-1 alpha-2")]
pub struct CountryError;

impl Country {
    /// The two-letter code, in capitals.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Two ASCII capitals, checked when it was made.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl FromStr for Country {
    type Err = CountryError;

    /// Accepts either case; stores capitals.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.as_bytes() {
            &[a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Ok(Self([a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
            }
            _ => Err(CountryError),
        }
    }
}

impl fmt::Display for Country {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a call to a Control Plane failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The Control Plane's endpoint is not a usable URL.
    #[error("the Control Plane's endpoint is not a usable https URL")]
    Endpoint,
    /// The call failed below the protocol: the connection, TLS, or gRPC.
    #[error("the Control Plane could not be reached ({code:?}): {message}")]
    Transport {
        /// The gRPC status code.
        code: tonic::Code,
        /// What gRPC reported.
        message: String,
    },
    /// No answer in time.
    #[error("the Control Plane did not answer in time")]
    Timeout,
    /// The Control Plane closed the conversation without answering.
    #[error("the Control Plane closed the stream without answering")]
    Closed,
    /// The Control Plane answered with an error.
    #[error("the Control Plane refused: {message}")]
    Refused {
        /// The protocol's error code; see `ErrorCode` in `client.proto`.
        code: i32,
        /// The Control Plane's explanation.
        message: String,
    },
    /// The answer does not hold together: a missing field, a wrong length, a
    /// value out of range.
    #[error("the Control Plane's answer is malformed: {0}")]
    Malformed(&'static str),
    /// The answer contradicts the chain or the request. The Control Plane
    /// should not be trusted for this call again.
    #[error("the Control Plane's answer cannot be trusted: {0}")]
    Untrusted(&'static str),
    /// The request was for a different Control Plane, window or session
    /// than this call.
    #[error("the request does not fit this call: {0}")]
    Mismatch(&'static str),
    /// A read from the chain failed.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// The node's sealed credentials could not be opened.
    #[error(transparent)]
    Open(#[from] OpenError),
    /// The wallet did not sign.
    #[error(transparent)]
    Wallet(#[from] wallet::WalletError),
    /// The store failed.
    #[error(transparent)]
    Store(#[from] store::StoreError),
    /// A membership proof could not be made.
    #[error(transparent)]
    Prove(#[from] crate::zk::ProveError),
    /// The subscriber's identity is not in the anonymity set: the
    /// subscription was activated without it, or the registration has not
    /// reached the chain yet.
    #[error("this identity is not in the anonymity set")]
    NotRegistered,
    /// Every permission the subscription may take this window is taken:
    /// held by this client's sessions, or taken by its other devices.
    #[error("every permission of this window is taken")]
    NoPermissionFree,
    /// The permission at this index was taken already this window, by
    /// another of the subscription's devices or an earlier request.
    #[error("permission {0} of this window is taken already")]
    PermissionTaken(u32),
    /// No permission is free now, but one whose session has ended will be
    /// once the Control Planes' hold on it runs out, at this time.
    #[error("no permission is free until {}", .0 .0)]
    PermissionFreeAt(UnixTime),
    /// The Control Plane admitted a session on `node`, and the client refused
    /// the node's answer: it did not check out against the chain. Try another
    /// node; this one, or the path to it, does not answer as it must.
    #[error("the answer from node {node} was refused: {error}")]
    NodeAnswer {
        /// The node the answer names.
        node: StarId,
        /// Why it was refused.
        error: Box<ClientError>,
    },
    /// No Control Plane answered.
    #[error("no Control Plane is available")]
    NoControlPlane,
}

impl ClientError {
    fn from_status(status: &tonic::Status) -> Self {
        Self::Transport {
            code: status.code(),
            message: status.message().to_owned(),
        }
    }
}
