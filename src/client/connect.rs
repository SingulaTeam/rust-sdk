//! The whole client, in a few calls.
//!
//! [`Singula`] holds what every call needs — the chain, the prover, the
//! store — and runs the protocol's steps in the order they must happen:
//! identity before proof, the day's right before the session it opens.
//! [`Singula::connect`] ends with a running [`Connection`]: tunnel settings
//! to hand to the engine, and a task that keeps the session — by pings on a
//! right, by reports and renewals for a wallet — until it is closed.
//!
//! Everything here is built from the calls in [`ControlPlaneClient`] and
//! [`Chain`]; use those directly where this does not fit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::task::JoinSet;

use super::connection::{Connection, Keeper, Opened, Timing, TrafficMeter};
use super::governance::{GovernanceAction, Participant};
use super::pinger::{self, OnRight};
use super::records::Records;
use super::relay::{Activated, MAX_SLOTS, Minted};
use super::rights::JournalState;
use super::session::{NotOpened, SessionRequest};
use super::store::Store;
use super::time::{SystemTime, TimeSource};
use super::wallet::{PersonalMessage, Wallet, sign_message_checked};
use super::{ClientError, ControlPlaneClient, Country, TunnelSettings, WalletAuth};
use crate::chain::{Chain, Payment, Rpc, TokenId, TxHash};
use crate::id::{StarId, UnixTime};
use crate::zk::{Identity, Prover};

/// How long a Control Plane has to answer when one is being chosen.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// A subscriber's identities in the set, one per registered slot, each with
/// its slot number. Never empty.
pub(super) type Identities = Arc<[(u8, Arc<Identity>)]>;

/// The SDK's whole client: chain, prover and store, shared by every call.
///
/// Cheap to clone; clones share everything.
pub struct Singula<R, S> {
    pub(super) inner: Arc<Inner<R, S>>,
}

pub(super) struct Inner<R, S> {
    pub(super) chain: Chain<R>,
    pub(super) prover: Prover,
    pub(super) store: S,
    /// Control Planes reached at an address of the application's choosing
    /// rather than the one they published.
    pinned: Mutex<HashMap<StarId, ControlPlaneClient>>,
    time: Mutex<Arc<dyn TimeSource>>,
    /// The journal's reads from the chain, and the day's rights.
    pub(super) journal: tokio::sync::Mutex<JournalState>,
}

impl<R, S> Clone for Singula<R, S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// How a session is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Access {
    /// By the day's right of one of the subscription's slots. The Control
    /// Plane learns that some paid slot connected today, and nothing else.
    #[default]
    Anonymous,
    /// By the wallet's sign-in. The Control Plane knows whose session it is.
    Wallet,
}

/// What [`Singula::connect`] should open.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct ConnectOptions {
    access: Access,
    control_plane: Option<StarId>,
    node: Option<StarId>,
    country: Option<Country>,
    cover: Option<String>,
    exit_leg: bool,
    timing: Timing,
}

impl ConnectOptions {
    /// Anonymous access, at whichever Control Plane answers fastest.
    pub fn new() -> Self {
        Self::default()
    }

    /// How the session is admitted.
    pub fn access(mut self, access: Access) -> Self {
        self.access = access;
        self
    }

    /// Use this Control Plane rather than choosing one.
    pub fn control_plane(mut self, cp: StarId) -> Self {
        self.control_plane = Some(cp);
        self
    }

    /// Use exactly this node, or fail.
    pub fn node(mut self, node: StarId) -> Self {
        self.node = Some(node);
        self
    }

    /// Prefer a node in this country.
    pub fn country(mut self, country: Country) -> Self {
        self.country = Some(country);
        self
    }

    /// Ask for this cover preset.
    pub fn cover(mut self, preset: impl Into<String>) -> Self {
        self.cover = Some(preset.into());
        self
    }

    /// Mark the session as the exit leg of a chain the application builds;
    /// see [`SessionRequest::exit_leg`].
    pub fn exit_leg(mut self) -> Self {
        self.exit_leg = true;
        self
    }

    /// Ping, report and renew on another schedule than the default.
    pub fn timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    /// `request`, asking for the node, country, cover and leg chosen here.
    fn shape(&self, mut request: SessionRequest) -> SessionRequest {
        if let Some(node) = self.node {
            request = request.node(node);
        }
        if let Some(country) = self.country {
            request = request.country(country);
        }
        if let Some(cover) = self.cover.clone() {
            request = request.cover(cover);
        }
        if self.exit_leg {
            request = request.exit_leg();
        }
        request
    }
}

impl<R: Rpc + 'static, S: Store + 'static> Singula<R, S> {
    /// A client over `chain`, proving with `prover`, remembering in `store`.
    pub fn new(chain: Chain<R>, prover: Prover, store: S) -> Self {
        Self {
            inner: Arc::new(Inner {
                chain,
                prover,
                store,
                pinned: Mutex::new(HashMap::new()),
                time: Mutex::new(Arc::new(SystemTime)),
                journal: tokio::sync::Mutex::new(JournalState::default()),
            }),
        }
    }

    /// Reaches `client`'s Control Plane through `client` rather than at the
    /// endpoint it published: a local Control Plane in development, or one
    /// reached through a proxy.
    #[must_use]
    pub fn with_control_plane(self, client: ControlPlaneClient) -> Self {
        self.inner
            .pinned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(client.star(), client);
        self
    }

    /// Reads the time from `source` instead of the system clock.
    #[must_use]
    pub fn with_time(self, source: impl TimeSource) -> Self {
        *self
            .inner
            .time
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(source);
        self
    }

    /// Now, by the time source.
    pub(super) fn now(&self) -> UnixTime {
        self.inner
            .time
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .now()
    }

    /// The chain.
    #[must_use]
    pub fn chain(&self) -> &Chain<R> {
        &self.inner.chain
    }

    /// A client for Control Plane `star`, at the endpoint it published.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoControlPlane`] if `star` publishes no
    /// endpoint or no longer holds the role.
    pub async fn control_plane(&self, star: StarId) -> Result<ControlPlaneClient, ClientError> {
        if let Some(pinned) = self.pinned(star) {
            return Ok(pinned);
        }
        let cp = self
            .inner
            .chain
            .control_plane(star)
            .await?
            .ok_or(ClientError::NoControlPlane)?;
        ControlPlaneClient::new(&cp)
    }

    /// The healthy Control Plane that answers fastest.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoControlPlane`] if none answers in time.
    pub async fn choose_control_plane(&self) -> Result<ControlPlaneClient, ClientError> {
        let mut probes = JoinSet::new();
        for cp in self.control_planes().await? {
            probes.spawn(async move {
                let answer = tokio::time::timeout(HEALTH_TIMEOUT, cp.health()).await;
                matches!(answer, Ok(Ok(h)) if h.healthy).then_some(cp)
            });
        }
        // The first healthy answer is the fastest one.
        while let Some(probe) = probes.join_next().await {
            if let Ok(Some(cp)) = probe {
                return Ok(cp);
            }
        }
        Err(ClientError::NoControlPlane)
    }

    /// Every Control Plane: those pinned to an address of the application's
    /// choosing, and every other the chain lists, in random order. The
    /// pinned ones are there even when the chain cannot be read.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Chain`] if the list cannot be read and none is
    /// pinned.
    pub(super) async fn control_planes(&self) -> Result<Vec<ControlPlaneClient>, ClientError> {
        let mut out: Vec<ControlPlaneClient> = self
            .inner
            .pinned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        match self.inner.chain.control_planes().await {
            Ok(listed) => {
                for cp in listed {
                    if !out.iter().any(|c| c.star() == cp.star) {
                        // An endpoint that does not form a URL is skipped, not fatal.
                        out.extend(ControlPlaneClient::new(&cp));
                    }
                }
            }
            Err(e) if out.is_empty() => return Err(e.into()),
            Err(_) => {}
        }
        shuffle(&mut out);
        Ok(out)
    }

    /// The wallet's anonymous identity: the one it derived before, or a new
    /// derivation, which asks the wallet to sign once and is then kept.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the wallet does not sign or the store fails.
    pub async fn identity<W: Wallet>(&self, wallet: &W) -> Result<Arc<Identity>, ClientError> {
        let records = Records(&self.inner.store);
        if let Some(identity) = records.identity(wallet.address()).await? {
            return Ok(Arc::new(identity));
        }
        let signature =
            sign_message_checked(wallet, PersonalMessage::Text(Identity::SIGNING_MESSAGE)).await?;
        // The text the wallet returns, as the JavaScript client passes it on.
        let identity = Identity::from_signature(&format!("0x{}", crate::hex::lower(&signature.0)));
        records.keep_identity(wallet.address(), &identity).await?;
        Ok(Arc::new(identity))
    }

    /// The wallet's identities in the subscriber set: one per slot of its
    /// Orbit, all derived from the one signature [`identity`](Self::identity)
    /// asks for.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotRegistered`] if none of them is in the set,
    /// and as [`identity`](Self::identity).
    pub async fn identities<W: Wallet>(&self, wallet: &W) -> Result<Identities, ClientError> {
        let base = self.identity(wallet).await?;
        let group = self.inner.chain.subscriber_group().await?;
        let mut registered = Vec::new();
        for slot in 0..MAX_SLOTS {
            let identity = if slot == 0 {
                Arc::clone(&base)
            } else {
                Arc::new(base.for_slot(slot))
            };
            if group.index_of(identity.commitment()).is_some() {
                registered.push((slot, identity));
            }
        }
        if registered.is_empty() {
            return Err(ClientError::NotRegistered);
        }
        Ok(registered.into())
    }

    /// The wallet's sign-in to `cp`: the one kept, or a fresh one.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the wallet does not sign or the store fails.
    pub async fn sign_in<W: Wallet>(
        &self,
        wallet: &W,
        cp: StarId,
    ) -> Result<WalletAuth, ClientError> {
        let records = Records(&self.inner.store);
        if let Some(auth) = records.sign_in(cp, wallet.address()).await? {
            return Ok(auth);
        }
        let auth = WalletAuth::sign(wallet, cp).await?;
        records.keep_sign_in(&auth).await?;
        Ok(auth)
    }

    /// Buys one subscription with `slots` concurrent sessions, 1 to 5, paid
    /// in `payment`: `slots` times the price.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if no Control Plane answers, the wallet does
    /// not sign, or the relay fails.
    pub async fn mint<W: Wallet>(
        &self,
        wallet: &W,
        payment: Payment,
        slots: u8,
    ) -> Result<Minted, ClientError> {
        let cp = self.choose_control_plane().await?;
        let auth = self.sign_in(wallet, cp.star()).await?;
        cp.mint(&self.inner.chain, wallet, &auth, payment, slots)
            .await
    }

    /// Adds `extra` slots to `token`, an Orbit the wallet holds, for the part
    /// of its term left, and joins the set with the new slots' identities if
    /// it is already activated; an Orbit not activated yet names them all at
    /// activation.
    ///
    /// # Errors
    ///
    /// As [`mint`](Self::mint), and [`ClientError::Mismatch`] if the wallet
    /// does not hold `token`.
    pub async fn add_slots<W: Wallet>(
        &self,
        wallet: &W,
        token: TokenId,
        extra: u8,
    ) -> Result<TxHash, ClientError> {
        let held = self
            .inner
            .chain
            .subscriptions(wallet.address())
            .await?
            .into_iter()
            .find(|s| s.token == token)
            .ok_or(ClientError::Mismatch(
                "this wallet does not hold that Orbit",
            ))?;
        let commitments = if held.starts_at.is_some() {
            let identity = self.identity(wallet).await?;
            (held.slots..held.slots.saturating_add(extra))
                .map(|slot| identity.for_slot(slot).commitment())
                .collect()
        } else {
            Vec::new()
        };
        let cp = self.choose_control_plane().await?;
        let auth = self.sign_in(wallet, cp.star()).await?;
        cp.add_slots(&self.inner.chain, wallet, &auth, token, extra, &commitments)
            .await
    }

    /// Mints `amount` of test USDC to the wallet, on a test network; see
    /// [`ControlPlaneClient::faucet`].
    ///
    /// # Errors
    ///
    /// As [`mint`](Self::mint), and the Control Plane refuses on a
    /// production network.
    pub async fn faucet<W: Wallet>(&self, wallet: &W, amount: u128) -> Result<TxHash, ClientError> {
        let cp = self.choose_control_plane().await?;
        let auth = self.sign_in(wallet, cp.star()).await?;
        cp.faucet(&self.inner.chain, wallet, &auth, amount).await
    }

    /// Takes part in governance as `who` — a proposal, a vote or a reply —
    /// without ETH; see [`ControlPlaneClient::governance`].
    ///
    /// # Errors
    ///
    /// As [`ControlPlaneClient::governance`].
    pub async fn governance<W: Wallet>(
        &self,
        wallet: &W,
        who: &Participant,
        action: &GovernanceAction,
    ) -> Result<TxHash, ClientError> {
        let cp = self.choose_control_plane().await?;
        cp.governance(&self.inner.chain, wallet, who, action).await
    }

    /// Activates `token` and joins the anonymity set with one of the wallet's
    /// identities per slot, in one transaction.
    ///
    /// # Errors
    ///
    /// As [`mint`](Self::mint).
    pub async fn activate<W: Wallet>(
        &self,
        wallet: &W,
        token: TokenId,
    ) -> Result<Activated, ClientError> {
        let identity = self.identity(wallet).await?;
        let slots = self.inner.chain.slots_of(token).await?;
        let commitments: Vec<_> = (0..slots)
            .map(|slot| match slot {
                0 => identity.commitment(),
                _ => identity.for_slot(slot).commitment(),
            })
            .collect();
        let cp = self.choose_control_plane().await?;
        let auth = self.sign_in(wallet, cp.star()).await?;
        cp.activate(&self.inner.chain, wallet, &auth, token, &commitments)
            .await
    }

    /// Opens a session and keeps it until the returned [`Connection`] is
    /// closed: by pings on the day's right, with the traffic `meter` counts,
    /// or — for a wallet's session — by reports and renewals.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotRegistered`] if anonymous access is asked
    /// for and none of the wallet's slots is a member for the whole day,
    /// [`ClientError::NodeAnswer`] if the node's answer does not check out,
    /// and any error of the steps along the way.
    pub async fn connect<W: Wallet, M: TrafficMeter>(
        &self,
        wallet: &W,
        options: ConnectOptions,
        meter: M,
    ) -> Result<Connection, ClientError> {
        let cp = match options.control_plane {
            Some(star) => self.control_plane(star).await?,
            None => self.choose_control_plane().await?,
        };
        match options.access {
            Access::Wallet => self.connect_wallet(wallet, cp, &options, meter).await,
            Access::Anonymous => self.connect_on_right(wallet, cp, &options, meter).await,
        }
    }

    /// A wallet's session, kept by reports and renewals.
    async fn connect_wallet<W: Wallet, M: TrafficMeter>(
        &self,
        wallet: &W,
        cp: ControlPlaneClient,
        options: &ConnectOptions,
        meter: M,
    ) -> Result<Connection, ClientError> {
        let auth = self.sign_in(wallet, cp.star()).await?;
        let request = options.shape(SessionRequest::wallet(auth.clone()));
        let session = cp
            .open(&self.inner.chain, request)
            .await
            .map_err(not_opened)?;
        let tunnel = TunnelSettings::decode(session.credentials())?;
        let reporter = if session.report_to() == cp.star() {
            cp.clone()
        } else {
            self.control_plane(session.report_to()).await?
        };
        let opened = Opened {
            session,
            tunnel,
            admitting: cp,
            reporter,
            auth,
        };
        Ok(Keeper::start(self.clone(), opened, meter, options.timing))
    }

    /// A session on the day's right of one of the wallet's slots, kept by
    /// pings. Slots another device was found on today are tried last.
    async fn connect_on_right<W: Wallet, M: TrafficMeter>(
        &self,
        wallet: &W,
        cp: ControlPlaneClient,
        options: &ConnectOptions,
        meter: M,
    ) -> Result<Connection, ClientError> {
        let identities = self.identities(wallet).await?;
        let window = self
            .window_at(self.now(), Duration::ZERO)
            .ok_or(ClientError::Mismatch("the protocol has not started"))?;
        for (slot, identity) in self.slot_order(&identities, window).await.iter() {
            let day = match self.day_right(identity, *slot, window).await {
                Ok(day) => day,
                // Its Orbit ends during the day: another slot may not.
                Err(ClientError::NotRegistered) => continue,
                Err(e) => return Err(e),
            };
            let params = self.inner.chain.journal_params();
            let request = SessionRequest::on_right(day.right.clone(), Arc::clone(&day.key), params);
            let session = cp
                .open(&self.inner.chain, options.shape(request))
                .await
                .map_err(not_opened)?;
            let tunnel = TunnelSettings::decode(session.credentials())?;
            let opened = OnRight {
                session,
                tunnel,
                admitting: cp,
                identity: Arc::clone(identity),
                slot: *slot,
                window,
                day,
            };
            return Ok(pinger::start(self.clone(), opened, meter, options.timing));
        }
        Err(ClientError::NotRegistered)
    }

    fn pinned(&self, star: StarId) -> Option<ControlPlaneClient> {
        self.inner
            .pinned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&star)
            .cloned()
    }
}

impl<R, S> std::fmt::Debug for Singula<R, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Singula").finish_non_exhaustive()
    }
}

/// The error a failed open stands for: the node's answer refused, when the
/// Control Plane admitted the session and the node's answer did not check
/// out.
fn not_opened(failed: NotOpened) -> ClientError {
    match failed.node {
        Some(node) if failed.admitted => ClientError::NodeAnswer {
            node,
            error: Box::new(failed.error),
        },
        _ => failed.error,
    }
}

/// Puts `items` in a uniformly random order (Fisher–Yates).
fn shuffle<T>(items: &mut [T]) {
    use rand_core::{OsRng, RngCore as _};
    for i in (1..items.len()).rev() {
        let j = usize::try_from(OsRng.next_u64() % (i as u64 + 1)).unwrap_or(0);
        items.swap(i, j);
    }
}
