//! The whole client, in a few calls.
//!
//! [`Singula`] holds what every call needs — the chain, the prover, the
//! store — and runs the protocol's steps in the order they must happen:
//! identity before proof, packet before permission, a hold written down
//! before it is used. [`Singula::connect`] ends with a running
//! [`Connection`]: tunnel settings to hand to the engine, and a task that
//! reports traffic and renews the session until it is closed.
//!
//! Everything here is built from the calls in [`ControlPlaneClient`] and
//! [`Chain`]; use those directly where this does not fit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::task::JoinSet;

use super::connection::{Connection, Keeper, Opened, Timing, TrafficMeter};
use super::governance::{GovernanceAction, Participant};
use super::ledger::{Lease, Ledger, SLOT_STRIDE};
use super::proto::client::ErrorCode;
use super::relay::{Activated, MAX_SLOTS, Minted};
use super::session::SessionRequest;
use super::store::Store;
use super::time::{SystemTime, TimeSource};
use super::wallet::{PersonalMessage, Wallet, sign_message_checked};
use super::{ClientError, ControlPlaneClient, Country, TunnelSettings, WalletAuth};
use crate::chain::{Chain, Payment, Rpc, TokenId, TxHash};
use crate::id::{Epoch, StarId, UnixTime};
use crate::zk::{AccessProof, Claim, Identity, Prover};

/// How long a Control Plane has to answer when one is being chosen.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long Control Planes keep a permission after its session ends: one
/// lease (a minute) past the last renewal heard, with room for the
/// federation's gossip to arrive late.
const HELD_AFTER_END: Duration = Duration::from_secs(90);

/// How long Control Planes keep a session nobody reports on: five minutes
/// without a checkpoint, up to two more until the next sweep, and the lease
/// after that. A client that died holding a permission takes it back then.
const KEPT_WITHOUT_REPORTS: Duration = Duration::from_secs(8 * 60);

/// How many of a client's permissions may be waiting out a Control Plane's
/// hold before it waits too, rather than take another index.
///
/// One: a session that failed is usually retried at once, on another node,
/// and waiting out the hold on its permission would stall that by a minute
/// and a half. A second failure in a row waits, so a client spends at most
/// its running sessions and two more of the subscription's indices.
const COOLING_BEFORE_WAIT: usize = 2;

/// How many quota slots in a row may turn out used by the subscription's
/// other devices before a connect gives up: the most a Control Plane allows.
const MAX_CLAIMS_USED: u32 = 50;

/// A subscriber's identities in the set, one per registered slot, each with
/// its slot number. Never empty.
pub(super) type Identities = Arc<[(u8, Arc<Identity>)]>;

/// The SDK's whole client: chain, prover and store, shared by every call.
///
/// Cheap to clone; clones share everything.
pub struct Singula<R, S> {
    inner: Arc<Inner<R, S>>,
}

pub(super) struct Inner<R, S> {
    pub(super) chain: Chain<R>,
    pub(super) prover: Prover,
    pub(super) store: S,
    /// Control Planes reached at an address of the application's choosing
    /// rather than the one they published.
    pinned: Mutex<HashMap<StarId, ControlPlaneClient>>,
    time: Mutex<Arc<dyn TimeSource>>,
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
    /// By a membership proof and a permission. The Control Plane learns that
    /// some subscriber connected, and nothing else.
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

    /// Report and renew on another schedule than the default.
    pub fn timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
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
        let mut candidates: Vec<ControlPlaneClient> = self
            .inner
            .pinned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        for cp in self.inner.chain.control_planes().await? {
            if !candidates.iter().any(|c| c.star() == cp.star) {
                // An endpoint that does not form a URL is skipped, not fatal.
                candidates.extend(ControlPlaneClient::new(&cp));
            }
        }
        let mut probes = JoinSet::new();
        for cp in candidates {
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

    /// The wallet's anonymous identity: the one it derived before, or a new
    /// derivation, which asks the wallet to sign once and is then kept.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the wallet does not sign or the store fails.
    pub async fn identity<W: Wallet>(&self, wallet: &W) -> Result<Arc<Identity>, ClientError> {
        let ledger = Ledger(&self.inner.store);
        if let Some(identity) = ledger.identity(wallet.address()).await? {
            return Ok(Arc::new(identity));
        }
        let signature =
            sign_message_checked(wallet, PersonalMessage::Text(Identity::SIGNING_MESSAGE)).await?;
        // The text the wallet returns, as the JavaScript client passes it on.
        let identity = Identity::from_signature(&format!("0x{}", crate::hex::lower(&signature.0)));
        ledger.keep_identity(wallet.address(), &identity).await?;
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
        let ledger = Ledger(&self.inner.store);
        if let Some(auth) = ledger.sign_in(cp, wallet.address()).await? {
            return Ok(auth);
        }
        let auth = WalletAuth::sign(wallet, cp).await?;
        ledger.keep_sign_in(&auth).await?;
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

    /// Opens a session and keeps it: reports its traffic, as `meter` counts
    /// it, and renews it, until the returned [`Connection`] is closed.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotRegistered`] if anonymous access is asked
    /// for by an identity not in the set, [`ClientError::NoPermissionFree`]
    /// if every permission of the window is held, [`ClientError::NodeAnswer`]
    /// if the node's answer does not check out, and any error of the steps
    /// along the way. A permission leased for a session that did not open is
    /// given back, unless the Control Plane took it first.
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
        let ledger = Ledger(&self.inner.store);
        let mut claims_used = 0;
        let (session, held) = loop {
            let (admission, held) = match options.access {
                Access::Wallet => (
                    SessionRequest::wallet(self.sign_in(wallet, cp.star()).await?),
                    None,
                ),
                Access::Anonymous => {
                    let identities = self.identities(wallet).await?;
                    let (proof, lease) = self.admit(&cp, &identities).await?;
                    (
                        SessionRequest::anonymous(proof, lease.permission.clone()),
                        Some((lease, identities)),
                    )
                }
            };
            let mut request = admission;
            if let Some(node) = options.node {
                request = request.node(node);
            }
            if let Some(country) = options.country {
                request = request.country(country);
            }
            if let Some(cover) = options.cover.clone() {
                request = request.cover(cover);
            }
            if options.exit_leg {
                request = request.exit_leg();
            }

            let failed = match cp.open(&self.inner.chain, request).await {
                Ok(session) => break (session, held),
                Err(failed) => failed,
            };
            if let Some((lease, _)) = &held {
                if claim_used(&failed.error) && claims_used < MAX_CLAIMS_USED {
                    // Another of the subscription's devices used this quota
                    // slot at this Control Plane; it counts its own. The
                    // permission was not spent — the proof is checked first —
                    // and the next slot is proved with it.
                    claims_used += 1;
                    ledger.release(lease).await?;
                    continue;
                }
                if failed.admitted || spent(&failed.error) {
                    // The Control Plane took the permission — for a
                    // session this client refused and has ended, or one
                    // it still holds — and frees it within a lease.
                    ledger.release_at(lease, self.held_until()).await?;
                } else {
                    ledger.release(lease).await?;
                }
            }
            return Err(match failed.node {
                Some(node) if failed.admitted => ClientError::NodeAnswer {
                    node,
                    error: Box::new(failed.error),
                },
                _ => failed.error,
            });
        };
        if let Some((lease, _)) = &held {
            ledger.bind(lease, session.id(), self.kept_until()).await?;
        }
        let tunnel = TunnelSettings::decode(session.credentials())?;
        let reporter = if session.report_to() == cp.star() {
            cp.clone()
        } else {
            self.control_plane(session.report_to()).await?
        };
        let auth = match options.access {
            Access::Wallet => Some(self.sign_in(wallet, cp.star()).await?),
            Access::Anonymous => None,
        };
        let opened = Opened {
            session,
            tunnel,
            admitting: cp,
            reporter,
            auth,
            held,
        };
        Ok(Keeper::start(self.clone(), opened, meter, options.timing))
    }

    /// A session proof and a permission for one session at `cp`: one held,
    /// or one taken now.
    ///
    /// The proof is made by the identity whose permission it is, when that
    /// one is still in the set; a permission is not tied to an identity, so
    /// one held from an Orbit since replaced is proved for by any of them.
    async fn admit(
        &self,
        cp: &ControlPlaneClient,
        identities: &Identities,
    ) -> Result<(AccessProof, Lease), ClientError> {
        let epoch = self.current_epoch()?;
        let lease = self.lease(cp, identities, epoch).await?;
        let identity = identities
            .iter()
            .find(|(slot, _)| *slot == lease.slot)
            .unwrap_or(&identities[0])
            .1
            .clone();
        let slot = Ledger(&self.inner.store).take_slot(cp.star(), epoch).await;
        let slot = match slot {
            Ok(slot) => slot,
            Err(e) => {
                Ledger(&self.inner.store).release(&lease).await?;
                return Err(e.into());
            }
        };
        let claim = Claim::Session {
            control_plane: cp.star(),
            epoch,
            index: slot,
        };
        match self.prove(&identity, claim).await {
            Ok(proof) => Ok((proof, lease)),
            Err(e) => {
                Ledger(&self.inner.store).release(&lease).await?;
                Err(e)
            }
        }
    }

    /// A free permission of `window`: one this client holds, or one taken
    /// now from `cp` by one of `identities`, under an index nobody has taken
    /// yet. Each identity has its own indices, one per permission the issuer
    /// grants it a window.
    ///
    /// A new index is taken only while few permissions held here are waiting
    /// out a hold (see [`COOLING_BEFORE_WAIT`]). One whose session ended
    /// frees again within a minute and a half, and waiting for it keeps the
    /// subscription's other indices for its other devices: taking a new one
    /// on every reconnect would spend them all on one.
    pub(super) async fn lease(
        &self,
        cp: &ControlPlaneClient,
        identities: &Identities,
        window: Epoch,
    ) -> Result<Lease, ClientError> {
        let ledger = Ledger(&self.inner.store);
        if let Some(lease) = ledger.lease(window, self.now(), self.kept_until()).await? {
            return Ok(lease);
        }
        let cooling = ledger.cooling(window, self.now()).await?;
        let wait = || {
            cooling.first().map_or(ClientError::NoPermissionFree, |at| {
                ClientError::PermissionFreeAt(UnixTime(*at))
            })
        };
        if cooling.len() >= COOLING_BEFORE_WAIT {
            return Err(wait());
        }
        let key = cp.issuer_key(&self.inner.chain).await?;
        if key.window() != window {
            return Err(ClientError::Mismatch(
                "the issuer signs for another window than the current one",
            ));
        }
        // In random order, so devices starting at once rarely race for the
        // same index and spend a proof on a refusal.
        let candidates: Vec<u32> = identities
            .iter()
            .flat_map(|(slot, _)| {
                (0..key.packet_size()).map(move |index| u32::from(*slot) * SLOT_STRIDE + index)
            })
            .collect();
        let mut untried = ledger.untried(window, &candidates).await?;
        shuffle(&mut untried);
        for held in untried {
            let (slot, index) = (held / SLOT_STRIDE, held % SLOT_STRIDE);
            let Some((_, identity)) = identities.iter().find(|(s, _)| u32::from(*s) == slot) else {
                continue;
            };
            let proof = self
                .prove(identity, Claim::Permission { window, index })
                .await?;
            match cp.take_permission(&key, index, &proof).await {
                Ok(permission) => {
                    ledger.add(held, &permission).await?;
                    return ledger
                        .lease(window, self.now(), self.kept_until())
                        .await?
                        .ok_or(ClientError::NoPermissionFree);
                }
                Err(ClientError::PermissionTaken(_)) => {
                    ledger.taken_elsewhere(window, held).await?;
                }
                Err(e) => return Err(e),
            }
        }
        Err(wait())
    }

    /// Proves membership for `claim` on the blocking pool, against the set
    /// as the chain holds it now.
    pub(super) async fn prove(
        &self,
        identity: &Arc<Identity>,
        claim: Claim,
    ) -> Result<AccessProof, ClientError> {
        let group = self.inner.chain.subscriber_group().await?;
        if group.index_of(identity.commitment()).is_none() {
            return Err(ClientError::NotRegistered);
        }
        let this = self.clone();
        let identity = Arc::clone(identity);
        tokio::task::spawn_blocking(move || this.inner.prover.prove(&identity, &group, claim))
            .await
            .map_err(|_| ClientError::Malformed("the prover stopped"))?
            .map_err(ClientError::from)
    }

    pub(super) fn current_epoch(&self) -> Result<Epoch, ClientError> {
        self.inner
            .chain
            .deployment()
            .clock
            .epoch_at(self.now())
            .ok_or(ClientError::Mismatch("the protocol has not started"))
    }

    /// How long a permission stays held by a session that is never reported
    /// on again: until its Control Plane has swept the silent session.
    pub(super) fn kept_until(&self) -> UnixTime {
        UnixTime(self.now().0 + i64::try_from(KEPT_WITHOUT_REPORTS.as_secs()).unwrap_or(i64::MAX))
    }

    /// When a permission whose session ends now is free again everywhere.
    pub(super) fn held_until(&self) -> UnixTime {
        UnixTime(self.now().0 + i64::try_from(HELD_AFTER_END.as_secs()).unwrap_or(i64::MAX))
    }

    pub(super) fn ledger(&self) -> Ledger<'_, S> {
        Ledger(&self.inner.store)
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

/// Whether a Control Plane refused a session proof's quota slot as used.
fn claim_used(e: &ClientError) -> bool {
    matches!(e, ClientError::Refused { code, .. } if *code == ErrorCode::AccessClaimUsed as i32)
}

/// Whether a Control Plane refused a permission as held already.
fn spent(e: &ClientError) -> bool {
    matches!(e, ClientError::Refused { code, .. } if *code == ErrorCode::PermissionSpent as i32)
}

/// Puts `items` in a uniformly random order (Fisher–Yates).
fn shuffle(items: &mut [u32]) {
    use rand_core::{OsRng, RngCore as _};
    for i in (1..items.len()).rev() {
        let j = usize::try_from(OsRng.next_u64() % (i as u64 + 1)).unwrap_or(0);
        items.swap(i, j);
    }
}
