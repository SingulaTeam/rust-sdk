//! A session kept alive: reported on and renewed in the background.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use super::connect::{Identities, Singula};
use super::ledger::Lease;
use super::session::{Session, Traffic};
use super::store::Store;
use super::{ClientError, ControlPlaneClient, TunnelSettings, WalletAuth};
use crate::chain::Rpc;
use crate::id::{SessionId, StarId, UnixTime};

/// How many events wait for the application before the oldest are dropped.
const EVENT_BUFFER: usize = 32;

/// How often a connection reports and when it renews.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Timing {
    /// Between traffic reports. Reports are what the node is paid for, and
    /// what keeps the session's nonce fresh.
    pub report_every: Duration,
    /// How long before expiry renewal starts.
    pub renew_ahead: Duration,
    /// Between renewal attempts once one has failed.
    pub renew_retry: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            report_every: Duration::from_secs(30),
            renew_ahead: Duration::from_secs(10 * 60),
            renew_retry: Duration::from_secs(60),
        }
    }
}

/// The traffic a session has carried, as the tunnel engine counts it.
///
/// The SDK carries no traffic, so it cannot count any: the application
/// reads the engine's counters for this session's tunnel.
pub trait TrafficMeter: Send + Sync + 'static {
    /// Bytes sent and received since the tunnel came up. Cumulative: never
    /// smaller than an earlier reading.
    fn traffic(&self) -> Traffic;
}

impl<F: Fn() -> Traffic + Send + Sync + 'static> TrafficMeter for F {
    fn traffic(&self) -> Traffic {
        self()
    }
}

/// Something that happened to a connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// A report was accepted.
    Reported(Traffic),
    /// A report failed; the next one will try again.
    ReportFailed {
        /// What went wrong.
        error: ClientError,
        /// Failures in a row so far.
        in_a_row: u32,
    },
    /// The session was extended.
    Renewed {
        /// Its new expiry.
        expires_at: UnixTime,
    },
    /// A renewal failed; it will be retried until the session expires.
    RenewalFailed(ClientError),
    /// The session is over. Nothing more happens on this connection; open a
    /// new one to carry on.
    Ended(EndReason),
}

/// Why a connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndReason {
    /// The application closed it.
    Closed,
    /// It expired without being renewed.
    Expired,
}

/// An open session, kept alive in the background.
///
/// Dropping it stops the background task, as [`close`](Self::close) does,
/// without waiting for it.
#[derive(Debug)]
pub struct Connection {
    id: SessionId,
    node: StarId,
    control_plane: StarId,
    tunnel: TunnelSettings,
    events: mpsc::Receiver<Event>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Connection {
    /// The session's id.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The node serving it.
    #[must_use]
    pub fn node(&self) -> StarId {
        self.node
    }

    /// The Control Plane that admitted it.
    #[must_use]
    pub fn control_plane(&self) -> StarId {
        self.control_plane
    }

    /// The tunnel settings, for the engine.
    #[must_use]
    pub fn tunnel(&self) -> &TunnelSettings {
        &self.tunnel
    }

    /// The next event, or `None` once the connection has ended and every
    /// event has been read.
    pub async fn next_event(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// Ends the session: a wallet's session is ended at the Control Plane, an
    /// anonymous one is no longer renewed. Either way its permission is
    /// returned.
    pub async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// What the background task holds.
pub(super) struct Keeper<R, S, M> {
    singula: Singula<R, S>,
    session: Session,
    admitting: ControlPlaneClient,
    reporter: ControlPlaneClient,
    auth: Option<WalletAuth>,
    /// The permission the session holds, and the identity to take the next
    /// window's with.
    held: Option<(Lease, Identities)>,
    meter: M,
    timing: Timing,
    events: mpsc::Sender<Event>,
}

/// A session just opened, and what keeping it needs.
pub(super) struct Opened {
    pub(super) session: Session,
    pub(super) tunnel: TunnelSettings,
    pub(super) admitting: ControlPlaneClient,
    pub(super) reporter: ControlPlaneClient,
    pub(super) auth: Option<WalletAuth>,
    pub(super) held: Option<(Lease, Identities)>,
}

impl<R: Rpc + 'static, S: Store + 'static, M: TrafficMeter> Keeper<R, S, M> {
    /// Starts keeping `opened` and returns its connection.
    pub(super) fn start(
        singula: Singula<R, S>,
        opened: Opened,
        meter: M,
        timing: Timing,
    ) -> Connection {
        let (events, receiver) = mpsc::channel(EVENT_BUFFER);
        let (stop, stopped) = oneshot::channel();
        let connection_parts = (
            opened.session.id().clone(),
            opened.session.node(),
            opened.admitting.star(),
        );
        let keeper = Self {
            singula,
            session: opened.session,
            admitting: opened.admitting,
            reporter: opened.reporter,
            auth: opened.auth,
            held: opened.held,
            meter,
            timing,
            events,
        };
        let task = tokio::spawn(keeper.run(stopped));
        Connection {
            id: connection_parts.0,
            node: connection_parts.1,
            control_plane: connection_parts.2,
            tunnel: opened.tunnel,
            events: receiver,
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn run(mut self, mut stopped: oneshot::Receiver<()>) {
        let mut reports = tokio::time::interval_at(
            Instant::now() + self.timing.report_every,
            self.timing.report_every,
        );
        // A sleeping laptop wakes to one report, not a burst of them.
        reports.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut renew_at = self.renewal_due();
        let mut failed_reports = 0;

        let reason = loop {
            tokio::select! {
                _ = &mut stopped => break EndReason::Closed,
                _ = reports.tick() => {
                    let traffic = self.meter.traffic();
                    match self.reporter.report(&mut self.session, traffic).await {
                        Ok(()) => {
                            failed_reports = 0;
                            self.keep_permission().await;
                            self.emit(Event::Reported(traffic));
                        }
                        Err(error) => {
                            failed_reports += 1;
                            self.emit(Event::ReportFailed { error, in_a_row: failed_reports });
                        }
                    }
                }
                () = tokio::time::sleep_until(renew_at) => {
                    if self.singula.now() >= self.session.expires_at() {
                        break EndReason::Expired;
                    }
                    match self.renew().await {
                        Ok(()) => {
                            self.emit(Event::Renewed { expires_at: self.session.expires_at() });
                            renew_at = self.renewal_due();
                        }
                        Err(e) => {
                            self.emit(Event::RenewalFailed(e));
                            renew_at = Instant::now() + self.timing.renew_retry;
                        }
                    }
                }
            }
        };
        self.finish(reason).await;
    }

    /// Records that the session's permission is still held, so it does not
    /// lapse in the ledger while the session runs.
    async fn keep_permission(&self) {
        if let Some((lease, _)) = &self.held {
            // Best effort: a missed write only lets the hold lapse earlier,
            // and the next report writes again.
            let _ = self
                .singula
                .ledger()
                .keep(lease, self.session.id(), self.singula.kept_until())
                .await;
        }
    }

    /// When renewal should start: `renew_ahead` before expiry.
    fn renewal_due(&self) -> Instant {
        let left = u64::try_from(self.session.expires_at().0 - self.singula.now().0).unwrap_or(0);
        let wait = Duration::from_secs(left).saturating_sub(self.timing.renew_ahead);
        Instant::now() + wait
    }

    /// Renews the session; into a new window, with a permission of that
    /// window's packet.
    async fn renew(&mut self) -> Result<(), ClientError> {
        let Some((lease, identities)) = &self.held else {
            return self.admitting.renew(&mut self.session, None).await;
        };
        let window = self.singula.current_epoch()?;
        if window == lease.window {
            return self.admitting.renew(&mut self.session, None).await;
        }
        let identities = Arc::clone(identities);
        let next = self
            .singula
            .lease(&self.admitting, &identities, window)
            .await?;
        let ledger = self.singula.ledger();
        match self
            .admitting
            .renew(&mut self.session, Some(&next.permission))
            .await
        {
            Ok(()) => {
                ledger
                    .bind(&next, self.session.id(), self.singula.kept_until())
                    .await?;
                if let Some((old, _)) = self.held.replace((next, identities)) {
                    ledger.release(&old).await?;
                }
                Ok(())
            }
            Err(e) => {
                // The renewal may have been admitted before it failed.
                ledger.release_at(&next, self.singula.held_until()).await?;
                Err(e)
            }
        }
    }

    async fn finish(self, reason: EndReason) {
        let held_until = self.singula.held_until();
        let ledger = self.singula.ledger();
        if let Some((lease, _)) = &self.held {
            // Best effort: a release that fails leaves the permission marked
            // held until the window turns, which costs concurrency, not access.
            let _ = ledger.release_at(lease, held_until).await;
        }
        if reason == EndReason::Closed {
            let traffic = self.meter.traffic();
            // Ended rather than left to expire, so its permission is free
            // again within a lease, not hours.
            let _ = match &self.auth {
                Some(auth) => {
                    self.admitting
                        .end_session(auth, self.session, traffic)
                        .await
                }
                None => {
                    self.admitting
                        .end_anonymous_session(self.session, traffic)
                        .await
                }
            };
        }
        let _ = self.events.try_send(Event::Ended(reason));
    }

    /// Sends `event` unless the application has stopped reading: a full
    /// buffer drops the event rather than stalling the session.
    fn emit(&self, event: Event) {
        let _ = self.events.try_send(event);
    }
}
