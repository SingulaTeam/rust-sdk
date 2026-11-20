//! A session kept alive: reported on and renewed in the background.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use super::connect::Singula;
use super::session::{Session, Traffic};
use super::store::Store;
use super::{ClientError, ControlPlaneClient, TunnelSettings, WalletAuth};
use crate::chain::Rpc;
use crate::id::{SessionId, StarId, UnixTime};
use crate::journal::{CloseReason, Committed};

/// How many events wait for the application before the oldest are dropped.
pub(super) const EVENT_BUFFER: usize = 32;

/// How often a connection pings, reports and renews.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Timing {
    /// Between pings of a session on a right. Pings are what the node is paid
    /// for: the seconds after the last one are not counted. Control Planes
    /// close a session no ping was recorded for in ten minutes.
    pub ping_every: Duration,
    /// Between traffic reports of a wallet's session. Reports are what keeps
    /// the session's nonce fresh.
    pub report_every: Duration,
    /// How long before expiry renewal starts.
    pub renew_ahead: Duration,
    /// Between renewal attempts once one has failed.
    pub renew_retry: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            ping_every: Duration::from_secs(5 * 60),
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
    /// A ping reached the journal: a strict majority of the Control Planes
    /// recorded it, as checked against the chain.
    Pinged {
        /// The seconds it counted.
        total: u64,
        /// When the majority recorded it, and which registry version they
        /// belong to.
        committed: Committed,
        /// The Control Plane it went through.
        control_plane: StarId,
    },
    /// A ping reached no majority through any Control Plane; the next one
    /// will try again.
    PingFailed {
        /// What went wrong at the last Control Plane tried.
        error: ClientError,
        /// Failures in a row so far.
        in_a_row: u32,
    },
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndReason {
    /// The application closed it.
    Closed,
    /// It expired without being renewed.
    Expired,
    /// The network closed it, for this reason. Show it, and reconnect: a
    /// new session, on another of the subscription's slots when the reason
    /// is [`CloseReason::Overlap`].
    ClosedByNetwork(CloseReason),
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
    /// A connection over a background `task` that sends `events` and stops
    /// when `stop` fires.
    pub(super) fn new(
        parts: Parts,
        tunnel: TunnelSettings,
        events: mpsc::Receiver<Event>,
        stop: oneshot::Sender<()>,
        task: JoinHandle<()>,
    ) -> Self {
        Self {
            id: parts.id,
            node: parts.node,
            control_plane: parts.control_plane,
            tunnel,
            events,
            stop: Some(stop),
            task: Some(task),
        }
    }

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

    /// Ends the session at the Control Plane, after a last ping or report
    /// so its final seconds count.
    pub async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// What a [`Connection`] says about its session, taken before the session
/// moves into its background task.
pub(super) struct Parts {
    id: SessionId,
    node: StarId,
    control_plane: StarId,
}

impl Parts {
    pub(super) fn of(session: &Session) -> Self {
        Self {
            id: session.id().clone(),
            node: session.node(),
            control_plane: session.admitted_by(),
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

/// What the background task of a wallet's session holds.
pub(super) struct Keeper<R, S, M> {
    singula: Singula<R, S>,
    session: Session,
    admitting: ControlPlaneClient,
    reporter: ControlPlaneClient,
    auth: WalletAuth,
    meter: M,
    timing: Timing,
    events: mpsc::Sender<Event>,
}

/// A wallet's session just opened, and what keeping it needs.
pub(super) struct Opened {
    pub(super) session: Session,
    pub(super) tunnel: TunnelSettings,
    pub(super) admitting: ControlPlaneClient,
    pub(super) reporter: ControlPlaneClient,
    pub(super) auth: WalletAuth,
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
        let parts = Parts::of(&opened.session);
        let keeper = Self {
            singula,
            session: opened.session,
            admitting: opened.admitting,
            reporter: opened.reporter,
            auth: opened.auth,
            meter,
            timing,
            events,
        };
        let task = tokio::spawn(keeper.run(stopped));
        Connection::new(parts, opened.tunnel, receiver, stop, task)
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
                    match self.admitting.renew(&mut self.session).await {
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

    /// When renewal should start: `renew_ahead` before expiry.
    fn renewal_due(&self) -> Instant {
        let left = u64::try_from(self.session.expires_at().0 - self.singula.now().0).unwrap_or(0);
        let wait = Duration::from_secs(left).saturating_sub(self.timing.renew_ahead);
        Instant::now() + wait
    }

    async fn finish(self, reason: EndReason) {
        if reason == EndReason::Closed {
            // Ended rather than left to expire, with its final traffic.
            let traffic = self.meter.traffic();
            let _ = self
                .admitting
                .end_session(&self.auth, self.session, traffic)
                .await;
        }
        let _ = self.events.try_send(Event::Ended(reason));
    }

    /// Sends `event` unless the application has stopped reading: a full
    /// buffer drops the event rather than stalling the session.
    fn emit(&self, event: Event) {
        let _ = self.events.try_send(event);
    }
}
