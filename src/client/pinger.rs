//! A session on a right, kept alive by pings in the background.
//!
//! Every [`Timing::ping_every`] the session's seconds so far are signed with
//! the day's right key and sent to a Control Plane. Its answer counts only
//! once its attestations check out against the chain: a strict majority of
//! one registry version. When a Control Plane cannot show that, the same
//! ping goes to the others, and the first that can carries the session from
//! then on — the tunnel never notices.
//!
//! Past midnight the session carries on under the new day's right, which
//! travels with its first ping; its seconds count from zero again.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, MissedTickBehavior};

use super::connect::Singula;
use super::connection::{Connection, EVENT_BUFFER, EndReason, Event, Parts, Timing, TrafficMeter};
use super::rights::DayRight;
use super::session::Session;
use super::store::Store;
use super::{ClientError, ControlPlaneClient, TunnelSettings};
use crate::chain::Rpc;
use crate::id::{Epoch, StarId};
use crate::journal::{AckError, CloseReason, Committed, Ping, SessionStatus, SignedPing};
use crate::zk::Identity;

/// How long after midnight, by this machine's clock, the new day's right
/// takes over. The Control Planes' clocks may lag this one; a ping under a
/// day that has not begun for them is refused. One minute is the journal's
/// tolerance for clocks.
const NEW_DAY_AFTER: Duration = Duration::from_secs(60);

/// A session opened on a right, and what keeping it needs.
pub(super) struct OnRight {
    pub(super) session: Session,
    pub(super) tunnel: TunnelSettings,
    pub(super) admitting: ControlPlaneClient,
    pub(super) identity: Arc<Identity>,
    pub(super) slot: u8,
    pub(super) window: Epoch,
    pub(super) day: DayRight,
}

/// What the background task holds.
struct Pinger<R, S, M> {
    singula: Singula<R, S>,
    session: Session,
    admitting: ControlPlaneClient,
    /// The Control Plane pings go to, until one fails to show a majority.
    current: ControlPlaneClient,
    identity: Arc<Identity>,
    slot: u8,
    window: Epoch,
    day: DayRight,
    /// When the day's seconds began: the session's opening, or midnight.
    counting_from: Instant,
    /// Whether the day's right still has to travel with a ping.
    right_to_send: bool,
    meter: M,
    events: mpsc::Sender<Event>,
}

/// Starts keeping `opened` and returns its connection.
pub(super) fn start<R: Rpc + 'static, S: Store + 'static, M: TrafficMeter>(
    singula: Singula<R, S>,
    opened: OnRight,
    meter: M,
    timing: Timing,
) -> Connection {
    let (events, receiver) = mpsc::channel(EVENT_BUFFER);
    let (stop, stopped) = oneshot::channel();
    let OnRight {
        session,
        tunnel,
        admitting,
        identity,
        slot,
        window,
        day,
    } = opened;
    let parts = Parts::of(&session);
    let pinger = Pinger {
        singula,
        current: admitting.clone(),
        admitting,
        session,
        identity,
        slot,
        window,
        day,
        counting_from: Instant::now(),
        right_to_send: false,
        meter,
        events,
    };
    let task = tokio::spawn(pinger.run(stopped, timing));
    Connection::new(parts, tunnel, receiver, stop, task)
}

impl<R: Rpc + 'static, S: Store + 'static, M: TrafficMeter> Pinger<R, S, M> {
    async fn run(mut self, mut stopped: oneshot::Receiver<()>, timing: Timing) {
        // The first ping at once: it dates the session's start, and shows
        // early whether the federation records it.
        let mut pings = tokio::time::interval(timing.ping_every);
        // A sleeping laptop wakes to one ping, not a burst of them.
        pings.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut failed = 0;
        let reason = loop {
            tokio::select! {
                _ = &mut stopped => break EndReason::Closed,
                _ = pings.tick() => {
                    if let Some(reason) = self.tick(&mut failed).await {
                        break reason;
                    }
                }
            }
        };
        self.finish(reason).await;
    }

    /// One round: carry the session into a new day if one began, ping, and
    /// learn whether the network has closed it.
    async fn tick(&mut self, failed: &mut u32) -> Option<EndReason> {
        if let Err(error) = self.roll_over().await {
            // The old right still carries the session until the day ends;
            // the next round tries again.
            self.emit(Event::PingFailed {
                error,
                in_a_row: *failed,
            });
        }
        let total = self.counting_from.elapsed().as_secs();
        match self.ping(total).await {
            Ok((committed, control_plane)) => {
                *failed = 0;
                self.emit(Event::Pinged {
                    total,
                    committed,
                    control_plane,
                });
            }
            Err(error) => {
                *failed += 1;
                self.emit(Event::PingFailed {
                    error,
                    in_a_row: *failed,
                });
            }
        }
        match self.current.session_status(self.session.id()).await {
            Ok(SessionStatus::Closed(reason)) => Some(EndReason::ClosedByNetwork(reason)),
            _ => None,
        }
    }

    /// Takes the new day's right once the day has begun everywhere.
    async fn roll_over(&mut self) -> Result<(), ClientError> {
        let now = self.singula.now();
        let Some(today) = self.singula.window_at(now, NEW_DAY_AFTER) else {
            return Ok(());
        };
        if today <= self.window {
            return Ok(());
        }
        let day = self
            .singula
            .day_right(&self.identity, self.slot, today)
            .await?;
        let start = self
            .singula
            .chain()
            .deployment()
            .clock
            .epoch_start(today)
            .ok_or(ClientError::Mismatch("the day has no start"))?;
        // Counted from midnight less the clock tolerance, so the first ping's
        // seconds never reach back before the day began for the Control
        // Planes.
        let into_day = u64::try_from(now.0 - start.0)
            .unwrap_or(0)
            .saturating_sub(NEW_DAY_AFTER.as_secs());
        self.counting_from = Instant::now()
            .checked_sub(Duration::from_secs(into_day))
            .unwrap_or_else(Instant::now);
        self.window = today;
        self.day = day;
        self.right_to_send = true;
        Ok(())
    }

    /// Sends a ping of `total` seconds through the current Control Plane, or
    /// the first of the others that shows it reached a majority.
    async fn ping(&mut self, total: u64) -> Result<(Committed, StarId), ClientError> {
        let params = self.singula.chain().journal_params();
        let ping = Ping::new(
            self.window,
            self.day.right.nullifier,
            self.session.id().clone(),
            self.session.node(),
            total,
        );
        let signed = self.day.key.sign_ping(params, ping);
        let mut last = match self.ping_at(&self.current.clone(), &signed).await {
            Ok(committed) => return Ok((committed, self.current.star())),
            Err(e) => e,
        };
        for cp in self.others().await {
            match self.ping_at(&cp, &signed).await {
                Ok(committed) => {
                    let star = cp.star();
                    self.current = cp;
                    return Ok((committed, star));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Sends `signed` to `cp` and checks its answer against the chain.
    async fn ping_at(
        &mut self,
        cp: &ControlPlaneClient,
        signed: &SignedPing,
    ) -> Result<Committed, ClientError> {
        let params = self.singula.chain().journal_params();
        let right = self.right_to_send.then_some(&self.day.right);
        let ack = cp.ping(params, signed, self.meter.traffic(), right).await?;
        let mut versions = self.singula.versions(false).await?;
        let mut committed = ack.committed(&versions, params, self.singula.now());
        if committed == Err(AckError::UnknownVersion) {
            versions = self.singula.versions(true).await?;
            committed = ack.committed(&versions, params, self.singula.now());
        }
        let committed = committed.map_err(ClientError::NotCommitted)?;
        self.right_to_send = false;
        Ok(committed)
    }

    /// Every other Control Plane the chain lists, in random order.
    async fn others(&self) -> Vec<ControlPlaneClient> {
        let mut others = self.singula.control_planes().await.unwrap_or_default();
        others.retain(|cp| cp.star() != self.current.star());
        others
    }

    async fn finish(self, reason: EndReason) {
        if reason == EndReason::Closed {
            // The seconds since the last ping, so the node is paid for them;
            // then the session's end. Both best effort: the session ends on
            // its own once pings stop.
            let total = self.counting_from.elapsed().as_secs();
            let params = self.singula.chain().journal_params();
            let ping = Ping::new(
                self.window,
                self.day.right.nullifier,
                self.session.id().clone(),
                self.session.node(),
                total,
            );
            let signed = self.day.key.sign_ping(params, ping);
            let _ = self
                .current
                .ping(params, &signed, self.meter.traffic(), None)
                .await;
            let traffic = self.meter.traffic();
            let _ = self
                .admitting
                .end_anonymous_session(self.session, traffic)
                .await;
        }
        if reason == EndReason::ClosedByNetwork(CloseReason::Overlap) {
            self.singula.slot_busy(self.slot, self.window).await;
        }
        let _ = self.events.try_send(Event::Ended(reason));
    }

    /// Sends `event` unless the application has stopped reading: a full
    /// buffer drops the event rather than stalling the session.
    fn emit(&self, event: Event) {
        let _ = self.events.try_send(event);
    }
}
