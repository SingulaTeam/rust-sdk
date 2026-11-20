//! A slot's day: its right, proved once a day, and the chain it is checked
//! against.
//!
//! Each of a subscription's slots buys one session at a time. A day's right
//! is proved against the day's subscriber tree, which this client builds
//! itself from the chain — never takes from a Control Plane — and is kept
//! for the day, so reconnecting costs no new proof.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore as _};

use super::ClientError;
use super::connect::{Identities, Singula};
use super::store::Store;
use crate::chain::{RegistryHistory, Rpc, SubscriberLog, WindowTreeError};
use crate::id::{Epoch, UnixTime};
use crate::journal::{Right, RightKey, Versions};
use crate::zk::{Claim, Identity};

/// How long the registry's history is trusted before it is read again. A
/// new version only matters once an ack names it, which also triggers a
/// read; this bounds how long a removed Control Plane's word is taken.
const HISTORY_FRESH: Duration = Duration::from_secs(10 * 60);

/// What the journal keeps between calls.
#[derive(Default)]
pub(super) struct JournalState {
    history: RegistryHistory,
    history_read: Option<Instant>,
    log: SubscriberLog,
    /// Rights proved, by slot and day.
    rights: HashMap<(u8, Epoch), DayRight>,
    /// Slots another device was found on, and the day it was.
    busy: HashMap<u8, Epoch>,
    /// Slots carrying one of this client's sessions, or about to: a slot
    /// holds one session at a time.
    held: HashSet<u8>,
}

/// A slot's right for one day, with its key.
#[derive(Debug, Clone)]
pub(super) struct DayRight {
    pub(super) right: Right,
    pub(super) key: Arc<RightKey>,
}

impl<R: Rpc + 'static, S: Store + 'static> Singula<R, S> {
    /// The day's right of `identity`, slot `slot`: the one proved before,
    /// or a proof now against the day's tree.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NotRegistered`] if the slot is in none of the
    /// day's trees — not registered, or its Orbit ends during the day — and
    /// any error reading the chain or proving.
    pub(super) async fn day_right(
        &self,
        identity: &Arc<Identity>,
        slot: u8,
        window: Epoch,
    ) -> Result<DayRight, ClientError> {
        let mut journal = self.inner.journal.lock().await;
        if let Some(day) = journal.rights.get(&(slot, window)) {
            return Ok(day.clone());
        }
        journal.log.refresh(&self.inner.chain).await?;
        let clock = self.inner.chain.deployment().clock;
        let tree = journal
            .log
            .window_tree(&clock, window, identity.commitment())
            .map_err(|e| match e {
                WindowTreeError::NotAMember => ClientError::NotRegistered,
                _ => ClientError::Malformed("the day's subscriber tree cannot be built yet"),
            })?;
        let params = self.inner.chain.journal_params();
        let key = Arc::new(
            identity
                .right_key(params, window)
                .map_err(|_| ClientError::Malformed("no right key for the day"))?,
        );
        let claim = Claim::Right {
            window,
            key: key.public_key(),
        };
        let this = self.clone();
        let prover_identity = Arc::clone(identity);
        let proof = tokio::task::spawn_blocking(move || {
            this.inner
                .prover
                .prove(&prover_identity, &tree.group, claim)
        })
        .await
        .map_err(|_| ClientError::Malformed("the prover stopped"))??;
        let right = proof.to_right(tree.state_index);
        let day = DayRight { right, key };
        journal.rights.retain(|(_, w), _| *w >= window);
        journal.rights.insert((slot, window), day.clone());
        Ok(day)
    }

    /// The Control Plane registry's history, read again when older than
    /// [`HISTORY_FRESH`] or when `stale` says an ack named a version not
    /// read yet.
    ///
    /// # Errors
    ///
    /// Returns any error reading the chain, and
    /// [`ClientError::Malformed`] while no version has been read.
    pub(super) async fn versions(&self, stale: bool) -> Result<Versions, ClientError> {
        let mut journal = self.inner.journal.lock().await;
        let fresh = journal
            .history_read
            .is_some_and(|at| at.elapsed() < HISTORY_FRESH);
        if stale || !fresh {
            journal.history.refresh(&self.inner.chain).await?;
            journal.history_read = Some(Instant::now());
        }
        journal
            .history
            .versions()
            .map_err(|_| ClientError::Malformed("no Control Plane registry version yet"))
    }

    /// Notes that another device holds `slot` on `window`, so the next
    /// connection takes another.
    pub(super) async fn slot_busy(&self, slot: u8, window: Epoch) {
        self.inner.journal.lock().await.busy.insert(slot, window);
    }

    /// Takes a slot for a new session on `window`: one that carries none of
    /// this client's sessions and is not in `tried`, preferring those no other
    /// device was found on today, at random among equals so devices starting
    /// at once rarely pick the same. The slot stays taken until
    /// [`release_slot`](Self::release_slot).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::NoFreeSlot`] if every slot carries one of this
    /// client's sessions, and [`ClientError::NotRegistered`] if every free
    /// one has been tried.
    pub(super) async fn take_slot(
        &self,
        identities: &Identities,
        window: Epoch,
        tried: &HashSet<u8>,
    ) -> Result<(u8, Arc<Identity>), ClientError> {
        let mut journal = self.inner.journal.lock().await;
        let mut free: Vec<_> = identities
            .iter()
            .filter(|(slot, _)| !journal.held.contains(slot))
            .cloned()
            .collect();
        if free.is_empty() {
            return Err(ClientError::NoFreeSlot);
        }
        free.retain(|(slot, _)| !tried.contains(slot));
        // Fisher–Yates, then a stable sort that keeps the shuffle within groups.
        for i in (1..free.len()).rev() {
            let j = usize::try_from(OsRng.next_u64() % (i as u64 + 1)).unwrap_or(0);
            free.swap(i, j);
        }
        free.sort_by_key(|(slot, _)| journal.busy.get(slot) == Some(&window));
        let (slot, identity) = free.into_iter().next().ok_or(ClientError::NotRegistered)?;
        journal.held.insert(slot);
        Ok((slot, identity))
    }

    /// Gives back a slot taken by [`take_slot`](Self::take_slot).
    pub(super) async fn release_slot(&self, slot: u8) {
        self.inner.journal.lock().await.held.remove(&slot);
    }

    /// The window a ping made at `now` belongs to: the window `now` falls
    /// in, `margin` ago.
    pub(super) fn window_at(&self, now: UnixTime, margin: Duration) -> Option<Epoch> {
        let back = i64::try_from(margin.as_secs()).unwrap_or(0);
        self.inner
            .chain
            .deployment()
            .clock
            .epoch_at(UnixTime(now.0.saturating_sub(back)))
    }
}
