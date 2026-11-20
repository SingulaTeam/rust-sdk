//! A slot's day: its right, proved once a day, and the chain it is checked
//! against.
//!
//! Each of a subscription's slots buys one session at a time. A day's right
//! is proved against the day's subscriber tree, which this client builds
//! itself from the chain — never takes from a Control Plane — and is kept
//! for the day, so reconnecting costs no new proof.

use std::collections::HashMap;
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

    /// The slots to try for a session on `window`, in order: those no other
    /// device was found on today first, each group in random order, so
    /// devices starting at once rarely pick the same.
    pub(super) async fn slot_order(&self, identities: &Identities, window: Epoch) -> Identities {
        let journal = self.inner.journal.lock().await;
        let mut slots: Vec<_> = identities.iter().cloned().collect();
        // Fisher–Yates, then a stable sort that keeps the shuffle within groups.
        for i in (1..slots.len()).rev() {
            let j = usize::try_from(OsRng.next_u64() % (i as u64 + 1)).unwrap_or(0);
            slots.swap(i, j);
        }
        slots.sort_by_key(|(slot, _)| journal.busy.get(slot) == Some(&window));
        slots.into()
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
