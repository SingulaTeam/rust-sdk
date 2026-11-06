//! The records the SDK keeps in a [`Store`], and the rules for changing them.
//!
//! Every change that commits the subscriber to something — holding a
//! permission, using a quota slot — is written before it is acted on. A crash
//! in between then leaves the record claiming a little more than happened,
//! which costs at most one wasted round trip; the opposite order could hand
//! one permission to two sessions, or one slot to two proofs.
//!
//! | Key                      | Holds                                  | Secret |
//! |--------------------------|----------------------------------------|--------|
//! | `identity/<wallet>`      | the wallet's identity secret           | yes    |
//! | `sign-in/<cp>/<wallet>`  | the wallet's sign-in to a Control Plane | yes    |
//! | `permissions`            | this window's permissions, and holders | yes    |
//! | `slots/<cp>/<epoch>`     | the next unused quota slot             | no     |

use serde::{Deserialize, Serialize};

use super::auth::WalletAuth;
use super::permission::Permission;
use super::store::{Key, Store, StoreError};
use super::wallet::WalletSignature;
use crate::id::{Address, Epoch, SessionId, StarId, UnixTime};
use crate::zk::Identity;

/// The [`Store`] seen as the SDK's records.
pub(crate) struct Ledger<'a, S>(pub(crate) &'a S);

/// A window's permissions as stored: those this client took, which session
/// holds each, and the indices other devices took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WindowRecord {
    pub(crate) window: u64,
    pub(crate) permissions: Vec<Held>,
    /// Indices refused as taken: by another of the subscription's devices.
    #[serde(default)]
    pub(crate) taken_elsewhere: Vec<u32>,
}

/// How far apart the indices of two slots' identities are numbered: a
/// permission taken by slot `s` under index `i` is recorded as
/// `s × SLOT_STRIDE + i`. Slot 0's indices are the plain ones, so a ledger
/// written before slots reads the same.
pub(crate) const SLOT_STRIDE: u32 = 1 << 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Held {
    /// The index it was taken under, numbered across slots; see [`SLOT_STRIDE`].
    pub(crate) index: u32,
    pub(crate) issuer: u64,
    #[serde(with = "hex_bytes")]
    pub(crate) issuer_public_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub(crate) prepared_message: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub(crate) signature: Vec<u8>,
    /// The holder: `Some("")` while a session is being opened with it, the
    /// session's id once it is open, `None` when it is free.
    pub(crate) holder: Option<String>,
    /// When the permission may be lent again, in Unix seconds. For a free
    /// one: once the Control Planes have let it go after its session ended.
    /// For a held one: once its holder has stopped keeping it — every report
    /// pushes this on, so a holder that died without a word, and whose
    /// session the Control Plane has therefore swept, gives it back too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) free_at: Option<i64>,
}

/// A permission lent out, and where to give it back.
#[derive(Debug, Clone)]
pub(crate) struct Lease {
    pub(crate) index: usize,
    pub(crate) window: Epoch,
    pub(crate) permission: Permission,
    /// The slot whose identity took it, and so proves the session it admits.
    pub(crate) slot: u8,
}

/// A sign-in as stored.
#[derive(Serialize, Deserialize)]
struct StoredSignIn {
    control_plane: u64,
    wallet: String,
    nonce: String,
    issued_at: i64,
    #[serde(with = "hex_bytes")]
    signature: Vec<u8>,
}

impl<S: Store> Ledger<'_, S> {
    /// The identity this wallet derived before, if it was kept.
    pub(crate) async fn identity(&self, wallet: Address) -> Result<Option<Identity>, StoreError> {
        let key = Key::secret(format!("identity/{}", hex_address(wallet)));
        let Some(bytes) = self.0.get(&key).await? else {
            return Ok(None);
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| StoreError::Corrupt(key.to_string()))?;
        Identity::from_secret(text)
            .map(Some)
            .map_err(|_| StoreError::Corrupt(key.to_string()))
    }

    pub(crate) async fn keep_identity(
        &self,
        wallet: Address,
        identity: &Identity,
    ) -> Result<(), StoreError> {
        let key = Key::secret(format!("identity/{}", hex_address(wallet)));
        self.0.put(&key, identity.secret().as_bytes()).await
    }

    /// The wallet's sign-in to `cp`, while it still has a day to run.
    pub(crate) async fn sign_in(
        &self,
        cp: StarId,
        wallet: Address,
    ) -> Result<Option<WalletAuth>, StoreError> {
        let key = sign_in_key(cp, wallet);
        let Some(stored) = self.json::<StoredSignIn>(&key).await? else {
            return Ok(None);
        };
        let corrupt = || StoreError::Corrupt(key.to_string());
        let signature: [u8; 65] = stored.signature.try_into().map_err(|_| corrupt())?;
        let auth = WalletAuth::from_parts(
            StarId(stored.control_plane),
            stored.wallet.parse().map_err(|_| corrupt())?,
            stored.nonce,
            UnixTime(stored.issued_at),
            WalletSignature(signature),
        )
        .map_err(|_| corrupt())?;
        // A sign-in about to lapse would fail mid-session; sign again instead.
        let fresh = auth.expires_at().0 - UnixTime::now().0 > 24 * 60 * 60;
        Ok(fresh.then_some(auth))
    }

    pub(crate) async fn keep_sign_in(&self, auth: &WalletAuth) -> Result<(), StoreError> {
        let stored = StoredSignIn {
            control_plane: auth.control_plane().0,
            wallet: auth.wallet().to_string(),
            nonce: auth.nonce().to_owned(),
            issued_at: auth.issued_at().0,
            signature: auth.signature().0.to_vec(),
        };
        self.put_json(&sign_in_key(auth.control_plane(), auth.wallet()), &stored)
            .await
    }

    /// What this client knows of `window`'s permissions; `None` until it has
    /// taken or been refused one.
    pub(crate) async fn permissions(
        &self,
        window: Epoch,
    ) -> Result<Option<WindowRecord>, StoreError> {
        Ok(self
            .json::<WindowRecord>(&permissions_key())
            .await?
            .filter(|p| p.window == window.0))
    }

    /// The record for `window`, empty when the one kept is another
    /// window's: permissions of a past window open nothing.
    async fn window(&self, window: Epoch) -> Result<WindowRecord, StoreError> {
        Ok(self.permissions(window).await?.unwrap_or(WindowRecord {
            window: window.0,
            permissions: Vec::new(),
            taken_elsewhere: Vec::new(),
        }))
    }

    /// Keeps a freshly taken permission, taken under `index`.
    pub(crate) async fn add(&self, index: u32, permission: &Permission) -> Result<(), StoreError> {
        let mut record = self.window(permission.window).await?;
        record.permissions.push(Held {
            index,
            issuer: permission.issuer.0,
            issuer_public_key: permission.issuer_public_key.clone(),
            prepared_message: permission.prepared_message.clone(),
            signature: permission.signature.clone(),
            holder: None,
            free_at: None,
        });
        self.put_json(&permissions_key(), &record).await
    }

    /// Records that `index` of `window` was taken by someone else.
    pub(crate) async fn taken_elsewhere(
        &self,
        window: Epoch,
        index: u32,
    ) -> Result<(), StoreError> {
        let mut record = self.window(window).await?;
        if !record.taken_elsewhere.contains(&index) {
            record.taken_elsewhere.push(index);
        }
        self.put_json(&permissions_key(), &record).await
    }

    /// The indices below `count` this client has neither taken nor seen
    /// taken in `window`.
    /// Which of `candidates` — indices numbered across slots — this client
    /// has neither taken nor seen taken by another device.
    pub(crate) async fn untried(
        &self,
        window: Epoch,
        candidates: &[u32],
    ) -> Result<Vec<u32>, StoreError> {
        let record = self.window(window).await?;
        Ok(candidates
            .iter()
            .copied()
            .filter(|i| {
                !record.taken_elsewhere.contains(i)
                    && !record.permissions.iter().any(|p| p.index == *i)
            })
            .collect())
    }

    /// Takes a permission of `window` that is free at `now`,
    /// recorded as held until `kept_until` before it is returned.
    pub(crate) async fn lease(
        &self,
        window: Epoch,
        now: UnixTime,
        kept_until: UnixTime,
    ) -> Result<Option<Lease>, StoreError> {
        let Some(mut packet) = self.permissions(window).await? else {
            return Ok(None);
        };
        let free = |p: &Held| match (&p.holder, p.free_at) {
            (None, at) => at.is_none_or(|t| t <= now.0),
            // A hold nobody kept: its holder is gone.
            (Some(_), Some(t)) => t <= now.0,
            (Some(_), None) => false,
        };
        let Some(index) = packet.permissions.iter().position(free) else {
            return Ok(None);
        };
        packet.permissions[index].holder = Some(String::new());
        packet.permissions[index].free_at = Some(kept_until.0);
        self.put_json(&permissions_key(), &packet).await?;
        let held = &packet.permissions[index];
        Ok(Some(Lease {
            index,
            window,
            slot: u8::try_from(held.index / SLOT_STRIDE).unwrap_or(u8::MAX),
            permission: Permission {
                issuer: StarId(held.issuer),
                window,
                prepared_message: held.prepared_message.clone(),
                signature: held.signature.clone(),
                issuer_public_key: held.issuer_public_key.clone(),
            },
        }))
    }

    /// Records which session holds a leased permission, until `kept_until`.
    pub(crate) async fn bind(
        &self,
        lease: &Lease,
        session: &SessionId,
        kept_until: UnixTime,
    ) -> Result<(), StoreError> {
        self.set(lease, Some(session.to_string()), Some(kept_until.0))
            .await
    }

    /// Pushes on the hold `session` has on a permission: it is still running.
    /// A permission since taken by another session is left alone.
    pub(crate) async fn keep(
        &self,
        lease: &Lease,
        session: &SessionId,
        kept_until: UnixTime,
    ) -> Result<(), StoreError> {
        let Some(mut packet) = self.permissions(lease.window).await? else {
            return Ok(());
        };
        if let Some(held) = packet.permissions.get_mut(lease.index) {
            if held.holder.as_deref() == Some(session.as_str()) {
                held.free_at = Some(kept_until.0);
                self.put_json(&permissions_key(), &packet).await?;
            }
        }
        Ok(())
    }

    /// Gives a permission back at once: no Control Plane ever took it.
    pub(crate) async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
        self.set(lease, None, None).await
    }

    /// Gives a permission back from `free_at` on: a Control Plane took it,
    /// for a session that has ended or never worked, and holds it until its
    /// lease runs out. Lent before then it would be refused as spent.
    pub(crate) async fn release_at(
        &self,
        lease: &Lease,
        free_at: UnixTime,
    ) -> Result<(), StoreError> {
        self.set(lease, None, Some(free_at.0)).await
    }

    /// When each of this client's permissions of `window` that is waiting
    /// out a Control Plane's hold frees, earliest first.
    pub(crate) async fn cooling(
        &self,
        window: Epoch,
        now: UnixTime,
    ) -> Result<Vec<i64>, StoreError> {
        let Some(record) = self.permissions(window).await? else {
            return Ok(Vec::new());
        };
        let mut at: Vec<i64> = record
            .permissions
            .iter()
            .filter(|p| p.holder.is_none())
            .filter_map(|p| p.free_at)
            .filter(|t| *t > now.0)
            .collect();
        at.sort_unstable();
        Ok(at)
    }

    async fn set(
        &self,
        lease: &Lease,
        holder: Option<String>,
        free_at: Option<i64>,
    ) -> Result<(), StoreError> {
        // A lease from a window since replaced is gone with it; touching the
        // new window's entry would free a permission another session holds.
        let Some(mut packet) = self.permissions(lease.window).await? else {
            return Ok(());
        };
        if let Some(held) = packet.permissions.get_mut(lease.index) {
            held.holder = holder;
            held.free_at = free_at;
            self.put_json(&permissions_key(), &packet).await?;
        }
        Ok(())
    }

    /// The next quota slot for sessions at `cp` in `epoch`, recorded as used
    /// before it is returned.
    pub(crate) async fn take_slot(&self, cp: StarId, epoch: Epoch) -> Result<u32, StoreError> {
        let key = Key::plain(format!("slots/{}/{}", cp.0, epoch.0));
        let next = self.json::<u32>(&key).await?.unwrap_or(0);
        self.put_json(&key, &(next + 1)).await?;
        Ok(next)
    }

    async fn json<T: for<'de> Deserialize<'de>>(&self, key: &Key) -> Result<Option<T>, StoreError> {
        match self.0.get(key).await? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| StoreError::Corrupt(key.to_string())),
            None => Ok(None),
        }
    }

    async fn put_json<T: Serialize>(&self, key: &Key, value: &T) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(value).map_err(|e| StoreError::Backend(e.into()))?;
        self.0.put(key, &bytes).await
    }
}

fn permissions_key() -> Key {
    Key::secret("permissions".to_owned())
}

fn sign_in_key(cp: StarId, wallet: Address) -> Key {
    Key::secret(format!("sign-in/{}/{}", cp.0, hex_address(wallet)))
}

/// An address as a key segment: lowercase hex, no prefix.
fn hex_address(a: Address) -> String {
    crate::hex::lower(&a.0)
}

mod hex_bytes {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::hex::lower(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        alloy_primitives::hex::decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::super::store::MemoryStore;
    use super::super::wallet::{LocalWallet, Wallet as _};
    use super::*;

    const NOW: UnixTime = UnixTime(1_790_000_000);
    /// Far enough on that no hold in these tests lapses unless one means it to.
    const KEPT: UnixTime = UnixTime(NOW.0 + 3_600);

    fn permissions(window: u64, n: u8) -> Vec<Permission> {
        (0..n)
            .map(|i| Permission {
                issuer: StarId(8),
                window: Epoch(window),
                prepared_message: vec![i; 64],
                signature: vec![i; 256],
                issuer_public_key: vec![9; 16],
            })
            .collect()
    }

    /// Keeps `permissions` as if taken under indices 0, 1, …
    async fn install(ledger: &Ledger<'_, MemoryStore>, permissions: &[Permission]) {
        for (index, p) in (0u32..).zip(permissions) {
            ledger.add(index, p).await.expect("keeps");
        }
    }

    #[tokio::test]
    async fn tries_only_indices_nobody_took() {
        let store = MemoryStore::new();
        let ledger = Ledger(&store);
        assert_eq!(
            ledger
                .untried(Epoch(137), &[0, 1, 2, 3, 4])
                .await
                .expect("reads"),
            [0, 1, 2, 3, 4]
        );
        ledger.add(3, &permissions(137, 1)[0]).await.expect("keeps");
        ledger.taken_elsewhere(Epoch(137), 0).await.expect("keeps");
        assert_eq!(
            ledger
                .untried(Epoch(137), &[0, 1, 2, 3, 4])
                .await
                .expect("reads"),
            [1, 2, 4]
        );
        // A new window starts clean.
        assert_eq!(
            ledger
                .untried(Epoch(138), &[0, 1, 2, 3, 4])
                .await
                .expect("reads"),
            [0, 1, 2, 3, 4]
        );
    }

    fn session(n: u8) -> SessionId {
        format!("00000000-0000-0000-0000-0000000000{n:02x}")
            .parse()
            .expect("a session id")
    }

    #[tokio::test]
    async fn lends_each_permission_once() {
        let store = MemoryStore::new();
        let ledger = Ledger(&store);
        install(&ledger, &permissions(137, 2)).await;
        let a = ledger
            .lease(Epoch(137), NOW, KEPT)
            .await
            .expect("reads")
            .expect("one free");
        let b = ledger
            .lease(Epoch(137), NOW, KEPT)
            .await
            .expect("reads")
            .expect("another free");
        assert_ne!(a.permission.prepared_message, b.permission.prepared_message);
        assert!(
            ledger
                .lease(Epoch(137), NOW, KEPT)
                .await
                .expect("reads")
                .is_none(),
            "a third session was licensed"
        );
        assert!(
            ledger
                .lease(Epoch(138), NOW, KEPT)
                .await
                .expect("reads")
                .is_none(),
            "the packet is for 137 only"
        );
    }

    #[tokio::test]
    async fn a_hold_is_written_before_the_permission_is_used() {
        let store = MemoryStore::new();
        ledger_with_one(&store).await;
        let _ = Ledger(&store)
            .lease(Epoch(137), NOW, KEPT)
            .await
            .expect("reads")
            .expect("free");
        // A fresh view of the same store — as after a crash — sees it held.
        assert!(
            Ledger(&store)
                .lease(Epoch(137), NOW, KEPT)
                .await
                .expect("reads")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_released_permission_can_be_lent_again() {
        let store = MemoryStore::new();
        let ledger = ledger_with_one(&store).await;
        let lease = ledger
            .lease(Epoch(137), NOW, KEPT)
            .await
            .expect("reads")
            .expect("free");
        ledger.bind(&lease, &session(1), KEPT).await.expect("binds");
        ledger.release(&lease).await.expect("releases");
        assert!(
            ledger
                .lease(Epoch(137), NOW, KEPT)
                .await
                .expect("reads")
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_permission_a_control_plane_still_holds_waits_its_turn() {
        let store = MemoryStore::new();
        let ledger = ledger_with_one(&store).await;
        let lease = ledger
            .lease(Epoch(137), NOW, KEPT)
            .await
            .expect("reads")
            .expect("free");
        let later = UnixTime(NOW.0 + 90);
        ledger.release_at(&lease, later).await.expect("releases");
        assert!(
            ledger
                .lease(Epoch(137), NOW, KEPT)
                .await
                .expect("reads")
                .is_none(),
            "lent while a Control Plane still holds it"
        );
        assert_eq!(
            ledger.cooling(Epoch(137), NOW).await.expect("reads"),
            [later.0]
        );
        assert!(
            ledger
                .lease(Epoch(137), later, KEPT)
                .await
                .expect("reads")
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_hold_nobody_keeps_lapses() {
        let store = MemoryStore::new();
        let ledger = ledger_with_one(&store).await;
        let soon = UnixTime(NOW.0 + 480);
        let lease = ledger
            .lease(Epoch(137), NOW, soon)
            .await
            .expect("reads")
            .expect("free");
        ledger.bind(&lease, &session(1), soon).await.expect("binds");
        assert!(
            ledger
                .lease(Epoch(137), NOW, KEPT)
                .await
                .expect("reads")
                .is_none()
        );

        // Reported on: the hold moves on.
        let later = UnixTime(NOW.0 + 900);
        ledger
            .keep(&lease, &session(1), later)
            .await
            .expect("keeps");
        assert!(
            ledger
                .lease(Epoch(137), soon, KEPT)
                .await
                .expect("reads")
                .is_none()
        );
        // Kept by another session's id: not this hold's to move.
        ledger
            .keep(&lease, &session(2), UnixTime(NOW.0 + 9_999))
            .await
            .expect("ignores");

        // Its holder went quiet — the process died — and it lapses.
        assert!(
            ledger
                .lease(Epoch(137), later, KEPT)
                .await
                .expect("reads")
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_lease_from_a_replaced_packet_touches_nothing() {
        let store = MemoryStore::new();
        let ledger = ledger_with_one(&store).await;
        let old = ledger
            .lease(Epoch(137), NOW, KEPT)
            .await
            .expect("reads")
            .expect("free");
        install(&ledger, &permissions(138, 1)).await;
        let new = ledger
            .lease(Epoch(138), NOW, KEPT)
            .await
            .expect("reads")
            .expect("free");
        ledger.release(&old).await.expect("is a no-op");
        assert!(
            ledger
                .lease(Epoch(138), NOW, KEPT)
                .await
                .expect("reads")
                .is_none(),
            "{new:?} was freed by a stale lease"
        );
    }

    #[tokio::test]
    async fn slots_are_never_handed_out_twice() {
        let store = MemoryStore::new();
        let ledger = Ledger(&store);
        assert_eq!(
            ledger
                .take_slot(StarId(8), Epoch(137))
                .await
                .expect("counts"),
            0
        );
        assert_eq!(
            ledger
                .take_slot(StarId(8), Epoch(137))
                .await
                .expect("counts"),
            1
        );
        assert_eq!(
            ledger
                .take_slot(StarId(9), Epoch(137))
                .await
                .expect("counts"),
            0,
            "per Control Plane"
        );
        assert_eq!(
            ledger
                .take_slot(StarId(8), Epoch(138))
                .await
                .expect("counts"),
            0,
            "per epoch"
        );
    }

    #[tokio::test]
    async fn keeps_an_identity_and_a_sign_in() {
        let store = MemoryStore::new();
        let ledger = Ledger(&store);
        let wallet = LocalWallet::random();
        let identity = Identity::from_signature("0xabc");
        ledger
            .keep_identity(wallet.address(), &identity)
            .await
            .expect("keeps");
        let back = ledger
            .identity(wallet.address())
            .await
            .expect("reads")
            .expect("kept");
        assert_eq!(back.commitment(), identity.commitment());

        let auth = WalletAuth::sign(&wallet, StarId(8)).await.expect("signs");
        ledger.keep_sign_in(&auth).await.expect("keeps");
        assert_eq!(
            ledger
                .sign_in(StarId(8), wallet.address())
                .await
                .expect("reads"),
            Some(auth)
        );
        assert_eq!(
            ledger
                .sign_in(StarId(9), wallet.address())
                .await
                .expect("reads"),
            None
        );
    }

    async fn ledger_with_one(store: &MemoryStore) -> Ledger<'_, MemoryStore> {
        let ledger = Ledger(store);
        install(&ledger, &permissions(137, 1)).await;
        ledger
    }
}
