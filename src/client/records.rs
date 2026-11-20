//! The records the SDK keeps in a [`Store`]: what is costly to make again.
//!
//! | Key                      | Holds                                   | Secret |
//! |--------------------------|-----------------------------------------|--------|
//! | `identity/<wallet>`      | the wallet's identity secret            | yes    |
//! | `sign-in/<cp>/<wallet>`  | the wallet's sign-in to a Control Plane | yes    |
//!
//! An identity takes a wallet signature to derive, and a sign-in another;
//! keeping them saves the user a prompt on every start.

use serde::{Deserialize, Serialize};

use super::auth::WalletAuth;
use super::store::{Key, Store, StoreError};
use super::wallet::WalletSignature;
use crate::id::{Address, StarId, UnixTime};
use crate::zk::Identity;

/// The [`Store`] seen as the SDK's records.
pub(crate) struct Records<'a, S>(pub(crate) &'a S);

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

impl<S: Store> Records<'_, S> {
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

    #[tokio::test]
    async fn keeps_an_identity_and_a_sign_in() {
        let store = MemoryStore::new();
        let records = Records(&store);
        let wallet = LocalWallet::random();
        let identity = Identity::from_signature("0xabc");
        records
            .keep_identity(wallet.address(), &identity)
            .await
            .expect("keeps");
        let back = records
            .identity(wallet.address())
            .await
            .expect("reads")
            .expect("kept");
        assert_eq!(back.commitment(), identity.commitment());

        let auth = WalletAuth::sign(&wallet, StarId(8)).await.expect("signs");
        records.keep_sign_in(&auth).await.expect("keeps");
        assert_eq!(
            records
                .sign_in(StarId(8), wallet.address())
                .await
                .expect("reads"),
            Some(auth)
        );
        assert_eq!(
            records
                .sign_in(StarId(9), wallet.address())
                .await
                .expect("reads"),
            None
        );
    }
}
