//! Signing in with a wallet.

use std::time::Duration;

use rand_core::{OsRng, RngCore as _};

use super::proto::client::{ClientAuth, ClientInfo};
use super::wallet::{PersonalMessage, Wallet, WalletError, WalletSignature, sign_message_checked};
use crate::eth;
use crate::id::{Address, StarId, UnixTime};
use crate::sign_in::SignInMessage;

/// How long a Control Plane honours a sign-in.
pub const SIGN_IN_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// A wallet's signed sign-in to one Control Plane.
///
/// One signature serves every call to that Control Plane for a week, so the
/// person is asked once; keep it with the wallet's other session data. It
/// names the Control Plane, so it is worthless at any other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletAuth {
    control_plane: StarId,
    wallet: Address,
    nonce: String,
    issued_at: UnixTime,
    signature: WalletSignature,
}

/// Why a stored sign-in cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WalletAuthError {
    /// The signature is not the wallet's over this sign-in.
    #[error("the signature is not the wallet's sign-in")]
    WrongSignature,
    /// The nonce is not one a sign-in can carry.
    #[error("the sign-in nonce is malformed")]
    Nonce,
}

impl WalletAuth {
    /// Asks `wallet` to sign in to `control_plane`.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError`] if the wallet does not sign, or signs as
    /// someone else.
    pub async fn sign<W: Wallet>(wallet: &W, control_plane: StarId) -> Result<Self, WalletError> {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let nonce = crate::hex::lower(&bytes);
        let issued_at = UnixTime::now();
        let message = SignInMessage::new(control_plane, &nonce, issued_at)
            .map_err(|_| WalletError::WrongSignature)?
            .to_string();
        let signature = sign_message_checked(wallet, PersonalMessage::Text(&message)).await?;
        Ok(Self {
            control_plane,
            wallet: wallet.address(),
            nonce,
            issued_at,
            signature,
        })
    }

    /// Restores a sign-in saved earlier, checking its signature.
    ///
    /// # Errors
    ///
    /// Returns [`WalletAuthError`] if the parts do not make a sign-in by
    /// `wallet`.
    pub fn from_parts(
        control_plane: StarId,
        wallet: Address,
        nonce: String,
        issued_at: UnixTime,
        signature: WalletSignature,
    ) -> Result<Self, WalletAuthError> {
        let message = SignInMessage::new(control_plane, &nonce, issued_at)
            .map_err(|_| WalletAuthError::Nonce)?;
        let hash = eth::personal_message_hash(message.to_string().as_bytes());
        if eth::recover(&hash, &signature.0) != Ok(wallet) {
            return Err(WalletAuthError::WrongSignature);
        }
        Ok(Self {
            control_plane,
            wallet,
            nonce,
            issued_at,
            signature,
        })
    }

    /// The Control Plane it signs in to.
    #[must_use]
    pub fn control_plane(&self) -> StarId {
        self.control_plane
    }

    /// The wallet that signed.
    #[must_use]
    pub fn wallet(&self) -> Address {
        self.wallet
    }

    /// The nonce it carries, for storing it.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// When it was signed.
    #[must_use]
    pub fn issued_at(&self) -> UnixTime {
        self.issued_at
    }

    /// The wallet's signature, for storing it.
    #[must_use]
    pub fn signature(&self) -> WalletSignature {
        self.signature
    }

    /// When the Control Plane stops honouring it.
    #[must_use]
    pub fn expires_at(&self) -> UnixTime {
        let lifetime = i64::try_from(SIGN_IN_LIFETIME.as_secs()).unwrap_or(i64::MAX);
        UnixTime(self.issued_at.0.saturating_add(lifetime))
    }

    pub(super) fn to_wire(&self) -> ClientAuth {
        ClientAuth {
            wallet_address: self.wallet.to_string(),
            signature: self.signature.0.to_vec(),
            timestamp: self.issued_at.0,
            nonce: self.nonce.clone(),
            // Each session sends its own key; the stream needs none.
            public_key: Vec::new(),
            client_info: Some(ClientInfo {
                app_version: env!("CARGO_PKG_VERSION").to_owned(),
                platform: std::env::consts::OS.to_owned(),
                preferred_country: String::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::wallet::LocalWallet;
    use super::*;

    #[tokio::test]
    async fn a_sign_in_survives_being_stored() {
        let wallet = LocalWallet::random();
        let auth = WalletAuth::sign(&wallet, StarId(8)).await.expect("signs");
        let restored = WalletAuth::from_parts(
            auth.control_plane(),
            auth.wallet(),
            auth.nonce().to_owned(),
            auth.issued_at(),
            auth.signature(),
        );
        assert_eq!(restored.as_ref(), Ok(&auth));
    }

    #[tokio::test]
    async fn a_sign_in_names_its_control_plane() {
        let wallet = LocalWallet::random();
        let auth = WalletAuth::sign(&wallet, StarId(8)).await.expect("signs");
        assert_eq!(
            WalletAuth::from_parts(
                StarId(9),
                auth.wallet(),
                auth.nonce().to_owned(),
                auth.issued_at(),
                auth.signature()
            ),
            Err(WalletAuthError::WrongSignature)
        );
    }
}
