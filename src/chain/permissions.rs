//! Commitments to the keys Control Planes issue permissions under.

use alloy_primitives::U256;

use super::contracts::IVoucherKeyRegistry;
use super::{Block, Chain, ChainError, Rpc, required, unix_time};
use crate::id::{Epoch, StarId, UnixTime};

/// What a Control Plane committed to, on chain, for one window's permission
/// key — before it could know who would ask for permissions under it.
///
/// A client checks the key the Control Plane hands it against this before
/// blinding anything: a key made for one client alone would mark every
/// permission signed under it as that client's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PermissionKeyCommitment {
    /// keccak-256 of the key's DER encoding followed by the packet size as
    /// four bytes big-endian.
    pub key_hash: [u8; 32],
    /// How many permissions a packet under this key carries, and so how many
    /// sessions a subscription may hold at once. (The contract still calls
    /// it `denominationGB`, from before packets.)
    pub packet_size: u32,
    /// When the commitment was made.
    pub set_at: UnixTime,
    /// Whether the issuer still holds the Control Plane role.
    pub issuer_active: bool,
}

impl<R: Rpc> Chain<R> {
    /// `issuer`'s commitment for `window`, or `None` if it made none.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn permission_key_commitment(
        &self,
        issuer: StarId,
        window: Epoch,
    ) -> Result<Option<PermissionKeyCommitment>, ChainError> {
        let registry = required(
            self.deployment.contracts.permission_key_registry,
            "VoucherKeyRegistry",
        )?;
        let k = self
            .read(
                registry,
                IVoucherKeyRegistry::getEpochKeyCall {
                    issuerStarId: U256::from(issuer.0),
                    epoch: U256::from(window.0),
                },
                Block::Latest,
                "getEpochKey",
            )
            .await?;
        if k.keyHash.is_zero() {
            return Ok(None);
        }
        Ok(Some(PermissionKeyCommitment {
            key_hash: k.keyHash.0,
            packet_size: k.denominationGB,
            set_at: unix_time(k.setAt, "getEpochKey")?,
            issuer_active: k.issuerActive,
        }))
    }
}
