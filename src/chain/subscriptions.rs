//! Orbit, the subscription NFT.

use alloy_primitives::U256;

use super::contracts::ISubscriptionNFT;
use super::{Block, Chain, ChainError, Rpc, required, to_alloy, to_u64, unix_time};
use crate::id::{Address, UnixTime};

/// An Orbit token's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId(pub u64);

/// A transaction's hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxHash(pub [u8; 32]);

impl std::str::FromStr for TxHash {
    type Err = ChainError;

    /// Reads `0x` and 64 hex digits.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            alloy_primitives::hex::decode(s).map_err(|_| ChainError::Decode("transaction hash"))?;
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| ChainError::Decode("transaction hash"))
    }
}

impl std::fmt::Display for TxHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", crate::hex::lower(&self.0))
    }
}

impl std::fmt::Debug for TxHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TxHash({self})")
    }
}

/// One subscription a wallet holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Subscription {
    /// The Orbit token.
    pub token: TokenId,
    /// When its time starts; `None` until it is activated. Later than its
    /// activation when it was activated while another of the holder's still
    /// ran: subscriptions stack, each starting where the last one ends.
    pub starts_at: Option<UnixTime>,
    /// When it lapses; `None` until it is activated.
    pub expires_at: Option<UnixTime>,
    /// Whether it entitles its holder to service now, or is queued to.
    pub active: bool,
    /// How many concurrent sessions it pays for, 1 to 5: one per price paid.
    /// It joins the anonymity set with one identity per slot.
    pub slots: u8,
}

impl<R: Rpc> Chain<R> {
    /// The subscriptions `owner` holds, read against one block.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if a read fails.
    pub async fn subscriptions(&self, owner: Address) -> Result<Vec<Subscription>, ChainError> {
        let nft = required(self.deployment.contracts.subscriptions, "SubscriptionNFT")?;
        let block = Block::Number(self.rpc.block_number().await?);
        let owner = to_alloy(owner);
        let count = self
            .read(
                nft,
                ISubscriptionNFT::balanceOfCall { owner },
                block,
                "balanceOf",
            )
            .await?;
        let count = to_u64(count, "balanceOf")?;

        let mut out = Vec::new();
        for index in 0..count {
            let id = self
                .read(
                    nft,
                    ISubscriptionNFT::tokenOfOwnerByIndexCall {
                        owner,
                        index: U256::from(index),
                    },
                    block,
                    "tokenOfOwnerByIndex",
                )
                .await?;
            let expires = self
                .read(
                    nft,
                    ISubscriptionNFT::expiresAtCall { tokenId: id },
                    block,
                    "expiresAt",
                )
                .await?;
            let starts = self
                .read(
                    nft,
                    ISubscriptionNFT::activatedAtCall { tokenId: id },
                    block,
                    "activatedAt",
                )
                .await?;
            let active = self
                .read(
                    nft,
                    ISubscriptionNFT::isTokenActiveCall { tokenId: id },
                    block,
                    "isTokenActive",
                )
                .await?;
            let slots = self
                .read(
                    nft,
                    ISubscriptionNFT::slotsOfCall { tokenId: id },
                    block,
                    "slotsOf",
                )
                .await?;
            out.push(Subscription {
                token: TokenId(to_u64(id, "tokenOfOwnerByIndex")?),
                starts_at: match to_u64(starts, "activatedAt")? {
                    0 => None,
                    at => Some(unix_time(at, "activatedAt")?),
                },
                expires_at: match to_u64(expires, "expiresAt")? {
                    0 => None,
                    at => Some(unix_time(at, "expiresAt")?),
                },
                active,
                slots,
            });
        }
        Ok(out)
    }

    /// What adding `extra` slots to `token` costs now, in USDC's smallest
    /// unit: one price per slot for the part of its term left.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails, as it does for an Orbit that
    /// has ended or would pass five slots.
    pub async fn add_slots_cost(&self, token: TokenId, extra: u8) -> Result<u128, ChainError> {
        let nft = required(self.deployment.contracts.subscriptions, "SubscriptionNFT")?;
        let block = Block::Number(self.rpc.block_number().await?);
        let cost = self
            .read(
                nft,
                ISubscriptionNFT::addSlotsCostCall {
                    tokenId: U256::from(token.0),
                    extra,
                },
                block,
                "addSlotsCost",
            )
            .await?;
        u128::try_from(cost).map_err(|_| ChainError::Decode("addSlotsCost"))
    }

    /// How many slots `token` has: concurrent sessions it pays for, and
    /// identities it may join the set with.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn slots_of(&self, token: TokenId) -> Result<u8, ChainError> {
        let nft = required(self.deployment.contracts.subscriptions, "SubscriptionNFT")?;
        let block = Block::Number(self.rpc.block_number().await?);
        self.read(
            nft,
            ISubscriptionNFT::slotsOfCall {
                tokenId: U256::from(token.0),
            },
            block,
            "slotsOf",
        )
        .await
    }
}
