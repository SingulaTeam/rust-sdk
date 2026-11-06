//! What a subscription costs, and what a wallet can pay with.

use alloy_primitives::{FixedBytes, U256};

use super::contracts::{IErc20, IGasStation, ISubscriptionNFT};
use super::{Block, Chain, ChainError, Rpc, required, to_alloy};
use crate::id::Address;

/// A token a subscription can be paid in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Payment {
    /// The stablecoin.
    Usdc,
    /// ECHO, at the contract's discount — when the contract accepts it.
    Echo,
}

/// A gasless purchase whose gas it pays for itself, in USDC, on top of its
/// price: the gas of the purchase and of what follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GasOp {
    /// Buying an Orbit, then activating it and joining the set with one
    /// identity per slot.
    Purchase,
    /// Adding slots to an Orbit, their identities included.
    AddSlots,
}

impl GasOp {
    /// The name `GasStation` prices it under, as a `bytes32` string.
    fn name(self) -> FixedBytes<32> {
        let name: &[u8] = match self {
            Self::Purchase => b"MINT",
            Self::AddSlots => b"ADD_SLOTS",
        };
        let mut word = [0u8; 32];
        word[..name.len()].copy_from_slice(name);
        FixedBytes(word)
    }
}

/// What a wallet signs for a gas fee it has been quoted: half as much again.
/// Gas prices move between signing and the relay; the contract takes the fee
/// at the moment it runs, never more than this.
#[must_use]
pub fn fee_ceiling(fee: u128) -> u128 {
    fee.saturating_add(fee / 2)
}

impl<R: Rpc> Chain<R> {
    /// The gas fee of `op` with `slots` slots, in USDC's smallest unit, at
    /// today's gas and ETH prices. Charged only on the gasless path.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn gas_fee(&self, op: GasOp, slots: u8) -> Result<u128, ChainError> {
        let station = required(self.deployment.contracts.gas_station, "GasStation")?;
        let fee = self
            .read(
                station,
                IGasStation::gasFeeCall {
                    op: op.name(),
                    k: U256::from(slots),
                },
                Block::Latest,
                "gasFee",
            )
            .await?;
        u128::try_from(fee).map_err(|_| ChainError::OutOfRange("gasFee"))
    }

    /// What one subscription costs in `payment`, in the token's smallest
    /// unit, or `None` if the contract does not accept that token now.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if a read fails.
    pub async fn subscription_price(&self, payment: Payment) -> Result<Option<u128>, ChainError> {
        let nft = required(self.deployment.contracts.subscriptions, "SubscriptionNFT")?;
        let block = Block::Number(self.rpc.block_number().await?);
        let price = match payment {
            Payment::Usdc => {
                self.read(nft, ISubscriptionNFT::priceUSDCCall {}, block, "priceUSDC")
                    .await?
            }
            Payment::Echo => {
                let enabled = self
                    .read(
                        nft,
                        ISubscriptionNFT::echoMintingEnabledCall {},
                        block,
                        "echoMintingEnabled",
                    )
                    .await?;
                if !enabled {
                    return Ok(None);
                }
                let full = self
                    .read(nft, ISubscriptionNFT::priceEchoCall {}, block, "priceEcho")
                    .await?;
                let discount = self
                    .read(
                        nft,
                        ISubscriptionNFT::echoDiscountCall {},
                        block,
                        "echoDiscount",
                    )
                    .await?;
                // The contract's own arithmetic, rounding included.
                let hundred = U256::from(100);
                full.checked_mul(
                    hundred
                        .checked_sub(discount)
                        .ok_or(ChainError::OutOfRange("echoDiscount"))?,
                )
                .ok_or(ChainError::OutOfRange("priceEcho"))?
                    / hundred
            }
        };
        u128::try_from(price)
            .map(Some)
            .map_err(|_| ChainError::OutOfRange("price"))
    }

    /// What an Orbit of `slots` slots costs in USDC now, in its smallest
    /// unit: `slots` prices less the running promotion's discount, if any —
    /// the contract's own figure for this purchase, which is not always
    /// `slots` times the price of one, since a campaign may have the
    /// allowance for a one-slot discount and not for a larger one. The gas
    /// fee is not in it ([`Chain::gas_fee`]).
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails, which it does for a count
    /// outside 1 to 5, the most slots one Orbit carries.
    pub async fn mint_cost(&self, slots: u8) -> Result<u128, ChainError> {
        let nft = required(self.deployment.contracts.subscriptions, "SubscriptionNFT")?;
        let cost = self
            .read(
                nft,
                ISubscriptionNFT::mintCostCall { slots },
                Block::Latest,
                "mintCost",
            )
            .await?;
        u128::try_from(cost).map_err(|_| ChainError::OutOfRange("mintCost"))
    }

    /// `owner`'s balance of `payment`, in the token's smallest unit.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn balance(&self, owner: Address, payment: Payment) -> Result<u128, ChainError> {
        let token = self.payment_token(payment)?;
        let balance = self
            .read(
                token,
                IErc20::balanceOfCall {
                    owner: to_alloy(owner),
                },
                Block::Latest,
                "balanceOf",
            )
            .await?;
        u128::try_from(balance).map_err(|_| ChainError::OutOfRange("balanceOf"))
    }

    /// The contract of the token `payment` names.
    pub(crate) fn payment_token(&self, payment: Payment) -> Result<Address, ChainError> {
        match payment {
            Payment::Usdc => required(self.deployment.contracts.usdc_token, "USDC"),
            Payment::Echo => required(self.deployment.contracts.echo_token, "EchoToken"),
        }
    }

    /// How many subscriptions `owner` holds but has not activated.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn unactivated_subscriptions(&self, owner: Address) -> Result<u64, ChainError> {
        let nft = required(self.deployment.contracts.subscriptions, "SubscriptionNFT")?;
        let n = self
            .read(
                nft,
                ISubscriptionNFT::unactivatedCountCall {
                    wallet: to_alloy(owner),
                },
                Block::Latest,
                "unactivatedCount",
            )
            .await?;
        super::to_u64(n, "unactivatedCount")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_operations_as_gas_station_does() {
        let mut mint = [0u8; 32];
        mint[..4].copy_from_slice(b"MINT");
        assert_eq!(GasOp::Purchase.name(), FixedBytes(mint));
        let mut add = [0u8; 32];
        add[..9].copy_from_slice(b"ADD_SLOTS");
        assert_eq!(GasOp::AddSlots.name(), FixedBytes(add));
    }

    #[test]
    fn signs_for_half_as_much_again() {
        assert_eq!(fee_ceiling(100), 150);
        assert_eq!(fee_ceiling(u128::MAX), u128::MAX);
    }
}
