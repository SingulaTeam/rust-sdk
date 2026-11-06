//! What a wallet needs from the chain to sign for a relayed transaction: the
//! contracts' EIP-712 domains, and the nonces each signature must carry.

use alloy_primitives::U256;
use alloy_sol_types::Eip712Domain;

use super::contracts::{IEip712, IGasStation, ISubscriptionNFT};
use super::{Block, Chain, ChainError, Rpc, required, to_alloy};
use crate::id::Address;

/// The `fields` bits EIP-5267 sets for name, version, chain id and verifying
/// contract — the four every domain here uses, and nothing else.
const NAME_VERSION_CHAIN_CONTRACT: u8 = 0x0f;

impl<R: Rpc> Chain<R> {
    /// `contract`'s EIP-712 domain, as it reports it.
    ///
    /// Read rather than written into the SDK, and checked: a domain naming
    /// another chain or another contract would yield signatures the contract
    /// refuses, after the wallet had been asked to sign.
    pub(crate) async fn eip712_domain(
        &self,
        contract: Address,
    ) -> Result<Eip712Domain, ChainError> {
        let d = self
            .read(
                contract,
                IEip712::eip712DomainCall {},
                Block::Latest,
                "eip712Domain",
            )
            .await?;
        if d.fields.0 != [NAME_VERSION_CHAIN_CONTRACT]
            || d.chainId != U256::from(self.deployment.chain_id)
            || d.verifyingContract != to_alloy(contract)
        {
            return Err(ChainError::OutOfRange("eip712Domain"));
        }
        Ok(Eip712Domain::new(
            Some(d.name.into()),
            Some(d.version.into()),
            Some(d.chainId),
            Some(d.verifyingContract),
            None,
        ))
    }

    /// `contract.nonces(owner)`: the next nonce a signature for `owner` must
    /// carry, for every contract here that counts them that way.
    pub(crate) async fn nonce(
        &self,
        contract: Address,
        owner: Address,
    ) -> Result<U256, ChainError> {
        self.read(
            contract,
            IEip712::noncesCall {
                owner: to_alloy(owner),
            },
            Block::Latest,
            "nonces",
        )
        .await
    }

    /// The next nonce of `wallet`'s mint intents, counted apart from its
    /// other signatures.
    pub(crate) async fn mint_nonce(&self, wallet: Address) -> Result<U256, ChainError> {
        let nft = required(self.deployment.contracts.subscriptions, "SubscriptionNFT")?;
        self.read(
            nft,
            ISubscriptionNFT::mintNoncesCall {
                wallet: to_alloy(wallet),
            },
            Block::Latest,
            "mintNonces",
        )
        .await
    }

    /// The next nonce of `signer`'s gas-relay requests.
    pub(crate) async fn relay_nonce(&self, signer: Address) -> Result<U256, ChainError> {
        let station = required(self.deployment.contracts.gas_station, "GasStation")?;
        self.read(
            station,
            IGasStation::noncesCall {
                signer: to_alloy(signer),
            },
            Block::Latest,
            "nonces",
        )
        .await
    }
}
