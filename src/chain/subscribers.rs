//! The anonymity set: subscribers' identity commitments.

use alloy_primitives::U256;

use super::contracts::ISubscriberRegistry;
use super::{Block, Chain, ChainError, Rpc, required, to_u64};

/// Commitments per call. Small enough for any RPC node's response limit,
/// large enough that the set loads in few round trips.
const PAGE: u64 = 500;

impl<R: Rpc> Chain<R> {
    /// Every commitment in the registry, in insertion order, as 32 bytes
    /// big-endian; zero where a member was removed.
    ///
    /// The pages are all read against one block, so the set is one the chain
    /// actually held, never a mix of two.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if a read fails or the registry answers
    /// inconsistently.
    pub async fn subscriber_commitments(&self) -> Result<Vec<[u8; 32]>, ChainError> {
        let registry = required(
            self.deployment.contracts.subscriber_registry,
            "SubscriberRegistry",
        )?;
        let block = Block::Number(self.rpc.block_number().await?);
        let total = self
            .read(
                registry,
                ISubscriberRegistry::totalCommitmentsCall {},
                block,
                "totalCommitments",
            )
            .await?;
        let total = to_u64(total, "totalCommitments")?;

        let mut out = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
        let mut start = 0;
        while start < total {
            let page = self
                .read(
                    registry,
                    ISubscriberRegistry::commitmentsSliceCall {
                        start: U256::from(start),
                        count: U256::from(PAGE),
                    },
                    block,
                    "commitmentsSlice",
                )
                .await?;
            // Against a fixed block every page but the last is full; anything
            // else means the node is not answering for that block.
            let expected = PAGE.min(total - start);
            if page.len() as u64 != expected {
                return Err(ChainError::Decode("commitmentsSlice"));
            }
            out.extend(page.iter().map(U256::to_be_bytes::<32>));
            start += expected;
        }
        Ok(out)
    }

    /// The circuit release proofs must be built against, such as
    /// `semaphore/4.14.3/16`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn circuit_version(&self) -> Result<String, ChainError> {
        let registry = required(
            self.deployment.contracts.subscriber_registry,
            "SubscriberRegistry",
        )?;
        self.read(
            registry,
            ISubscriberRegistry::circuitVersionCall {},
            Block::Latest,
            "circuitVersion",
        )
        .await
    }

    /// The anonymity set as a [`Group`](crate::zk::Group), ready to prove
    /// membership of.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if a read fails, or if the registry holds a
    /// value that is not a field element or is empty.
    #[cfg(feature = "zk")]
    pub async fn subscriber_group(&self) -> Result<crate::zk::Group, ChainError> {
        let members = self
            .subscriber_commitments()
            .await?
            .iter()
            .map(crate::zk::FieldElement::from_be_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ChainError::OutOfRange("commitmentsSlice"))?;
        crate::zk::Group::new(&members).map_err(|_| ChainError::OutOfRange("totalCommitments"))
    }
}
