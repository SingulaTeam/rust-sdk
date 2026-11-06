//! An in-memory chain for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_sol_types::SolCall;

use super::rpc::{Block, Rpc, RpcError};
use crate::id::Address;

/// Answers calls from a table, and records which blocks were asked for.
pub(crate) struct MockRpc {
    pub(crate) chain_id: u64,
    pub(crate) block: u64,
    answers: HashMap<(Address, Vec<u8>), Vec<u8>>,
    pub(crate) blocks_seen: Mutex<Vec<Block>>,
}

impl MockRpc {
    pub(crate) fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            block: 1_000,
            answers: HashMap::new(),
            blocks_seen: Mutex::new(Vec::new()),
        }
    }

    /// Answer `call` on `to` with `ret`, encoded as the function returns it.
    pub(crate) fn answer<C: SolCall>(&mut self, to: Address, call: &C, ret: &C::Return) {
        self.answers
            .insert((to, call.abi_encode()), C::abi_encode_returns(ret));
    }

    /// Answer `call` on `to` with raw bytes.
    pub(crate) fn answer_raw<C: SolCall>(&mut self, to: Address, call: &C, raw: Vec<u8>) {
        self.answers.insert((to, call.abi_encode()), raw);
    }
}

impl MockRpc {
    /// A chain whose directory answers as Arbitrum Sepolia's did.
    pub(crate) fn sepolia() -> Self {
        let mut rpc = Self::new(super::Network::ARBITRUM_SEPOLIA.chain_id);
        let snapshot =
            alloy_primitives::hex::decode(include_str!("snapshot-arbitrum-sepolia.hex").trim())
                .unwrap_or_default();
        rpc.answer_raw(
            super::Network::ARBITRUM_SEPOLIA.directory,
            &super::contracts::ISingulaProtocol::snapshotCall {},
            snapshot,
        );
        rpc
    }
}

impl Rpc for MockRpc {
    fn chain_id(&self) -> impl Future<Output = Result<u64, RpcError>> + Send {
        std::future::ready(Ok(self.chain_id))
    }

    fn block_number(&self) -> impl Future<Output = Result<u64, RpcError>> + Send {
        std::future::ready(Ok(self.block))
    }

    fn call(
        &self,
        to: Address,
        data: &[u8],
        block: Block,
    ) -> impl Future<Output = Result<Vec<u8>, RpcError>> + Send {
        std::future::ready(self.respond(to, data, block))
    }
}

impl MockRpc {
    /// What `call` answers: the canned reply, after noting the block asked at.
    fn respond(&self, to: Address, data: &[u8], block: Block) -> Result<Vec<u8>, RpcError> {
        self.blocks_seen
            .lock()
            .map_err(|_| RpcError::Malformed("poisoned"))?
            .push(block);
        self.answers
            .get(&(to, data.to_vec()))
            .cloned()
            .ok_or_else(|| RpcError::Reverted(Vec::new()))
    }
}
