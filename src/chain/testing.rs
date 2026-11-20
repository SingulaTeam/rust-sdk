//! An in-memory chain for tests.

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_sol_types::SolCall;

use super::rpc::{Block, Header, Log, LogFilter, Rpc, RpcError};
use crate::id::{Address, UnixTime};

/// Answers calls from a table, and records which blocks were asked for.
pub(crate) struct MockRpc {
    pub(crate) chain_id: u64,
    pub(crate) block: u64,
    answers: HashMap<(Address, Vec<u8>), Vec<u8>>,
    pub(crate) blocks_seen: Mutex<Vec<Block>>,
    /// The finalized block; `block` (the tip) unless set.
    pub(crate) finalized: Option<u64>,
    /// Every log on the chain, in log order.
    pub(crate) logs: Vec<(Address, Log)>,
    /// The widest span `logs` answers; wider is refused as nodes do.
    pub(crate) max_span: u64,
    /// How many log queries were made.
    pub(crate) log_queries: Mutex<u32>,
}

impl MockRpc {
    pub(crate) fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            block: 1_000,
            answers: HashMap::new(),
            blocks_seen: Mutex::new(Vec::new()),
            finalized: None,
            logs: Vec::new(),
            max_span: u64::MAX,
            log_queries: Mutex::new(0),
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

    fn header(&self, block: Block) -> impl Future<Output = Result<Header, RpcError>> + Send {
        let number = match block {
            Block::Number(n) => n,
            Block::Finalized => self.finalized.unwrap_or(self.block),
            _ => self.block,
        };
        std::future::ready(Ok(Self::header_of(number)))
    }

    fn logs(&self, filter: &LogFilter) -> impl Future<Output = Result<Vec<Log>, RpcError>> + Send {
        if let Ok(mut n) = self.log_queries.lock() {
            *n += 1;
        }
        // As Arbitrum's public node: a hundredth of the span for a query
        // with more than one value per topic.
        let max_span = if filter.events.len() > 1 {
            self.max_span / 100
        } else {
            self.max_span
        };
        if filter.to.saturating_sub(filter.from) >= max_span {
            return std::future::ready(Err(RpcError::Node {
                code: -32_005,
                message: "query exceeds max block range".to_owned(),
            }));
        }
        let found = self
            .logs
            .iter()
            .filter(|(at, l)| {
                *at == filter.address
                    && (filter.from..=filter.to).contains(&l.block)
                    && l.topics.first().is_some_and(|t| filter.events.contains(t))
            })
            .map(|(_, l)| l.clone())
            .collect();
        std::future::ready(Ok(found))
    }
}

impl MockRpc {
    /// Block `n`: hashed as its number, one second per block from 1000.
    pub(crate) fn header_of(n: u64) -> Header {
        let mut hash = [0; 32];
        hash[24..].copy_from_slice(&n.to_be_bytes());
        Header::new(
            n,
            hash,
            UnixTime(1_000 + i64::try_from(n).unwrap_or(i64::MAX)),
        )
    }

    /// Emits `topics`/`data` from `address` in block `block`.
    pub(crate) fn emit(
        &mut self,
        address: Address,
        block: u64,
        topics: Vec<[u8; 32]>,
        data: Vec<u8>,
    ) {
        let index = self.logs.iter().filter(|(_, l)| l.block == block).count() as u64;
        let hash = Self::header_of(block).hash;
        self.logs
            .push((address, Log::new(block, hash, index, topics, data)));
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
