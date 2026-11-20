//! The transport `chain` reads through.

use std::future::Future;

use crate::id::{Address, UnixTime};

/// Which state a read is made against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block {
    /// The newest block the node knows.
    Latest,
    /// The newest block the chain calls finalized: on Arbitrum, one whose
    /// batch Ethereum has finalized. What every reader agrees on for good.
    Finalized,
    /// A fixed block, so several reads see one consistent state.
    Number(u64),
}

/// What a block is: its number, hash and timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// The block's number.
    pub number: u64,
    /// The block's hash.
    pub hash: [u8; 32],
    /// The block's timestamp.
    pub timestamp: UnixTime,
}

impl Header {
    /// A header from its parts.
    #[must_use]
    pub const fn new(number: u64, hash: [u8; 32], timestamp: UnixTime) -> Self {
        Self {
            number,
            hash,
            timestamp,
        }
    }
}

/// Which logs `eth_getLogs` should return: those of one contract, with one
/// of the given first topics (the event's signature), in a range of blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogFilter {
    /// The contract that emitted them.
    pub address: Address,
    /// Any of these as the first topic.
    pub events: Vec<[u8; 32]>,
    /// The first block, inclusive.
    pub from: u64,
    /// The last block, inclusive.
    pub to: u64,
}

impl LogFilter {
    /// Logs of `address` with one of `events` as their first topic, in
    /// blocks `from` to `to`, inclusive.
    #[must_use]
    pub fn new(address: Address, events: Vec<[u8; 32]>, from: u64, to: u64) -> Self {
        Self {
            address,
            events,
            from,
            to,
        }
    }
}

/// An event a contract emitted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Log {
    /// The block it is in.
    pub block: u64,
    /// That block's hash.
    pub block_hash: [u8; 32],
    /// Its position among the block's logs.
    pub index: u64,
    /// Its topics: the event's signature first, then the indexed arguments.
    pub topics: Vec<[u8; 32]>,
    /// Its other arguments, ABI-encoded.
    pub data: Vec<u8>,
}

impl Log {
    /// A log from its parts.
    #[must_use]
    pub fn new(
        block: u64,
        block_hash: [u8; 32],
        index: u64,
        topics: Vec<[u8; 32]>,
        data: Vec<u8>,
    ) -> Self {
        Self {
            block,
            block_hash,
            index,
            topics,
            data,
        }
    }
}

/// A connection to an Ethereum JSON-RPC node.
///
/// [`HttpRpc`](super::HttpRpc) implements it over HTTPS; implement it
/// yourself to read through another transport, a pool of nodes, or a test
/// double.
///
/// # Security
///
/// Everything this crate learns about the network it learns through this
/// connection, so the endpoint must be one the user or the application
/// chose — never one suggested by a Control Plane, which could then answer
/// every question about itself.
pub trait Rpc: Send + Sync {
    /// `eth_chainId`.
    fn chain_id(&self) -> impl Future<Output = Result<u64, RpcError>> + Send;

    /// `eth_blockNumber`.
    fn block_number(&self) -> impl Future<Output = Result<u64, RpcError>> + Send;

    /// `eth_call`: runs `data` against the contract at `to` and returns what
    /// it returned.
    ///
    /// A call that reverts is [`RpcError::Reverted`], with the revert data.
    fn call(
        &self,
        to: Address,
        data: &[u8],
        block: Block,
    ) -> impl Future<Output = Result<Vec<u8>, RpcError>> + Send;

    /// `eth_getBlockByNumber`, without transactions.
    fn header(&self, block: Block) -> impl Future<Output = Result<Header, RpcError>> + Send;

    /// `eth_getLogs`, in log order. Logs the node marks as removed by a
    /// reorganisation are left out.
    ///
    /// Nodes cap the range a query may span; one refused as too wide is an
    /// [`RpcError::Node`], and the caller asks again over less.
    fn logs(&self, filter: &LogFilter) -> impl Future<Output = Result<Vec<Log>, RpcError>> + Send;
}

/// Why a JSON-RPC request failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RpcError {
    /// The node could not be reached, or the connection failed.
    #[error("the RPC node could not be reached")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The node did not answer in time.
    #[error("the RPC node did not answer in time")]
    Timeout,
    /// The call reverted.
    #[error("the call reverted")]
    Reverted(Vec<u8>),
    /// The node answered with a JSON-RPC error.
    #[error("the RPC node refused the request ({code}): {message}")]
    Node {
        /// The JSON-RPC error code.
        code: i64,
        /// The node's message.
        message: String,
    },
    /// The answer was not a well-formed JSON-RPC response.
    #[error("the RPC node's answer is malformed: {0}")]
    Malformed(&'static str),
}
