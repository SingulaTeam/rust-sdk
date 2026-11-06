//! The transport `chain` reads through.

use std::future::Future;

use crate::id::Address;

/// Which state a read is made against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    /// The newest block the node knows.
    Latest,
    /// A fixed block, so several reads see one consistent state.
    Number(u64),
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
