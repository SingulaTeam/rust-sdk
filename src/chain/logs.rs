//! Reading a contract's events over spans the node accepts.

use super::rpc::{Log, LogFilter, RpcError};
use super::{Chain, ChainError, Rpc};
use crate::id::Address;

/// The span of one log query to begin with. Endpoints cap it, each its own
/// way — Arbitrum's public one at ten million blocks for one address — so
/// a refused span is halved, down to [`MIN_SPAN`].
const FIRST_SPAN: u64 = 10_000_000;

/// The narrowest span tried before a refusal is taken as final.
const MIN_SPAN: u64 = 1_000;

impl<R: Rpc> Chain<R> {
    /// The events of `address` with one of `events` as their first topic,
    /// in blocks `from` to `to`, in log order.
    ///
    /// Each event is asked for on its own and the answers merged: nodes allow
    /// a far wider span for a query with one value per topic — Arbitrum's
    /// public one ten million blocks against a hundred thousand.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::Rpc`] if a query fails for any reason other
    /// than its span, or still fails at the narrowest span.
    pub(crate) async fn logs_between(
        &self,
        address: Address,
        events: &[[u8; 32]],
        from: u64,
        to: u64,
    ) -> Result<Vec<Log>, ChainError> {
        let mut out = Vec::new();
        for event in events {
            out.extend(self.event_logs(address, *event, from, to).await?);
        }
        out.sort_by_key(|l| (l.block, l.index));
        Ok(out)
    }

    /// One event's logs over `from` to `to`, in spans the node accepts.
    async fn event_logs(
        &self,
        address: Address,
        event: [u8; 32],
        from: u64,
        to: u64,
    ) -> Result<Vec<Log>, ChainError> {
        let mut out = Vec::new();
        let mut span = FIRST_SPAN;
        let mut next = from;
        while next <= to {
            let end = to.min(next.saturating_add(span - 1));
            let filter = LogFilter::new(address, vec![event], next, end);
            match self.rpc.logs(&filter).await {
                Ok(logs) => {
                    out.extend(logs);
                    next = end + 1;
                }
                Err(e) if too_wide(&e) && span > MIN_SPAN => span = (span / 2).max(MIN_SPAN),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(out)
    }
}

/// Whether a node refused a log query for its span, or for an answer too
/// large to take: both are cured by asking over less.
fn too_wide(e: &RpcError) -> bool {
    match e {
        RpcError::Malformed(reason) => reason.contains("too large"),
        RpcError::Node { message, .. } => {
            let m = message.to_lowercase();
            ["range", "blocks", "too many", "limit", "exceed"]
                .iter()
                .any(|s| m.contains(s))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::MockRpc;
    use super::*;

    #[tokio::test]
    async fn a_refused_span_is_read_in_halves() {
        let mut rpc = MockRpc::sepolia();
        let at = Address([7; 20]);
        rpc.block = 40_000_000;
        rpc.max_span = 3_000_000;
        rpc.emit(at, 5, vec![[1; 32]], vec![]);
        rpc.emit(at, 39_999_999, vec![[1; 32]], vec![]);
        rpc.emit(at, 20_000_000, vec![[2; 32]], vec![]); // another event
        let chain = Chain::connect(rpc, super::super::Network::ARBITRUM_SEPOLIA)
            .await
            .unwrap_or_else(|_| unreachable!());
        let logs = chain
            .logs_between(at, &[[1; 32]], 0, 40_000_000)
            .await
            .unwrap_or_default();
        assert_eq!(
            logs.iter().map(|l| l.block).collect::<Vec<_>>(),
            [5, 39_999_999]
        );
    }

    #[tokio::test]
    async fn events_asked_for_apart_come_back_in_log_order() {
        let mut rpc = MockRpc::sepolia();
        let at = Address([7; 20]);
        rpc.emit(at, 5, vec![[2; 32]], vec![]);
        rpc.emit(at, 5, vec![[1; 32]], vec![]);
        rpc.emit(at, 3, vec![[1; 32]], vec![]);
        let chain = Chain::connect(rpc, super::super::Network::ARBITRUM_SEPOLIA)
            .await
            .unwrap_or_else(|_| unreachable!());
        let logs = chain
            .logs_between(at, &[[1; 32], [2; 32]], 0, 10)
            .await
            .unwrap_or_default();
        let order: Vec<_> = logs
            .iter()
            .map(|l| (l.block, l.index, l.topics[0][0]))
            .collect();
        assert_eq!(order, [(3, 0, 1), (5, 0, 2), (5, 1, 1)]);
    }

    #[test]
    fn knows_a_span_refusal_from_other_errors() {
        let node = |m: &str| RpcError::Node {
            code: -32_000,
            message: m.to_owned(),
        };
        assert!(too_wide(&node("query exceeds max block range 10000")));
        assert!(too_wide(&RpcError::Malformed("response too large")));
        assert!(!too_wide(&node("execution reverted")));
        assert!(!too_wide(&RpcError::Timeout));
    }
}
