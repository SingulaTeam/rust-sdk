//! Open an anonymous session and keep it running.
//!
//! ```text
//! SINGULA_RPC_URL=https://… cargo run --example connect --features client,http
//! ```
//!
//! The wallet here is a fresh key with no subscription, so this stops at
//! "not in the anonymity set" unless you give it a subscriber's key: buy and
//! activate first, with `Singula::mint` and `Singula::activate`.

// An example's output is what it prints; the library itself never does.
#![allow(clippy::print_stderr)]

use singula::chain::{Chain, HttpRpc, Network};
use singula::client::store::FileStore;
use singula::client::wallet::LocalWallet;
use singula::client::{ConnectOptions, Singula, Traffic};
use singula::zk::Prover;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("SINGULA_RPC_URL")?;
    let chain = Chain::connect(HttpRpc::new(&url)?, Network::ARBITRUM_SEPOLIA).await?;
    let singula = Singula::new(chain, Prover::new()?, FileStore::new("./singula-data")?);

    let wallet = LocalWallet::random();
    // Read your tunnel engine's counters for this session here.
    let meter = || Traffic { up: 0, down: 0 };

    let mut conn = singula
        .connect(&wallet, ConnectOptions::new(), meter)
        .await?;
    let tunnel = conn.tunnel();
    eprintln!("node {} at {}:{}", conn.node(), tunnel.address, tunnel.port);

    // Reports and renewals happen on their own; these are what they did.
    while let Some(event) = conn.next_event().await {
        eprintln!("{event:?}");
    }
    Ok(())
}
