//! Calls to a live Control Plane on the test network.
//!
//! Ignored by default: they need a network connection and an RPC endpoint.
//! Run them with
//!
//! ```text
//! SINGULA_RPC_URL=https://… cargo test --features client,http --test client_live -- --ignored
//! ```

// A failed expectation here is a failed test, with its reason attached.
#![allow(clippy::expect_used)]

use singula::chain::{Chain, HttpRpc, Network, Role};
use singula::client::ControlPlaneClient;

async fn setup() -> (Chain<HttpRpc>, ControlPlaneClient) {
    let url = std::env::var("SINGULA_RPC_URL")
        .expect("SINGULA_RPC_URL names an Arbitrum Sepolia RPC endpoint");
    let chain = Chain::connect(
        HttpRpc::new(&url).expect("a valid RPC URL"),
        Network::ARBITRUM_SEPOLIA,
    )
    .await
    .expect("the directory is readable");
    let cps = chain
        .control_planes()
        .await
        .expect("the endpoint registry is readable");
    let cp = cps.first().expect("the test network runs a Control Plane");
    (
        chain,
        ControlPlaneClient::new(cp).expect("a usable endpoint"),
    )
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn lists_nodes_that_are_nodes_on_chain() {
    let (chain, cp) = setup().await;
    let nodes = cp.list_nodes().await.expect("the Control Plane answers");
    for node in nodes {
        let star = chain
            .star(node.star)
            .await
            .expect("readable")
            .expect("a listed node is registered");
        assert_eq!(star.role, Role::Node, "{node:?}");
    }
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn the_control_plane_knows_nothing_of_a_session_it_never_held() {
    let (_, cp) = setup().await;
    let id: singula::SessionId = "00000000-0000-4000-8000-000000000000"
        .parse()
        .expect("a session id");
    let status = cp.session_status(&id).await.expect("answers");
    assert_eq!(status, singula::journal::SessionStatus::Unknown);
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn the_control_plane_reports_its_health_and_network() {
    let (chain, cp) = setup().await;
    let health = cp.health().await.expect("the Control Plane answers");
    let skew = (health.time.0 - singula::UnixTime::now().0).abs();
    assert!(skew < 300, "the Control Plane's clock is {skew} s off");
    let info = cp.network_info().await.expect("the Control Plane answers");
    assert_eq!(info.chain_id, chain.deployment().chain_id);
    assert_eq!(
        info.subscriptions,
        chain.deployment().contracts.subscriptions
    );
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn a_new_wallet_can_sign_in() {
    use singula::client::WalletAuth;
    use singula::client::wallet::LocalWallet;

    let (_, cp) = setup().await;
    // A wallet with no subscription: the Control Plane still accepts the
    // sign-in, so that it can relay the wallet's first purchase.
    let wallet = LocalWallet::random();
    let auth = WalletAuth::sign(&wallet, cp.star()).await.expect("signs");
    let subscription = cp
        .subscription(&auth)
        .await
        .expect("the sign-in is accepted");
    assert!(!subscription.active);
}
