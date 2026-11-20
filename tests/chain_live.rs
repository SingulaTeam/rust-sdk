//! Reads from the live test network.
//!
//! Ignored by default: it needs a network connection and an RPC endpoint.
//! Run it with
//!
//! ```text
//! SINGULA_RPC_URL=https://… cargo test --features http,zk --test chain_live -- --ignored
//! ```

// A failed expectation here is a failed test, with its reason attached.
#![allow(clippy::expect_used)]

use singula::chain::{Chain, HttpRpc, Network, Role};

async fn connect() -> Chain<HttpRpc> {
    let url = std::env::var("SINGULA_RPC_URL")
        .expect("SINGULA_RPC_URL names an Arbitrum Sepolia RPC endpoint");
    let rpc = HttpRpc::new(&url).expect("a valid RPC URL");
    Chain::connect(rpc, Network::ARBITRUM_SEPOLIA)
        .await
        .expect("the directory is readable")
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn every_listed_control_plane_is_a_control_plane() {
    let chain = connect().await;
    let cps = chain
        .control_planes()
        .await
        .expect("the endpoint registry is readable");
    assert!(!cps.is_empty(), "the test network runs Control Planes");
    for cp in cps {
        let star = chain
            .star(cp.star)
            .await
            .expect("readable")
            .expect("a listed Star exists");
        assert_eq!(star.role, Role::ControlPlane, "{cp:?}");
        assert_eq!(
            chain.star_by_signer(star.signer).await.expect("readable"),
            Some(cp.star)
        );
    }
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn the_subscriber_set_builds_a_group() {
    let chain = connect().await;
    let version = chain.circuit_version().await.expect("readable");
    assert!(version.starts_with("semaphore/4."), "{version}");
    let commitments = chain.subscriber_commitments().await.expect("readable");
    let group = chain
        .subscriber_group()
        .await
        .expect("the set is a valid group");
    assert_eq!(group.len(), commitments.len());
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn the_registry_history_ends_in_the_listed_control_planes() {
    let chain = connect().await;
    let mut history = singula::chain::RegistryHistory::new();
    history
        .refresh(&chain)
        .await
        .expect("the registry's log is readable");
    let latest = history.versions().expect("versions").latest().clone();
    let listed = chain.control_planes().await.expect("readable");
    for cp in listed {
        let signer = chain
            .star(cp.star)
            .await
            .expect("readable")
            .expect("exists")
            .signer;
        assert!(
            latest.control_planes.contains(&(cp.star, signer)),
            "listed Control Plane {} with its signer is in the latest version",
            cp.star
        );
    }
}

#[tokio::test]
#[ignore = "needs the network and SINGULA_RPC_URL"]
async fn the_subscriber_log_reads_every_leaf() {
    let chain = connect().await;
    let mut log = singula::chain::SubscriberLog::new();
    log.refresh(&chain)
        .await
        .expect("the registry's log is readable");
    let on_chain = chain.subscriber_commitments().await.expect("readable");
    assert_eq!(
        log.leaves().len(),
        on_chain.len(),
        "one leaf per commitment slot"
    );
    for (leaf, now) in log.leaves().iter().zip(&on_chain) {
        assert!(
            *now == leaf.commitment || *now == [0; 32],
            "a leaf is as inserted, or removed since"
        );
        assert!(leaf.expires_at > leaf.inserted_at);
    }
}
