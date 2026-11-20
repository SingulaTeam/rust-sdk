//! Every client call, against the Control Plane in `testing`.

use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::SolCall as _;

use super::testing::{self, CP, MockCp, NODE, NODE_ADDRESS, TX, addr, alloy, window};
use super::wallet::{LocalWallet, Wallet as _};
use super::{
    ClientError, ControlPlaneClient, GovernanceAction, Participant, SessionRequest, Traffic,
    TunnelSettings, Vote, WalletAuth,
};
use crate::chain::contracts::{
    IEip712, IGasStation, IProtocolGovernor, ISingulaProtocol, IStarRegistry, ISubscriberRegistry,
    ISubscriptionNFT,
};
use crate::chain::testing::MockRpc;
use crate::chain::{Chain, Network, Payment, TokenId, TxHash, fee_ceiling};
use crate::id::{Address, Epoch};
use crate::zk::{FieldElement, Group, Identity, Prover};

/// The gas fee `GasStation` quotes in these tests, whatever the operation.
const GAS_FEE: u64 = 10u64.pow(17);

/// A Control Plane, and a chain that knows about it, its node and `wallet`.
async fn setup(wallet: Address) -> (MockCp, ControlPlaneClient, Chain<MockRpc>) {
    setup_with_slots(wallet, 1).await
}

/// As [`setup`], with the test identity's first `slots` slots in the set.
async fn setup_with_slots(
    wallet: Address,
    slots: u8,
) -> (MockCp, ControlPlaneClient, Chain<MockRpc>) {
    let cp = MockCp::new();
    let client = cp.serve().await;
    let node_signer = crate::eth::address_of(cp.state().node_signer.verifying_key());

    let mut rpc = MockRpc::sepolia();
    let stars = addr("0xced082443d1787e8014d2747f463ff9f2888447c");
    rpc.answer(
        stars,
        &IStarRegistry::getStarCall {
            starId: U256::from(NODE.0),
        },
        &IStarRegistry::StarInfo {
            owner: alloy(wallet),
            signer: alloy(node_signer),
            role: 1,
            registerEpoch: 1,
        },
    );
    for (name, contract) in [
        ("SingulaSubscriberRegistry", testing::REGISTRY),
        ("SingulaSubscription", testing::NFT),
        ("Singula USDC", testing::USDC),
        ("SingulaGovernor", testing::GOVERNOR),
    ] {
        rpc.answer(
            addr(contract),
            &IEip712::eip712DomainCall {},
            &IEip712::eip712DomainReturn {
                fields: FixedBytes([0x0f]),
                name: name.into(),
                version: "1".into(),
                chainId: U256::from(testing::CHAIN_ID),
                verifyingContract: alloy(addr(contract)),
                salt: FixedBytes::ZERO,
                extensions: Vec::new(),
            },
        );
        rpc.answer(
            addr(contract),
            &IEip712::noncesCall {
                owner: alloy(wallet),
            },
            &U256::ZERO,
        );
    }
    let nft = addr(testing::NFT);
    rpc.answer(
        nft,
        &ISubscriptionNFT::mintNoncesCall {
            wallet: alloy(wallet),
        },
        &U256::ZERO,
    );
    answer_prices(&mut rpc, nft);
    answer_gas_fees(&mut rpc);
    rpc.answer(
        addr(testing::STATION),
        &IGasStation::noncesCall {
            signer: alloy(wallet),
        },
        &U256::ZERO,
    );
    answer_the_set(&mut rpc, slots);
    answer_the_journal(&mut rpc, &cp, slots);
    let mut governor_name = [0u8; 32];
    governor_name[..16].copy_from_slice(b"ProtocolGovernor");
    rpc.answer(
        Network::ARBITRUM_SEPOLIA.directory,
        &ISingulaProtocol::contractForCall {
            name: FixedBytes(governor_name),
        },
        &alloy(addr(testing::GOVERNOR)),
    );

    let chain = Chain::connect(rpc, Network::ARBITRUM_SEPOLIA)
        .await
        .expect("connects");
    (cp, client, chain)
}

/// `GAS_FEE` for every purchase the tests make.
fn answer_gas_fees(rpc: &mut MockRpc) {
    for (op, k) in [
        (&b"MINT"[..], 1u8),
        (b"MINT", 3),
        (b"MINT", 6),
        (b"ADD_SLOTS", 2),
    ] {
        let mut name = [0u8; 32];
        name[..op.len()].copy_from_slice(op);
        rpc.answer(
            addr(testing::STATION),
            &IGasStation::gasFeeCall {
                op: FixedBytes(name),
                k: U256::from(k),
            },
            &U256::from(GAS_FEE),
        );
    }
}

/// What the subscription contract quotes: a price, a discounted purchase of
/// three slots, and two slots added to Orbit 11.
fn answer_prices(rpc: &mut MockRpc, nft: Address) {
    rpc.answer(
        nft,
        &ISubscriptionNFT::priceUSDCCall {},
        &U256::from(10u64.pow(19)),
    );
    // A discounted price, unlike three times the one above: what the wallet
    // signs is the contract's own figure for the purchase.
    rpc.answer(
        nft,
        &ISubscriptionNFT::mintCostCall { slots: 3 },
        &U256::from(27 * 10u128.pow(18)),
    );
    rpc.answer(
        nft,
        &ISubscriptionNFT::addSlotsCostCall {
            tokenId: U256::from(11),
            extra: 2,
        },
        &U256::from(10u64.pow(19)),
    );
}

/// A purchase of three slots is signed at the contract's discounted price for
/// it, not three full prices, with the gas fee and its room on top.
fn assert_signed_the_quoted_price(cp: &MockCp) {
    assert_eq!(
        cp.state().mint_ceilings,
        [U256::from(
            27 * 10u128.pow(18) + fee_ceiling(u128::from(GAS_FEE))
        )]
    );
}

/// The anonymity set: three strangers and the test identity's first `slots`
/// slots.
fn answer_the_set(rpc: &mut MockRpc, slots: u8) {
    let (identity, _) = member();
    let members: Vec<U256> =
        [111u64, 222, 333]
            .into_iter()
            .map(U256::from)
            .chain((0..slots).map(|slot| {
                U256::from_be_bytes(identity.for_slot(slot).commitment().to_be_bytes())
            }))
            .collect();
    let registry = addr(testing::REGISTRY);
    rpc.answer(
        registry,
        &ISubscriberRegistry::totalCommitmentsCall {},
        &U256::from(members.len()),
    );
    rpc.answer(
        registry,
        &ISubscriberRegistry::commitmentsSliceCall {
            start: U256::ZERO,
            count: U256::from(500),
        },
        &members,
    );
}

/// The chain the journal reads: the test identity's slots registered long
/// ago for an Orbit that outlasts the tests, and the test federation's
/// Control Planes in `StarRegistry`. The tip is now, so today's tree and
/// tomorrow's can both be built.
fn answer_the_journal(rpc: &mut MockRpc, cp: &MockCp, slots: u8) {
    use alloy_sol_types::SolEvent as _;
    let emit = |rpc: &mut MockRpc, at: Address, block: u64, data: alloy_primitives::LogData| {
        let topics = data.topics().iter().map(|t| t.0).collect();
        rpc.emit(at, block, topics, data.data.to_vec());
    };
    for name in ["starRegistryFromBlock", "subscriberRegistryFromBlock"] {
        let mut key = [0u8; 32];
        key[..name.len()].copy_from_slice(name.as_bytes());
        rpc.answer(
            Network::ARBITRUM_SEPOLIA.directory,
            &ISingulaProtocol::paramCall {
                name: FixedBytes(key),
            },
            &U256::ZERO,
        );
    }
    let (identity, _) = member();
    let leaves: Vec<U256> =
        [111u64, 222, 333]
            .into_iter()
            .map(U256::from)
            .chain((0..slots).map(|slot| {
                U256::from_be_bytes(identity.for_slot(slot).commitment().to_be_bytes())
            }))
            .collect();
    for (index, commitment) in leaves.into_iter().enumerate() {
        let registered = ISubscriberRegistry::Registered {
            index: U256::from(index),
            tokenId: U256::from(1),
            commitment,
        };
        emit(
            rpc,
            addr(testing::REGISTRY),
            3,
            registered.encode_log_data(),
        );
    }
    rpc.answer(
        addr(testing::NFT),
        &ISubscriptionNFT::expiresAtCall {
            tokenId: U256::from(1),
        },
        &U256::from(4_000_000_000u64),
    );

    let stars = addr("0xced082443d1787e8014d2747f463ff9f2888447c");
    let members = cp.state().journal.members();
    for (id, signer) in &members {
        let created = IStarRegistry::StarRegistered {
            starId: U256::from(id.0),
            owner: alloy(addr("0x00000000000000000000000000000000000000ee")),
            signer: alloy(*signer),
        };
        emit(rpc, stars, 2, created.encode_log_data());
        let promoted = IStarRegistry::RoleForced {
            starId: U256::from(id.0),
            oldRole: 1,
            newRole: 2,
            withSlashing: false,
        };
        emit(rpc, stars, 2, promoted.encode_log_data());
    }
    rpc.times.insert(2, 1_000);
    rpc.times.insert(3, 1_000);
    rpc.block = 10;
    rpc.times
        .insert(10, crate::id::UnixTime::now().0 + 2 * 86_400);
    let version = crate::journal::RegistryVersion::new(
        crate::journal::RegistryVersionId::new(
            testing::CHAIN_ID,
            stars,
            2,
            &MockRpc::header_of(2).hash,
        ),
        2,
        crate::id::UnixTime(1_000),
        members,
    );
    cp.state().journal.recorded_as(version);
}

/// An identity, and a group it belongs to.
fn member() -> (Identity, Group) {
    let identity =
        Identity::from_secret("0x08207bd92786697f8bed5caf78eda4d3b78fbc3326eb624744b966e7f94f5f59")
            .expect("a secret");
    let members: Vec<FieldElement> = ["111", "222", "333"]
        .iter()
        .map(|m| m.parse().expect("an element"))
        .chain([identity.commitment()])
        .collect();
    (identity, Group::new(&members).expect("a group"))
}

#[tokio::test]
async fn lists_what_the_control_plane_serves() {
    let (_, cp, _) = setup(Address([1; 20])).await;
    let nodes = cp.list_nodes().await.expect("answers");
    assert_eq!(
        (nodes[0].star, nodes[0].country.map(|c| c.to_string())),
        (NODE, Some("DE".to_owned()))
    );
    assert_eq!(cp.list_countries().await.expect("answers")[0].nodes, 1);
    assert!(cp.health().await.expect("answers").healthy);
    assert_eq!(cp.network_info().await.expect("answers").chain_id, 421_614);
}

#[tokio::test]
async fn refuses_credentials_from_a_node_other_than_the_registered_one() {
    let wallet = LocalWallet::random();
    let (cp_state, cp, chain) = setup(wallet.address()).await;
    // The relaying Control Plane swaps in a node key of its own.
    cp_state.state().node_signer = crate::eth::random_key();
    let auth = WalletAuth::sign(&wallet, CP).await.expect("signs");
    let result = cp.open_session(&chain, SessionRequest::wallet(auth)).await;
    assert!(
        matches!(result, Err(ClientError::Open(crate::OpenError::WrongNode))),
        "{result:?}"
    );
}

#[tokio::test]
async fn runs_a_wallet_session_and_ends_it() {
    let wallet = LocalWallet::random();
    let (cp_state, cp, chain) = setup(wallet.address()).await;
    let auth = WalletAuth::sign(&wallet, CP).await.expect("signs");

    let subscription = cp.subscription(&auth).await.expect("signs in");
    assert_eq!(
        (subscription.active, subscription.token),
        (true, Some(TokenId(11)))
    );

    let mut session = cp
        .open_session(&chain, SessionRequest::wallet(auth.clone()))
        .await
        .expect("opens");
    assert_eq!(session.wallet(), Some(wallet.address()));
    cp.report(&mut session, Traffic { up: 1, down: 2 })
        .await
        .expect("accepted");
    let id = session.id().to_string();
    cp.end_session(&auth, session, Traffic { up: 1, down: 2 })
        .await
        .expect("ends");
    assert_eq!(cp_state.state().ended, [id]);
}

#[tokio::test]
async fn refuses_a_sign_in_for_another_control_plane() {
    let wallet = LocalWallet::random();
    let (_, cp, _) = setup(wallet.address()).await;
    let auth = WalletAuth::sign(&wallet, crate::StarId(9))
        .await
        .expect("signs");
    assert!(matches!(
        cp.subscription(&auth).await,
        Err(ClientError::Mismatch(_))
    ));
}

#[tokio::test]
async fn relays_registration_activation_mint_and_faucet() {
    let wallet = LocalWallet::random();
    let (cp_state, cp, chain) = setup(wallet.address()).await;
    let auth = WalletAuth::sign(&wallet, CP).await.expect("signs");
    let tx: TxHash = TX.parse().expect("a hash");

    let (identity, _) = member();
    let registered = cp
        .register_commitment(
            &chain,
            &wallet,
            &auth,
            TokenId(11),
            &[identity.commitment()],
        )
        .await;
    assert_eq!(registered.expect("relayed"), tx);
    // An Orbit with two slots joins with two identities.
    let second = identity.for_slot(1);
    let activated = cp
        .activate(
            &chain,
            &wallet,
            &auth,
            TokenId(11),
            &[identity.commitment(), second.commitment()],
        )
        .await
        .expect("relayed");
    assert_eq!(activated.tx, tx);
    assert_eq!(
        cp_state.state().joined,
        [
            identity.commitment().to_be_bytes(),
            second.commitment().to_be_bytes()
        ],
        "joined on activation"
    );
    cp.activate(&chain, &wallet, &auth, TokenId(12), &[])
        .await
        .expect("relayed without joining");
    assert_eq!(cp_state.state().joined.len(), 2);
    assert!(matches!(
        cp.mint(&chain, &wallet, &auth, Payment::Usdc, 6).await,
        Err(ClientError::Mismatch(_))
    ));
    let minted = cp
        .mint(&chain, &wallet, &auth, Payment::Usdc, 3)
        .await
        .expect("relayed");
    assert_eq!(minted.token, TokenId(12));
    assert_signed_the_quoted_price(&cp_state);
    let funded = cp
        .faucet(&chain, &wallet, &auth, 100 * 10u128.pow(18))
        .await
        .expect("relayed");
    assert_eq!(funded, tx);
    // Two more slots for Orbit 11, with the identities of slots 2 and 3.
    let added = cp
        .add_slots(
            &chain,
            &wallet,
            &auth,
            TokenId(11),
            2,
            &[
                identity.for_slot(2).commitment(),
                identity.for_slot(3).commitment(),
            ],
        )
        .await
        .expect("relayed");
    assert_eq!(added, tx);
    assert_eq!(cp_state.state().joined.len(), 4);

    assert_eq!(
        cp_state.state().relayed,
        [
            "register",
            "activate",
            "activate",
            "mint",
            "faucet",
            "add_slots"
        ]
    );
}

#[tokio::test]
async fn relays_governance_signed_by_the_wallet() {
    let wallet = LocalWallet::random();
    let (cp_state, cp, chain) = setup(wallet.address()).await;
    let tx: TxHash = TX.parse().expect("a hash");

    let propose = GovernanceAction::Propose {
        parameter: "accessQuotaPerEpoch".into(),
        value: 30,
        title: "More openings".into(),
        text: "Phones reconnect a lot".into(),
    };
    let proposed = cp
        .governance(&chain, &wallet, &Participant::Subscriber, &propose)
        .await
        .expect("relayed");
    assert_eq!(proposed, tx);
    let vote = GovernanceAction::Vote {
        proposal: 1,
        vote: Vote::For,
        reason: "as proposed".into(),
    };
    let stars = Participant::Stars(vec![NODE]);
    cp.governance(&chain, &wallet, &stars, &vote)
        .await
        .expect("relayed");

    let s = cp_state.state();
    assert_eq!(s.relayed, ["governance", "governance"]);
    let p =
        IProtocolGovernor::proposeAsSubscriberCall::abi_decode(&s.governed[0]).expect("a proposal");
    assert_eq!(&p.key.0[..19], b"accessQuotaPerEpoch");
    assert_eq!(p.value, U256::from(30));
    assert_eq!(p.text, "Phones reconnect a lot");
    let v = IProtocolGovernor::voteAsStarCall::abi_decode(&s.governed[1]).expect("a vote");
    assert_eq!(v.starIds, [U256::from(NODE.0)]);
    assert_eq!(v.choice, U256::from(1));
}

#[tokio::test]
async fn refuses_to_relay_for_a_wallet_other_than_the_signed_in_one() {
    let wallet = LocalWallet::random();
    let (_, cp, chain) = setup(wallet.address()).await;
    let auth = WalletAuth::sign(&LocalWallet::random(), CP)
        .await
        .expect("signs");
    let result = cp.activate(&chain, &wallet, &auth, TokenId(11), &[]).await;
    assert!(
        matches!(result, Err(ClientError::Mismatch(_))),
        "{result:?}"
    );
}

// ── The whole client ─────────────────────────────────────────────────────

/// A client over the mock chain and Control Plane, with the test identity
/// already kept for `wallet`.
async fn singula(
    wallet: &LocalWallet,
) -> (MockCp, super::Singula<MockRpc, super::store::MemoryStore>) {
    singula_with_slots(wallet, 1).await
}

/// As [`singula`], for an Orbit with `slots` slots, all in the set.
async fn singula_with_slots(
    wallet: &LocalWallet,
    slots: u8,
) -> (MockCp, super::Singula<MockRpc, super::store::MemoryStore>) {
    let (cp_state, cp, chain) = setup_with_slots(wallet.address(), slots).await;
    let store = super::store::MemoryStore::new();
    let (identity, _) = member();
    super::records::Records(&store)
        .keep_identity(wallet.address(), &identity)
        .await
        .expect("keeps");
    let prover = Prover::new().expect("the circuit loads");
    (
        cp_state,
        super::Singula::new(chain, prover, store).with_control_plane(cp),
    )
}

/// Pings and reports every tick, and renews almost at once: the session the
/// mock opens runs for an hour.
fn quick() -> super::Timing {
    super::Timing {
        ping_every: std::time::Duration::from_millis(100),
        report_every: std::time::Duration::from_millis(100),
        renew_ahead: std::time::Duration::from_secs(3_599),
        renew_retry: std::time::Duration::from_millis(100),
    }
}

/// Reads events until `want` matches one, failing on an end.
async fn until(conn: &mut super::Connection, want: impl Fn(&super::Event) -> bool) {
    let waiting = async {
        while let Some(event) = conn.next_event().await {
            if want(&event) {
                return;
            }
            assert!(
                !matches!(event, super::Event::Ended(_)),
                "ended early: {event:?}"
            );
        }
        panic!("the connection stopped sending events");
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), waiting)
        .await
        .expect("in time");
}

#[tokio::test]
async fn ends_a_session_whose_answer_it_refused() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let options = || super::ConnectOptions::new().control_plane(CP);

    // The Control Plane admits the session, but the node's answer is not
    // signed, so the client refuses it — and ends it, with its own key.
    cp_state.state().unsigned_credentials = true;
    let refused = singula.connect(&wallet, options(), Traffic::default).await;
    assert!(
        matches!(&refused, Err(ClientError::NodeAnswer { node, error })
            if *node == NODE && matches!(**error, ClientError::Open(_))),
        "{refused:?}"
    );
    assert_eq!(
        cp_state.state().ended.len(),
        1,
        "the refused session is ended"
    );

    // The day's right is kept: the next session opens on it at once.
    cp_state.state().unsigned_credentials = false;
    let conn = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects again");
    assert_eq!(
        cp_state.state().journal.rights.len(),
        1,
        "one right for the day"
    );
    conn.close().await;
}

#[tokio::test]
async fn a_session_on_a_right_pings_until_closed_then_ends_with_its_own_key() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let options = super::ConnectOptions::new()
        .control_plane(CP)
        .timing(quick());
    let mut conn = singula
        .connect(&wallet, options, || Traffic { up: 10, down: 20 })
        .await
        .expect("connects");
    assert_eq!(
        (conn.node(), conn.tunnel().address.as_str()),
        (NODE, NODE_ADDRESS)
    );
    until(
        &mut conn,
        |e| matches!(e, super::Event::Pinged { control_plane, .. } if *control_plane == CP),
    )
    .await;
    until(&mut conn, |e| matches!(e, super::Event::Pinged { .. })).await;

    let id = conn.id().to_string();
    let pinged = cp_state.state().journal.pings.len();
    conn.close().await;
    let s = cp_state.state();
    assert_eq!(s.journal.opened_on_right, 1);
    assert!(
        s.journal.pings.len() > pinged,
        "a last ping on close, so its seconds count"
    );
    assert!(
        s.journal.pings.windows(2).all(|w| w[0].total <= w[1].total),
        "totals never go back"
    );
    assert_eq!(s.ended, [id], "ended, not left to expire");
}

#[tokio::test]
async fn pings_move_to_a_control_plane_that_shows_a_majority() {
    // One that reaches none, and one that claims one it does not have.
    for failing in [testing::Acks::Short, testing::Acks::Forged] {
        let wallet = LocalWallet::random();
        let (cp_state, singula) = singula(&wallet).await;
        // A second Control Plane of the same federation.
        let other = MockCp::new();
        other.state().journal = cp_state.state().journal.clone();
        let other_star = crate::id::StarId(9);
        let singula = singula.with_control_plane(other.serve_as(other_star).await);

        let options = super::ConnectOptions::new()
            .control_plane(CP)
            .timing(quick());
        let mut conn = singula
            .connect(&wallet, options, Traffic::default)
            .await
            .expect("connects");
        until(
            &mut conn,
            |e| matches!(e, super::Event::Pinged { control_plane, .. } if *control_plane == CP),
        )
        .await;

        other.state().journal.rights = cp_state.state().journal.rights.clone();
        cp_state.state().journal.acks = failing;
        until(&mut conn, |e| {
            matches!(e, super::Event::Pinged { control_plane, .. } if *control_plane == other_star)
        })
        .await;
        conn.close().await;
    }
}

#[tokio::test]
async fn ends_when_the_network_closes_it_and_leaves_a_busy_slot() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula_with_slots(&wallet, 2).await;
    let options = || {
        super::ConnectOptions::new()
            .control_plane(CP)
            .timing(quick())
    };
    let mut conn = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects");
    let first = cp_state
        .state()
        .journal
        .rights
        .keys()
        .copied()
        .collect::<Vec<_>>();
    // Another device holds the slot: the Control Plane closes this session.
    cp_state
        .state()
        .journal
        .statuses
        .insert(conn.id().to_string(), (2, "overlap".into()));
    let ended = async {
        while let Some(event) = conn.next_event().await {
            if let super::Event::Ended(reason) = event {
                return reason;
            }
        }
        panic!("the connection stopped without ending");
    };
    let reason = tokio::time::timeout(std::time::Duration::from_secs(10), ended)
        .await
        .expect("in time");
    assert_eq!(
        reason,
        super::EndReason::ClosedByNetwork(crate::journal::CloseReason::Overlap)
    );

    // The next session takes the other slot.
    let next = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects");
    let rights = cp_state.state().journal.rights.clone();
    assert_eq!(rights.len(), 2, "a second slot's right");
    assert!(rights.keys().any(|n| !first.contains(n)));
    next.close().await;
}

#[tokio::test]
async fn carries_a_session_past_midnight_on_the_next_days_right() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let end = epoch_start(window() + 1);
    let time = testing::ManualTime::at(crate::id::UnixTime(end.0 - 30));
    cp_state.state().clock = Some(time.clone());
    let singula = singula.with_time(time.clone());

    let options = super::ConnectOptions::new()
        .control_plane(CP)
        .timing(quick());
    let mut conn = singula
        .connect(&wallet, options, Traffic::default)
        .await
        .expect("connects");
    until(&mut conn, |e| matches!(e, super::Event::Pinged { .. })).await;

    // A minute and more past midnight, the next day's right takes over.
    time.set(crate::id::UnixTime(end.0 + 61));
    until(
        &mut conn,
        |e| matches!(e, super::Event::Pinged { total, .. } if *total < 30),
    )
    .await;
    let (last, rights) = {
        let s = cp_state.state();
        (
            s.journal.pings.last().cloned().expect("pings"),
            s.journal.rights.len(),
        )
    };
    assert_eq!(
        last.window,
        Epoch(window() + 1),
        "under the new day's right"
    );
    assert_eq!(rights, 2, "today's right and tomorrow's");
    assert_eq!(
        last.session.to_string(),
        conn.id().to_string(),
        "the same session"
    );
    conn.close().await;
}

#[tokio::test]
async fn a_wallet_session_ends_at_the_control_plane_on_close() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let options = super::ConnectOptions::new()
        .control_plane(CP)
        .access(super::Access::Wallet);
    let conn = singula
        .connect(&wallet, options, Traffic::default)
        .await
        .expect("connects");
    let id = conn.id().to_string();
    conn.close().await;
    assert_eq!(cp_state.state().ended, [id]);
}

#[tokio::test]
async fn refuses_an_identity_outside_the_set() {
    let wallet = LocalWallet::random();
    let (_, singula) = singula(&wallet).await;
    // Another wallet: its identity is derived on the spot, and nobody registered it.
    let stranger = LocalWallet::random();
    let result = singula
        .connect(
            &stranger,
            super::ConnectOptions::new().control_plane(CP),
            Traffic::default,
        )
        .await;
    assert!(
        matches!(result, Err(ClientError::NotRegistered)),
        "{result:?}"
    );
}

/// When epoch `w` begins on the test network.
fn epoch_start(w: u64) -> crate::id::UnixTime {
    let clock = crate::chain::Clock {
        epoch_zero: crate::id::UnixTime(1_780_417_577),
        epoch_length: std::time::Duration::from_secs(86_400),
    };
    clock.epoch_start(Epoch(w)).expect("in range")
}

#[tokio::test]
async fn ends_when_renewal_is_refused_until_expiry() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let time = testing::ManualTime::at(crate::id::UnixTime::now());
    cp_state.state().clock = Some(time.clone());
    let singula = singula.with_time(time.clone());

    let options = super::ConnectOptions::new()
        .control_plane(CP)
        .access(super::Access::Wallet)
        .timing(quick());
    let mut conn = singula
        .connect(&wallet, options, Traffic::default)
        .await
        .expect("connects");
    cp_state.state().refuse_renewals = true;
    until(&mut conn, |e| matches!(e, super::Event::RenewalFailed(_))).await;

    // An hour on, the session has run out.
    time.set(crate::id::UnixTime(crate::id::UnixTime::now().0 + 3_601));
    let ended = async {
        while let Some(event) = conn.next_event().await {
            if let super::Event::Ended(reason) = event {
                return reason;
            }
        }
        panic!("the connection stopped without ending");
    };
    let reason = tokio::time::timeout(std::time::Duration::from_secs(10), ended)
        .await
        .expect("in time");
    assert_eq!(reason, super::EndReason::Expired);
}

#[tokio::test]
async fn refuses_an_endpoint_that_changes_what_the_url_means() {
    use std::net::IpAddr;

    use crate::chain::ControlPlane;
    use crate::id::UnixTime;

    let cp = |host: &str| ControlPlane {
        star: CP,
        host: host.to_owned(),
        port: None,
        updated_at: UnixTime(0),
        reality_key: None,
    };
    let here = [IpAddr::from([127, 0, 0, 1])];
    assert!(ControlPlaneClient::new(&cp("cp.example")).is_ok());
    assert!(ControlPlaneClient::at(&cp("cp.example"), &here).is_ok());
    for host in [
        "",
        "cp.example/path",
        "user@cp.example",
        "cp.example?q",
        "cp example",
    ] {
        assert!(
            matches!(
                ControlPlaneClient::new(&cp(host)),
                Err(ClientError::Endpoint)
            ),
            "{host:?}"
        );
        assert!(
            matches!(
                ControlPlaneClient::at(&cp(host), &here),
                Err(ClientError::Endpoint)
            ),
            "{host:?}"
        );
    }
    assert!(
        matches!(
            ControlPlaneClient::at(&cp("cp.example"), &[]),
            Err(ClientError::Endpoint)
        ),
        "an address is needed to connect to"
    );
}

#[tokio::test]
async fn reaches_a_control_plane_through_a_transport_the_application_gives() {
    let port = MockCp::new().listen().await;
    // The application's tunnel, played by a plain connection.
    let cp = ControlPlaneClient::through(CP, move || {
        tokio::net::TcpStream::connect(("127.0.0.1", port))
    });
    assert!(cp.health().await.expect("answers").healthy);
}

// ── The shared journal ──────────────────────────────────────────────────────

mod journal {
    use std::sync::Arc;

    use super::*;
    use crate::client::testing::Acks;
    use crate::id::{SessionId, StarId, UnixTime};
    use crate::journal::{
        AckError, CloseReason, JournalParams, Nullifier, Ping, Right, RightKey, SessionStatus,
    };

    const PARAMS: JournalParams = JournalParams::new(testing::CHAIN_ID);

    /// A right of the test identity's day, with its key. The test Control
    /// Plane checks the key's signatures, not the proof.
    fn right(nullifier: u8) -> (Right, Arc<RightKey>) {
        let key = RightKey::derive(&[nullifier; 32], PARAMS, Epoch(window())).expect("derives");
        let right = Right::new(
            Epoch(window()),
            0,
            Nullifier([nullifier; 32]),
            key.public_key(),
            [[0; 32]; 8],
        );
        (right, Arc::new(key))
    }

    fn ping(
        right: &Right,
        key: &RightKey,
        session: &SessionId,
        total: u64,
    ) -> crate::journal::SignedPing {
        key.sign_ping(
            PARAMS,
            Ping::new(right.window, right.nullifier, session.clone(), NODE, total),
        )
    }

    #[tokio::test]
    async fn opens_a_session_on_a_right() {
        let wallet = LocalWallet::random().address();
        let (mock, cp, chain) = setup(wallet).await;
        let (right, key) = right(5);
        let session = cp
            .open_session(&chain, SessionRequest::on_right(right.clone(), key, PARAMS))
            .await
            .expect("the right opens a session");
        let tunnel = TunnelSettings::decode(session.credentials()).expect("decodes");
        assert_eq!(tunnel.address, NODE_ADDRESS);
        let s = mock.state();
        assert_eq!(s.journal.opened_on_right, 1);
        assert!(s.journal.rights.contains_key(&right.nullifier.0));
    }

    #[tokio::test]
    async fn refuses_a_challenge_naming_another_control_plane() {
        let wallet = LocalWallet::random().address();
        let (mock, cp, chain) = setup(wallet).await;
        mock.state().journal.challenge_names = StarId(99);
        let (right, key) = right(5);
        let result = cp
            .open_session(&chain, SessionRequest::on_right(right, key, PARAMS))
            .await;
        assert!(
            matches!(result, Err(ClientError::Untrusted(_))),
            "{result:?}"
        );
        assert_eq!(
            mock.state().journal.opened_on_right,
            0,
            "nothing was signed for it"
        );
    }

    #[tokio::test]
    async fn a_ping_is_committed_by_a_checked_majority() {
        let wallet = LocalWallet::random().address();
        let (mock, cp, chain) = setup(wallet).await;
        let (right, key) = right(5);
        let session = cp
            .open_session(
                &chain,
                SessionRequest::on_right(right.clone(), Arc::clone(&key), PARAMS),
            )
            .await
            .expect("opens");
        let versions = mock.state().journal.versions();
        let signed = ping(&right, &key, session.id(), 300);
        let traffic = Traffic { up: 10, down: 20 };

        let ack = cp
            .ping(PARAMS, &signed, traffic, None)
            .await
            .expect("taken");
        let committed = ack
            .committed(&versions, PARAMS, UnixTime::now())
            .expect("a majority");
        assert_eq!(committed.version, versions.latest().id);
        assert_eq!(
            mock.state().journal.pings.last().map(|p| p.total),
            Some(300)
        );

        mock.state().journal.acks = Acks::Short;
        let ack = cp
            .ping(PARAMS, &signed, traffic, None)
            .await
            .expect("taken");
        assert!(matches!(
            ack.committed(&versions, PARAMS, UnixTime::now()),
            Err(AckError::NoQuorum { .. })
        ));

        mock.state().journal.acks = Acks::Forged;
        let ack = cp
            .ping(PARAMS, &signed, traffic, None)
            .await
            .expect("taken");
        assert!(matches!(
            ack.committed(&versions, PARAMS, UnixTime::now()),
            Err(AckError::BadAttestation(_))
        ));

        mock.state().journal.acks = Acks::OtherPing;
        let result = cp.ping(PARAMS, &signed, traffic, None).await;
        assert!(
            matches!(result, Err(ClientError::Untrusted(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_new_days_right_travels_with_its_first_ping() {
        let wallet = LocalWallet::random().address();
        let (mock, cp, chain) = setup(wallet).await;
        let (today, key) = right(5);
        let session = cp
            .open_session(&chain, SessionRequest::on_right(today, key, PARAMS))
            .await
            .expect("opens");
        let (tomorrow, next_key) = right(6);
        let first = ping(&tomorrow, &next_key, session.id(), 30);

        let refused = cp.ping(PARAMS, &first, Traffic::default(), None).await;
        assert!(
            matches!(refused, Err(ClientError::Refused { .. })),
            "an unknown right's ping"
        );
        cp.ping(PARAMS, &first, Traffic::default(), Some(&tomorrow))
            .await
            .expect("taken with its right");
        assert!(
            mock.state()
                .journal
                .rights
                .contains_key(&tomorrow.nullifier.0)
        );
    }

    #[tokio::test]
    async fn says_why_a_session_closed() {
        let wallet = LocalWallet::random().address();
        let (mock, cp, _) = setup(wallet).await;
        let open: SessionId = "8f14e45f-ceea-467f-a8d5-000000000001"
            .parse()
            .expect("an id");
        let closed: SessionId = "8f14e45f-ceea-467f-a8d5-000000000002"
            .parse()
            .expect("an id");
        let unknown: SessionId = "8f14e45f-ceea-467f-a8d5-000000000003"
            .parse()
            .expect("an id");
        {
            let mut s = mock.state();
            s.journal
                .statuses
                .insert(open.to_string(), (1, String::new()));
            s.journal
                .statuses
                .insert(closed.to_string(), (2, "overlap".into()));
        }
        assert!(matches!(
            cp.session_status(&open).await,
            Ok(SessionStatus::Open { .. })
        ));
        assert_eq!(
            cp.session_status(&closed).await.expect("answers"),
            SessionStatus::Closed(CloseReason::Overlap)
        );
        assert_eq!(
            cp.session_status(&unknown).await.expect("answers"),
            SessionStatus::Unknown
        );
    }
}

/// Every long-running call can be spawned on a multi-threaded runtime, as an
/// application keeping a session in the background does.
#[tokio::test]
async fn connections_and_calls_can_be_spawned() {
    fn send<T: Send>(_: &T) {}
    let wallet = LocalWallet::random();
    let (_, singula) = singula(&wallet).await;
    send(&singula.connect(&wallet, super::ConnectOptions::new(), Traffic::default));
    send(&singula.choose_control_plane());
    send(&singula.identities(&wallet));
    let (_, cp, chain) = setup(wallet.address()).await;
    let auth = WalletAuth::sign(&wallet, CP).await.expect("signs");
    send(&cp.open_session(&chain, SessionRequest::wallet(auth)));
}

#[tokio::test]
async fn each_of_a_clients_sessions_takes_its_own_slot() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula_with_slots(&wallet, 2).await;
    let options = || {
        super::ConnectOptions::new()
            .control_plane(CP)
            .timing(quick())
    };

    // Two hops of a route, say: two slots, two rights.
    let first = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects");
    let second = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects on the other slot");
    assert_eq!(cp_state.state().journal.rights.len(), 2, "a right per slot");

    // A third has no slot to go on, rather than opening one to be closed.
    let third = singula.connect(&wallet, options(), Traffic::default).await;
    assert!(matches!(third, Err(ClientError::NoFreeSlot)), "{third:?}");

    // A slot given back is taken again.
    first.close().await;
    let again = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects on the slot given back");
    assert_eq!(
        cp_state.state().journal.rights.len(),
        2,
        "no new right: the day's is kept"
    );
    again.close().await;
    second.close().await;
}
