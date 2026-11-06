//! Every client call, against the Control Plane in `testing`.

use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::SolCall as _;
use blind_rsa_signatures::SecretKeySha384PSSRandomized;
use sha3::{Digest as _, Keccak256};

use super::testing::{self, CP, MockCp, NODE, NODE_ADDRESS, PACKET_SIZE, TX, addr, alloy, window};
use super::wallet::{LocalWallet, Wallet as _};
use super::{
    ClientError, ControlPlaneClient, GovernanceAction, Participant, SessionRequest, Traffic,
    TunnelSettings, Vote, WalletAuth,
};
use crate::chain::contracts::{
    IEip712, IGasStation, IProtocolGovernor, ISingulaProtocol, IStarRegistry, ISubscriberRegistry,
    ISubscriptionNFT, IVoucherKeyRegistry,
};
use crate::chain::testing::MockRpc;
use crate::chain::{Chain, Network, Payment, TokenId, TxHash, fee_ceiling};
use crate::id::{Address, Epoch};
use crate::zk::{Claim, FieldElement, Group, Identity, Prover};

/// The gas fee `GasStation` quotes in these tests, whatever the operation.
const GAS_FEE: u64 = 10u64.pow(17);

/// The test issuer's key.
fn issuer() -> (Vec<u8>, SecretKeySha384PSSRandomized) {
    testing::issuer_key().clone()
}

/// A Control Plane, and a chain that knows about it, its node and `wallet`.
async fn setup(wallet: Address) -> (MockCp, ControlPlaneClient, Chain<MockRpc>) {
    setup_with_slots(wallet, 1).await
}

/// As [`setup`], with the test identity's first `slots` slots in the set.
async fn setup_with_slots(
    wallet: Address,
    slots: u8,
) -> (MockCp, ControlPlaneClient, Chain<MockRpc>) {
    let (der, secret) = issuer();
    let cp = MockCp::new(der.clone(), secret);
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
    let mut committed = der;
    committed.extend_from_slice(&PACKET_SIZE.to_be_bytes());
    // This window's key and the next one's: the same key, committed for each.
    for w in [window(), window() + 1] {
        rpc.answer(
            addr("0xe88168636f525122c27482f09144759ea281869d"),
            &IVoucherKeyRegistry::getEpochKeyCall {
                issuerStarId: U256::from(CP.0),
                epoch: U256::from(w),
            },
            &IVoucherKeyRegistry::getEpochKeyReturn {
                keyHash: FixedBytes(Keccak256::digest(&committed).into()),
                denominationGB: PACKET_SIZE,
                setAt: 1_760_000_000,
                issuerActive: true,
            },
        );
    }
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
async fn runs_an_anonymous_session_from_permission_to_renewal() {
    let (cp_state, cp, chain) = setup(Address([1; 20])).await;
    let (identity, group) = member();
    let prover = Prover::new().expect("the circuit loads");

    let key = cp
        .issuer_key(&chain)
        .await
        .expect("the key matches its commitment");
    assert_eq!(
        (key.window(), key.packet_size()),
        (Epoch(window()), PACKET_SIZE)
    );
    let permission_proof = prover
        .prove(
            &identity,
            &group,
            Claim::Permission {
                window: Epoch(window()),
                index: 1,
            },
        )
        .expect("proves");
    let permission = cp
        .take_permission(&key, 1, &permission_proof)
        .await
        .expect("signs the permission");
    // The index is spent: asking for it again is refused as taken, which
    // is how a device learns another took it.
    let again = cp.take_permission(&key, 1, &permission_proof).await;
    assert!(
        matches!(again, Err(ClientError::PermissionTaken(1))),
        "{again:?}"
    );

    let claim = Claim::Session {
        control_plane: CP,
        epoch: Epoch(window()),
        index: 0,
    };
    let proof = prover.prove(&identity, &group, claim).expect("proves");
    let mut session = cp
        .open_session(
            &chain,
            SessionRequest::anonymous(proof, permission).node(NODE),
        )
        .await
        .expect("opens");
    assert_eq!(
        (session.node(), session.report_to(), session.wallet()),
        (NODE, CP, None)
    );
    let tunnel = TunnelSettings::decode(session.credentials()).expect("decodes");
    assert_eq!((tunnel.address.as_str(), tunnel.port), (NODE_ADDRESS, 443));

    // Two reports in a row: the second only verifies with the nonce the first got back.
    cp.report(
        &mut session,
        Traffic {
            up: 1_000,
            down: 9_000,
        },
    )
    .await
    .expect("accepted");
    cp.report(
        &mut session,
        Traffic {
            up: 2_000,
            down: 18_000,
        },
    )
    .await
    .expect("accepted with the new nonce");

    let renewal_proof = prover
        .prove(
            &identity,
            &group,
            Claim::Permission {
                window: Epoch(window()),
                index: 2,
            },
        )
        .expect("proves");
    let renewal = cp
        .take_permission(&key, 2, &renewal_proof)
        .await
        .expect("signs another");
    let before = session.expires_at();
    cp.renew(&mut session, Some(&renewal))
        .await
        .expect("renews");
    assert!(session.expires_at() > before);
    assert_eq!(
        cp_state.state().permissions_seen,
        2,
        "one to open, one to renew"
    );
}

#[tokio::test]
async fn refuses_a_proof_for_another_control_plane() {
    let (_, cp, chain) = setup(Address([1; 20])).await;
    let (identity, group) = member();
    let prover = Prover::new().expect("the circuit loads");
    let elsewhere = Claim::Session {
        control_plane: crate::StarId(9),
        epoch: Epoch(window()),
        index: 0,
    };
    let proof = prover.prove(&identity, &group, elsewhere).expect("proves");
    let permission = super::Permission {
        issuer: CP,
        window: Epoch(window()),
        prepared_message: Vec::new(),
        signature: Vec::new(),
        issuer_public_key: Vec::new(),
    };
    let result = cp
        .open_session(&chain, SessionRequest::anonymous(proof, permission))
        .await;
    assert!(
        matches!(result, Err(ClientError::Mismatch(_))),
        "{result:?}"
    );
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
    super::ledger::Ledger(&store)
        .keep_identity(wallet.address(), &identity)
        .await
        .expect("keeps");
    let prover = Prover::new().expect("the circuit loads");
    (
        cp_state,
        super::Singula::new(chain, prover, store).with_control_plane(cp),
    )
}

/// Reports every tick, and renews almost at once: the session the mock opens
/// runs for an hour.
fn quick() -> super::Timing {
    super::Timing {
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
async fn connects_reports_renews_and_gives_the_permission_back() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let meter = || Traffic { up: 10, down: 20 };
    let options = super::ConnectOptions::new()
        .control_plane(CP)
        .timing(quick());
    let mut conn = singula
        .connect(&wallet, options, meter)
        .await
        .expect("connects");
    assert_eq!(
        (conn.node(), conn.tunnel().address.as_str()),
        (NODE, NODE_ADDRESS)
    );

    until(&mut conn, |e| matches!(e, super::Event::Reported(_))).await;
    until(&mut conn, |e| matches!(e, super::Event::Renewed { .. })).await;
    assert_eq!(
        cp_state.state().permissions_seen,
        1,
        "renewal inside the window takes none"
    );

    // One permission is taken, and held while the session runs…
    let ledger = singula.ledger();
    let held = ledger
        .permissions(Epoch(window()))
        .await
        .expect("reads")
        .expect("the window's permissions");
    assert_eq!(
        held.permissions
            .iter()
            .filter(|p| p.holder.is_some())
            .count(),
        1
    );
    // …and the one held is kept for minutes past the last report, so it
    // lapses only if the reports stop.
    let kept = held
        .permissions
        .iter()
        .find_map(|p| p.holder.as_ref().and(p.free_at))
        .expect("a hold with a lapse time");
    assert!(kept > crate::id::UnixTime::now().0 + 60, "{kept}");
    conn.close().await;
    // …and free once it is closed.
    let after = ledger
        .permissions(Epoch(window()))
        .await
        .expect("reads")
        .expect("the window's permissions");
    assert!(after.permissions.iter().all(|p| p.holder.is_none()));
}

#[tokio::test]
async fn takes_an_index_per_concurrent_session_and_never_reuses_a_slot() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let options = || super::ConnectOptions::new().control_plane(CP);
    let first = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects");
    let second = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects");
    assert_eq!(
        cp_state.state().permissions_taken,
        2,
        "an index for each session running at once"
    );
    let third = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects");
    // Three permissions, three sessions: the fourth has nothing to hold.
    let fourth = singula.connect(&wallet, options(), Traffic::default).await;
    assert!(
        matches!(fourth, Err(ClientError::NoPermissionFree)),
        "{fourth:?}"
    );
    assert_eq!(cp_state.state().slots_seen, [0, 1, 2]);
    for conn in [first, second, third] {
        conn.close().await;
    }
}

// An Orbit with k slots holds k identities, each with its own permissions:
// k times as many sessions at once, and not one more.
#[tokio::test]
async fn takes_permissions_with_each_slots_identity() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula_with_slots(&wallet, 2).await;
    let options = || super::ConnectOptions::new().control_plane(CP);
    let mut open = Vec::new();
    for _ in 0..2 * PACKET_SIZE {
        open.push(
            singula
                .connect(&wallet, options(), Traffic::default)
                .await
                .expect("connects"),
        );
    }
    let refused = singula.connect(&wallet, options(), Traffic::default).await;
    assert!(
        matches!(refused, Err(ClientError::NoPermissionFree)),
        "{refused:?}"
    );
    let taken = cp_state.state().nullifiers_taken.clone();
    assert_eq!(taken.len(), 6, "three permissions for each identity");
    let mut distinct = taken.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 6, "no permission taken twice");
    for conn in open {
        conn.close().await;
    }
}

#[tokio::test]
async fn shares_the_window_with_the_subscriptions_other_devices() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let options = || super::ConnectOptions::new().control_plane(CP);
    // Another device took two of the three indices.
    {
        let mut s = cp_state.state();
        let w = s.window;
        s.indices_taken = vec![(w, 0), (w, 2)];
    }
    let conn = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects on the index left");
    assert_eq!(
        cp_state.state().permissions_taken,
        1,
        "the taken ones were refused, the free one signed"
    );
    let known = singula
        .ledger()
        .permissions(Epoch(window()))
        .await
        .expect("reads")
        .expect("the window's permissions");
    assert_eq!(
        known
            .permissions
            .iter()
            .map(|p| p.index)
            .collect::<Vec<_>>(),
        [1]
    );
    // Nothing is left for a second session at once.
    let second = singula.connect(&wallet, options(), Traffic::default).await;
    assert!(
        matches!(second, Err(ClientError::NoPermissionFree)),
        "{second:?}"
    );
    conn.close().await;
}

#[tokio::test]
async fn proves_past_the_quota_slots_another_device_used() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    cp_state.state().slots_used_elsewhere = vec![0, 1];
    let conn = singula
        .connect(
            &wallet,
            super::ConnectOptions::new().control_plane(CP),
            Traffic::default,
        )
        .await
        .expect("connects on the first slot left");
    let (seen, taken) = {
        let s = cp_state.state();
        (s.slots_seen.clone(), s.permissions_taken)
    };
    assert_eq!(seen, [2]);
    assert_eq!(taken, 1, "one permission, kept through the retries");
    conn.close().await;
}

#[tokio::test]
async fn ends_a_session_whose_answer_it_refused_and_waits_out_the_hold() {
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

    // Its permission waits out the Control Plane's hold; the next session
    // takes another.
    cp_state.state().unsigned_credentials = false;
    let conn = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects on the next permission");
    let presented = cp_state.state().permissions_presented.clone();
    assert_ne!(
        presented[0], presented[1],
        "the held one is not offered yet"
    );
    conn.close().await;
}

#[tokio::test]
async fn an_anonymous_session_ends_with_its_own_key_on_close() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let conn = singula
        .connect(
            &wallet,
            super::ConnectOptions::new().control_plane(CP),
            Traffic::default,
        )
        .await
        .expect("connects");
    let id = conn.id().to_string();
    conn.close().await;
    assert_eq!(cp_state.state().ended, [id], "ended, not left to expire");
}

#[tokio::test]
async fn a_permission_refused_as_held_comes_back_after_the_hold() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    let time = testing::ManualTime::at(crate::id::UnixTime::now());
    let singula = singula.with_time(time.clone());
    let options = || super::ConnectOptions::new().control_plane(CP);
    // This Control Plane holds on after an end, as one whose lease has not
    // run out yet.
    cp_state.state().holds_after_end = true;

    let first = singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects");
    first.close().await;
    // Past the client's own wait, but the Control Plane still holds it.
    time.set(crate::id::UnixTime(crate::id::UnixTime::now().0 + 120));
    let refused = singula.connect(&wallet, options(), Traffic::default).await;
    assert!(
        matches!(refused, Err(ClientError::Refused { code: 9, .. })),
        "{refused:?}"
    );
    // Not given up for the window: it waits once more, and the next
    // session takes another.
    let packet = singula
        .ledger()
        .permissions(Epoch(window()))
        .await
        .expect("reads")
        .expect("the window's permissions");
    assert!(packet.permissions.iter().all(|p| p.holder.is_none()));
    assert!(packet.permissions.iter().any(|p| p.free_at.is_some()));
    singula
        .connect(&wallet, options(), Traffic::default)
        .await
        .expect("connects on another permission")
        .close()
        .await;
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
async fn renews_into_the_next_window_with_its_packet() {
    let wallet = LocalWallet::random();
    let (cp_state, singula) = singula(&wallet).await;
    // Half a minute before the window turns.
    let w = window();
    let time = testing::ManualTime::at(crate::id::UnixTime(epoch_start(w + 1).0 - 30));
    cp_state.state().clock = Some(time.clone());
    let singula = singula.with_time(time.clone());

    let options = super::ConnectOptions::new()
        .control_plane(CP)
        .timing(quick());
    let mut conn = singula
        .connect(&wallet, options, Traffic::default)
        .await
        .expect("connects");

    // The window turns before the first renewal.
    time.set(crate::id::UnixTime(epoch_start(w + 1).0 + 10));
    cp_state.state().window = w + 1;
    until(&mut conn, |e| matches!(e, super::Event::Renewed { .. })).await;

    let counts = {
        let s = cp_state.state();
        (s.permissions_taken, s.permissions_seen)
    };
    assert_eq!(counts, (2, 2), "a permission taken and spent per window");
    let next = singula
        .ledger()
        .permissions(Epoch(w + 1))
        .await
        .expect("reads")
        .expect("the new window's permissions");
    let held: Vec<_> = next
        .permissions
        .iter()
        .filter_map(|p| p.holder.clone())
        .collect();
    assert_eq!(
        held,
        [conn.id().to_string()],
        "the session holds the new window's permission"
    );
    conn.close().await;
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
    let packet = singula
        .ledger()
        .permissions(Epoch(window()))
        .await
        .expect("reads")
        .expect("the window's permissions");
    assert!(
        packet.permissions.iter().all(|p| p.holder.is_none()),
        "its permission is free again"
    );
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
    let (der, secret) = issuer();
    let port = MockCp::new(der, secret).listen().await;
    // The application's tunnel, played by a plain connection.
    let cp = ControlPlaneClient::through(CP, move || {
        tokio::net::TcpStream::connect(("127.0.0.1", port))
    });
    assert!(cp.health().await.expect("answers").healthy);
}
