//! A Control Plane, and the node behind it, for the client's tests.
//!
//! It plays both parts honestly: it checks every signature it is sent the way
//! the real Control Plane and contracts do, and it seals credentials the way
//! a node does. A test passes only if the SDK's messages would be accepted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use alloy_primitives::{Address as AlloyAddress, FixedBytes, U256};
use alloy_sol_types::{Eip712Domain, SolCall as _, SolStruct as _};
use blind_rsa_signatures::SecretKeySha384PSSRandomized;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use hkdf::Hkdf;
use k256::ecdsa::SigningKey;
use prost::Message as _;
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status, Streaming};
use x25519_dalek::{PublicKey, StaticSecret};

use super::ControlPlaneClient;
use super::proto::admin::{HealthRequest, HealthResponse};
use super::proto::client::client_message::Message as In;
use super::proto::client::control_plane_message::Message as Out;
use super::proto::client::{self as wire, ClientMessage, ControlPlaneMessage};
use super::proto::node::{SniVariant, VlessCredentials};
use super::proto::server::admin::admin_service_server::{AdminService, AdminServiceServer};
use super::proto::server::client::client_service_server::{ClientService, ClientServiceServer};
use super::relay::{Relay, relay_digest};
use super::wallet::{Act, Activation, AddSlots, Message, MintRequest, Permit, Register, TypedData};
use crate::chain::contracts::{ISubscriptionNFT, ITestToken};
use crate::digest::{Checkpoint, Renewal};
use crate::eth;
use crate::id::{Address, RequestId, SessionId, StarId, UnixTime};
use crate::sign_in::SignInMessage;

/// The Control Plane's Star id.
pub(super) const CP: StarId = StarId(8);
/// The node's.
pub(super) const NODE: StarId = StarId(12);
/// The window everything happens in: the current one, by the test
/// network's clock, since the client checks the issuer's key against it.
pub(super) fn window() -> u64 {
    let clock = crate::chain::Clock {
        epoch_zero: UnixTime(1_780_417_577),
        epoch_length: std::time::Duration::from_secs(86_400),
    };
    clock.current_epoch().map_or(0, |e| e.0)
}
/// Permissions per packet.
pub(super) const PACKET_SIZE: u32 = 3;
/// The address the node's tunnel settings name.
pub(super) const NODE_ADDRESS: &str = "203.0.113.7";

pub(super) const NFT: &str = "0xA0c2F384345CBc868D25e5Df4f555C6dB2795f85";
pub(super) const REGISTRY: &str = "0x7Be0A074b56BcD165C22258773811bDf819cD434";
pub(super) const USDC: &str = "0x87bD133c121E2D2a49E6D620D18fbE51047F6fc4";
pub(super) const STATION: &str = "0x63ffBD0A2F38cd7093b2887227cA9Ff35D44A469";
pub(super) const GOVERNOR: &str = "0x6F7E6E000000000000000000000000000000Ab01";
pub(super) const CHAIN_ID: u64 = 421_614;
/// What the transactions it relays are called.
pub(super) const TX: &str = "0xabababababababababababababababababababababababababababababababab";

/// The issuer's key pair for the tests: generated once per run, since a
/// 2048-bit RSA key takes a moment, and never written anywhere.
pub(super) fn issuer_key() -> &'static (Vec<u8>, SecretKeySha384PSSRandomized) {
    static KEY: std::sync::OnceLock<(Vec<u8>, SecretKeySha384PSSRandomized)> =
        std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let pair = blind_rsa_signatures::KeyPairSha384PSSRandomized::generate(
            &mut blind_rsa_signatures::DefaultRng,
            2048,
        )
        .expect("a key pair");
        (pair.pk.to_der().expect("encodes"), pair.sk)
    })
}

/// What the Control Plane remembers, for tests to inspect.
pub(super) struct State {
    /// The window it issues for.
    pub(super) window: u64,
    /// Its clock, when a test controls it.
    pub(super) clock: Option<ManualTime>,
    /// Whether it declines every renewal.
    pub(super) refuse_renewals: bool,
    /// Whether it relays credentials without the node's signature, as nodes
    /// from before the signature did.
    pub(super) unsigned_credentials: bool,
    pub(super) issuer: SecretKeySha384PSSRandomized,
    pub(super) issuer_der: Vec<u8>,
    pub(super) node_signer: SigningKey,
    sessions: HashMap<String, Held>,
    /// Sessions ended by their wallet.
    pub(super) ended: Vec<String>,
    /// Relays it accepted, by kind.
    pub(super) relayed: Vec<&'static str>,
    /// The ceilings wallets signed for the purchases it relayed.
    pub(super) mint_ceilings: Vec<U256>,
    /// Commitments that joined the anonymity set on activation.
    pub(super) joined: Vec<[u8; 32]>,
    /// Governance calls relayed, as the wallet signed them.
    pub(super) governed: Vec<Vec<u8>>,
    /// Permissions signed.
    pub(super) permissions_taken: usize,
    /// Indices another device of the subscription took, by window; set by a
    /// test. They stand for the test identity's.
    pub(super) indices_taken: Vec<(u64, u32)>,
    /// Nullifiers of the permissions it signed. Like a real Control Plane it
    /// knows a permission was taken by its nullifier, which differs between
    /// a subscriber's identities: each slot's identity has its own indices.
    pub(super) nullifiers_taken: Vec<Vec<u8>>,
    /// Quota slots another device used, refused as such.
    pub(super) slots_used_elsewhere: Vec<u32>,
    /// Quota slots presented with session requests, in order.
    pub(super) slots_seen: Vec<u32>,
    /// Permissions presented with session requests and renewals.
    pub(super) permissions_seen: usize,
    /// The prepared messages of permissions presented with session requests.
    pub(super) permissions_presented: Vec<Vec<u8>>,
    /// Whether it keeps holding a permission after its session is ended, as
    /// a Control Plane does until its lease runs out.
    pub(super) holds_after_end: bool,
    /// Sessions opened, for distinct ids.
    sessions_opened: u64,
}

/// A clock a test moves by hand.
#[derive(Clone, Debug)]
pub(super) struct ManualTime(Arc<std::sync::atomic::AtomicI64>);

impl ManualTime {
    pub(super) fn at(t: UnixTime) -> Self {
        Self(Arc::new(std::sync::atomic::AtomicI64::new(t.0)))
    }

    pub(super) fn set(&self, t: UnixTime) {
        self.0.store(t.0, std::sync::atomic::Ordering::SeqCst);
    }
}

impl super::TimeSource for ManualTime {
    fn now(&self) -> UnixTime {
        UnixTime(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

impl State {
    fn now(&self) -> UnixTime {
        use super::TimeSource as _;
        self.clock
            .as_ref()
            .map_or_else(UnixTime::now, ManualTime::now)
    }
}

struct Held {
    checkpoint_key: VerifyingKey,
    nonce: Vec<u8>,
    wallet: Option<Address>,
    /// The permission it was admitted on, held until it ends.
    permission: Option<Vec<u8>>,
}

/// A running Control Plane.
#[derive(Clone)]
pub(super) struct MockCp(Arc<Mutex<State>>);

impl MockCp {
    pub(super) fn new(issuer_der: Vec<u8>, issuer: SecretKeySha384PSSRandomized) -> Self {
        Self(Arc::new(Mutex::new(State {
            issuer,
            issuer_der,
            node_signer: eth::random_key(),
            sessions: HashMap::new(),
            ended: Vec::new(),
            relayed: Vec::new(),
            mint_ceilings: Vec::new(),
            joined: Vec::new(),
            governed: Vec::new(),
            permissions_taken: 0,
            indices_taken: Vec::new(),
            nullifiers_taken: Vec::new(),
            slots_used_elsewhere: Vec::new(),
            slots_seen: Vec::new(),
            permissions_seen: 0,
            permissions_presented: Vec::new(),
            holds_after_end: false,
            sessions_opened: 0,
            window: window(),
            clock: None,
            refuse_renewals: false,
            unsigned_credentials: false,
        })))
    }

    pub(super) fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serves on a local port and returns a client for it.
    pub(super) async fn serve(&self) -> ControlPlaneClient {
        let port = self.listen().await;
        ControlPlaneClient::with_url(CP, &format!("http://127.0.0.1:{port}")).expect("a local URL")
    }

    /// Serves plain HTTP/2 on a local port, as a front forwards it, and
    /// returns the port.
    pub(super) async fn listen(&self) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a local port");
        let port = listener.local_addr().expect("bound").port();
        let server = tonic::transport::Server::builder()
            .add_service(ClientServiceServer::new(self.clone()))
            .add_service(AdminServiceServer::new(self.clone()))
            .serve_with_incoming(TcpListenerStream::new(listener));
        tokio::spawn(server);
        port
    }
}

#[tonic::async_trait]
impl ClientService for MockCp {
    type ConnectStream = ReceiverStream<Result<ControlPlaneMessage, Status>>;

    async fn connect(
        &self,
        request: Request<Streaming<ClientMessage>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let cp = self.clone();
        tokio::spawn(async move {
            // The wallet this stream signed in as.
            let mut wallet = None;
            while let Ok(Some(msg)) = inbound.message().await {
                let Some(msg) = msg.message else { continue };
                let replies = cp.handle(&mut wallet, msg);
                for message in replies {
                    if tx
                        .send(Ok(ControlPlaneMessage {
                            message: Some(message),
                        }))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tonic::async_trait]
impl AdminService for MockCp {
    async fn get_health(
        &self,
        _: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "healthy".into(),
            time: UnixTime::now().0,
        }))
    }
}

/// The Control Plane's refusal, as it sends one.
fn refuse(request_id: &str, why: &str) -> Vec<Out> {
    vec![Out::Error(wire::Error {
        code: 8,
        message: why.into(),
        request_id: request_id.into(),
    })]
}

impl MockCp {
    fn handle(&self, wallet: &mut Option<Address>, msg: In) -> Vec<Out> {
        match msg {
            In::Auth(a) => Self::auth(wallet, &a),
            In::ListNodes(r) => vec![Out::ListNodesResult(wire::ListNodesResult {
                request_id: r.request_id,
                nodes: vec![wire::ClientNode {
                    star_id: NODE.0,
                    country: "de".into(),
                    latency_ms: 20,
                    load: 0.5,
                    available: true,
                }],
            })],
            In::ListCountries(r) => vec![Out::ListCountriesResponse(wire::ListCountriesResponse {
                request_id: r.request_id,
                countries: vec![wire::CountryEntry {
                    country: "DE".into(),
                    node_count: 1,
                }],
            })],
            In::GetNetworkInfo(_) => vec![Out::NetworkInfo(wire::NetworkInfo {
                chain_id: 421_614,
                subscription_nft_addr: NFT.into(),
                price_usdc_wei: "10000000000000000000".into(),
                ..Default::default()
            })],
            In::GetIssuerKey(r) => {
                // One lock for both fields: the state's mutex is not reentrant.
                let s = self.state();
                vec![Out::GetIssuerKeyResult(wire::GetIssuerKeyResult {
                    request_id: r.request_id,
                    success: true,
                    issuer_star_id: CP.0,
                    window: s.window,
                    issuer_public_key: s.issuer_der.clone(),
                    packet_size: PACKET_SIZE,
                    ..Default::default()
                })]
            }
            In::TakePacket(r) => self.take_packet(r),
            In::SessionRequest(r) => self.open(*wallet, r),
            In::TrafficCheckpoint(c) => self.checkpoint(&c),
            In::RenewSession(r) => self.renew(r),
            In::SessionEnd(e) if !e.signature.is_empty() => self.end_signed(&e),
            In::SessionEnd(e) => {
                let mut s = self.state();
                let owned = s
                    .sessions
                    .get(&e.session_uuid)
                    .is_some_and(|h| h.wallet.is_some() && h.wallet == *wallet);
                if owned {
                    s.ended.push(e.session_uuid);
                }
                Vec::new()
            }
            In::RegisterCommitment(r) => self.register(*wallet, &r),
            In::ActivationRequest(r) => self.activate(*wallet, &r),
            In::MintRequest(r) => self.mint(*wallet, &r),
            In::FaucetRequest(r) => self.faucet(*wallet, &r),
            In::AddSlotsRequest(r) => self.add_slots(*wallet, &r),
            In::GovernanceRequest(r) => self.governance(&r),
            In::Pong(_) => Vec::new(),
        }
    }

    fn auth(wallet: &mut Option<Address>, a: &wire::ClientAuth) -> Vec<Out> {
        let claimed: Option<Address> = a.wallet_address.parse().ok();
        let signed = SignInMessage::new(CP, &a.nonce, UnixTime(a.timestamp))
            .ok()
            .and_then(|m| {
                let signature: [u8; 65] = a.signature.as_slice().try_into().ok()?;
                eth::recover(
                    &eth::personal_message_hash(m.to_string().as_bytes()),
                    &signature,
                )
                .ok()
            });
        if claimed.is_none() || signed != claimed {
            return vec![Out::AuthResult(wire::AuthResult {
                success: false,
                error_message: "invalid signature".into(),
                subscription: None,
            })];
        }
        *wallet = claimed;
        vec![Out::AuthResult(wire::AuthResult {
            success: true,
            error_message: String::new(),
            subscription: Some(wire::SubscriptionInfo {
                is_active: true,
                expires_at: 1_790_000_000,
                token_id: 11,
                ..Default::default()
            }),
        })]
    }

    fn take_packet(&self, r: wire::TakePacketRequest) -> Vec<Out> {
        let access = r.access.unwrap_or_default();
        if access.points.len() != 8 || r.blinded.len() != 1 || r.index >= PACKET_SIZE {
            return refuse(&r.request_id, "malformed permission request");
        }
        let mut s = self.state();
        let taken = (s.window, r.index);
        if s.indices_taken.contains(&taken) || s.nullifiers_taken.contains(&access.nullifier) {
            return vec![Out::TakePacketResult(wire::TakePacketResult {
                request_id: r.request_id,
                success: false,
                error_message: "this permission is already taken".into(),
                index_taken: true,
                ..Default::default()
            })];
        }
        s.nullifiers_taken.push(access.nullifier.clone());
        s.permissions_taken += 1;
        let signatures: Option<Vec<Vec<u8>>> = r
            .blinded
            .iter()
            .map(|b| s.issuer.blind_sign(b).ok().map(|sig| sig.0))
            .collect();
        let Some(blind_signatures) = signatures else {
            return refuse(&r.request_id, "cannot sign");
        };
        vec![Out::TakePacketResult(wire::TakePacketResult {
            request_id: r.request_id,
            success: true,
            blind_signatures,
            issuer_star_id: CP.0,
            issuer_public_key: s.issuer_der.clone(),
            window: s.window,
            ..Default::default()
        })]
    }

    fn open(&self, wallet: Option<Address>, r: wire::SessionRequest) -> Vec<Out> {
        let anonymous = r.access.is_some();
        if anonymous && r.permission.is_none() {
            return refuse(&r.request_id, "a permission is required");
        }
        if !anonymous && wallet.is_none() {
            return refuse(&r.request_id, "not authenticated");
        }
        let Ok(client_key) = <[u8; 32]>::try_from(r.session_public_key.as_slice()) else {
            return refuse(&r.request_id, "session key");
        };
        let Some(checkpoint_key) = <[u8; 32]>::try_from(r.checkpoint_public_key.as_slice())
            .ok()
            .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        else {
            return refuse(&r.request_id, "checkpoint key");
        };

        let mut s = self.state();
        s.sessions_opened += 1;
        let session: SessionId = format!("8f14e45f-ceea-467f-a8d5-{:012x}", s.sessions_opened)
            .parse()
            .expect("a session id");
        if let Some(access) = &r.access {
            if s.slots_used_elsewhere.contains(&access.index) {
                return vec![Out::Error(wire::Error {
                    code: wire::ErrorCode::AccessClaimUsed.into(),
                    message: "this access claim has already been used".into(),
                    request_id: r.request_id,
                })];
            }
            s.slots_seen.push(access.index);
        }
        s.permissions_seen += usize::from(r.permission.is_some());
        if let Some(p) = &r.permission {
            let held = s
                .sessions
                .values()
                .any(|h| h.permission.as_ref() == Some(&p.prepared_message));
            if held {
                return vec![Out::Error(wire::Error {
                    code: wire::ErrorCode::PermissionSpent.into(),
                    message: "this permission has already been spent".into(),
                    request_id: r.request_id,
                })];
            }
            s.permissions_presented.push(p.prepared_message.clone());
        }
        let credentials = VlessCredentials {
            uuid: session.to_string(),
            address: NODE_ADDRESS.into(),
            port: 443,
            endpoint_port: 443,
            flow: "xtls-rprx-vision".into(),
            preset_id: "default".into(),
            sni_pool: vec![SniVariant {
                server_name: "cover.example".into(),
                short_id: "ab".into(),
            }],
            ..Default::default()
        };
        let sealed = seal(
            &s.node_signer,
            &client_key,
            &session,
            &credentials.encode_to_vec(),
        );
        let challenge = vec![1, 2, 3, 4];
        s.sessions.insert(
            session.to_string(),
            Held {
                checkpoint_key,
                nonce: challenge.clone(),
                wallet,
                permission: r.permission.as_ref().map(|p| p.prepared_message.clone()),
            },
        );
        vec![Out::SessionCredentials(wire::SessionCredentials {
            request_id: r.request_id,
            session_uuid: session.to_string(),
            node_id: NODE.0.to_string(),
            session_public_key: sealed.node_key.to_vec(),
            encrypted_credentials: sealed.ciphertext,
            nonce: sealed.nonce.to_vec(),
            expires_at: s.now().0 + 3_600,
            challenge_nonce: challenge,
            egress_mode: wire::EgressMode::Direct.into(),
            node_signer_signature: if s.unsigned_credentials {
                Vec::new()
            } else {
                sealed.signature.to_vec()
            },
            ..Default::default()
        })]
    }

    /// An end signed by the session's key: the session ends, and with it
    /// the hold on its permission, unless this one holds on.
    fn end_signed(&self, e: &wire::SessionEnd) -> Vec<Out> {
        let mut s = self.state();
        let answer = |success: bool, why: &str| {
            vec![Out::SessionEndResult(wire::SessionEndResult {
                session_uuid: e.session_uuid.clone(),
                success,
                error_message: why.into(),
            })]
        };
        let (Some(held), Ok(session)) = (
            s.sessions.get(&e.session_uuid),
            e.session_uuid.parse::<SessionId>(),
        ) else {
            return answer(false, "no such session");
        };
        let digest = crate::digest::Ending {
            session: &session,
            up: u64::try_from(e.final_bytes_uploaded).unwrap_or(0),
            down: u64::try_from(e.final_bytes_downloaded).unwrap_or(0),
            timestamp: UnixTime(e.timestamp),
        }
        .digest();
        let signed = Signature::from_slice(&e.signature)
            .is_ok_and(|sig| held.checkpoint_key.verify(digest.as_bytes(), &sig).is_ok());
        if !signed {
            return answer(false, "not signed by the session's key");
        }
        if !s.holds_after_end {
            s.sessions.remove(&e.session_uuid);
        }
        s.ended.push(e.session_uuid.clone());
        answer(true, "")
    }

    fn checkpoint(&self, c: &wire::TrafficCheckpoint) -> Vec<Out> {
        let mut s = self.state();
        let Some(held) = s.sessions.get_mut(&c.session_uuid) else {
            return refuse("", "no such session");
        };
        let Ok(session) = c.session_uuid.parse::<SessionId>() else {
            return refuse("", "session id");
        };
        let (Ok(up), Ok(down)) = (
            u64::try_from(c.bytes_uploaded),
            u64::try_from(c.bytes_downloaded),
        ) else {
            return refuse("", "traffic");
        };
        let digest = Checkpoint {
            session: &session,
            bytes_up: up,
            bytes_down: down,
            timestamp: UnixTime(c.timestamp),
            nonce: &c.nonce,
        }
        .digest();
        if c.nonce != held.nonce || !verifies(&held.checkpoint_key, digest.as_bytes(), &c.signature)
        {
            return refuse("", "invalid checkpoint");
        }
        let mut next = vec![0; 16];
        OsRng.fill_bytes(&mut next);
        held.nonce.clone_from(&next);
        vec![Out::NonceUpdate(wire::NonceUpdate {
            session_uuid: c.session_uuid.clone(),
            next_nonce: next,
        })]
    }

    fn renew(&self, r: wire::RenewSessionRequest) -> Vec<Out> {
        let mut s = self.state();
        s.permissions_seen += usize::from(r.permission.is_some());
        let Some(held) = s.sessions.get(&r.session_uuid) else {
            return refuse(&r.request_id, "no such session");
        };
        let (Ok(session), Ok(request)) = (
            r.session_uuid.parse::<SessionId>(),
            r.request_id.parse::<RequestId>(),
        ) else {
            return refuse(&r.request_id, "ids");
        };
        let digest = Renewal {
            session: &session,
            request: &request,
            timestamp: UnixTime(r.timestamp),
        }
        .digest();
        let success =
            !s.refuse_renewals && verifies(&held.checkpoint_key, digest.as_bytes(), &r.signature);
        vec![Out::RenewSessionResult(wire::RenewSessionResult {
            request_id: r.request_id,
            session_uuid: r.session_uuid,
            success,
            expires_at: if success { s.now().0 + 7_200 } else { 0 },
            error_message: if success {
                String::new()
            } else {
                "not this session's key".into()
            },
        })]
    }

    fn register(&self, wallet: Option<Address>, r: &wire::RegisterCommitmentRequest) -> Vec<Out> {
        let ok = wallet.is_some_and(|w| {
            w.to_string() == r.wallet
                && signed_by(
                    w,
                    &TypedData::new(
                        domain("SingulaSubscriberRegistry", REGISTRY),
                        Message::Register(Register {
                            wallet: alloy(w),
                            tokenId: U256::from(r.token_id),
                            commitments: r
                                .commitments
                                .iter()
                                .map(|c| U256::from_be_slice(c))
                                .collect(),
                            deadline: U256::from(r.deadline),
                            nonce: U256::ZERO,
                        }),
                    )
                    .signing_hash(),
                    &r.register_sig,
                )
        });
        self.relayed(ok, "register");
        vec![Out::RegisterCommitmentResult(
            wire::RegisterCommitmentResult {
                success: ok,
                error_message: reason(ok),
                tx_hash: tx(ok),
            },
        )]
    }

    fn activate(&self, wallet: Option<Address>, r: &wire::ActivationRequest) -> Vec<Out> {
        let commitments: Vec<U256> = r
            .commitments
            .iter()
            .map(|c| U256::from_be_slice(c))
            .collect();
        let ok = r.commitments.iter().all(|c| !c.is_empty() && c.len() <= 32)
            && wallet.is_some_and(|w| {
                let intent = TypedData::new(
                    domain("SingulaSubscription", NFT),
                    Message::Activation(Activation {
                        wallet: alloy(w),
                        tokenId: U256::from(r.token_id),
                        commitments: commitments.clone(),
                        deadline: U256::from(r.deadline),
                        nonce: U256::ZERO,
                    }),
                );
                let calldata = ISubscriptionNFT::activateWithSignatureCall {
                    wallet: alloy(w),
                    tokenId: U256::from(r.token_id),
                    commitments: commitments.clone(),
                    deadline: U256::from(r.deadline),
                    signature: r.signature.clone().into(),
                }
                .abi_encode();
                w.to_string() == r.wallet
                    && signed_by(w, &intent.signing_hash(), &r.signature)
                    && relayed_by(w, &calldata, r.gas_deadline, &r.gas_sig)
            });
        self.relayed(ok, "activate");
        if ok {
            self.state()
                .joined
                .extend(commitments.iter().map(U256::to_be_bytes::<32>));
        }
        vec![Out::ActivationResult(wire::ActivationResult {
            success: ok,
            error_message: reason(ok),
            tx_hash: tx(ok),
            token_id: r.token_id,
            expires_at: 1_790_000_000,
        })]
    }

    fn add_slots(&self, wallet: Option<Address>, r: &wire::AddSlotsRequest) -> Vec<Out> {
        let commitments: Vec<U256> = r
            .commitments
            .iter()
            .map(|c| U256::from_be_slice(c))
            .collect();
        let ok = wallet.is_some_and(|w| {
            let (Ok(cost), Ok(extra), Ok(v)) = (
                r.max_cost.parse::<U256>(),
                u8::try_from(r.extra),
                u8::try_from(r.permit_v),
            ) else {
                return false;
            };
            let (Ok(pr), Ok(ps)) = (
                <[u8; 32]>::try_from(r.permit_r.as_slice()),
                <[u8; 32]>::try_from(r.permit_s.as_slice()),
            ) else {
                return false;
            };
            let intent = TypedData::new(
                domain("SingulaSubscription", NFT),
                Message::AddSlots(AddSlots {
                    wallet: alloy(w),
                    tokenId: U256::from(r.token_id),
                    extra,
                    commitments: commitments.clone(),
                    maxCost: cost,
                    deadline: U256::from(r.deadline),
                    nonce: U256::ZERO,
                }),
            );
            let calldata = ISubscriptionNFT::addSlotsWithPermitCall {
                wallet: alloy(w),
                tokenId: U256::from(r.token_id),
                extra,
                commitments: commitments.clone(),
                maxCost: cost,
                deadline: U256::from(r.deadline),
                sig: r.sig.clone().into(),
                permitDeadline: U256::from(r.permit_deadline),
                permitV: v,
                permitR: FixedBytes(pr),
                permitS: FixedBytes(ps),
            }
            .abi_encode();
            w.to_string() == r.wallet
                && signed_by(w, &intent.signing_hash(), &r.sig)
                && relayed_by(w, &calldata, r.gas_deadline, &r.gas_sig)
        });
        self.relayed(ok, "add_slots");
        if ok {
            self.state()
                .joined
                .extend(commitments.iter().map(U256::to_be_bytes::<32>));
        }
        vec![Out::AddSlotsResult(wire::AddSlotsResult {
            success: ok,
            error_message: reason(ok),
            tx_hash: tx(ok),
        })]
    }

    fn mint(&self, wallet: Option<Address>, r: &wire::MintRequest) -> Vec<Out> {
        let ok = wallet.is_some_and(|w| {
            let Ok(cost) = r.max_cost.parse::<U256>() else {
                return false;
            };
            let Ok(slots) = u8::try_from(r.slots) else {
                return false;
            };
            let intent = TypedData::new(
                domain("SingulaSubscription", NFT),
                Message::Mint(MintRequest {
                    wallet: alloy(w),
                    payWithEcho: r.pay_with_echo,
                    slots,
                    maxCost: cost,
                    deadline: U256::from(r.mint_deadline),
                    nonce: U256::ZERO,
                }),
            );
            let permit = TypedData::new(
                domain("Singula USDC", USDC),
                Message::Permit(Permit {
                    owner: alloy(w),
                    spender: alloy(addr(NFT)),
                    value: cost,
                    nonce: U256::ZERO,
                    deadline: U256::from(r.permit_deadline),
                }),
            );
            let Ok(v) = u8::try_from(r.permit_v) else {
                return false;
            };
            let permit_sig = [r.permit_r.as_slice(), r.permit_s.as_slice(), &[v]].concat();
            let (Ok(pr), Ok(ps)) = (
                <[u8; 32]>::try_from(r.permit_r.as_slice()),
                <[u8; 32]>::try_from(r.permit_s.as_slice()),
            ) else {
                return false;
            };
            let calldata = ISubscriptionNFT::mintWithPermitCall {
                wallet: alloy(w),
                payWithEcho: r.pay_with_echo,
                slots,
                maxCost: cost,
                mintDeadline: U256::from(r.mint_deadline),
                mintSig: r.mint_sig.clone().into(),
                permitDeadline: U256::from(r.permit_deadline),
                permitV: v,
                permitR: FixedBytes(pr),
                permitS: FixedBytes(ps),
            }
            .abi_encode();
            w.to_string() == r.wallet
                && !r.pay_with_echo
                && signed_by(w, &intent.signing_hash(), &r.mint_sig)
                && signed_by(w, &permit.signing_hash(), &permit_sig)
                && relayed_by(w, &calldata, r.gas_deadline, &r.gas_sig)
        });
        self.relayed(ok, "mint");
        if ok {
            if let Ok(cost) = r.max_cost.parse::<U256>() {
                self.state().mint_ceilings.push(cost);
            }
        }
        vec![Out::MintResult(wire::MintResult {
            success: ok,
            error_message: reason(ok),
            tx_hash: tx(ok),
            token_id: 12,
        })]
    }

    fn faucet(&self, wallet: Option<Address>, r: &wire::FaucetRequest) -> Vec<Out> {
        let ok = wallet.is_some_and(|w| {
            let Ok(amount) = r.amount.parse::<U256>() else {
                return false;
            };
            let calldata = ITestToken::mintCall {
                to: alloy(w),
                amount,
            }
            .abi_encode();
            w.to_string() == r.wallet && relayed_to(USDC, w, &calldata, r.gas_deadline, &r.gas_sig)
        });
        self.relayed(ok, "faucet");
        vec![Out::FaucetResult(wire::FaucetResult {
            success: ok,
            error_message: reason(ok),
            tx_hash: tx(ok),
        })]
    }

    /// A governance action: the wallet it names signed the Act it carries in
    /// the governor's domain, and the relay of `act` around it. The stream
    /// need not be signed in.
    fn governance(&self, r: &wire::GovernanceRequest) -> Vec<Out> {
        let ok = r.wallet.parse::<Address>().is_ok_and(|w| {
            let Ok(act_sig) = <[u8; 65]>::try_from(r.act_sig.as_slice()) else {
                return false;
            };
            let act = Act {
                wallet: alloy(w),
                data: r.call.clone().into(),
                nonce: U256::ZERO,
                deadline: U256::from(u64::try_from(r.act_deadline).unwrap_or_default()),
            };
            let hash = act
                .eip712_signing_hash(&domain("SingulaGovernor", GOVERNOR))
                .0;
            let relayed = super::governance::act_call(w, &r.call, r.act_deadline, &act_sig);
            signed_by(w, &hash, &act_sig)
                && relayed_to(GOVERNOR, w, &relayed, r.gas_deadline, &r.gas_sig)
        });
        if ok {
            self.state().governed.push(r.call.clone());
        }
        self.relayed(ok, "governance");
        vec![Out::GovernanceResult(wire::GovernanceResult {
            success: ok,
            error_message: reason(ok),
            tx_hash: tx(ok),
        })]
    }

    fn relayed(&self, ok: bool, kind: &'static str) {
        if ok {
            self.state().relayed.push(kind);
        }
    }
}

/// A node's sealed answer.
struct Sealed {
    node_key: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    signature: [u8; 65],
}

/// Seals `plain` to `client_key` as a node does, signing the exchange with
/// `signer`.
fn seal(signer: &SigningKey, client_key: &[u8; 32], session: &SessionId, plain: &[u8]) -> Sealed {
    let secret = StaticSecret::random_from_rng(OsRng);
    let node_key = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(*client_key));
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(b"singula-session-v1", &mut key)
        .expect("32 bytes");
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = Aes256Gcm::new((&key).into())
        .encrypt(&Nonce::from(nonce), plain)
        .expect("encrypts");
    let digest = crate::session::origin_digest(session, client_key, &node_key);
    let signature = eth::sign(signer, &eth::personal_message_hash(&digest));
    Sealed {
        node_key,
        nonce,
        ciphertext,
        signature,
    }
}

fn verifies(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    <[u8; 64]>::try_from(signature)
        .is_ok_and(|s| key.verify(message, &Signature::from_bytes(&s)).is_ok())
}

/// Whether `signature` over `hash` is `wallet`'s, as a contract checks it.
fn signed_by(wallet: Address, hash: &[u8; 32], signature: &[u8]) -> bool {
    <[u8; 65]>::try_from(signature).is_ok_and(|s| eth::recover(hash, &s) == Ok(wallet))
}

/// Whether `signature` is `wallet`'s `GasStation.relayClient` signature over
/// `calldata` to the subscription contract.
fn relayed_by(wallet: Address, calldata: &[u8], deadline: i64, signature: &[u8]) -> bool {
    relayed_to(NFT, wallet, calldata, deadline, signature)
}

fn relayed_to(
    target: &str,
    wallet: Address,
    calldata: &[u8],
    deadline: i64,
    signature: &[u8],
) -> bool {
    let digest = relay_digest(&Relay {
        signer: wallet,
        target: addr(target),
        calldata,
        nonce: U256::ZERO,
        deadline: UnixTime(deadline),
        chain_id: CHAIN_ID,
        station: addr(STATION),
    });
    signed_by(wallet, &eth::personal_message_hash(&digest), signature)
}

pub(super) fn domain(name: &str, contract: &str) -> Eip712Domain {
    Eip712Domain::new(
        Some(name.to_owned().into()),
        Some("1".into()),
        Some(U256::from(CHAIN_ID)),
        Some(alloy(addr(contract))),
        None,
    )
}

pub(super) fn addr(s: &str) -> Address {
    s.parse().expect("an address")
}

pub(super) fn alloy(a: Address) -> AlloyAddress {
    AlloyAddress::from(a.0)
}

fn reason(ok: bool) -> String {
    if ok { String::new() } else { "refused".into() }
}

fn tx(ok: bool) -> String {
    if ok { TX.into() } else { String::new() }
}
