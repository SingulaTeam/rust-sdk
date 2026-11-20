//! What the shared journal reads from the chain: the Control Plane set's
//! history, and the subscriber log a day's tree is built from.
//!
//! Both are read from events, from the block the registry was deployed at
//! (the directory publishes it), and kept: each [`refresh`] reads only the
//! blocks since the last. Nothing here comes from a Control Plane. The tree
//! a right is proved against in particular must not: one that handed a
//! client a tree of its choosing — one where the client is the only member
//! left, say — would learn who it is from the proof.
//!
//! [`refresh`]: RegistryHistory::refresh

use std::collections::{BTreeMap, HashMap};

use alloy_primitives::{B256, U256};
use alloy_sol_types::SolEvent;

use super::contracts::{ISingulaProtocol, IStarRegistry, ISubscriberRegistry, ISubscriptionNFT};
use super::rpc::Log;
use super::subscriptions::TokenId;
use super::{Block, Chain, ChainError, Rpc, required, to_u64};
use crate::id::{Address, StarId, UnixTime};
use crate::journal::{JournalParams, RegistryVersion, RegistryVersionId, Versions, VersionsError};

/// The directory parameters naming the blocks the registries were deployed
/// at; zero, or absent, reads from the start of the chain.
const STAR_REGISTRY_FROM: &str = "starRegistryFromBlock";
const SUBSCRIBER_REGISTRY_FROM: &str = "subscriberRegistryFromBlock";

/// `StarRegistry`'s roles.
const ROLE_NODE: u8 = 1;
const ROLE_CONTROL_PLANE: u8 = 2;

impl<R: Rpc> Chain<R> {
    /// The parameters the journal's signatures are bound to on this chain.
    #[must_use]
    pub fn journal_params(&self) -> JournalParams {
        JournalParams::new(self.deployment.chain_id)
    }

    /// A parameter the directory publishes; zero when it publishes none.
    async fn directory_param(&self, name: &str) -> Result<u64, ChainError> {
        let mut key = [0u8; 32];
        key[..name.len()].copy_from_slice(name.as_bytes());
        let value = self
            .read(
                self.network.directory,
                ISingulaProtocol::paramCall { name: key.into() },
                Block::Latest,
                "param",
            )
            .await?;
        to_u64(value, "param")
    }
}

/// The Control Plane set's history: a [`RegistryVersion`] for every block
/// that changed who is a Control Plane, or with which key, up to the
/// chain's finalized block.
#[derive(Debug, Clone, Default)]
pub struct RegistryHistory {
    /// The next block to read; `None` before the first read.
    next: Option<u64>,
    stars: BTreeMap<u64, StarState>,
    versions: Vec<RegistryVersion>,
}

#[derive(Debug, Clone, Copy)]
struct StarState {
    signer: Address,
    role: u8,
}

impl RegistryHistory {
    /// An empty history; [`refresh`](Self::refresh) reads it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads the registry's changes since the last refresh, up to the
    /// finalized block. Nothing is kept unless all of it reads.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if a read fails, or a change names a Star whose
    /// creation was never read — the directory's deployment block would then
    /// be wrong, and with it every version after.
    pub async fn refresh<R: Rpc>(&mut self, chain: &Chain<R>) -> Result<(), ChainError> {
        let registry = required(chain.deployment.contracts.star_registry, "StarRegistry")?;
        let next = match self.next {
            Some(next) => next,
            None => chain.directory_param(STAR_REGISTRY_FROM).await?,
        };
        let finalized = chain.rpc.header(Block::Finalized).await?.number;
        if next > finalized {
            return Ok(());
        }
        let events = [
            IStarRegistry::StarRegistered::SIGNATURE_HASH.0,
            IStarRegistry::RoleForced::SIGNATURE_HASH.0,
            IStarRegistry::SignerUpdated::SIGNATURE_HASH.0,
        ];
        let logs = chain
            .logs_between(registry, &events, next, finalized)
            .await?;

        let mut known = self.stars.clone();
        let mut added = Vec::new();
        let mut last = self.versions.last().map(|v| v.control_planes.clone());
        let mut i = 0;
        while i < logs.len() {
            let (block, hash) = (logs[i].block, logs[i].block_hash);
            while i < logs.len() && logs[i].block == block {
                apply(&mut known, &logs[i])?;
                i += 1;
            }
            let set = control_planes(&known);
            if last.as_ref() == Some(&set) {
                continue;
            }
            let start = chain.rpc.header(Block::Number(block)).await?.timestamp;
            let id = RegistryVersionId::new(chain.deployment.chain_id, registry, block, &hash);
            added.push(RegistryVersion::new(id, block, start, set.clone()));
            last = Some(set);
        }
        self.stars = known;
        self.versions.extend(added);
        self.next = Some(finalized + 1);
        Ok(())
    }

    /// The history read so far, ready to check acks against.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError::Empty`] before any version has been read.
    pub fn versions(&self) -> Result<Versions, VersionsError> {
        Versions::new(self.versions.clone())
    }
}

/// What a registry event changes about a Star it does not create.
enum Change {
    Role(u8),
    Signer(Address),
}

/// One registry event, applied to the Stars known so far.
fn apply(stars: &mut BTreeMap<u64, StarState>, log: &Log) -> Result<(), ChainError> {
    let topics = || log.topics.iter().map(|t| B256::from(*t));
    let first = log.topics.first().copied().unwrap_or_default();
    let (id, change) = if first == IStarRegistry::StarRegistered::SIGNATURE_HASH.0 {
        let e = IStarRegistry::StarRegistered::decode_raw_log(topics(), &log.data)
            .map_err(|_| ChainError::Decode("StarRegistered"))?;
        let signer = Address(e.signer.into_array());
        let id = to_u64(e.starId, "StarRegistered")?;
        stars.insert(
            id,
            StarState {
                signer,
                role: ROLE_NODE,
            },
        );
        return Ok(());
    } else if first == IStarRegistry::RoleForced::SIGNATURE_HASH.0 {
        let e = IStarRegistry::RoleForced::decode_raw_log(topics(), &log.data)
            .map_err(|_| ChainError::Decode("RoleForced"))?;
        (to_u64(e.starId, "RoleForced")?, Change::Role(e.newRole))
    } else if first == IStarRegistry::SignerUpdated::SIGNATURE_HASH.0 {
        let e = IStarRegistry::SignerUpdated::decode_raw_log(topics(), &log.data)
            .map_err(|_| ChainError::Decode("SignerUpdated"))?;
        let signer = Address(e.newSigner.into_array());
        (to_u64(e.starId, "SignerUpdated")?, Change::Signer(signer))
    } else {
        return Ok(());
    };
    let state = stars.get_mut(&id).ok_or(ChainError::OutOfRange(
        "a Star changed before its creation was read",
    ))?;
    match change {
        Change::Role(role) => state.role = role,
        Change::Signer(signer) => state.signer = signer,
    }
    Ok(())
}

/// The Stars holding the Control Plane role, by id.
fn control_planes(stars: &BTreeMap<u64, StarState>) -> Vec<(StarId, Address)> {
    stars
        .iter()
        .filter(|(_, s)| s.role == ROLE_CONTROL_PLANE)
        .map(|(id, s)| (StarId(*id), s.signer))
        .collect()
}

/// One commitment in `SubscriberRegistry`'s log, with when it was inserted
/// and when its subscription ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SubscriberLeaf {
    /// The commitment, 32 bytes big-endian.
    pub commitment: [u8; 32],
    /// The Orbit it was registered for.
    pub token: TokenId,
    /// Its block's timestamp.
    pub inserted_at: UnixTime,
    /// When the Orbit's term ends.
    pub expires_at: UnixTime,
}

/// `SubscriberRegistry`'s log: every commitment ever inserted, in leaf
/// order, whether or not the registry has since removed it. A day's trees
/// are built from it as the Control Planes build them.
#[derive(Debug, Clone, Default)]
pub struct SubscriberLog {
    next: Option<u64>,
    leaves: Vec<SubscriberLeaf>,
    /// How far the log has been read, in block time.
    read_to: Option<UnixTime>,
    expiries: HashMap<TokenId, UnixTime>,
}

impl SubscriberLog {
    /// An empty log; [`refresh`](Self::refresh) reads it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The leaves read so far.
    #[must_use]
    pub fn leaves(&self) -> &[SubscriberLeaf] {
        &self.leaves
    }

    /// Reads the commitments inserted since the last refresh, up to the
    /// newest block. Nothing is kept unless all of it reads.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if a read fails, or the log skips or repeats a
    /// leaf — a tree built from it would be one no Control Plane builds.
    pub async fn refresh<R: Rpc>(&mut self, chain: &Chain<R>) -> Result<(), ChainError> {
        let contracts = &chain.deployment.contracts;
        let registry = required(contracts.subscriber_registry, "SubscriberRegistry")?;
        let orbits = required(contracts.subscriptions, "SubscriptionNFT")?;
        let next = match self.next {
            Some(next) => next,
            None => chain.directory_param(SUBSCRIBER_REGISTRY_FROM).await?,
        };
        let tip = chain.rpc.header(Block::Latest).await?;
        if next > tip.number {
            return Ok(());
        }
        let event = ISubscriberRegistry::Registered::SIGNATURE_HASH.0;
        let logs = chain
            .logs_between(registry, &[event], next, tip.number)
            .await?;

        let mut added = Vec::with_capacity(logs.len());
        let mut expiries = HashMap::new();
        let mut block_times = HashMap::new();
        for log in &logs {
            let topics = log.topics.iter().map(|t| B256::from(*t));
            let e = ISubscriberRegistry::Registered::decode_raw_log(topics, &log.data)
                .map_err(|_| ChainError::Decode("Registered"))?;
            let index = to_u64(e.index, "Registered")?;
            if index != (self.leaves.len() + added.len()) as u64 {
                return Err(ChainError::OutOfRange("Registered skips or repeats a leaf"));
            }
            let token = TokenId(to_u64(e.tokenId, "Registered")?);
            let inserted_at = block_time(chain, log.block, &mut block_times).await?;
            let expires_at = if let Some(t) = self.expiries.get(&token) {
                *t
            } else {
                expiry(chain, orbits, token, &mut expiries).await?
            };
            if expires_at <= inserted_at {
                return Err(ChainError::OutOfRange(
                    "an Orbit ending before its commitment",
                ));
            }
            added.push(SubscriberLeaf {
                commitment: e.commitment.to_be_bytes::<32>(),
                token,
                inserted_at,
                expires_at,
            });
        }
        self.leaves.extend(added);
        self.expiries.extend(expiries);
        self.read_to = Some(tip.timestamp);
        self.next = Some(tip.number + 1);
        Ok(())
    }
}

/// A block's timestamp, read once per block.
async fn block_time<R: Rpc>(
    chain: &Chain<R>,
    block: u64,
    cache: &mut HashMap<u64, UnixTime>,
) -> Result<UnixTime, ChainError> {
    if let Some(t) = cache.get(&block) {
        return Ok(*t);
    }
    let t = chain.rpc.header(Block::Number(block)).await?.timestamp;
    cache.insert(block, t);
    Ok(t)
}

/// When an Orbit's term ends, read once: an activated Orbit's term does not
/// change.
async fn expiry<R: Rpc>(
    chain: &Chain<R>,
    orbits: Address,
    token: TokenId,
    cache: &mut HashMap<TokenId, UnixTime>,
) -> Result<UnixTime, ChainError> {
    if let Some(t) = cache.get(&token) {
        return Ok(*t);
    }
    let call = ISubscriptionNFT::expiresAtCall {
        tokenId: U256::from(token.0),
    };
    let raw = chain.read(orbits, call, Block::Latest, "expiresAt").await?;
    let t = UnixTime(i64::try_from(to_u64(raw, "expiresAt")?).unwrap_or(i64::MAX));
    cache.insert(token, t);
    Ok(t)
}

#[cfg(feature = "zk")]
pub use tree::{WindowTree, WindowTreeError};

#[cfg(feature = "zk")]
mod tree {
    use super::SubscriberLog;
    use crate::chain::Clock;
    use crate::id::{Epoch, UnixTime};
    use crate::zk::{FieldElement, Group};

    /// One of a window's subscriber trees, as the Control Planes build it:
    /// what a right is proved against.
    ///
    /// State 0 is the tree at the window's start: every leaf inserted
    /// before it, those whose Orbit ends inside the window zeroed in place.
    /// State `k` is the tree right after the window's `k`-th insertion,
    /// zeroed the same way. A state is paid from `valid_from`: the window's
    /// start for state 0, the `k`-th insertion for state `k`.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct WindowTree {
        /// The window.
        pub window: Epoch,
        /// Which of its states this is.
        pub state_index: u32,
        /// The tree, ready to prove membership of.
        pub group: Group,
        /// When every member of this state had paid.
        pub valid_from: UnixTime,
    }

    /// Why a window has no tree for a member.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[non_exhaustive]
    pub enum WindowTreeError {
        /// The log has not been read past the window's start yet.
        #[error("the subscriber log is not read up to the window's start")]
        NotReadYet,
        /// The member is in none of the window's trees: not registered, or
        /// its Orbit ends inside the window.
        #[error("not a member for the whole window")]
        NotAMember,
        /// A commitment in the log is not a field element.
        #[error("the subscriber log holds a value that is not a field element")]
        BadLeaf,
    }

    impl SubscriberLog {
        /// The earliest of `window`'s trees `member` is in — the one paid
        /// from the earliest time — as the Control Planes will rebuild it.
        ///
        /// # Errors
        ///
        /// Returns [`WindowTreeError`] if the log is not read far enough or
        /// `member` is in none of the window's trees.
        pub fn window_tree(
            &self,
            clock: &Clock,
            window: Epoch,
            member: FieldElement,
        ) -> Result<WindowTree, WindowTreeError> {
            let (Some(start), Some(end)) = (
                clock.epoch_start(window),
                clock.epoch_start(Epoch(window.0.saturating_add(1))),
            ) else {
                return Err(WindowTreeError::NotAMember);
            };
            if self.read_to.is_none_or(|t| t < start) {
                return Err(WindowTreeError::NotReadYet);
            }
            let member = member.to_be_bytes();
            let first = self.leaves.partition_point(|l| l.inserted_at < start);
            // The member's earliest leaf that holds for the whole window and
            // is in one of its states: inserted before the window ends.
            let at = self
                .leaves
                .iter()
                .position(|l| l.commitment == member && l.expires_at >= end && l.inserted_at < end)
                .ok_or(WindowTreeError::NotAMember)?;
            let (count, state_index, valid_from) = if at < first {
                (first, 0, start)
            } else {
                let k = u32::try_from(at - first + 1).map_err(|_| WindowTreeError::NotAMember)?;
                (at + 1, k, self.leaves[at].inserted_at)
            };
            let members = self.leaves[..count]
                .iter()
                .map(|l| {
                    // A leaf whose Orbit ends inside the window is zeroed in
                    // place, so the indices of the others do not move.
                    let value = if l.expires_at >= end {
                        l.commitment
                    } else {
                        [0; 32]
                    };
                    FieldElement::from_be_bytes(&value)
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| WindowTreeError::BadLeaf)?;
            let group = Group::new(&members).map_err(|_| WindowTreeError::BadLeaf)?;
            Ok(WindowTree {
                window,
                state_index,
                group,
                valid_from,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Address as AlloyAddress;

    use super::super::testing::MockRpc;
    use super::super::{Network, contracts::ISingulaProtocol};
    use super::*;

    fn param_call(name: &str) -> ISingulaProtocol::paramCall {
        let mut key = [0u8; 32];
        key[..name.len()].copy_from_slice(name.as_bytes());
        ISingulaProtocol::paramCall { name: key.into() }
    }

    fn emit<E: SolEvent>(rpc: &mut MockRpc, at: Address, block: u64, event: &E) {
        let data = event.encode_log_data();
        let topics = data.topics().iter().map(|t| t.0).collect();
        rpc.emit(at, block, topics, data.data.to_vec());
    }

    fn alloy(a: u8) -> AlloyAddress {
        AlloyAddress::from([a; 20])
    }

    async fn connect(rpc: MockRpc) -> Chain<MockRpc> {
        Chain::connect(rpc, Network::ARBITRUM_SEPOLIA)
            .await
            .unwrap_or_else(|e| panic!("connects: {e}"))
    }

    fn star_registry() -> Address {
        "0xced082443d1787e8014d2747f463ff9f2888447c"
            .parse()
            .unwrap_or_else(|_| unreachable!())
    }

    fn registered(rpc: &mut MockRpc, block: u64, star: u64, signer: u8) {
        emit(
            rpc,
            star_registry(),
            block,
            &IStarRegistry::StarRegistered {
                starId: U256::from(star),
                owner: alloy(0xee),
                signer: alloy(signer),
            },
        );
    }

    fn role(rpc: &mut MockRpc, block: u64, star: u64, old: u8, new: u8) {
        emit(
            rpc,
            star_registry(),
            block,
            &IStarRegistry::RoleForced {
                starId: U256::from(star),
                oldRole: old,
                newRole: new,
                withSlashing: false,
            },
        );
    }

    #[tokio::test]
    async fn the_registry_history_is_the_control_planes() {
        let mut rpc = MockRpc::sepolia();
        rpc.answer(
            Network::ARBITRUM_SEPOLIA.directory,
            &param_call(STAR_REGISTRY_FROM),
            &U256::from(3),
        );
        registered(&mut rpc, 2, 9, 0x09); // before the registry's block: never read
        registered(&mut rpc, 3, 1, 0x01);
        registered(&mut rpc, 3, 2, 0x02);
        role(&mut rpc, 5, 1, ROLE_NODE, ROLE_CONTROL_PLANE);
        role(&mut rpc, 5, 2, ROLE_NODE, ROLE_CONTROL_PLANE); // one block, one version
        emit(
            &mut rpc,
            star_registry(),
            7,
            &IStarRegistry::SignerUpdated {
                starId: U256::from(1),
                oldSigner: alloy(0x01),
                newSigner: alloy(0x11),
            },
        );
        role(&mut rpc, 9, 2, ROLE_CONTROL_PLANE, 3); // banned
        rpc.block = 12;
        rpc.finalized = Some(8);
        let chain = connect(rpc).await;

        let mut history = RegistryHistory::new();
        history
            .refresh(&chain)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let v = history.versions().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(v.latest().block, 7, "block 9 is not final yet");
        let cps = |pairs: &[(u64, u8)]| -> Vec<(StarId, Address)> {
            pairs
                .iter()
                .map(|(id, a)| (StarId(*id), Address([*a; 20])))
                .collect()
        };
        assert_eq!(v.latest().control_planes, cps(&[(1, 0x11), (2, 0x02)]));
        let id = RegistryVersionId::new(421_614, star_registry(), 7, &MockRpc::header_of(7).hash);
        assert_eq!(v.latest().id, id);
        assert_eq!(v.latest().start, MockRpc::header_of(7).timestamp);
    }

    #[tokio::test]
    async fn a_refresh_reads_only_what_is_new() {
        let mut rpc = MockRpc::sepolia();
        rpc.answer(
            Network::ARBITRUM_SEPOLIA.directory,
            &param_call(STAR_REGISTRY_FROM),
            &U256::ZERO,
        );
        registered(&mut rpc, 3, 1, 0x01);
        role(&mut rpc, 5, 1, ROLE_NODE, ROLE_CONTROL_PLANE);
        role(&mut rpc, 9, 1, ROLE_CONTROL_PLANE, ROLE_NODE);
        rpc.block = 12;
        rpc.finalized = Some(8);
        let mut chain = connect(rpc).await;
        let mut history = RegistryHistory::new();
        history
            .refresh(&chain)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        chain.rpc.finalized = Some(12);
        history
            .refresh(&chain)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let v = history.versions().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(v.latest().block, 9);
        assert_eq!(v.latest().control_planes, Vec::new(), "the only CP left");
    }

    #[tokio::test]
    async fn a_change_to_an_unseen_star_is_an_error() {
        let mut rpc = MockRpc::sepolia();
        rpc.answer(
            Network::ARBITRUM_SEPOLIA.directory,
            &param_call(STAR_REGISTRY_FROM),
            &U256::ZERO,
        );
        role(&mut rpc, 5, 1, ROLE_NODE, ROLE_CONTROL_PLANE);
        let chain = connect(rpc).await;
        let mut history = RegistryHistory::new();
        assert!(history.refresh(&chain).await.is_err());
        assert!(
            history.versions().is_err(),
            "nothing kept from a failed read"
        );
    }

    #[tokio::test]
    async fn the_subscriber_log_reads_leaves_with_their_times() {
        let mut rpc = MockRpc::sepolia();
        let chain_for = Chain::connect(MockRpc::sepolia(), Network::ARBITRUM_SEPOLIA)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let contracts = chain_for.deployment.contracts.clone();
        let (registry, orbits) = (
            contracts
                .subscriber_registry
                .unwrap_or_else(|| unreachable!()),
            contracts.subscriptions.unwrap_or_else(|| unreachable!()),
        );
        for (index, token, block) in [(0u64, 5u64, 4u64), (1, 5, 4), (2, 6, 8)] {
            emit(
                &mut rpc,
                registry,
                block,
                &ISubscriberRegistry::Registered {
                    index: U256::from(index),
                    tokenId: U256::from(token),
                    commitment: U256::from(100 + index),
                },
            );
        }
        for (token, end) in [(5u64, 90_000u64), (6, 95_000)] {
            rpc.answer(
                orbits,
                &ISubscriptionNFT::expiresAtCall {
                    tokenId: U256::from(token),
                },
                &U256::from(end),
            );
        }
        rpc.answer(
            Network::ARBITRUM_SEPOLIA.directory,
            &param_call(SUBSCRIBER_REGISTRY_FROM),
            &U256::from(4),
        );
        rpc.block = 10;
        let chain = connect(rpc).await;
        let mut log = SubscriberLog::new();
        log.refresh(&chain).await.unwrap_or_else(|e| panic!("{e}"));
        let leaves = log.leaves();
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[2].inserted_at, MockRpc::header_of(8).timestamp);
        assert_eq!(leaves[2].expires_at, UnixTime(95_000));
        assert_eq!(leaves[1].commitment[31], 101);
    }

    #[cfg(feature = "zk")]
    #[test]
    fn a_windows_trees_are_the_control_planes() {
        use std::time::Duration;

        use crate::chain::Clock;
        use crate::id::Epoch;
        use crate::zk::FieldElement;

        // The journal's fixture: its commitments, and the roots the Go
        // journal builds for window 10's state 0 and state 1.
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/data/journal-fixture.json"))
                .unwrap_or_else(|e| panic!("{e}"));
        let leaves: Vec<SubscriberLeaf> = f["commitments"]
            .as_array()
            .unwrap_or_else(|| unreachable!())
            .iter()
            .map(|c| {
                let value: U256 = c["commitment"]
                    .as_str()
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or_default();
                SubscriberLeaf {
                    commitment: value.to_be_bytes::<32>(),
                    token: TokenId(0),
                    inserted_at: UnixTime(c["insertedAt"].as_i64().unwrap_or_default()),
                    expires_at: UnixTime(c["expiresAt"].as_i64().unwrap_or_default()),
                }
            })
            .collect();
        let log = SubscriberLog {
            next: Some(0),
            leaves: leaves.clone(),
            read_to: Some(UnixTime(10 * 86_400 + 1)),
            expiries: HashMap::new(),
        };
        let clock = Clock {
            epoch_zero: UnixTime(0),
            epoch_length: Duration::from_secs(86_400),
        };
        let root = |name: &str| {
            f[name]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches("0x")
                .to_owned()
        };
        let member = |i: usize| {
            FieldElement::from_be_bytes(&leaves[i].commitment).unwrap_or_else(|_| unreachable!())
        };

        // Leaf 2 was in before the window and lasts it: state 0.
        let early = log
            .window_tree(&clock, Epoch(10), member(2))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(early.state_index, 0);
        assert_eq!(early.valid_from, UnixTime(864_000));
        assert_eq!(
            hex::encode(early.group.root().to_be_bytes()),
            root("sweepRoot")
        );

        // Leaf 4 joined during the window: state 1, paid from its insertion.
        let late = log
            .window_tree(&clock, Epoch(10), member(4))
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(late.state_index, 1);
        assert_eq!(late.valid_from, leaves[4].inserted_at);
        assert_eq!(
            hex::encode(late.group.root().to_be_bytes()),
            root("insertedRoot")
        );

        // Leaf 1's Orbit ends inside the window: no tree of it has the member.
        assert_eq!(
            log.window_tree(&clock, Epoch(10), member(1)).err(),
            Some(WindowTreeError::NotAMember)
        );
        // Not read past the window's start: no tree yet.
        let unread = SubscriberLog {
            read_to: Some(UnixTime(863_999)),
            ..log
        };
        assert_eq!(
            unread.window_tree(&clock, Epoch(10), member(2)).err(),
            Some(WindowTreeError::NotReadYet)
        );
    }
}
