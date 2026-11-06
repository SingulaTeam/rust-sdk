//! Reading the protocol's contracts.
//!
//! A client trusts the chain for the facts no Control Plane may vouch for
//! itself: who runs which Star and with which signer key, where Control
//! Planes say they can be reached, who holds a subscription, and which
//! commitments make up the anonymity set. [`Chain`] reads them through the
//! `SingulaProtocol` directory, starting from a [`Network`]'s one fixed
//! address and an [`Rpc`] endpoint the application chose.
//!
//! ```no_run
//! # #[cfg(feature = "http")]
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use singula::StarId;
//! use singula::chain::{Chain, HttpRpc, Network};
//!
//! let rpc = HttpRpc::new("https://rpc.example")?;
//! let chain = Chain::connect(rpc, Network::ARBITRUM_SEPOLIA).await?;
//! let epoch = chain.deployment().clock.current_epoch();
//! let star = chain.star(StarId(4)).await?;
//! # let _ = (epoch, star);
//! # Ok(())
//! # }
//! ```

pub(crate) mod contracts;
mod deployment;
pub mod front;
#[cfg(feature = "http")]
mod http;
mod payments;
mod permissions;
mod rpc;
#[cfg(feature = "client")]
mod signing;
mod stars;
mod subscribers;
mod subscriptions;
#[cfg(test)]
pub(crate) mod testing;

use std::time::Duration;

use alloy_primitives::U256;
use alloy_sol_types::SolCall;

pub use deployment::{Clock, Contracts, Deployment, Network};
#[cfg(feature = "http")]
pub use http::HttpRpc;
pub use payments::{GasOp, Payment, fee_ceiling};
pub use permissions::PermissionKeyCommitment;
pub use rpc::{Block, Rpc, RpcError};
pub use stars::{ControlPlane, Role, Star};
pub use subscriptions::{Subscription, TokenId, TxHash};

use crate::id::{Address, UnixTime};
use contracts::ISingulaProtocol;

/// The protocol's contracts on one chain, read through one RPC endpoint.
#[derive(Debug)]
pub struct Chain<R> {
    rpc: R,
    network: Network,
    deployment: Deployment,
}

/// Why a read from the chain failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The RPC request failed.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// The RPC node is on another chain than the network's.
    #[error("the RPC node is on chain {actual}, not {expected}")]
    WrongChain {
        /// The network's chain id.
        expected: u64,
        /// The node's.
        actual: u64,
    },
    /// The directory has no entry for a contract this read needs.
    #[error("the directory names no {0}")]
    NotDeployed(&'static str),
    /// A contract's answer did not decode as its interface says.
    #[error("{0} returned something that does not decode")]
    Decode(&'static str),
    /// A contract returned a value outside what the protocol allows.
    #[error("{0} returned a value out of range")]
    OutOfRange(&'static str),
}

impl<R: Rpc> Chain<R> {
    /// Connects to `network` through `rpc`, reading the directory once.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::WrongChain`] if the node is on another chain —
    /// the same address on another chain is another contract, or none — and
    /// any error reading the directory.
    pub async fn connect(rpc: R, network: Network) -> Result<Self, ChainError> {
        let actual = rpc.chain_id().await?;
        if actual != network.chain_id {
            return Err(ChainError::WrongChain {
                expected: network.chain_id,
                actual,
            });
        }
        let deployment = read_deployment(&rpc, network).await?;
        Ok(Self {
            rpc,
            network,
            deployment,
        })
    }

    /// What the directory reported at connection.
    #[must_use]
    pub fn deployment(&self) -> &Deployment {
        &self.deployment
    }

    /// Reads the directory again and says whether it now publishes another
    /// deployment than the one this `Chain` connected to: a contract
    /// replaced, or the clock changed. A client that runs for long checks now
    /// and then and, when it has, connects again — the old contracts keep
    /// answering, so nothing else would tell it.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the directory cannot be read.
    pub async fn directory_moved(&self) -> Result<bool, ChainError> {
        Ok(read_deployment(&self.rpc, self.network).await? != self.deployment)
    }

    /// `ProtocolGovernor`, where proposals, votes and replies go. Read from
    /// the directory when asked rather than at connection: few clients take
    /// part in governance, and none needs it to connect.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::NotDeployed`] if the directory names none, and
    /// [`ChainError`] if it cannot be read.
    pub async fn protocol_governor(&self) -> Result<Address, ChainError> {
        let mut name = [0u8; 32];
        name[..PROTOCOL_GOVERNOR.len()].copy_from_slice(PROTOCOL_GOVERNOR.as_bytes());
        let a = self
            .read(
                self.network.directory,
                ISingulaProtocol::contractForCall { name: name.into() },
                Block::Latest,
                "contractFor",
            )
            .await?;
        required(entry(a), PROTOCOL_GOVERNOR)
    }
}

/// The governor's name in the directory.
const PROTOCOL_GOVERNOR: &str = "ProtocolGovernor";

/// The deployment `network`'s directory publishes now.
async fn read_deployment<R: Rpc>(rpc: &R, network: Network) -> Result<Deployment, ChainError> {
    let s = read(
        rpc,
        network.directory,
        ISingulaProtocol::snapshotCall {},
        Block::Latest,
        "snapshot",
    )
    .await?;
    // The directory reports the chain it executes on; it must agree.
    let reported = to_u64(s.chainId, "snapshot")?;
    if reported != network.chain_id {
        return Err(ChainError::WrongChain {
            expected: network.chain_id,
            actual: reported,
        });
    }
    let epoch_length = to_u64(s.epochDuration, "snapshot")?;
    if epoch_length == 0 {
        return Err(ChainError::OutOfRange("snapshot"));
    }
    let clock = Clock {
        epoch_zero: unix_time(to_u64(s.epochZeroStart, "snapshot")?, "snapshot")?,
        epoch_length: Duration::from_secs(epoch_length),
    };
    let contracts = Contracts {
        star_registry: entry(s.starRegistry),
        subscriber_registry: entry(s.subscriberRegistry),
        permission_key_registry: entry(s.voucherKeyRegistry),
        control_plane_registry: entry(s.cpEndpointRegistry),
        subscriptions: entry(s.subscriptionNft),
        epoch_attestations: entry(s.epochAttestations),
        reward_distributor: entry(s.rewardDistributor),
        echo_token: entry(s.echoToken),
        usdc_token: entry(s.usdcToken),
        gas_station: entry(s.gasStation),
    };
    Ok(Deployment {
        chain_id: reported,
        clock,
        contracts,
    })
}

impl<R: Rpc> Chain<R> {
    /// The transport.
    #[must_use]
    pub fn rpc(&self) -> &R {
        &self.rpc
    }

    /// Calls `call` on `to`, named `method` in errors.
    async fn read<C: SolCall + Send>(
        &self,
        to: Address,
        call: C,
        block: Block,
        method: &'static str,
    ) -> Result<C::Return, ChainError> {
        read(&self.rpc, to, call, block, method).await
    }
}

async fn read<R: Rpc, C: SolCall + Send>(
    rpc: &R,
    to: Address,
    call: C,
    block: Block,
    method: &'static str,
) -> Result<C::Return, ChainError> {
    let out = rpc.call(to, &call.abi_encode(), block).await?;
    C::abi_decode_returns(&out).map_err(|_| ChainError::Decode(method))
}

/// `address`, or the error naming the directory entry that is missing.
fn required(address: Option<Address>, name: &'static str) -> Result<Address, ChainError> {
    address.ok_or(ChainError::NotDeployed(name))
}

/// A directory entry; the zero address means "not set".
fn entry(a: alloy_primitives::Address) -> Option<Address> {
    (!a.is_zero()).then(|| Address(a.into_array()))
}

fn to_alloy(a: Address) -> alloy_primitives::Address {
    alloy_primitives::Address::from(a.0)
}

fn to_u64(v: U256, method: &'static str) -> Result<u64, ChainError> {
    u64::try_from(v).map_err(|_| ChainError::OutOfRange(method))
}

fn unix_time(seconds: u64, method: &'static str) -> Result<UnixTime, ChainError> {
    i64::try_from(seconds)
        .map(UnixTime)
        .map_err(|_| ChainError::OutOfRange(method))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::FixedBytes;

    use super::contracts::{
        ICPEndpointRegistry, IStarRegistry, ISubscriberRegistry, ISubscriptionNFT,
        IVoucherKeyRegistry,
    };
    use super::testing::MockRpc;
    use super::*;
    use crate::id::{Epoch, StarId};

    const SEPOLIA: Network = Network::ARBITRUM_SEPOLIA;

    fn mock() -> MockRpc {
        MockRpc::sepolia()
    }

    fn addr(s: &str) -> Address {
        s.parse().expect("an address")
    }

    const STAR_REGISTRY: &str = "0xced082443d1787e8014d2747f463ff9f2888447c";
    const SUBSCRIBERS: &str = "0x7be0a074b56bcd165c22258773811bdf819cd434";

    /// Reads can run on a multi-threaded runtime, as `tokio::spawn` needs.
    #[test]
    fn reads_are_send() {
        fn send<T: Send>(_: &T) {}
        let chain = Chain {
            rpc: mock(),
            network: SEPOLIA,
            deployment: Deployment {
                chain_id: SEPOLIA.chain_id,
                clock: Clock {
                    epoch_zero: UnixTime(0),
                    epoch_length: Duration::from_secs(1),
                },
                contracts: Contracts {
                    star_registry: None,
                    subscriber_registry: None,
                    permission_key_registry: None,
                    control_plane_registry: None,
                    subscriptions: None,
                    epoch_attestations: None,
                    reward_distributor: None,
                    echo_token: None,
                    usdc_token: None,
                    gas_station: None,
                },
            },
        };
        send(&Chain::connect(mock(), SEPOLIA));
        send(&chain.star(StarId(1)));
        send(&chain.control_planes());
        send(&chain.subscriber_commitments());
        send(&chain.subscriptions(Address([0; 20])));
        send(&chain.permission_key_commitment(StarId(1), Epoch(1)));
    }

    #[tokio::test]
    async fn notices_a_contract_replaced_in_the_directory() {
        let mut chain = Chain::connect(mock(), SEPOLIA).await.expect("connects");
        assert!(!chain.directory_moved().await.expect("reads"));

        // The same snapshot with another GasStation.
        let mut snapshot =
            alloy_primitives::hex::decode(include_str!("snapshot-arbitrum-sepolia.hex").trim())
                .expect("hex");
        let old = addr("0x63ffBD0A2F38cd7093b2887227cA9Ff35D44A469").0;
        let at = snapshot
            .windows(20)
            .position(|w| w == old)
            .expect("the snapshot names the station");
        snapshot[at + 19] ^= 1;
        chain.rpc.answer_raw(
            SEPOLIA.directory,
            &contracts::ISingulaProtocol::snapshotCall {},
            snapshot,
        );
        assert!(chain.directory_moved().await.expect("reads"));
    }

    #[tokio::test]
    async fn reads_the_directory() {
        let chain = Chain::connect(mock(), SEPOLIA).await.expect("connects");
        let d = chain.deployment();
        assert_eq!(d.chain_id, 421_614);
        assert_eq!(d.clock.epoch_zero, UnixTime(1_780_417_577));
        assert_eq!(d.clock.epoch_length, Duration::from_secs(86_400));
        assert_eq!(d.contracts.star_registry, Some(addr(STAR_REGISTRY)));
        assert_eq!(d.contracts.subscriber_registry, Some(addr(SUBSCRIBERS)));
        assert_eq!(
            d.contracts.gas_station,
            Some(addr("0x63ffBD0A2F38cd7093b2887227cA9Ff35D44A469"))
        );
    }

    #[tokio::test]
    async fn refuses_a_node_on_another_chain() {
        let mut rpc = mock();
        rpc.chain_id = 1;
        assert!(matches!(
            Chain::connect(rpc, SEPOLIA).await,
            Err(ChainError::WrongChain {
                expected: 421_614,
                actual: 1
            })
        ));
    }

    #[tokio::test]
    async fn reads_a_star() {
        let mut rpc = mock();
        let owner = addr("0x804aE4C760B39a084B2E9840C598697Afc3cad15");
        let signer = addr("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
        let info = IStarRegistry::StarInfo {
            owner: to_alloy(owner),
            signer: to_alloy(signer),
            role: 1,
            registerEpoch: 12,
        };
        rpc.answer(
            addr(STAR_REGISTRY),
            &IStarRegistry::getStarCall {
                starId: U256::from(4),
            },
            &info,
        );
        let empty = IStarRegistry::StarInfo {
            owner: alloy_primitives::Address::ZERO,
            signer: alloy_primitives::Address::ZERO,
            role: 0,
            registerEpoch: 0,
        };
        rpc.answer(
            addr(STAR_REGISTRY),
            &IStarRegistry::getStarCall {
                starId: U256::from(5),
            },
            &empty,
        );
        rpc.answer(
            addr(STAR_REGISTRY),
            &IStarRegistry::getStarIdBySignerCall {
                signer: to_alloy(signer),
            },
            &U256::from(4),
        );

        let chain = Chain::connect(rpc, SEPOLIA).await.expect("connects");
        let star = chain.star(StarId(4)).await.expect("reads").expect("exists");
        assert_eq!(
            (star.owner, star.signer, star.role, star.registered_in),
            (owner, signer, Role::Node, Epoch(12))
        );
        assert_eq!(chain.star(StarId(5)).await.expect("reads"), None);
        assert_eq!(
            chain.star_by_signer(signer).await.expect("reads"),
            Some(StarId(4))
        );
    }

    #[tokio::test]
    async fn reads_control_planes() {
        let mut rpc = mock();
        let registry = addr("0xf0caf0d2f0f5fcfc493889d49ed204f628ea1f78");
        rpc.answer(
            registry,
            &ICPEndpointRegistry::getActiveEndpointsCall {},
            &ICPEndpointRegistry::getActiveEndpointsReturn {
                starIds: vec![U256::from(1), U256::from(7)],
                hosts: vec!["cp1.example".to_owned(), "cp7.example".to_owned()],
                ports: vec![443, 0],
                updatedAts: vec![1_760_000_000, 1_760_000_001],
            },
        );
        let chain = Chain::connect(rpc, SEPOLIA).await.expect("connects");
        let cps = chain.control_planes().await.expect("reads");
        assert_eq!(cps.len(), 2);
        assert_eq!(
            (
                cps[0].star,
                cps[0].host.as_str(),
                cps[0].port.map(u16::from)
            ),
            (StarId(1), "cp1.example", Some(443))
        );
        assert_eq!(cps[1].port, None, "port 0 means the default");
    }

    #[tokio::test]
    async fn reads_the_whole_set_against_one_block() {
        let mut rpc = mock();
        let registry = addr(SUBSCRIBERS);
        let total = 1_203u64;
        let leaf = |i: u64| U256::from(i * 3 + 1);
        rpc.answer(
            registry,
            &ISubscriberRegistry::totalCommitmentsCall {},
            &U256::from(total),
        );
        for start in (0..total).step_by(500) {
            let page: Vec<U256> = (start..total.min(start + 500)).map(leaf).collect();
            rpc.answer(
                registry,
                &ISubscriberRegistry::commitmentsSliceCall {
                    start: U256::from(start),
                    count: U256::from(500),
                },
                &page,
            );
        }
        let chain = Chain::connect(rpc, SEPOLIA).await.expect("connects");
        let set = chain.subscriber_commitments().await.expect("reads");
        assert_eq!(set.len(), 1_203);
        assert_eq!(set[1_202], leaf(1_202).to_be_bytes::<32>());
        let seen = chain
            .rpc()
            .blocks_seen
            .lock()
            .expect("not poisoned")
            .clone();
        // The directory read used the newest block; every page used one fixed block.
        assert!(
            seen[1..].iter().all(|b| *b == Block::Number(1_000)),
            "{seen:?}"
        );
        assert_eq!(seen.len(), 1 + 1 + 3);
    }

    #[tokio::test]
    async fn notices_a_short_page() {
        let mut rpc = mock();
        let registry = addr(SUBSCRIBERS);
        rpc.answer(
            registry,
            &ISubscriberRegistry::totalCommitmentsCall {},
            &U256::from(3),
        );
        rpc.answer(
            registry,
            &ISubscriberRegistry::commitmentsSliceCall {
                start: U256::ZERO,
                count: U256::from(500),
            },
            &vec![U256::from(1), U256::from(2)],
        );
        let chain = Chain::connect(rpc, SEPOLIA).await.expect("connects");
        assert!(matches!(
            chain.subscriber_commitments().await,
            Err(ChainError::Decode("commitmentsSlice"))
        ));
    }

    #[tokio::test]
    async fn reads_a_wallets_subscriptions() {
        let mut rpc = mock();
        let nft = addr("0xa0c2f384345cbc868d25e5df4f555c6db2795f85");
        let owner = to_alloy(addr("0x804aE4C760B39a084B2E9840C598697Afc3cad15"));
        rpc.answer(
            nft,
            &ISubscriptionNFT::balanceOfCall { owner },
            &U256::from(2),
        );
        for (i, (id, starts, expires, active)) in [
            (11u64, 1_787_408_000u64, 1_790_000_000u64, true),
            (12, 0, 0, false),
        ]
        .into_iter()
        .enumerate()
        {
            let token = U256::from(id);
            rpc.answer(
                nft,
                &ISubscriptionNFT::tokenOfOwnerByIndexCall {
                    owner,
                    index: U256::from(i),
                },
                &token,
            );
            rpc.answer(
                nft,
                &ISubscriptionNFT::expiresAtCall { tokenId: token },
                &U256::from(expires),
            );
            rpc.answer(
                nft,
                &ISubscriptionNFT::activatedAtCall { tokenId: token },
                &U256::from(starts),
            );
            rpc.answer(
                nft,
                &ISubscriptionNFT::isTokenActiveCall { tokenId: token },
                &active,
            );
            rpc.answer(nft, &ISubscriptionNFT::slotsOfCall { tokenId: token }, &2u8);
        }
        let chain = Chain::connect(rpc, SEPOLIA).await.expect("connects");
        let subs = chain
            .subscriptions(Address(owner.into_array()))
            .await
            .expect("reads");
        assert_eq!(subs.len(), 2);
        assert_eq!(
            (
                subs[0].token,
                subs[0].starts_at,
                subs[0].expires_at,
                subs[0].active
            ),
            (
                TokenId(11),
                Some(UnixTime(1_787_408_000)),
                Some(UnixTime(1_790_000_000)),
                true
            )
        );
        assert_eq!(
            (subs[1].starts_at, subs[1].expires_at, subs[1].active),
            (None, None, false),
            "not yet activated"
        );
    }

    #[tokio::test]
    async fn reads_a_permission_key_commitment() {
        let mut rpc = mock();
        let registry = addr("0xe88168636f525122c27482f09144759ea281869d");
        let call = |window: u64| IVoucherKeyRegistry::getEpochKeyCall {
            issuerStarId: U256::from(7),
            epoch: U256::from(window),
        };
        rpc.answer(
            registry,
            &call(137),
            &IVoucherKeyRegistry::getEpochKeyReturn {
                keyHash: FixedBytes([9; 32]),
                denominationGB: 5,
                setAt: 1_760_000_000,
                issuerActive: true,
            },
        );
        rpc.answer(
            registry,
            &call(138),
            &IVoucherKeyRegistry::getEpochKeyReturn {
                keyHash: FixedBytes::ZERO,
                denominationGB: 0,
                setAt: 0,
                issuerActive: true,
            },
        );
        let chain = Chain::connect(rpc, SEPOLIA).await.expect("connects");
        let k = chain
            .permission_key_commitment(StarId(7), Epoch(137))
            .await
            .expect("reads")
            .expect("committed");
        assert_eq!(
            (k.key_hash, k.packet_size, k.issuer_active),
            ([9; 32], 5, true)
        );
        assert_eq!(
            chain
                .permission_key_commitment(StarId(7), Epoch(138))
                .await
                .expect("reads"),
            None
        );
    }
}
