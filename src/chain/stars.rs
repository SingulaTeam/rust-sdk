//! Stars and the Control Planes among them.

use std::num::NonZeroU16;

use alloy_primitives::U256;

use super::contracts::{ICPEndpointRegistry, IStarRegistry};
use super::{Block, Chain, ChainError, Rpc, entry, required, to_alloy, to_u64, unix_time};
use crate::id::{Address, Epoch, StarId, UnixTime};

/// A Star as `StarRegistry` records it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Star {
    /// Its id.
    pub id: StarId,
    /// The wallet that registered it and collects its rewards. Fixed at
    /// registration, so two Stars with one owner are one operator.
    pub owner: Address,
    /// The key the Star signs with: its answers to clients, its reports.
    pub signer: Address,
    /// What it currently does.
    pub role: Role,
    /// The epoch it registered in.
    pub registered_in: Epoch,
}

/// What a Star does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// It carries traffic.
    Node,
    /// It coordinates nodes and admits clients.
    ControlPlane,
    /// It was removed from the network.
    Banned,
}

/// A Control Plane's published endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ControlPlane {
    /// The Control Plane's Star id.
    pub star: StarId,
    /// Host name or IP address literal, as its owner published it.
    pub host: String,
    /// The gRPC port, or `None` for the protocol's default.
    pub port: Option<NonZeroU16>,
    /// When the endpoint last changed.
    pub updated_at: UnixTime,
    /// Its front's REALITY public key, if it published one; see
    /// [`front`](super::front).
    pub reality_key: Option<[u8; 32]>,
}

impl<R: Rpc> Chain<R> {
    /// The Star with this id, or `None` if there is none.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn star(&self, id: StarId) -> Result<Option<Star>, ChainError> {
        let registry = required(self.deployment.contracts.star_registry, "StarRegistry")?;
        let info = self
            .read(
                registry,
                IStarRegistry::getStarCall {
                    starId: U256::from(id.0),
                },
                Block::Latest,
                "getStar",
            )
            .await?;
        let role = match info.role {
            // `Role.None`: no Star was ever registered here, or it was removed.
            0 => return Ok(None),
            1 => Role::Node,
            2 => Role::ControlPlane,
            3 => Role::Banned,
            _ => return Err(ChainError::OutOfRange("getStar")),
        };
        let (Some(owner), Some(signer)) = (entry(info.owner), entry(info.signer)) else {
            return Err(ChainError::OutOfRange("getStar"));
        };
        Ok(Some(Star {
            id,
            owner,
            signer,
            role,
            registered_in: Epoch(info.registerEpoch),
        }))
    }

    /// The Star whose signer key is `signer`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn star_by_signer(&self, signer: Address) -> Result<Option<StarId>, ChainError> {
        let registry = required(self.deployment.contracts.star_registry, "StarRegistry")?;
        let id = self
            .read(
                registry,
                IStarRegistry::getStarIdBySignerCall {
                    signer: to_alloy(signer),
                },
                Block::Latest,
                "getStarIdBySigner",
            )
            .await?;
        Ok(match to_u64(id, "getStarIdBySigner")? {
            0 => None,
            id => Some(StarId(id)),
        })
    }

    /// Every Control Plane that holds the role and has published an endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn control_planes(&self) -> Result<Vec<ControlPlane>, ChainError> {
        let registry = required(
            self.deployment.contracts.control_plane_registry,
            "CPEndpointRegistry",
        )?;
        let all = self
            .read(
                registry,
                ICPEndpointRegistry::getActiveEndpointsCall {},
                Block::Latest,
                "getActiveEndpoints",
            )
            .await?;
        let n = all.starIds.len();
        if all.hosts.len() != n || all.ports.len() != n || all.updatedAts.len() != n {
            return Err(ChainError::Decode("getActiveEndpoints"));
        }
        let mut planes = all
            .starIds
            .into_iter()
            .zip(all.hosts)
            .zip(all.ports.into_iter().zip(all.updatedAts))
            .map(|((id, host), (port, updated))| {
                Ok(ControlPlane {
                    star: StarId(to_u64(id, "getActiveEndpoints")?),
                    host,
                    port: NonZeroU16::new(port),
                    updated_at: unix_time(updated, "getActiveEndpoints")?,
                    reality_key: None,
                })
            })
            .collect::<Result<Vec<_>, ChainError>>()?;
        for cp in &mut planes {
            cp.reality_key = self.reality_key(registry, cp.star).await;
        }
        Ok(planes)
    }

    /// A Control Plane's REALITY key, if it published one. A registry from
    /// before fronts has none to give, and a failed read is no key: the
    /// endpoint itself still works.
    async fn reality_key(&self, registry: Address, star: StarId) -> Option<[u8; 32]> {
        let key = self
            .read(
                registry,
                ICPEndpointRegistry::getRealityKeyCall {
                    starId: U256::from(star.0),
                },
                Block::Latest,
                "getRealityKey",
            )
            .await
            .ok()?;
        let key: [u8; 32] = key.0;
        (key != [0; 32]).then_some(key)
    }

    /// Control Plane `id`'s endpoint, or `None` if it has none or no longer
    /// holds the role.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if the read fails.
    pub async fn control_plane(&self, id: StarId) -> Result<Option<ControlPlane>, ChainError> {
        let registry = required(
            self.deployment.contracts.control_plane_registry,
            "CPEndpointRegistry",
        )?;
        let e = self
            .read(
                registry,
                ICPEndpointRegistry::getEndpointCall {
                    starId: U256::from(id.0),
                },
                Block::Latest,
                "getEndpoint",
            )
            .await?;
        if !e.active {
            return Ok(None);
        }
        Ok(Some(ControlPlane {
            star: id,
            host: e.host,
            port: NonZeroU16::new(e.port),
            updated_at: unix_time(e.updatedAt, "getEndpoint")?,
            reality_key: self.reality_key(registry, id).await,
        }))
    }
}
