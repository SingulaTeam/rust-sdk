//! Who counts towards a majority, and checking that one was reached.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use super::JournalParams;
use super::attestation::Attestation;
use crate::id::{Address, StarId, UnixTime};

/// How long after a registry version is superseded its Control Planes'
/// attestations still count: time for the change to finalize on Ethereum and
/// reach every Control Plane. The Control Planes' `ledgerVersionGrace`.
pub const VERSION_GRACE: Duration = Duration::from_secs(3600);

/// A registry version's id:
///
/// ```text
/// keccak256("singula-registry-v1" ‖ chainId ‖ registry ‖ block ‖ block hash)
/// ```
///
/// with `chainId` and `block` 8 bytes big-endian and `registry` the 20-byte
/// address of `StarRegistry`, so attestations made against one registry
/// never pass for another after a move.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegistryVersionId(pub [u8; 32]);

impl RegistryVersionId {
    /// The id of the version that `block`, hashed `block_hash`, started.
    #[must_use]
    pub fn new(chain_id: u64, registry: Address, block: u64, block_hash: &[u8; 32]) -> Self {
        let mut e = super::Encoder::tagged("singula-registry-v1");
        e.u64(chain_id)
            .bytes(&registry.0)
            .u64(block)
            .bytes(block_hash);
        Self(e.keccak())
    }
}

impl fmt::Debug for RegistryVersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegistryVersionId(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        write!(f, ")")
    }
}

/// The Control Plane set as of the end of `block`, the block that last
/// changed it: the Stars holding the Control Plane role in `StarRegistry`,
/// each with the key it signs with.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegistryVersion {
    /// The version's id.
    pub id: RegistryVersionId,
    /// The block that started it.
    pub block: u64,
    /// That block's timestamp.
    pub start: UnixTime,
    /// The Control Planes and their signer keys.
    pub control_planes: Vec<(StarId, Address)>,
}

impl RegistryVersion {
    /// A version as read from the chain.
    #[must_use]
    pub fn new(
        id: RegistryVersionId,
        block: u64,
        start: UnixTime,
        control_planes: Vec<(StarId, Address)>,
    ) -> Self {
        Self {
            id,
            block,
            start,
            control_planes,
        }
    }

    /// How many Control Planes of this version make a strict majority.
    #[must_use]
    pub fn quorum(&self) -> usize {
        self.control_planes.len() / 2 + 1
    }

    fn signer(&self, cp: StarId) -> Option<Address> {
        self.control_planes
            .iter()
            .find(|(id, _)| *id == cp)
            .map(|(_, signer)| *signer)
    }
}

/// A registry's history, indexed for checking acks.
#[derive(Debug, Clone)]
pub struct Versions {
    /// In block order.
    versions: Vec<RegistryVersion>,
}

/// Why a history is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VersionsError {
    /// No versions at all.
    #[error("the registry history is empty")]
    Empty,
    /// Two versions share a block or an id.
    #[error("two registry versions at one block or with one id")]
    Duplicate,
}

/// A ping recorded by a strict majority of one registry version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Committed {
    /// The ping's time: the lower median of the majority's attestations.
    pub at: UnixTime,
    /// The version the majority belongs to.
    pub version: RegistryVersionId,
}

/// Why an ack does not show that a ping reached the journal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AckError {
    /// The ack names a version this history does not hold: read the
    /// registry again, then check once more.
    #[error("the ack names a registry version not read yet")]
    UnknownVersion,
    /// The version was superseded longer ago than [`VERSION_GRACE`]: its
    /// Control Planes no longer speak for the journal.
    #[error("the ack's registry version is out of date")]
    StaleVersion,
    /// An attestation in the ack does not check out against its version: a
    /// Control Plane outside it, a wrong signer, or a time outside the
    /// version's span. The Control Plane that sent it should not be trusted.
    #[error("the attestation by Control Plane {0} does not check out")]
    BadAttestation(StarId),
    /// Fewer Control Planes than a strict majority of the version attested.
    #[error("{have} of the {need} attestations a majority needs")]
    NoQuorum {
        /// Distinct Control Planes that attested.
        have: usize,
        /// A strict majority of the version.
        need: usize,
    },
}

impl Versions {
    /// The history made of `versions`, in any order.
    ///
    /// # Errors
    ///
    /// Returns [`VersionsError`] if it is empty or has duplicates.
    pub fn new(mut versions: Vec<RegistryVersion>) -> Result<Self, VersionsError> {
        if versions.is_empty() {
            return Err(VersionsError::Empty);
        }
        versions.sort_by_key(|v| v.block);
        let duplicate = versions.windows(2).any(|w| w[0].block == w[1].block)
            || versions
                .iter()
                .enumerate()
                .any(|(i, v)| versions[..i].iter().any(|u| u.id == v.id));
        if duplicate {
            return Err(VersionsError::Duplicate);
        }
        Ok(Self { versions })
    }

    /// The newest version.
    #[must_use]
    pub fn latest(&self) -> &RegistryVersion {
        // Never empty: checked in `new`.
        &self.versions[self.versions.len() - 1]
    }

    /// Checks the attestations an ack carried for the ping hashed
    /// `ping_hash`: that `version` is one still speaking for the journal at
    /// `now`, and that a strict majority of it attested, each with its own
    /// key and inside the version's span.
    ///
    /// Attestations naming another version are not counted; one naming this
    /// version that does not check out fails the whole ack.
    ///
    /// # Errors
    ///
    /// Returns [`AckError`] saying what is missing.
    pub fn check_ack(
        &self,
        params: JournalParams,
        ping_hash: &[u8; 32],
        version: RegistryVersionId,
        attestations: &[Attestation],
        now: UnixTime,
    ) -> Result<Committed, AckError> {
        let i = self
            .versions
            .iter()
            .position(|v| v.id == version)
            .ok_or(AckError::UnknownVersion)?;
        let v = &self.versions[i];
        let grace = i64::try_from(VERSION_GRACE.as_secs()).unwrap_or(i64::MAX);
        let end = self.versions.get(i + 1).map(|next| next.start.0);
        if end.is_some_and(|end| now.0 >= end.saturating_add(grace)) {
            return Err(AckError::StaleVersion);
        }

        let mut by_cp = BTreeMap::new();
        for a in attestations.iter().filter(|a| a.version == version) {
            let in_span = a.received_at >= v.start
                && end.is_none_or(|end| a.received_at.0 < end.saturating_add(grace));
            let signed = v
                .signer(a.cp)
                .is_some_and(|want| a.signer(params, ping_hash) == Some(want));
            if !in_span || !signed {
                return Err(AckError::BadAttestation(a.cp));
            }
            let earliest = by_cp.entry(a.cp).or_insert(a.received_at);
            *earliest = (*earliest).min(a.received_at);
        }
        if by_cp.len() < v.quorum() {
            return Err(AckError::NoQuorum {
                have: by_cp.len(),
                need: v.quorum(),
            });
        }
        let mut times: Vec<UnixTime> = by_cp.into_values().collect();
        times.sort_unstable();
        Ok(Committed {
            at: times[(times.len() - 1) / 2],
            version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth;

    const PARAMS: JournalParams = JournalParams::new(421_614);
    const PING: [u8; 32] = [9; 32];
    const GRACE: i64 = 3600;

    struct Cp {
        id: StarId,
        key: k256::ecdsa::SigningKey,
    }

    impl Cp {
        fn new(id: u64) -> Self {
            let mut secret = [0u8; 32];
            secret[31] = u8::try_from(id).unwrap_or(1);
            secret[0] = 1;
            Self {
                id: StarId(id),
                key: k256::ecdsa::SigningKey::from_slice(&secret)
                    .unwrap_or_else(|_| unreachable!()),
            }
        }

        fn member(&self) -> (StarId, Address) {
            (self.id, eth::address_of(self.key.verifying_key()))
        }

        fn attest(&self, version: RegistryVersionId, at: i64) -> Attestation {
            let mut a = Attestation::new(self.id, UnixTime(at), version, [0; 65]);
            a.signature = eth::sign(&self.key, &a.digest(PARAMS, &PING));
            a
        }
    }

    fn version(block: u64, start: i64, cps: &[&Cp]) -> RegistryVersion {
        RegistryVersion::new(
            RegistryVersionId::new(PARAMS.chain_id, Address([0x5a; 20]), block, &[0; 32]),
            block,
            UnixTime(start),
            cps.iter().map(|c| c.member()).collect(),
        )
    }

    #[test]
    fn a_version_speaks_until_its_grace_runs_out() {
        let (a, b, c) = (Cp::new(1), Cp::new(2), Cp::new(3));
        let v1 = version(10, 1_000, &[&a, &b, &c]);
        let v2 = version(20, 5_000, &[&a, &b]); // C banned at 5000
        let versions = Versions::new(vec![v2, v1.clone()]).unwrap_or_else(|_| unreachable!());
        let acks = [a.attest(v1.id, 4_000), c.attest(v1.id, 4_000)];

        assert!(
            versions
                .check_ack(PARAMS, &PING, v1.id, &acks, UnixTime(5_000 + GRACE - 1))
                .is_ok()
        );
        assert_eq!(
            versions.check_ack(PARAMS, &PING, v1.id, &acks, UnixTime(5_000 + GRACE)),
            Err(AckError::StaleVersion)
        );
        assert_eq!(
            versions.check_ack(
                PARAMS,
                &PING,
                RegistryVersionId([1; 32]),
                &acks,
                UnixTime(5_000)
            ),
            Err(AckError::UnknownVersion)
        );
    }

    #[test]
    fn an_attestation_outside_its_version_fails_the_ack() {
        let (a, b, c) = (Cp::new(1), Cp::new(2), Cp::new(3));
        let v1 = version(10, 1_000, &[&a, &b, &c]);
        let v2 = version(20, 5_000, &[&a, &b]);
        let versions = Versions::new(vec![v1.clone(), v2]).unwrap_or_else(|_| unreachable!());
        let now = UnixTime(5_100);
        // Stamped after the grace of a version already superseded.
        let late = [a.attest(v1.id, 4_000), c.attest(v1.id, 5_000 + GRACE)];
        assert_eq!(
            versions.check_ack(PARAMS, &PING, v1.id, &late, now),
            Err(AckError::BadAttestation(StarId(3)))
        );
        // Stamped before the version began.
        let early = [a.attest(v1.id, 999), b.attest(v1.id, 1_000)];
        assert_eq!(
            versions.check_ack(PARAMS, &PING, v1.id, &early, now),
            Err(AckError::BadAttestation(StarId(1)))
        );
        // Signed by a key that is not this CP's.
        let mut forged = b.attest(v1.id, 2_000);
        forged.cp = StarId(1);
        assert_eq!(
            versions.check_ack(PARAMS, &PING, v1.id, &[forged, b.attest(v1.id, 2_000)], now),
            Err(AckError::BadAttestation(StarId(1)))
        );
    }

    #[test]
    fn only_the_named_versions_votes_count_one_per_control_plane() {
        let (a, b, c) = (Cp::new(1), Cp::new(2), Cp::new(3));
        let v1 = version(10, 1_000, &[&a, &b, &c]);
        let v2 = version(20, 5_000, &[&a, &b, &c]);
        let versions =
            Versions::new(vec![v1.clone(), v2.clone()]).unwrap_or_else(|_| unreachable!());
        let now = UnixTime(6_000);
        // A twice and B once under v1, C under v2: one v1 vote short of two.
        let acks = [
            a.attest(v1.id, 5_200),
            a.attest(v1.id, 5_100),
            c.attest(v2.id, 5_300),
        ];
        assert_eq!(
            versions.check_ack(PARAMS, &PING, v1.id, &acks, now),
            Err(AckError::NoQuorum { have: 1, need: 2 })
        );
        let acks = [
            a.attest(v1.id, 5_200),
            a.attest(v1.id, 5_100),
            b.attest(v1.id, 5_400),
        ];
        let committed = versions.check_ack(PARAMS, &PING, v1.id, &acks, now);
        assert_eq!(
            committed.map(|c| c.at),
            Ok(UnixTime(5_100)),
            "A's earlier stamp is its vote"
        );
    }

    #[test]
    fn a_history_is_one() {
        let a = Cp::new(1);
        assert_eq!(Versions::new(vec![]).err(), Some(VersionsError::Empty));
        let v = version(10, 1_000, &[&a]);
        assert_eq!(
            Versions::new(vec![v.clone(), v]).err(),
            Some(VersionsError::Duplicate)
        );
    }
}
