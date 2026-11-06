//! Where the protocol lives on a chain, and its clock.

use std::time::Duration;

use crate::id::{Address, Epoch, UnixTime};

/// A chain the protocol is deployed on, named by its one fixed address.
///
/// Everything else — the registries, the epoch clock — is read from the
/// `SingulaProtocol` directory at that address, so this is the only value a
/// client has to carry. It never comes from a Control Plane: a party that
/// could name the directory could name a subscriber set or a key registry of
/// its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// The chain id the RPC node must report.
    pub chain_id: u64,
    /// The `SingulaProtocol` directory.
    pub directory: Address,
}

impl Network {
    /// The test network on Arbitrum Sepolia.
    pub const ARBITRUM_SEPOLIA: Self = Self {
        chain_id: 421_614,
        directory: Address([
            0xc7, 0xaa, 0x88, 0x37, 0x5c, 0xe5, 0xb1, 0xd4, 0x37, 0x68, 0xea, 0x05, 0x45, 0x06,
            0x9c, 0xb2, 0x94, 0xfc, 0x29, 0x92,
        ]),
    };
}

/// What the directory reported when the connection was made.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Deployment {
    /// The chain the directory runs on.
    pub chain_id: u64,
    /// The protocol's epochs.
    pub clock: Clock,
    /// The contracts the directory points at.
    pub contracts: Contracts,
}

/// The contracts a [`Deployment`] consists of. `None` where the directory
/// has no entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Contracts {
    /// Stars: owners, signer keys and roles.
    pub star_registry: Option<Address>,
    /// The anonymity set: subscribers' identity commitments, in order.
    pub subscriber_registry: Option<Address>,
    /// Commitments to the keys Control Planes issue permissions under.
    pub permission_key_registry: Option<Address>,
    /// Control Planes' published endpoints.
    pub control_plane_registry: Option<Address>,
    /// Orbit, the subscription NFT.
    pub subscriptions: Option<Address>,
    /// Served time, attested per epoch.
    pub epoch_attestations: Option<Address>,
    /// The reward pool.
    pub reward_distributor: Option<Address>,
    /// ECHO, the protocol's token.
    pub echo_token: Option<Address>,
    /// The stablecoin subscriptions are priced in.
    pub usdc_token: Option<Address>,
    /// The relay that pays gas for users' signed requests.
    pub gas_station: Option<Address>,
}

/// The protocol's epochs: fixed-length periods counted from a fixed start.
///
/// Read once from the chain and computed locally after that; the pair is
/// fixed when `StarRegistry` is deployed and never changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// When epoch 0 began.
    pub epoch_zero: UnixTime,
    /// How long an epoch lasts. Never zero.
    pub epoch_length: Duration,
}

impl Clock {
    /// The epoch `at` falls in, or `None` before epoch 0.
    #[must_use]
    pub fn epoch_at(&self, at: UnixTime) -> Option<Epoch> {
        let since = u64::try_from(at.0.checked_sub(self.epoch_zero.0)?).ok()?;
        since.checked_div(self.epoch_length.as_secs()).map(Epoch)
    }

    /// The epoch now, by this machine's clock.
    #[must_use]
    pub fn current_epoch(&self) -> Option<Epoch> {
        self.epoch_at(UnixTime::now())
    }

    /// When `epoch` begins, or `None` if that is past the end of time.
    #[must_use]
    pub fn epoch_start(&self, epoch: Epoch) -> Option<UnixTime> {
        let offset = epoch.0.checked_mul(self.epoch_length.as_secs())?;
        self.epoch_zero.0.checked_add_unsigned(offset).map(UnixTime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOCK: Clock = Clock {
        epoch_zero: UnixTime(1_780_417_577),
        epoch_length: Duration::from_secs(86_400),
    };

    #[test]
    fn counts_epochs_from_zero() {
        assert_eq!(CLOCK.epoch_at(UnixTime(1_780_417_577)), Some(Epoch(0)));
        assert_eq!(
            CLOCK.epoch_at(UnixTime(1_780_417_577 + 86_399)),
            Some(Epoch(0))
        );
        assert_eq!(
            CLOCK.epoch_at(UnixTime(1_780_417_577 + 86_400)),
            Some(Epoch(1))
        );
        assert_eq!(CLOCK.epoch_at(UnixTime(1_780_417_576)), None);
        assert_eq!(
            CLOCK.epoch_start(Epoch(137)),
            Some(UnixTime(1_780_417_577 + 137 * 86_400))
        );
    }

    #[test]
    fn the_pinned_directory_is_the_deployed_one() {
        let want: Address = "0xC7aA88375cE5B1d43768EA0545069CB294Fc2992"
            .parse()
            .expect("an address");
        assert_eq!(Network::ARBITRUM_SEPOLIA.directory, want);
    }
}
