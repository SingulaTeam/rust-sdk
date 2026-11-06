//! What a Control Plane says about itself and about a signed-in wallet.

use super::auth::WalletAuth;
use super::call::{Conversation, Step, exchange};
use super::proto::admin::HealthRequest;
use super::proto::admin::admin_service_client::AdminServiceClient;
use super::proto::client::GetNetworkInfoRequest;
use super::proto::client::client_message::Message as Outbound;
use super::proto::client::control_plane_message::Message as Inbound;
use super::{ClientError, ControlPlaneClient};
use crate::chain::TokenId;
use crate::id::{Address, UnixTime};

/// Whether a Control Plane is answering, and how well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Health {
    /// `false` when it reports itself degraded.
    pub healthy: bool,
    /// Its clock. A large difference from this machine's will make its
    /// time-bound checks — sign-ins, renewals — fail.
    pub time: UnixTime,
}

/// A wallet's subscription, as the Control Plane sees it.
///
/// The Control Plane's reading, for display; the chain is the authority —
/// see [`Chain::subscriptions`](crate::chain::Chain::subscriptions).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SubscriptionInfo {
    /// Whether it entitles the wallet to service now.
    pub active: bool,
    /// When it lapses.
    pub expires_at: Option<UnixTime>,
    /// The active Orbit token.
    pub token: Option<TokenId>,
    /// Tokens the wallet holds but has not activated.
    pub unactivated: u32,
}

/// Contract addresses and prices, as a Control Plane states them.
///
/// # Security
///
/// For display only. Every value comes from the Control Plane, which is the
/// party a client checks things against; a hostile one could name its own
/// contracts and its own RPC node and be verified against a reality of its
/// making. Read anything a decision rests on through
/// [`Chain`](crate::chain::Chain) instead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkInfo {
    /// The chain id it says it runs on.
    pub chain_id: u64,
    /// The subscription contract it names.
    pub subscriptions: Option<Address>,
    /// ECHO's contract.
    pub echo_token: Option<Address>,
    /// USDC's contract.
    pub usdc_token: Option<Address>,
    /// The price in USDC's smallest unit, as stated.
    pub price_usdc: String,
    /// The price in ECHO's smallest unit, before any discount, as stated.
    pub price_echo: String,
}

impl ControlPlaneClient {
    /// Whether this Control Plane is answering.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the call fails.
    pub async fn health(&self) -> Result<Health, ClientError> {
        let mut client = AdminServiceClient::new(self.channel.clone());
        let answer = tokio::time::timeout(self.timeout, client.get_health(HealthRequest {}))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|s| ClientError::from_status(&s))?
            .into_inner();
        Ok(Health {
            healthy: answer.status == "healthy",
            time: UnixTime(answer.time),
        })
    }

    /// `auth`'s wallet's subscription, as this Control Plane sees it.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Refused`] if the sign-in is not accepted, and
    /// any error of the call.
    pub async fn subscription(&self, auth: &WalletAuth) -> Result<SubscriptionInfo, ClientError> {
        exchange(
            self,
            Conversation {
                auth: Some(auth),
                request: None,
                messages: Vec::new(),
            },
            |m| match m {
                Inbound::AuthResult(r) => {
                    let s = r.subscription.unwrap_or_default();
                    Step::Done(Ok(SubscriptionInfo {
                        active: s.is_active,
                        expires_at: (s.expires_at > 0).then_some(UnixTime(s.expires_at)),
                        token: u64::try_from(s.token_id)
                            .ok()
                            .filter(|&t| t > 0)
                            .map(TokenId),
                        unactivated: u32::try_from(s.unactivated_count).unwrap_or(0),
                    }))
                }
                _ => Step::Skip,
            },
        )
        .await
    }

    /// The contracts and prices this Control Plane states; see
    /// [`NetworkInfo`] for why they are for display only.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the call fails.
    pub async fn network_info(&self) -> Result<NetworkInfo, ClientError> {
        let message = Outbound::GetNetworkInfo(GetNetworkInfoRequest {});
        exchange(
            self,
            Conversation {
                auth: None,
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::NetworkInfo(n) => Step::Done(Ok(NetworkInfo {
                    chain_id: u64::try_from(n.chain_id).unwrap_or(0),
                    subscriptions: n.subscription_nft_addr.parse().ok(),
                    echo_token: n.echo_token_address.parse().ok(),
                    usdc_token: n.usdc_token_address.parse().ok(),
                    price_usdc: n.price_usdc_wei,
                    price_echo: n.price_echo_wei,
                })),
                _ => Step::Skip,
            },
        )
        .await
    }
}
