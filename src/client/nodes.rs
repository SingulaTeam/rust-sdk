//! Which nodes a Control Plane can serve.

use std::time::Duration;

use super::call::{Conversation, Step, exchange, request_id};
use super::proto::client::client_message::Message as Outbound;
use super::proto::client::control_plane_message::Message as Inbound;
use super::proto::client::{ListCountriesRequest, ListNodesRequest};
use super::{ClientError, ControlPlaneClient, Country};
use crate::id::StarId;

/// A node a Control Plane offers, described by what a client needs to choose.
///
/// No address: that arrives only with a session, so that the list is not a
/// map of the network. Who runs the node is for the client to read from the
/// chain under [`star`](Self::star).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct NodeCandidate {
    /// The node's Star id.
    pub star: StarId,
    /// Where the node says it is.
    pub country: Option<Country>,
    /// The Control Plane's round trip to the node; `None` until measured.
    /// Add the client's own round trip to the Control Plane for the closest
    /// estimate of the whole path.
    pub latency: Option<Duration>,
    /// How busy the node is, from 0 to 1.
    pub load: f32,
    /// Whether it is accepting sessions.
    pub available: bool,
}

/// How many nodes a Control Plane can serve in one country.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CountryNodes {
    /// The country.
    pub country: Country,
    /// Available nodes there.
    pub nodes: u32,
}

impl ControlPlaneClient {
    /// The nodes this Control Plane can serve now, in no particular order.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the call fails.
    pub async fn list_nodes(&self) -> Result<Vec<NodeCandidate>, ClientError> {
        let id = request_id();
        let message = Outbound::ListNodes(ListNodesRequest {
            request_id: id.to_string(),
        });
        exchange(
            self,
            Conversation {
                auth: None,
                request: Some(&id),
                messages: vec![message],
            },
            |m| match m {
                Inbound::ListNodesResult(r) if r.request_id == id.as_str() => Step::Done(Ok(r
                    .nodes
                    .into_iter()
                    .map(|n| NodeCandidate {
                        star: StarId(n.star_id),
                        country: n.country.parse().ok(),
                        latency: (n.latency_ms > 0)
                            .then(|| Duration::from_millis(u64::from(n.latency_ms))),
                        // A value that is not a number is treated as full.
                        load: if n.load.is_finite() {
                            n.load.clamp(0.0, 1.0)
                        } else {
                            1.0
                        },
                        available: n.available,
                    })
                    .collect())),
                _ => Step::Skip,
            },
        )
        .await
    }

    /// The countries this Control Plane has available nodes in.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if the call fails.
    pub async fn list_countries(&self) -> Result<Vec<CountryNodes>, ClientError> {
        let id = request_id();
        let message = Outbound::ListCountries(ListCountriesRequest {
            request_id: id.to_string(),
        });
        exchange(
            self,
            Conversation {
                auth: None,
                request: Some(&id),
                messages: vec![message],
            },
            |m| match m {
                Inbound::ListCountriesResponse(r) if r.request_id == id.as_str() => {
                    Step::Done(Ok(r
                        .countries
                        .into_iter()
                        .filter_map(|c| {
                            Some(CountryNodes {
                                country: c.country.parse().ok()?,
                                nodes: u32::try_from(c.node_count).ok()?,
                            })
                        })
                        .collect()))
                }
                _ => Step::Skip,
            },
        )
        .await
    }
}
