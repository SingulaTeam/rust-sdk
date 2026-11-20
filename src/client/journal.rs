//! A session on a right, kept by pings.

use super::call::{Conversation, Step, exchange, request_id};
use super::proto::client::client_message::Message as Outbound;
use super::proto::client::control_plane_message::Message as Inbound;
use super::proto::client::{self as wire, LedgerSessionState};
use super::session::Traffic;
use super::{ClientError, ControlPlaneClient};
use crate::id::{SessionId, StarId, UnixTime};
use crate::journal::{
    AckError, Attestation, CloseReason, Committed, JournalParams, RegistryVersionId, Right,
    SessionStatus, SignedPing, Versions,
};

/// A Control Plane's answer to a ping: the attestations it gathered, and
/// whether it says they make a majority.
///
/// Its word is not taken: [`committed`](Self::committed) checks the
/// attestations against the registry's history.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ack {
    /// The ping it answers, as the journal names it.
    pub ping_hash: [u8; 32],
    /// Whether the Control Plane says a strict majority of one registry
    /// version attested it.
    pub quorum: bool,
    /// The version it says the majority belongs to.
    pub version: Option<RegistryVersionId>,
    /// The attestations: of that version when `quorum` is set, every one it
    /// holds otherwise.
    pub attestations: Vec<Attestation>,
}

impl Ack {
    /// Whether the ping reached the journal: a strict majority of the
    /// version the ack names attested it, each with its own key, checked
    /// against `versions` at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`AckError`] saying what is missing. A Control Plane that says
    /// "quorum" without one, or sends an attestation that does not check
    /// out, should not carry the session's pings any longer.
    pub fn committed(
        &self,
        versions: &Versions,
        params: JournalParams,
        now: UnixTime,
    ) -> Result<Committed, AckError> {
        let Some(version) = self.version.filter(|_| self.quorum) else {
            return Err(AckError::NoQuorum {
                have: 0,
                need: versions.latest().quorum(),
            });
        };
        versions.check_ack(params, &self.ping_hash, version, &self.attestations, now)
    }
}

impl ControlPlaneClient {
    /// Sends `ping`, with the traffic the session has carried — which the
    /// Control Plane uses to tell an idle session from a stalled one, and
    /// which reaches nobody else — and returns what it attested.
    ///
    /// `new_right` carries a new day's right into the running session, with
    /// the first ping made under it: the tunnel stays up across midnight.
    ///
    /// Any Control Plane takes any session's pings: a client whose pings
    /// stop reaching a majority through one moves to another and keeps its
    /// session.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Refused`] if the Control Plane does not take
    /// the ping, [`ClientError::Untrusted`] if it answers for another ping,
    /// and any error of the call.
    pub async fn ping(
        &self,
        params: JournalParams,
        ping: &SignedPing,
        traffic: Traffic,
        new_right: Option<&Right>,
    ) -> Result<Ack, ClientError> {
        let id = request_id();
        let message = Outbound::LedgerPing(wire::LedgerPing {
            request_id: id.to_string(),
            ping: ping.encode(),
            bytes_up: traffic.up,
            bytes_down: traffic.down,
            right: new_right.map(Right::encode).unwrap_or_default(),
        });
        let answer = exchange(
            self,
            Conversation {
                auth: None,
                request: Some(&id),
                messages: vec![message],
            },
            |m| match m {
                Inbound::LedgerAck(a) if a.request_id == id.as_str() => Step::Done(Ok(a)),
                _ => Step::Skip,
            },
        )
        .await?;
        if !answer.error.is_empty() {
            return Err(ClientError::Refused {
                code: 0,
                message: answer.error,
            });
        }
        let ack = decode_ack(&answer)?;
        if ack.ping_hash != ping.ping.hash(params) {
            return Err(ClientError::Untrusted("the ack is for another ping"));
        }
        Ok(ack)
    }

    /// What this Control Plane knows of session `id`: open, or closed and
    /// why. Asked when a tunnel drops, so the application can say why and
    /// reconnect the right way.
    ///
    /// # Errors
    ///
    /// Returns any error of the call.
    pub async fn session_status(&self, id: &SessionId) -> Result<SessionStatus, ClientError> {
        let request = request_id();
        let message = Outbound::LedgerSessionStatus(wire::LedgerSessionStatusRequest {
            request_id: request.to_string(),
            session_uuid: id.to_string(),
        });
        let answer = exchange(
            self,
            Conversation {
                auth: None,
                request: Some(&request),
                messages: vec![message],
            },
            |m| match m {
                Inbound::LedgerSessionStatus(s) if s.request_id == request.as_str() => {
                    Step::Done(Ok(s))
                }
                _ => Step::Skip,
            },
        )
        .await?;
        Ok(match LedgerSessionState::try_from(answer.state) {
            Ok(LedgerSessionState::Open) => SessionStatus::Open {
                total: answer.total,
                last: (answer.last != 0).then_some(UnixTime(answer.last)),
            },
            Ok(LedgerSessionState::Closed) => {
                SessionStatus::Closed(CloseReason::from_wire(&answer.reason))
            }
            _ => SessionStatus::Unknown,
        })
    }
}

/// An ack as the wire carries it, with every length checked.
fn decode_ack(a: &wire::LedgerAck) -> Result<Ack, ClientError> {
    let ping_hash = <[u8; 32]>::try_from(a.ping_hash.as_slice())
        .map_err(|_| ClientError::Malformed("a ping hash is 32 bytes"))?;
    let version = match a.registry_version.as_slice() {
        [] => None,
        bytes => Some(RegistryVersionId(<[u8; 32]>::try_from(bytes).map_err(
            |_| ClientError::Malformed("a registry version is 32 bytes"),
        )?)),
    };
    let attestations = a
        .attestations
        .iter()
        .map(|w| {
            let version = <[u8; 32]>::try_from(w.registry_version.as_slice())
                .map_err(|_| ClientError::Malformed("a registry version is 32 bytes"))?;
            let signature = <[u8; 65]>::try_from(w.sig.as_slice())
                .map_err(|_| ClientError::Malformed("an attestation's signature is 65 bytes"))?;
            Ok(Attestation::new(
                StarId(w.cp),
                UnixTime(w.received_at),
                RegistryVersionId(version),
                signature,
            ))
        })
        .collect::<Result<_, ClientError>>()?;
    Ok(Ack {
        ping_hash,
        quorum: a.quorum,
        version,
        attestations,
    })
}
