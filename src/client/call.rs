//! One conversation with a Control Plane.
//!
//! Every operation opens the `Connect` stream, sends its message, waits for
//! the answer that belongs to it, and closes. Nothing is held open between
//! operations, so nothing breaks when the network underneath changes — when a
//! tunnel comes up, say, and the next call to the Control Plane travels
//! through it. A session outlives the call that opened it: the Control Plane
//! knows it by its checkpoint key, not by a connection.

use std::time::Duration;

use rand_core::{OsRng, RngCore as _};
use tokio_stream::StreamExt as _;

use super::proto::client::client_service_client::ClientServiceClient;
use super::proto::client::control_plane_message::Message as Inbound;
use super::proto::client::{ClientMessage, client_message::Message as Outbound};
use super::{ClientError, ControlPlaneClient};
use crate::id::RequestId;

/// How long one conversation may take. Opening a session is the slowest: the
/// Control Plane has to reach a node, and the node has to set the session up.
pub(super) const CALL_TIMEOUT: Duration = Duration::from_secs(45);

/// One conversation: what to send, and how to recognise its answer.
pub(super) struct Conversation<'a> {
    /// Sent first when set, for calls that act as a wallet.
    pub(super) auth: Option<&'a super::auth::WalletAuth>,
    /// The request id the answer and any error will carry.
    pub(super) request: Option<&'a RequestId>,
    /// The messages, in order.
    pub(super) messages: Vec<Outbound>,
}

/// What to do with one message from the Control Plane.
pub(super) enum Step<T> {
    /// It is the answer.
    Done(Result<T, ClientError>),
    /// It belongs to some other conversation; keep reading.
    Skip,
}

/// Holds `conversation` with `cp` and returns the first answer `pick`
/// accepts.
///
/// A Control Plane `Error` for this request (or for none in particular) ends
/// the conversation as [`ClientError::Refused`], and so does a refused
/// sign-in. An accepted sign-in is passed to `pick` like any other message.
pub(super) async fn exchange<T>(
    cp: &ControlPlaneClient,
    conversation: Conversation<'_>,
    mut pick: impl FnMut(Inbound) -> Step<T>,
) -> Result<T, ClientError> {
    let Conversation {
        auth,
        request,
        messages,
    } = conversation;
    if auth.is_some_and(|a| a.control_plane() != cp.star) {
        return Err(ClientError::Mismatch(
            "the sign-in is for another Control Plane",
        ));
    }
    let outbound: Vec<ClientMessage> = auth
        .map(|a| Outbound::Auth(a.to_wire()))
        .into_iter()
        .chain(messages)
        .map(|m| ClientMessage { message: Some(m) })
        .collect();

    let conversation = async {
        // The outbound half stays open until the answer arrives: closing it
        // first would tell the Control Plane the conversation was over.
        let outbound = tokio_stream::iter(outbound).chain(tokio_stream::pending());
        let mut inbound = ClientServiceClient::new(cp.channel.clone())
            .connect(outbound)
            .await
            .map_err(|s| ClientError::from_status(&s))?
            .into_inner();
        loop {
            let Some(msg) = inbound
                .message()
                .await
                .map_err(|s| ClientError::from_status(&s))?
            else {
                return Err(ClientError::Closed);
            };
            match msg.message {
                Some(Inbound::Error(e))
                    if request
                        .is_none_or(|r| e.request_id.is_empty() || e.request_id == r.as_str()) =>
                {
                    return Err(ClientError::Refused {
                        code: e.code,
                        message: e.message,
                    });
                }
                Some(Inbound::AuthResult(a)) if !a.success => {
                    return Err(ClientError::Refused {
                        code: AUTH_FAILED,
                        message: a.error_message,
                    });
                }
                Some(other) => match pick(other) {
                    Step::Done(result) => return result,
                    Step::Skip => {}
                },
                None => {}
            }
        }
    };
    tokio::time::timeout(cp.timeout, conversation)
        .await
        .map_err(|_| ClientError::Timeout)?
}

/// `ErrorCode.ERROR_CODE_AUTH_FAILED`.
const AUTH_FAILED: i32 = 1;

/// A fresh, unguessable request id.
pub(super) fn request_id() -> RequestId {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    // Hex digits are never empty and never contain a NUL.
    crate::hex::lower(&bytes)
        .parse()
        .unwrap_or_else(|_| unreachable!("hex is a valid request id"))
}
