//! Opening, reporting on and renewing sessions.

use super::auth::WalletAuth;
use super::call::{Conversation, Step, exchange, request_id};
use super::permission::Permission;
use super::proto::client::client_message::Message as Outbound;
use super::proto::client::control_plane_message::Message as Inbound;
use super::proto::client::{
    self as wire, ListNodesRequest, RenewSessionRequest, SessionEnd, TrafficCheckpoint,
};
use super::{ClientError, ControlPlaneClient, Country};
use crate::chain::{Chain, Role, Rpc};
use crate::digest::{Checkpoint, Ending, Renewal};
use crate::id::{Address, Epoch, SessionId, StarId, UnixTime};
use crate::session::{Credentials, SealedCredentials, SessionKeypair};
use crate::signing::CheckpointKey;
use crate::zk::{AccessProof, Claim};

/// How long a signed end may take to be answered.
const END_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What to ask for when opening a session.
///
/// ```no_run
/// # use singula::client::{Permission, SessionRequest};
/// # use singula::zk::AccessProof;
/// # use singula::StarId;
/// # fn f(proof: AccessProof, permission: Permission) -> Result<(), Box<dyn std::error::Error>> {
/// let request = SessionRequest::anonymous(proof, permission)
///     .node(StarId(12))
///     .country("DE".parse()?);
/// # let _ = request;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct SessionRequest {
    admission: Admission,
    node: Option<StarId>,
    country: Option<Country>,
    cover: Option<String>,
    exit_leg: bool,
}

/// How a session is admitted.
#[derive(Debug, Clone)]
enum Admission {
    /// By a membership proof and a permission: the Control Plane learns that
    /// some subscriber connected, and nothing else.
    Anonymous {
        // Boxed: a proof is several hundred bytes, a sign-in a few dozen.
        proof: Box<AccessProof>,
        permission: Permission,
    },
    /// By the wallet's sign-in: the Control Plane knows which wallet.
    Wallet(WalletAuth),
}

/// What an [`Admission`] puts on the wire.
struct Admitted<'a> {
    access: Option<wire::AccessProof>,
    permission: Option<wire::Permission>,
    auth: Option<&'a WalletAuth>,
}

impl SessionRequest {
    /// An anonymous session, admitted by `proof` — a [`Claim::Session`]
    /// proof for the Control Plane it is sent to — and paid for with
    /// `permission`.
    pub fn anonymous(proof: AccessProof, permission: Permission) -> Self {
        Self::with(Admission::Anonymous {
            proof: Box::new(proof),
            permission,
        })
    }

    /// A session admitted by a wallet's sign-in. The Control Plane checks
    /// the wallet's subscription on chain, and knows whose session it is.
    pub fn wallet(auth: WalletAuth) -> Self {
        Self::with(Admission::Wallet(auth))
    }

    fn with(admission: Admission) -> Self {
        Self {
            admission,
            node: None,
            country: None,
            cover: None,
            exit_leg: false,
        }
    }

    /// Serve this exact node, or refuse; it is never quietly substituted.
    /// Without it the Control Plane chooses.
    pub fn node(mut self, node: StarId) -> Self {
        self.node = Some(node);
        self
    }

    /// Prefer a node in this country when the Control Plane chooses.
    pub fn country(mut self, country: Country) -> Self {
        self.country = Some(country);
        self
    }

    /// Ask the node for this cover preset (`"default"`, `"RU"`, `"CN"`,
    /// `"IR"`, …) instead of its default.
    pub fn cover(mut self, preset: impl Into<String>) -> Self {
        self.cover = Some(preset.into());
        self
    }

    /// Mark this as the exit leg of a chain: the client reaches the node
    /// through another proxy, which the node cannot see for itself and which
    /// changes how it must set the session up.
    pub fn exit_leg(mut self) -> Self {
        self.exit_leg = true;
        self
    }
}

/// How a node reaches the internet, as the node reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Egress {
    /// From its own address.
    Direct,
    /// Through Cloudflare WARP.
    Warp,
    /// Through something its operator configured.
    Custom,
    /// It did not say.
    Unknown,
}

/// Traffic a session has carried since it opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Traffic {
    /// Bytes the client sent.
    pub up: u64,
    /// Bytes the client received.
    pub down: u64,
}

/// An open session.
///
/// Holds the session's checkpoint key, which proves the session is the
/// holder's wherever it reports or renews from; it is wiped on drop.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    node: StarId,
    admitted_by: StarId,
    report_to: StarId,
    wallet: Option<Address>,
    expires_at: UnixTime,
    egress: Egress,
    credentials: Credentials,
    key: CheckpointKey,
    nonce: Vec<u8>,
}

impl Session {
    /// The session's id.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The node serving it.
    #[must_use]
    pub fn node(&self) -> StarId {
        self.node
    }

    /// The Control Plane that admitted it, and that renews it.
    #[must_use]
    pub fn admitted_by(&self) -> StarId {
        self.admitted_by
    }

    /// The Control Plane its reports must go to: the one that holds its node,
    /// which may be another operator's.
    #[must_use]
    pub fn report_to(&self) -> StarId {
        self.report_to
    }

    /// The wallet it was opened by, or `None` for an anonymous session.
    #[must_use]
    pub fn wallet(&self) -> Option<Address> {
        self.wallet
    }

    /// When it ends unless renewed.
    #[must_use]
    pub fn expires_at(&self) -> UnixTime {
        self.expires_at
    }

    /// How its node reaches the internet.
    #[must_use]
    pub fn egress(&self) -> Egress {
        self.egress
    }

    /// The node's tunnel settings, still encoded; see
    /// [`TunnelSettings`](super::TunnelSettings).
    #[must_use]
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }
}

/// Why a session did not open.
#[derive(Debug)]
pub(super) struct NotOpened {
    pub(super) error: ClientError,
    /// Whether the Control Plane admitted it — and so took its permission —
    /// before the client refused the answer.
    pub(super) admitted: bool,
    /// The node the refused answer names, when it names one.
    pub(super) node: Option<StarId>,
}

impl NotOpened {
    fn refused(error: ClientError) -> Self {
        Self {
            error,
            admitted: false,
            node: None,
        }
    }
}

impl ControlPlaneClient {
    /// Opens a session.
    ///
    /// The node's answer is checked against the signer key `StarRegistry`
    /// records for it, read from `chain`, before anything in it is used: a
    /// Control Plane relaying the answer cannot substitute one of its own.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if the proof is not for this Control
    /// Plane, [`ClientError::Untrusted`] if the answer names another node
    /// than the one asked for or a Star that is not a node, an
    /// [`OpenError`](crate::OpenError) if the node's signature or encryption
    /// does not check out, and any error of the call or the chain read.
    pub async fn open_session<R: Rpc>(
        &self,
        chain: &Chain<R>,
        request: SessionRequest,
    ) -> Result<Session, ClientError> {
        self.open(chain, request).await.map_err(|n| n.error)
    }

    /// [`open_session`](Self::open_session), saying on failure whether the
    /// Control Plane had admitted the session before it failed.
    pub(super) async fn open<R: Rpc>(
        &self,
        chain: &Chain<R>,
        request: SessionRequest,
    ) -> Result<Session, NotOpened> {
        let Admitted {
            access,
            permission,
            auth,
        } = self
            .admission(&request.admission)
            .map_err(NotOpened::refused)?;

        let keypair = SessionKeypair::generate();
        let key = CheckpointKey::generate();
        let id = request_id();
        let message = Outbound::SessionRequest(wire::SessionRequest {
            request_id: id.to_string(),
            preferred_country: request.country.map(|c| c.to_string()).unwrap_or_default(),
            session_public_key: keypair.public_key().to_vec(),
            region_hint: request.cover.clone().unwrap_or_default(),
            checkpoint_public_key: key.public_key().to_vec(),
            chained: request.exit_leg,
            access,
            permission,
            node_star_id: request.node.map_or(0, |n| n.0),
        });
        let answer = exchange(
            self,
            Conversation {
                auth,
                request: Some(&id),
                messages: vec![message],
            },
            |m| match m {
                Inbound::SessionCredentials(c) if c.request_id == id.as_str() => Step::Done(Ok(c)),
                _ => Step::Skip,
            },
        )
        .await
        .map_err(NotOpened::refused)?;

        // From here on the Control Plane has admitted the session: whatever
        // fails now, the permission it was admitted on is spent.
        let (session, node, credentials) =
            match verify(chain, &keypair, request.node, &answer).await {
                Ok(opened) => opened,
                Err(error) => {
                    // Ended at once, so the permission it holds is free again
                    // within a lease rather than when the session would expire.
                    if let Ok(id) = answer.session_uuid.parse::<SessionId>() {
                        let _ = self.end_signed(&id, &key, Traffic::default()).await;
                    }
                    return Err(NotOpened {
                        error,
                        admitted: true,
                        node: answer.node_id.parse().ok().map(StarId),
                    });
                }
            };

        Ok(Session {
            id: session,
            node,
            admitted_by: self.star,
            report_to: match answer.report_to_star_id {
                0 => self.star,
                other => StarId(other),
            },
            wallet: auth.map(WalletAuth::wallet),
            expires_at: UnixTime(answer.expires_at),
            egress: match wire::EgressMode::try_from(answer.egress_mode) {
                Ok(wire::EgressMode::Direct) => Egress::Direct,
                Ok(wire::EgressMode::Warp) => Egress::Warp,
                Ok(wire::EgressMode::Custom) => Egress::Custom,
                _ => Egress::Unknown,
            },
            credentials,
            key,
            nonce: answer.challenge_nonce,
        })
    }

    /// The wire fields `admission` fills in, after checking a proof is for
    /// this Control Plane.
    fn admission<'a>(&self, admission: &'a Admission) -> Result<Admitted<'a>, ClientError> {
        match admission {
            Admission::Anonymous { proof, permission } => {
                let Claim::Session {
                    control_plane,
                    epoch,
                    index,
                } = proof.claim
                else {
                    return Err(ClientError::Mismatch("the proof is not a session proof"));
                };
                if control_plane != self.star {
                    return Err(ClientError::Mismatch(
                        "the proof is for another Control Plane",
                    ));
                }
                Ok(Admitted {
                    access: Some(wire_proof(proof, epoch, index)),
                    permission: Some(permission.to_wire()),
                    auth: None,
                })
            }
            Admission::Wallet(auth) => Ok(Admitted {
                access: None,
                permission: None,
                auth: Some(auth),
            }),
        }
    }

    /// Reports the traffic `session` has carried so far.
    ///
    /// Must be sent to the Control Plane [`Session::report_to`] names, which
    /// answers with the nonce the next report must carry; the session keeps
    /// it.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if this is not the session's
    /// reporting Control Plane, and any error of the call.
    pub async fn report(&self, session: &mut Session, traffic: Traffic) -> Result<(), ClientError> {
        if session.report_to != self.star {
            return Err(ClientError::Mismatch(
                "reports for this session go to another Control Plane",
            ));
        }
        let timestamp = UnixTime::now();
        let digest = Checkpoint {
            session: &session.id,
            bytes_up: traffic.up,
            bytes_down: traffic.down,
            timestamp,
            nonce: &session.nonce,
        }
        .digest();
        let too_large = || ClientError::Mismatch("more traffic than the wire format can carry");
        let message = Outbound::TrafficCheckpoint(TrafficCheckpoint {
            session_uuid: session.id.to_string(),
            bytes_uploaded: i64::try_from(traffic.up).map_err(|_| too_large())?,
            bytes_downloaded: i64::try_from(traffic.down).map_err(|_| too_large())?,
            timestamp: timestamp.0,
            signature: session.key.sign(&digest).to_bytes().to_vec(),
            nonce: session.nonce.clone(),
        });
        // Wait for the next nonce rather than fire and forget: a report sent
        // with a stale one is dropped as a possible replay.
        let id = session.id.clone();
        let next = exchange(
            self,
            Conversation {
                auth: None,
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::NonceUpdate(n) if n.session_uuid == id.as_str() => {
                    Step::Done(Ok(n.next_nonce))
                }
                _ => Step::Skip,
            },
        )
        .await?;
        if next.is_empty() {
            return Err(ClientError::Malformed("an empty nonce"));
        }
        session.nonce = next;
        Ok(())
    }

    /// Extends `session` before it expires.
    ///
    /// Inside the window it was admitted in, the session's signature is
    /// enough; renewing into a new window takes a `permission` from that
    /// window's packet.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if this is not the session's
    /// admitting Control Plane, [`ClientError::Refused`] if renewal is
    /// declined, and any error of the call.
    pub async fn renew(
        &self,
        session: &mut Session,
        permission: Option<&Permission>,
    ) -> Result<(), ClientError> {
        if session.admitted_by != self.star {
            return Err(ClientError::Mismatch(
                "this session was admitted by another Control Plane",
            ));
        }
        let id = request_id();
        let timestamp = UnixTime::now();
        let digest = Renewal {
            session: &session.id,
            request: &id,
            timestamp,
        }
        .digest();
        let message = Outbound::RenewSession(RenewSessionRequest {
            request_id: id.to_string(),
            session_uuid: session.id.to_string(),
            permission: permission.map(Permission::to_wire),
            signature: session.key.sign(&digest).to_bytes().to_vec(),
            timestamp: timestamp.0,
        });
        let expires_at = exchange(
            self,
            Conversation {
                auth: None,
                request: Some(&id),
                messages: vec![message],
            },
            |m| match m {
                Inbound::RenewSessionResult(r) if r.request_id == id.as_str() => {
                    Step::Done(if r.success {
                        Ok(UnixTime(r.expires_at))
                    } else {
                        Err(ClientError::Refused {
                            code: 0,
                            message: r.error_message,
                        })
                    })
                }
                _ => Step::Skip,
            },
        )
        .await?;
        session.expires_at = expires_at;
        Ok(())
    }
}

impl ControlPlaneClient {
    /// Ends an anonymous session now, signed by the session's own key, so
    /// its permission is free again across the network within one lease.
    ///
    /// An anonymous session has no wallet to vouch for its end; its key is
    /// what ties a call to it, over any stream.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if the session was admitted by
    /// another Control Plane, [`ClientError::Refused`] if this one does not
    /// end it, and any error of the call.
    pub async fn end_anonymous_session(
        &self,
        session: Session,
        traffic: Traffic,
    ) -> Result<(), ClientError> {
        if session.admitted_by != self.star {
            return Err(ClientError::Mismatch(
                "this session was admitted by another Control Plane",
            ));
        }
        self.end_signed(&session.id, &session.key, traffic).await
    }

    /// Ends session `id` with an end signed by `key`.
    pub(super) async fn end_signed(
        &self,
        id: &SessionId,
        key: &CheckpointKey,
        traffic: Traffic,
    ) -> Result<(), ClientError> {
        let too_large = || ClientError::Mismatch("more traffic than the wire format can carry");
        let timestamp = UnixTime::now();
        let digest = Ending {
            session: id,
            up: traffic.up,
            down: traffic.down,
            timestamp,
        }
        .digest();
        let end = Outbound::SessionEnd(SessionEnd {
            session_uuid: id.to_string(),
            final_bytes_uploaded: i64::try_from(traffic.up).map_err(|_| too_large())?,
            final_bytes_downloaded: i64::try_from(traffic.down).map_err(|_| too_large())?,
            timestamp: timestamp.0,
            signature: key.sign(&digest).to_bytes().to_vec(),
        });
        // A Control Plane from before signed ends does not answer one; it is
        // not worth the whole call timeout to find out.
        let cp = self.clone().with_timeout(END_TIMEOUT);
        exchange(
            &cp,
            Conversation {
                auth: None,
                request: None,
                messages: vec![end],
            },
            |m| match m {
                Inbound::SessionEndResult(r) if r.session_uuid == id.as_str() => {
                    Step::Done(if r.success {
                        Ok(())
                    } else {
                        Err(ClientError::Refused {
                            code: 0,
                            message: r.error_message,
                        })
                    })
                }
                _ => Step::Skip,
            },
        )
        .await
    }

    /// Ends a wallet's session now, with its final traffic, rather than
    /// letting it expire.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if the session is not `auth`'s
    /// wallet's or was admitted elsewhere, and any error of the call.
    pub async fn end_session(
        &self,
        auth: &WalletAuth,
        session: Session,
        traffic: Traffic,
    ) -> Result<(), ClientError> {
        if session.wallet != Some(auth.wallet()) {
            return Err(ClientError::Mismatch("the session is not this wallet's"));
        }
        if session.admitted_by != self.star {
            return Err(ClientError::Mismatch(
                "this session was admitted by another Control Plane",
            ));
        }
        let too_large = || ClientError::Mismatch("more traffic than the wire format can carry");
        let end = Outbound::SessionEnd(SessionEnd {
            session_uuid: session.id.to_string(),
            final_bytes_uploaded: i64::try_from(traffic.up).map_err(|_| too_large())?,
            final_bytes_downloaded: i64::try_from(traffic.down).map_err(|_| too_large())?,
            ..SessionEnd::default()
        });
        // The end has no answer of its own. A Control Plane handles a
        // stream's messages in order, so the answer to a request sent after
        // it means the end was handled.
        let id = request_id();
        let barrier = Outbound::ListNodes(ListNodesRequest {
            request_id: id.to_string(),
        });
        exchange(
            self,
            Conversation {
                auth: Some(auth),
                request: Some(&id),
                messages: vec![end, barrier],
            },
            |m| match m {
                Inbound::ListNodesResult(r) if r.request_id == id.as_str() => Step::Done(Ok(())),
                _ => Step::Skip,
            },
        )
        .await
    }
}

/// Checks a node's answer against the chain and opens it: the session, the
/// node, and the node's credentials.
async fn verify<R: Rpc>(
    chain: &Chain<R>,
    keypair: &SessionKeypair,
    asked_for: Option<StarId>,
    answer: &wire::SessionCredentials,
) -> Result<(SessionId, StarId, Credentials), ClientError> {
    let session: SessionId = answer
        .session_uuid
        .parse()
        .map_err(|_| ClientError::Malformed("session id"))?;
    let node = StarId(
        answer
            .node_id
            .parse()
            .map_err(|_| ClientError::Malformed("node id"))?,
    );
    if asked_for.is_some_and(|asked| asked != node) {
        return Err(ClientError::Untrusted(
            "the answer is from another node than the one asked for",
        ));
    }
    let star = chain.star(node).await?.ok_or(ClientError::Untrusted(
        "the answer names no registered Star",
    ))?;
    if star.role != Role::Node {
        return Err(ClientError::Untrusted(
            "the answer names a Star that is not a node",
        ));
    }
    let credentials = keypair.open(
        &SealedCredentials {
            session: &session,
            session_public_key: &answer.session_public_key,
            signer_signature: &answer.node_signer_signature,
            nonce: &answer.nonce,
            ciphertext: &answer.encrypted_credentials,
        },
        &star.signer,
    )?;
    Ok((session, node, credentials))
}

/// A proof as the wire carries it: field elements as 32 bytes big-endian.
pub(super) fn wire_proof(proof: &AccessProof, epoch: Epoch, index: u32) -> wire::AccessProof {
    wire::AccessProof {
        epoch: epoch.0,
        merkle_root: proof.merkle_root.to_be_bytes().to_vec(),
        nullifier: proof.nullifier.to_be_bytes().to_vec(),
        index,
        points: proof.points.iter().map(|p| p.to_vec()).collect(),
    }
}
