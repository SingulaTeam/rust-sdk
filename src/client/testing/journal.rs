//! The shared journal as the test Control Plane keeps it: challenges, rights,
//! pings and the attestations of a federation of three.

use std::collections::HashMap;

use k256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use p256::ecdsa::{Signature, VerifyingKey};

use super::{CHAIN_ID, CP};
use crate::eth;
use crate::id::{Address, Epoch, SessionId, StarId, UnixTime};
use crate::journal::{
    Attestation, JournalParams, Nullifier, Ping, RegistryVersion, RegistryVersionId, Versions,
    open_digest,
};

/// A right key, `x` and `y`.
type RightPublicKey = ([u8; 32], [u8; 32]);

/// How the federation answers pings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::client) enum Acks {
    /// Two of its three Control Planes attest: a majority.
    Quorum,
    /// Only this one does, and it says so.
    Short,
    /// It claims a majority, with the second attestation signed by a key
    /// that is not that Control Plane's.
    Forged,
    /// It answers for another ping than the one sent.
    OtherPing,
}

/// What the test federation keeps of the journal.
pub(in crate::client) struct MockJournal {
    pub(in crate::client) params: JournalParams,
    /// Its Control Planes: this one first.
    cps: Vec<(StarId, SigningKey)>,
    pub(in crate::client) version: RegistryVersion,
    /// The right keys it knows, by nullifier.
    pub(in crate::client) rights: HashMap<[u8; 32], RightPublicKey>,
    /// Every ping taken, in order.
    pub(in crate::client) pings: Vec<Ping>,
    /// Sessions and what a status request answers for them: state 1 open,
    /// 2 closed, with the reason.
    pub(in crate::client) statuses: HashMap<String, (i32, String)>,
    pub(in crate::client) acks: Acks,
    /// The Control Plane its challenges name; this one unless a test lies.
    pub(in crate::client) challenge_names: StarId,
    /// Sessions opened on a right.
    pub(in crate::client) opened_on_right: usize,
}

impl MockJournal {
    pub(in crate::client) fn new() -> Self {
        let cps: Vec<(StarId, SigningKey)> = [CP.0, 9, 10]
            .into_iter()
            .map(|id| (StarId(id), eth::random_key()))
            .collect();
        let members = cps
            .iter()
            .map(|(id, key)| (*id, eth::address_of(key.verifying_key())))
            .collect();
        let id = RegistryVersionId::new(CHAIN_ID, Address([0x5a; 20]), 1, &[1; 32]);
        Self {
            params: JournalParams::new(CHAIN_ID),
            cps,
            version: RegistryVersion::new(id, 1, UnixTime(0), members),
            rights: HashMap::new(),
            pings: Vec::new(),
            statuses: HashMap::new(),
            acks: Acks::Quorum,
            challenge_names: CP,
            opened_on_right: 0,
        }
    }

    /// The registry's history, as the client reads it from the chain.
    pub(in crate::client) fn versions(&self) -> Versions {
        Versions::new(vec![self.version.clone()]).unwrap_or_else(|_| unreachable!())
    }

    /// Checks a session open on a right: its challenge, and its key's
    /// signature over the challenge, this Control Plane and the session key.
    pub(in crate::client) fn admit(
        &mut self,
        issued: Option<[u8; 32]>,
        access: &super::wire::LedgerAccess,
        session_key: &[u8],
    ) -> Result<(), &'static str> {
        let issued = issued.ok_or("no challenge on this stream")?;
        if access.challenge != issued {
            return Err("not this stream's challenge");
        }
        let (nullifier, key) = decode_right(&access.right).ok_or("not a right")?;
        let digest = open_digest(self.params, &issued, CP, session_key);
        if !signed(&key, &digest, &access.signature) {
            return Err("the open signature is not by the right's key");
        }
        self.rights.insert(nullifier, key);
        self.opened_on_right += 1;
        Ok(())
    }

    /// Takes a ping and answers as the federation would.
    pub(in crate::client) fn ping(
        &mut self,
        r: &super::wire::LedgerPing,
        now: UnixTime,
    ) -> super::wire::LedgerAck {
        let mut ack = super::wire::LedgerAck {
            request_id: r.request_id.clone(),
            ..Default::default()
        };
        if !r.right.is_empty() {
            let Some((nullifier, key)) = decode_right(&r.right) else {
                ack.error = "right: not a right".into();
                return ack;
            };
            self.rights.insert(nullifier, key);
        }
        let Some((ping, rs)) = decode_ping(&r.ping) else {
            ack.error = "ping: not a client ping".into();
            return ack;
        };
        let hash = ping.hash(self.params);
        let Some(key) = self.rights.get(&ping.nullifier.0) else {
            ack.error = "no right for this ping".into();
            return ack;
        };
        if !signed(key, &hash, &rs) {
            ack.error = "the ping's signature does not verify".into();
            return ack;
        }
        self.pings.push(ping);

        let attesting = match self.acks {
            Acks::Short => 1,
            _ => 2,
        };
        let mut attestations: Vec<Attestation> = self.cps[..attesting]
            .iter()
            .map(|(id, key)| self.attest(*id, key, &hash, now))
            .collect();
        if self.acks == Acks::Forged {
            attestations[1] = self.attest(self.cps[1].0, &self.cps[0].1, &hash, now);
        }
        ack.ping_hash = if self.acks == Acks::OtherPing {
            vec![0; 32]
        } else {
            hash.to_vec()
        };
        ack.quorum = self.acks != Acks::Short;
        if ack.quorum {
            ack.registry_version = self.version.id.0.to_vec();
        }
        ack.attestations = attestations
            .iter()
            .map(|a| super::wire::LedgerAttestation {
                cp: a.cp.0,
                received_at: a.received_at.0,
                sig: a.signature.to_vec(),
                registry_version: a.version.0.to_vec(),
            })
            .collect();
        ack
    }

    fn attest(&self, cp: StarId, key: &SigningKey, hash: &[u8; 32], now: UnixTime) -> Attestation {
        let mut a = Attestation::new(cp, now, self.version.id, [0; 65]);
        a.signature = eth::sign(key, &a.digest(self.params, hash));
        a
    }
}

/// Whether `signature`, `r ‖ s`, is the P-256 key's over `digest`.
fn signed(key: &RightPublicKey, digest: &[u8; 32], signature: &[u8]) -> bool {
    let mut sec1 = vec![4];
    sec1.extend_from_slice(&key.0);
    sec1.extend_from_slice(&key.1);
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(&sec1),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    key.verify_prehash(digest, &signature).is_ok()
}

/// A right's nullifier and key, from its canonical encoding.
fn decode_right(b: &[u8]) -> Option<([u8; 32], RightPublicKey)> {
    // kind, window, state index, nullifier, x, y, eight points.
    if b.len() != 1 + 8 + 4 + 32 * 3 + 32 * 8 || b[0] != 1 {
        return None;
    }
    let word = |at: usize| <[u8; 32]>::try_from(&b[at..at + 32]).ok();
    Some((word(13)?, (word(45)?, word(77)?)))
}

/// A client ping and its signature, from its canonical encoding.
fn decode_ping(b: &[u8]) -> Option<(Ping, Vec<u8>)> {
    // kind, window, nullifier, session, node, total, r, s, no attestations.
    if b.len() != 1 + 8 + 32 + 16 + 8 + 8 + 64 + 4 || b[0] != 2 || b[b.len() - 4..] != [0; 4] {
        return None;
    }
    let u64_at = |at: usize| u64::from_be_bytes(b[at..at + 8].try_into().unwrap_or_default());
    let h = crate::hex::lower(&b[41..57]);
    let session: SessionId = format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
    .parse()
    .ok()?;
    let ping = Ping::new(
        Epoch(u64_at(1)),
        Nullifier(b[9..41].try_into().ok()?),
        session,
        StarId(u64_at(57)),
        u64_at(65),
    );
    Some((ping, b[73..137].to_vec()))
}
