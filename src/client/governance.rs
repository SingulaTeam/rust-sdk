//! Taking part in the network's governance without ETH.
//!
//! `ProtocolGovernor` sets the network's parameters by proposals that Stars
//! and subscribers vote on. A subscriber buys without ETH and a Star's owner
//! is meant to stay cold, so neither sends a transaction: the wallet signs the
//! action as EIP-712 typed data in the governor's domain, signs the
//! `GasStation` meta-transaction around it, and a Control Plane forwards both.
//! The governor checks the first signature and runs the action as the wallet;
//! `GasStation` pays.
//!
//! Who may do what — weight, ownership of a Star, the proposal's state — is
//! the governor's to decide, and a Control Plane refuses an action the governor
//! would refuse, before anyone pays for it.

use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::SolCall as _;

use super::call::{Conversation, Step, exchange};
use super::proto::client::GovernanceRequest;
use super::proto::client::client_message::Message as Outbound;
use super::proto::client::control_plane_message::Message as Inbound;
use super::relay::{alloy, deadline, outcome, relay_signature};
use super::wallet::{Act, Message, TypedData, Wallet, sign_typed_data_checked};
use super::{ClientError, ControlPlaneClient};
use crate::chain::contracts::IProtocolGovernor;
use crate::chain::{Chain, Rpc, TxHash};
use crate::id::StarId;

/// Who takes part: the subscriber whose Orbits the wallet holds, or Stars the
/// wallet owns.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Participant {
    /// The wallet as a subscriber; it weighs the slot-time its Orbits served.
    Subscriber,
    /// The wallet as the owner of these Stars. A vote counts each of them; a
    /// proposal or a reply is made as exactly one.
    Stars(Vec<StarId>),
}

/// A vote on a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Vote {
    /// Against the value proposed.
    Against,
    /// For the value proposed.
    For,
    /// Counts toward the quorum, neither for nor against.
    Abstain,
    /// A value of one's own, for a parameter decided by weighted median.
    Value(u128),
}

impl Vote {
    /// The `choice` the governor takes.
    fn choice(self) -> U256 {
        match self {
            Self::Against => U256::ZERO,
            Self::For => U256::from(1),
            Self::Abstain => U256::from(2),
            Self::Value(v) => U256::from(v),
        }
    }
}

/// What to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GovernanceAction {
    /// Opens a proposal to set `parameter`, named as the directory names it
    /// (such as `"minCheckpointBytes"`), to `value`. The title and text are
    /// published on chain with it.
    Propose {
        /// The parameter's name, ASCII, at most 32 bytes.
        parameter: String,
        /// The value proposed.
        value: u128,
        /// A line, at most 200 bytes.
        title: String,
        /// The case for it, at most 4096 bytes.
        text: String,
    },
    /// Votes on proposal `proposal`, with an optional reason published with
    /// the vote. Voting again replaces the earlier vote.
    Vote {
        /// The proposal's number.
        proposal: u64,
        /// The vote.
        vote: Vote,
        /// Why, at most 4096 bytes; may be empty.
        reason: String,
    },
    /// Replies in proposal `proposal`'s discussion.
    Reply {
        /// The proposal's number.
        proposal: u64,
        /// The argument answered, or 0 for none.
        reply_to: u64,
        /// The reply, 1 to 4096 bytes.
        text: String,
    },
}

impl ControlPlaneClient {
    /// Takes part in governance as `who`, through this Control Plane. The
    /// wallet signs the action as EIP-712 `Act` typed data in the governor's
    /// domain and the `GasStation` meta-transaction around it; the Control
    /// Plane forwards both and `GasStation` pays. No sign-in is needed: the
    /// two signatures bind the action to the wallet.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if a parameter's name does not fit,
    /// or if a proposal or reply as a Star names other than one;
    /// [`ClientError::Refused`] if the Control Plane or the governor
    /// declines; and any wallet, chain or call error.
    pub async fn governance<R: Rpc, W: Wallet>(
        &self,
        chain: &Chain<R>,
        wallet: &W,
        who: &Participant,
        action: &GovernanceAction,
    ) -> Result<TxHash, ClientError> {
        let owner = wallet.address();
        let call = encode(who, action)?;
        let governor = chain.protocol_governor().await?;
        let deadline = deadline()?;

        let act = TypedData::new(
            chain.eip712_domain(governor).await?,
            Message::Act(Act {
                wallet: alloy(owner),
                data: call.clone().into(),
                nonce: chain.nonce(governor, owner).await?,
                deadline: U256::from(deadline.0),
            }),
        );
        let act_sig = sign_typed_data_checked(wallet, &act).await?;
        let relayed = act_call(owner, &call, deadline.0, &act_sig.0);
        let gas = relay_signature(chain, wallet, governor, &relayed, deadline).await?;

        let message = Outbound::GovernanceRequest(GovernanceRequest {
            wallet: owner.to_string(),
            call,
            act_deadline: deadline.0,
            act_sig: act_sig.0.to_vec(),
            gas_deadline: deadline.0,
            gas_sig: gas.0.to_vec(),
        });
        exchange(
            self,
            Conversation {
                auth: None,
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::GovernanceResult(r) => {
                    Step::Done(outcome(r.success, r.error_message, &r.tx_hash))
                }
                _ => Step::Skip,
            },
        )
        .await
    }
}

/// `ProtocolGovernor.act(wallet, call, deadline, sig)`: what `GasStation`
/// relays, and so what the wallet's relay signature covers.
pub(super) fn act_call(
    wallet: crate::Address,
    call: &[u8],
    deadline: i64,
    sig: &[u8; 65],
) -> Vec<u8> {
    alloy_sol_types::sol! {
        function act(address wallet, bytes data, uint256 deadline, bytes sig) external returns (bytes);
    }
    actCall {
        wallet: alloy(wallet),
        data: call.to_vec().into(),
        deadline: U256::from(u64::try_from(deadline).unwrap_or_default()),
        sig: sig.to_vec().into(),
    }
    .abi_encode()
}

/// The governor's participant call for `action` taken as `who`.
pub(super) fn encode(who: &Participant, action: &GovernanceAction) -> Result<Vec<u8>, ClientError> {
    let one_star = |stars: &[StarId]| match stars {
        [star] => Ok(U256::from(star.0)),
        _ => Err(ClientError::Mismatch(
            "a proposal or a reply is made as one Star",
        )),
    };
    Ok(match (who, action) {
        (
            Participant::Subscriber,
            GovernanceAction::Propose {
                parameter,
                value,
                title,
                text,
            },
        ) => IProtocolGovernor::proposeAsSubscriberCall {
            key: key(parameter)?,
            value: U256::from(*value),
            title: title.clone(),
            text: text.clone(),
        }
        .abi_encode(),
        (
            Participant::Stars(stars),
            GovernanceAction::Propose {
                parameter,
                value,
                title,
                text,
            },
        ) => IProtocolGovernor::proposeAsStarCall {
            starId: one_star(stars)?,
            key: key(parameter)?,
            value: U256::from(*value),
            title: title.clone(),
            text: text.clone(),
        }
        .abi_encode(),
        (
            Participant::Subscriber,
            GovernanceAction::Vote {
                proposal,
                vote,
                reason,
            },
        ) => IProtocolGovernor::voteAsSubscriberCall {
            id: U256::from(*proposal),
            choice: vote.choice(),
            reason: reason.clone(),
        }
        .abi_encode(),
        (
            Participant::Stars(stars),
            GovernanceAction::Vote {
                proposal,
                vote,
                reason,
            },
        ) => {
            if stars.is_empty() {
                return Err(ClientError::Mismatch("a vote as Stars names at least one"));
            }
            IProtocolGovernor::voteAsStarCall {
                id: U256::from(*proposal),
                starIds: stars.iter().map(|s| U256::from(s.0)).collect(),
                choice: vote.choice(),
                reason: reason.clone(),
            }
            .abi_encode()
        }
        (
            Participant::Subscriber,
            GovernanceAction::Reply {
                proposal,
                reply_to,
                text,
            },
        ) => IProtocolGovernor::argueAsSubscriberCall {
            id: U256::from(*proposal),
            replyTo: U256::from(*reply_to),
            text: text.clone(),
        }
        .abi_encode(),
        (
            Participant::Stars(stars),
            GovernanceAction::Reply {
                proposal,
                reply_to,
                text,
            },
        ) => IProtocolGovernor::argueAsStarCall {
            id: U256::from(*proposal),
            starId: one_star(stars)?,
            replyTo: U256::from(*reply_to),
            text: text.clone(),
        }
        .abi_encode(),
    })
}

/// A parameter's name as the directory keys it: ASCII, left-aligned in 32
/// bytes and padded with zeros.
fn key(name: &str) -> Result<FixedBytes<32>, ClientError> {
    if name.is_empty() || name.len() > 32 || !name.is_ascii() {
        return Err(ClientError::Mismatch(
            "a parameter's name is 1 to 32 ASCII bytes",
        ));
    }
    let mut out = [0u8; 32];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Ok(FixedBytes(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_a_parameter_as_the_directory_does() {
        let k = key("minCheckpointBytes").expect("fits");
        assert_eq!(&k.0[..18], b"minCheckpointBytes");
        assert!(k.0[18..].iter().all(|b| *b == 0));
        assert!(key("").is_err());
        assert!(key(&"x".repeat(33)).is_err());
        assert!(key("ключ").is_err());
    }

    #[test]
    fn makes_a_proposal_or_a_reply_as_one_star_only() {
        let reply = GovernanceAction::Reply {
            proposal: 1,
            reply_to: 0,
            text: "hi".into(),
        };
        assert!(encode(&Participant::Stars(vec![StarId(1), StarId(2)]), &reply).is_err());
        assert!(encode(&Participant::Stars(vec![]), &reply).is_err());
        assert!(encode(&Participant::Stars(vec![StarId(1)]), &reply).is_ok());
        let vote = GovernanceAction::Vote {
            proposal: 1,
            vote: Vote::For,
            reason: String::new(),
        };
        assert!(encode(&Participant::Stars(vec![]), &vote).is_err());
        assert!(encode(&Participant::Stars(vec![StarId(1), StarId(2)]), &vote).is_ok());
    }

    #[test]
    fn votes_as_the_governor_counts_them() {
        assert_eq!(Vote::Against.choice(), U256::ZERO);
        assert_eq!(Vote::For.choice(), U256::from(1));
        assert_eq!(Vote::Abstain.choice(), U256::from(2));
        assert_eq!(Vote::Value(18_000).choice(), U256::from(18_000));
    }
}
