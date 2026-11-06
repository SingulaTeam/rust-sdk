//! Transactions a Control Plane relays for a wallet, so the subscriber pays
//! no gas.
//!
//! The wallet signs what the contract will check — an EIP-712 intent, and
//! for mint and activation also the `GasStation` meta-transaction around it
//! — and the Control Plane only forwards. It cannot change what was signed,
//! and a contract refuses anything the wallet did not sign. Every nonce,
//! price and signing domain is read from the chain, not from the Control
//! Plane.

use std::time::Duration;

use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::SolCall as _;
use sha3::{Digest as _, Keccak256};

use super::auth::WalletAuth;
use super::call::{Conversation, Step, exchange};
use super::proto::client::client_message::Message as Outbound;
use super::proto::client::control_plane_message::Message as Inbound;
use super::proto::client::{
    ActivationRequest, AddSlotsRequest, FaucetRequest, MintRequest as WireMint,
    RegisterCommitmentRequest,
};
use super::wallet::{
    Activation, AddSlots, Message, MintRequest, Permit, PersonalMessage, Register, TypedData,
    Wallet, WalletSignature, sign_message_checked, sign_typed_data_checked,
};
use super::{ClientError, ControlPlaneClient};
use crate::chain::contracts::{ISubscriptionNFT, ITestToken};
use crate::chain::{Chain, ChainError, GasOp, Payment, Rpc, TokenId, TxHash, fee_ceiling};
use crate::id::{Address, UnixTime};
use crate::zk::FieldElement;

/// How long a relayed request stays valid after it is signed: long enough
/// for a person to approve it, short enough that a request left unsent does
/// not linger.
pub const RELAY_DEADLINE: Duration = Duration::from_secs(10 * 60);

/// The most slots one Orbit carries: `SubscriptionNFT.MAX_SLOTS`. A slot is
/// one concurrent session and costs one price.
pub const MAX_SLOTS: u8 = 5;

/// A subscription bought.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Minted {
    /// The transaction.
    pub tx: TxHash,
    /// The new Orbit token. It still has to be activated.
    pub token: TokenId,
}

/// A subscription started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Activated {
    /// The transaction.
    pub tx: TxHash,
    /// When the subscription lapses, if the Control Plane said.
    pub expires_at: Option<UnixTime>,
}

impl ControlPlaneClient {
    /// Adds `commitment` — the wallet's anonymous identity — to the
    /// anonymity set, against the wallet's active subscription `token`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if `auth` is not `wallet`'s,
    /// [`ClientError::Refused`] if the Control Plane declines or the
    /// transaction fails, and any wallet, chain or call error.
    pub async fn register_commitment<R: Rpc, W: Wallet>(
        &self,
        chain: &Chain<R>,
        wallet: &W,
        auth: &WalletAuth,
        token: TokenId,
        commitments: &[FieldElement],
    ) -> Result<TxHash, ClientError> {
        let owner = signer(wallet, auth)?;
        let registry = contract(
            chain.deployment().contracts.subscriber_registry,
            "SubscriberRegistry",
        )?;
        let deadline = deadline()?;
        let intent = TypedData::new(
            chain.eip712_domain(registry).await?,
            Message::Register(Register {
                wallet: alloy(owner),
                tokenId: U256::from(token.0),
                commitments: words(commitments),
                deadline: U256::from(deadline.0),
                nonce: chain.nonce(registry, owner).await?,
            }),
        );
        let signature = sign_typed_data_checked(wallet, &intent).await?;
        let message = Outbound::RegisterCommitment(RegisterCommitmentRequest {
            wallet: owner.to_string(),
            token_id: token.0,
            commitments: wire(commitments),
            deadline: deadline.0,
            register_sig: signature.0.to_vec(),
        });
        exchange(
            self,
            Conversation {
                auth: Some(auth),
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::RegisterCommitmentResult(r) => {
                    Step::Done(outcome(r.success, r.error_message, &r.tx_hash))
                }
                _ => Step::Skip,
            },
        )
        .await
    }

    /// Activates `token`, which starts its subscription period, and joins
    /// the anonymity set with `commitment` in the same transaction.
    ///
    /// The commitment is part of what the wallet signs, so the relaying
    /// Control Plane cannot substitute another identity; and the two happen
    /// together or not at all. Pass `None` to activate without joining — a
    /// wallet-tier subscriber may never need to — and join later with
    /// [`register_commitment`](Self::register_commitment).
    ///
    /// # Errors
    ///
    /// As [`register_commitment`](Self::register_commitment).
    pub async fn activate<R: Rpc, W: Wallet>(
        &self,
        chain: &Chain<R>,
        wallet: &W,
        auth: &WalletAuth,
        token: TokenId,
        commitments: &[FieldElement],
    ) -> Result<Activated, ClientError> {
        let owner = signer(wallet, auth)?;
        let nft = contract(
            chain.deployment().contracts.subscriptions,
            "SubscriptionNFT",
        )?;
        let deadline = deadline()?;
        let intent = TypedData::new(
            chain.eip712_domain(nft).await?,
            Message::Activation(Activation {
                wallet: alloy(owner),
                tokenId: U256::from(token.0),
                commitments: words(commitments),
                deadline: U256::from(deadline.0),
                nonce: chain.nonce(nft, owner).await?,
            }),
        );
        let signature = sign_typed_data_checked(wallet, &intent).await?;
        let call = ISubscriptionNFT::activateWithSignatureCall {
            wallet: alloy(owner),
            tokenId: U256::from(token.0),
            commitments: words(commitments),
            deadline: U256::from(deadline.0),
            signature: signature.0.to_vec().into(),
        };
        let gas = relay_signature(chain, wallet, nft, &call.abi_encode(), deadline).await?;
        let message = Outbound::ActivationRequest(ActivationRequest {
            token_id: token.0,
            wallet: owner.to_string(),
            deadline: deadline.0,
            signature: signature.0.to_vec(),
            gas_deadline: deadline.0,
            gas_sig: gas.0.to_vec(),
            commitments: wire(commitments),
        });
        exchange(
            self,
            Conversation {
                auth: Some(auth),
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::ActivationResult(r) => {
                    Step::Done(outcome(r.success, r.error_message, &r.tx_hash).map(|tx| {
                        Activated {
                            tx,
                            expires_at: (r.expires_at > 0).then_some(UnixTime(r.expires_at)),
                        }
                    }))
                }
                _ => Step::Skip,
            },
        )
        .await
    }

    /// Adds `extra` slots to `token`, an Orbit `wallet` holds, paying one
    /// price per slot for the part of its term left, and joins the set with
    /// `commitments`, the new slots' identities — none for an Orbit not yet
    /// activated, which names them at activation.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if the Orbit cannot take that many
    /// more slots; otherwise as [`register_commitment`](Self::register_commitment).
    pub async fn add_slots<R: Rpc, W: Wallet>(
        &self,
        chain: &Chain<R>,
        wallet: &W,
        auth: &WalletAuth,
        token: TokenId,
        extra: u8,
        commitments: &[FieldElement],
    ) -> Result<TxHash, ClientError> {
        let owner = signer(wallet, auth)?;
        let nft = contract(
            chain.deployment().contracts.subscriptions,
            "SubscriptionNFT",
        )?;
        if extra == 0 || extra > MAX_SLOTS {
            return Err(ClientError::Mismatch("an Orbit has 1 to 5 slots"));
        }
        // The slots, and their gas with room for the price to move. The
        // contract takes what both cost when it runs, never more.
        let cost = chain.add_slots_cost(token, extra).await?;
        let fee = fee_ceiling(chain.gas_fee(GasOp::AddSlots, extra).await?);
        let cost = U256::from(cost.saturating_add(fee));
        let deadline = deadline()?;
        let intent = TypedData::new(
            chain.eip712_domain(nft).await?,
            Message::AddSlots(AddSlots {
                wallet: alloy(owner),
                tokenId: U256::from(token.0),
                extra,
                commitments: words(commitments),
                maxCost: cost,
                deadline: U256::from(deadline.0),
                nonce: chain.mint_nonce(owner).await?,
            }),
        );
        let sig = sign_typed_data_checked(wallet, &intent).await?;

        // The permit is for the ceiling; the contract pulls what it charges.
        let usdc = chain.payment_token(Payment::Usdc)?;
        let permit = TypedData::new(
            chain.eip712_domain(usdc).await?,
            Message::Permit(Permit {
                owner: alloy(owner),
                spender: alloy(nft),
                value: cost,
                nonce: chain.nonce(usdc, owner).await?,
                deadline: U256::from(deadline.0),
            }),
        );
        let permit_sig = sign_typed_data_checked(wallet, &permit).await?;
        let (r, s, v) = split(&permit_sig);

        let call = ISubscriptionNFT::addSlotsWithPermitCall {
            wallet: alloy(owner),
            tokenId: U256::from(token.0),
            extra,
            commitments: words(commitments),
            maxCost: cost,
            deadline: U256::from(deadline.0),
            sig: sig.0.to_vec().into(),
            permitDeadline: U256::from(deadline.0),
            permitV: v,
            permitR: FixedBytes(r),
            permitS: FixedBytes(s),
        };
        let gas = relay_signature(chain, wallet, nft, &call.abi_encode(), deadline).await?;
        let message = Outbound::AddSlotsRequest(AddSlotsRequest {
            wallet: owner.to_string(),
            token_id: token.0,
            extra: u32::from(extra),
            commitments: wire(commitments),
            max_cost: cost.to_string(),
            deadline: deadline.0,
            sig: sig.0.to_vec(),
            permit_deadline: deadline.0,
            permit_v: u32::from(v),
            permit_r: r.to_vec(),
            permit_s: s.to_vec(),
            gas_deadline: deadline.0,
            gas_sig: gas.0.to_vec(),
        });
        exchange(
            self,
            Conversation {
                auth: Some(auth),
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::AddSlotsResult(r) => {
                    Step::Done(outcome(r.success, r.error_message, &r.tx_hash))
                }
                _ => Step::Skip,
            },
        )
        .await
    }

    /// Buys one subscription with `slots` concurrent sessions for `wallet`,
    /// paid in `payment`: in USDC at what the contract charges for it now
    /// ([`Chain::mint_cost`], a promotion's discount included) plus the gas
    /// fee ([`Chain::gas_fee`]), so no ETH is needed; in ECHO at `slots`
    /// times its price.
    ///
    /// The wallet signs that price as its ceiling. If the discount it was
    /// quoted is gone by the time the purchase runs, the purchase is refused
    /// rather than charged the full price.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mismatch`] if the contract does not accept
    /// `payment` now; otherwise as
    /// [`register_commitment`](Self::register_commitment).
    pub async fn mint<R: Rpc, W: Wallet>(
        &self,
        chain: &Chain<R>,
        wallet: &W,
        auth: &WalletAuth,
        payment: Payment,
        slots: u8,
    ) -> Result<Minted, ClientError> {
        let owner = signer(wallet, auth)?;
        let nft = contract(
            chain.deployment().contracts.subscriptions,
            "SubscriptionNFT",
        )?;
        if slots == 0 || slots > MAX_SLOTS {
            return Err(ClientError::Mismatch("an Orbit has 1 to 5 slots"));
        }
        // In USDC, the contract's price for this purchase, and the gas of it
        // and of what follows it on top, with room for gas to move. ECHO
        // cannot pay the fee: it then comes from a USDC allowance.
        let price = if payment == Payment::Usdc {
            U256::from(chain.mint_cost(slots).await?)
                + U256::from(fee_ceiling(chain.gas_fee(GasOp::Purchase, slots).await?))
        } else {
            let price = chain
                .subscription_price(payment)
                .await?
                .ok_or(ClientError::Mismatch(
                    "the contract does not accept this payment now",
                ))?;
            U256::from(price) * U256::from(slots)
        };
        let deadline = deadline()?;
        let pay_with_echo = payment == Payment::Echo;

        let intent = TypedData::new(
            chain.eip712_domain(nft).await?,
            Message::Mint(MintRequest {
                wallet: alloy(owner),
                payWithEcho: pay_with_echo,
                slots,
                maxCost: price,
                deadline: U256::from(deadline.0),
                nonce: chain.mint_nonce(owner).await?,
            }),
        );
        let mint_sig = sign_typed_data_checked(wallet, &intent).await?;

        // The permit is for the ceiling; the contract pulls what it charges.
        let token = chain.payment_token(payment)?;
        let permit = TypedData::new(
            chain.eip712_domain(token).await?,
            Message::Permit(Permit {
                owner: alloy(owner),
                spender: alloy(nft),
                value: price,
                nonce: chain.nonce(token, owner).await?,
                deadline: U256::from(deadline.0),
            }),
        );
        let permit_sig = sign_typed_data_checked(wallet, &permit).await?;
        let (r, s, v) = split(&permit_sig);

        let call = ISubscriptionNFT::mintWithPermitCall {
            wallet: alloy(owner),
            payWithEcho: pay_with_echo,
            slots,
            maxCost: price,
            mintDeadline: U256::from(deadline.0),
            mintSig: mint_sig.0.to_vec().into(),
            permitDeadline: U256::from(deadline.0),
            permitV: v,
            permitR: FixedBytes(r),
            permitS: FixedBytes(s),
        };
        let gas = relay_signature(chain, wallet, nft, &call.abi_encode(), deadline).await?;
        let message = Outbound::MintRequest(WireMint {
            pay_with_echo,
            wallet: owner.to_string(),
            max_cost: price.to_string(),
            mint_deadline: deadline.0,
            mint_sig: mint_sig.0.to_vec(),
            permit_deadline: deadline.0,
            permit_v: u32::from(v),
            permit_r: r.to_vec(),
            permit_s: s.to_vec(),
            gas_deadline: deadline.0,
            gas_sig: gas.0.to_vec(),
            slots: u32::from(slots),
        });
        exchange(
            self,
            Conversation {
                auth: Some(auth),
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::MintResult(r) => Step::Done(
                    outcome(r.success, r.error_message, &r.tx_hash).map(|tx| Minted {
                        tx,
                        token: TokenId(r.token_id),
                    }),
                ),
                _ => Step::Skip,
            },
        )
        .await
    }
}

impl ControlPlaneClient {
    /// Mints `amount` of the test network's USDC to `wallet`, in the token's
    /// smallest units.
    ///
    /// Test networks only: there the payment token is a stand-in anyone may
    /// mint, and the Control Plane relays the call so the wallet needs no
    /// gas. Elsewhere the Control Plane refuses. It also refuses an amount
    /// that would leave the wallet holding more than its cap.
    ///
    /// # Errors
    ///
    /// As [`register_commitment`](Self::register_commitment).
    pub async fn faucet<R: Rpc, W: Wallet>(
        &self,
        chain: &Chain<R>,
        wallet: &W,
        auth: &WalletAuth,
        amount: u128,
    ) -> Result<TxHash, ClientError> {
        let owner = signer(wallet, auth)?;
        let token = chain.payment_token(Payment::Usdc)?;
        let deadline = deadline()?;
        let call = ITestToken::mintCall {
            to: alloy(owner),
            amount: U256::from(amount),
        };
        let gas = relay_signature(chain, wallet, token, &call.abi_encode(), deadline).await?;
        let message = Outbound::FaucetRequest(FaucetRequest {
            wallet: owner.to_string(),
            amount: amount.to_string(),
            gas_deadline: deadline.0,
            gas_sig: gas.0.to_vec(),
        });
        exchange(
            self,
            Conversation {
                auth: Some(auth),
                request: None,
                messages: vec![message],
            },
            |m| match m {
                Inbound::FaucetResult(r) => {
                    Step::Done(outcome(r.success, r.error_message, &r.tx_hash))
                }
                _ => Step::Skip,
            },
        )
        .await
    }
}

/// The wallet's signature over the `GasStation.relayClient` meta-transaction
/// that carries `calldata` to `target`:
///
/// ```text
/// keccak256(signer ‖ target ‖ calldata ‖ nonce (u256) ‖ deadline (u256) ‖ chainId (u256) ‖ gasStation)
/// ```
///
/// signed with `personal_sign` — `abi.encodePacked`, as `GasStation` hashes it.
pub(super) async fn relay_signature<R: Rpc, W: Wallet>(
    chain: &Chain<R>,
    wallet: &W,
    target: Address,
    calldata: &[u8],
    deadline: UnixTime,
) -> Result<WalletSignature, ClientError> {
    let station = contract(chain.deployment().contracts.gas_station, "GasStation")?;
    let digest = relay_digest(&Relay {
        signer: wallet.address(),
        target,
        calldata,
        nonce: chain.relay_nonce(wallet.address()).await?,
        deadline,
        chain_id: chain.deployment().chain_id,
        station,
    });
    Ok(sign_message_checked(wallet, PersonalMessage::Raw(&digest)).await?)
}

/// A `GasStation.relayClient` meta-transaction, before signing.
pub(super) struct Relay<'a> {
    pub(super) signer: Address,
    pub(super) target: Address,
    pub(super) calldata: &'a [u8],
    pub(super) nonce: U256,
    pub(super) deadline: UnixTime,
    pub(super) chain_id: u64,
    pub(super) station: Address,
}

/// What the wallet signs for `relay`.
pub(super) fn relay_digest(relay: &Relay<'_>) -> [u8; 32] {
    Keccak256::new()
        .chain_update(relay.signer.0)
        .chain_update(relay.target.0)
        .chain_update(relay.calldata)
        .chain_update(relay.nonce.to_be_bytes::<32>())
        .chain_update(U256::from(relay.deadline.0).to_be_bytes::<32>())
        .chain_update(U256::from(relay.chain_id).to_be_bytes::<32>())
        .chain_update(relay.station.0)
        .finalize()
        .into()
}

/// The wallet's address, after checking `auth` is its sign-in.
pub(super) fn signer<W: Wallet>(wallet: &W, auth: &WalletAuth) -> Result<Address, ClientError> {
    if auth.wallet() == wallet.address() {
        Ok(wallet.address())
    } else {
        Err(ClientError::Mismatch("the sign-in is another wallet's"))
    }
}

fn contract(address: Option<Address>, name: &'static str) -> Result<Address, ClientError> {
    address.ok_or(ClientError::Chain(ChainError::NotDeployed(name)))
}

pub(super) fn deadline() -> Result<UnixTime, ClientError> {
    let secs =
        i64::try_from(RELAY_DEADLINE.as_secs()).map_err(|_| ClientError::Mismatch("deadline"))?;
    Ok(UnixTime(UnixTime::now().0.saturating_add(secs)))
}

pub(super) fn alloy(a: Address) -> alloy_primitives::Address {
    alloy_primitives::Address::from(a.0)
}

/// `r`, `s` and `v` of a signature, as ERC-2612's `permit` takes them.
fn split(signature: &WalletSignature) -> ([u8; 32], [u8; 32], u8) {
    let mut r = [0; 32];
    let mut s = [0; 32];
    r.copy_from_slice(&signature.0[..32]);
    s.copy_from_slice(&signature.0[32..64]);
    (r, s, signature.0[64])
}

/// A relay's result: the transaction, or the Control Plane's refusal.
pub(super) fn outcome(success: bool, error: String, tx: &str) -> Result<TxHash, ClientError> {
    if !success {
        return Err(ClientError::Refused {
            code: 0,
            message: error,
        });
    }
    tx.parse()
        .map_err(|_| ClientError::Malformed("transaction hash"))
}

/// Commitments as the contract's `uint256[]`.
fn words(commitments: &[FieldElement]) -> Vec<U256> {
    commitments
        .iter()
        .map(|c| U256::from_be_bytes(c.to_be_bytes()))
        .collect()
}

/// Commitments as the proto carries them: 32 bytes big-endian each.
fn wire(commitments: &[FieldElement]) -> Vec<Vec<u8>> {
    commitments
        .iter()
        .map(|c| c.to_be_bytes().to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Computed independently: with viem, which the desktop client uses for the
    // same calls, and with ethers for the calls that changed with slots.
    const WALLET: &str = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23";
    const NFT: &str = "0xA0c2F384345CBc868D25e5Df4f555C6dB2795f85";
    const STATION: &str = "0x63ffBD0A2F38cd7093b2887227cA9Ff35D44A469";

    fn addr(s: &str) -> Address {
        s.parse().expect("an address")
    }

    fn mint_calldata() -> Vec<u8> {
        let mut sig = vec![0x11; 64];
        sig.push(0x1b);
        ISubscriptionNFT::mintWithPermitCall {
            wallet: alloy(addr(WALLET)),
            payWithEcho: false,
            slots: 3,
            maxCost: U256::from(10u64.pow(19)),
            mintDeadline: U256::from(1_760_000_000),
            mintSig: sig.into(),
            permitDeadline: U256::from(1_760_000_000),
            permitV: 28,
            permitR: FixedBytes([0x22; 32]),
            permitS: FixedBytes([0x33; 32]),
        }
        .abi_encode()
    }

    #[test]
    fn encodes_the_mint_call_as_ethers_does() {
        assert_eq!(
            crate::hex::lower(&Keccak256::digest(mint_calldata())),
            "b0ef019fbce7ae717eea7c996cdb863dfceb753770b8f0dc1d4c3f27bae57214"
        );
    }

    #[test]
    fn hashes_the_relay_as_gas_station_does() {
        let calldata = mint_calldata();
        let digest = relay_digest(&Relay {
            signer: addr(WALLET),
            target: addr(NFT),
            calldata: &calldata,
            nonce: U256::from(3),
            deadline: UnixTime(1_760_000_000),
            chain_id: 421_614,
            station: addr(STATION),
        });
        assert_eq!(
            crate::hex::lower(&digest),
            "06f331ee5d4a3da8ead24aad4bd0c2331ed96d6208b8646e8d051a004d9df5d9"
        );
    }

    /// The same bytes the Control Plane's Go encoder is pinned to, from ethers.
    #[test]
    fn encodes_the_activation_as_ethers_does() {
        let mut sig = vec![0x11; 64];
        sig.push(0x1b);
        let calldata = ISubscriptionNFT::activateWithSignatureCall {
            wallet: alloy(addr(WALLET)),
            tokenId: U256::from(11),
            commitments: vec![U256::from(12_345), U256::from(67_890)],
            deadline: U256::from(1_760_000_000),
            signature: sig.into(),
        }
        .abi_encode();
        let want = concat!(
            "da794867",
            "0000000000000000000000002c7536e3605d9c16a7a3d7b1898e529396a65c23",
            "000000000000000000000000000000000000000000000000000000000000000b",
            "00000000000000000000000000000000000000000000000000000000000000a0",
            "0000000000000000000000000000000000000000000000000000000068e77800",
            "0000000000000000000000000000000000000000000000000000000000000100",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000003039",
            "0000000000000000000000000000000000000000000000000000000000010932",
            "0000000000000000000000000000000000000000000000000000000000000041",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "1b00000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(crate::hex::lower(&calldata), want);
    }

    #[test]
    fn splits_a_signature_for_permit() {
        let mut sig = [0u8; 65];
        sig[..32].fill(1);
        sig[32..64].fill(2);
        sig[64] = 28;
        assert_eq!(split(&WalletSignature(sig)), ([1; 32], [2; 32], 28));
    }
}
