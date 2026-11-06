//! Wallets: whatever holds a subscriber's key and signs on their behalf.
//!
//! The SDK never holds a user's wallet key. It hands the [`Wallet`] what to
//! sign — a `personal_sign` message or EIP-712 typed data — and checks the
//! signature that comes back recovers to the wallet's address before using
//! it, so a wallet that signed the wrong thing fails here, not after a
//! Control Plane has spent gas relaying it.

use std::fmt;
use std::future::Future;

use alloy_primitives::{Address as AlloyAddress, U256};
use alloy_sol_types::{Eip712Domain, SolStruct, sol};
use k256::ecdsa::SigningKey;
use serde_json::{Map, Value, json};

use crate::eth;
use crate::id::Address;

sol! {
    /// `SubscriptionNFT`'s gasless mint intent.
    struct MintRequest {
        address wallet;
        bool payWithEcho;
        uint8 slots;
        uint256 maxCost;
        uint256 deadline;
        uint256 nonce;
    }

    /// `SubscriptionNFT`'s gasless activation, joining the anonymity set
    /// with one identity per slot.
    struct Activation {
        address wallet;
        uint256 tokenId;
        uint256[] commitments;
        uint256 deadline;
        uint256 nonce;
    }

    /// `SubscriberRegistry`'s gasless registration.
    struct Register {
        address wallet;
        uint256 tokenId;
        uint256[] commitments;
        uint256 deadline;
        uint256 nonce;
    }

    /// `SubscriptionNFT`'s gasless purchase of more slots for an Orbit,
    /// with the new slots' identities.
    struct AddSlots {
        address wallet;
        uint256 tokenId;
        uint8 extra;
        uint256[] commitments;
        uint256 maxCost;
        uint256 deadline;
        uint256 nonce;
    }

    /// `ProtocolGovernor`'s signed action: a proposal, vote or reply the
    /// governor runs as `wallet`.
    struct Act {
        address wallet;
        bytes data;
        uint256 nonce;
        uint256 deadline;
    }

    /// EIP-2612.
    struct Permit {
        address owner;
        address spender;
        uint256 value;
        uint256 nonce;
        uint256 deadline;
    }
}

/// A `personal_sign` message: shown to the person as text when it is text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonalMessage<'a> {
    /// Readable text, such as the sign-in message.
    Text(&'a str),
    /// Raw bytes, such as a 32-byte digest; wallets show these as hex.
    Raw(&'a [u8]),
}

impl PersonalMessage<'_> {
    /// The bytes that are signed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Text(t) => t.as_bytes(),
            Self::Raw(b) => b,
        }
    }
}

/// EIP-712 typed data for one of the protocol's signed requests.
///
/// Give a local key [`signing_hash`](Self::signing_hash); give a wallet
/// connector [`to_json`](Self::to_json), the `eth_signTypedData_v4` form, so
/// it can show the person what they are signing.
#[derive(Clone)]
pub struct TypedData {
    domain: Eip712Domain,
    message: Message,
}

#[derive(Clone)]
pub(crate) enum Message {
    Mint(MintRequest),
    Activation(Activation),
    Register(Register),
    AddSlots(AddSlots),
    Act(Act),
    Permit(Permit),
}

impl TypedData {
    pub(crate) fn new(domain: Eip712Domain, message: Message) -> Self {
        Self { domain, message }
    }

    /// The 32-byte hash a key signs.
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        match &self.message {
            Message::Mint(m) => m.eip712_signing_hash(&self.domain),
            Message::Activation(m) => m.eip712_signing_hash(&self.domain),
            Message::Register(m) => m.eip712_signing_hash(&self.domain),
            Message::AddSlots(m) => m.eip712_signing_hash(&self.domain),
            Message::Act(m) => m.eip712_signing_hash(&self.domain),
            Message::Permit(m) => m.eip712_signing_hash(&self.domain),
        }
        .0
    }

    /// The message's `encodeType` and its values in that order, as JSON.
    fn fields(&self) -> (String, Vec<Value>) {
        match &self.message {
            Message::Mint(m) => (
                encode_type(m),
                vec![
                    address(m.wallet),
                    json!(m.payWithEcho),
                    json!(m.slots),
                    uint(m.maxCost),
                    uint(m.deadline),
                    uint(m.nonce),
                ],
            ),
            Message::Activation(m) => (
                encode_type(m),
                vec![
                    address(m.wallet),
                    uint(m.tokenId),
                    uints(&m.commitments),
                    uint(m.deadline),
                    uint(m.nonce),
                ],
            ),
            Message::Register(m) => (
                encode_type(m),
                vec![
                    address(m.wallet),
                    uint(m.tokenId),
                    uints(&m.commitments),
                    uint(m.deadline),
                    uint(m.nonce),
                ],
            ),
            Message::AddSlots(m) => (
                encode_type(m),
                vec![
                    address(m.wallet),
                    uint(m.tokenId),
                    json!(m.extra),
                    uints(&m.commitments),
                    uint(m.maxCost),
                    uint(m.deadline),
                    uint(m.nonce),
                ],
            ),
            Message::Act(m) => (
                encode_type(m),
                vec![
                    address(m.wallet),
                    Value::from(m.data.to_string()),
                    uint(m.nonce),
                    uint(m.deadline),
                ],
            ),
            Message::Permit(m) => (
                encode_type(m),
                vec![
                    address(m.owner),
                    address(m.spender),
                    uint(m.value),
                    uint(m.nonce),
                    uint(m.deadline),
                ],
            ),
        }
    }

    /// The typed data as `eth_signTypedData_v4` takes it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let (encode_type, values) = self.fields();
        // `Name(type field,…)`: the one place the fields are declared, so the
        // JSON cannot drift from what is hashed.
        let (primary, fields) = encode_type
            .trim_end_matches(')')
            .split_once('(')
            .unwrap_or_default();
        let fields: Vec<(&str, &str)> = fields
            .split(',')
            .filter_map(|f| f.split_once(' '))
            .collect();
        let types: Vec<Value> = fields
            .iter()
            .map(|(ty, name)| json!({ "name": name, "type": ty }))
            .collect();
        let message: Map<String, Value> = fields
            .iter()
            .map(|(_, name)| (*name).to_owned())
            .zip(values)
            .collect();

        let d = &self.domain;
        json!({
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" },
                    { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" },
                    { "name": "verifyingContract", "type": "address" },
                ],
                primary: types,
            },
            "primaryType": primary,
            "domain": {
                "name": d.name.as_deref().unwrap_or_default(),
                "version": d.version.as_deref().unwrap_or_default(),
                "chainId": d.chain_id.map(uint).unwrap_or_default(),
                "verifyingContract": d.verifying_contract.map(address).unwrap_or_default(),
            },
            "message": message,
        })
    }
}

impl fmt::Debug for TypedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedData")
            .field("data", &self.to_json())
            .finish()
    }
}

/// `Name(type field,…)` for `T`.
fn encode_type<T: SolStruct>(_: &T) -> String {
    T::eip712_encode_type().into_owned()
}

fn address(a: AlloyAddress) -> Value {
    Value::from(a.to_checksum(None))
}

fn uint(v: U256) -> Value {
    Value::from(v.to_string())
}

fn uints(v: &[U256]) -> Value {
    Value::from(v.iter().map(ToString::to_string).collect::<Vec<_>>())
}

/// A 65-byte wallet signature, `r ‖ s ‖ v`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WalletSignature(pub [u8; 65]);

impl fmt::Debug for WalletSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WalletSignature(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        write!(f, ")")
    }
}

/// Why a wallet did not sign.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WalletError {
    /// The person declined.
    #[error("the signature request was declined")]
    Declined,
    /// The wallet failed.
    #[error("the wallet failed to sign")]
    Failed(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The wallet returned a signature by another address, or over other
    /// data than it was asked to sign.
    #[error("the wallet's signature is not by its own address over the request")]
    WrongSignature,
}

/// Something that signs as a subscriber's wallet.
///
/// Implement it over whatever the application uses — a browser wallet
/// through a connector, an embedded wallet, a hardware key.
pub trait Wallet: Send + Sync {
    /// The wallet's address.
    fn address(&self) -> Address;

    /// Signs `message` with `personal_sign` (EIP-191).
    fn sign_message(
        &self,
        message: PersonalMessage<'_>,
    ) -> impl Future<Output = Result<WalletSignature, WalletError>> + Send;

    /// Signs `data` with `eth_signTypedData_v4` (EIP-712).
    fn sign_typed_data(
        &self,
        data: &TypedData,
    ) -> impl Future<Output = Result<WalletSignature, WalletError>> + Send;
}

/// Asks `wallet` to sign `message` and checks what comes back.
pub(crate) async fn sign_message_checked<W: Wallet>(
    wallet: &W,
    message: PersonalMessage<'_>,
) -> Result<WalletSignature, WalletError> {
    let signature = wallet.sign_message(message).await?;
    let hash = eth::personal_message_hash(message.bytes());
    check(wallet.address(), &hash, signature)
}

/// Asks `wallet` to sign `data` and checks what comes back.
pub(crate) async fn sign_typed_data_checked<W: Wallet>(
    wallet: &W,
    data: &TypedData,
) -> Result<WalletSignature, WalletError> {
    let signature = wallet.sign_typed_data(data).await?;
    check(wallet.address(), &data.signing_hash(), signature)
}

fn check(
    expected: Address,
    hash: &[u8; 32],
    signature: WalletSignature,
) -> Result<WalletSignature, WalletError> {
    match eth::recover(hash, &signature.0) {
        Ok(signer) if signer == expected => Ok(signature),
        _ => Err(WalletError::WrongSignature),
    }
}

/// A wallet whose key is held in memory: for scripts, services and tests.
///
/// The key is wiped from memory on drop.
pub struct LocalWallet {
    key: SigningKey,
    address: Address,
}

impl LocalWallet {
    /// A wallet with a fresh random key.
    #[must_use]
    pub fn random() -> Self {
        Self::from_key(eth::random_key())
    }

    /// A wallet for the 32-byte secret key `secret`.
    ///
    /// # Errors
    ///
    /// Returns [`WalletError::Failed`] if `secret` is not a valid key.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, WalletError> {
        SigningKey::from_slice(secret)
            .map(Self::from_key)
            .map_err(|e| WalletError::Failed(e.into()))
    }

    fn from_key(key: SigningKey) -> Self {
        let address = eth::address_of(key.verifying_key());
        Self { key, address }
    }

    fn sign_hash(&self, hash: &[u8; 32]) -> WalletSignature {
        WalletSignature(eth::sign(&self.key, hash))
    }
}

impl Wallet for LocalWallet {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign_message(
        &self,
        message: PersonalMessage<'_>,
    ) -> Result<WalletSignature, WalletError> {
        Ok(self.sign_hash(&eth::personal_message_hash(message.bytes())))
    }

    async fn sign_typed_data(&self, data: &TypedData) -> Result<WalletSignature, WalletError> {
        Ok(self.sign_hash(&data.signing_hash()))
    }
}

impl fmt::Debug for LocalWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalWallet")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

    use super::*;

    fn domain() -> Eip712Domain {
        Eip712Domain::new(
            Some("SingulaSubscription".into()),
            Some("1".into()),
            Some(U256::from(421_614)),
            Some(address!("0xA0c2F384345CBc868D25e5Df4f555C6dB2795f85")),
            None,
        )
    }

    fn activation() -> TypedData {
        TypedData::new(
            domain(),
            Message::Activation(Activation {
                wallet: address!("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"),
                tokenId: U256::from(11),
                commitments: vec![U256::from(12_345), U256::from(67_890)],
                deadline: U256::from(1_760_000_000),
                nonce: U256::from(2),
            }),
        )
    }

    #[test]
    fn hashes_typed_data_as_eip712_defines() {
        // Built independently: keccak256(0x1901 ‖ domainSeparator ‖ hashStruct).
        use sha3::{Digest as _, Keccak256};
        let k = |b: &[u8]| -> [u8; 32] { Keccak256::digest(b).into() };
        let word = |v: u64| U256::from(v).to_be_bytes::<32>();
        let addr_word = |a: &str| {
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&hex::decode(a).expect("hex"));
            w
        };
        let domain_type = k(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let separator = k(&[
            domain_type,
            k(b"SingulaSubscription"),
            k(b"1"),
            word(421_614),
            addr_word("a0c2f384345cbc868d25e5df4f555c6db2795f85"),
        ]
        .concat());
        // An array member is the keccak256 of its elements' words.
        let struct_hash = k(&[
            k(b"Activation(address wallet,uint256 tokenId,uint256[] commitments,uint256 deadline,uint256 nonce)"),
            addr_word("2c7536e3605d9c16a7a3d7b1898e529396a65c23"),
            word(11),
            k(&[word(12_345), word(67_890)].concat()),
            word(1_760_000_000),
            word(2),
        ]
        .concat());
        let want = k(&[&[0x19, 0x01][..], &separator, &struct_hash].concat());
        assert_eq!(activation().signing_hash(), want);
        // …and as ethers' TypedDataEncoder, the same vector the Control Plane pins.
        assert_eq!(
            crate::hex::lower(&want),
            "ad39f120bdfe6fcd2d4c53a747d0f4379ffae711c0a4d4ee661d564c00ddc3b2"
        );
    }

    /// Hashes computed independently: viem's `hashTypedData` for the permit,
    /// ethers' `TypedDataEncoder` for the requests that changed with slots.
    #[test]
    fn hashes_every_request_as_viem_does() {
        let domain = |name: &str, contract| {
            Eip712Domain::new(
                Some(name.to_owned().into()),
                Some("1".into()),
                Some(U256::from(421_614)),
                Some(contract),
                None,
            )
        };
        let wallet = address!("0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
        let nft = address!("0xA0c2F384345CBc868D25e5Df4f555C6dB2795f85");
        let cases = [
            (
                TypedData::new(
                    domain(
                        "SingulaSubscriberRegistry",
                        address!("0x7Be0A074b56BcD165C22258773811bDf819cD434"),
                    ),
                    Message::Register(Register {
                        wallet,
                        tokenId: U256::from(11),
                        commitments: vec![U256::from(12_345), U256::from(67_890)],
                        deadline: U256::from(1_760_000_000),
                        nonce: U256::from(2),
                    }),
                ),
                "b8880c95629d3b341d657647d5baa0f79a859ed38d03ef7b2312c84c63c931bc",
            ),
            (
                TypedData::new(
                    domain(
                        "Singula USDC",
                        address!("0x87bD133c121E2D2a49E6D620D18fbE51047F6fc4"),
                    ),
                    Message::Permit(Permit {
                        owner: wallet,
                        spender: nft,
                        value: U256::from(10u64.pow(19)),
                        nonce: U256::ZERO,
                        deadline: U256::from(1_760_000_000),
                    }),
                ),
                "a642496844a85276b504e7e6dd764b91497ea6167d8b9668a2aeb9ecac1e0951",
            ),
            (
                TypedData::new(
                    domain("SingulaSubscription", nft),
                    Message::Mint(MintRequest {
                        wallet,
                        payWithEcho: false,
                        slots: 3,
                        maxCost: U256::from(10u64.pow(19)),
                        deadline: U256::from(1_760_000_000),
                        nonce: U256::from(1),
                    }),
                ),
                "4d892403555b6b2788cc9130ff363b87cf044f4eb7a6d0569e73e7119c4cc5af",
            ),
            (
                TypedData::new(
                    domain("SingulaSubscription", nft),
                    Message::AddSlots(AddSlots {
                        wallet,
                        tokenId: U256::from(11),
                        extra: 2,
                        commitments: vec![U256::from(12_345), U256::from(67_890)],
                        maxCost: U256::from(10u64.pow(19)),
                        deadline: U256::from(1_760_000_000),
                        nonce: U256::from(4),
                    }),
                ),
                "49d1cd24a53020d1282c6a616bb0b34cec92ce83decbfc226e796ecea442aab8",
            ),
        ];
        for (data, want) in cases {
            assert_eq!(crate::hex::lower(&data.signing_hash()), want, "{data:?}");
        }
    }

    #[test]
    fn describes_the_same_data_as_json() {
        let json = activation().to_json();
        assert_eq!(json["primaryType"], "Activation");
        assert_eq!(
            json["types"]["Activation"][1],
            json!({ "name": "tokenId", "type": "uint256" })
        );
        assert_eq!(json["message"]["tokenId"], "11");
        assert_eq!(
            json["types"]["Activation"][2],
            json!({ "name": "commitments", "type": "uint256[]" })
        );
        assert_eq!(json["message"]["commitments"], json!(["12345", "67890"]));
        assert_eq!(json["domain"]["chainId"], "421614");
        assert_eq!(
            json["message"]["wallet"],
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
        );
    }

    #[tokio::test]
    async fn a_local_wallet_passes_its_own_check() {
        let wallet = LocalWallet::random();
        assert!(
            sign_typed_data_checked(&wallet, &activation())
                .await
                .is_ok()
        );
        assert!(
            sign_message_checked(&wallet, PersonalMessage::Text("hello"))
                .await
                .is_ok()
        );
    }

    /// A wallet that signs whatever it likes.
    struct Liar(LocalWallet, LocalWallet);

    impl Wallet for Liar {
        fn address(&self) -> Address {
            self.0.address()
        }
        async fn sign_message(
            &self,
            m: PersonalMessage<'_>,
        ) -> Result<WalletSignature, WalletError> {
            self.1.sign_message(m).await
        }
        async fn sign_typed_data(&self, d: &TypedData) -> Result<WalletSignature, WalletError> {
            self.1.sign_typed_data(d).await
        }
    }

    #[tokio::test]
    async fn refuses_a_signature_by_someone_else() {
        let liar = Liar(LocalWallet::random(), LocalWallet::random());
        assert!(matches!(
            sign_typed_data_checked(&liar, &activation()).await,
            Err(WalletError::WrongSignature)
        ));
        assert!(matches!(
            sign_message_checked(&liar, PersonalMessage::Text("hello")).await,
            Err(WalletError::WrongSignature)
        ));
    }
}
