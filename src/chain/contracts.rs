//! The contract interfaces this crate reads, as Solidity declares them.
//!
//! Only the view functions a client needs; see `arbitrum/contracts` for the
//! full contracts.

alloy_sol_types::sol! {
    interface ISingulaProtocol {
        struct Snapshot {
            uint256 chainId;
            uint256 currentEpoch;
            uint256 epochZeroStart;
            uint256 epochDuration;
            address starRegistry;
            address subscriberRegistry;
            address voucherKeyRegistry;
            address cpEndpointRegistry;
            address subscriptionNft;
            address epochAttestations;
            address rewardDistributor;
            address echoToken;
            address usdcToken;
            address gasStation;
        }

        function snapshot() external view returns (Snapshot memory);
        function contractFor(bytes32 name) external view returns (address);
    }

    /// The participant functions of `ProtocolGovernor`, which a wallet signs
    /// and a Control Plane relays through `act`.
    interface IProtocolGovernor {
        function proposeAsStar(uint256 starId, bytes32 key, uint256 value, string title, string text) external returns (uint256);
        function proposeAsSubscriber(bytes32 key, uint256 value, string title, string text) external returns (uint256);
        function voteAsStar(uint256 id, uint256[] starIds, uint256 choice, string reason) external;
        function voteAsSubscriber(uint256 id, uint256 choice, string reason) external;
        function argueAsStar(uint256 id, uint256 starId, uint256 replyTo, string text) external;
        function argueAsSubscriber(uint256 id, uint256 replyTo, string text) external;
    }

    interface IStarRegistry {
        struct StarInfo {
            address owner;
            address signer;
            uint8 role;
            uint64 registerEpoch;
        }

        function getStar(uint256 starId) external view returns (StarInfo memory);
        function getStarIdBySigner(address signer) external view returns (uint256);
    }

    interface ICPEndpointRegistry {
        function getEndpoint(uint256 starId) external view returns (
            string memory host, uint16 port, uint64 updatedAt, bool active
        );
        function getActiveEndpoints() external view returns (
            uint256[] memory starIds, string[] memory hosts, uint16[] memory ports, uint64[] memory updatedAts
        );
        function getRealityKey(uint256 starId) external view returns (bytes32);
    }

    /// EIP-5267, which every `OpenZeppelin` v5 `EIP712` contract implements.
    interface IEip712 {
        function eip712Domain() external view returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
        function nonces(address owner) external view returns (uint256);
    }

    interface IErc20 {
        function balanceOf(address owner) external view returns (uint256);
    }

    /// A test network's stand-in for USDC, which anyone may mint.
    interface ITestToken {
        function mint(address to, uint256 amount) external;
    }

    interface IGasStation {
        function nonces(address signer) external view returns (uint256);
        function gasFee(bytes32 op, uint256 k) external view returns (uint256);
        function relayClient(address signer, address target, bytes calldata data, uint256 deadline, bytes calldata signature)
            external returns (bytes memory);
    }

    interface ISubscriberRegistry {
        function totalCommitments() external view returns (uint256);
        function commitmentsOf(uint256 tokenId) external view returns (uint256[] memory registered, uint256[] memory indices);
        function commitmentsSlice(uint256 start, uint256 count) external view returns (uint256[] memory);
        function circuitVersion() external view returns (string memory);
    }

    interface ISubscriptionNFT {
        function balanceOf(address owner) external view returns (uint256);
        function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256);
        function expiresAt(uint256 tokenId) external view returns (uint256);
        function activatedAt(uint256 tokenId) external view returns (uint256);
        function isTokenActive(uint256 tokenId) external view returns (bool);
        function slotsOf(uint256 tokenId) external view returns (uint8);
        function slotsNow(address holder) external view returns (uint8);
        function mintNonces(address wallet) external view returns (uint256);
        function unactivatedCount(address wallet) external view returns (uint256);
        function priceUSDC() external view returns (uint256);
        function mintCost(uint8 slots) external view returns (uint256);
        function priceEcho() external view returns (uint256);
        function echoDiscount() external view returns (uint256);
        function echoMintingEnabled() external view returns (bool);
        function mintWithPermit(
            address wallet, bool payWithEcho, uint8 slots, uint256 maxCost, uint256 mintDeadline, bytes calldata mintSig,
            uint256 permitDeadline, uint8 permitV, bytes32 permitR, bytes32 permitS
        ) external returns (uint256);
        function addSlotsCost(uint256 tokenId, uint8 extra) external view returns (uint256);
        function addSlotsWithPermit(
            address wallet, uint256 tokenId, uint8 extra, uint256[] calldata commitments, uint256 maxCost,
            uint256 deadline, bytes calldata sig, uint256 permitDeadline, uint8 permitV, bytes32 permitR, bytes32 permitS
        ) external;
        function activateWithSignature(
            address wallet, uint256 tokenId, uint256[] calldata commitments, uint256 deadline, bytes calldata signature
        ) external;
    }

    interface IVoucherKeyRegistry {
        function getEpochKey(uint256 issuerStarId, uint256 epoch) external view returns (
            bytes32 keyHash, uint32 denominationGB, uint64 setAt, bool issuerActive
        );
    }
}
