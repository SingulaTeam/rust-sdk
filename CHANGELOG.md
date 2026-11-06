# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Singula::governance` and `ControlPlaneClient::governance`: proposals,
  votes and replies in `ProtocolGovernor`, as a subscriber or as a Star's
  owner (`Participant`, `GovernanceAction`, `Vote`), without ETH. The wallet
  signs the action as EIP-712 `Act` typed data in the governor's domain and
  the `GasStation` meta-transaction around it; a Control Plane forwards both.
  `Chain::protocol_governor` reads the governor's address from the directory
  when asked.

- `Chain::mint_cost`: what an Orbit of a given number of slots costs in USDC
  now, read from `SubscriptionNFT.mintCost` — the nominal price less a
  running promotion's discount. Not always the slots times the price of one:
  a campaign may cover a one-slot discount and not a larger one.

- `Chain::directory_moved`: reads the `SingulaProtocol` directory again and
  says whether a contract has been replaced since the `Chain` connected, so
  a long-running client can connect again.

- `Chain::gas_fee` and `GasOp`: what a gasless purchase or addition pays in
  USDC for its gas, read from `GasStation.gasFee`; `fee_ceiling`, the half
  again a wallet signs for so that a moving gas price does not fail it.

- `Singula::add_slots` and `ControlPlaneClient::add_slots`: more slots for an
  Orbit already bought, priced for the part of its term left
  (`Chain::add_slots_cost`), with the new slots' identities joining the set in
  the same transaction.
- `Singula::faucet` and `ControlPlaneClient::faucet`: test USDC, minted
  through a Control Plane's relay so the wallet needs no gas. Test networks
  only; the Control Plane caps what one wallet may hold.

- Control Plane fronts, for networks that block the endpoint: the
  protocol's settings in `chain::front`, each Control Plane's REALITY key in
  `ControlPlane::reality_key` and `ControlPlane::front`, read from
  `CPEndpointRegistry.getRealityKey`, and `ControlPlaneClient::through` to
  call a Control Plane over the application's tunnel to its front.

### Changed

- `k256` 0.13 → 0.14, which moves its big-integer arithmetic to
  `crypto-bigint` 0.7.6 and later (RUSTSEC-2026-0387). `LocalWallet::random`
  now draws its key from the operating system's generator directly.
- `blind-rsa-signatures` 0.17 → 0.18. `rsa` is pinned to 0.10.0-rc.19:
  `blind-rsa-signatures` accepts any `rsa` 0.10 pre-release, and rc.21 no
  longer builds with it, so a project resolving its dependencies afresh
  would otherwise fail to compile this crate.

- `mint` in USDC signs `mint_cost` plus the gas fee's ceiling, not the
  nominal price: if the discount a wallet was quoted is gone when the
  purchase runs, it is refused rather than charged in full. Needs the
  `SubscriptionNFT` with `mintCost`.

- `mint` and `add_slots` sign and permit the price plus the gas fee's
  ceiling, in USDC; the contract takes what both cost when it runs. Needs the
  `SubscriptionNFT` that charges the fee: against the one before, the wallet
  signs for more than it is charged.

- Orbits have slots: 1 to 5 concurrent sessions, each one price
  (`MAX_SLOTS`). `Singula::mint` and `ControlPlaneClient::mint` take the
  count and pay that many prices; `Subscription::slots` and
  `Chain::slots_of` read it. An Orbit joins the anonymity set with one
  identity per slot, all derived from the one wallet signature
  (`Identity::for_slot`; slot 0 is the identity as before), so activation and
  registration take a list of commitments. `Singula::identities` lists the
  wallet's identities in the set, and `Singula::connect` takes each session's
  permission with whichever has one free. Needs `SubscriptionNFT` v3 and
  `SubscriberRegistry` v2, and Control Planes that speak the new `MintRequest`,
  `ActivationRequest` and `RegisterCommitmentRequest`.
- Permissions are taken one at a time, each under an index of its own
  (`Claim::Permission { window, index }`, `ControlPlaneClient::take_permission`),
  in place of one packet per window. A subscription's devices can now each
  take their own, together no more than the issuer's count; `Singula::connect`
  picks a free index and moves past those taken elsewhere
  (`ClientError::PermissionTaken`). Needs Control Planes that take the index.
- `Singula::connect` proves the next quota slot when a Control Plane refuses
  one as used (`ERROR_CODE_ACCESS_CLAIM_USED`): each device counts its slots
  apart, and another may have used the first ones.
- BLAKE-512 for identities is computed in the crate: `blake-hash` panics on
  ARM. Identities are unchanged.

### Fixed

- The RPC client on Android verifies TLS against Mozilla's roots; reqwest's
  platform verifier panicked there without the app's JNI context.

## [0.1.0]

The first release: the whole client side of the protocol.

### Added

- Core: Star, epoch, session and request identifiers; the checkpoint and
  renewal digests; the session key exchange (X25519, HKDF-SHA256,
  AES-256-GCM), with the node's answer checked against its registered signer
  key; checkpoint signing (Ed25519); the wallet sign-in message.
- `chain`: the `SingulaProtocol` directory and the epoch clock; Stars and
  their signer keys; Control Plane endpoints; subscriptions and prices; the
  subscriber set, read against one block; permission key commitments.
  `http`: a JSON-RPC transport over HTTPS.
- `zk`: Semaphore v4 identities compatible with the JavaScript client; the
  subscriber group as a Lean IMT; session and packet claims; a prover with
  the circuit bundled, needing no files and no network.
- `client`: every Control Plane call a client makes — issuer keys and blind
  permission packets, node and country lists, anonymous and wallet sessions,
  traffic reports, renewal, session end, health, subscription status — and
  the gasless relays for mint, activation (joining the anonymity set in the
  same transaction) and commitment registration, with EIP-712 typed data for
  any wallet.
- `client::Singula` and `Connection`: `connect` in one call, with reports
  and renewals kept in the background; `Store` for what must outlive the
  process, with `FileStore` and `MemoryStore`; `TimeSource` for devices
  whose clock cannot be trusted.
- `ControlPlaneClient::at` and `HttpRpc::at`: reach a Control Plane or an
  RPC node at addresses the application resolved itself, with TLS still
  checked against the published host — for clients whose kill switch blocks
  DNS while their tunnel is down.
- Anonymous sessions end early: `Ending`, the end signed by the session's own
  key, and `ControlPlaneClient::end_anonymous_session`; `Connection::close`
  ends every session it holds, so its permission is free again within a
  lease. A permission still held by a Control Plane waits out the hold
  (`ClientError::PermissionFreeAt`) instead of being offered and refused; a
  node whose answer does not check out is named (`ClientError::NodeAnswer`).
  A permission's hold in the `Store` lapses unless reports keep it, so one
  held by a client that died is lent again once Control Planes have swept the
  silent session.
- `Subscription::starts_at`: subscriptions stack, and one activated while
  another still runs starts where it ends.

[Unreleased]: https://github.com/SingulaTeam/rust-sdk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SingulaTeam/rust-sdk/releases/tag/v0.1.0
