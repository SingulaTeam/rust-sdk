# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-11-20

### Fixed

- A session on a right sends its first ping one interval after opening, not
  at once: an application brings its tunnel up right after a session opens,
  and a ping in the middle of that could lose its connection. The seconds
  before the first ping count all the same.
- A ping that reaches no majority is tried again after `Timing::ping_retry`
  (30 seconds) rather than a whole interval, so a passing network error no
  longer leaves the session without a ping for ten minutes, when the
  Control Planes close it.

## [0.2.1] - 2026-11-20

### Fixed

- `Singula::connect` keeps each of a client's sessions on a slot of its own:
  a slot holds one session at a time, and a second one on it — another hop
  of a route, say — would be closed as an overlap. With every slot taken it
  returns the new `ClientError::NoFreeSlot` instead of opening a session to
  be closed. A route of several hops needs as many slots. The slot is given
  back when the session ends — before `Event::Ended` arrives, so reconnecting
  at once finds it free — when it fails to open, and when the call opening
  it is cancelled.

- `Singula::connect` and `ControlPlaneClient::open_session` return `Send`
  futures again, so a session can be opened from a spawned task. Opening on a
  right held a non-`Sync` reference across an await.

## [0.2.0] - 2026-11-20

### Added

- The shared journal (`journal`, in the core): a subscriber's slot takes a
  daily `Right` — a Semaphore proof against the day's subscriber tree — and
  delegates the day to a `RightKey`, derived from the slot's secret and the
  day so every device of a subscription derives the same one. Sessions are
  kept by `Ping`s of their seconds so far, signed with that key; Control
  Planes answer with `Attestation`s that `Versions::check_ack` checks against
  the Control Plane registry's history (`RegistryVersion`). `CloseReason` and
  `SessionStatus` say why the network closed a session. Every wire format is
  checked against the Control Planes' fixture of real proofs and signatures.
- `Claim::Right`, `Identity::right_key` and `AccessProof::to_right`.
- `chain::RegistryHistory`, the Control Plane set's history from
  `StarRegistry`'s events up to the finalized block, and
  `chain::SubscriberLog` with `SubscriberLog::window_tree`, a day's subscriber
  trees as the Control Planes build them: read from the chain, never taken
  from a Control Plane. Both start at the deployment blocks the directory
  publishes. `Chain::journal_params`.
- `Rpc::header` and `Rpc::logs`, and `Block::Finalized`. Logs are read one
  event at a time, in spans the node accepts.
- `SessionRequest::on_right`, `ControlPlaneClient::ping` (`Ack`,
  `Ack::committed`) and `ControlPlaneClient::session_status`.
- `Event::Pinged`, `Event::PingFailed`, `EndReason::ClosedByNetwork` and
  `Timing::ping_every`.
- `SessionId::to_bytes`.

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

- `Singula::connect` with `Access::Anonymous` opens the session on the day's
  right of one of the wallet's slots and keeps it by pings every five
  minutes: a ping counts once a strict majority of Control Planes recorded
  it, as checked against the chain, and goes to another Control Plane when
  one cannot show that. Past midnight the session carries on under the next
  day's right. A session the network closes ends with the reason; one closed
  because another device holds the slot leaves that slot for the next
  connection. Needs Control Planes that run the shared journal.
- `Rpc` has two more required methods, and `Block` is `#[non_exhaustive]`.
- `EndReason` is no longer `Copy`: `ClosedByNetwork` carries a reason.
- `ControlPlaneClient::renew` takes no permission: only a wallet's session
  is renewed.
- `ClientError::NotRegistered` also covers a slot whose Orbit ends during
  the day; `ClientError::NotCommitted` is a ping no majority recorded.
- `k256` 0.13 → 0.14, which moves its big-integer arithmetic to
  `crypto-bigint` 0.7.6 and later (RUSTSEC-2026-0387). `LocalWallet::random`
  now draws its key from the operating system's generator directly.

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
  wallet's identities in the set, and `Singula::connect` opens each session
  on one of their rights. Needs `SubscriptionNFT` v3 and
  `SubscriberRegistry` v2, and Control Planes that speak the new `MintRequest`,
  `ActivationRequest` and `RegisterCommitmentRequest`.
- BLAKE-512 for identities is computed in the crate: `blake-hash` panics on
  ARM. Identities are unchanged.

### Removed

- Per-window permissions, which the daily right replaces: `Permission`,
  `IssuerKey`, `ControlPlaneClient::issuer_key` and `take_permission`,
  `SessionRequest::anonymous`, `Claim::Session` and `Claim::Permission`,
  `chain::PermissionKeyCommitment` and `Chain::permission_key_commitment`,
  and `ClientError::NoPermissionFree`, `PermissionTaken` and
  `PermissionFreeAt`. With them go the `blind-rsa-signatures` and `rsa`
  dependencies.

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

[Unreleased]: https://github.com/SingulaTeam/rust-sdk/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/SingulaTeam/rust-sdk/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/SingulaTeam/rust-sdk/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/SingulaTeam/rust-sdk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SingulaTeam/rust-sdk/releases/tag/v0.1.0
