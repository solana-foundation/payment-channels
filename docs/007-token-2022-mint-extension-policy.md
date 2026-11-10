# ADR-007: Token-2022 Mint Extension Policy

**Status:** Implemented (2026-10-29)

**Parent ADRs:** [ADR-001](./001-payment-channel-state-machine.md) (Token Program
Support, Mint trust model), [ADR-003](./003-program-instructions.md) (error codes)

## Context

Until this ADR the mint allow-list admitted six Token-2022 extensions, all
metadata or group pointers. Every Token-2022 stablecoin that matters is issued
by Paxos and carries eight. Live mainnet state, read via RPC on 2026-10-27:

| Extension | PYUSD `2b1kV6…4GXo` / USDG `2u1tsz…jGWH` |
|---|---|
| `mintCloseAuthority` | set (Paxos) |
| `permanentDelegate` | set (Paxos) |
| `transferFeeConfig` | 0 bps, max 0, on both fee schedules; withheld 0 |
| `confidentialTransferMint` | `autoApproveNewAccounts: false` |
| `confidentialTransferFeeConfig` | withheld 0 |
| `transferHook` | `programId: null` |
| `metadataPointer`, `tokenMetadata` | set |

Both mints were therefore rejected at `open`, and worse, rejected with the same
code as a corrupt account (issue #83). USDC, USDT, EURC and USDS are plain SPL
Token mints and were never affected.

Token-2022 also adds account-side records to every token account of such a mint
(`TransferFeeAmount` for a fee mint, `TransferHookAccount` for a hook mint,
`PausableAccount` for a pausable mint), so admitting the mint without admitting
those records would still reject every ATA.

## Decision

`MintExtensionPolicy` admits extensions in three tiers. Anything else, including
unknown ids, is `UnsupportedMintTokenExtensions` (63).

1. **Inert, always allowed.** `MetadataPointer`, `TokenMetadata`, `GroupPointer`,
   `TokenGroup`, `GroupMemberPointer`, `TokenGroupMember`, `MintCloseAuthority`,
   `ConfidentialTransferMint`, `ConfidentialTransferFeeConfig`,
   `InterestBearingConfig`, `ScaledUiAmount`. None changes what a plain
   `TransferChecked` moves in base units. Closing a mint needs `supply == 0`,
   which a funded escrow prevents. Confidential balances live in an opt-in
   account extension the account policy rejects.
2. **Trusted, allowed under the mint trust model.** `PermanentDelegate`,
   `Pausable`. Issuer powers over the escrow: seize and pause respectively.
   Accepted on the same grounds ADR-001 accepts the freeze authority: the same
   regulated issuer already holds it, and rejecting it excludes every
   Paxos-issued stablecoin.
3. **State-gated, allowed only while dormant.** `TransferFeeConfig` when
   neither the schedule charging now nor the one scheduled next can charge
   (`transfer_fee_basis_points == 0` or `maximum_fee == 0`, mirroring
   `TransferFee::calculate_fee`; "now" is `get_epoch_fee(clock.epoch)`: `newer`
   from its epoch on, `older` before), and `TransferHook` when no `program_id`
   is installed. A live configuration is `ActiveMintTokenExtension` (64). The
   gate runs in `TokenContext::new` with the current `Clock` epoch, so every
   token-moving instruction (`open`, `topUp`, `withdrawPayer`, `distribute`)
   re-evaluates it.

`TokenAccountExtensionPolicy` admits `ImmutableOwner`, `TransferFeeAmount`,
`TransferHookAccount` and `PausableAccount` without inspecting state. Withheld
fees on a beneficiary account never block a credit, and the escrow can only
accrue them while a fee is live, which the mint gate already rejects.

Still rejected: `NonTransferable`, `DefaultAccountState`, `ConfidentialMintBurn`,
and the opt-in account extensions `ConfidentialTransferAccount` (holder can
refuse non-confidential credits), `MemoTransfer`, `CpiGuard`. Each can make a
payout fail, so they stay on the redirect-to-treasury path rather than being
allowed to brick the crank.

## Why the fee and hook must be dormant

A live fee breaks the accounting identity the state machine rests on. Token-2022
debits the source the full `amount` and credits the destination `amount − fee`.
On `open` and `topUp` the escrow is the destination, so it would hold less than
the `deposit` credited; the terminal `distribute` then cannot satisfy
`escrow == Σ payouts + sweep` and the channel can never close. On payouts the
escrow is the source, so the identity holds but recipients receive less than
their bps share. A live hook needs extra account metas the fixed four-account
`TransferChecked` in `transfer.rs` does not carry, so every escrow movement would
fail inside the CPI.

Checking the scheduled-next fee as well as the current one means a
`SetTransferFee` is rejected the moment it is scheduled, two epochs before it
takes effect. Checking only the schedule that governs now means a reverted fee
is admitted again exactly when Token-2022 stops charging it: on revert,
Token-2022 moves the active fee into `older` and schedules zero in `newer` two
epochs out, and `older` keeps charging until then.

## Alternatives considered

- **Keep rejecting by presence.** Excludes PYUSD and USDG for extensions that
  are inert or dormant on every deployed instance. Rejected.
- **Fee-tolerant accounting** (`TransferCheckedWithFee`, crediting
  `deposit` net of fee). Makes `deposit`/`settled` depend on issuer-mutable
  state and breaks the base-unit exactness every distribution test pins.
  Rejected.
- **Tolerate a live fee on outflows only** (reject at `open`/`topUp`, allow
  `distribute`). Keeps the escrow identity but silently pays recipients less
  than their committed share. Rejected in favour of one uniform gate.
- **Resolve hook accounts in the CPI.** Substantial, and a hook program can
  revert any transfer anyway. Deferred; nothing deployed uses a hook.
- **Reject `PermanentDelegate`.** Would exclude every Paxos mint. The power is
  strictly stronger than freeze, but it is held by the same issuer under the
  same legal process. Accepted as a documented trust decision.

## Consequences

- **Issuer activation wedges the channel.** If Paxos activates a fee or installs
  a hook, every token-moving instruction fails with `ActiveMintTokenExtension`
  until it is reverted. Funds stay in escrow; nothing is lost. Same operational
  class as a freeze. A hook revert reopens the gate at once; a fee revert
  reopens it when the zero schedule takes over, up to two epochs later. Tests
  cover both, including a fee that activated before the revert.
- **Permanent delegate can drain the escrow.** The program does not detect it.
  OPEN distributes then fail on insufficient funds and the SEALED distribute
  underflows (`DistributeBalanceCalculationOverflow`), so the channel cannot
  close. Unlike a freeze this is not reversible by inaction: only the issuer
  re-crediting the escrow restores the accounting identity. Merchants accept
  this by allow-listing the mint (ADR-002 §4).
- **Unsolicited transfers while a fee is live** leave withheld fees on the
  escrow ATA that block `CloseAccount`; the permissionless
  `HarvestWithheldTokensToMint` clears them.
- **Compute.** Token-2022 runs fee and hook bookkeeping on every transfer of
  such a mint and each ATA carries three extra records:

  | Scenario | extensionless Token-2022 | PYUSD-shaped |
  |---|---|---|
  | `open[n=01]` | 31,823 CU | 37,632 CU |
  | `distribute[n=16,open]` | 135,569 CU | 168,244 CU |
  | `distribute[n=32,fin]` | 256,266 CU | 320,843 CU |

  Existing rows are unchanged. The `tok=t22-pyusd` benchmark rows pin this.
- **Error codes.** 63 and 64 appended; `MalformedMintTokenExtensions` (56) now
  means only a structurally bad trailer. PR #84 adds the same code 63.

## Verification

- Unit: policy tiers, both state gates at their boundaries, payload length
  checks, and `offset_of!` pins of the fee and hook layouts against
  `spl-token-2022-interface`. An upstream-driven test asserts every account
  record Token-2022 auto-adds for an allowed mint extension is itself allowed.
- Mollusk, no CPI: `open`, `topUp`, `withdrawPayer` and `distribute` each run
  against crafted mint accounts (plain, Paxos-shaped dormant, live fee, fee
  reverted but still governed by `older`, live hook, non-transferable,
  truncated record) and return 64, 63 or 56 at the gate, or fall through to
  the next check when the mint passes.
- SBF, real Token-2022 program: a mint built with the exact Paxos extension set
  opens, tops up, distributes from OPEN and from SEALED (escrow close with the
  auto-added records), then the issuer schedules a fee and installs a hook and
  each instruction rejects with 64 and no state change, and succeeds again after
  revert; a second run advances the `Clock` epoch through activation, revert
  and hand-over to the zero schedule and checks the gate tracks Token-2022.
- `scripts/mint-extensions.mjs` mirrors the policy and is the operator preflight
  for the server allow-list.
