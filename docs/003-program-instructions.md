# ADR-003: Program Instructions Reference

**Status:** Draft

## Context

Quick reference for every instruction exposed by the payment-channels program: discriminator, input parameters, accounts, and a one-line purpose. For state machine, transition guards, voucher verification, and splits canonicalization, see [ADR-001](./001-payment-channel-state-machine.md).

## Summary

| Disc | Instruction | Caller | Signer | Transition | Purpose |
|---|---|---|---|---|---|
| 1 | `open` | payer | payer | `NONEXISTENT → OPEN` | Create the channel PDA, create escrow ATA, transfer the initial deposit, and commit the distribution preimage hash. |
| 2 | `settle` | permissionless | Ed25519 voucher | `OPEN → OPEN` | Advance the cumulative settled watermark from an authorized-signer voucher. |
| 3 | `topUp` | payer | payer | `OPEN → OPEN` | Add escrow and raise the deposit ceiling. |
| 4 | `settleAndSeal` | payee | payee, optional Ed25519 voucher | `OPEN/CLOSING → SEALED` | Optional final settle, then lock the channel for distribution/refund. |
| 5 | `requestClose` | payer | payer | `OPEN → CLOSING` | Start the grace-period close window. |
| 6 | `seal` | permissionless | — | `CLOSING → SEALED` | Seal after the grace period expires. |
| 7 | `distribute` | permissionless | — | `OPEN → OPEN` or `SEALED → DISTRIBUTED` | Pay cumulative floor deltas to recipients/payee; on `SEALED`, refund/sweep and close the escrow immediately (never slot-gated), then deallocate the channel PDA in place if `clock.slot > open_slot + OPEN_SLOT_WINDOW` already holds, else mark it `DISTRIBUTED`. Channel PDA signs token CPIs internally. |
| 8 | `withdrawPayer` | payer | payer | `SEALED → SEALED` | One-shot payer refund of `deposit - settled` without closing the PDA. Channel PDA signs the refund CPI internally. |
| 9 | `reclaim` | permissionless | — | `DISTRIBUTED → gone` | Deallocate a fully-drained `DISTRIBUTED` channel PDA and return all its lamports to `rent_payer`, once `clock.slot > open_slot + OPEN_SLOT_WINDOW`. Batchable. |
| 228 | `emitEvent` | program self-CPI | event authority PDA | — | Internal Anchor-compatible event emission target. |

The **Signer** column lists transaction-level signers where applicable; `Ed25519 voucher` means precompile-verified authorization rather than an account signer. PDA signer seeds used for internal CPIs are called out in the purpose or account descriptions.

> **Account shape strictness.** Every instruction takes an exact account list: handlers destructure fixed-size slices and reject transactions with missing *or extra* accounts. The single exception is `distribute`, which accepts a dynamic tail of recipient token accounts after its 11 fixed accounts. The generated clients enforce the same shapes: the TypeScript parsers reject extra accounts, the Rust builders drop their remaining-accounts helpers, and only `distribute` keeps the dynamic tail (`scripts/enforce-fixed-account-shapes.mjs` tightens the codama output at generation time).

## `open` (1)

Payer-signed initializer. Creates the active channel PDA, creates its escrow ATA, transfers `deposit` from the payer token account, stores the exact Blake3 hash of the distribution preimage, and emits `Opened`. The `authorized_signer` account must be a valid Ed25519 public key, but it does not need to sign `open`. The `payee` account is not curve-checked and may be a program-derived address (PDA) beneficiary.

Both creates are **prefund-tolerant**: lamports already sitting on the channel PDA (the PDA is allocated with `Allocate` + `Assign` after topping up only the rent shortfall) and a pre-existing canonical escrow ATA (idempotent CPI) are accepted. This also means a lamport donation to a previously-closed channel address cannot block a legitimate reopen. Surplus PDA lamports flow to `rent_payer` at close; tokens already on the escrow ATA are swept to treasury at `seal` via the existing residual logic. See [Accounting authority](./001-payment-channel-state-machine.md#accounting-authority).

> **Mint trust model.** `open` does not reject mints with a live freeze authority (or mint authority). A merchant accepting a channel denominated in mint `M` is implicitly accepting that `M`'s freeze authority can freeze the channel's escrow ATA and wedge `topUp`, `distribute`, and `withdrawPayer` until thawed. This is intentional so that mainstream stablecoins (USDC, USDT, PYUSD, …) remain usable; merchants are expected to vet the mint off-chain. See [ADR-001 → Mint trust model](./001-payment-channel-state-machine.md#mint-trust-model).

**Args**

Wire after the discriminator:

```text
salt(u64 LE) || deposit(u64 LE) || grace_period(u32 LE) || open_slot(u64 LE) || count(u32 LE) || entries(count × 34)
```

`entries[i] = recipient(32 bytes) || bps(u16 LE)`. Only active entries are encoded; there is no padding to `MAX_DISTRIBUTION_RECIPIENTS`.

| Name | Type | Description |
|---|---|---|
| `salt` | `u64` | PDA disambiguator for concurrent channels with the same payer/payee/mint/signer tuple. |
| `deposit` | `u64` | Initial escrow amount. Must be non-zero. |
| `grace_period` | `u32` | Seconds that must elapse after `requestClose` before permissionless `seal`. Must be non-zero. |
| `open_slot` | `u64` | Client-supplied per-incarnation epoch; a PDA seed, so it is also a derivation input for the channel address. Validated on-chain: `open_slot ≤ clock.slot` and `clock.slot − open_slot ≤ OPEN_SLOT_WINDOW` (150). A back-dated value shortens the terminal-close delay at the cost of a narrower landing window; the current slot maximizes landing safety. |
| `recipients` | `Vec<DistributionEntry>` | Distribution preimage. Parsed as `count(u32 LE) || entries`; stored only as `blake3(preimage)` in the channel. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | yes | yes | Funds the token deposit and signs the authorization. Must own `payer_token_account`. |
| 1 | `rent_payer` | yes | yes | Funds the PDA + escrow-ATA rent via system CPI; recorded in `Channel.rent_payer` and receives all freed SOL at close. MAY equal `payer`. |
| 2 | `payee` | — | — | Channel payee and implicit-remainder recipient. May be on-curve or a program-derived address (PDA); bound into PDA seeds and channel state. |
| 3 | `mint` | — | — | SPL Token or Token-2022 mint for escrow/payouts. |
| 4 | `authorized_signer` | — | — | Ed25519 voucher signer. Must be a valid Ed25519 public key; bound into PDA seeds and channel state. |
| 5 | `channel` | — | yes | Channel PDA derived from `[b"channel", payer, payee, mint, authorized_signer, salt (u64 LE), open_slot (u64 LE)]`. |
| 6 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`; source of the initial deposit. |
| 7 | `channel_token_account` | — | yes | Escrow ATA `ATA(channel, mint, token_program)` created by this instruction. |
| 8 | `token_program` | — | — | SPL Token or Token-2022 program. |
| 9 | `system_program` | — | — | System program account used by channel creation and ATA CPI. |
| 10 | `rent` | — | — | Rent sysvar currently used to compute channel rent exemption. |
| 11 | `associated_token_program` | — | — | Currently present in the ABI; the Pinocchio ATA CPI helper targets the ATA program by ID. |
| 12 | `event_authority` | — | — | Event authority PDA used for Anchor-compatible self-CPI events. |
| 13 | `self_program` | — | — | This program's ID, used as the self-CPI target for event emission. |

## `settle` (2)

Permissionless crank. Authority is the Ed25519 voucher signed by `Channel.authorized_signer` and verified through the previous instruction in the Instructions sysvar.

**Args**

| Name | Type | Description |
|---|---|---|
| `voucher` | `VoucherArgs` | Signed payload, read from the preceding Ed25519 precompile ix: `magic || channel_id || cumulative_amount || expires_at` (50 bytes). No epoch field — `channel_id` alone binds the incarnation, because `open_slot` is a PDA seed. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` | — | yes | Active channel. `settled` is advanced in place. |
| 1 | `instructions_sysvar` | — | — | Used to read the immediately preceding Ed25519 precompile instruction. |

## `topUp` (3)

Payer-signed deposit increase while the channel is `OPEN`.

**Args**

| Name | Type | Description |
|---|---|---|
| `amount` | `u64` | Additional base-unit amount to transfer into escrow and add to `deposit`. Must be non-zero. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | yes | yes | Original channel payer. |
| 1 | `channel` | — | yes | Active channel whose `deposit` increases. |
| 2 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`, source of top-up tokens. |
| 3 | `channel_token_account` | — | yes | Escrow ATA, destination of top-up tokens. |
| 4 | `mint` | — | — | Mint bound in the channel. |
| 5 | `token_program` | — | — | SPL Token or Token-2022 program. |

## `settleAndSeal` (4)

Payee-signed cooperative close. Optionally applies one final voucher using the same Ed25519 verification path as `settle`, then moves the channel to `SEALED`. A direct transaction requires an on-curve `payee` signer equal to `Channel.payee`; if `payee` is a program-derived address (PDA), the owning program must invoke this instruction via CPI with signer seeds.

**Args**

Current wire after the discriminator is a single byte: `has_voucher(u8)`. The voucher itself never rides in this instruction's data — when applied, it is read from the bundled Ed25519 precompile ix, exactly as in `settle`.

| Name | Type | Description |
|---|---|---|
| `has_voucher` | `u8` | `0` skips voucher verification; any non-zero value applies the voucher carried by the preceding Ed25519 precompile ix. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payee` | yes | — | Must equal channel `payee`; PDA payees require CPI signer seeds from the owning program. |
| 1 | `channel` | — | yes | Channel whose `settled`, `status`, and `closure_started_at` may be updated. |
| 2 | `instructions_sysvar` | — | — | Required by the current ABI; consulted when `has_voucher != 0`. |

## `requestClose` (5)

Payer-signed adversarial-close start.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | yes | — | Must equal channel `payer`. |
| 1 | `channel` | — | yes | Must be `OPEN`; moves to `CLOSING` and stores `closure_started_at = now`. |

## `seal` (6)

Permissionless post-grace crank.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` | — | yes | Must be `CLOSING`; moves to `SEALED` once `now >= closure_started_at + grace_period`. |

## `distribute` (7)

Permissionless crank. Verifies the committed splits preimage (Blake3) against `Channel.distribution_hash`, then pays cumulative floor deltas between `payout_watermark` and `settled` to the merchant side: each recipient gets `floor(settled * bps[i] / 10000) - floor(payout_watermark * bps[i] / 10000)` and the **payee** gets the implicit remainder delta using `10000 - sum(bps)`. From `OPEN`, zero-delta shares are skipped, residual dust remains in escrow for later cumulative deltas, and `payout_watermark` advances to `settled` as the accounted watermark. From `SEALED`, the final cumulative merchant payout runs before the payer receives the unspent `deposit - settled` headroom (gated by `payer_withdrawn_at == 0`); final irreducible residual dust is swept to treasury and the escrow ATA is closed — all immediately, with no slot gate on any token movement. The Channel PDA itself is then fully deallocated in the same instruction (every lamport to `rent_payer`) if `clock.slot > open_slot + OPEN_SLOT_WINDOW` has already passed; otherwise the channel is marked `DISTRIBUTED` — inert to every instruction — and its rent is recovered later by the permissionless `reclaim` (9). On a nonzero share, if the beneficiary's canonical ATA is unusable — missing/uninitialized, frozen, closed/malformed, carrying an unsupported Token-2022 extension, or with a reassigned authority — that share is redirected to the treasury, a `PayoutRedirected` event is emitted, and `payout_watermark` **still advances**, so the beneficiary **permanently forfeits** it (repairing the ATA later does not reclaim it, since future cumulative deltas only cover newly settled amounts). Operators should ensure recipient/payee ATAs exist and are healthy before cranking. Malformed token-account data/TLV and wrong (non-canonical) accounts hard-fail.

**Client transaction format:** at `count == 32`, callers MUST use **version 0 transactions with an address lookup table** indexing recipient ATAs. The instruction uses 11 fixed accounts plus up to 32 recipient ATAs (43 total); legacy transactions cannot fit the static account-key budget (~32 keys including fee payer and program id).

**CPI profile:** SPL Token batches non-zero payouts via inner `Batch` CPIs (up to 8 transfers per invoke when ≥2 transfers are queued). Token-2022 uses one `TransferChecked` CPI per non-zero payout.

**Treasury sweep (SEALED):** `treasury_sweep = escrow_balance_at_entry − sum(queued_payouts)`; the sweep captures bps flooring dust not assigned to recipients or the payee.

**Args**

| Name | Type | Description |
|---|---|---|
| `recipients` | `Vec<DistributionEntry>` | Splits preimage (`count(u32 LE) || [recipient(32) || bps(u16 LE)] × count`). Rehashed on-chain; Blake3 digest must equal `Channel.distribution_hash`. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` | — | yes | Channel PDA. Self-signs CPI transfers; on `SEALED`, deallocated in place (fast path) or marked `DISTRIBUTED` for `reclaim`. |
| 1 | `payer` | — | yes | Payer SOL account; must equal `Channel.payer`. |
| 2 | `rent_payer` | — | yes | Must equal `Channel.rent_payer`; receives the escrow-ATA rent and all channel-PDA lamports at close. Not a signer. |
| 3 | `channel_token_account` | — | yes | Escrow ATA owned by `channel`. Source for all transfers; closed at `SEALED` close. |
| 4 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`. Used **only** by the SEALED refund branch. |
| 5 | `payee_token_account` | — | yes | `ATA(payee, mint, token_program)`. Receives the cumulative floor delta for the implicit `10000 - sum(bps)` remainder share. The transfer is skipped when the delta is zero; the account is still validated. |
| 6 | `treasury_token_account` | — | yes | `ATA(TREASURY_OWNER, mint, token_program)`. Receives final irreducible residual dust when `distribute` runs from `SEALED`. The operator must hold the corresponding private key for `TREASURY_OWNER`, otherwise accumulated residuals are unspendable. |
| 7 | `mint` | — | — | Token mint bound at `open`. |
| 8 | `token_program` | — | — | SPL Token or Token-2022, must equal the program that owns the mint and ATAs. |
| 9 | `event_authority` | — | — | Event authority PDA used for Anchor-compatible self-CPI events; signs the self-CPI that emits `PayoutRedirected` when a poisoned beneficiary share is redirected to treasury. |
| 10 | `self_program` | — | — | This program's ID, used as the self-CPI target for event emission. |
| 11…N | `recipient_token_accounts[i]` | — | yes | `ATA(recipients[i].recipient, mint, token_program)` in the same order as the active preimage entries. |

## `withdrawPayer` (8)

Payer-signed one-shot refund in `SEALED`. Does not close the PDA and is not slot-gated.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | yes | — | Must equal channel `payer`. |
| 1 | `channel` | — | yes | Must be `SEALED`; `payer_withdrawn_at` is stamped. |
| 2 | `channel_token_account` | — | yes | Escrow ATA, source of the refund. |
| 3 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`, destination of `deposit - settled`. |
| 4 | `mint` | — | — | Mint bound in the channel. |
| 5 | `token_program` | — | — | SPL Token or Token-2022 program. |

## `reclaim` (9)

Permissionless crank. Deallocates a fully-drained `DISTRIBUTED` channel PDA — every token leg was already paid and the escrow ATA already closed by the SEALED `distribute`, so the only value left at the address is the PDA's own rent. Requires `clock.slot > open_slot + OPEN_SLOT_WINDOW`; the gate exists solely to keep the address occupied through the epoch window (the address-never-repeats invariant: once the account can be deallocated, its `open_slot` seed is too stale for `open` to ever re-derive the address), so delaying this instruction delays nobody's money. Two writable accounts and no signers: operators SHOULD batch many `reclaim` instructions per sweep transaction. Not needed when `distribute` ran after the window had already elapsed (its fast path deallocates directly).

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` | — | yes | Must be `DISTRIBUTED`. Deallocated; all lamports drained. |
| 1 | `rent_payer` | — | yes | Must equal `Channel.rent_payer`; receives every remaining lamport. |

## `emitEvent` (228)

Internal self-CPI target for Anchor-compatible events. Event instruction data is `EVENT_IX_TAG_LE` (8 bytes) `|| event_discriminator` (8 bytes) `|| borsh_payload`; because `EVENT_IX_TAG_LE[0] == 228`, byte-0 dispatch routes to this handler. Only the event authority PDA may sign. Both emitted events (`Opened`, `PayoutRedirected`) are declared in the committed Codama IDL (`program.events`) together with their 8-byte Anchor discriminators, so IDL-driven indexers can decode them without custom tooling.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `event_authority` | yes | — | PDA derived from `b"event_authority"`. |

## Error Codes

`PaymentChannelsError` is surfaced to clients as `ProgramError::Custom(code)`. Codes are grouped by category and each variant maps 1:1 to a numeric value below. The canonical source is `program/payment_channels/src/errors.rs`; the table below lists all variants for client integrators.

### General channel validation

| Code | Variant | Meaning |
|---|---|---|
| 0 | `NotImplemented` | Reserved sentinel; unused on the current dispatch surface. |
| 1 | `MissingRequiredSignature` | A required transaction signature was not present. |
| 2 | `InvalidChannelStatus` | Channel is not in the `ChannelStatus` the instruction expects. |
| 3 | `InvalidAccountDiscriminator` | Channel account's first byte is not `AccountDiscriminator::Channel`. |
| 4 | `UnsupportedChannelVersion` | Channel `version` byte does not match `CURRENT_CHANNEL_VERSION` (1). |
| 5 | `InvalidChannelPayer` | Provided `payer` account does not equal `Channel.payer`. |
| 6 | `InvalidChannelPayee` | Provided `payee` account does not equal `Channel.payee`. |
| 7 | `InvalidChannelMint` | Provided `mint` account does not equal `Channel.mint`. |
| 8 | `InvalidEventAuthority` | `event_authority` account does not match the program-derived event-authority PDA. |
| 9 | `NotEnoughAccountKeys` | The instruction received fewer accounts than required. |

### Account validation

| Code | Variant | Meaning |
|---|---|---|
| 50 | `ChannelAccountMismatch` | Channel account does not match the PDA derived from the seeds. |
| 51 | `InvalidChannelTokenAccount` | Escrow ATA is not `ATA(channel, mint, token_program)`. |
| 52 | `InvalidChannelTokenExtensions` | Escrow ATA carries a Token-2022 extension outside the allow-list. |
| 53 | `MintAccountMismatch` | Provided mint cannot be parsed for the supplied token program. |
| 54 | `InvalidMintTokenProgram` | Token program is neither SPL Token nor Token-2022. |
| 55 | `MalformedMintTokenAccountData` | Token-2022 mint account base/TLV layout is malformed. |
| 56 | `MalformedMintTokenExtensions` | Token-2022 mint TLV trailer is malformed. |
| 57 | `PayerAccountMismatch` | Payer ATA is not `ATA(payer, token_program, mint)`. |
| 58 | `InvalidPayerTokenAccount` | Payer ATA fails state/owner/mint validation. |
| 59 | `InvalidPayerTokenExtensions` | Payer ATA carries a Token-2022 extension outside the allow-list. |
| 60 | `PayeeAccountMismatch` | Payee ATA is not `ATA(payee, token_program, mint)`. |
| 61 | `InvalidPayeeTokenAccount` | Payee ATA fails state/owner/mint validation. |
| 62 | `InvalidPayeeTokenExtensions` | Payee ATA carries a Token-2022 extension outside the allow-list. |

### General object validation

| Code | Variant | Meaning |
|---|---|---|
| 200 | `DepositMustBeNonZero` | Deposit (`open`) or top-up amount (`topUp`) is zero. |
| 201 | `GracePeriodMustBeNonZero` | `open.grace_period == 0`; channels must have a non-zero close window. |

### Voucher validation

| Code | Variant | Meaning |
|---|---|---|
| 230 | `MissingEd25519Verification` | No Ed25519 precompile instruction at `current_index − 1`, or wrong program id. |
| 231 | `MalformedEd25519Instruction` | Ed25519 precompile data fails the canonical-layout parser (length, padding, offsets, message size, cross-instruction guards). |
| 232 | `VoucherChannelMismatch` | `voucher.channel_id` does not equal the channel PDA address. Because `open_slot` is a PDA seed, this check also covers cross-incarnation replay: a voucher issued for a previous channel at recycled parameters targets a different (and never-again-derivable) address. |
| 233 | `VoucherExpired` | `voucher.expires_at != 0` and `now ≥ voucher.expires_at`. |
| 234 | `VoucherWatermarkNotMonotonic` | `voucher.cumulative_amount ≤ Channel.settled` (must be strictly greater). |
| 235 | `VoucherOverDeposit` | `voucher.cumulative_amount > Channel.deposit`. |
| 236 | `VoucherMessageMismatch` | Reserved (formerly: signed message did not equal a caller-supplied voucher copy; the voucher is now read from the precompile message directly). |
| 237 | `VoucherSignerMismatch` | Ed25519 pubkey does not equal `Channel.authorized_signer`. |
| 238 | `VoucherEpochMismatch` | Reserved, never emitted (formerly: voucher `open_slot` did not equal `Channel.open_slot`; `open_slot` is now a PDA seed, so the `channel_id` binding covers the epoch — see 232). The discriminant is retained so error codes stay stable. |
| 239 | `VoucherBadMagic` | Voucher payload does not start with the `[0x56, 0x01]` magic (tag byte `'V'` + format version). |

### Distribution validation

| Code | Variant | Meaning |
|---|---|---|
| 260 | `InvalidRecipientCount` | Preimage `count` is outside `[0, MAX_DISTRIBUTION_RECIPIENTS]`. |
| 261 | `InvalidSplitConfig` | Per-entry `bps == 0`, `Σ bps > 10_000`, or a recipient equals the channel PDA. |
| 262 | `DistributionPartsOverflow` | Overflow while accumulating `Σ bps` (defensive — bounded by 10_000 in practice). |
| 263 | `DuplicateRecipient` | Distribution preimage contains the same recipient address twice. |
| 264 | `DistributionAmountOverflow` | Overflow inside basis-point share math when computing a recipient's share. |
| 265 | `DistributionPreimageLengthOverflow` | Overflow when computing the expected preimage length from `count`. |

### `open` (instruction 1)

| Code | Variant | Meaning |
|---|---|---|
| 2000 | `ChannelAddressMismatch` | Provided `channel` account address does not match `find_pda(payer, payee, mint, authorized_signer, salt, open_slot)`. |
| 2001 | `PayerPayeeMustDiffer` | `payer` and `payee` accounts are equal. |
| 2002 | `InvalidAuthorizedSigner` | `authorized_signer` is not a valid Ed25519 public key. |
| 2003 | `OpenSlotOutOfWindow` | `open_slot > clock.slot` (future) or `clock.slot − open_slot > OPEN_SLOT_WINDOW` (too stale). |

### `topUp` (instruction 3)

| Code | Variant | Meaning |
|---|---|---|
| 2100 | `TopUpDepositOverflow` | `deposit + amount` would overflow `u64`. |

### `seal` (instruction 6)

| Code | Variant | Meaning |
|---|---|---|
| 2200 | `SealDeadlineOverflow` | `closure_started_at + grace_period` would overflow `i64`. |

### `withdrawPayer` (instruction 8)

| Code | Variant | Meaning |
|---|---|---|
| 2300 | `PayerAlreadyWithdrawn` | `Channel.payer_withdrawn_at != 0`; the one-shot refund has already been claimed. |
| 2301 | `RefundCalculationOverflow` | `deposit − settled` underflowed (defensive — `settled ≤ deposit` invariant). |

### `distribute` (instruction 7)

| Code | Variant | Meaning |
|---|---|---|
| 2400 | `ChannelNotDistributable` | Channel status is neither `OPEN` nor `SEALED`. |
| 2401 | `TreasuryAccountMismatch` | Treasury ATA is not `ATA(TREASURY_OWNER, mint, token_program)`. |
| 2402 | `InvalidTreasuryTokenAccount` | Treasury ATA fails state/owner/mint validation. |
| 2403 | `InvalidTreasuryTokenExtensions` | Treasury ATA carries a Token-2022 extension outside the allow-list. |
| 2404 | `RecipientAccountMismatch` | A recipient ATA is not `ATA(recipient, token_program, mint)`. |
| 2405 | `InvalidRecipientTokenAccount` | A recipient ATA fails state/owner/mint validation. |
| 2406 | `InvalidRecipientTokenExtensions` | A recipient ATA carries a Token-2022 extension outside the allow-list. |
| 2407 | `InvalidDistributionHash` | Blake3 of the revealed preimage does not equal `Channel.distribution_hash`. |
| 2408 | `NothingToDistribute` | `settled == payout_watermark` while channel is `OPEN` (no newly settled watermark to account). |
| 2409 | `RecipientAccountCountMismatch` | Number of recipient ATAs in the account tail does not equal the preimage entry count. |
| 2410 | `DistributePoolOverflow` | `settled - payout_watermark` underflowed (defensive: `payout_watermark <= settled`). |
| 2411 | `DistributeBalanceCalculationOverflow` | Escrow/treasury arithmetic underflow. |
| 2412 | `DistributePayerBalanceOverflow` | Rent-payer lamports `+ delta` would overflow `u64` during the close-time rent transfer. |
| 2413 | `DistributeTransferQueueOverflow` | Transfer queue capacity exceeded (defensive — distribute queues at most 35 payouts). |
| 2414 | `ChannelCloseTooEarly` | `reclaim` attempted at `clock.slot ≤ open_slot + OPEN_SLOT_WINDOW`; retry once the window elapses. Never emitted by `distribute` (its fast path simply defers deallocation to `reclaim`). |

## Appendix

### `VoucherArgs`

50-byte signed payload (offsets `0..2`, `2..34`, `34..42`, `42..50`); the struct bytes ARE the Ed25519 precompile message (canonical single-signature precompile ix: 162 bytes; `message_data_size == 50`).

| Name | Type | Description |
|---|---|---|
| `magic` | `[u8; 2]` | Domain-separation prefix: fixed tag byte `'V'` (`0x56`, constant across all payload versions) + format-version byte (`0x01`). |
| `channel_id` | `Address` | Channel PDA the voucher applies to. Also the incarnation binding: `open_slot` is a PDA seed, so the address is per-incarnation and no separate epoch field is needed. |
| `cumulative_amount` | `u64` | Strictly increasing cumulative watermark. Must be `<= deposit`. |
| `expires_at` | `i64` | Unix timestamp expiry; `0` means no expiry. |

### `DistributionEntry`

| Name | Type | Description |
|---|---|---|
| `recipient` | `Address` | Recipient owner whose ATA appears in the dynamic account tail for `distribute`. |
| `bps` | `u16` | Basis-point share. Active entries must be non-zero and total share must be `<= 10000`. |
