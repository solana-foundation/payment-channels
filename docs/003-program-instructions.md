# ADR-003: Program Instructions Reference

**Status:** Draft

## Context

Quick reference for every instruction exposed by the payment-channels program: discriminator, input parameters, accounts, and a one-line purpose. For state machine, transition guards, voucher verification, and splits canonicalization, see [ADR-001](./001-payment-channel-state-machine.md).

## Summary

| Disc | Instruction | Caller | Signer | Transition | Purpose |
|---|---|---|---|---|---|
| 1 | `open` | payer | payer | `NONEXISTENT → OPEN` | Create the channel PDA, create escrow ATA, transfer the initial deposit, and commit the distribution preimage hash. |
| 2 | `settle` | permissionless | Ed25519 voucher | `OPEN → OPEN` | Advance the cumulative settled watermark from a payer-signed voucher. |
| 3 | `topUp` | payer | payer | `OPEN → OPEN` | Add escrow and raise the deposit ceiling. |
| 4 | `settleAndFinalize` | merchant/payee | merchant/payee, optional Ed25519 voucher | `OPEN/CLOSING → FINALIZED` | Optional final settle, then lock the channel for distribution/refund. |
| 5 | `requestClose` | payer | payer | `OPEN → CLOSING` | Start the grace-period close window. |
| 6 | `finalize` | permissionless | — | `CLOSING → FINALIZED` | Finalize after the grace period expires. |
| 7 | `distribute` | permissionless | — | `OPEN → OPEN` or `FINALIZED → CLOSED` | Pay the newly settled pool to recipients/payee; on `FINALIZED`, refund/sweep/close/tombstone. Channel PDA signs token CPIs internally. |
| 8 | `withdrawPayer` | payer | payer | `FINALIZED → FINALIZED` | One-shot payer refund of `deposit - settled` without tombstoning. Channel PDA signs the refund CPI internally. |
| 228 | `emitEvent` | program self-CPI | event authority PDA | — | Internal Anchor-compatible event emission target. |

The **Signer** column lists transaction-level signers where applicable; `Ed25519 voucher` means precompile-verified authorization rather than an account signer. PDA signer seeds used for internal CPIs are called out in the purpose or account descriptions.

## `open` (1)

Payer-signed initializer. Creates the active channel PDA, creates its escrow ATA, transfers `deposit` from the payer token account, stores the exact Blake3 hash of the distribution preimage, and emits `Opened`.

> **Mint trust model.** `open` does not reject mints with a live freeze authority (or mint authority). A merchant accepting a channel denominated in mint `M` is implicitly accepting that `M`'s freeze authority can freeze the channel's escrow ATA and wedge `topUp`, `distribute`, and `withdrawPayer` until thawed. This is intentional so that mainstream stablecoins (USDC, USDT, PYUSD, …) remain usable; merchants are expected to vet the mint off-chain. See [ADR-001 → Mint trust model](./001-payment-channel-state-machine.md#mint-trust-model).

**Args**

Wire after the discriminator:

```text
salt(u64 LE) || deposit(u64 LE) || grace_period(u32 LE) || count(u32 LE) || entries(count × 34)
```

`entries[i] = recipient(32 bytes) || bps(u16 LE)`. Only active entries are encoded; there is no padding to `MAX_DISTRIBUTION_RECIPIENTS`.

| Name | Type | Description |
|---|---|---|
| `salt` | `u64` | PDA disambiguator for concurrent channels with the same payer/payee/mint/signer tuple. |
| `deposit` | `u64` | Initial escrow amount. Must be non-zero. |
| `grace_period` | `u32` | Seconds that must elapse after `requestClose` before permissionless `finalize`. Must be non-zero. |
| `recipients` | `Vec<DistributionEntry>` | Distribution preimage. Parsed as `count(u32 LE) || entries`; stored only as `blake3(preimage)` in the channel. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | yes | yes | Funds rent, deposit, and escrow ATA creation. Must own `payer_token_account`. |
| 1 | `payee` | — | — | Channel payee and implicit-remainder recipient. Bound into PDA seeds and channel state. |
| 2 | `mint` | — | — | SPL Token or Token-2022 mint for escrow/payouts. |
| 3 | `authorized_signer` | — | — | Ed25519 voucher signer. Bound into PDA seeds and channel state. |
| 4 | `channel` | — | yes | Channel PDA derived from `[b"channel", payer, payee, mint, authorized_signer, salt]`. |
| 5 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`; source of the initial deposit. |
| 6 | `channel_token_account` | — | yes | Escrow ATA `ATA(channel, mint, token_program)` created by this instruction. |
| 7 | `token_program` | — | — | SPL Token or Token-2022 program. |
| 8 | `system_program` | — | — | System program account used by channel creation and ATA CPI. |
| 9 | `rent` | — | — | Rent sysvar currently used to compute channel rent exemption. |
| 10 | `associated_token_program` | — | — | Currently present in the ABI; the Pinocchio ATA CPI helper targets the ATA program by ID. |
| 11 | `event_authority` | — | — | Event authority PDA used for Anchor-compatible self-CPI events. |
| 12 | `self_program` | — | — | This program's ID, used as the self-CPI target for event emission. |

## `settle` (2)

Permissionless crank. Authority is the payer-signed Ed25519 voucher verified through the previous instruction in the Instructions sysvar.

**Args**

| Name | Type | Description |
|---|---|---|
| `voucher` | `VoucherArgs` | Signed payload: `channel_id || cumulative_amount || expires_at`. |

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

## `settleAndFinalize` (4)

Merchant/payee-signed cooperative close. Optionally applies one final voucher using the same Ed25519 verification path as `settle`, then moves the channel to `FINALIZED`.

**Args**

Current wire after the discriminator is fixed-size: `voucher(48) || has_voucher(u8)`.

| Name | Type | Description |
|---|---|---|
| `voucher` | `VoucherArgs` | Final voucher payload. Ignored when `has_voucher == 0`. |
| `has_voucher` | `u8` | `0` skips voucher verification; any non-zero value currently applies `voucher`. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `merchant` | yes | — | Must equal channel `payee`. |
| 1 | `channel` | — | yes | Channel whose `settled`, `status`, and `closure_started_at` may be updated. |
| 2 | `instructions_sysvar` | — | — | Required by the current ABI; consulted when `has_voucher != 0`. |

## `requestClose` (5)

Payer-signed adversarial-close start.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | yes | — | Must equal channel `payer`. |
| 1 | `channel` | — | yes | Must be `OPEN`; moves to `CLOSING` and stores `closure_started_at = now`. |

## `finalize` (6)

Permissionless post-grace crank.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` | — | yes | Must be `CLOSING`; moves to `FINALIZED` once `now >= closure_started_at + grace_period`. |

## `distribute` (7)

Permissionless crank. Verifies the committed splits preimage (Blake3) against `Channel.distribution_hash`, then pays `pool = settled − paid_out` to the merchant side: each recipient gets `floor(pool * bps[i] / 10000)` and the **payee** gets the implicit remainder `floor(pool * (10000 − Σ bps) / 10000)`. From `OPEN`, flooring residual remains in the channel ATA. From `FINALIZED`, the residual is swept to the treasury ATA, the payer receives the unspent `deposit − settled` headroom (gated by `payer_withdrawn_at == 0`), and the escrow ATA + Channel PDA are tombstoned.

**Args**

| Name | Type | Description |
|---|---|---|
| `recipients` | `Vec<DistributionEntry>` | Splits preimage (`count(u32 LE) || [recipient(32) || bps(u16 LE)] × count`). Rehashed on-chain; Blake3 digest must equal `Channel.distribution_hash`. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` | — | yes | Channel PDA. Self-signs CPI transfers; tombstoned on `FINALIZED`. |
| 1 | `payer` | — | yes | Payer SOL account. Writable so escrow / PDA rent can flow back on tombstone. |
| 2 | `channel_token_account` | — | yes | Escrow ATA owned by `channel`. Source for all transfers; closed on tombstone. |
| 3 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`. Used **only** by the FINALIZED refund branch. |
| 4 | `payee_token_account` | — | yes | `ATA(payee, mint, token_program)`. Receives `floor(pool * (10000 − Σ bps) / 10000)` whenever `pool > 0`. The transfer is a no-op when `Σ bps == 10000`; the account is still validated. |
| 5 | `treasury_token_account` | — | yes | `ATA(TREASURY_OWNER, mint, token_program)`. Receives flooring residual only when `distribute` runs from `FINALIZED`. |
| 6 | `mint` | — | — | Token mint bound at `open`. |
| 7 | `token_program` | — | — | SPL Token or Token-2022, must equal the program that owns the mint and ATAs. |
| 8…N | `recipient_token_accounts[i]` | — | yes | `ATA(recipients[i].recipient, mint, token_program)` in the same order as the active preimage entries. |

## `withdrawPayer` (8)

Payer-signed one-shot refund in `FINALIZED`. Does not tombstone the PDA.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | yes | — | Must equal channel `payer`. |
| 1 | `channel` | — | yes | Must be `FINALIZED`; `payer_withdrawn_at` is stamped. |
| 2 | `channel_token_account` | — | yes | Escrow ATA, source of the refund. |
| 3 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`, destination of `deposit - settled`. |
| 4 | `mint` | — | — | Mint bound in the channel. |
| 5 | `token_program` | — | — | SPL Token or Token-2022 program. |

## `emitEvent` (228)

Internal self-CPI target for Anchor-compatible events. Event instruction data is `EVENT_IX_TAG_LE` (8 bytes) `|| event_discriminator` (8 bytes) `|| borsh_payload`; because `EVENT_IX_TAG_LE[0] == 228`, byte-0 dispatch routes to this handler. Only the event authority PDA may sign.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `event_authority` | yes | — | PDA derived from `b"event_authority"`. |

## Error Codes

`PaymentChannelsError` is surfaced to clients as `ProgramError::Custom(code)`. Codes are grouped by category and each variant maps 1:1 to a numeric value below. The canonical source is `program/payment_channels/src/errors.rs`; this table mirrors it for client integrators.

### General channel validation

| Code | Variant | Meaning |
|---|---|---|
| 0 | `NotImplemented` | Reserved sentinel; unused on the current dispatch surface. |
| 1 | `MissingRequiredSignature` | A required transaction signature was not present. |
| 2 | `InvalidChannelStatus` | Channel is not in the `ChannelStatus` the instruction expects. |
| 3 | `InvalidAccountDiscriminator` | Channel account's first byte is not `AccountDiscriminator::Channel`. |
| 4 | `UnsupportedChannelVersion` | Channel `version` byte does not match `CURRENT_CHANNEL_VERSION`. |
| 5 | `InvalidChannelPayer` | Provided `payer` account does not equal `Channel.payer`. |
| 6 | `InvalidChannelPayee` | Provided merchant/payee account does not equal `Channel.payee`. |
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
| 232 | `VoucherChannelMismatch` | `voucher.channel_id` does not equal the channel PDA address. |
| 233 | `VoucherExpired` | `voucher.expires_at != 0` and `now ≥ voucher.expires_at`. |
| 234 | `VoucherWatermarkNotMonotonic` | `voucher.cumulative_amount ≤ Channel.settled` (must be strictly greater). |
| 235 | `VoucherOverDeposit` | `voucher.cumulative_amount > Channel.deposit`. |
| 236 | `VoucherMessageMismatch` | Ed25519-signed message bytes do not equal the voucher payload. |
| 237 | `VoucherSignerMismatch` | Ed25519 pubkey does not equal `Channel.authorized_signer`. |

### Distribution validation

| Code | Variant | Meaning |
|---|---|---|
| 260 | `InvalidRecipientCount` | Preimage `count` is outside `[0, MAX_DISTRIBUTION_RECIPIENTS]`. |
| 261 | `InvalidSplitConfig` | Per-entry `bps == 0`, `Σ bps > 10_000`, or a recipient equals the channel PDA. |
| 262 | `DistributionPartsOverflow` | Overflow while accumulating `Σ bps` (defensive — bounded by 10_000 in practice). |
| 263 | `DuplicateRecipient` | Distribution preimage contains the same recipient address twice. |
| 264 | `DistributionAmountOverflow` | Overflow inside `floor_bps_share` when computing a recipient's share. |
| 265 | `DistributionPreimageLengthOverflow` | Overflow when computing the expected preimage length from `count`. |

### `open` (instruction 1)

| Code | Variant | Meaning |
|---|---|---|
| 2000 | `ChannelAddressMismatch` | Provided `channel` account address does not match `find_pda(payer, payee, mint, authorized_signer, salt)`. |
| 2001 | `PayerPayeeMustDiffer` | `payer` and `payee` accounts are equal. |

### `topUp` (instruction 3)

| Code | Variant | Meaning |
|---|---|---|
| 2100 | `TopUpDepositOverflow` | `deposit + amount` would overflow `u64`. |

### `finalize` (instruction 6)

| Code | Variant | Meaning |
|---|---|---|
| 2200 | `FinalizeDeadlineOverflow` | `closure_started_at + grace_period` would overflow `i64`. |

### `withdrawPayer` (instruction 8)

| Code | Variant | Meaning |
|---|---|---|
| 2300 | `PayerAlreadyWithdrawn` | `Channel.payer_withdrawn_at != 0`; the one-shot refund has already been claimed. |
| 2301 | `RefundCalculationOverflow` | `deposit − settled` underflowed (defensive — `settled ≤ deposit` invariant). |

### `distribute` (instruction 7)

| Code | Variant | Meaning |
|---|---|---|
| 2400 | `ChannelNotDistributable` | Channel status is neither `OPEN` nor `FINALIZED`. |
| 2401 | `TreasuryAccountMismatch` | Treasury ATA is not `ATA(TREASURY_OWNER, mint, token_program)`. |
| 2402 | `InvalidTreasuryTokenAccount` | Treasury ATA fails state/owner/mint validation. |
| 2403 | `InvalidTreasuryTokenExtensions` | Treasury ATA carries a Token-2022 extension outside the allow-list. |
| 2404 | `RecipientAccountMismatch` | A recipient ATA is not `ATA(recipient, token_program, mint)`. |
| 2405 | `InvalidRecipientTokenAccount` | A recipient ATA fails state/owner/mint validation. |
| 2406 | `InvalidRecipientTokenExtensions` | A recipient ATA carries a Token-2022 extension outside the allow-list. |
| 2407 | `InvalidDistributionHash` | Blake3 of the revealed preimage does not equal `Channel.distribution_hash`. |
| 2408 | `NothingToDistribute` | `pool == 0` while channel is `OPEN` (no newly settled funds). |
| 2409 | `RecipientAccountCountMismatch` | Number of recipient ATAs in the account tail does not equal the preimage entry count. |
| 2410 | `DistributePoolOverflow` | `settled − paid_out` underflowed (defensive — `paid_out ≤ settled` invariant). |
| 2411 | `DistributeBalanceCalculationOverflow` | `current_lamports − new_min` underflowed during tombstone rent rebalance. |
| 2412 | `DistributePayerBalanceOverflow` | Payer lamports `+ delta` would overflow `u64` during tombstone rent refund. |

## Appendix

### `VoucherArgs`

| Name | Type | Description |
|---|---|---|
| `channel_id` | `Address` | Channel PDA the voucher applies to. |
| `cumulative_amount` | `u64` | Strictly increasing cumulative watermark. Must be `<= deposit`. |
| `expires_at` | `i64` | Unix timestamp expiry; `0` means no expiry. |

### `DistributionEntry`

| Name | Type | Description |
|---|---|---|
| `recipient` | `Address` | Recipient owner whose ATA appears in the dynamic account tail for `distribute`. |
| `bps` | `u16` | Basis-point share. Active entries must be non-zero and total share must be `<= 10000`. |
