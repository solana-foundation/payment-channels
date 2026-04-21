# ADR-003: Program Instructions Reference

**Status:** Draft

## Context

Quick reference for every instruction exposed by the payment-channels program: discriminator, input parameters, accounts, and a one-line purpose. For state machine, transition guards, voucher verification, and splits canonicalization, see [ADR-001](./001-payment-channel-state-machine.md).

## Summary

| Disc | Instruction | Caller | Signer | Transition | Purpose |
|---|---|---|---|---|---|
| 1 | `open` | anyone | payer | `NONEXISTENT → OPEN` | Create channel PDA, lock deposit, commit distribution hash |
| 2 | `settle` | merchant | merchant | `OPEN → OPEN` | Advance `settled` watermark against a payer-signed voucher |
| 3 | `topUp` | payer | payer | `OPEN → OPEN` | Extend `deposit` (disallowed after `requestClose`) |
| 4 | `settleAndFinalize` | merchant | merchant | `OPEN`/`CLOSING → FINALIZED` | Cooperative close; optional final voucher |
| 5 | `requestClose` | payer | payer | `OPEN → CLOSING` | Start grace period |
| 6 | `finalize` | anyone | any | `CLOSING → FINALIZED` | Post-grace permissionless freeze |
| 7 | `distribute` | anyone | any | `OPEN → OPEN` / `FINALIZED → CLOSED` | Pay splits; from `FINALIZED` also refund payer and tombstone |
| 8 | `withdrawPayer` | payer | payer | `FINALIZED → FINALIZED` | One-shot refund of `deposit − settled` |

All instructions are fee-sponsorable, the transaction fee payer is distinct from the authority signer above. `any` means no specific program-level signer is required.

Discriminator `228` (`emit_event`) is an internal self-CPI target, not part of the public interface.

## `open` (1)

Create the `Channel` PDA, pull `deposit` into escrow, commit the distribution hash.

**Args**

| Name | Type | Description |
|---|---|---|
| `salt` | `u64` | PDA disambiguator (seed-only, not stored) |
| `deposit` | `u64` | Initial escrow amount; ceiling on `settled` until `topUp` |
| `grace_period` | `u32` | `CLOSING → FINALIZED` unlock delay (seconds) |
| `distribution_hash` | `[u8; 32]` | Commitment to the `distribute` splits preimage |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | ✓ | ✓ | Funds deposit + PDA rent, bound to `Channel.payer` |
| 1 | `payee` |  |  | Bound to `Channel.payee` |
| 2 | `mint` |  |  | Token mint |
| 3 | `authorized_signer` |  |  | Bound to `Channel.authorized_signer` (voucher author) |
| 4 | `channel` |  | ✓ | Channel PDA to allocate |
| 5 | `payer_token_account` |  | ✓ | Source for the deposit transfer |
| 6 | `channel_token_account` |  | ✓ | Escrow ATA owned by `channel` |
| 7 | `token_program` |  |  | SPL Token / Token-2022 |
| 8 | `system_program` |  |  | System program |
| 9 | `rent` |  |  | Rent sysvar |
| 10 | `event_authority` |  |  | Self-CPI signer PDA for event emission |
| 11 | `self_program` |  |  | This program (self-CPI target) |
| 12 | `associated_token_program` |  |  | ATA program (for `create_idempotent`) |

## `settle` (2)

Advance `Channel.settled` against a payer-signed voucher. No token movement.

**Args**

| Name | Type | Description |
|---|---|---|
| `voucher` | [`VoucherArgs`](#voucherargs) | Payer-signed authorization |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `merchant` | ✓ |  | Merchant submitter |
| 1 | `channel` |  | ✓ | `settled` advanced in place |
| 2 | `instructions_sysvar` |  |  | Locates the bundled Ed25519 ix for voucher verification |

## `topUp` (3)

Extend `Channel.deposit` by `amount`.

**Args**

| Name | Type | Description |
|---|---|---|
| `amount` | `u64` | Base units to pull from payer into escrow |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | ✓ | ✓ | Must equal `Channel.payer` |
| 1 | `channel` |  | ✓ | `deposit` grows by `amount` |
| 2 | `payer_token_account` |  | ✓ | Source |
| 3 | `channel_token_account` |  | ✓ | Escrow ATA |
| 4 | `mint` |  |  | Token mint |
| 5 | `token_program` |  |  | SPL Token / Token-2022 |

## `settleAndFinalize` (4)

Cooperative close; optionally applies a final voucher then moves the channel to `FINALIZED`.

**Args**

| Name | Type | Description |
|---|---|---|
| `voucher` | [`VoucherArgs`](#voucherargs) | Final voucher; consumed only when `has_voucher == 1` |
| `has_voucher` | `u8` | Option tag: `0` skips, `1` applies `voucher` first |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `merchant` | ✓ |  | Merchant submitter |
| 1 | `channel` |  | ✓ | `settled`, `status`, `closure_started_at` all written |
| 2 | `instructions_sysvar` |  |  | Consulted only when `has_voucher == 1` |

## `requestClose` (5)

Start the grace period: `status → CLOSING`, `closure_started_at → now`. No args.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | ✓ |  | Must equal `Channel.payer` |
| 1 | `channel` |  | ✓ | Transitioned to `CLOSING` |

## `finalize` (6)

Permissionless post-grace freeze: `CLOSING → FINALIZED`, `closure_started_at → 0`. No args.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` |  | ✓ | Transitioned to `FINALIZED` |

## `distribute` (7)

| `distribute` | Re-supply the splits preimage, hash-check against `Channel.distribution_hash`, pay `settled - paid_out` to the split recipients (giving any rounding dust to the final recipient). From `FINALIZED` also refunds `deposit - settled` to the payer (if not already withdrawn) and tombstones the PDA.

**Args**

| Name | Type | Description |
|---|---|---|
| `preimage_len` | `u16` | Active byte count of `preimage` |
| `preimage` | `&[u8]` | Variable-length splits blob; hashed and compared to `distribution_hash` |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` |  | ✓ | `paid_out` grows, tombstoned from `FINALIZED` |
| 1 | `channel_token_account` |  | ✓ | Escrow source |
| 2 | `payer_token_account` |  | ✓ | Refund destination (used only from `FINALIZED`) |
| 3 | `mint` |  |  | Token mint |
| 4 | `token_program` |  |  | SPL Token / Token-2022 |
| 5+ | `recipient_token_accounts` |  | ✓ | Remaining accounts: ATAs for each recipient in the preimage |

## `withdrawPayer` (8)

Refund `deposit − settled` to the payer and stamp `payer_withdrawn_at`. Does not tombstone. No args.

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `payer` | ✓ |  | Must equal `Channel.payer` |
| 1 | `channel` |  | ✓ | `payer_withdrawn_at` stamped |
| 2 | `channel_token_account` |  | ✓ | Escrow source |
| 3 | `payer_token_account` |  | ✓ | Refund destination |
| 4 | `mint` |  |  | Token mint |
| 5 | `token_program` |  |  | SPL Token / Token-2022 |

## Error Codes

_TBD._

## Appendix

### `VoucherArgs`

Shared input for `settle` and `settleAndFinalize`. Signature verification is offloaded to a caller-bundled Ed25519 native-program ix; see [ADR-001](./001-payment-channel-state-machine.md#voucher).

| Name | Type | Description |
|---|---|---|
| `cumulative_amount` | `u64` | Monotonic watermark; `settled < cumulative_amount ≤ deposit` |
| `expires_at` | `i64` | Unix seconds TTL; `0` = no expiry |
| `channel_id` | `Address` | Replay scope; must equal the `Channel` PDA |
| `signer` | `Address` | Voucher author; must equal `Channel.authorized_signer` |
| `signature` | `[u8; 64]` | Ed25519 signature over Borsh-serialized payload |
