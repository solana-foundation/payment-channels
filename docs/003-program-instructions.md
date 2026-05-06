# ADR-003: Program Instructions Reference

**Status:** Draft

## Context

Quick reference for every instruction exposed by the payment-channels program: discriminator, input parameters, accounts, and a one-line purpose. For state machine, transition guards, voucher verification, and splits canonicalization, see [ADR-001](./001-payment-channel-state-machine.md).

## Summary

| Disc | Instruction | Caller | Signer | Transition | Purpose |
|---|---|---|---|---|---|
| | | | | | |

## `open` (1)

**Args**

| Name | Type | Description |
|---|---|---|
| | | |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| | | | | |

## `settle` (2)

**Args**

| Name | Type | Description |
|---|---|---|
| | | |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| | | | | |

## `topUp` (3)

**Args**

| Name | Type | Description |
|---|---|---|
| | | |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| | | | | |

## `settleAndFinalize` (4)

**Args**

| Name | Type | Description |
|---|---|---|
| | | |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| | | | | |

## `requestClose` (5)

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| | | | | |

## `finalize` (6)

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| | | | | |

## `distribute` (7)

Permissionless crank. Verifies the committed splits preimage (Blake3) against `Channel.distribution_hash`, then pays `pool = settled − paid_out` to the merchant side: each recipient gets `floor(pool * shareBps[i] / 10000)` and the **payee** gets the implicit remainder `floor(pool * (10000 − Σ shareBps) / 10000)`. From `OPEN`, flooring residual remains in the channel ATA. From `FINALIZED`, the residual is swept to the treasury ATA, the payer receives the unspent `deposit − settled` headroom (gated by `payer_withdrawn_at == 0`), and the escrow ATA + Channel PDA are tombstoned.

**Args**

| Name | Type | Description |
|---|---|---|
| `recipients` | `Vec<DistributionEntry>` | Splits preimage (`count(u32 LE) || [recipient(32) || shareBps(u16 LE)] × count`). Rehashed on-chain; Blake3 digest must equal `Channel.distribution_hash`. |

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| 0 | `channel` | — | yes | Channel PDA. Self-signs CPI transfers; tombstoned on `FINALIZED`. |
| 1 | `payer` | — | yes | Payer SOL account. Writable so escrow / PDA rent can flow back on tombstone. |
| 2 | `channel_token_account` | — | yes | Escrow ATA owned by `channel`. Source for all transfers; closed on tombstone. |
| 3 | `payer_token_account` | — | yes | `ATA(payer, mint, token_program)`. Used **only** by the FINALIZED refund branch. |
| 4 | `payee_token_account` | — | yes | `ATA(payee, mint, token_program)`. Receives `floor(pool * (10000 − Σ shareBps) / 10000)` whenever `pool > 0`. The transfer is a no-op when `Σ shareBps == 10000`; the account is still validated. |
| 5 | `treasury_token_account` | — | yes | `ATA(TREASURY_OWNER, mint, token_program)`. Receives flooring residual only when `distribute` runs from `FINALIZED`. |
| 6 | `mint` | — | — | Token mint bound at `open`. |
| 7 | `token_program` | — | — | SPL Token or Token-2022, must equal the program that owns the mint and ATAs. |
| 8…N | `recipient_token_accounts[i]` | — | yes | `ATA(recipients.entries[i].recipient, mint, token_program)` in the same order as the active preimage entries. |

## `withdrawPayer` (8)

**Accounts**

| # | Name | Signer | Writable | Description |
|---|---|---|---|---|
| | | | | |

## Error Codes

_TBD._

## Appendix

### `VoucherArgs`

| Name | Type | Description |
|---|---|---|
| | | |
