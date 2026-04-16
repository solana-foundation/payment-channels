# ADR-001: Payment Channel State Machine

**Status:** Draft

## Context

This ADR specifies the channel lifecycle, instruction set, and on-chain PDA layout for a Solana payment channel program aligned with [`draft-solana-session-00`](https://github.com/solana-foundation/mpp-specs/blob/a64edb477cfcb5e071e4f73f4227cf329dd1c4b5/specs/methods/solana/draft-solana-session-00.md) from the MPP specification.

## Decision

The program implements **unidirectional payment channels** over SPL Token and Token-2022. Each channel is a PDA holding escrowed tokens; payer-signed off-chain vouchers carry a monotonically increasing cumulative amount that on-chain instructions commit to a `settled` watermark. Actual token movement only occurs at closure, via one of two paths:

- **Happy path — `settleAndFinalize` + `distribute`**: the merchant commits the final voucher (locks the watermark, transitions to `FINALIZED`) and then executes the hash-committed multi-destination payout, refunding `deposit − settled` to the payer in the same `distribute` instruction.
- **Unhappy path — post-grace permissionless escape**: after `requestClose` starts the grace period, if the merchant never submits a voucher via `settleAndFinalize`, anyone may call `finalize` post-grace to freeze the watermark and transition `CLOSING → FINALIZED`. From there `withdraw_payee` (post-grace, permissionless) atomically pays `settled` to `channel.payee` and refunds `deposit − settled` to the payer if `payerWithdrawnAt == 0`, then tombstones the PDA. Payer may also pull their refund early at any point during `FINALIZED` via the standalone `withdraw_payer` ix.

Instructions whose destinations are fully determined by PDA seeds are **permissionless cranks** — anyone can submit the transaction; the authority is encoded in the seeds, the timer, or a preimage, not in the signer.

## Channel State Machine

### Status enum

```rust
#[repr(u8)]
pub enum ChannelStatus {
    Open      = 0,
    Finalized = 1,
    Closing   = 2,
}
```

### Channel PDA

```rust
/// Active channel account. 90 bytes.
#[repr(C)]
pub struct Channel {
    pub deposit:            u64,       // [ 0..8 )  Initial escrow amount
    pub settled:            u64,       // [ 8..16)  Cumulative authorized watermark
    pub paid_out:           u64,       // [16..24)  Cumulative tokens distributed to merchant; paid_out ≤ settled
    pub closure_started_at: i64,       // [24..32)  Unix ts; 0 = not in closure trajectory
    pub payer_withdrawn_at: i64,       // [32..40)  Unix ts; 0 = payer has not withdrawn
    pub distribution_hash:  [u8; 16],  // [40..56)  Blake3-truncated commitment to splits config
    pub payee:              [u8; 32],  // [56..88)  Fallback destination for withdraw_payee
    pub status:             u8,        // [88..89)  ChannelStatus
    pub bump:               u8,        // [89..90)  Canonical PDA bump
}
```

### Voucher

Payer-signed off-chain payload authorizing cumulative spend against a channel. Submitted with each metered HTTP request and committed on-chain via `settle` or `settleAndFinalize`.

```rust
/// Inner voucher payload. Signed bytes are the JCS canonicalization (RFC 8785)
/// of this object serialized as JSON.
pub struct Voucher {
    pub channel_id:        Pubkey,        // JSON: base58 string
    pub cumulative_amount: u64,           // JSON: decimal ASCII string (base units)
    pub expires_at:        Option<i64>,   // JSON: ISO 8601 string when Some, omitted when None
}

/// Wire format. Carried inside the MPP `Authorization: Payment <base64url-JSON>`
/// HTTP header and re-encoded as ix data when the merchant submits on-chain.
pub struct SignedVoucher {
    pub voucher:        Voucher,
    pub signer:         Pubkey,           // JSON: base58 string
    pub signature:      [u8; 64],         // JSON: base58 string
    pub signature_type: SigType,          // always SigType::Ed25519
}

#[repr(u8)]
pub enum SigType {
    Ed25519 = 0,
}
```

**Verification.** Caller bundles an Ed25519 native-program ix in the same transaction; our program reads the verified message bytes via Instructions-sysvar introspection and asserts they match the JCS bytes reconstructed from the `Voucher` fields in our ix data. `signer` MUST equal the channel's `authorized_signer` (or `payer` if no delegate was bound at `open`).

**Replay protection.** `channel_id` (a PDA, hence program- and seed-specific) + monotonic `cumulative_amount > settled` + optional `expires_at`. No explicit nonce.

### FSM

![Channel state machine](./fsm.png)

`CLOSED` is drawn dashed because it is **not** a `ChannelStatus` value — it is a visual convergence point representing "the channel is about to be tombstoned". The transition into it is atomic with the final tombstone realloc; there is no persistent `CLOSED` state.

## Transition Guards

| Instruction | From → To | Guard |
|---|---|---|
| `open` | `NONEXISTENT → OPEN` | PDA does not exist |
| `settle` | `OPEN → OPEN` | `settled < voucher.cumulative ≤ deposit` & voucher fresh† |
| `topUp` | `OPEN → OPEN` | — |
| `settleAndFinalize` | `OPEN → FINALIZED` | merchant signer; voucher optional (if present: `settled ≤ voucher.cumulative ≤ deposit` & voucher fresh†); sets `closureStartedAt = now` |
| `requestClose` | `OPEN → CLOSING` | sets `closureStartedAt = now` |
| `settleAndFinalize` | `CLOSING → FINALIZED` | merchant signer & `now < closureStartedAt + GRACE`; voucher optional (if present: `settled ≤ voucher.cumulative ≤ deposit` & voucher fresh†); resets `closureStartedAt = 0` |
| `finalize` | `CLOSING → FINALIZED` | `now ≥ closureStartedAt + GRACE`; resets `closureStartedAt = 0` |
| `distribute` | `OPEN → OPEN` | hash(preimage) == distributionHash & `settled > paid_out` |
| `distribute` | `FINALIZED → CLOSED` | hash(preimage) == distributionHash |
| `withdraw_payer` | `FINALIZED → FINALIZED` | `payerWithdrawnAt == 0` |
| `withdraw_payee` | `FINALIZED → CLOSED` | `now ≥ closureStartedAt + GRACE` |

† **voucher fresh** = `voucher.expires_at == None` OR `now < voucher.expires_at`. Expired vouchers MUST be rejected to prevent merchants from settling stale authorizations after the payer's TTL has passed.

## Instructions

| Instruction | Description                                                                                                                         | Caller | Signers |
|---|-------------------------------------------------------------------------------------------------------------------------------------|---|---|
| `open` | Creates the channel PDA, locks the deposit, and commits to the distribution hash.                                                   | anyone | payer |
| `settle` | Advances the on-chain `settled` watermark against a payer-signed voucher. `OPEN` only.                                              | merchant | merchant |
| `topUp` | Adds to `deposit`. `OPEN` only — disallowed once `closureStartedAt > 0`.                                                            | payer | payer |
| `settleAndFinalize` | Optionally commits a final voucher, locks the watermark, and transitions to `FINALIZED`. Sets `closureStartedAt = now` when called from `OPEN`. From `CLOSING`, callable only while the grace period is open. | merchant | merchant |
| `requestClose` | Starts the grace period by setting `closureStartedAt = now`.                                                                        | payer | payer |
| `finalize` | Freezes the current watermark and transitions `CLOSING → FINALIZED`. Permissionless, voucher-free; callable only after the grace period has expired. | anyone | any |
| `distribute` | Verifies the distribution-hash preimage and pays `settled − paid_out` to merchant splits per the preimage; updates `paid_out`. From `OPEN`: channel stays open (mid-session settlement). From `FINALIZED`: also refunds `deposit − settled` to the payer when `payerWithdrawnAt == 0` and tombstones the PDA. | anyone | any |
| `withdraw_payer` | Refunds `deposit − settled` to the payer and sets `payerWithdrawnAt = now`. Callable any time the channel is `FINALIZED`. Does not tombstone. | payer | payer |
| `withdraw_payee` | Post-grace only. Sends `settled − paid_out` to the stored `channel.payee` and, if `payerWithdrawnAt == 0`, atomically refunds `deposit − settled` to the payer in the same ix. Tombstones the PDA. Rent refunded to the payer. | anyone | any |

**Signers** lists only transaction-level signers (verified by the Solana runtime). Voucher signatures (payer-signed off-chain, verified inside the program via Ed25519 syscall over ix data) are **not** transaction-level signers. `any` means no specific account signature is required — the transaction needs only a fee payer.

**All ixs are fee-sponsorable.** The tx fee payer may be any account (typically the merchant's server, per the MPP HTTP flow) and is distinct from the authority signer; sponsor signatures MUST NOT satisfy authority checks.


## TBD

### Replace tombstone with `init_id` generation marker

Instead of realloc-to-8-bytes + `ClosedChannel` discriminator, fully close the PDA at end-of-life (all rent returned) and add an `init_id: i64` field to `Channel`, set from `Clock::slot` at `open`. Every voucher and preimage binds `channelId = (pda_address, init_id)`; re-opening the same PDA seeds produces a new `init_id`, which cryptographically invalidates any pre-close voucher against the old generation.

This technique allows absolute rent reimbursement on close.

### Rejected Mint Extensions

`open` MUST read the mint and reject the channel if any of the following Token-2022 extensions is present (or active, where applicable). Each one would either trap funds, distort the deposit/settled accounting, or undermine the program's custody guarantee:

| Extension | Reason |
|---|---|
| `NonTransferable` | No transfer from escrow could ever succeed |
| `PermanentDelegate` | Delegate can move escrow arbitrarily; breaks custody |
| `DefaultAccountState = Frozen` | Destination ATAs would be born frozen, blocking payouts |
| `ConfidentialTransferMint` (required) | Program does not produce confidential-transfer proofs |
| `TransferFeeConfig` | Withheld fees on incoming and outgoing transfers desynchronize `deposit`/`settled` from real escrow balance |
| `TransferHook` | Hook program can revert any transfer based on arbitrary logic; funds could be permanently trapped |
| `InterestBearing` | Real balance accrues over time; nominal `deposit`/`settled` math becomes incorrect |
| `ScaledUiAmountConfig` | Display-vs-raw amount divergence breaks accounting |

In-ix mitigations still apply for compatible mints — destination ATAs are created via `create_idempotent` if missing, and `MemoTransfer` mints get an `spl-memo` CPI in the same tx.
