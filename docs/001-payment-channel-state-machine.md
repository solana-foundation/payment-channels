# ADR-001: Payment Channel State Machine

**Status:** Draft

## Context

This ADR specifies the channel lifecycle, instruction set, and on-chain PDA layout for a Solana payment channel program aligned with [`draft-solana-session-00`](https://github.com/solana-foundation/mpp-specs/blob/a64edb477cfcb5e071e4f73f4227cf329dd1c4b5/specs/methods/solana/draft-solana-session-00.md) from the MPP specification.

## Decision

The program implements unidirectional payment channels. Channels are PDAs holding escrowed tokens. Payer-signed off-chain vouchers carry a cumulative amount committed to a `settled` watermark. The split config (a list of `(recipient, shareBps)` with `0 < sum(shareBps) < 10000`) is passed to `open`. The program stores the 32-byte Blake3 digest in `Channel.distribution_hash`. Splits are recoverable from the `open` instruction data. Token movement occurs at closure via two paths:

- **Happy path (`settleAndFinalize` + `distribute`)**: Merchant commits the final voucher (transitions to `FINALIZED`) and runs `distribute` with the splits preimage. The program verifies the Blake3 hash, pays `settled - paid_out` proportionally across recipients, pays the payer's implicit remainder share, sends rounding residual dust to the treasury ATA, refunds `deposit - settled` to the payer, and tombstones the PDA. These instructions SHOULD be bundled.
- **Unhappy path (post-grace permissionless crank)**: If the merchant fails to submit a voucher after `requestClose` starts the grace period, anyone can call `finalize` post-grace to transition to `FINALIZED`. Anyone can then call `distribute` using the publicly recoverable splits preimage. The payer can also pull their refund early during `FINALIZED` via `withdraw_payer`.

Instructions determined by on-chain state are permissionless cranks. Authority is encoded in the channel state, not the signer.

## Channel State Machine

### Status enum

```rust
#[repr(u8)]
pub enum ChannelStatus {
    Open          = 0,
    Finalized     = 1,
    Closing       = 2,
}
```

Zero-initialized accounts are rejected by `AccountDiscriminator::Channel` before
the status byte is interpreted.

### Account discriminator

```rust
#[repr(u8)]
pub enum AccountDiscriminator {
    Channel = 1,                    // starts at 1 so zero-init accounts fail load
    // ClosedChannel = 2,           // reserved for tombstone shape per TBD
}
```

### Channel PDA

```rust
/// Active channel account. 208 bytes.
#[repr(C, packed)]
pub struct Channel {
    pub discriminator:      u8,       // [  0..1  )
    pub version:            u8,       // [  1..2  )
    pub bump:               u8,       // [  2..3  )  canonical bump
    pub status:             u8,       // [  3..4  )
    pub deposit:            u64,      // [  4..12 )  escrow amount (mutated by `topUp`)
    pub settled:            u64,      // [ 12..20 )  cumulative authorized watermark
    pub paid_out:           u64,      // [ 20..28 )  paid_out ≤ settled
    pub closure_started_at: i64,      // [ 28..36 )  unix ts; set by `requestClose`, gates `finalize`
    pub payer_withdrawn_at: i64,      // [ 36..44 )  unix ts; 0 = not yet withdrawn
    pub grace_period:       u32,      // [ 44..48 )  seconds; set at `open`
    pub distribution_hash:  [u8; 32], // [ 48..80 )  Blake3 digest of the canonical splits preimage, computed on-chain at `open`
    pub payer:              Address,  // [ 80..112)  refund destination + payer-authority signer
    pub payee:              Address,  // [112..144)  PDA seed binding only (not otherwise consumed)
    pub authorized_signer:  Address,  // [144..176)  voucher signer; equals `payer` when no delegate bound
    pub mint:               Address,  // [176..208)
}
```

### PDA derivation

```text
seeds = [ b"channel", payer, payee, mint, authorized_signer, salt.to_le_bytes() ]
```

- `payer`, `payee`, `mint`, `authorized_signer`: Stored in the struct after `open`.
- `salt: u64`: Disambiguator for concurrent channels. Not stored on-chain.
- `bump`: Canonical bump stored in the struct.

Seeds bind all identity parameters, allowing PDA re-derivation for account verification.

### Voucher

Payer-signed off-chain payload authorizing cumulative spend. Committed on-chain via `settle` or `settleAndFinalize`.

```rust
/// Inner voucher payload. Signed bytes are the Borsh serialization
/// of this struct.
pub struct Voucher {
    pub channel_id:        Pubkey,        // JSON: base58 string
    pub cumulative_amount: u64,           // JSON: decimal ASCII string (base units)
    pub expires_at:        i64,           // JSON: ISO 8601 string when != 0, omitted when 0
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

**Verification.** Caller bundles an Ed25519 native-program ix in the same transaction; our program reads the verified message bytes via Instructions-sysvar introspection and asserts they match the Borsh-serialized bytes reconstructed from the `Voucher` fields in our ix data. `signer` MUST equal the channel's `authorized_signer` (or `payer` if no delegate was bound at `open`).

**Replay protection.** `channel_id` (a PDA, hence program- and seed-specific) + monotonic `cumulative_amount > settled` + optional `expires_at`. No explicit nonce.

### FSM

![Channel state machine](./fsm.png)

`CLOSED` is a visual convergence point, not a `ChannelStatus` value. The transition is atomic with the tombstone realloc.

## Transition Guards

| Instruction | From → To | Guard |
|---|---|---|
| `open` | `NONEXISTENT → OPEN` | PDA does not exist; `1 ≤ num_splits ≤ MAX_DISTRIBUTION_RECIPIENTS`; `shareBps[i] > 0 ∀ i ∈ [0, num_splits)`; `0 < Σ shareBps[0..num_splits] < 10000` |
| `settle` | `OPEN → OPEN` | `settled < voucher.cumulative ≤ deposit` & voucher fresh† |
| `topUp` | `OPEN → OPEN` | `closureStartedAt == 0` |
| `settleAndFinalize` | `OPEN → FINALIZED` | merchant signer; voucher optional (if present: `settled ≤ voucher.cumulative ≤ deposit` & voucher fresh†) |
| `requestClose` | `OPEN → CLOSING` | sets `closureStartedAt = now` |
| `settleAndFinalize` | `CLOSING → FINALIZED` | merchant signer & `now < closureStartedAt + GRACE`; voucher optional (if present: `settled ≤ voucher.cumulative ≤ deposit` & voucher fresh†) |
| `finalize` | `CLOSING → FINALIZED` | `now ≥ closureStartedAt + GRACE` |
| `distribute` | `OPEN → OPEN` | `Blake3(canonicalized preimage) == distribution_hash` & `settled > paid_out` |
| `distribute` | `FINALIZED → CLOSED` | `Blake3(canonicalized preimage) == distribution_hash` & (`settled > paid_out` OR refund/tombstone work remains) (permissionless; tombstones the PDA) |
| `withdraw_payer` | `FINALIZED → FINALIZED` | `payerWithdrawnAt == 0` |

† **voucher fresh** = `voucher.expires_at == 0` OR `now < voucher.expires_at`. Expired vouchers MUST be rejected to prevent merchants from settling stale authorizations after the payer's TTL has passed.

‡ **`closureStartedAt` semantics:** Set by `requestClose`. Gates `finalize` via `now >= closureStartedAt + grace_period`. Reset to `0` on transition to `FINALIZED`. Only `CLOSING` carries a live timestamp. Once `FINALIZED`, `distribute` and `withdraw_payer` are immediately callable. The payer's worst-case wait is one `grace_period`.

## Instructions

See [ADR-003: Program Instructions Reference](./003-program-instructions.md) for the full per-instruction args + accounts listing.

## Splits Preimage Canonicalization

Byte layout hashed at `open` and re-hashed at `distribute`:

```text
num_splits (u8) || [ recipient (32 bytes) || shareBps (u16 LE) ] × num_splits
```

- Only active entries are hashed (variable length, no zero-padding).
- `shareBps` is a `u16` in basis points (0..10000). Every active entry MUST have `shareBps > 0`; `open` rejects zero-share entries.
- `0 < Σ shareBps[0..num_splits] < 10000` is checked at `open`; `distribute` verifies only that the submitted preimage matches the immutable hash commitment, then uses the committed bps values for payout math.
- Recipient `i` receives `floor((settled - paid_out) * shareBps[i] / 10000)`.
- The payer receives the implicit remainder share `floor((settled - paid_out) * (10000 - Σ shareBps) / 10000)`.
- Any residual dust from flooring is sent to the treasury ATA.
- Default `MAX_DISTRIBUTION_RECIPIENTS = 32`. Program-level constant; tunable per deployment.

## Token Program Support

Every token-moving instruction receives a `token_program` account and accepts
only the classic SPL Token program or Token-2022. ATAs are derived as
`ATA(owner, mint, token_program)`, and transfers/closures use common
Token-2022 CPI helpers (`TransferChecked`, `CloseAccount`) with the supplied
program id, so extensionless Token-2022 and classic SPL Token share one path.

`open` and `distribute` MUST validate the mint and all token accounts
defensively:

- Classic SPL Token mints/accounts must use the base layouts.
- Token-2022 mints/accounts are parsed with the account-type byte and TLV
  extension trailer.
- Token-2022 mint extensions are allowed only when they do not affect transfer
  semantics or exact accounting: `MetadataPointer`, `TokenMetadata`,
  `GroupPointer`, `TokenGroup`, `GroupMemberPointer`, `TokenGroupMember`.
- Token-2022 token-account extensions are allowed only for base accounts and
  `ImmutableOwner`.
- Unknown, malformed, or unsupported extensions are rejected before escrow
  movement or `paid_out` mutation.

## TBD

### Replace tombstone with `init_id` generation marker

Fully close the PDA at end-of-life and add an `init_id: i64` field to `Channel`, set from `Clock::slot` at `open`. Vouchers bind `channelId = (pda_address, init_id)`. Re-opening the same PDA produces a new `init_id`, invalidating old vouchers.

### Rejected Token-2022 Extensions

`open` MUST read the mint and reject the channel if any of the following Token-2022 extensions is present (or active, where applicable). `distribute` continues to validate runtime token accounts supplied for payout before transfer. Each rejected extension would either trap funds, distort the deposit/settled accounting, add CPI account requirements, or undermine the program's custody guarantee:

| Extension | Reason |
|---|---|
| `NonTransferable` | No transfer from escrow could ever succeed |
| `PermanentDelegate` | Delegate can move escrow arbitrarily; breaks custody |
| `DefaultAccountState = Frozen` | Destination ATAs would be born frozen, blocking payouts |
| `ConfidentialTransferMint` (required) | Program does not produce confidential-transfer proofs |
| `TransferFeeConfig` | Withheld fees on incoming and outgoing transfers desynchronize `deposit`/`settled` from real escrow balance |
| `TransferHook` | Hook program can revert any transfer based on arbitrary logic; funds could be permanently trapped |
| `InterestBearing` | User-visible token amount changes over time; exact channel accounting is intentionally base-unit only |
| `ScaledUiAmountConfig` | Display-vs-raw amount divergence breaks user-visible exact distribution |
| `Pausable` | Mint-level pause can block escrow release |
| `CpiGuard` / `MemoTransfer` account extensions | Distribution CPIs do not use delegate flow or memo pre-instructions |
| `MintCloseAuthority` | Mint identity can be closed and recreated while channels reference the address |
