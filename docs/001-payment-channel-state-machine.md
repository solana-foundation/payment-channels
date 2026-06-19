# ADR-001: Payment Channel State Machine

**Status:** Draft

## Context

This ADR specifies the channel lifecycle, instruction set, and on-chain PDA layout for a Solana payment channel program aligned with [`draft-solana-session-00`](https://github.com/solana-foundation/mpp-specs/blob/a64edb477cfcb5e071e4f73f4227cf329dd1c4b5/specs/methods/solana/draft-solana-session-00.md) from the MPP specification.

## Decision

The program implements unidirectional payment channels. Channels are PDAs holding escrowed tokens. Payer-signed off-chain vouchers carry a cumulative amount committed to a `settled` watermark. The split config (a list of `(recipient, bps)` entries with `0 ≤ sum(bps) ≤ 10000`) is passed to `open`. The program stores the 32-byte Blake3 digest in `Channel.distribution_hash`. Splits are recoverable from the `open` instruction data. Token movement occurs at closure via two paths:

- **Happy path (`settleAndFinalize` + `distribute`)**: Merchant commits the final voucher (transitions to `FINALIZED`) and runs `distribute` with the splits preimage. The program verifies the Blake3 hash, pays cumulative floor deltas between `payout_watermark` and `settled` across recipients and the payee's implicit remainder share, sweeps final irreducible residual dust to the treasury ATA, refunds `deposit - settled` to the payer, and tombstones the PDA. These instructions SHOULD be bundled.
- **Unhappy path (post-grace permissionless crank)**: If the merchant fails to submit a voucher after `requestClose` starts the grace period, anyone can call `finalize` post-grace to transition to `FINALIZED`. Anyone can then call `distribute` using the publicly recoverable splits preimage. The payer can also pull their refund early during `FINALIZED` via `withdrawPayer`.

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
    ClosedChannel = 2,              // one-byte tombstone after finalized distribution
}
```

### Channel PDA

```rust
/// Active channel account. 216 bytes.
#[repr(C)]
pub struct Channel {
    pub discriminator:      u8,       // [  0..1  )
    pub version:            u8,       // [  1..2  )
    pub bump:               u8,       // [  2..3  )  canonical bump
    pub status:             u8,       // [  3..4  )
    pub salt:               u64,      // [  4..12 )  PDA disambiguator; stored so `distribute` / `withdrawPayer` can re-derive seeds and self-sign without off-chain data
    pub deposit:            u64,      // [ 12..20 )  escrow amount (mutated by `topUp`)
    pub settlement:         SettlementWatermarks, // [ 20..36 )
    pub closure_started_at: i64,      // [ 36..44 )  unix ts; set by `requestClose`, gates `finalize`
    pub payer_withdrawn_at: i64,      // [ 44..52 )  unix ts; 0 = not yet withdrawn
    pub grace_period:       u32,      // [ 52..56 )  seconds; set at `open`; must be non-zero
    pub distribution_hash:  [u8; 32], // [ 56..88 )  Blake3 digest of the canonical splits preimage, computed on-chain at `open`
    pub payer:              Address,  // [ 88..120)  refund destination + payer-authority signer
    pub payee:              Address,  // [120..152)  PDA seed binding + implicit-remainder destination on `distribute`
    pub authorized_signer:  Address,  // [152..184)  voucher signer; equals `payer` when no delegate bound
    pub mint:               Address,  // [184..216)
}

#[repr(C)]
pub struct SettlementWatermarks {
    pub settled:            u64,      // [ 20..28 )  cumulative authorized watermark
    pub payout_watermark:   u64,      // [ 28..36 )  accounted distribution watermark; payout_watermark ≤ settled
}
```

Multi-byte fields are stored as align-1 `[u8; N]` byte arrays in the actual struct, with `from_le_bytes` / `to_le_bytes` accessors; the typed view above is the logical layout.

### Accounting authority

`Channel` state — `deposit`, `settlement.settled`, `settlement.payout_watermark`, `payer_withdrawn_at` — is authoritative for pending settlement amounts. The escrow ATA balance and the channel PDA's lamports can exceed those values: third parties can transfer tokens to the escrow ATA address (either before `open` via a precreated ATA or directly afterward), and lamports can be transferred to the PDA address before `open`. The program accepts these states (`open` is prefund-tolerant) but does not record them in `Channel`. Surplus tokens are swept to treasury at `finalize` via `distribute`'s `escrow_at_entry − scheduled_outflow` residual; surplus PDA lamports refund to the payer at tombstone via the rent rebalance. Off-chain consumers MUST derive pending value from channel state, never from raw account balances.

### PDA derivation

```text
seeds = [ b"channel", payer, payee, mint, authorized_signer, salt.to_le_bytes() ]
```

- `payer`, `payee`, `mint`, `authorized_signer`: Stored in the struct after `open`.
- `salt: u64`: Disambiguator for concurrent channels. Stored on-chain in `Channel.salt` so `distribute` and `withdrawPayer` can re-derive these seeds for self-signing without off-chain data.
- `bump`: Canonical bump stored in the struct.

Seeds bind all identity parameters, allowing PDA re-derivation for account verification.

### Voucher

Payer-signed off-chain payload authorizing cumulative spend. Committed on-chain via `settle` or `settleAndFinalize`.

#### Off-chain wire format

Carried inside the MPP `Authorization: Payment <base64url-JSON>` HTTP header. Clients exchange the full envelope; only the inner `Voucher` bytes are signed and forwarded on-chain.

```rust
pub struct Voucher {
    pub channel_id:        Pubkey,        // JSON: base58 string
    pub cumulative_amount: u64,           // JSON: decimal ASCII string (base units)
    pub expires_at:        i64,           // JSON: ISO 8601 string when != 0, omitted when 0
}

pub struct SignedVoucher {
    pub voucher:        Voucher,
    pub signer:         Pubkey,           // JSON: base58 string; equals Channel.authorized_signer
    pub signature:      [u8; 64],         // JSON: base58 string
    pub signature_type: SigType,          // always SigType::Ed25519
}

#[repr(u8)]
pub enum SigType {
    Ed25519 = 0,
}
```

#### On-chain ix payload

Only the inner `Voucher` bytes ride on-chain — `signer` and `signature` come from the caller-bundled Ed25519 precompile ix, recovered via Instructions-sysvar introspection. The on-chain ix args struct is:

```rust
#[repr(C)]
pub struct VoucherArgs {
    pub channel_id:        Pubkey,        // 32 bytes
    pub cumulative_amount: u64,           //  8 bytes, LE
    pub expires_at:        i64,           //  8 bytes, LE
}
```

Total 48 bytes, stored align-1 (`[u8; 8]` arrays for the two ints). Field order matches `Borsh({ channel_id, cumulative_amount, expires_at })`, so the struct's raw bytes ARE the Ed25519-signed payload — no repack between `VoucherArgs` and the precompile message.

**Verification.** The caller bundles an Ed25519 native-program ix immediately before each voucher-bearing program ix in the same transaction. The program reads the verified message bytes from that ix via the Instructions sysvar and asserts they equal `VoucherArgs::as_bytes()`. The pubkey embedded in the precompile ix MUST equal `Channel.authorized_signer` (which equals `payer` if no delegate was bound at `open`). `open` rejects `authorized_signer` values that are not valid Ed25519 public-key points.

**Replay protection.** `channel_id` (a PDA, hence program- and seed-specific) + strictly monotonic `cumulative_amount > settled` + optional `expires_at`. No explicit nonce. This strict watermark rule applies to `settle` and to `settleAndFinalize` when a voucher is supplied. A supplied `settleAndFinalize` voucher with `cumulative_amount <= settled` is invalid and MUST cause the `settleAndFinalize` instruction to reject; if no additional settlement is needed, call `settleAndFinalize` without a voucher to finalize the current `settled` watermark.

### FSM

![Channel state machine](./fsm.png)

`CLOSED` is a visual convergence point, not a `ChannelStatus` value. The transition is atomic with the tombstone realloc.

## Transition Guards

| Instruction | From → To | Guard |
|---|---|---|
| `open` | `NONEXISTENT → OPEN` | payer signer; `authorized_signer` is a valid Ed25519 public key; channel PDA matches seeds and is uninitialized; `deposit > 0`; `grace_period > 0`; `payer != payee`; `payee` may be on-curve or a program-derived address (PDA); `count ≤ MAX_DISTRIBUTION_RECIPIENTS`; exact preimage length; `bps[i] > 0 ∀ i ∈ [0, count)`; `Σ bps[0..count] ≤ 10000`; recipients unique; no recipient equals the derived channel PDA |
| `settle` | `OPEN → OPEN` | channel is `OPEN`; preceding Ed25519 ix exists; voucher channel id matches the channel PDA; voucher signer equals `authorized_signer`; voucher fresh†; `settled < voucher.cumulative ≤ deposit` |
| `topUp` | `OPEN → OPEN` | payer signer equals channel `payer`; `amount > 0`; channel is `OPEN`; mint/source/escrow token accounts match channel |
| `settleAndFinalize` | `OPEN → FINALIZED` | merchant signer equals channel `payee`; voucher optional (if present: preceding Ed25519 ix, signer equals `authorized_signer`, voucher fresh†, `settled < voucher.cumulative ≤ deposit`) |
| `requestClose` | `OPEN → CLOSING` | payer signer equals channel `payer`; channel is `OPEN`; sets `closureStartedAt = now` |
| `settleAndFinalize` | `CLOSING → FINALIZED` | merchant signer equals channel `payee`; `now < closureStartedAt + GRACE`; voucher optional (if present: preceding Ed25519 ix, signer equals `authorized_signer`, voucher fresh†, `settled < voucher.cumulative ≤ deposit`) |
| `finalize` | `CLOSING → FINALIZED` | channel is `CLOSING`; `now ≥ closureStartedAt + GRACE` |
| `distribute` | `OPEN → OPEN` | channel is `OPEN`; parsed preimage hash matches `distribution_hash`; recipient account tail length/order matches preimage; `settled > payout_watermark`; pays cumulative floor deltas and advances `payout_watermark` to `settled` |
| `distribute` | `FINALIZED → CLOSED` | channel is `FINALIZED`; parsed preimage hash matches `distribution_hash`; recipient account tail length/order matches preimage; pays cumulative floor deltas for any unaccounted settled watermark, performs any pending payer refund, sweeps final irreducible residual dust to treasury, closes escrow, and tombstones the PDA |
| `withdrawPayer` | `FINALIZED → FINALIZED` | payer signer equals channel `payer`; channel is `FINALIZED`; `payerWithdrawnAt == 0`; mint/escrow/refund ATAs match channel |

† **voucher fresh** = `voucher.expires_at == 0` OR `now < voucher.expires_at`. Expired vouchers MUST be rejected to prevent merchants from settling stale authorizations after the payer's TTL has passed.

‡ **`closureStartedAt` semantics:** Set by `requestClose`. Gates `finalize` via `now >= closureStartedAt + grace_period`. Reset to `0` on transition to `FINALIZED`. Only `CLOSING` carries a live timestamp. Once `FINALIZED`, `distribute` and `withdrawPayer` are immediately callable. The payer's worst-case wait is one `grace_period`.

**PDA payees.** `open` intentionally does not require `payee` to be on-curve. Direct `settleAndFinalize` transactions still require a signer equal to `Channel.payee`, so program-derived address (PDA) payees can use the cooperative-close path only when their owning program invokes payment channels via CPI with signer seeds. Permissionless `settle`, `finalize`, and `distribute` do not depend on a payee signature.

## Instructions

See [ADR-003: Program Instructions Reference](./003-program-instructions.md) for the full per-instruction args + accounts listing.

## Splits Preimage Canonicalization

Byte layout hashed at `open` and re-hashed at `distribute`:

```text
count (u32 LE) || [ recipient (32 bytes) || bps (u16 LE) ] × count
```

- Only active entries are encoded and hashed (variable length, no zero-padding); `count == 0` is legal and collapses to a vanilla two-party channel where the payee receives 100% of the pool.
- `bps` is a `u16` basis-point share (1..=10000) in the generated IDL/clients. Every active entry MUST have `bps > 0`; `open` and `distribute` reject zero-share entries. A single entry of `10000` is legal (recipient takes 100% of pool, payee carve-out is zero).
- `0 ≤ Σ bps[0..count] ≤ 10000` and duplicate-recipient rejection are checked when the preimage is parsed. `distribute` additionally verifies that the submitted preimage's Blake3 digest matches the immutable hash commitment before using the bps values for payout math.
- Recipient `i` receives `floor(settled * bps[i] / 10000) - floor(payout_watermark * bps[i] / 10000)`.
- The payee receives the implicit remainder delta `floor(settled * (10000 - Σ bps) / 10000) - floor(payout_watermark * (10000 - Σ bps) / 10000)`.
- During `OPEN`, residual dust from floor math remains in escrow while `payout_watermark` advances to `settled` as an accounted watermark. Later distributions compute cumulative floor deltas from that watermark, so previously residual value remains claimable when a share's cumulative entitlement crosses the next whole token.
- During `FINALIZED`, the final cumulative floor delta runs once, then final irreducible residual dust is swept to the treasury ATA before the escrow ATA is closed.
- Nonzero beneficiary shares redirect to treasury only when the canonical Token-2022 ATA has an unsupported account extension. Malformed extension TLV/data, uninitialized accounts, wrong mint/owner/address, invalid token program, mint failures, escrow failures, and treasury failures hard-fail. Zero-amount shares validate only the canonical ATA address.
- Default `MAX_DISTRIBUTION_RECIPIENTS = 32`. Program-level constant; tunable per deployment.

## Token Program Support

Every token-moving instruction receives a `token_program` account and accepts
only the SPL Token program or Token-2022. ATAs are derived as
`ATA(owner, mint, token_program)`, and transfers/closures use common
Token-2022 CPI helpers (`TransferChecked`, `CloseAccount`) with the supplied
program id, so extensionless Token-2022 and SPL Token share one path.

Defensive validation runs before any escrow movement or `payout_watermark` mutation:

- `open` validates the mint and the payer's source token account. The channel's escrow ATA is created in-band by the ATA program after the address is checked against `find_program_address([channel, token_program, mint], …)`, so it needs no extension scan.
- `distribute` validates the mint and every token account it touches: the channel escrow, the payer refund ATA, the treasury ATA, and each recipient ATA.
- SPL Token mints/accounts must use the base layouts (strict length equality).
- Token-2022 mints/accounts are parsed with the account-type byte and TLV extension trailer.
- Token-2022 mint extensions are allowed only for an explicitly enumerated set: `MetadataPointer`, `TokenMetadata`, `GroupPointer`, `TokenGroup`, `GroupMemberPointer`, `TokenGroupMember`. The list is fixed; future extensions, even ones that would not affect transfer semantics, are rejected until added here.
- Token-2022 token-account extensions are allowed only for base accounts and `ImmutableOwner`.
- Unknown, malformed, or unsupported extensions are rejected before any token transfer, except for the beneficiary redirect case described above.

### Why the allow-list excludes the rest

Each row below would either trap funds, distort the `deposit`/`settled` accounting, add CPI account requirements, or undermine the program's custody guarantee. `open` rejects mints carrying any of these extensions; `distribute` re-validates each runtime token account before transfer. Rejection is by allow-list exclusion (not state inspection) — extension presence alone is disqualifying.

| Extension | Reason |
|---|---|
| `NonTransferable` | No transfer from escrow could ever succeed |
| `PermanentDelegate` | Delegate can move escrow arbitrarily; breaks custody |
| `DefaultAccountState` | Destination ATAs could be born in any non-`Initialized` state, blocking payouts; rejected regardless of the configured state |
| `ConfidentialTransferMint` | Program does not produce confidential-transfer proofs; rejected in both auto-approve and required modes |
| `TransferFeeConfig` | Withheld fees on incoming and outgoing transfers desynchronize `deposit`/`settled` from real escrow balance |
| `TransferHook` | Hook program can revert any transfer based on arbitrary logic; funds could be permanently trapped |
| `InterestBearing` | User-visible token amount changes over time; exact channel accounting is intentionally base-unit only |
| `ScaledUiAmountConfig` | Display-vs-raw amount divergence breaks user-visible exact distribution |
| `Pausable` | Mint-level pause can block escrow release |
| `CpiGuard` / `MemoTransfer` account extensions | Distribution CPIs do not use delegate flow or memo pre-instructions |
| `MintCloseAuthority` | Mint identity can be closed and recreated while channels reference the address |

### Mint trust model

`open` and `topUp` do NOT inspect or reject the mint's base-layout authorities — specifically the **freeze authority** and the **mint authority**. Vetting the mint is the merchant's responsibility.

Freeze authority is the main actor. A live freeze authority can freeze the channel's escrow ATA at any time. Once frozen, the escrow ATA is no longer `Initialized`, so every value-moving instruction rejects:

- `topUp` cannot add collateral.
- `distribute` cannot release `settled - paid_out` to recipients or the payee.
- `withdrawPayer` cannot refund `deposit - settled` to the payer.

The channel stays wedged until the freeze authority thaws the escrow. There is no permissionless crank or alternate instruction that can unwind it, and the lockup blocks both the merchant payout leg and the payer refund leg — neither side can extract value while the freeze stands.

This is intentional. Hard-rejecting any mint with a live freeze authority would exclude the majority of real-world stablecoins (USDC, USDT, PYUSD, EURC, …), all of which retain a freeze authority controlled by the issuer. The trust decision is therefore pushed off-chain: a merchant accepting payments in mint `M` is implicitly accepting that `M`'s freeze authority can wedge any channel denominated in `M`, and should only do so for mints whose freeze authority they consider acceptably governed.

The same reasoning applies, less acutely, to the mint authority and to any Token-2022 update authority for allow-listed extensions: the program does not audit these at `open`, and merchants should treat the mint as a trust dependency of the channel, not a parameter the program defends against.

## TBD

### Replace tombstone with `init_id` generation marker

Fully close the PDA at end-of-life and add an `init_id: i64` field to `Channel`, set from `Clock::slot` at `open`. Vouchers bind `channelId = (pda_address, init_id)`. Re-opening the same PDA produces a new `init_id`, invalidating old vouchers.
