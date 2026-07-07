# ADR-001: Payment Channel State Machine

**Status:** Draft

## Context

This ADR specifies the channel lifecycle, instruction set, and on-chain PDA layout for a Solana payment channel program aligned with [`draft-solana-session-00`](https://github.com/solana-foundation/mpp-specs/blob/a64edb477cfcb5e071e4f73f4227cf329dd1c4b5/specs/methods/solana/draft-solana-session-00.md) from the MPP specification.

## Decision

The program implements unidirectional payment channels. Channels are PDAs holding escrowed tokens. Payer-signed off-chain vouchers carry a cumulative amount committed to a `settled` watermark. The split config (a list of `(recipient, bps)` entries with `0 ≤ sum(bps) ≤ 10000`) is passed to `open`. The program stores the 32-byte SHA-256 digest in `Channel.distribution_hash`. Splits are recoverable from the `open` instruction data. Token movement occurs at closure via two paths:

- **Happy path (`settleAndSeal` + `distribute`)**: Merchant commits the final voucher (transitions to `SEALED`) and runs `distribute` with the splits preimage — these SHOULD be bundled. The program verifies the SHA-256 hash, pays cumulative floor deltas between `payout_watermark` and `settled` across recipients and the payee's implicit remainder share, sweeps final irreducible residual dust to the treasury ATA, refunds `deposit - settled` to the payer, and closes the escrow ATA — all immediately; no token movement is ever slot-gated. The channel PDA itself is fully deallocated in the same instruction when `clock.slot > open_slot + OPEN_SLOT_WINDOW` has already passed, otherwise it flips to `DISTRIBUTED` and a later permissionless `reclaim` returns its rent to `rent_payer` once the window elapses.
- **Unhappy path (post-grace permissionless crank)**: If the merchant fails to submit a voucher after `requestClose` starts the grace period, anyone can call `seal` post-grace to transition to `SEALED`. Anyone can then call `distribute` using the publicly recoverable splits preimage. The payer can also pull their refund early during `SEALED` via `withdrawPayer`.

Instructions determined by on-chain state are permissionless cranks. Authority is encoded in the channel state, not the signer.

## Channel State Machine

### Status enum

```rust
#[repr(u8)]
pub enum ChannelStatus {
    Open        = 0,
    Sealed      = 1,
    Closing     = 2,
    Distributed = 3,   // fully drained; awaits `reclaim` once the epoch window passes
}
```

Zero-initialized accounts are rejected by `AccountDiscriminator::Channel` before
the status byte is interpreted.

### Account discriminator

```rust
#[repr(u8)]
pub enum AccountDiscriminator {
    Channel = 1,                    // starts at 1 so zero-init accounts fail load
    ClosedChannel = 2,              // tombstones of a previous deployment; not created or read
}
```

### Channel PDA

```rust
/// Active channel account. 256 bytes.
#[repr(C)]
pub struct Channel {
    pub discriminator:      u8,       // [  0..1  )
    pub version:            u8,       // [  1..2  )  CURRENT_CHANNEL_VERSION = 1
    pub bump:               u8,       // [  2..3  )  canonical bump
    pub status:             u8,       // [  3..4  )
    pub salt:               u64,      // [  4..12 )  PDA disambiguator; stored so `distribute` / `withdrawPayer` can re-derive seeds and self-sign without off-chain data
    pub deposit:            u64,      // [ 12..20 )  escrow amount (mutated by `topUp`)
    pub settlement:         SettlementWatermarks, // [ 20..36 )
    pub closure_started_at: i64,      // [ 36..44 )  unix ts; set by `requestClose`, gates `seal`
    pub payer_withdrawn_at: i64,      // [ 44..52 )  unix ts; 0 = not yet withdrawn
    pub grace_period:       u32,      // [ 52..56 )  seconds; set at `open`; must be non-zero
    pub distribution_hash:  [u8; 32], // [ 56..88 )  SHA-256 digest of the canonical splits preimage, computed on-chain at `open`
    pub payer:              Address,  // [ 88..120)  refund destination + payer-authority signer
    pub payee:              Address,  // [120..152)  PDA seed binding + implicit-remainder destination on `distribute`
    pub authorized_signer:  Address,  // [152..184)  voucher signer; equals `payer` when no delegate bound
    pub mint:               Address,  // [184..216)
    pub rent_payer:         Address,  // [216..248)  funded PDA + escrow-ATA rent at `open`; receives all freed SOL at close
    pub open_slot:          u64,      // [248..256)  client-supplied, window-validated per-incarnation epoch; PDA seed, reclaim-gate input, kept on-struct for signer-seed reconstruction
}

#[repr(C)]
pub struct SettlementWatermarks {
    pub settled:            u64,      // [ 20..28 )  cumulative authorized watermark
    pub payout_watermark:   u64,      // [ 28..36 )  accounted distribution watermark; payout_watermark ≤ settled
}
```

Multi-byte fields are stored as align-1 `[u8; N]` byte arrays in the actual struct, with `from_le_bytes` / `to_le_bytes` accessors; the typed view above is the logical layout.

### Accounting authority

`Channel` state — `deposit`, `settlement.settled`, `settlement.payout_watermark`, `payer_withdrawn_at` — is authoritative for pending settlement amounts. The escrow ATA balance and the channel PDA's lamports can exceed those values: third parties can transfer tokens to the escrow ATA address (either before `open` via a precreated ATA or directly afterward), and lamports can be transferred to the PDA address before `open`. The program accepts these states (`open` is prefund-tolerant) but does not record them in `Channel`. Surplus tokens are swept to treasury at `seal` via `distribute`'s `escrow_at_entry − scheduled_outflow` residual; surplus PDA lamports flow to `rent_payer` at close (full deallocation drains every lamport). Off-chain consumers MUST derive pending value from channel state, never from raw account balances.

### PDA derivation

```text
seeds = [ b"channel", payer, payee, mint, authorized_signer, salt.to_le_bytes(), open_slot.to_le_bytes() ]
```

- `payer`, `payee`, `mint`, `authorized_signer`: Stored in the struct after `open`.
- `salt: u64`: Disambiguator for concurrent channels. Stored on-chain in `Channel.salt` so `distribute` and `withdrawPayer` can re-derive these seeds for self-signing without off-chain data.
- `open_slot: u64`: Client-supplied per-incarnation epoch (see [Channel Closure](#channel-closure-epoch-bound-full-deallocation)). Stored on-chain in `Channel.open_slot` for the same signer-seed reconstruction and for the reclaim gate.
- `bump`: Canonical bump stored in the struct.

Seeds bind all identity parameters plus the incarnation epoch, allowing PDA re-derivation for account verification.

Because `open_slot` is a seed, the channel address is **per-incarnation by construction**: the open window (`open_slot ≤ clock.slot` and `clock.slot − open_slot ≤ OPEN_SLOT_WINDOW`, K = 150) plus the reclaim gate (`clock.slot > open_slot + OPEN_SLOT_WINDOW`) guarantee that an address can never host two channels — while a channel is live or `DISTRIBUTED` the address is occupied, and once the account can be deallocated its `open_slot` is already too stale to re-derive at `open`. Vouchers therefore bind their incarnation by binding the channel address alone; no separate epoch field is needed.

### Voucher

Payer-signed off-chain payload authorizing cumulative spend. Committed on-chain via `settle` or `settleAndSeal`.

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
    pub magic:             [u8; 2],       //  2 bytes, = [0x56, 0x01] (tag byte 'V' + format version)
    pub channel_id:        Pubkey,        // 32 bytes
    pub cumulative_amount: u64,           //  8 bytes, LE
    pub expires_at:        i64,           //  8 bytes, LE
}
```

Total 50 bytes (offsets `0..2`, `2..34`, `34..42`, `42..50`), stored align-1 (`[u8; 8]` arrays for the ints). Field order matches `Borsh({ magic, channel_id, cumulative_amount, expires_at })`, so the struct's raw bytes ARE the Ed25519-signed payload — no repack between `VoucherArgs` and the precompile message. There is no epoch field: because `open_slot` is a PDA seed, the channel address is per-incarnation and binding `channel_id` alone binds the incarnation. The `magic` prefix domain-separates voucher bytes from anything else the session key might sign and pins the format version inside the signed bytes: the tag byte `0x56` (`'V'`, constant across all payload versions) only needs to differ from the first byte of other Ed25519-signable payloads (legacy transaction messages start with a small signature count, versioned transactions with `0x80`, offchain messages with `0xff`) — the domain-separation strength comes from the exact 50-byte length pin plus the `channel_id` PDA binding, not from tag entropy.

**Verification.** The caller bundles an Ed25519 native-program ix immediately before each voucher-bearing program ix in the same transaction (canonical single-signature layout, 162 bytes total = 112-byte prefix + 50-byte message; `message_data_size` MUST be exactly 50). The program reads the voucher fields straight out of the precompile-verified message via the Instructions sysvar — there is no second in-data copy to reconcile — and checks, in order: the magic MUST equal `[0x56, 0x01]`; `channel_id` MUST equal the channel PDA address (this single check also covers cross-incarnation replay, since the address is per-incarnation); the voucher must be fresh†; `cumulative_amount ≤ deposit`; `cumulative_amount > settled`; and the pubkey embedded in the precompile ix MUST equal `Channel.authorized_signer` (which equals `payer` if no delegate was bound at `open`). `open` rejects `authorized_signer` values that are not valid Ed25519 public-key points.

**Replay protection.** `channel_id` (a PDA, hence program- and seed-specific — and, because `open_slot` is a seed, incarnation-specific) + strictly monotonic `cumulative_amount > settled` + optional `expires_at`. No explicit nonce and no epoch field. Binding the address is what allows terminal `distribute` to fully deallocate the PDA: `open` validates `open_slot <= clock.slot && clock.slot - open_slot <= OPEN_SLOT_WINDOW` (future slots strictly rejected) and terminal closure requires `clock.slot > open_slot + OPEN_SLOT_WINDOW`, so the channel address never repeats — a reincarnation of the same participant tuple necessarily carries a new `open_slot` and lands at a new address, and an old voucher fails as wrong-address (`VoucherChannelMismatch`) or hits a nonexistent account. `OPEN_SLOT_WINDOW` is consensus-critical and may only ever be decreased across program versions. The strict watermark rule applies to `settle` and to `settleAndSeal` when a voucher is supplied. A supplied `settleAndSeal` voucher with `cumulative_amount <= settled` is invalid and MUST cause the `settleAndSeal` instruction to reject; if no additional settlement is needed, call `settleAndSeal` without a voucher to seal the current `settled` watermark.

**Cluster scope.** Vouchers are not bound to a cluster. A voucher could in principle be replayed against an identically-addressed channel on another cluster — which requires the same program, mint, salt, payer, authorized_signer, and open_slot at identical addresses on two clusters plus an operator accepting it cross-cluster. This residual replay is an accepted operational risk (no parallel clusters in use; SVM has no EVM-style cross-chain vector), mitigated off-chain by pinning each server and channel to one cluster — see ADR-002, Server Implementation Requirements.

### FSM

![Channel state machine](./fsm.png)

`DISTRIBUTED` is a real `ChannelStatus` value (3): fully drained (every token leg paid, escrow ATA closed), inert to every instruction except `reclaim`, holding only its own PDA rent. `reclaim` (or `distribute`'s fast path, when the window has already elapsed) deallocates the account entirely — it ceases to exist and the address becomes reopenable.

## Transition Guards

| Instruction | From → To | Guard |
|---|---|---|
| `open` | `NONEXISTENT → OPEN` | payer signer; `authorized_signer` is a valid Ed25519 public key; channel PDA matches the seeds — derived over `open_slot` among the rest — and is uninitialized; `deposit > 0`; `grace_period > 0`; `open_slot ≤ clock.slot` and `clock.slot − open_slot ≤ OPEN_SLOT_WINDOW`; `payer != payee`; `payee` may be on-curve or a program-derived address (PDA); `count ≤ MAX_DISTRIBUTION_RECIPIENTS`; exact preimage length; `bps[i] > 0 ∀ i ∈ [0, count)`; `Σ bps[0..count] ≤ 10000`; recipients unique; no recipient equals the derived channel PDA |
| `settle` | `OPEN → OPEN` | channel is `OPEN`; preceding Ed25519 ix exists; voucher magic valid; voucher channel id matches the channel PDA (which also binds the incarnation); voucher signer equals `authorized_signer`; voucher fresh†; `settled < voucher.cumulative ≤ deposit` |
| `topUp` | `OPEN → OPEN` | payer signer equals channel `payer`; `amount > 0`; channel is `OPEN`; mint/source/escrow token accounts match channel |
| `settleAndSeal` | `OPEN → SEALED` | payee signer equals channel `payee`; voucher optional (if present: preceding Ed25519 ix, signer equals `authorized_signer`, voucher fresh†, `settled < voucher.cumulative ≤ deposit`) |
| `requestClose` | `OPEN → CLOSING` | payer signer equals channel `payer`; channel is `OPEN`; sets `closureStartedAt = now` |
| `settleAndSeal` | `CLOSING → SEALED` | payee signer equals channel `payee`; `now < closureStartedAt + GRACE`; voucher optional (if present: preceding Ed25519 ix, signer equals `authorized_signer`, voucher fresh†, `settled < voucher.cumulative ≤ deposit`) |
| `seal` | `CLOSING → SEALED` | channel is `CLOSING`; `now ≥ closureStartedAt + GRACE` |
| `distribute` | `OPEN → OPEN` | channel is `OPEN`; parsed preimage hash matches `distribution_hash`; recipient account tail length/order matches preimage; `settled > payout_watermark`; pays cumulative floor deltas and advances `payout_watermark` to `settled` |
| `distribute` | `SEALED → DISTRIBUTED` | channel is `SEALED`; parsed preimage hash matches `distribution_hash`; recipient account tail length/order matches preimage; pays cumulative floor deltas for any unaccounted settled watermark, performs any pending payer refund, sweeps final irreducible residual dust to treasury, and closes escrow — none of it slot-gated; then deallocates the PDA in place if `clock.slot > open_slot + OPEN_SLOT_WINDOW` already holds, else sets `DISTRIBUTED` |
| `reclaim` | `DISTRIBUTED → gone` | permissionless; channel is `DISTRIBUTED`; `rent_payer` account equals `Channel.rent_payer`; `clock.slot > open_slot + OPEN_SLOT_WINDOW`; drains all lamports to `rent_payer` and deallocates the PDA |
| `withdrawPayer` | `SEALED → SEALED` | payer signer equals channel `payer`; channel is `SEALED`; `payerWithdrawnAt == 0`; mint/escrow/refund ATAs match channel |

† **voucher fresh** = `voucher.expires_at == 0` OR `now < voucher.expires_at`. Expired vouchers MUST be rejected to prevent merchants from settling stale authorizations after the payer's TTL has passed.

‡ **`closureStartedAt` semantics:** Set by `requestClose`. Gates `seal` via `now >= closureStartedAt + grace_period`. Reset to `0` on transition to `SEALED`. Only `CLOSING` carries a live timestamp. Once `SEALED`, `distribute` and `withdrawPayer` are immediately callable. The payer's worst-case wait is one `grace_period`.

**PDA payees.** `open` intentionally does not require `payee` to be on-curve. Direct `settleAndSeal` transactions still require a signer equal to `Channel.payee`, so program-derived address (PDA) payees can use the cooperative-close path only when their owning program invokes payment channels via CPI with signer seeds. Permissionless `settle`, `seal`, and `distribute` do not depend on a payee signature.

## Instructions

See [ADR-003: Program Instructions Reference](./003-program-instructions.md) for the full per-instruction args + accounts listing.

## Splits Preimage Canonicalization

Byte layout hashed at `open` and re-hashed at `distribute`:

```text
count (u32 LE) || [ recipient (32 bytes) || bps (u16 LE) ] × count
```

- Only active entries are encoded and hashed (variable length, no zero-padding); `count == 0` is legal and collapses to a vanilla two-party channel where the payee receives 100% of the pool.
- `bps` is a `u16` basis-point share (1..=10000) in the generated IDL/clients. Every active entry MUST have `bps > 0`; `open` and `distribute` reject zero-share entries. A single entry of `10000` is legal (recipient takes 100% of pool, payee carve-out is zero).
- `0 ≤ Σ bps[0..count] ≤ 10000` and duplicate-recipient rejection are checked when the preimage is parsed. `distribute` additionally verifies that the submitted preimage's SHA-256 digest matches the immutable hash commitment before using the bps values for payout math.
- Recipient `i` receives `floor(settled * bps[i] / 10000) - floor(payout_watermark * bps[i] / 10000)`.
- The payee receives the implicit remainder delta `floor(settled * (10000 - Σ bps) / 10000) - floor(payout_watermark * (10000 - Σ bps) / 10000)`.
- During `OPEN`, residual dust from floor math remains in escrow while `payout_watermark` advances to `settled` as an accounted watermark. Later distributions compute cumulative floor deltas from that watermark, so previously residual value remains claimable when a share's cumulative entitlement crosses the next whole token.
- During `SEALED`, the final cumulative floor delta runs once, then final irreducible residual dust is swept to the treasury ATA before the escrow ATA is closed.
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

## Channel Closure: Epoch-Bound Full Deallocation

`open_slot` is a PDA seed, so the channel address itself is per-incarnation: each incarnation of a participant tuple lives at its own address, and channels are identified by the address alone. This resolves the former TBD ("replace tombstone with a per-incarnation generation marker") and removes the permanent per-channel rent cost documented in the original tombstone design (897,840 lamports stranded per channel).

- **`open_slot` is client-supplied**, so the client can derive the channel address at transaction-build time (`open_slot` is one of the derivation inputs) — vouchers can be pre-signed while `open` is in flight, with no post-confirmation read-back. It is validated on-chain: `open_slot ≤ clock.slot` (future slots strictly rejected, which prevents a payer from stalling the reclaim gate forever) and `clock.slot − open_slot ≤ OPEN_SLOT_WINDOW`.
- **Token movement is never slot-gated.** The SEALED `distribute` runs immediately: payouts, payer refund, treasury sweep, escrow-ATA close. Only the *deallocation of the PDA itself* — i.e. recovering its own rent — waits for `clock.slot > open_slot + OPEN_SLOT_WINDOW`: `distribute` deallocates in place when that already holds (fast path), and otherwise leaves the channel `DISTRIBUTED` for a later permissionless `reclaim` (two writable accounts, no signers — operators batch many per sweep transaction).
- **Uniqueness proof**: an address encodes one fixed `open_slot` in its seeds, so it can only ever be re-derived while `clock.slot − open_slot ≤ OPEN_SLOT_WINDOW`. The address stays occupied — live, then `DISTRIBUTED` — until it is deallocated at some slot `C > open_slot + OPEN_SLOT_WINDOW`; from `C` onward the open window can never re-admit that `open_slot`, so **the address never repeats**: no address ever hosts two channels, for any client behavior inside the window, including adversarial. An old voucher can never settle against a later incarnation — the later incarnation lives at a different address, so the stale voucher fails as wrong-address (`VoucherChannelMismatch`) or targets a deallocated account.
- **Trade-off**: the open-landing window and the reclaim unlock share the `OPEN_SLOT_WINDOW` budget measured from the supplied slot, but the only thing the wait delays is the operator's recovery of the PDA rent (~2.7M lamports per channel for up to ~60 s). All settlement and payout value moves ungated; back-dating `open_slot` remains available to shorten the rent float at the cost of a narrower landing window. Additionally, every incarnation lives at a fresh address — anything keyed by channel address (metering ledgers, indexers, resume flows) sees a new identifier per incarnation, and reopening a closed relationship means opening a new channel at a new address (the same `salt` is fine); in exchange the voucher needs no epoch field and consumers need no `(channelId, openSlot)` composite key.
- **`OPEN_SLOT_WINDOW = 150`** (~60 s). Consensus-critical: it may only ever be **decreased** in future program versions — the proof requires the window in force at a close to out-wait the window of any later `open` attempt at that address; enlarging it could let a deallocated address become re-derivable again.
