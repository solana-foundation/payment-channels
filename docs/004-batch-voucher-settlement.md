# ADR-004: Batch Voucher Settlement

**Status:** Proposed future work — not implemented

**Parent ADRs:** [ADR-001](./001-payment-channel-state-machine.md), [ADR-002](./002-http-protocol.md), [ADR-003](./003-program-instructions.md)

## Context

The current settlement path uses one signed voucher and one `settle` instruction
per channel:

```text
ed25519(voucher_0) -> settle(channel_0)
ed25519(voucher_1) -> settle(channel_1)
...
```

Each `settle` instruction is already small: it carries a one-byte discriminator
and references the channel plus the Instructions sysvar. Most transaction bytes
come from repeating the Ed25519 public key, signature, offsets record, and
50-byte voucher message.

A client can instead authorize target watermarks for several channels with one
signature when every channel names the same `authorized_signer`. A new
`settleBatch` instruction could apply those targets atomically. This is a new
voucher type and protocol extension; existing single-channel vouchers cannot be
combined after signing. The current
[`draft-solana-session-00`](https://github.com/solana-foundation/mpp-specs/blob/a64edb477cfcb5e071e4f73f4227cf329dd1c4b5/specs/methods/solana/draft-solana-session-00.md)
defines a voucher for one channel, so the batch envelope also needs explicit
capability negotiation.

The optimization does not apply to a merchant sweep across unrelated customer
keys. Ed25519 signatures are not aggregatable, and the program must not replace
independent payer authorization with a merchant or facilitator signature.

## Goals

- Settle many channels sharing one `authorized_signer` with one Ed25519
  signature and one payment-channel instruction.
- Preserve each channel's cumulative watermark, deposit cap, status, expiry,
  signer, and incarnation checks.
- Bind every signed amount to the exact channel account at the same index.
- Keep the existing `settle` and version-1 voucher behavior unchanged.
- Make replay and transaction retries safe when some targets were settled
  independently.
- Fit the largest useful batch within Solana's transaction account limit rather
  than its 1,232-byte transaction limit.

## Non-goals

- Aggregate signatures from different authorized signers.
- Convert stored version-1 vouchers into a batch voucher.
- Transfer tokens, distribute proceeds, seal channels, or close accounts.
- Settle an unsatisfied target after its channel leaves `OPEN`.
- Support partial redemption that omits entries from the signed batch.
- Standardize the off-chain transport in MPP or x402 as part of the on-chain
  change.

## Proposed design

Add a permissionless `settleBatch` instruction. The immediately preceding
Ed25519 precompile instruction verifies one canonical inline
`BatchVoucherArgsV2` message. `settleBatch` reads that message through the
Instructions sysvar, validates the complete batch, and advances every
unsatisfied target.

The transaction shape is:

```text
[optional compute-budget instructions]
ed25519(batch_voucher)
settleBatch(instructions_sysvar, channel_0, ..., channel_n)
```

The existing `settle` instruction continues to accept only the 50-byte
version-1 voucher.

### Off-chain envelope

The transport representation carries the complete entry list so a verifier can
reconstruct the signed message:

```json
{
  "voucher": {
    "entries": [
      {
        "channelId": "<base58 channel PDA>",
        "cumulativeAmount": "<u64 decimal string>"
      }
    ],
    "expiresAt": "<RFC 3339 timestamp; optional>"
  },
  "signer": "<base58 authorized signer>",
  "signature": "<base58 Ed25519 signature>",
  "signatureType": "ed25519"
}
```

The client sorts `entries` by the 32 raw channel-address bytes before signing.
Duplicate channel IDs are invalid. JSON is an envelope only; the signature
covers the binary message below.

This envelope requires capability negotiation at the HTTP layer. A server that
does not advertise batch-voucher support must continue requesting and accepting
version-1 single-channel vouchers.

### Signed binary message

```text
BatchVoucherArgsV2 =
    magic(2)
 || count(1)
 || expires_at(8)
 || channels_hash(32)
 || cumulative_amounts(count * 8)
```

| Offset | Size | Field | Encoding |
|---|---:|---|---|
| `0..2` | 2 | `magic` | `[0x56, 0x02]` (`'V'`, voucher format version 2) |
| `2..3` | 1 | `count` | Number of entries; `1..=MAX_BATCH_SETTLEMENTS` |
| `3..11` | 8 | `expires_at` | Unix timestamp as `i64` LE; `0` disables expiry |
| `11..43` | 32 | `channels_hash` | SHA-256 channel-list commitment |
| `43..` | `count * 8` | `cumulative_amounts` | One `u64` LE target per channel |

The exact message length is:

```text
43 + 8 * count
```

Set `MAX_BATCH_SETTLEMENTS = 60`. Sixty is the largest batch that can fit the
current 64-account transaction limit when no Compute Budget instruction is
present. Builders that include the Compute Budget program must stop at 59.

The Ed25519 instruction uses the same canonical inline layout as the current
voucher:

- `num_signatures == 1`;
- zero padding;
- public key at byte `16`;
- signature at byte `48`;
- message at byte `112`;
- all three `*_instruction_index` fields equal `u16::MAX`;
- `message_data_size == 43 + 8 * count`; and
- no prefix, suffix, second offsets record, or unparsed rider bytes.

A separate batch parser should enforce these rules. The version-1 parser must
remain fixed at one signature and a 50-byte message.

### Channel-list commitment

Compute the channel commitment as:

```text
channels_hash = SHA256(
    "payment_channels:batch_voucher:v2"
 || program_id
 || count
 || channel_id[0]
 || ...
 || channel_id[count - 1]
)
```

All fields after the fixed domain string have fixed widths:

- `program_id`: 32 bytes;
- `count`: one byte; and
- each `channel_id`: 32 bytes.

The encoding is therefore unambiguous without per-address length prefixes.
Including `program_id` prevents a batch signed for one deployment from being
interpreted by a different program ID. As with the existing voucher, the design
does not bind a cluster genesis hash; operators must keep channel state scoped
to one cluster.

The on-chain implementation can extend the existing SHA-256 helper with a
bounded `sha256v` form and hash the fixed prefix plus account-address slices.
It should not allocate a contiguous `32 * count` buffer on the BPF stack.

This commitment introduces reliance on SHA-256 second-preimage resistance. The
current voucher signs its one channel ID directly and does not need that
additional assumption.

### Instruction data and accounts

`settleBatch` carries only its discriminator. Its accounts are:

| Index | Account | Signer | Writable | Purpose |
|---:|---|:---:|:---:|---|
| 0 | Instructions sysvar | no | no | Load the immediately preceding Ed25519 instruction |
| `1..=count` | channel PDAs | no | yes | Validate and advance target watermarks |

The dynamic channel tail is the only new variable account shape. Generated
clients must require exactly `count` channel accounts after the Instructions
sysvar.

The entry at `cumulative_amounts[i]` applies only to channel account `i + 1`.
The program recomputes `channels_hash` from those account addresses, so a
relayer cannot reorder, add, remove, or substitute a channel without invalidating
the signed commitment.

### Validation algorithm

Use checked arithmetic for every offset and length calculation.

1. Require at least the Instructions sysvar and one channel account.
2. Load instruction `current_index - 1`; require the Ed25519 program ID.
3. Parse the canonical one-signature inline layout.
4. Require `magic == [0x56, 0x02]`.
5. Require `1 <= count <= MAX_BATCH_SETTLEMENTS`.
6. Require an exact message length of `43 + 8 * count`.
7. Require exactly `count` channel accounts after the Instructions sysvar.
8. Reject an expired voucher using the same rule as version 1:
   `expires_at != 0 && now >= expires_at`.
9. Require channel addresses to be strictly increasing by raw bytes. This
   rejects duplicates and pins canonical order in one pass.
10. Recompute `channels_hash` from the program ID, count, and ordered account
    addresses; require exact equality with the signed hash.
11. Validate every channel before writing any channel:
    - the account is owned by this program;
    - discriminator and version are supported;
    - `authorized_signer` equals the Ed25519 public key;
    - target is nonzero;
    - target does not exceed `deposit`; and
    - if `settled < target`, status is `OPEN`.
12. In a second pass, set `settled = target` only where `settled < target`.

Solana transactions roll back earlier writes when any instruction fails, but
the two-pass structure is still preferable: it makes the all-or-nothing rule
explicit and avoids observable partial mutation in program tests or future
refactors.

## Replay and concurrency semantics

Treat each entry as a target state, not as a command that must advance from the
state observed when the voucher was signed:

```text
settled >= target  -> already satisfied; no-op
settled < target   -> require OPEN, then advance to target
```

This differs intentionally from version-1 `settle`, which rejects a voucher at
or below the current watermark. Strict monotonic rejection is fragile for a
batch: another transaction advancing one channel would invalidate every other
entry. Target-state semantics make retries and overlapping batches safe without
authorizing additional spend.

The program still validates the signer, account type, deposit cap, ordering,
hash, and expiry for entries that are already satisfied. It must not skip those
checks merely because an entry is a no-op. Otherwise an attacker could obtain a
successful result for accounts the signer never controlled.

An already-satisfied target may be a no-op in `OPEN`, `CLOSING`, `SEALED`, or
`DISTRIBUTED`. An unsatisfied target requires `OPEN`. A deallocated channel
cannot be loaded or proven satisfied, so it invalidates the complete
transaction.

Replaying a fresh batch after all targets are satisfied succeeds without state
changes. Replaying an expired batch fails, even if every target is already
satisfied. This preserves the existing meaning of voucher expiry and prevents
an expired authorization from producing a fresh successful execution result.

## Adversarial analysis

| Attack or failure | Required behavior |
|---|---|
| Relayer changes an amount | Signature verification fails because all amounts are in the signed message. |
| Relayer substitutes, reorders, adds, or removes a channel | Recomputed `channels_hash` differs or `count`/length validation fails. |
| Relayer repeats one channel account | Strict address ordering rejects the duplicate. |
| Batch contains different authorized signers | Per-channel signer validation fails the complete batch. |
| Signature is valid under an unrelated key | Every channel compares the parsed Ed25519 public key with its stored `authorized_signer`. |
| Voucher targets a different program deployment | `program_id` changes the channel commitment. |
| Voucher is replayed on another cluster with identical addresses | Possible, as with version 1; cluster-scoped operation remains mandatory. |
| Target exceeds a channel deposit | The complete batch fails before mutation. |
| Target is zero | The complete batch fails; zero targets provide no settlement value and can only pad a batch. |
| One target was settled by another transaction | That entry is a no-op; other valid entries can advance. |
| One unsatisfied channel is `CLOSING`, `SEALED`, or `DISTRIBUTED` | The complete batch fails; batch settlement cannot bypass state transitions. |
| One channel was deallocated after signing | Account loading fails and poisons the batch. The relayer must preflight and use a newer batch. |
| Malformed count causes an offset overflow or truncated amount | Checked exact-length validation fails before any field slice or account write. |
| Ed25519 instruction contains extra signatures or rider bytes | Canonical parser rejects it even if the precompile accepted the valid first signature. |
| Ed25519 offsets point into another instruction | Canonical parser rejects every non-`u16::MAX` instruction index. |
| Hash collision substitutes another ordered channel list | Security reduces to SHA-256 second-preimage resistance; no practical attack is known, but this is a new assumption. |
| Transaction fails after the Ed25519 precompile succeeds | Solana transaction atomicity leaves every channel unchanged; the fee payer still pays the failed transaction fee. |
| Malicious signer creates an oversized or poisoned batch | `MAX_BATCH_SETTLEMENTS`, exact lengths, and normal transaction limits bound program work; the signer can still create an economically useless batch that no relayer should submit. |

### Signer compromise and signing UX

The batch does not increase the authority of a compromised
`authorized_signer`: that key can already sign a maximum cumulative voucher for
each channel. It increases the number of channels affected by one signing
action. Client software should display every channel and target, reject hidden
or duplicate entries, and cap the batch at `MAX_BATCH_SETTLEMENTS` before asking
for a signature.

### Mixed payees

Channels in one batch may have different payees because `settle` only advances
authorization state; it does not transfer or distribute tokens. Any relayer may
submit the permissionless instruction. Each channel's stored distribution
configuration still controls eventual payout.

Batching mixed payees links those channels in one transaction and one signature.
The shared `authorized_signer` is already stored on chain, but the batch reveals
that the targets were coordinated at the same time.

### Writable-account contention

The transaction write-locks every channel in the batch. Larger batches have a
higher chance of colliding with `settle`, `settleAndSeal`, `requestClose`, or
another batch, and each writable account contributes scheduler cost. Operators
should choose batch sizes from observed inclusion and retry behavior rather
than always filling the theoretical maximum.

## Packing estimate

[Solana currently limits a transaction to 1,232 bytes and 64
accounts](https://solana.com/docs/core/transactions#limits). The following
measurements use this repository's `solana-message` version-0 compiler and
assume:

- a version-0 transaction;
- one fee-payer signature;
- one address lookup table containing the Instructions sysvar and every channel;
- static payment-channel, Ed25519, and Compute Budget program IDs;
- one compute-unit-limit instruction;
- one Ed25519 instruction; and
- one `settleBatch` instruction.

| Shape | Approximate serialized size | Limiting factor | Estimated channels |
|---|---:|---|---:|
| Current `[ed25519, settle] * N` | `275 + 173N` | 1,232-byte packet | 5 |
| One signature over full `(channel_id, amount)` entries | `407 + 42N` | 1,232-byte packet | 19 |
| One signature over `channels_hash` plus amounts | `439 + 10N` | 64 transaction accounts | 59 |

For the committed design, the fixed transaction accounts are the fee payer,
three program IDs, and the Instructions sysvar. That leaves 59 channel accounts
when the Compute Budget program is present:

```text
4 static accounts + 1 loaded Instructions sysvar + 59 loaded channels = 64
```

Without a Compute Budget instruction, 60 channels fit and the serialized
transaction is 999 bytes. The measured boundary cases with a Compute Budget
instruction are:

```text
current pairs:   N=5  -> 1,140 bytes; N=6  -> 1,313 bytes
full-entry batch: N=19 -> 1,205 bytes; N=20 -> 1,247 bytes
committed batch: N=59 -> 1,029 bytes / 64 accounts
                 N=60 -> 1,039 bytes / 65 accounts
```

These figures validate the proposed shape against the current SDK; they are not
permanent protocol constants. The implementation must pin the boundary in
generated-client tests and revalidate it when SDK or cluster limits change.

The current benchmark reports 574 program CUs for one `settle`, excluding any
future loop and commitment implementation. A batch should remove repeated
Clock, Instructions-sysvar, and instruction-dispatch work, and it performs one
Ed25519 verification. Benchmark `N = 1, 16, 32, 59, 60` before selecting the
SDK default batch size.

## Trade-offs and rejected alternatives

### Keep packing independent settlement pairs

This preserves the current protocol and supports unrelated signers, but repeats
162 bytes of Ed25519 instruction data per voucher. Transaction size remains the
binding constraint at about five channels.

### Put every channel ID directly in the batch message

This is simpler because the signature directly covers `(channel_id, amount)`
pairs. Each entry costs 40 message bytes plus an account index, limiting a
transaction to about 19 entries. The proposed commitment reuses channel
addresses already supplied as account metas and raises the limit to the
high-50s at the cost of one SHA-256 commitment and its collision-resistance
assumption.

### Put several independent signatures in one Ed25519 instruction

The [Ed25519 precompile supports multiple signatures in one
instruction](https://solana.com/docs/core/programs/precompiles#verify-ed25519-signature),
but verification cost still scales with the signature count and each signer
still needs a public key and 64-byte signature. This slightly reduces framing
bytes; it does not approach one-signature batch density.

### Give every entry an independent expiry

Per-entry expiries let channels use different settlement windows, but add eight
signed bytes per channel and complicate retry decisions. One batch-level expiry
keeps the wire compact and gives the authorization one clear validity window.
The trade-off is coupling: the shortest acceptable window applies to every
entry, and an expired batch must be re-signed in full.

### Sign a Merkle root and redeem subsets

A Merkle root would let relayers omit closed or unrelated entries and redeem
different subsets independently. Each redeemed entry would need a Merkle proof,
which adds roughly `32 * ceil(log2(N))` bytes per entry unless the program and
client implement multiproofs. Multiproofs add substantial parser, canonical
ordering, and security complexity. They are useful only if partial redemption
becomes a requirement; they are a poor first design for settling the complete
batch.

### Use the authorized signer as a transaction signer

A transaction signature would cover every channel without an Ed25519
precompile, but recent blockhash expiry prevents storing it as an off-chain
voucher for later permissionless relay. Durable nonce transactions introduce a
nonce account, mutable nonce state, and transaction-level coordination. They do
not replace a portable batch voucher.

### Allow invalid entries to be skipped

Skipping wrong signers, over-deposit targets, malformed accounts, or
unsatisfied non-`OPEN` channels would make a successful transaction ambiguous
and could hide client or relayer bugs. Only an already-satisfied target is a
safe no-op. Every other invalid entry fails the complete batch.

## Compatibility

- `settle` and `[0x56, 0x01]` vouchers remain unchanged.
- `settleAndSeal` continues to accept only its optional version-1 voucher or
  metered pair (`has_voucher == 2`); it does not accept batch vouchers.
- `settleBatch` uses a new discriminator and `[0x56, 0x02]` message.
  Discriminator `10` is taken by `settleMetered`, and `[0x56, 0x03]` /
  `[0x56, 0x04]` by the metered cap and claim. See the
  [voucher magic registry](./003-program-instructions.md#voucher-magic-registry).
- Existing clients can ignore the new instruction.
- Batch-capable clients and servers must negotiate the off-chain envelope and
  persist the complete ordered entry list with the signature.
- A server cannot synthesize a batch signature from previously accepted
  single-channel vouchers.

## Implementation and review gates

Do not enable batch vouchers in production until all of these gates pass:

1. Add a dedicated batch Ed25519 parser with exhaustive offset, count, length,
   magic, and rider-byte tests.
2. Add unit tests for deterministic sorting, commitment construction, and
   binary encoding in Rust and TypeScript.
3. Add end-to-end tests covering maximum size, duplicate accounts, reordered
   accounts, wrong signer, mixed signers, expiry boundaries, over-deposit
   targets, status races, replay, and deallocated accounts.
4. Add property tests asserting that any change to an entry, amount, order,
   count, program ID, or account list changes verification outcome.
5. Serialize real legacy and version-0 transactions at every supported batch
   size; pin the largest valid transaction and the first oversize transaction.
6. Benchmark compute and scheduler behavior at `N = 1, 16, 32, 59, 60`,
   including the SHA-256 vector syscall and one Ed25519 verification.
7. Run an external security review focused on parser differentials between the
   Ed25519 precompile and program introspection, target-state replay semantics,
   and account-list commitment.
8. Update ADR-001, ADR-002, ADR-003, generated clients, HTTP capability
   negotiation, and operator preflight rules only after the implementation and
   tests define the final wire contract.
