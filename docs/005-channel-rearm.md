# ADR-005: Channel Re-Arm

**Status:** Proposed future work — not implemented

**Parent ADRs:** [ADR-001](./001-payment-channel-state-machine.md),
[ADR-002](./002-http-protocol.md), [ADR-003](./003-program-instructions.md),
[ADR-004](./004-batch-voucher-settlement.md)

## Context

A session between a recurring payer↔payee pair currently ends with a full
channel teardown and the next session starts with a full channel build:

```text
open                         36,086 scheduler cost units (mainnet p50)
settle_and_seal + distribute 23,875
reclaim (batched 8/tx)          748
                             ------
per-session boundary         60,709
```

98.8% of that is `open` plus the terminal close — account creation and
destruction, not settlement. At one million logical payments per second the
block cost budget grants about 125 units per payment (250M units/s nominal at
a 50% availability assumption), so a channel must amortize its boundary over
`⌈60,709 / 125⌉ = 486` payments. For a 60-requests-per-minute user that forces
a minimum session window of ~8 minutes. No scheduled network upgrade changes
this: slot-time reductions preserve ~250M units/s by construction, rent
reduction is working capital, and larger transactions are bytes. The boundary
constant is the wall.

The teardown/rebuild cycle also wastes what the epoch-addressed design of
[PR #77] made cheap but not free: every re-open re-derives and re-creates the
same channel PDA shape and escrow ATA for a relationship that both parties
intend to continue.

Three per-session obligations force the boundary today:

1. the payee wants the session's final voucher enforced and paid out;
2. the payer wants the unspent remainder of their deposit back; and
3. both sides want the next session to start from a clean risk position.

None of these requires destroying and recreating accounts. Interim `settle`
and OPEN-state `distribute` already exist; the only thing that today requires
a terminal close is (2), the payer refund.

## Goals

- End a session and start the next one on the same channel accounts: enforce
  the final voucher, pay all pending distribution deltas, refund the payer's
  unspent deposit, and leave the channel `OPEN` — in one instruction.
- Preserve the version-1 voucher format, the ADR-004 batch voucher, the replay
  argument, and the `payout_watermark ≤ settled ≤ deposit` invariant unchanged.
- Keep the terminal close path (`settleAndSeal`/`seal` → `distribute` →
  `reclaim`) fully available and unmodified.
- Require no `Channel` layout change and no new voucher wire format.

## Non-goals

- Reset or rewind watermarks. Watermarks are cumulative for the life of the
  channel address, across sessions.
- Rotate `authorized_signer`, `payer`, `payee`, `mint`, or the distribution
  split. All are PDA seeds or hash-committed at `open`; changing any of them
  means opening a new channel.
- Batch re-arms across channels (see Rejected alternatives).
- Fund the next session in the same instruction (see Rejected alternatives;
  `topUp` remains the funding path).
- Standardize the MPP/x402 session-continuation envelope as part of the
  on-chain change (capability negotiation belongs to ADR-002).

## Proposed design

### Key decision: sessions are watermark ranges, not epochs

The instinctive design — reset `settled` to zero per session and bind vouchers
to a stored epoch counter — is rejected (see Rejected alternatives). Instead,
**nothing about voucher semantics changes**: `settled` and `payout_watermark`
remain strictly cumulative over the channel's whole life, and a *session* is
simply the off-chain range `(settled_at_previous_rearm, settled_at_this_rearm]`.
Replay protection remains exactly the ADR-001 argument: per-incarnation
address plus strictly monotonic cumulative watermark. There is no new signed
payload, no magic byte, and no second voucher parser.

### The `rearm` instruction

`rearm` executes, atomically, on an `OPEN` channel:

1. **Optional voucher application** — identical rules to `settleAndSeal`'s
   optional voucher: preceding canonical Ed25519 instruction, 50-byte
   version-1 message, signer equals `authorized_signer`, fresh†,
   `settled < cumulative_amount ≤ deposit`; then `settled := cumulative_amount`.
2. **Distribution** — identical to OPEN-state `distribute`: verify the splits
   preimage against `distribution_hash`, pay cumulative floor deltas between
   `payout_watermark` and `settled` to each recipient and the payee's implicit
   remainder, advance `payout_watermark := settled`. Floor-rounding dust stays
   in escrow (it remains claimable by later cumulative crossings; there is no
   treasury sweep — the channel is not closing).
3. **Payer refund** — transfer `deposit − settled` from escrow to the payer's
   canonical ATA, then set `deposit := settled`.

The channel remains `OPEN` with `payout_watermark = settled = deposit`, the
escrow ATA holding only floor dust (plus any unrecorded third-party prefunds,
whose treatment is unchanged from ADR-001's accounting-authority rule). The
next session begins when the payer `topUp`s and signs vouchers strictly above
the standing watermark — which their client already tracks.

**Authority.** `rearm` requires the `payee` signer, exactly like
`settleAndSeal`, because it carries the same self-forfeiture semantics: a
payee who re-arms while holding a higher unsettled voucher caps that voucher
at `deposit = settled` and forfeits the difference unless the payer funds
again — the payee is the only party entitled to make that call. It is not a
permissionless crank: the refund and forfeiture decisions need the payee's
explicit consent, and the payer's exit path (`requestClose` → grace → `seal`)
is untouched.

**FSM addition:**

```text
OPEN --> OPEN: rearm
```

`rearm` is invalid from `CLOSING` (it must not override a payer's declared
exit intent — the existing `settleAndSeal`-before-deadline path covers
cooperative closure from `CLOSING`), from `SEALED`, and from `DISTRIBUTED`.
`closure_started_at` and `payer_withdrawn_at` are untouched (both are zero in
`OPEN`).

### Accounts and args

Accounts mirror `distribute`'s shape plus the payer refund ATA:

| Index | Account | Signer | Writable | Purpose |
|---:|---|:---:|:---:|---|
| 0 | payee | yes | no | Authorizes forfeiture + refund semantics |
| 1 | channel PDA | no | yes | Watermarks, deposit |
| 2 | escrow ATA | no | yes | Source of payouts and refund |
| 3 | mint | no | no | `TransferChecked` |
| 4 | payer refund ATA | no | yes | Receives `deposit − settled` |
| 5 | token program | no | no | SPL Token or Token-2022 |
| 6 | Instructions sysvar | no | no | Optional voucher introspection |
| 7.. | payee ATA + recipient ATA tail | no | yes | Cumulative floor deltas, preimage order |

Instruction data: discriminator, a voucher-present flag, and the canonical
splits preimage (`count (u32 LE) || [recipient || bps] × count`), exactly as
`distribute` carries it.

### Validation algorithm

Use checked arithmetic throughout.

1. Require channel status `OPEN`, discriminator/version supported.
2. Require the `payee` signer to equal `Channel.payee`.
3. If the voucher flag is set: load instruction `current_index − 1`, require
   the canonical single-signature Ed25519 layout with a 50-byte message,
   `magic == [0x56, 0x01]`, `channel_id` equal to the channel PDA, signer
   equal to `authorized_signer`, freshness†, and
   `settled < cumulative_amount ≤ deposit`; apply `settled := cumulative_amount`.
4. Verify the splits preimage hash against `distribution_hash`; require the
   recipient account tail to match the preimage in length and order.
5. Require work to exist: at least one of (a voucher was applied),
   `settled > payout_watermark`, or `deposit > settled`. Reject a no-op.
6. Validate every token account it touches (escrow, payer refund ATA, payee
   ATA, each recipient ATA) under the ADR-001 token-validation rules.
   **The payer refund ATA hard-fails if unusable** — no treasury redirect
   (see Adversarial analysis).
7. Pay cumulative floor deltas; advance `payout_watermark := settled`.
8. Transfer `deposit − settled` to the payer refund ATA; set
   `deposit := settled`.
9. Emit a `Rearmed` event carrying the closing watermark so indexers can
   delimit the session range.

† freshness as in ADR-001: `expires_at == 0 || now < expires_at`.

## Replay and concurrency semantics

- **Old vouchers stay dead.** Every voucher at or below the standing `settled`
  is rejected today and remains rejected; `rearm` never lowers `settled`.
- **The late-settle window.** An *unsettled* voucher from a previous session
  with `cumulative_amount > settled` is momentarily unsatisfiable after
  `rearm` (it exceeds `deposit = settled`) but becomes satisfiable again once
  the payer `topUp`s past it. This is not a replay — it is a genuine,
  payer-signed cumulative authorization being enforced late, with value the
  payer authorized and never paid. It is, however, an accounting surprise for
  an off-chain layer that believes sessions are sealed. Servers operating
  re-armable flows MUST therefore set `expires_at` on vouchers to no later
  than the session's intended settlement deadline, and SHOULD treat a voucher
  from a closed session range as reconciliation input, not fresh revenue.
  (ADR-002 addition, gated below.)
- **Races.** `settle`/`settleBatch` landing before `rearm` only raises
  `settled`; `rearm`'s voucher then either still advances or is rejected as
  stale, exactly like `settleAndSeal` today. `topUp` landing between voucher
  signing and `rearm` raises `deposit`; the refund is computed on-chain at
  execution (`deposit − settled`), so the payer's added funds come straight
  back — harmless. `requestClose` landing first moves the channel to
  `CLOSING` and `rearm` rejects. Two `rearm`s racing: the second finds either
  no-op (rejected by step 5) or residual refund work — never a double payout,
  because deltas and refund are both computed from on-chain state.
- **Invariant.** `payout_watermark ≤ settled ≤ deposit` holds after every
  step: step 7 makes `payout_watermark = settled`; step 8 makes
  `deposit = settled`. Property tests below must assert it across arbitrary
  instruction interleavings.

## Adversarial analysis

| Attack or failure | Required behavior |
|---|---|
| Payee re-arms while holding a higher unsettled voucher | Self-forfeiture, identical in kind to sealing at the current watermark today; payee signature makes it consensual. |
| Payee re-arms to deny split recipients | Impossible: floor deltas up to `settled` are paid before the refund; recipients lose nothing they were entitled to. |
| Payee uses `rearm` to strand the payer's funds | Impossible: the instruction's only lamport/token flows are *toward* recipients, payee, and the payer refund ATA. |
| Payee re-arms with an unusable payer refund ATA | Hard failure. Unlike terminal `distribute` (permissionless, must make progress, redirects to treasury), `rearm` is optional sugar initiated by the payee — it must never convert the payer's refund into treasury revenue. The payee falls back to plain `settle` + OPEN-state `distribute`, or the terminal path where the redirect rules and the payer's grace-period agency already apply. |
| Attacker replays an old session's settled voucher | `cumulative_amount ≤ settled` — rejected, unchanged from ADR-001. |
| Merchant hoards an unsettled voucher and enforces it sessions later | Possible until `expires_at`; bounded by the mandatory expiry policy above; value was payer-authorized. |
| Third-party escrow prefunds | Unchanged: not recorded in `deposit`, not refunded by `rearm` (refund uses channel state, never balances), swept to treasury only at terminal close per ADR-001. |
| `rearm` from `CLOSING`/`SEALED`/`DISTRIBUTED` | Rejected; state machine authority unchanged. |
| Repeated/racing `rearm` | Second execution rejects as no-op or performs only remaining refund; no double spend (all amounts derived from current on-chain state). |
| Arithmetic edge: `deposit − settled` | Never underflows (`settled ≤ deposit` is a standing invariant); zero refund is legal when combined with distribution work. |

## Cost planning envelope

Deliberately pessimistic, same discipline as ADR-004 (constants from the
Agave cost model; execution anchored to the measured mainnet interim
`distribute` of 11,328 CUs plus a validated refund leg):

```text
2 transaction signatures (payee + fee payer)   1,440
1 Ed25519 voucher verification                 2,400
7 writable locks (fee payer, channel, escrow,
  payee ATA, refund ATA, 1 recipient ATA, …)   2,100
instruction data (~215 B / 4)                     54
execution: distribute-shape validation +
  2 TransferChecked + watermark/deposit ops  ~13,000
                                              ------
rough upper envelope                         <19,000 cost units
```

With `topUp` for the next session (~10,200 cost units in the same
accounting: 720 + 4 locks + 8,267 measured execution + data), the recurring
session boundary becomes:

```text
rearm + topUp        ≈ 29,200 cost units
vs open + close + reclaim  60,709          → 2.1× cheaper (3.2× excluding topUp)
```

The one-time `open` and eventual terminal close amortize over the channel's
whole life, and the accounting must not double-charge the last session: a
channel hosting K sessions pays `open` once, **K − 1** re-arm boundaries (the
final voucher of sessions 1..K−1 rides `rearm`; the next deposit rides
`topUp`), **one** terminal close carrying the last session's voucher (23,875
measured), and one reclaim. Per session:

```text
lifecycle(K) = [ 36,086 + (K − 1) × 29,200 + 23,875 + 748 ] / K
             = 29,200 + 31,509 / K
```

At K = 1 this degenerates exactly to today's lifecycle (60,709 cost units —
zero re-arms occur), so **re-arm is never worse than close-and-reopen and
strictly better for every K > 1**. The overhead term is ~315 units at
K = 100 and vanishes asymptotically. Simulations must use this form: the
naive `boundary + (open + close + reclaim) / K` charges session K for both a
re-arm and the terminal close and wrongly shows re-arm *losing* to
close-and-reopen at small K.

**Capacity implication.** At 1M logical payments/s and a 125M units/s
available budget, the minimum session window at 60 RPM per user drops from
`486 payments ≈ 8.1 min` to `⌈29,200 / 125⌉ = 234 payments ≈ 3.9 min`.
Re-arm alone does not buy one-minute *boundaries*; it is the
capital-recycling plane of the decoupled cadence architecture (vouchers for
risk, interim/batch `settle` for enforceability, lazy `distribute` for cash),
where the payer's idle deposit is reclaimed at whatever cadence capital
efficiency demands without ever paying the account-lifecycle toll. As with
ADR-004, shared parsing should beat the envelope's summed parts; the numbers
above are planning bounds, not benchmarks.

## Trade-offs and rejected alternatives

### Epoch reset (stored epoch counter + voucher epoch field)

Reset `settled` per session, add `epoch` to `Channel`, and bind vouchers to
`(channel_id, epoch)` via a new `[0x56, 0x03]` message. Rejected: it
introduces a second voucher wire format and parser, splits the client
ecosystem, requires capability negotiation for the *signing* path (not just
serving), and — decisively — reopens the cross-incarnation replay analysis
that the epoch-addressed design of PR #77 closed by construction. The
cumulative-watermark design achieves the same amortization with zero wire
change and an unchanged replay argument. What epoch reset would additionally
buy — re-keying `authorized_signer` or changing splits per session — is
already excluded by PDA seeds and the hash commitment, and is properly served
by opening a new channel.

> The `[0x56, 0x03]` magic named above was never allocated by this design.
> It is now the metered cap voucher; see the
> [voucher magic registry](./003-program-instructions.md#voucher-magic-registry).
> A revived epoch-reset design would need a new format byte.

### Fold `topUp` into `rearm`

One instruction, one round trip. Rejected: it requires payer and payee
signatures in the same transaction, coupling both parties' liveness at every
boundary and breaking the pre-signed/relayed flows that payee-only authority
allows. The two-instruction sequence also lets the payer fund on their own
schedule (or not at all, ending the relationship with zero further cost).

### Permissionless `rearm`

Rejected. The refund-and-forfeit decision must not be grantable to third
parties: a relayer could otherwise cap a merchant's outstanding voucher the
instant a session's watermark lands. Payee-signer authority mirrors
`settleAndSeal`, the instruction whose semantics `rearm` extends.

### Allow `rearm` from `CLOSING`

Rejected: `requestClose` is the payer's declared exit; a payee override that
returns the channel to `OPEN` — even with a full refund — keeps alive an
address the payer asked to wind down and re-opens the grace-period clock
games ADR-001 deliberately avoids.

### Sweep dust at `rearm`

Rejected: OPEN-state accounting keeps floor-rounding residue claimable when a
share's cumulative entitlement crosses the next whole unit; sweeping at every
boundary would silently confiscate it session by session. Dust is swept once,
at terminal close, as today.

### Batch `rearm` across channels

Deferred. Unlike `settleBatch` (state-only), `rearm` moves tokens: each
channel contributes several writable token accounts, capping a batch at
roughly 5–8 channels per transaction — worth an ADR only if boundary volume
demands it after this lands.

## Compatibility

- `Channel` layout: **unchanged** — no new fields, no version bump, no
  migration. All live channels become re-armable at program upgrade; this is
  safe because `rearm` grants the payee nothing more harmful than
  `settleAndSeal` already does, and grants the payer an early refund.
- Voucher format: version-1 `[0x56, 0x01]` unchanged; ADR-004's batch voucher
  unchanged and composes (a batch `settle` may advance the watermark that a
  later `rearm` distributes).
- New discriminator; existing clients ignore it.
- ADR-002 (HTTP): requires a capability flag for session continuation, the
  mandatory `expires_at` policy for re-armable flows, and a session-range
  convention (`channel_id` + closing watermark from the `Rearmed` event) for
  metering and receipts.

## Implementation and review gates

Do not enable in production until all of these pass:

1. Unit tests for every validation step, including the no-op rejection and
   both voucher-present and voucher-absent paths.
2. An interleaving matrix: `rearm` against `settle`, `settleBatch`, `topUp`,
   `requestClose`, `distribute`, and a second `rearm`, in both orders.
3. Property tests asserting `payout_watermark ≤ settled ≤ deposit` and
   no-value-creation across arbitrary instruction sequences.
4. Explicit late-settle tests: unsettled voucher above the re-armed deposit,
   re-funded past it, settled — and rejected once expired.
5. Refund-leg token-validation tests: frozen, closed, reassigned, and
   non-canonical payer ATAs must hard-fail without state mutation.
6. CU benchmark at recipient counts 0, 1, 4, 16, 32 against the envelope
   above; pin the measured numbers into `bench_report.md`.
7. External security review focused on the refund leg, the late-settle
   window, and payee-authority forfeiture semantics.
8. Update ADR-001 (FSM + guards table), ADR-002 (capability + expiry policy),
   ADR-003 (instruction reference), and generated clients only after the wire
   contract is pinned by tests.

[PR #77]: https://github.com/solana-foundation/payment-channels/pull/77
