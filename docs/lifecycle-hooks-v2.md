# Lifecycle hooks V2 ABI

V2 adds four immutable optional callbacks inside channel funding and distribution.
This is an experimental program ABI deployed on devnet; see the
[deployment record](devnet-v2-deployment.md). A successful build is not proof of
issuer integration. There is no Coinflow production adapter or issuer ABI in
this implementation.

## Select a deployment explicitly

| Build | Program ID | Channel bytes |
| --- | --- | --- |
| Default V1 | `CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX` | 256 |
| Feature `v2` | `CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ` | 1121 |

```sh
just build-v2-localnet
cargo test -p payment_channels --lib --features v2
just build-v2-devnet
```

Localnet V2 artifacts go to `target/deploy-v2/payment_channels.so`; devnet V2
uses `target/deploy-v2-devnet/payment_channels.so`. Default recipes continue
to build V1. Devnet uses the existing devnet treasury owner
`4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap`. Localnet keeps its test sentinel.
These commands do not deploy anything.

The V2 recipes pin platform-tools `v1.58` and `--arch v3`; the callback test
adapter uses the same compiler and SBF architecture. SBF v3 is the executable
instruction set, separate from channel ABI V2 and callback ABI 1. The default
`cargo build-sbf` architecture is v0 and must not be used for this deployment.
Run `just test-v2-hooks` to execute the v3 artifacts, not only native unit tests.
The test runtime uses LiteSVM 0.13.1 or later to support this v3 ELF format.

V2 retains instruction discriminators, channel PDA seeds, and voucher bytes.
The different program ID separates channel addresses and therefore vouchers.
V1 rejects the V2 owner/layout; V2 rejects V1 owner/layout. V2 `open` requires
explicit configuration bytes even when all four slots are disabled.

## Lifecycle boundaries

| Slot | Phase byte | Operations |
| --- | --- | --- |
| `preFund` | 0 | `open` (1), `topUp` (3), before deposit transfer |
| `postFund` | 1 | Same, after transfer and deposit accounting |
| `preDistribute` | 2 | `distribute` (7), `withdrawPayer` (8), before transfers |
| `postDistribute` | 3 | Same, after transfers/accounting, before escrow cleanup |

Configured hooks run on eligible zero-refund operations too. Open and top-up
amounts must remain positive. Duplicate withdrawals and open-channel
distributions with no newly settled watermark fail before hooks. Settle,
settle-and-seal, request-close, seal and reclaim never invoke hooks.

A pre/post error rolls back the whole transaction, including channel creation
and changes made by callbacks. Transaction fees are not rolled back.

## Public immutable configuration

The first 256 bytes retain V1 field offsets, except `version = 2`.

| Offset | Size | Field |
| --- | --- | --- |
| 256 | 1 | Guard: 0 idle, 1 operation in progress |
| 257 | 8 | Operation sequence, unsigned little-endian |
| 265 | 32 | Configuration commitment |
| 297 | 824 | Four 206-byte descriptors in phase order |

Each descriptor is:

| Relative offset | Size | Field |
| --- | --- | --- |
| 0 | 32 | Target program |
| 32 | 8 | Callback entrypoint bytes |
| 40 | 1 | Additional account count, 0–4 |
| 41 | 1 | Static-context length, 0–32 |
| 42 | 32 | Static context, zero-padded |
| 74 | 132 | Four `(address[32], writable u8)` entries |

A disabled descriptor is entirely zero. Unused static bytes and account entries
are zero. Writable is exactly 0 or 1. Additional accounts never sign. Duplicate
additional addresses are forbidden. Target zero and the channel program itself
are forbidden for enabled descriptors.

The commitment is `SHA256(descriptors[0] || ... || descriptors[3])`, exactly
824 bytes, without a prefix. The full preimage is on-chain, not held by an
operator. No instruction can modify the configuration.

### Compact opening encoding

Append four slots after V1's complete `open` payload, including its distribution
preimage. A slot is a one-byte enable tag:

- `0`: no further bytes for this slot.
- `1`: `program[32] | entrypoint[8] | account_count u8 | static_len u8 |
  static_context[static_len] | (address[32] | writable u8) × account_count`.

Reject other tags, truncated fields, oversized lengths and trailing bytes.
An unhooked V2 opening appends four zero bytes.

### Operation account tails

Keep the existing fixed account head. `distribute` additionally takes exactly
the committed recipient count before any hook accounts. Then append each
enabled descriptor in the operation's pair, in phase order:

```text
target_program, callback_authority, extra_account_0, ... extra_account_n
```

Disabled slots consume no accounts. Open has 14 fixed accounts; top-up and
withdrawal have 6; distribute has 11 plus its recipient count. The complete
pair's count, addresses, executability and requested privileges are checked
before its first callback.

## Capability and callback ABI

Derive the callback authority under the V2 program ID:

```text
[b"channel_hook", channel_address, configuration_commitment,
 phase_as_one_byte, target_program]
```

The channel address already identifies the incarnation. The channel program
signs only with this scoped PDA; it never forwards the escrow-owning channel
PDA signer. Callback CPI accounts are:

1. Callback authority: readonly, signer.
2. Channel: readonly, not signer.
3. Committed additional accounts: exact writable flags, never signers.

Extras cannot alias the channel, current callback authority or callback target.
Outer payer, sponsor and rent-payer signing privileges are not inherited.
Permissionless distribution therefore needs no new customer signature.

Instruction bytes are `entrypoint[8] | HookContext | static_len u8 |
static_context[static_len]`. `HookContext` is 428 bytes in this Borsh order,
all integers little-endian:

```text
abi_version u8 = 1
phase u8
operation u8                 # actual instruction discriminator
executed u8                  # 0 pre, 1 post
channel[32]
sequence u64
open_slot u64
payer[32]
payee[32]
mint[32]
token_program[32]
configuration[32]
authorized_signer[32]
distribution_hash[32]
deposit_before u64
settled_before u64
payout_before u64
withdrawn_before i64
funding_requested u64
merchant_due u64
refund_due u64
funding_transferred u64
merchant_transferred u64
refund_transferred_to_payer u64
redirected_principal u64
treasury_surplus u64
deposit_after u64
payout_after u64
withdrawn_after i64
refund_destination[32]
```

Pre contexts contain planned `*_requested`/`*_due` fields, zero executed-transfer
fields, and unchanged `*_after` accounting. Post contexts report completed
transfers and accounting. `merchant_due` is the sum of cumulative floor deltas,
not the entire newly settled watermark. `merchant_transferred` excludes
redirected shares. `treasury_surplus` is final rounding dust and donated excess,
not refundable principal. The refund destination is the canonical payer ATA,
including zero-refund operations. For an unhooked redirected payer refund it
records treasury instead.

The sequence starts at 1 on opening and increments for each eligible funding or
distribution operation. Failure rolls it back. Replay identity is
`(channel, configuration, sequence, operation, phase)`. Adapters must retain any
issuance replay records they need after terminal channel cleanup.

## Safety and adapter responsibilities

Every entrypoint checks the in-progress guard. It remains set through post-hook
validation and terminal cleanup. No data borrow is held over callback CPI.
Canonical token accounts are reloaded after callbacks, and hooks may not change
escrow balances. Direct donations outside protocol funding remain surplus.

Any configured hook makes positive payer refunds strict: an unusable canonical
payer ATA fails instead of redirecting principal to treasury. Merchant payout
redirects retain the existing policy and are represented separately in context.
No hook-skipping flag or alternate instruction bypass exists.

A scoped signer is a capability, not proof of an immediate caller. An adapter
must verify its exact authority, context bindings and replay domain; a nested
CPI can carry signer privilege onward. A post hook restoring credits must
require the actual issuer update to succeed and must not leave the same
backing principal freely spendable by the customer. The callback PDA does not
automatically own or delegate authority over the payer's token account.

The payer and rent sponsor approve configuration at opening. Merchants must
accept the hook programs' upgrade authorities and failure behavior before
serving the channel. A broken or paused mandatory hook can block funding,
payout and refund; the protocol provides no policy bypass.

## Resource limits and remaining release checks

Each callback has at most 6 CPI metas: capability, channel and 4 extras.
Static data is at most 32 bytes; the full callback payload is at most 469 bytes.
Only one callback per phase is supported. Sparse opening configuration is
bounded by 828 bytes before the normal opening arguments. Those individual
bounds do not guarantee a transaction fits Solana's packet limit: clients must
measure the complete signed transaction, including account addresses and
signatures. Address lookup tables do not compress instruction-data bytes.

Before release, run SBF integration tests with a failure-injecting test adapter
and nested issuer/token calls, check rollback for every phase/operation,
permissionless tails, aliases, signer leakage, strict refund failures,
zero-refund/prior-withdrawal paths, replay and terminal cleanup. Measure complete
transaction size, compute use and CPI depth. Generate distinct V2 IDL/client
artifacts while retaining default V1 outputs. These are release gates, not
claims made by the current ABI document.
