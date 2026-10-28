# Token-backed credit provider example

This Rust program converts deposited SPL tokens into credits, spends those credits
through V2 payment-channel hooks, and restores credits only after recovering actual
refund tokens. It is a local testing and integration example, not a production-ready
custodian, security certification, or endorsement of any provider.

## Build

From the repository root, keep the executable channel and provider dependency
builds in separate target directories:

```sh
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
CARGO_TARGET_DIR="$CARGO_TARGET_DIR/channel-sbf" cargo build-sbf \
  --manifest-path program/payment_channels/Cargo.toml \
  --sbf-out-dir "$PWD/target/deploy-v2" --arch v3 --tools-version v1.58
CARGO_TARGET_DIR="$CARGO_TARGET_DIR/provider-sbf" cargo build-sbf \
  --manifest-path examples/credit-provider/Cargo.toml \
  --sbf-out-dir "$PWD/target/deploy" --arch v3 --tools-version v1.58
cargo test --manifest-path examples/credit-provider/Cargo.toml --features client
```

The example has its own small Cargo workspace. Its program dependency enables only
`no-entrypoint`: it imports the real channel state, canonical program ID, operation
discriminators, hook descriptor types and callback context, without linking a
second entrypoint. Token and associated-token IDs come from the same Pinocchio
crates used by the channel program. No devnet deployment is needed.

The default channel runtime supports both ordinary 256-byte channels and hooked
1121-byte channels. Hooked funding and refund instructions use outer tags 10–13;
callbacks retain economic operation tags 1/3/7/8. The example deliberately does
not enable `devnet-deployment`, which selects an alternate program address.

`no-entrypoint` suppresses only the channel entrypoint on SBF; the channel library
still supplies its no-allocation runtime and panic handler. An SBF consumer must
not define duplicate allocator or panic handlers. On host targets this feature
links `std` so the dependency's declared `cdylib` can link for client tests.
Default channel builds are unchanged. This is a narrow example integration,
not a general-purpose runtime-independent interface crate.

## Transaction flow

1. Deploy both SBF programs on a local Surfpool validator. Keep the example
   upgradeable, with an ephemeral test issuer as its upgrade authority.
2. Create an original SPL Token mint, the owner's canonical ATA, and the canonical
   vault ATA owned by `ledger_address(example_program, owner, mint)`.
3. Call `client::initialize`, signed by owner and issuer. Initialization reads
   the loader-owned executable and its referenced ProgramData account to verify
   the issuer. A first caller cannot choose an arbitrary issuer. Rent top-up and
   signed allocation/assignment tolerate third-party lamport donations to the
   uninitialized ledger PDA.
4. Call `client::deposit`, signed by the owner. The program transfers actual
   tokens from the owner's ATA into the vault before increasing credits.
5. Have the owner approve the ledger PDA as the payer ATA's SPL Token delegate,
   for **exactly the authorization cap**. Then call `client::authorize`, signed
   by both owner and issuer. Prefer combining approval, authorization and channel
   open in one transaction so a failed open also rolls back authorization.
6. Open the channel with `client::hook_config` and append
   `client::hook_tail(..., phase = 0)` to its accounts. The pre-funding hook
   debits credits and moves backing vault → payer ATA. The channel then transfers
   payer ATA → escrow in the same transaction.
7. Append phase `0` tails to top-ups, and phase `3` tails to `withdrawPayer` and
   `distribute`. The post-distribution hook returns the reported actual refund
   payer ATA → vault before restoring credits.

Use the repository's V2 channel and voucher builders for channel instructions.
The example's host builders return `solana_instruction::Instruction` and account
metas; enable its `client` Cargo feature. The program ID is supplied explicitly,
so local tests need no committed deployment keypair.

## Read the actual Rust

These are implemented functions, not pseudocode:

| Source | Responsibility |
| --- | --- |
| [`processor::initialize`](src/processor.rs) | Verify the issuer and create the ledger PDA |
| [`processor::deposit`](src/processor.rs) | Transfer backing before issuing credits |
| [`processor::authorize`](src/processor.rs) | Bind the owner's and issuer's signed policy |
| [`processor::callback`](src/processor.rs) | Validate the channel, scoped signer and context |
| [`processor::pre_fund`](src/processor.rs) | Debit credits and transfer bounded funding |
| [`processor::post_distribute`](src/processor.rs) | Recover refund custody before crediting |
| [`decode_callback`](src/lib.rs) | Decode into the real V2 `HookContext` type |
| [`client`](src/client.rs) | Build provider instructions, configuration and hook tails |

Copy complete functions together with their referenced helpers and imports when
using these as documentation excerpts. The phase handlers are reached only through
the validation in `callback`; they are not independent instruction entrypoints.

## Custody and accounting

There is one ledger and one vault per `(owner, mint)`. Amounts are integer token
base units. The invariant is `vault.amount >= ledger.credits`. Donations to the
vault are not credits, and there is no administrative credit-minting instruction.

For example, deposit 100, open with 60 and top up by 20:

| Point | Credits | Vault | Channel principal | Payer spendable refund |
| --- | ---: | ---: | ---: | ---: |
| Deposit | 100 | 100 | 0 | 0 |
| Open | 40 | 40 | 60 | 0 |
| Top up | 20 | 20 | 80 | 0 |
| Pay merchant 50, return 30 | 50 | 50 | 0 | 0 |

The refund's temporary appearance in the payer ATA is inside a single atomic
transaction. A failure to recover it aborts the channel distribution and all
related accounting. The owner cannot retain spendable refund tokens and receive
duplicate credits.

`funded` and `refunded` are cumulative for the active authorization. Refunds never
replenish its cap. The cap limits total funding, including every top-up, rather
than merely limiting current outstanding principal. Totals remain available after
terminal distribution and reset on the next authorization.

## Authorization and provider policy

The serialized `Authorization` contains:

- approved payee and exact voucher signer;
- approved distribution hash;
- salt and open slot, which derive the exact channel incarnation;
- total funding cap;
- monotonically increasing nonce, starting at 1;
- funding-expiry slot.

The ledger also binds its owner, mint, issuer and canonical hook commitment.
The issuer co-signs **every** authorization; an owner signature alone cannot
authorize an arbitrary merchant, distribution or replacement voucher signer.
The issuer must inspect the distribution preimage and approve recipients under
its own policy. Merely checking `payee != owner` cannot identify other wallets
controlled by the owner. This program does not claim to identify beneficial
ownership on chain.

The authorization derives the complete hook policy rather than accepting a
caller-provided commitment. Every callback verifies both the commitment and
all four stored descriptors. An owner cannot keep the funding hook while disabling
or replacing the refund hook. Opening a different, unhooked channel with the
owner's own tokens does not access provider credits.

There is at most one active authorization. A funded authorization cannot be renewed
or replaced while active. `withdrawPayer` **does not release it**: a later terminal distribution must
still use the original binding, even with a zero refund. Only a successful
post-distribution callback for a sealed channel releases it. The next authorization
requires both signatures and the next nonce. Expiry blocks funding, not refunds.

## Callback ABI

The entrypoint is the eight bytes `credit!!`. The remaining data is the actual
core V2 `HookContext` Borsh encoding followed by a zero static-context length.
ABI version 1 is accepted; unknown versions, phases, operations, trailing bytes
and truncated payloads fail closed.

Only `preFund` (phase 0) and `postDistribute` (phase 3) are configured.
`postFund` and `preDistribute` are disabled. Each enabled callback receives:

| Index | Account | Privilege |
| --- | --- | --- |
| 0 | Channel-program scoped hook authority PDA | Readonly signer |
| 1 | Exact channel incarnation | Readonly |
| 2 | Ledger/authorization PDA | Writable |
| 3 | Ledger's canonical vault ATA | Writable |
| 4 | Owner's canonical payer ATA | Writable |
| 5 | Original SPL Token program | Readonly executable |

That is **four extra accounts**, within the core limit. Neither owner nor sponsor
signature is inherited. The provider signs token CPIs only as the ledger PDA.
The authority is derived with the core authority seed, channel address,
configuration commitment, phase, and this example's program ID, under the V2
channel program ID.

Callback validation checks the channel's real owner, discriminator/version,
canonical PDA, in-progress guard and sequence against the supplied context.
It verifies the owner, mint, payee, voucher signer, distribution and incarnation
against the stored authorization. The ledger consumes every accepted callback
sequence, including callbacks reporting zero actual refund.

## Revocation, failures and deliberate limits

- The payer ATA's owner can revoke or reduce the refund delegation at any time.
  Funding then fails unless sufficient bounded delegation remains. A nonzero-refund
  distribution or withdrawal fails atomically when delegation is missing or
  insufficient; it does not issue unbacked credits. Reapprove the ledger for a
  sufficient amount no greater than the signed cap to resume. A zero-refund
  terminal distribution does not require delegation.
- Delegation is restricted to the canonical payer ATA. The provider has no generic
  delegated-transfer instruction. It can pull only the actual refund reported by
  an authenticated channel callback, bounded by funded principal.
- If authorization succeeds separately but open never succeeds before expiry,
  use `client::cancel_unfunded`, signed by **both owner and issuer**. It succeeds
  only if no funding, refund or callback sequence was ever recorded. It preserves
  the consumed nonce and credits. Any replacement requires both signatures and
  the next nonce. It cannot release a funded channel, even after all principal
  was refunded. There is no credit redemption, ledger closing, migration or
  funded-channel cap renewal in this small example.
- The issuer is pinned at ledger creation. Rotating the program upgrade authority
  does not change existing ledger issuers. Upgrade authority is ultimately trusted
  to change code; use an appropriate deployment/governance model outside tests.
- Only original SPL Token accounts are supported. Token-2022 extensions, native
  wrapped SOL, delegated vaults and separately configured token close authorities
  are rejected. Mint freeze authority and validator availability remain liveness
  dependencies.
- Exact token balance deltas are checked after transfers. Arithmetic is checked.
  Ledger state is marked busy before CPI and reset afterward; nested access fails.
  Any failed CPI or postcondition rolls back the whole transaction.
- Terminal release happens inside the hook before channel cleanup, but cleanup
  failure rolls back release too. Core channel reentrancy guards and runtime CPI
  rules remain part of the trust boundary.

Tests and review are evidence about this example, not a substitute for a deployment
security audit, recipient policy, recovery design, or key-management review.
