# Payment channel on-chain interface

`payment-channel-interface` is a `no_std`, library-only crate for programs receiving
payment-channel lifecycle callbacks. It defines no entrypoint, allocator or panic
handler. The channel program and the credit-provider example share these ABI types.

## What it provides

- `hooks`: Borsh callback context, bounded descriptors, commitment encoding,
  phase/operation tags, and scoped authority derivation.
- `channel`: read-only, version-specific account views and channel address derivation.
- `validation`: `validate_callback` with independently trusted `CallbackExpectations`,
  returning the validated context and channel snapshot.

Validation checks framing, the expected channel program and account, canonical PDA,
supported layout, committed descriptors, callback signer, exact account privileges,
phase/operation pairing, in-progress guard and current sequence. It compares the
appropriate pre- or post-operation snapshot against channel state.

Pass expectations derived from your program's trusted configuration and stored
authorization. Do not copy them from untrusted transaction accounts or callback bytes.

## What it does not authorize

A validated callback is not customer permission to spend. Your program still checks
issuer/customer authorization, merchant policy, cap, expiry, nonce, token custody,
refund destination and amounts, and a durable replay watermark. Economic context
is produced by the trusted channel program; the SDK does not independently reconstruct
all transfers or unavailable historical snapshots.

The [credit-provider callback](../../examples/credit-provider/src/processor.rs)
demonstrates the separation: it validates the callback using this crate, then
checks its ledger authorization and custody before changing credits.

## Validate

From the repository root:

```sh
cargo test -p payment-channel-interface
just test-v2-hooks
just test-credit-provider-surfpool
just test-same-address-upgrade
```

The last two commands use offline Surfpool; their harness READMEs specify toolchain
requirements. The same-address test reloads an executable locally, not a signed
loader upgrade. This crate and the example are experimental, not a production
provider approval.
