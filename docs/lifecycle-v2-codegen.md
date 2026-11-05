# Dual-version generated bindings

The primary IDL and clients describe both account versions at canonical
`CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX`. Original instruction names retain
their wire encodings; explicit `WithHooks` variants are additive. The runtime
revision is experimental and is not the older separate-address devnet deployment.

## Generate and check

From the repository root:

```sh
pnpm install --frozen-lockfile
just generate-client
pnpm --filter @payment-channels/client build
pnpm --filter @payment-channels/client typecheck
pnpm --filter @payment-channels/client test
cargo test -p payment_channels_client
```

| Output | Path |
| --- | --- |
| Codama IDL | `program/payment_channels/idl/payment_channels.json` |
| TypeScript | `clients/typescript/src/generated` |
| Rust | `clients/rust/src/generated` |
| Shared parity vectors | `fixtures/lifecycle-v2.json` |

The separate unpublished V2 packages are replaced by additive primary bindings.
`Channel` decodes only a complete V1 account; `ChannelWithHooks` decodes only a
complete V2 account. Its nested header is a structural type, not a shortcut for
treating the full account as V1. Account-boundary decoding checks exact length,
discriminator and version.

Codama reads Rust syntax without expanding `cfg`, so `build.rs` explicitly
selects the deployment ID. The lifecycle visitor extracts the fixed ABI structs;
unsupported declarations stop generation rather than silently omitting fields.

## Compact configuration is representable, but not as an ordinary vector

The IDL represents exactly four `Option<CompactHookDescriptor>` values. An
enabled descriptor contains its program and entrypoint followed by
`CompactHookAccounts`. This enum has five variants, `Accounts0` through
`Accounts4`. Its one-byte discriminant is the **account count**. Each variant
contains:

1. Static context, prefixed by a one-byte length.
2. A fixed-size array of zero through four account metas.

This puts `account_count` before `static_len` and the static bytes, as required
by the program. A conventional `Vec<HookMeta>` would put its length in the
wrong position. Rust generation uses `spl-collections` with its `borsh`
feature for the one-byte-prefixed static context.

`OpenWithHooksArgs.hookConfig` (Rust: `hook_config`) is required. Four disabled
slots encode as `00 00 00 00`, not as an omitted suffix. V1 `OpenArgs` has no
hook configuration.

Generated codecs describe wire encoding, not the complete admission policy.
Callers must still enforce the 32-byte static-context limit, canonical padding,
0/1 writable flags, unique extras, prohibited aliases, target restrictions,
and transaction-size limits described in [the ABI](lifecycle-hooks-v2.md).
TypeScript uses standard Codama numeric codecs; pass `bigint` for 64-bit values.

## Append hook account tails explicitly

The generated instruction builders produce the fixed account head, and
`distribute` also accepts its existing recipient ATA list. They do **not**
resolve hook authorities or append lifecycle accounts. Append the enabled
pair's tails after those accounts, in phase order:

```text
target program (readonly, nonsigner)
callback authority (readonly, nonsigner in the outer transaction)
committed extras (exact writable flags, nonsigners)
```

The channel program signs for the callback authority only during CPI. Do not
mark the authority as a transaction signer. Do not model the heterogeneous
tail as uniformly writable or forward outer signer privileges.

## Parity evidence and limits

The shared vectors cover all five account counts, sparse enabled slots,
nonempty static context, a complete empty-hook `openWithHooks`, and a callback context
with nonzero and signed accounting values. Regenerate them only for an
intentional ABI change:

```sh
node scripts/generate-v2-fixtures.mjs
```

TypeScript tests compare generated encodings with independently assembled
bytes, fixed sizes, original discriminators, and frozen V1 IDL-node hashes. Rust tests decode
and re-encode the same vectors, compare real program storage with generated
types, and compare the real callback context's Borsh bytes.

The dependency build's parser cannot execute its SHA-256 syscall on the host.
These client tests therefore do not claim SBF parser, callback-execution,
rollback, compute-budget, or packet-size coverage. Those remain program-level
checks. They also do not validate a production issuer integration.
