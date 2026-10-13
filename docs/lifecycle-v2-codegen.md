# Experimental V2 generated bindings

V2 outputs are separate from the default V1 IDL and clients. They target
`CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ`; they do not describe a deployed
or audited program.

## Generate and check

From the repository root:

```sh
pnpm install --frozen-lockfile
pnpm run generate:v2
pnpm --filter @payment-channels/client-v2 build
pnpm --filter @payment-channels/client-v2 typecheck
pnpm --filter @payment-channels/client-v2 test
cargo test --manifest-path clients/rust-v2/Cargo.toml
```

| Output | Path |
| --- | --- |
| Codama IDL | `program/payment_channels/idl/payment_channels_v2.json` |
| TypeScript | `clients/typescript-v2/src/generated` |
| Rust | `clients/rust-v2/src/generated` |
| Shared parity vectors | `fixtures/lifecycle-v2.json` |

The Rust V2 client has its own workspace and lockfile. This prevents its
parity-test dependency on the V2 program from enabling V2 in the default
workspace's V1 tests. It is a wire-only, unpublished crate; optional generated
Anchor and RPC integrations are not exposed.

`pnpm run generate` and the existing `just generate-client` remain V1 commands.
Codama reads Rust syntax without expanding `cfg`, so `build.rs` explicitly
selects the program ID and strips V2 channel storage from V1. The V2 visitor
extracts the simple fixed wire structs directly from `hooks.rs`; unsupported
new Rust declarations stop generation rather than silently omitting fields.

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

`OpenArgs.hookConfig` (Rust: `hook_config`) is required. Four disabled slots
encode as `00 00 00 00`, not as an omitted suffix.

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
nonempty static context, a complete unhooked `open`, and a callback context
with nonzero and signed accounting values. Regenerate them only for an
intentional ABI change:

```sh
node scripts/generate-v2-fixtures.mjs
```

TypeScript tests compare generated encodings with independently assembled
bytes, fixed sizes, V1 discriminators, and the V1 IDL hash. Rust tests decode
and re-encode the same vectors, compare real program storage with generated
types, and compare the real callback context's Borsh bytes.

The dependency build's parser cannot execute its SHA-256 syscall on the host.
These client tests therefore do not claim SBF parser, callback-execution,
rollback, compute-budget, or packet-size coverage. Those remain program-level
checks. They also do not validate a production issuer integration.
