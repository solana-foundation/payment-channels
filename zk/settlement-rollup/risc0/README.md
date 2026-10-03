# ADR-006 RISC Zero V1 Voucher Authorization Prototype

This directory contains an experimental RISC Zero zkVM prototype for the
settlement-rollup direction described in ADR-006.

The prototype investigates whether existing payment-channel V1 vouchers can be
verified inside a zkVM without changing the current V1 signed-message format.

This is currently an authorization prototype. It is not yet a complete
settlement rollup.

## Motivation

The existing payment-channel protocol authorizes settlement using signed,
cumulative V1 vouchers.

Each voucher is signed by the channel's `authorized_signer`.

For channels with different authorized signers, settlement normally requires
repeated signature verification and repeated channel-state processing.

ADR-006 explores whether many independently signed vouchers can eventually be
verified inside one succinct proof.

This prototype validates the first part of that direction:

```text
existing V1 voucher
        |
        v
RISC Zero zkVM
        |
        +-- validate exact V1 framing
        +-- verify Ed25519 authorization
        +-- parse authenticated fields
        |
        v
public journal
```

No new voucher format is introduced.

## Current Scope

The guest receives a private witness containing:

- the existing 50-byte V1 voucher payload;
- the channel's 32-byte Ed25519 `authorized_signer` public key;
- the 64-byte Ed25519 signature.

The guest currently enforces:

1. the payload is exactly 50 bytes;
2. the V1 magic bytes are `[0x56, 0x01]`;
3. the Ed25519 signature verifies over the exact 50-byte payload under the
   supplied authorized signer;
4. the authenticated payload is parsed into:
   - `channel_id`;
   - `cumulative_amount`;
   - `expires_at`.

The parsed values are committed to the RISC Zero journal.

## Existing V1 Signed Message

The prototype preserves the existing V1 payload exactly:

```text
offset  size  field
------  ----  ----------------------------------------
0       2     magic = [0x56, 0x01]
2       32    channel_id
34      8     cumulative_amount (u64 little-endian)
42      8     expires_at (i64 little-endian)

total: 50 bytes
```

The signature is verified over these exact 50 bytes.

## Workspace Layout

```text
risc0/
├── host/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── methods/
│   ├── Cargo.toml
│   ├── build.rs
│   ├── src/
│   │   └── lib.rs
│   └── guest/
│       ├── Cargo.toml
│       ├── Cargo.lock
│       └── src/
│           └── main.rs
├── shared/
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
├── .gitignore
├── Cargo.toml
└── Cargo.lock
```

### `shared`

Contains the Borsh types shared between the host and guest:

- `V1VoucherInput`
- `V1VoucherJournal`

It also defines the V1 payload constants used by the guest.

### `methods/guest`

Contains the RISC Zero guest program.

The guest performs:

```text
deserialize private witness
        |
        v
require payload length == 50
        |
        v
require magic == [0x56, 0x01]
        |
        v
verify Ed25519 signature
        |
        v
parse authenticated V1 fields
        |
        v
commit V1VoucherJournal
```

### `methods`

Uses `risc0-build` to compile and embed the guest.

The generated output exposes:

- the guest binary;
- the guest path;
- the guest image ID.

The image ID cryptographically identifies the exact guest computation being
verified.

### `host`

The host:

1. loads the canonical V1 fixture;
2. converts the fixture fields into `V1VoucherInput`;
3. serializes the input using Borsh;
4. constructs a RISC Zero `ExecutorEnv`;
5. executes/proves the guest;
6. verifies the receipt against the generated guest image ID;
7. decodes the public journal;
8. checks the result against the expected fixture values.

The host also contains adversarial authorization tests.

## Canonical V1 Fixture

The prototype uses the deterministic fixture at:

```text
../fixtures/v1-valid.json
```

The current fixture represents a valid V1 voucher with:

```text
channel_id        = 0707070707070707070707070707070707070707070707070707070707070707
cumulative_amount = 500000
expires_at        = 0
```

The fixture is generated independently from the payment-channel V1 wire format
and is used as a stable compatibility test vector.

## Authorization Tests

The host currently covers four cases:

```text
canonical V1 voucher       -> accepted
mutated signature          -> rejected
wrong authorized signer    -> rejected
mutated signed payload     -> rejected
```

The negative cases are important because they demonstrate that the guest is not
only parsing the voucher.

It is enforcing that the supplied Ed25519 signature authenticates the exact
signed V1 payload under the expected signer.

### Mutated Signature

One bit of the original signature is changed while leaving the payload and
signer unchanged.

Expected result:

```text
Ed25519 verification fails
```

### Wrong Authorized Signer

The original payload and signature are retained, but a different valid Ed25519
public key is supplied.

Expected result:

```text
Ed25519 verification fails
```

### Mutated Signed Payload

One byte of `cumulative_amount` is changed while retaining the original
signature.

Expected result:

```text
Ed25519 verification fails
```

This demonstrates that the signature is bound to the exact signed protocol
bytes.

## Building the Guest

From this directory:

```bash
RISC0_BUILD_LOCKED=1 \
cargo build --locked -p zkchannel-zk-methods
```

The guest is compiled for the RISC Zero zkVM RISC-V target.

The resulting image ID is generated by `risc0-build` and embedded into the
`zkchannel-zk-methods` crate.

## Running the Demo

For fast local development:

```bash
RISC0_DEV_MODE=1 \
RISC0_BUILD_LOCKED=1 \
cargo run --locked -p zkchannel-zk-host
```

Expected output includes:

```text
Proving ZKChannel V1 voucher authorization...

Receipt verified against ZKChannel guest image ID.

V1 voucher journal verified:
  channel_id        = 0707070707070707070707070707070707070707070707070707070707070707
  cumulative_amount = 500000
  expires_at        = 0

ZKChannel V1 authorization succeeded.
```

## Running the Tests

Run the authorization tests in RISC Zero development mode:

```bash
RISC0_DEV_MODE=1 \
RISC0_BUILD_LOCKED=1 \
cargo test --locked \
  -p zkchannel-zk-host \
  -- --test-threads=1
```

The expected result is:

```text
4 passed
0 failed
```

The tests are executed sequentially because zkVM execution can be relatively
resource-intensive.

## Development Mode

`RISC0_DEV_MODE=1` is intended only for fast development and testing.

In development mode, RISC Zero executes the guest logic and produces the
expected journal behavior, but it does not generate a secure cryptographic
proof.

Therefore:

```text
development mode
    |
    +-- useful for guest logic testing
    +-- useful for adversarial tests
    +-- useful for protocol iteration
    |
    `-- NOT a production proof
```

Real proving must be performed without `RISC0_DEV_MODE=1`.

## Reproducibility

The prototype pins:

```text
risc0-zkvm  = 3.0.3
risc0-build = 3.0.3
```

The workspace and guest use separate lockfiles.

This is intentional because RISC Zero builds the guest as a separate RISC-V
workspace.

Both lockfiles are committed so that:

- the host dependency graph is reproducible;
- the guest dependency graph is reproducible;
- guest compilation does not silently drift to incompatible transitive
  versions;
- the resulting guest image can be reproduced from the pinned source and
  dependencies.

The RISC Zero dependency graph used here is aligned with the dependency graph
used by the RISC Zero Solana `v3.0.0` release examples.

## Ed25519 Verification

The guest currently uses:

```text
ed25519-dalek = 2.2.0
```

with strict Ed25519 verification.

The current prototype demonstrates that the canonical payment-channel V1
signature is accepted and that basic adversarial mutations are rejected.

However, this does not yet establish full behavioral equivalence with Solana's
Ed25519 precompile.

Before treating the zkVM verifier as a production replacement for runtime
precompile semantics, differential compatibility testing is required.

That testing should compare acceptance and rejection behavior for cases such as:

- malformed public keys;
- malformed signatures;
- non-canonical encodings;
- signature malleability edge cases;
- mutated messages;
- boundary conditions accepted or rejected by the Solana runtime.

## Current Limitations

This prototype proves only V1 voucher framing and authorization logic.

It does not yet prove channel-state semantics.

The following are not yet implemented:

- authenticated channel-state membership;
- channel-status eligibility;
- binding the voucher to an authenticated channel state;
- expiry validation against a trusted Solana time value;
- `cumulative_amount <= deposit`;
- strict settlement-watermark advancement;
- payout-watermark constraints;
- duplicate-channel rejection across a batch;
- multiple-voucher batch execution;
- settlement accumulator membership proofs;
- settlement accumulator root transitions;
- `old_root -> new_root` proof statements;
- Solana-side receipt verification;
- Groth16 seal generation for Solana verification;
- RISC Zero Router CPI integration;
- production verifier deployment or governance assumptions;
- production benchmarks.

## Why a Succinct Proof Alone Is Not Enough

Verifying many vouchers inside one proof can compress computation.

However, if settlement still writes every individual Channel PDA, the protocol
still pays the cost of:

```text
N writable channel accounts
+
N state updates
+
N write locks
```

Therefore ADR-006 requires more than proof aggregation.

The intended direction is to combine succinct verification with a settlement
state accumulator.

## Intended ADR-006 Direction

The target architecture is:

```text
N independent payment channels
N independent authorized signers
N existing V1 vouchers
              |
              v
      RISC Zero zkVM
              |
              +-- verify each V1 Ed25519 signature
              +-- verify channel binding
              +-- verify expiry
              +-- verify deposit bounds
              +-- verify watermark advancement
              +-- reject duplicate channels
              +-- authenticate old logical state
              |
              v
     prove state transition
              |
              v
      old accumulator root
              |
              v
      new accumulator root
              |
              v
       succinct receipt
              |
              v
        Solana verifier
              |
              v
   one canonical root update
```

The goal is therefore:

```text
proof compression
        +
state-update compression
```

rather than proof compression alone.

## Planned Follow-Up Work

The next prototype stages are expected to add:

1. payment-channel semantic validation;
2. batching across independently authorized channels;
3. duplicate-channel rejection;
4. authenticated settlement-state membership;
5. accumulator root transitions;
6. real cryptographic proof benchmarks;
7. Groth16 receipt generation;
8. Solana-side proof verification;
9. one-root settlement updates;
10. comparison against individual and conventional batch settlement.

## Security Status

This code is experimental.

It has not undergone an independent security audit.

It should not be used to authorize production funds.

The purpose of this prototype is to validate the ADR-006 architecture,
compatibility assumptions, and performance characteristics before any
production integration is considered.
