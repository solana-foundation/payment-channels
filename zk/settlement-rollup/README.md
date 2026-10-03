# ZKChannel Settlement Rollup Prototype

## Status

Experimental research prototype for ADR-006-style settlement rollups in the
Solana Foundation payment-channels protocol.

This implementation is intended to evaluate feasibility, security semantics,
compute cost, proving cost, and state-compression design.

It is not production-ready and must not be treated as an audited payment system.

## Motivation

The existing payment-channel settlement path verifies and updates channels
individually.

ADR-004 explores batching channels that share one authorized signer, but that
does not solve the case where many channels are controlled by independent
signer authorities.

ADR-006 proposes using a succinct zero-knowledge proof to attest to many
independently authorized settlements.

Proof aggregation alone is not sufficient because updating one writable
Channel account per settlement still leaves account-count and write-lock
scaling limits.

The useful target is therefore:

    many independent voucher verifications
                +
    many logical settlement transitions
                ↓
        one Groth16 proof
                +
        one accumulator root update

## Compatibility Requirement

ZKChannel must preserve the existing V1 voucher authorization format.

A V1 voucher is exactly 50 bytes:

    magic               2 bytes
    channel_id          32 bytes
    cumulative_amount    8 bytes little-endian
    expires_at           8 bytes little-endian signed integer

The V1 magic is:

    [0x56, 0x01]

The prototype must not replace the existing Ed25519 authorization scheme with
a SNARK-friendly signature scheme merely to make proving easier.

## Security Model

The prover is untrusted.

A valid proof must not be sufficient merely because a prover supplies a valid
signature.

The proof must bind the signature to the authorized signer of the correct
payment-channel incarnation and must prove that the resulting settlement
transition is valid.

The final design must preserve the protocol's settlement invariants and replay
protection.

## Milestone 1: Exact V1 Voucher Authorization

The first feasibility milestone proves one existing V1 voucher.

For one voucher, the circuit must establish that:

    1. the voucher has the expected V1 format and magic;
    2. the voucher is bound to the expected channel_id;
    3. the Ed25519 signature is valid over the exact 50 signed bytes;
    4. the signature verifies under the expected authorized signer;
    5. cumulative_amount and expires_at are the values encoded in those
       signed bytes.

The following mutations must invalidate verification:

    - signature mutation
    - authorized signer substitution
    - channel_id mutation
    - cumulative_amount mutation
    - expires_at mutation
    - voucher magic mutation

Milestone 1 deliberately does not implement the settlement accumulator.

Its purpose is to determine whether proving real RFC8032 Ed25519 authorization
for existing V1 vouchers is practical enough to justify the remaining rollup
architecture.

## Milestone 2: Settlement Transition Semantics

After Milestone 1 is proven feasible, the circuit will incorporate channel
settlement semantics.

At minimum, the design must establish that:

    old_settled < new_settled
    new_settled <= deposit

and must correctly enforce voucher expiry using a timestamp or other time value
that is itself safely bound to the on-chain verification context.

The exact public/private input boundary is intentionally not frozen yet.

## Milestone 3: Settlement Accumulator

The accumulator will commit to enough authenticated state to verify settlement
transitions without loading every Channel PDA during a rollup transaction.

The initial design question is whether an accumulator leaf should commit to
values such as:

    channel_id
    authorized_signer
    deposit
    settled
    settlement eligibility

The final leaf format must minimize duplicated protocol state while still
preventing a prover from inventing signer, deposit, lifecycle, or watermark
information.

The accumulator root represents logical settlement state.

Updating the root does not mean that every underlying Channel PDA is rewritten.

## Materialization

The intended state-compression model may allow accumulator settlement state to
advance ahead of the settlement watermark stored in an individual Channel PDA.

Before an instruction that requires current per-channel settlement state, the
channel may need to be materialized from the accumulator using an authenticated
proof.

The exact interaction with:

    settle
    top_up
    request_close
    seal
    distribute
    withdraw_payer
    reclaim
    rearm

must be specified before the accumulator design is considered safe.

## Rollup Proof Target

The eventual proof should establish a transition of the form:

    R_old -> R_new

where R_old is the currently committed settlement state and R_new is the result
of applying a valid batch of independently authorized V1 voucher settlements.

For each updated channel, the proof will eventually need to establish:

    - membership of the old channel settlement state in R_old;
    - correct V1 channel binding;
    - valid Ed25519 authorization;
    - correct authorized signer;
    - valid expiry;
    - valid watermark advancement;
    - deposit bound;
    - settlement eligibility;
    - correct computation of the resulting accumulator state.

The design must also prevent duplicate updates of the same channel within one
batch.

## Feasibility Gates

The prototype proceeds only if evidence supports each stage.

Gate A:
One real V1 Ed25519 voucher can be proven and verified correctly.

Gate B:
Proof generation time, memory use, constraint count, and proving-key size are
measured for increasing numbers of independent signatures.

Gate C:
A Groth16 proof generated off-chain can be verified by the Solana program.

Gate D:
The accumulator design removes the need for one writable Channel account per
logical settlement.

Gate E:
Adversarial tests reject tampered signatures, signer substitution, channel
substitution, expired vouchers, stale roots, invalid watermark transitions,
deposit violations, duplicate channels, and proof replay.

Gate F:
All existing upstream payment-channel tests continue to pass.

## Benchmark Plan

The prototype will measure:

    - circuit constraint count
    - witness generation time
    - proof generation time
    - proving memory usage
    - proving-key size
    - proof size
    - Solana verifier compute units
    - full rollup-instruction compute units
    - transaction size
    - account count
    - supported batch size

Batch sizes will be increased empirically rather than assuming a target size in
advance.

## Non-Goals

This prototype does not claim:

- payment privacy;
- removal of per-channel escrow accounts;
- removal or modification of the existing V1 voucher format;
- replacement of Ed25519 with another authorization scheme;
- production readiness or security before external cryptographic review.

## Generated Artifacts

Large or machine-generated proving artifacts must not be committed to Git.

Examples include:

- `*.r1cs`
- `*.wtns`
- `*.zkey`
- `*.ptau`
- `proof.json`
- `verification_key.json`
- generated witness directories

Reproducible scripts and source circuits should be committed instead.

## Design Principles

Design decisions must be justified by protocol semantics rather than
prototype or demonstration convenience.

The implementation should preserve compatibility with the existing
payment-channels protocol wherever possible.

Any intentional deviation from existing protocol semantics must be explicitly
documented and must not be represented as equivalent behavior.

Security-critical assumptions must be documented and tested.

Generated cryptographic results and benchmarks should be reproducible from
committed source code and scripts.