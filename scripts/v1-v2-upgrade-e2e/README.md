# Historical V1 → dual-runtime binary reload regression

Run from the repository root:

```sh
bash scripts/v1-v2-upgrade-e2e/run.sh
```

Requires cached Cargo dependencies, platform-tools v1.58, `cargo-build-sbf`,
Surfpool 1.5, `curl`, Git, and `shasum`. No wallet files, production keys, or
network cluster are used. Surfpool runs offline on a dedicated loopback port
(default 18999; override with `UPGRADE_PORT`).

The runner extracts commit `25df9636698c320a0716ba224cbc8724acf63edf` into
ignored `target/v1-upgrade-baseline`, builds that actual historical program,
and separately builds the current default runtime. Both builds use SBPF v3 /
platform-tools v1.58; this tests historical **source** compatibility, not
reproducibility of a previously published binary. Host and both SBF build
directories are isolated. `UPGRADE_BUILD_ROOT` can select another attached
worktree's build cache when disk space is limited.

The harness links the unmodified generated Rust client from the extracted
historical commit. It does not substitute the current SDK or reconstruct
V1 channel instructions manually. SPL setup and Ed25519 instruction envelopes
are local test helpers; voucher serialization uses the historical client type.
An independent, hand-encoded V2 open probe uses discriminator 10 plus four
disabled sparse hook descriptors: it must fail with `InvalidInstructionData`
on the old ELF and succeed unchanged on the new ELF, creating 1121 bytes at
version 2. This distinguishes a real runtime replacement from a stale program
cache. That probe is wire compatibility, not a claim of an old SDK V2 API.

The test:

1. Loads the old ELF at canonical program address
   `CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX`.
2. Opens a 256-byte/version-1 channel with 1,000 tokens, settles and distributes
   200, then signs a cumulative-700 voucher **before** replacing the program.
3. Reloads the new ELF at the **same** address via `surfnet_writeProgram` and
   asserts the entire channel and token-account RPC representations are unchanged.
4. Uses original top-up/settle/seal/withdraw/distribute instructions and the
   retained Ed25519 signature to top up 500, settle 700, refund 800, and close.
   Final balances are payer 9,300, payee 700, treasury 0; both channel and escrow
   must be absent. If distribution leaves an inert `Distributed` channel during
   the historical 1,500-slot replay window, the historical `reclaim` instruction
   closes it after the window expires. The local slot time is 10 ms to keep this
   bounded without modifying the clock or account data. No resize or migration
   transaction occurs.
5. Uses the same historical client to open a **new** 256-byte/version-1 channel
   on the dual runtime, repeats the economic lifecycle, and checks closure.

Logs, source revision, working-tree diff hash, and both ELF SHA-256 hashes are
retained under `target/v1-upgrade-run.*`. Ephemeral signers exist only in memory.

This is **binary reload compatibility**, not a signed loader upgrade or proof
of upgrade-authority/ProgramData behavior. Enabled callback success and bypass
rejection belong to the separate hook and credit-provider suites; this focused
regression intentionally has no dependency on their helpers or current core
host code.
