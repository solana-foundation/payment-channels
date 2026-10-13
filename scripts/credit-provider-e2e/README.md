# Offline backed-credit integration

Run from the repository root:

```sh
SOLANA_CLI=/path/to/agave-4.3.0/bin/solana just test-credit-provider-surfpool
```

Tested with Surfpool 1.5.0, Agave CLI 4.3.0 and platform-tools v1.58
(`--arch v3`). Rust dependencies and platform-tools must already be cached:
the recipe runs Cargo offline. Older Solana CLIs can reject SBPF v3 before
sending a transaction. `SOLANA_CLI` selects an existing executable without
changing the global CLI installation.

The recipe serially builds channel and provider SBF binaries in separate Cargo
target directories. This prevents the provider's `no-entrypoint` channel
dependency from overwriting the executable channel build. Both ELFs must have
SBPF v3 flags and a nonempty executable section containing their entrypoint.

The harness starts its own offline Surfpool on loopback, preloads the fixed
V2 channel program ID, and deploys the provider with a new local upgrade
authority. All mint, custody, authorization, voucher and channel operations
use signed transactions. No production wallet configuration is used.
`--skip-feature-verify` bypasses the CLI's cluster-feature precheck for local
SBPF v3 deployment, not transaction signatures or program execution.

`CARGO_TARGET_DIR` can reuse an attached worktree's warm host cache. Dedicated
SBF cache subdirectories remain separate. `CREDIT_E2E_PORT` defaults to 18899.
`PAYMENT_CHANNELS_V2_SO` and `CREDIT_PROVIDER_SO` are diagnostic artifact
overrides; leave both unset to validate the recipe's own builds.
Ephemeral key files are created mode 0600 beneath ignored `target/` and removed
on exit. Surfpool logs remain there for diagnosis.

Coverage includes rent-exempt PDA prefunding, issuer impostors, missing issuer
signature, substituted ProgramData, real token deposits, authorization overlap,
malformed hook configuration, cap rollback, topup, signed settlement, revoked
refund delegation rollback, custody refunds, duplicate terminal distribution,
nonce replay, withdrawal before zero-refund terminal settlement, expired
unfunded cancellation, and a fresh authorization after cancellation.
Negative cases assert the intended instruction error and unchanged financial
accounts. Fee-payer SOL is excluded because rejected transactions pay fees.

This verifies the current V2 ABI; it does not test a same-pubkey upgrade from V1
or authorize a deployment to a public network.
