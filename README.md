# solana-payment-channels

## Overview

This repo contains the Pinocchio Solana program that supports the MPP protocol for unidirectional payment channels.

The program escrows SPL Token or Token-2022 deposits. A payer signs off-chain Ed25519 vouchers for cumulative spend. The merchant can settle those vouchers on-chain and distribute settled funds.

## How It Works

- `open` creates a channel PDA and moves the deposit into escrow.
- Vouchers authorize cumulative spend. They are signed off-chain by the payer or authorized signer.
- `settle` advances the on-chain settled amount.
- `distribute` pays settled funds to the payee and any configured split recipients.
- Cooperative close uses `settleAndFinalize`, then `distribute`.
- Forced close uses `requestClose`, waits through the grace period, then uses `finalize` and `distribute`.

## Status

- No production program keypair is committed or uploaded by CI. Keep operator keypairs outside version control and pass the program-id keypair explicitly when deploying, e.g. `solana program deploy target/deploy/payment_channels.so --program-id <program-keypair>`.
- Local/test program id: `CQAyft83tN1w2bRofB5PZ79eVDU2xZUVo43LU1qL4zRg`. This ID is for generated fixtures and tests only; mainnet integrations must use the explicitly deployed production program address.
- `TREASURY_OWNER` is selected per cluster via Cargo features: `localnet` (default) uses a non-production placeholder for dev/test/CI; `devnet`/`mainnet` builds (`just build-devnet` / `just build-mainnet`) require that cluster's real owner set in `program/payment_channels/src/constants.rs` and fail to compile while the placeholder remains.

## Repo Layout

- `program/payment_channels`: Pinocchio program.
  - `src/instructions`: instruction processors and helpers.
  - `src/state`: channel account state.
  - `src/events`: program events.
  - `tests`: program tests.
  - `idl`: generated IDL.
- `clients/typescript`: generated TypeScript client.
- `clients/rust`: generated Rust client.
- `docs`: protocol ADRs and diagrams.
- `codama.js`: Codama generation config.
- `codama-visitors.mjs`: local Codama visitors.

## Development

```sh
just setup
just build-program
just generate-client
just test-program
just check
just fmt

# Cluster builds (require that cluster's real TREASURY_OWNER in constants.rs):
just build-devnet
just build-mainnet
```

## More Docs

- [State machine](docs/001-payment-channel-state-machine.md)
- [HTTP protocol](docs/002-http-protocol.md)
- [Instruction reference](docs/003-program-instructions.md)

## License

MIT. See [LICENSE](LICENSE).
