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

- The program keypair is committed at `keys/payment_channels-keypair.json` so local builds and tests use the same program id.
- Program id: `GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc`.
- `TREASURY_OWNER` is a placeholder and must be replaced before mainnet use.

## Repo Layout

- `program/payment_channels`: Pinocchio program.
  - `program/payment_channels/src/instructions`: instruction processors and helpers.
  - `program/payment_channels/src/state`: channel account state.
  - `program/payment_channels/src/events`: program events.
  - `program/payment_channels/tests`: program tests.
  - `program/payment_channels/idl`: generated IDL.
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
```

## More Docs

- [State machine](docs/001-payment-channel-state-machine.md)
- [HTTP protocol](docs/002-http-protocol.md)
- [Instruction reference](docs/003-program-instructions.md)

## License

MIT. See [LICENSE](LICENSE).
