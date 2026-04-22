# solana-payment-channels

A Solana payment channel program in the spirit of [`draft-solana-session-00`](https://github.com/solana-foundation/mpp-specs/blob/a64edb477cfcb5e071e4f73f4227cf329dd1c4b5/specs/methods/solana/draft-solana-session-00.md), with two-phase close, on-chain multi-destination split distribution, and an operator watermark voucher model.

See [`docs/001-payment-channel-state-machine.md`](docs/001-payment-channel-state-machine.md) for the FSM, transition guards, instruction set, and on-chain PDA layout.


## Layout

```
solana-payment-channels/
├── programs/
│   └── payment_channels/
│       ├── src/
│       │   ├── instructions/
│       │   │   └── helpers/
│       │   ├── state/
│       │   ├── events/
│       │   └── tests/
│       └── idl/
│
├── clients/
│   ├── rust/
│   │   └── src/
│   │       └── generated/
│   └── typescript/
│       ├── src/
│       │   ├── generated/
│       │   ├── instructions/
│       │   ├── accounts/
│       │   ├── types/
│       │   └── errors/
│       └── test/
│
├── scripts/
├── keys/
├── docs/
├── .github/
│   ├── actions/
│   │   └── setup/
│   └── workflows/
└── .githooks/
```


## License

MIT. See [`LICENSE`](LICENSE).
