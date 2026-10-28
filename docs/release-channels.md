# Release channels

The program is built per channel with [solex](https://github.com/lgalabru/solex).
`Solex.toml` at the repository root declares the deployments:

| Channel | Program id | Clusters | Features | Treasury owner |
| --- | --- | --- | --- | --- |
| `stable` | `CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX` | mainnet | none (V1 surface) | `Cs2zdf…` |
| `canary` | `CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ` | devnet | none yet | `4zTeC5…` |
| `canary` | `CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ` | mainnet | none yet | `Cs2zdf…` |

`canary` includes `stable`. It is one channel on two clusters at the same
address; the `[channels.canary.mainnet]` override swaps in the mainnet
treasury. `solex build --canary` therefore produces one artifact per cluster
under `target/solex/canary/<cluster>/`, each embedding its own treasury owner.
Channel-gated features are declared under `[features.<name>]` in `Solex.toml`
and gated in code with plain `#[cfg(feature = "<name>")]`.

## What replaced the cargo features

- `localnet` / `devnet` / `testnet` / `mainnet-beta` selected `TREASURY_OWNER`
  through mutually exclusive `mod cluster` blocks and a `0xBEEF` compile-time
  gate. The owner now comes from `vars.treasury_owner` on the channel via
  `solex::var!("treasury_owner")`; a channel without it does not compile.
- `declare_id!` is now `solex::declare_id!()`, which reads the channel's
  `program_id`.

## Building

```sh
solex channels                      # deployments and what each ships
solex features --check              # every channel feature against every channel
solex build --canary                # target/solex/canary/{devnet,mainnet}/payment_channels.so
solex build --channel stable        # target/solex/stable/payment_channels.so
SOLEX_CHANNEL=stable cargo build-sbf
```

Any `cargo build-sbf` or `cargo test` invocation selects a channel by exporting
`SOLEX_CHANNEL`; the `just` recipes do this. Without it the manifest default,
`stable`, applies.

## Deploying

`solex deploy --canary` lists the channel's clusters as a checklist and runs
`solana program deploy` for each one picked, with that cluster's program id,
artifact and keypair. The first mainnet deploy signs with
the channel keypair at `keys/canary.json` (gitignored; the maintainers hold
it) and needs a funded payer: the program account alone is rent-exempt at about 1.01 SOL for this
artifact, plus the buffer during upload. `solex deploy --canary --dry-run`
prints the exact commands.

## Promotion

Promoting a feature to stable is one manifest edit: add `"stable"` to its
`[features.<name>] channels`. The source does not change.

## Known gap

`solana-verify` builds in a container and must see `SOLEX_CHANNEL=stable`;
the `verified-build` recipe needs that environment plumbed through before it is
used for a channel-gated release.
