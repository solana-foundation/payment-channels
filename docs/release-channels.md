# Release channels

The program is built per channel with [solex](https://github.com/lgalabru/solex).
`Solex.toml` at the repository root declares the deployments:

| Channel | Program id | Clusters | Features | Treasury owner |
| --- | --- | --- | --- | --- |
| `stable` | `CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX` | mainnet-beta | none (V1 surface) | `Cs2zdf…` |
| `nightly` | `CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ` | devnet | `hooks` | `4zTeC5…` |

`nightly` includes `stable`. The local hook suite (`just test-v2-hooks`) runs
against the stable channel with the `hooks` Cargo feature enabled by hand, so
the program keeps the canonical address the generated client embeds.

## What replaced the cargo features

- `localnet` / `devnet` / `testnet` / `mainnet-beta` selected `TREASURY_OWNER`
  through mutually exclusive `mod cluster` blocks and a `0xBEEF` compile-time
  gate. The owner now comes from `vars.treasury_owner` on the channel via
  `solex::var!("treasury_owner")`; a channel without it does not compile.
- `devnet-deployment` switched `declare_id!`. `solex::declare_id!()` reads the
  channel's `program_id`.
- The four `*WithHooks` instructions are the `hooks` Cargo feature
  (`hooks = []` in the program's Cargo.toml), gated with plain
  `#[cfg(feature = "hooks")]` on their enum variants, `from_bytes` arms,
  dispatch arms, discriminators and handlers. `Solex.toml` declares
  `[features.hooks] channels = ["nightly"]`, so `solex build --channel nightly`
  passes `--features hooks` and a `stable` build contains none of them: no
  discriminator is recognised and no code is linked.

## Building

```sh
solex channels                      # deployments and what each ships
solex features --check              # the hooks feature against both channels
solex build --channel nightly       # target/solex/nightly/payment_channels.so, --features hooks
solex build --channel stable        # target/solex/stable/payment_channels.so
just test-v2-hooks                  # stable + hooks at the canonical address
SOLEX_CHANNEL=stable cargo build-sbf --tools-version v1.58 --arch v3
```

Any `cargo build-sbf` or `cargo test` invocation selects a channel by exporting
`SOLEX_CHANNEL`; the `just` recipes do this. Without it the manifest default,
`stable`, applies.

## Promotion

Promoting the V2 hooks to stable is one manifest edit: add `"stable"` to
`[features.hooks] channels`. The source does not change. Before doing so, read `docs/versioning-and-upgrades.md`:
once hooked accounts exist at an address, a rollback to a V1-only binary strands
them, so promotion of the account format is one-way.

## Known gap

`solana-verify` builds in a container and must see `SOLEX_CHANNEL=stable`;
the `verified-build` recipe needs that environment plumbed through before it is
used for a channel-gated release.
