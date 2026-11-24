# Canary devnet deployment

The `canary` channel (`Solex.toml`): the stable instruction set plus the
`hooks` feature, at its own address.

| Property | Value |
| --- | --- |
| Program | `CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ` |
| ProgramData | `CDMkCSmGv4NiEmNcnxGFNdwiSwXKZCwwKdV5Px2Sz53C` |
| Upgrade authority / devnet treasury | `4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap` |
| Source commit | `f186362` (`stack/nightly-6-settle-metered`: #100, #101, #102, #103, #109, #110) |
| Build | `just build-canary devnet` (`SOLEX_CHANNEL=canary SOLEX_CLUSTER=devnet`, `--features hooks`) |
| Compiler / architecture | platform-tools `v1.58`, `--arch v3` |
| Deployment slot | `520762057` |
| Executable SHA-256 | `731dfa219846dbcd1bdd11aefaf01fb25911d44706d34b713cd76097472e60a6` |
| IDL | published through the Program Metadata program ([explorer](https://explorer.solana.com/address/CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ/idl?cluster=devnet)) |

The hash is `solana-verify get-program-hash` of the deployed program and
`solana-verify get-executable-hash` of a local build at `f186362`; they match.
Builds of `stack/nightly-4` and `stack/nightly-5` do not, so the deployment
includes metered settlement.

The canonical program `CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX` was not
upgraded. No test callback adapter was deployed.

## Live credit-provider run

`scripts/credit-provider-e2e` in live mode against this deployment, with a
fresh `examples/credit-provider` program
(`5krCmPmknq9Gw8ZUrSka4Hof1fqTHMNn1EpGLLThnNor`) deployed by an ephemeral
issuer and a fresh SPL mint. All 45 steps passed, including the 11
rejections, each with its custody and channel accounts unchanged afterwards.

| Step | Transaction |
| --- | --- |
| `openWithHooks`: `preFund` debits 1,000 credits and backs the deposit | [`48V2fGth…`](https://explorer.solana.com/tx/48V2fGthiKBMoszkg2XjmqFL9hTJ4VodAb8TqL9ng63a6C6mx5S9wwN5vVUWyWp4AVm7ek2Tz51m8xsA9L2UK6eP?cluster=devnet) |
| `topUpWithHooks`: 200 more credits | [`2KrZ13bF…`](https://explorer.solana.com/tx/2KrZ13bFfyaE1RrC5YvJzHf27QQmqcUVfL4QzZt4Ucxo9QQFW4iHURHajEhDe2xzkTjfoKu4q1ucSgvKJZyN6Ug?cluster=devnet) |
| `distributeWithHooks`: payee 700, `postDistribute` returns 500 to custody and credits | [`91uzypra…`](https://explorer.solana.com/tx/91uzypraMTmVUJt6w28fVeccSmcjb2YKra5SJWZJcrKo1Vk5KFaeSFK4LAbXhJidEASZG9k2tTK5F6QpwjQGQtz?cluster=devnet) |
| `withdrawPayerWithHooks` before terminal distribution | [`2U7MYvLq…`](https://explorer.solana.com/tx/2U7MYvLqZj97v1QMKDED8LQ8b4JLy16nXHBRA82zyYk89uQGdd13nA1bS1hk5dDGmeFC21FvY595GDsUChf12Jhj?cluster=devnet) |

Reproduce, from the repository root, after building the provider with
`just test-credit-provider-surfpool` (or its provider `cargo build-sbf` line):

```sh
CARGO_TARGET_DIR=$PWD/target/credit-e2e-devnet \
CREDIT_E2E_LIVE=1 CREDIT_E2E_RPC=<https devnet RPC> \
CREDIT_E2E_FUNDER=<keypair with ~2 SOL> CREDIT_E2E_RUN_DIR=$(mktemp -d) \
CREDIT_PROVIDER_SO=$PWD/target/deploy/credit_provider.so \
SOLEX_CHANNEL=canary SOLEX_CLUSTER=devnet \
cargo run --manifest-path scripts/credit-provider-e2e/Cargo.toml
```

The public devnet RPC rate-limits the run; use a dedicated endpoint.
