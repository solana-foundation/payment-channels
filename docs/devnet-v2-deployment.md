# V2 devnet deployment

| Property | Value |
| --- | --- |
| Program | `CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ` |
| ProgramData | `CDMkCSmGv4NiEmNcnxGFNdwiSwXKZCwwKdV5Px2Sz53C` |
| Upgrade authority / devnet treasury | `4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap` |
| Source commit | `8af1e565eb3fe7fae4ec2c6368acf1feb8c40167` |
| Build | `just build-v2-devnet` |
| Compiler / architecture | platform-tools `v1.58`, `--arch v3` |
| Deployment CLI | Agave `4.3.0` |
| Finalized deployment slot | `510665656` |
| Artifact bytes | `84960` |
| SHA-256 | `f4cb07673abfb998b7b1034d0f2629aabea068295490516c238d5d396ceaab83` |

[Finalized upgrade transaction](https://explorer.solana.com/tx/4HWTyqg8nMMPWF5uQUWeeP9EnYBQkZMF5qiD6SZmh8eN4oQ6txLLPewq1FrQmBGCCwnKqPaij92C1qmBJE3i7ytU?cluster=devnet).

The program already existed at this address. A finalized scan found no
program-owned accounts before the upgrade. The previous executable was
preserved locally before upload. An interrupted RPC upload was resumed using
the same buffer; the old executable remained installed until the successful
upgrade.

After finalization, `solana program dump --commitment finalized` retrieved
the executable and `cmp` verified an exact byte match with the tested artifact.
The ELF header reports `e_flags = 3`. The artifact passed all 12 lifecycle-hook
SBF tests before deployment. This is local runtime execution plus on-chain
deployment verification, not a live Coinflow redemption test.

The V1 program at `CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX` was not
upgraded. No test callback adapter or production issuer adapter was deployed.
