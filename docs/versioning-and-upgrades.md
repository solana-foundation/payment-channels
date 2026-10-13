# Same-address account compatibility

The program supports V1 and hooked V2 accounts in one runtime. An upgrade must
preserve existing V1 accounts and instructions; new clients opt into hooks with
explicit instructions. No deployment is performed by build or test recipes.

## Frozen layout, version-aware access

V1 is a frozen 256-byte prefix. Hooked V2 appends configuration and operation
state for a total of 1121 bytes. Validate program ownership, discriminator,
version and the exact supported size before borrowing a typed prefix or extension.
An unknown version is not a V1 account with ignorable trailing bytes.

This follows the subscriptions program's version-aware-loading and frozen-layout
approach. Its migration scaffold is not evidence of a completed V1-to-V2 migration:
the inspected subscriptions revision `56de552` still declares version 1.

## No forced migration

- Existing `open` creates V1 and preserves its wire contract.
- Existing V1 channels remain usable through their ordinary funding, settlement,
  withdrawal and closure paths.
- `openWithHooks` creates V2 with an immutable, explicitly authorized hook policy.
- V2 uses the hooked funding/distribution instructions even when no slots are enabled.
- Shared non-hook instructions validate either supported account format.

Storage growth would require additional rent and allocation. More importantly,
attaching hooks changes who can block funding or refunds. Neither is an implicit
side effect of using an existing channel. There is no migration instruction in
this revision. Finish existing channels and explicitly open new hooked channels.

## Recovery is not a hook bypass

V1 recovery remains available without migration. V2 principal distribution and
withdrawal still execute mandatory callbacks. Loading only its V1 prefix must
never authorize an unhooked refund. Rent reclaim after terminal distribution is
separate from moving principal and still validates the supported account format.

Unknown future account versions fail closed. Adding another version requires
explicit decisions about normal operations, recovery and any migration steps.

## Client and rollback boundaries

Old clients keep their original instruction encodings and continue operating on
V1 accounts. They are not expected to understand hooked accounts. New clients
must select the correct account codec and instruction family rather than infer
hooks from a program ID.

The alternate `devnet-deployment` address selects a deployment identity only;
both builds support both versions. It is not a migration mechanism, and accounts
at different addresses are not interchangeable.

Once V2 accounts exist, rolling the program back to a V1-only binary can strand
them. A rollback candidate must retain both formats or wait until every affected
V2 channel has completed its lifecycle.

## Upgrade acceptance tests

Run `just test-same-address-upgrade` with the prerequisites in
[`scripts/v1-v2-upgrade-e2e/README.md`](../scripts/v1-v2-upgrade-e2e/README.md).
It builds the historical `25df963` source and links its unchanged generated Rust
client, then reloads the new binary through offline Surfpool at the same address.
This proves executable-replacement compatibility, not a signed loader upgrade.

An upgrade regression must load the previous V1 binary, create and partially use
V1 accounts, replace the executable at the same program address, and then:

1. Continue the old accounts using unchanged V1 client instructions.
2. Create new V1 accounts using those same clients after the upgrade.
3. Create and operate hooked accounts using explicit V2 instructions.
4. Reject V1 instructions against V2 principal paths, including empty-hook V2.
5. Reject hooked instructions against V1 and unknown versions or malformed sizes.
6. Preserve refunds, settlement watermarks, voucher identity and atomic rollback.

Native tests, a new binary operating on fabricated accounts, and two separate
deployments do not by themselves demonstrate a same-address upgrade.
