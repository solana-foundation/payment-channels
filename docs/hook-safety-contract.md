# Callback safety contract

Financial checks belong in the channel program, not only in the callback SDK:
a malicious provider can choose not to use an SDK. The interface crate validates
callback provenance for honest consumers; core validates effects on protected
accounts when the callback returns.

## Boundary

Each enabled callback has its own before/after snapshot. Capture immediately
before CPI and reload immediately after it returns, before another callback or
channel transfer runs. Channel-owned transfers between phases are not hook effects.

An invariant failure aborts the instruction and rolls back the transaction's
account changes. Transaction fees are not refunded.

## Protected effects

| Account role | Permitted callback effect |
| --- | --- |
| Channel | No changes to state, configuration, accounting, guard or sequence |
| Escrow | No token balance or control changes |
| Payee / split recipient / treasury | No balance decrease or control changes, subject to the payer-refund alias rule below |
| Payer during funding or pre-distribution | Balance may increase, but not decrease; no control changes |
| Payer during post-distribution | Net debit at most the actual refund transferred by this operation; no unrelated control changes |

The refund allowance comes from core's executed transfer result, never from a
caller-supplied amount, planned entitlement, total deposit or settlement watermark.
A zero actual refund grants zero debit allowance.

Authority, delegate, close-authority and token-state changes are not incidental
balance changes. A legitimate delegated refund can reduce the existing delegated
allowance, but must not introduce new authority or increase spending permission.
For wrapped native tokens, an allowed refund transfer also moves the corresponding
lamports. That decrease is bounded by the permitted token debit; rent reserves and
unrelated lamports remain protected. Non-native token accounts cannot lose lamports.
Delegated allowance consumption must match the payer's net token debit. A callback
that combines delegated refund recovery with incoming tokens masking that debit
is rejected; split those unrelated actions instead of weakening the refund bound.

## Aliases

Token balances are fungible. A payer may also be a recipient. The post-hook
snapshot then includes both the merchant payout and the actual refund.
Allowing at most that refund to leave preserves the account's prior funds and
merchant payout:

```text
after_hook >= before_hook - actual_refund
```

Do not apply the refund allowance twice because the account appears in two roles.
Escrow equality takes precedence over every other role. Ordinary beneficiary
accounts receive no refund allowance.

## Scope and limits

These checks bound net effects on accounts supplied to the channel operation.
They do not prove the absence of temporary intermediate transfers that are
reversed before the callback returns. They do not inspect arbitrary provider
vaults or constrain the provider outside this transaction.

A callback can still fail or exhaust its budget and block progress. Upgrade
governance, issuer authorization, backing conservation, provider replay records
and recovery availability remain separate requirements.

## Required evidence

Tests must include successful malicious CPIs that violate a postcondition, not
only rejected token instructions. Assert that the intended invariant rejects the
transaction and all protected financial state rolls back. Cover each phase,
exact/over-limit refunds, preexisting payer funds, zero refunds, withdrawal then
terminal distribution, account aliases, authority changes and donations.

Keep the honest provider Surfpool flow and historical V1 client upgrade test
passing. V1 does not execute lifecycle hooks and must retain its original behavior.
