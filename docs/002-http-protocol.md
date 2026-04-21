# ADR-002: HTTP Protocol & Session Lifecycle

**Status:** Draft

**Parent ADR:** ADR-001 Payment Channel State Machine

## Context

This ADR specifies the off-chain HTTP protocol for channel coordination, aligning with MPP [`draft-solana-session-00`](https://github.com/solana-foundation/mpp-specs/blob/a64edb477cfcb5e071e4f73f4227cf329dd1c4b5/specs/methods/solana/draft-solana-session-00.md).

## Decision

The client and server exchange payment credentials and vouchers. In the cooperative path, the server pays fees for the on-chain transactions it submits. Escape-route instructions (`requestClose`, `withdraw_payer`, `finalize`, `distribute`) are client-direct-to-RPC for when the server is unresponsive. Two canonical flows:

- **Happy path**: discovery -> open -> metered requests -> cooperative close (client `POST /channel/close`, server submits `settleAndFinalize` optionally bundled with `distribute`).
- **Forced close**: client broadcasts `requestClose` directly to RPC; after grace, anyone cranks `finalize` + `distribute`.

All on-chain instruction names referenced below are defined in ADR-001.

## HTTP Messages

Actors: **C** = client (payer). **S** = server (merchant).

| Direction | Transport | Wire shape | Drives on-chain ix |
|---|---|---|---|
| S → C | `402 Payment Required` + `WWW-Authenticate: Payment <auth-params>` header | auth-params: `id="…", method="solana", intent="session", request="<b64url-nopad(JCS(challenge-json))>"` | — |
| C → S | `POST /channel/open` | body: MPP credential envelope, `payload.action="open"`, carries `transaction` (base64 partial-signed open tx) | `open` |
| C → S | `GET <resource>` + `Authorization: Payment <b64url-nopad(JCS(credential-json))>` header | `payload.action="voucher"`, carries SignedVoucher | — (off-chain metering) |
| C → S | `POST /channel/topup` | body: MPP credential envelope, `payload.action="topUp"` (camelCase), carries `transaction` | `topUp` |
| C → S | `POST /channel/close` | body: MPP credential envelope, `payload.action="close"`, optional `payload.voucher` (SignedVoucher); no pre-signed tx | `settleAndFinalize` (optionally bundled with `distribute`) |
| S → C | Any 200 that accepted a voucher or submitted an on-chain tx on the client's behalf | `Payment-Receipt: <b64url-nopad(JSON)>` header | — |

### Notes

- **Minimum-deposit constraint:** `POST /channel/open` requires `payload.depositAmount >= challenge.methodDetails.minimumDeposit`. Enforced at the HTTP layer, not on-chain.
- **Server-submitted ixs:** `settle`, `settleAndFinalize`, and `distribute` are submitted directly by the server. In the cooperative path, the server triggers `distribute` (often bundled with `settleAndFinalize`) and may run mid-session distributes from `OPEN`.
- **Escape routes are direct-to-chain:** The client submits these directly to Solana RPC:
  - `requestClose`: Payer-signed. Callable in `OPEN`. Starts the grace period.
  - `withdraw_payer`: Payer-signed. Callable in `FINALIZED`. Refunds `deposit - settled`.
  - `finalize`: Permissionless. Post-grace. Transitions `CLOSING -> FINALIZED`.
  - `distribute`: Permissionless in `OPEN` and `FINALIZED`. Caller supplies splits preimage; program verifies hash against `Channel.distribution_hash`. From `OPEN`, advances `paid_out` by paying `settled - paid_out` to recipients (channel stays OPEN). From `FINALIZED`, also refunds `deposit - settled` to the payer (if `payerWithdrawnAt == 0`) and tombstones the PDA.
- **Escape-route self-sufficiency:** Clients persist the 402 challenge and `channelId` to independently invoke escape routes.
- **Distribution commitment:** The PDA stores a 32-byte sha256 digest of the splits preimage. Splits are passed to `open` and hashed on-chain, making them publicly recoverable from instruction data. `distribute` requires the caller to supply the preimage for hash verification.
- **Vouchers are purely off-chain:** No on-chain transactions during metered requests.

### Server-Side Validation

To avoid paying Solana network fees for invalid transactions and to ensure protocol security, the server MUST perform the following validations off-chain before submitting any transactions:

1. **`POST /channel/open` Payload Validation:** The server MUST strictly validate that the `distributionSplits`, `payee`, and `mint` in the payload exactly match what it requested in the `402` challenge. Failing to do so allows a malicious client to alter the distribution to themselves.
2. **Voucher Validation:** Before accepting a metered request or submitting `settle` / `settleAndFinalize`, the server MUST verify the Ed25519 signature over the Borsh-serialized voucher, check that `cumulativeAmount <= deposit`, and ensure the voucher is fresh (`expiresAt` is null or in the future). The same validation applies to any `voucher` carried in `POST /channel/close`.

**Challenge `request` object** (JCS-canonicalized then base64url-nopad into the `request` auth-param of `WWW-Authenticate: Payment`):

```json
{
  "amount": "<u64 decimal string — price per unit, in token base units>",
  "unitType": "<e.g. 'request' | 'token' | 'byte' — OPTIONAL>",
  "recipient": "<merchant pubkey base58>",
  "currency": "<SPL mint pubkey base58 — wrap SOL to wSOL>",
  "description": "<human-readable — OPTIONAL>",
  "externalId": "<server correlation id — OPTIONAL>",
  "methodDetails": {
    "network": "<'mainnet-beta' | 'devnet' | 'localnet' — OPTIONAL, default mainnet-beta>",
    "channelProgram": "<pubkey base58 — REQUIRED>",
    "channelId": "<pubkey base58 — OPTIONAL, resume existing channel>",
    "decimals": <integer 0-9 — REQUIRED when currency is an SPL mint>,
    "tokenProgram": "<pubkey base58 — OPTIONAL, SPL-Token or Token-2022>",
    "feePayer": <bool — OPTIONAL, true enables gasless flow>,
    "feePayerKey": "<pubkey base58 — REQUIRED when feePayer=true>",
    "minVoucherDelta": "<u64 decimal string — OPTIONAL; server-policy hint, not enforced on-chain>",
    "ttlSeconds": <integer — OPTIONAL; server-policy hint for voucher `expiresAt`, not enforced on-chain>,
    "gracePeriodSeconds": <integer — OPTIONAL, recommended 900>,

    // Solana-session extensions (not in MPP core; documented in Extensions section):
    "distributionSplits": [
      { "recipient": "<pubkey base58>", "shareBps": <integer 1–10000> }
      // 1..=MAX_SPLITS entries; every shareBps > 0; Σ shareBps == 10000.
      // Merchant's proposed splits; forwarded by the client as inputs to
      // `open` (program canonicalizes + hashes on-chain).
    ],
    "minimumDeposit": "<u64 decimal string — hard floor enforced at HTTP layer, not on-chain>"
  }
}

`authorizedSigner` is client-chosen and carried in the open credential's `payload`.
```

**SignedVoucher** (carried in `payload.voucher` of credentials; the inner `voucher` object is Borsh-serialized and Ed25519-signed by the payer, producing the base58 `signature`):

```json
{
  "voucher": {
    "channelId": "<PDA address base58>",
    "cumulativeAmount": "<u64 decimal string>",
    "expiresAt": "<RFC 3339 timestamp — OPTIONAL>"
  },
  "signer": "<payer pubkey base58>",
  "signature": "<base58 Ed25519 sig over Borsh(voucher)>",
  "signatureType": "ed25519"
}
```

## Happy Path

```mermaid
sequenceDiagram
    participant C as Client (payer)
    participant S as Server (merchant)
    participant P as Channel Program

    C->>S: GET /resource
    S->>C: 402 Payment Required + open-challenge

    C->>S: POST open credential<br/>(payer-signed partial `open` tx)
    S->>P: submit `open` ix (server = fee payer)
    P->>P: transfer deposit → PDA escrow<br/>init Channel<br/>state = OPEN
    P-->>S: OK
    S->>C: 200 + session established

    loop For each paid request
        C->>S: GET /resource + voucher {channelId, cumulativeAmount = N}
        S->>S: verify Ed25519, require N > acceptedCumulative
        S->>C: 200 + resource
    end

    Note over S: (optional) mid-session distribute
    S->>P: submit `distribute` ix (preimage)
    P->>P: verify hash(preimage)<br/>transfer (settled − paid_out) → recipients (per on-chain splits)<br/>paid_out = settled<br/>state stays OPEN
    P-->>S: OK

    Note over S: Server decides to close
    S->>P: submit `settleAndFinalize` ix (final voucher)
    P->>P: verify voucher, set settled<br/>state = FINALIZED
    P-->>S: OK

    S->>P: submit `distribute` ix (preimage)
    P->>P: verify hash(preimage)<br/>transfer (settled − paid_out) → recipients (per on-chain splits)<br/>transfer (deposit − settled) → payer<br/>realloc to 8 bytes<br/>state = tombstoned
    P-->>S: OK
```

## Client-Initiated Close

```mermaid
sequenceDiagram
    participant C as Client (payer)
    participant S as Server (merchant)
    participant A as Anyone (cranker)
    participant P as Channel Program

    alt Cooperative — server responsive
        C->>S: POST /channel/close<br/>(optional final voucher, no pre-signed tx)
        S->>P: submit `settleAndFinalize` ix (voucher optional)
        P->>P: (if voucher) set settled<br/>state = FINALIZED
        P-->>S: OK

        S->>P: submit `distribute` ix (preimage)
        P->>P: verify hash(preimage)<br/>transfer (settled − paid_out) → recipients (per on-chain splits)<br/>transfer (deposit − settled) → payer<br/>realloc to 8 bytes<br/>state = tombstoned
        P-->>S: OK
        S->>C: 200 + receipt { txHash, refunded }
    else Forced — server unresponsive
        C->>P: submit `requestClose` ix (direct RPC)
        P->>P: closureStartedAt = now<br/>state = CLOSING

        Note over C,P: wait until now ≥ closureStartedAt + GRACE

        A->>P: submit `finalize` ix (no voucher)
        P->>P: freeze watermark<br/>state = FINALIZED

        A->>P: submit `distribute` ix (preimage)
        P->>P: verify hash(preimage)<br/>transfer (settled − paid_out) → recipients (per on-chain splits)<br/>(if payerWithdrawnAt == 0) transfer (deposit − settled) → payer<br/>realloc to 8 bytes<br/>state = tombstoned
    end
```

## Wire Examples

Concrete request/response blocks for each flow.

**Example 1: 402 challenge (S -> C)**

Unauthenticated client requests a metered resource:

```http
GET /api/v1/inference/completion HTTP/1.1
Host: merchant.example
```

Server responds with a `402` and `WWW-Authenticate: Payment` challenge:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="018f1a2b-7d1e-7c4a-9e12-3d0f5a8b2c4d",
    method="solana", intent="session",
    request="eyJyZWNpcGllbnQiOiJQYXllZU1lcmNoYW50MTIzNC4uLiJ9"
```

`request` is the MPP auth-param. Decoding its base64url-nopad value yields the challenge JSON:

```json
{
  "amount": "10",
  "unitType": "request",
  "recipient": "PayeeMerchant1234567890abcdefghijklmnop",
  "currency": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "methodDetails": {
    "network": "mainnet-beta",
    "channelProgram": "PayCh111111111111111111111111111111111111",
    "decimals": 6,
    "feePayer": true,
    "feePayerKey": "SrvrFeePayer9876543210zyxwvutsrqponmlkji",
    "gracePeriodSeconds": 900,
    "distributionSplits": [
      { "recipient": "PayeeMerchant1234567890abcdefghijklmnop", "shareBps": 9500 },
      { "recipient": "PltfrmFee456789abcdefghijklmnopqrstuv",   "shareBps":  500 }
    ],
    "minimumDeposit": "1000000"
  }
}
```

**Example 2: `POST /channel/open` (C -> S)**

```http
POST /channel/open HTTP/1.1
Host: merchant.example
Content-Type: application/json

{
  "id": "018f1a2b-7d1e-7c4a-9e12-3d0f5a8b2c4d",
  "method": "solana",
  "intent": "session",
  "payload": {
    "action": "open",
    "channelId": "ChA9XyZabcdef1234567890abcdef1234567890abc",
    "payer": "PayerAbcdef1234567890abcdef1234567890abcde",
    "payee": "PayeeMerchant1234567890abcdefghijklmnop",
    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "authorizedSigner": "PayerAbcdef1234567890abcdef1234567890abcde",
    "salt": "42",
    "bump": 254,
    "depositAmount": "1000000",
    "distributionSplits": [
      { "recipient": "PayeeMerchant1234567890abcdefghijklmnop", "shareBps": 9500 },
      { "recipient": "PltfrmFee456789abcdefghijklmnopqrstuv",   "shareBps":  500 }
    ],
    "transaction": "AQABA4...base64-partial-signed-open-tx..."
  }
}
```

**Example 3: Metered `GET` with voucher (C -> S)**

```http
GET /api/v1/inference/completion HTTP/1.1
Host: merchant.example
Authorization: Payment eyJpZCI6IjAxOGYxYTJiLi4uIiwibWV0aG9kIjoic29sYW5hIi...
```

`Authorization: Payment <…>` decodes to:

```json
{
  "id": "018f1a2b-7d1e-7c4a-9e12-3d0f5a8b2c4d",
  "method": "solana",
  "intent": "session",
  "payload": {
    "action": "voucher",
    "voucher": {
      "voucher": {
        "channelId": "ChA9XyZabcdef1234567890abcdef1234567890abc",
        "cumulativeAmount": "42500"
      },
      "signer": "PayerAbcdef1234567890abcdef1234567890abcde",
      "signature": "5J7k...base58-Ed25519-sig-64-bytes...",
      "signatureType": "ed25519"
    }
  }
}
```

**Example 4: `POST /channel/topup` (C -> S)**

```http
POST /channel/topup HTTP/1.1
Content-Type: application/json

{
  "id": "018f1c3d-…",
  "method": "solana",
  "intent": "session",
  "payload": {
    "action": "topUp",
    "channelId": "ChA9XyZabcdef1234567890abcdef1234567890abc",
    "additionalAmount": "500000",
    "transaction": "AQABA...base64-partial-signed-topUp-tx..."
  }
}
```

**Example 5: `POST /channel/close` (C -> S)**

```http
POST /channel/close HTTP/1.1
Content-Type: application/json

{
  "id": "018f1d4e-…",
  "method": "solana",
  "intent": "session",
  "payload": {
    "action": "close",
    "channelId": "ChA9XyZabcdef1234567890abcdef1234567890abc",
    "voucher": {
      "voucher": {
        "channelId": "ChA9XyZabcdef1234567890abcdef1234567890abc",
        "cumulativeAmount": "842500",
        "expiresAt": "2026-04-20T18:30:00Z"
      },
      "signer": "PayerAbcdef1234567890abcdef1234567890abcde",
      "signature": "5J7k...base58-Ed25519-sig...",
      "signatureType": "ed25519"
    }
  }
}
```

`voucher` is OPTIONAL; omit it when no final settle is needed and the channel finalizes at the current on-chain `settled` watermark.

**Example 6: Successful response with `Payment-Receipt` (S -> C)**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Payment-Receipt: eyJtZXRob2QiOiJzb2xhbmEiLCJpbnRlbnQiOiJzZXNzaW9uIi...

{ "data": "...resource body or empty..." }
```

`Payment-Receipt` decodes to:

```json
{
  "method": "solana",
  "intent": "session",
  "reference": "ChA9XyZabcdef1234567890abcdef1234567890abc",
  "status": "success",
  "timestamp": "2026-04-20T18:42:03Z",
  "challengeId": "018f1a2b-7d1e-7c4a-9e12-3d0f5a8b2c4d",
  "acceptedCumulative": "42500",
  "spent": "250"
}
```

On close-receipt responses (`POST /channel/close`), add `"txHash": "<base58 solana sig>"` identifying the `settleAndFinalize` tx the server submitted (optionally bundled with `distribute`), and (if the bundled `distribute` ran) `"refunded": "<u64 decimal>"` for the `deposit - settled` leg paid back to the payer.
