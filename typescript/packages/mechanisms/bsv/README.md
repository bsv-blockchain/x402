# @x402/bsv

BSV (Bitcoin SV) blockchain implementation of the x402 payment protocol using the **Exact** and **Upto** payment schemes with **BRC-29 / BRC-121 native satoshi payments**.

## Installation

```bash
npm install @x402/bsv
```

## Overview

This package provides client, server, and facilitator components for handling x402 payments on BSV. `exact` fixes the payment amount when the client creates the transaction. `upto` extends that same path with a reusable maximum-payment signature and defers the actual amount until a fully signed transaction is selected.

| Scheme | Amount semantics | Client entrypoint | Server entrypoint | Facilitator entrypoint |
| --- | --- | --- | --- | --- |
| `exact` | One transaction for the required amount | `@x402/bsv/exact/client` | `@x402/bsv/exact/server` | `@x402/bsv/exact/facilitator` |
| `upto` | Maximum first, actual amount determined later | `@x402/bsv/upto/client` | `@x402/bsv/upto/server` | `@x402/bsv/upto/facilitator` |

For `exact`, the three roles behave as follows:

- **Client** — Derives a per-payment key from the recipient's identity key (BRC-42/BRC-29) and asks the client's BRC-100 wallet to create a fully-signed, fully-funded transaction paying it (BEEF format, SPV ancestry included)
- **Facilitator** — Wraps the _recipient's_ BRC-100 wallet: verifies payload structure, freshness, and exact amount, then settles by internalizing the payment output into the wallet (`internalizeAction`), which SPV-validates, takes custody, and rejects replays
- **Server** — Builds `PaymentRequirements` with satoshi price parsing (no silent fiat conversion — register a money parser for USD prices)

## Payment Flow (BRC-121 adapted to x402)

Unlike account-based chains, a BSV payment output is locked to a key that by default only the payer and the recipient can link to the recipient's identity key (BRC-42 ECDH derivation). A third party cannot take custody, and cannot verify the destination unilaterally, so the facilitator role is fulfilled by the recipient's own wallet — run in-process by the resource server or self-hosted as a facilitator service. (Either counterparty _can_ voluntarily prove a specific payment's linkage via BRC-100 `revealSpecificKeyLinkage` — BRC-69, verifiable per BRC-94's Schnorr ZKP — a path toward third-party verification and regulated-asset extensions; not required by this scheme.)

1. Server advertises `payTo` = the recipient wallet's identity public key (never appears on chain)
2. Client generates a fresh derivation prefix (nonce) and a timestamp suffix, derives the recipient's per-payment key, and creates the payment via `createAction` — the client pays the miner fee
3. Client sends `{ transaction (base64 BEEF), derivationPrefix, derivationSuffix, senderIdentityKey, outputIndex }`
4. Facilitator verifies structure, wallet-chain agreement, ±30 s freshness, **exact** amount, and that the P2PKH output pays the BRC-42-derived key for this payment
5. Settlement internalizes the output into the recipient wallet; replays are rejected via a facilitator txid dedup cache plus the wallet's merge signal (`isMerge` without newly internalized satoshis)
6. The wallet handles network propagation (e.g. via ARC)

## Upto Authorization and Settlement

`upto` preserves the existing BRC-29 identities, derivation metadata, BEEF transport, BSV asset rules, and recipient-wallet settlement path. It adds only the authorization needed to choose the actual amount later:

1. The server's `PaymentRequirements.amount` is the maximum authorized amount.
2. The recipient facilitator supplies a small control input. The payer signs its cap input with `SIGHASH_SINGLE | SIGHASH_FORKID`, binding its maximum debit and same-index floor output without selecting the actual amount.
3. The recipient signs a complete transaction version after the actual amount is known. The payer's charged amount is recomputed from its net input/output difference. The wire authorization and verifier permit multiple inputs and outputs; the default adapters construct the ordinary one-payer/one-recipient layout.
4. An application may stop after the first agreed transaction or retain successively higher cumulative versions while streaming. This is application behavior, not a signed `mode` or a separate stream settlement object.

The application supplies the transport for `UptoBsvControlProvider`, retains the signed authorization and transactions it needs, and configures the server's `getTransactionVersion` callback to select one at settlement. A transaction version carries only its `authorizationId` and exact BEEF bytes; amount, txid, `nSequence`, and cooperative close are derived during verification. Nodes only receive ordinary BSV transactions; conflicting versions are ordinary double spends, not an x402-specific node state machine.

The signed `validAfter`, `nLockTime`, and `deadline` fields are deliberately separate. Non-final versions settle only after `nLockTime`; every protocol operation remains inside `[validAfter, deadline)`. A cooperative close finalizes the control inputs and bypasses only `nLockTime`, never the deadline. The deadline is participant policy, not a script expiry.

```typescript
import { UptoBsvScheme as UptoBsvClientScheme } from "@x402/bsv/upto/client";
import { UptoBsvScheme as UptoBsvServerScheme } from "@x402/bsv/upto/server";
import {
  UptoBsvScheme as UptoBsvFacilitatorScheme,
  type UptoBsvSettlementStore,
} from "@x402/bsv/upto/facilitator";
import type { UptoBsvPayload, UptoBsvTransactionVersion } from "@x402/bsv";
```

The role-level flow is deliberately small:

```typescript
const facilitatorScheme = await UptoBsvFacilitatorScheme.create({
  wallet: recipientWallet,
  feeSatoshis: 1,
  nonFinalDelaySeconds: 120,
  // Required: validate the complete BEEF graph, scripts, and PoW/SPV anchors.
  verifyBeef: verifyCompleteBeefAgainstHeaderChain,
  // Required: an atomic shared store keyed by authorizationId. Its claims
  // must survive facilitator restarts until their Unix-ms deleteAfterMs time.
  settlementStore: sharedSettlementStore satisfies UptoBsvSettlementStore,
});

// In production this method is normally exposed through an authenticated,
// rate-limited application endpoint.
const clientScheme = new UptoBsvClientScheme(payerWallet, {
  controlProvider: facilitatorScheme,
});
const created = await clientScheme.createPaymentPayload(2, maximumRequirements);
const payload = created.payload as UptoBsvPayload;
const actualAmount = "250";
let previousVersion: UptoBsvTransactionVersion | undefined;

await facilitatorScheme.verify(
  { x402Version: 2, accepted: maximumRequirements, payload },
  maximumRequirements,
);
const selected = await facilitatorScheme.createTransactionVersion(payload, maximumRequirements, {
  amount: actualAmount,
  previous: previousVersion,
});

// The payer independently verifies the signed bytes before retaining them.
clientScheme.verifyTransactionVersion(payload, selected, previousVersion);
previousVersion = selected;

const serverScheme = new UptoBsvServerScheme({
  getTransactionVersion: () => selected,
});
// Register serverScheme normally. At settlement, x402 Core attaches `selected`
// and the settlement override carries `actualAmount` in requirements.amount.
```

## Supported Assets

| Type   | Symbol | Description     | Decimals |
| ------ | ------ | --------------- | -------- |
| Native | BSV    | Native satoshis | 8        |

Amounts are denominated in satoshis. There is no default USD conversion; use an explicit `{ amount: "<satoshis>", asset: "BSV" }` price, or register the bundled WhatsOnChain rate-feed parser (below) to accept dollar prices.

## Networks

| Network                         | Identifier    |
| ------------------------------- | ------------- |
| Mainnet                         | `bsv:mainnet` |
| Testnet                         | `bsv:testnet` |
| Teranode Test Net (Teratestnet) | `bsv:ttn`     |
| Teranode Scaling Test Net       | `bsv:tstn`    |
| Wildcard                        | `bsv:*`       |

Network identifiers follow the ChainAgnostic `bsv` namespace ([registration](https://github.com/ChainAgnostic/namespaces/pull/190)). `bip122` genesis references are ambiguous for BSV (shared genesis with BTC/BCH); this package refuses them rather than defaulting to BSV.

## Usage

### 1. Client Setup

The paying side needs a running BRC-100 wallet — `WalletClient` connects to the user's wallet (e.g. BSV Desktop).

```typescript
import { ExactBsvScheme } from "@x402/bsv/exact/client";
import { WalletClient } from "@bsv/sdk";
import { x402Client } from "@x402/core/client";

const client = new x402Client();
client.register("bsv:*", new ExactBsvScheme(new WalletClient()));
```

### 2. Server Setup

```typescript
import { ExactBsvScheme } from "@x402/bsv/exact/server";
import { x402ResourceServer } from "@x402/core/server";

server.register("bsv:*", new ExactBsvScheme());

// Route config — payTo is the recipient wallet's identity public key
const accepts = [
  {
    scheme: "exact",
    network: "bsv:mainnet",
    price: { amount: "1000", asset: "BSV" }, // 1000 satoshis
    payTo: process.env.BSV_IDENTITY_KEY!,
  },
];
```

#### USD prices via the WhatsOnChain rate feed

Register the bundled money parser to accept `price: "$0.001"` like other chains. Rates come from the WhatsOnChain exchange-rate API (cached 60 s, bounded stale fallback on outages); the satoshi amount is pinned when the 402 challenge is issued.

```typescript
import { createWhatsOnChainMoneyParser } from "@x402/bsv";

const serverScheme = new ExactBsvScheme().registerMoneyParser(createWhatsOnChainMoneyParser());
server.register("bsv:*", serverScheme);

// Now dollar prices work:
const accepts = [{ scheme: "exact", network: "bsv:mainnet", price: "$0.001", payTo: identityKey }];
```

### 3. Facilitator Setup

The facilitator holds the wallet that RECEIVES payments — settlement takes custody into it. Server deployments use a key-based wallet such as `ServerWallet` from [`@bsv/simple`](https://www.npmjs.com/package/@bsv/simple) (any BRC-100 `WalletInterface` works):

```typescript
import { ExactBsvScheme } from "@x402/bsv/exact/facilitator";
import { ServerWallet } from "@bsv/simple/server";
import { x402Facilitator } from "@x402/core/facilitator";

const wallet = await ServerWallet.create({
  privateKey: process.env.SERVER_PRIVATE_KEY!,
  network: "main",
  storageUrl: process.env.WALLET_STORAGE_URL ?? "https://store-us-1.bsvb.tech",
});

const scheme = await ExactBsvScheme.create({ wallet: wallet.getClient() });

// Register ONLY the network the wallet operates on. A scheme instance wraps a
// single wallet, and `verify`/`settle` reject any network that doesn't match
// the wallet's own `getNetwork()` (`invalid_network`). For multiple networks
// (mainnet / testnet / ttn / tstn), build a separate wallet + scheme per network.
const facilitator = new x402Facilitator();
facilitator.register("bsv:mainnet", scheme);
```

## Security Notes

- `payTo` **must** equal the facilitator wallet's identity key — the facilitator rejects payments it cannot take custody of (`invalid_exact_bsv_payload_payee_mismatch`)
- The payment output must carry **exactly** `requirements.amount` satoshis (stricter than plain BRC-121, which accepts overpayment) and must pay the BRC-42-derived key — verified via the wallet's own `forSelf` derivation before any resource work
- Freshness window: the timestamp encoded in `derivationSuffix` must be within ±30 s at verify time (configurable via `paymentWindowMs`); at settle time the window extends by `maxTimeoutSeconds`, the advertised settlement budget
- Replay protection: a facilitator-side txid dedup cache plus the wallet's merge signal (`isMerge` without newly internalized satoshis — both wallet-toolbox extensions to BRC-100); verification re-runs at settlement
- The subject transaction is resolved via the Atomic BEEF `atomicTxid`, matching what the wallet internalizes; SPV validity is enforced by the wallet during `internalizeAction` — settlement is the authoritative acceptance step
- An `upto` cap signature is a maximum-payment authorization, not a cryptographic expiry. `nLockTime` only constrains when a transaction becomes eligible for mining. Each party independently recognizes one fully signed version as its terminal transaction; there is no central `Final` state.
- `upto` fails closed without an application-supplied complete-BEEF and PoW/SPV verifier. This validates ancestry and anchors before resource work and again for the selected transaction; it does not prove an outpoint is unspent and does not imply data retention.
- Output `owner` values are signed accounting labels, not ownership proofs. The recipient independently derives its BRC-29 payment scripts and requires its real payment-output increase, adjusted for its control inputs and the fee, to cover the charged amount.
- `upto` requires an atomic `UptoBsvSettlementStore` shared by facilitator replicas and durable through each claim's Unix-ms `deleteAfterMs`; this consumes an `authorizationId` before wallet settlement. The store returns a per-acquisition token that must remain unique across replicas and restarts. A definitively rejected wallet attempt releases only that matching token, while success, replay, and indeterminate outcomes retain it. This settlement guard is separate from application delivery: non-idempotent handlers must also reserve `authorizationId` in shared durable storage before executing the business side effect.
- Cap and control sources are wallet `noSend` actions. Applications must release abandoned actions through their wallet's normal lifecycle. A remotely exposed control-proposal endpoint must authenticate, rate-limit, and deduplicate requests so callers cannot reserve recipient wallet funds without bound.

## References

- [BRC-121: Simple 402 Payments](https://bsv.brc.dev/payments/0121)
- [BRC-29: Simple Authenticated BSV P2PKH Payment Protocol](https://bsv.brc.dev/payments/0029)
- [BRC-42: BSV Key Derivation Scheme](https://bsv.brc.dev/key-derivation/0042)
- [BRC-62: BEEF](https://bsv.brc.dev/transactions/0062) / [BRC-95: Atomic BEEF](https://bsv.brc.dev/transactions/0095)
- [BRC-69: Revealing Key Linkages](https://bsv.brc.dev/key-derivation/0069) / [BRC-94: Verifiable Shared-Secret Revelation (Schnorr)](https://bsv.brc.dev/key-derivation/0094)
- [BRC-100: Wallet-to-Application Interface](https://bsv.brc.dev/wallet/0100)
- Spec: `specs/schemes/exact/scheme_exact_bsv.md`
- Upto spec: `specs/schemes/upto/scheme_upto_bsv.md`
