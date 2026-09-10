# @x402/bsv

BSV (Bitcoin SV) blockchain implementation of the x402 payment protocol using the **Exact** and **Upto** payment schemes with **BRC-29 / BRC-121 native satoshi payments**.

## Installation

```bash
npm install @x402/bsv
```

## Overview

This package provides client, resource-server, and recipient-wallet facilitator components for BSV. The `exact` scheme transfers one fixed amount. The `upto` scheme extends it with one reusable maximum authorization and a later actual amount.

- **Client** — For `exact`, creates the fully funded payment transaction. For `upto`, signs one maximum authorization, then verifies and retains the terminal transaction returned at settlement.
- **Facilitator** — Wraps the _recipient's_ BRC-100 wallet. It internalizes the fixed `exact` payment or completes one `upto` terminal transaction for the Resource Server's actual amount.
- **Server** — Builds `PaymentRequirements` with satoshi price parsing (no silent fiat conversion — register a money parser for USD prices)

## Exact Payment Flow (BRC-121 adapted to x402)

Unlike account-based chains, a BSV payment output is locked to a key that by default only the payer and the recipient can link to the recipient's identity key (BRC-42 ECDH derivation). A third party cannot take custody, and cannot verify the destination unilaterally, so the facilitator role is fulfilled by the recipient's own wallet — run in-process by the resource server or self-hosted as a facilitator service. (Either counterparty _can_ voluntarily prove a specific payment's linkage via BRC-100 `revealSpecificKeyLinkage` — BRC-69, verifiable per BRC-94's Schnorr ZKP — a path toward third-party verification and regulated-asset extensions; not required by this scheme.)

1. Server advertises `payTo` = the recipient wallet's identity public key (never appears on chain)
2. Client generates a fresh derivation prefix (nonce) and a timestamp suffix, derives the recipient's per-payment key, and creates the payment via `createAction` — the client pays the miner fee
3. Client sends `{ transaction (base64 BEEF), derivationPrefix, derivationSuffix, senderIdentityKey, outputIndex }`
4. Facilitator verifies structure, wallet-chain agreement, ±30 s freshness, **exact** amount, and that the P2PKH output pays the BRC-42-derived key for this payment
5. Settlement internalizes the output into the recipient wallet; replays are rejected via a facilitator txid dedup cache plus the wallet's merge signal (`isMerge` without newly internalized satoshis)
6. The wallet handles network propagation (e.g. via ARC)

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

Network identifiers follow the registered ChainAgnostic [`bsv` namespace](https://github.com/ChainAgnostic/namespaces/blob/main/bsv/caip2.md). `bip122` genesis references are ambiguous for BSV (shared genesis with BTC/BCH); this package refuses them rather than defaulting to BSV.

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

## Upto Payments

`upto` preserves the normal x402 exchange: one PaymentRequired response, one paid retry, and the existing settlement response. It adds no facilitator endpoint and the client does not contact the facilitator directly.

The signed amounts are:

```text
M = maximum service amount advertised and signed by the payer
A = actual service amount supplied at settlement (0 <= A <= M)
E = payer exposure fixed by cap inputs and payer floor outputs (E >= M)
F = terminal miner fee (0 <= F <= E - M)
R = payer refund = E - A - F
```

`E > M` is the normal fee-paying case. `E = M` only permits a zero-fee terminal transaction under this authorization.

The payer signs its cap authorization once; those signatures are reused unchanged in the terminal transaction. The recipient completes that transaction by fixing the actual allocation and signing the control inputs. The completed terminal is a peer-to-peer artifact needed by both parties: the recipient needs it to receive `A`, while the payer needs the same signed subject and a valid proof envelope to retain and spend its floor and refund outputs. A conforming party that wants to realize those outputs therefore has an economic incentive to retain the terminal, but that incentive is not a delivery or propagation guarantee. The recipient wallet retains the `exact` obligation to propagate promptly after acceptance; the payer may also submit the identical terminal transaction after receiving and verifying it. A post-selection failure does not revoke that transaction or make its shared inputs safe to authorize again. BEEF transports the transaction and available SPV evidence; it does not promise reliable delivery, permanent storage, mining, confirmation, or network-wide finality.

### Source reservation

Both roles reserve ordinary P2PKH sources before x402 consumes them:

- The recipient application prepares a control offer outside x402, including its Atomic BEEF, outpoint, nonce, and validity window. It must look up the same reservation by a stable quote/request key for the initial requirement and paid retry; a static offer shared across requests is unsafe.
- The payer application implements `UptoBsvCapSourceProvider` and returns cap sources reserved through the advertised deadline.

Use the exported wallet protocol identifiers when deriving those source keys; applications should not copy protocol strings:

```typescript
import { BSV_UPTO_CAP_PROTOCOL_ID } from "@x402/bsv/upto/client";
import { BSV_UPTO_CONTROL_PROTOCOL_ID } from "@x402/bsv/upto/facilitator";

await payerWallet.getPublicKey({
  protocolID: BSV_UPTO_CAP_PROTOCOL_ID,
  keyID: capNonce,
  counterparty: "anyone",
  forSelf: true,
});

await recipientWallet.getPublicKey({
  protocolID: BSV_UPTO_CONTROL_PROTOCOL_ID,
  keyID: controlNonce,
  counterparty: "anyone",
  forSelf: true,
});
```

The application is responsible for constructing the source transaction, retaining its Atomic BEEF, and preventing the source outpoint from being allocated elsewhere before the deadline.

### Role setup

```typescript
import { x402Client } from "@x402/core/client";
import { x402Facilitator } from "@x402/core/facilitator";
import { x402ResourceServer } from "@x402/core/server";
import { UptoBsvScheme as UptoBsvClient } from "@x402/bsv/upto/client";
import { UptoBsvScheme as UptoBsvFacilitator } from "@x402/bsv/upto/facilitator";
import { UptoBsvScheme as UptoBsvServer } from "@x402/bsv/upto/server";

const sourcePolicy = { maxSources: 4, maxAtomicBeefBytesPerSource: 512 };
const terminalPolicy = { maxAtomicBeefBytes: 4 * 1024 };

const clientScheme = new UptoBsvClient(payerWallet, {
  capSourceProvider, // Application-owned reservation callback.
  chainTracker,
  sourcePolicy,
  terminalPolicy,
});
const client = x402Client.fromConfig({
  schemes: [{ network: "bsv:mainnet", client: clientScheme }],
  spendControls: false, // Or configure an explicit BSV asset allowance/cap.
});

const terminalFee = 5n; // Recipient propagation policy.
const facilitatorScheme = await UptoBsvFacilitator.create({
  wallet: recipientWallet,
  chainTracker,
  sourcePolicy,
  terminalPolicy,
  terminalStore,
  admitFee: ({ feeHeadroom }) => feeHeadroom >= terminalFee,
  planTerminal: context => {
    if (terminalFee > context.feeHeadroom) throw new Error("insufficient fee headroom");
    const refund = context.exposure - context.actualAmount - terminalFee;
    return {
      recipientAmounts: [Number(context.actualAmount + context.controlInputTotal)],
      refundAmounts: refund === 0n ? [] : [Number(refund)],
    };
  },
});
const facilitator = new x402Facilitator().register("bsv:mainnet", facilitatorScheme);

// Keep the default settlement path inside the recipient-controlled process.
const resourceServer = new x402ResourceServer({
  verify: facilitator.verify.bind(facilitator),
  settle: facilitator.settle.bind(facilitator),
  getSupported: async () => facilitator.getSupported(),
}).register(
  "bsv:mainnet",
  new UptoBsvServer({
    authorizationStore,
  }),
);
```

For a separately deployed facilitator, use the existing `HTTPFacilitatorClient` authentication hook and enforce the matching credential and authorization at the facilitator host before it invokes the scheme:

```typescript
import { HTTPFacilitatorClient } from "@x402/core/server";

const headers = { Authorization: `Bearer ${await loadFacilitatorToken()}` };
const facilitatorClient = new HTTPFacilitatorClient({
  url: "https://facilitator.example",
  createAuthHeaders: async () => ({
    verify: headers,
    settle: headers,
    supported: headers,
  }),
});
```

The receiving host must validate that credential and authorize it for the referenced `payTo` and control offer before invoking scheme settlement. Configuring send-side headers alone does not implement that receiving check. The package assumes this trusted host boundary; it defines no settlement-caller credential. Local HTTP tests use a trusted in-process facilitator and do not establish remote authentication.

The sample limits above admit the package's complete 1×1 and 2×2 HTTP fixtures under an 8 KiB per-header budget. They are deployment examples, not protocol constants. Source and terminal parser caps are not by themselves transport budgets: Atomic BEEF is base64-encoded inside JSON and then encoded again for the x402 header. Measure all three complete headers with representative proofs, and lower the caps or use an environment with larger header limits when needed.

`authorizationStore` and `terminalStore` are deliberately narrow first-writer coordination seams. The former admits an authorization and binds `A`; the latter selects one terminal and records its accepted outcome. The package exports in-memory implementations for tests and single-process development; production deployments that span processes or survive restarts must inject durable atomic implementations. Neither store provides an outbox or makes application and wallet side effects exactly once, and the Resource Server store is not a settlement-response recovery channel.

Settlement never mutates the Client's payment payload or adds a server-owned payload field. The actual amount `A` travels only through the settlement-time `PaymentRequirements.amount`. This adds no HTTP round or facilitator endpoint.

At settlement, pass `{ amount: A }` through the existing `SettlementOverrides`. Omitting the override means `A = M`. Once a terminal has been selected and its evidence revalidates, both successful and structured unsuccessful `PAYMENT-RESPONSE` values carry its `A` and full Atomic BEEF in `extra.settlementTransaction`. A success also carries the terminal txid, and the registered client hook verifies the evidence before internalizing all payer-owned outputs. A failure keeps `transaction` empty; the hook verifies and retains the selected terminal without a payer-wallet effect, so a later conflicting result is rejected and a later identical success can be internalized once. Failures before terminal selection, and fail-closed results caused by unavailable or invalid selected evidence, carry no amount or terminal evidence.

The reference client rejects a conflicting terminal while the same scheme instance retains its selected record. It does not claim restart-stable payer retention; applications that need that policy must retain and enforce it outside the scheme. The reference map deliberately has no automatic eviction, because silently forgetting a selected terminal would weaken this check; applications should scope the scheme instance to their intended retention lifetime.

A fresh verification is not a settlement-evidence recovery channel: after any terminal has been selected, later paid requests fail closed during verification, and the facilitator returns revalidated selected evidence only to repeated settlement invocations (see "Deadline, single use, and retry" in the upto spec).

The authorization format is compatible with application-level streaming: a recipient may form complete, amount-increasing non-final candidates from the same payer cap signatures. Those candidates remain outside the x402 exchange. The package intentionally exposes no stream, session, revision, transaction-family, or node-selection API, and x402 settlement selects only one final terminal transaction.

### Validation

Run `pnpm --filter @x402/bsv test` from `typescript/` for offline transaction, signature, amount, single-use, and HTTP-flow tests. These tests use real SDK transactions and signatures with deterministic chain facts and simulated wallet acceptance; they do not establish live wallet custody or propagation.

The [dual-wallet integration guide](test/integrations/README.md) describes the opt-in test using funded BRC-100 wallets and externally prepared source BEEF. That test must be run separately; an environment-gated skip is not live payment evidence.

The [BSV E2E guide](../../../../e2e/BSV.md) provides the three-role HTTP setup and catalog commands for both `exact` and `upto`. It uses the same public interfaces as applications, without a new facilitator endpoint.

## Security Notes

For `exact`:

- `payTo` **must** equal the facilitator wallet's identity key — the facilitator rejects payments it cannot take custody of (`invalid_exact_bsv_payload_payee_mismatch`)
- The payment output must carry **exactly** `requirements.amount` satoshis (stricter than plain BRC-121, which accepts overpayment) and must pay the BRC-42-derived key — verified via the wallet's own `forSelf` derivation before any resource work
- Freshness window: the timestamp encoded in `derivationSuffix` must be within ±30 s at verify time (configurable via `paymentWindowMs`); at settle time the window extends by `maxTimeoutSeconds`, the advertised settlement budget
- Replay protection: a facilitator-side txid dedup cache plus the wallet's merge signal (`isMerge` without newly internalized satoshis — both wallet-toolbox extensions to BRC-100); verification re-runs at settlement
- The subject transaction is resolved via the Atomic BEEF `atomicTxid`, matching what the wallet internalizes; SPV validity is enforced by the wallet during `internalizeAction` — settlement is the authoritative acceptance step

For `upto`:

- Every source and the terminal Atomic BEEF is verified before use; injected policy bounds source counts and encoded sizes.
- `M` bounds conforming service value; `E` is the payer-signed worst-case exposure, including fee headroom.
- Recipient and payer amounts are recomputed from every transaction input and output. The service amount is distinct from the miner fee.
- The scheme defines no settlement-caller credential. A remotely reachable facilitator host must authenticate the Resource Server and authorize it for the referenced `payTo` and control offer before invoking scheme settlement; local HTTP tests are not remote-authentication evidence.
- BEEF and SPV establish transaction ancestry, not global unspentness. Admission rejects conflicts visible in the supplied source closures, including a selected outpoint already consumed there. A spend outside that evidence can still cause settlement to fail; deployments may strengthen admission through their own wallet or endpoint policy.
- Authorization and terminal first-writer records fail closed when their prior outcome cannot be determined. They do not make handler or wallet side effects exactly once.

For both schemes, BEEF, signatures, SPV proofs, and settlement records are evidence, not reliable data-retention guarantees.

## References

- [BRC-121: Simple 402 Payments](https://bsv.brc.dev/payments/0121)
- [BRC-29: Simple Authenticated BSV P2PKH Payment Protocol](https://bsv.brc.dev/payments/0029)
- [BRC-42: BSV Key Derivation Scheme](https://bsv.brc.dev/key-derivation/0042)
- [BRC-62: BEEF](https://bsv.brc.dev/transactions/0062) / [BRC-95: Atomic BEEF](https://bsv.brc.dev/transactions/0095)
- [BRC-69: Revealing Key Linkages](https://bsv.brc.dev/key-derivation/0069) / [BRC-94: Verifiable Shared-Secret Revelation (Schnorr)](https://bsv.brc.dev/key-derivation/0094)
- [BRC-100: Wallet-to-Application Interface](https://bsv.brc.dev/wallet/0100)
- Spec: `specs/schemes/exact/scheme_exact_bsv.md`
- Upto spec: `specs/schemes/upto/scheme_upto_bsv.md`
