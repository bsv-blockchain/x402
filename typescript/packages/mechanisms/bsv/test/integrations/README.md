# Live BSV wallet integration

`upto-bsv.test.ts` exercises the public exact and upto client, Resource Server, and facilitator roles with two distinct BRC-100 wallets on `bsv:testnet`. It uses the existing HTTP adapters for one PaymentRequired response and one paid retry, passes the metered amount through `SettlementOverrides`, and delivers the terminal Atomic BEEF to the payer through `PAYMENT-RESPONSE`.

Wallet calls and the SDK `WhatsOnChain("test")` ChainTracker are real. The tracker validates proof roots against block headers; transaction bytes come from the supplied BEEF and the settlement response. The HTTP adapter is in-process, so this suite does not establish proxy header compatibility or remote facilitator authentication.

The suite uses the package's in-memory stores in one process. It does not certify a deployment's durable coordination adapter or crash recovery.

The test first settles one upto terminal, checks the returned input/output amounts and both wallets' internalization of the identical subject, then repeats settlement without another wallet operation. It subsequently runs a separate exact payment through the same roles. The upto settlement itself uses one transaction; the exact payment is a second, independent purchase.

## Prerequisites

- Two running BRC-100 JSON wallet endpoints with different identity keys, both reporting `testnet`, and permissions for the chosen originator. The payer needs a spendable testnet balance for the exact payment and its miner fee.
- Fresh, unspent cap and control outputs reserved outside x402. Keep them reserved for the entire test and its 300-second authorization window. Do not let either wallet's automatic coin selection spend those outpoints elsewhere.
- Every source must be canonical P2PKH under the owning wallet's derived key: use the exported `BSV_UPTO_CAP_PROTOCOL_ID` or `BSV_UPTO_CONTROL_PROTOCOL_ID`, `keyID = nonce`, `counterparty = "anyone"`, and `forSelf = true` in `wallet.getPublicKey`. Each nonce is 32 random bytes encoded as padded standard base64. The test uses the corresponding wallet to sign; it accepts no fixture private keys.
- Each fixture source must carry its complete canonical Atomic BEEF subject closure and valid proof ancestry. The script and value at `sourceOutputIndex` must match the reserved output. No transaction index or synthetic ChainTracker is substituted when evidence is missing.
- A positive fixed floor for every cap input, `E = cap input total - floor output total >= M + F`, a metered amount `0 < A < M`, and sufficient dust-compatible floor/recipient/refund outputs for the wallets' policy. This tracer uses one recipient output and omits a zero refund deterministically.

This test admits at most eight combined sources, 256 KiB per source Atomic BEEF, and a 1 MiB terminal envelope. These are test deployment budgets, not protocol or HTTP-header limits.

Testnet coins are available through the [WhatsOnChain testnet faucet](https://faucet.whatsonchain.com/); availability is external to this suite. The source preparation application owns reservation and BEEF export. A previously consumed fixture cannot be reused.

## Fixture

Save an operator-owned JSON file outside the repository. Replace every placeholder with the identities and source evidence from those wallets:

```json
{
  "network": "bsv:testnet",
  "payerIdentityKey": "<payer compressed identity public key>",
  "recipientIdentityKey": "<recipient compressed identity public key>",
  "maximumAmount": "1000",
  "actualAmount": "600",
  "terminalFee": "5",
  "exactAmount": "5",
  "controlInputs": [
    {
      "nonce": "<32-byte padded-base64 control nonce>",
      "sourceTransaction": "<canonical base64 Atomic BEEF>",
      "sourceOutputIndex": 0
    }
  ],
  "capSources": [
    {
      "nonce": "<32-byte padded-base64 cap nonce>",
      "sourceTransaction": "<canonical base64 Atomic BEEF>",
      "sourceOutputIndex": 0,
      "floorAmount": "100"
    }
  ]
}
```

All amounts are satoshi strings. For this example, a 1,500-satoshi cap and 10-satoshi control yield `E = 1,400`, a 610-satoshi recipient output, and a 795-satoshi payer refund when `A = 600` and `F = 5`. The actual sources must have the stated values; this field-shape example contains no executable BEEF.

## Run

Running the enabled test signs and may broadcast real testnet payments. Obtain the wallet operator's authorization before running it. Local development validation must leave the opt-in variable unset; installation or a successful offline test run is not authorization to spend.

From `typescript/packages/mechanisms/bsv/`, after building the workspace dependencies:

```bash
BSV_UPTO_INTEGRATION=true \
BSV_UPTO_FIXTURE_FILE=/absolute/path/to/fresh-bsv-sources.json \
BSV_PAYER_WALLET_URL=http://127.0.0.1:3321 \
BSV_RECIPIENT_WALLET_URL=http://127.0.0.1:3322 \
BSV_UPTO_ORIGINATOR=x402-bsv-upto-integration.test \
pnpm exec vitest run --config vitest.integration.config.ts test/integrations/upto-bsv.test.ts
```

The suite skips when the opt-in or any required endpoint/fixture variable is absent. When enabled, an invalid fixture, unavailable wallet, rejected proof, refused internalization, or failed settlement fails the test. Mainnet and Teranode networks are intentionally excluded from this live tracer.

To verify collection without contacting wallets or spending:

```bash
BSV_UPTO_INTEGRATION=false \
pnpm exec vitest run --config vitest.integration.config.ts test/integrations/upto-bsv.test.ts
```

Use the explicit file filter. The existing `exact-bsv.test.ts` has its own `BSV_INTEGRATION` opt-in and throws at collection if it is absent; this addition does not change that existing behavior. A skipped suite establishes only load/type readiness, not real-wallet payment success, propagation, or catalog E2E coverage.
