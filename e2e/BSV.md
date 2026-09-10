# BSV exact and upto E2E

The TypeScript catalog exposes `/exact/bsv` (1000 satoshis) and `/upto/bsv`
(maximum 1000, actual 600). BSV is excluded from MCP. These tests require two
independent funded BRC-100 wallets and a Block Headers Service on `bsv:testnet`.
Mainnet runs are rejected. No wallet, source funding, or chain facts are mocked.

Add the variables declared in [the BSV catalog](config/mechanisms_bsv.json) to your local `.env-local`. `SERVER_BSV_ADDRESS` must be the
recipient wallet's identity public key. Wallet URLs must expose the SDK's
HTTPWalletJSON interface and permit the configured `BSV_ORIGINATOR`. The
recipient wallet must propagate transactions accepted by `internalizeAction`.
`BSV_HEADERS_URL` must describe the same chain as both wallets and the sources.

Prepare the inventory outside the test exchange using those wallets. Each pair
needs fresh cap sources owned by the payer and control sources owned by the
recipient, derived with the exported `BSV_UPTO_CAP_PROTOCOL_ID` and
`BSV_UPTO_CONTROL_PROTOCOL_ID`, `keyID = nonce`, `counterparty = "anyone"`, and
`forSelf = true`. Include complete Atomic BEEF ancestry for each selected output.
Retain these transactions and reserve all their outpoints for this run.

`BSV_INVENTORY_FILE` is an absolute path to this local JSON shape (placeholders
below are not runnable fixtures):

```json
{
  "network": "bsv:testnet",
  "payTo": "<recipient identity public key>",
  "fee": "10",
  "entries": [
    {
      "controlInputs": [
        {
          "nonce": "<32-byte base64>",
          "sourceTransaction": "<Atomic BEEF base64>",
          "sourceOutputIndex": 0
        }
      ],
      "capSources": [
        {
          "nonce": "<32-byte base64>",
          "sourceTransaction": "<Atomic BEEF base64>",
          "sourceOutputIndex": 0,
          "floorAmount": "100"
        }
      ]
    }
  ]
}
```

For example, a 1200-satoshi cap input with a 100-satoshi floor supplies exposure 1100. With a 10-satoshi control input, `fee = 10`, and actual amount 600, the
terminal has a 610-satoshi recipient output and 490-satoshi payer refund.
The scheme checks those values, scripts, signatures, and source proofs itself.
The E2E policy permits at most four sources, 64 KiB per source, and 256 KiB
terminal BEEF; normal HTTP header limits still apply, so use compact ancestry.

All processes use the same absolute `BSV_CLAIMS_DIRECTORY`. An exclusive file
claim permanently assigns each inventory pair to one quote across processes
and harness combinations. Never clear this directory, regroup used sources,
or replace the inventory with entries reusing consumed outpoints. This is
protection for one fixed E2E inventory, not a production wallet reservation
system. Exhaustion or process loss fails closed; prepare new source pairs.

The client adds a random application `quote` query value to its first request.
The server associates one preformed pair and a 60-second offer with that value;
the paid retry receives the same offer. Missing quotes and unknown paid quotes
allocate nothing. Startup route probes carry no quote and are intentionally
rejected. There are still two HTTP requests and one terminal settlement
transaction; preparing the source inventory is a separate funding operation.

`BSV_FACILITATOR_TOKEN` is a secret shared only by Resource Server and facilitator.
The existing `/settle` host authenticates it and checks `payTo` and the allocated
control offer before invoking the scheme. It is an E2E host credential, not a
scheme field. Protect non-loopback deployments with TLS. The client never
receives this token or contacts the facilitator directly.

```sh
pnpm install:all
pnpm test --testnet --families=bsv --versions=2 --facilitators=typescript --clients=typescript/http/fetch,typescript/http/axios --servers=typescript/http/express --min
```

Run offline inventory, authorization, and catalog checks with
`pnpm exec tsx --test bsv.test.ts`. Passing those checks is not evidence of live
wallet settlement. A live run must show recipient acceptance, terminal BEEF
delivery, and successful payer output internalization; retain its report and
transaction evidence before claiming E2E completion.
