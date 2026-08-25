# BSV Deferred-Amount Extension (`upto`)

> **Status: experimental.** This is a thin extension of the
> [BSV `exact` profile](../exact/scheme_exact_bsv.md), not a second BSV payment
> protocol:
>
> ```text
> upto = exact + reusable cap signature + deferred actual amount
> ```

## 1. Scope

With `exact`, the client knows the amount before it creates the payment
transaction. With `upto`, the client first authorizes a maximum and the actual
amount is fixed later by one ordinary, fully signed BSV transaction.

One authorization is still single-use and has at most one x402 settlement.
Applications can reach that transaction in either of two ways:

- construct one agreed amount after usage is known; or
- retain successively signed, cumulative transactions while usage is
  delivered, then settle one of them.

Stream transactions share inputs and therefore conflict with one another. They
are alternatives for one settlement, not multiple pay-per-chunk settlements.
Application chunks are application data; this profile defines no stream object,
stream hash, commitment output, or additional settlement type.

Unless changed below, implementations MUST reuse BSV `exact` behavior:

- BRC-42/BRC-29 identities and derived recipient outputs;
- BSV CAIP-2 network, native asset, freshness, and wallet-network checks;
- BEEF or Atomic BEEF transaction transport and subject selection;
- source transaction, script, signature, and SPV validation; and
- recipient-wallet `internalizeAction` with BRC-29 remittance metadata.

The public implementation remains a thin extension of the existing
`@x402/bsv` client, server, and facilitator. SDK transaction objects, source
hydration, sighash construction, and owner accounting remain internal.

## 2. Wire model

The authorization payload retains the exact-compatible fields
`derivationPrefix`, `derivationSuffix`, `senderIdentityKey`, and primary
`outputIndex`. It adds one authorization:

```text
UptoBsvAuthorization = {
  authorizationId,       // lowercase hex canonical digest
  terms,                 // UptoBsvAuthorizationTerms from section 4
  capSignatures: [
    {
      inputIndex,
      transactionSignature,   // base64 DER, signed for 0x43
      authorizationSignature  // base64 DER over authorizationDigest
    }, ...
  ]
}
```

There MUST be exactly one signature pair for every cap input and none for
control inputs. `transactionSignature` contains DER only; the verifier appends
the `0x43` sighash byte when constructing the input unlocking script.
`authorizationSignature` directly authenticates the canonical terms that the
transaction sighash does not completely cover, including owner accounting,
recipient indices, and timing.

At settlement, the application adds one `UptoBsvTransactionVersion`:

```text
UptoBsvTransactionVersion = {
  authorizationId,
  transaction             // base64 BEEF or Atomic BEEF
}
```

This wrapper intentionally contains no declared amount, txid, revision, chunk
index, sequence, or Final flag. The verifier derives the txid, owner net deltas,
common control-input `nSequence`, and cooperative-close condition from the
signed transaction. This avoids duplicate fields that could disagree with the
evidence.

## 3. Amount is an owner net delta

Every value-bearing input and output has one opaque `owner` identifier:

```text
netDelta[owner] = sum(owner input values) - sum(owner output values)
```

- positive delta means the owner pays net satoshis;
- negative delta means the owner receives net satoshis; and
- all owner deltas sum to the transaction fee.

An owner may have multiple inputs and outputs. The verifier calculates amounts
only from sums; no individual output is the authoritative payment amount.

`input.kind` is only a signing-mechanism classification:

- `cap`: reusable payer authorization signature;
- `control`: fresh signature over each complete transaction.

Neither `owner` nor `kind` creates a payer/payee business-role hierarchy.
`chargedOwners` identifies which positive owner deltas form the x402 charge:

```text
maxAmount = sum(
  value(cap input) - value(its fixed same-index floor output)
) for charged owners

actualAmount = sum(netDelta[owner]) for charged owners

0 <= actualAmount <= maxAmount
```

At verify time, `PaymentRequirements.amount` is `maxAmount`. At settle time it
is `actualAmount`, recomputed from the signed transaction. The facilitator MUST
re-verify the authorization against the original maximum before comparing the
recomputed actual amount with settlement requirements.

The wire authorization and verifier permit multiple inputs and outputs. The
default client/facilitator adapter constructs the common two-party layout: one
cap input, one or more small recipient control inputs, payer floor and refund
outputs, and recipient payment output. Advanced allocations supply all output
amounts explicitly.

`owner` is signed accounting metadata, not proof of script ownership. The
recipient MUST independently derive every `paymentOutputIndexes` script from
the exact-compatible BRC-29 context and, before signing and again before
settlement, enforce:

```text
recipientReceipt =
  sum(recipient payment outputs)
  - sum(recipient control inputs)
  + fee

recipientReceipt >= actualAmount
```

This aggregate check preserves multiple inputs and outputs without trusting a
refund output's owner label. One x402 requirement still names one `payTo`; this
profile does not claim independently priced multiple payees in one settlement.

## 4. Authorization

`UptoBsvAuthorizationTerms` fixes:

- authorization profile version, network, and native BSV asset;
- `payTo`, payer identity, and exact-compatible BRC-29 derivation fields;
- every ordered input's opaque owner, signing kind, source transaction and
  output index, and source P2PKH public key;
- every ordered output's opaque owner, locking script, and optional fixed value;
- charged owners and recipient payment-output indices;
- transaction fee, first control sequence, `validAfter`, protocol `deadline`,
  and the transaction's absolute `nLockTime`.

Cap inputs MUST precede control inputs. Each cap input at index `i` has a fixed,
same-owner floor output at index `i`, locked to that cap key. Every other output
attributed to a charged owner MUST also use one of that owner's cap-input keys;
an owner label alone is not proof that value was returned to that owner. Adding,
removing, replacing, or reordering an input creates a different authorization.

The authorization identifier is:

```text
authorizationDigest = SHA256(
  UTF8("x402-bsv-upto-authorization-v1") || 0x00 ||
  UTF8(JSON.stringify(orderedCanonicalTuple))
)

authorizationId = lowercase_hex(authorizationDigest)
```

The tuple is exactly:

```text
[
  version,
  network,
  "BSV",
  lowercase(payTo),
  lowercase(senderIdentityKey),
  derivationPrefix,
  derivationSuffix,
  inputs.map(input => [
    input.owner,
    input.kind,
    lowercase(resolvedSubjectTxid),
    input.sourceOutputIndex,
    canonicalDecimal(resolvedSourceSatoshis),
    lowercase(resolvedSourceLockingScriptHex),
    lowercase(input.publicKey)
  ]),
  outputs.map(output => [
    output.owner,
    lowercase(output.lockingScript),
    output.fixedAmount === absent ? null : canonicalDecimal(output.fixedAmount)
  ]),
  chargedOwners,
  paymentOutputIndexes,
  canonicalDecimal(fee),
  sequenceStart,
  validAfter,
  deadline,
  nLockTime
]
```

`JSON.stringify` means UTF-8 JSON with no insignificant whitespace. Array order
is preserved; JSON integer members use ordinary base-10 notation; strings use
standard JSON escaping. `canonicalDecimal` is unsigned base 10 with no leading
zeroes except `"0"`. Opaque owners, network, and derivation strings are not
case-folded or Unicode-normalized. Source BEEF is represented by its resolved
subject txid, selected output index, value, and locking script, so two valid
BEEF encodings of the same source do not change the authorization. Each cap key
directly signs `authorizationDigest` as authorization evidence.

The three signed Unix-second fields have distinct meanings:

```text
validAfter < nLockTime < deadline
validAfter <= now < deadline   // verify, create, and settle
now >= nLockTime               // additional non-final settlement condition
```

`nLockTime` MUST be a time-based uint32 lock time (at least 500,000,000) and is
written directly to every transaction. A cooperative close makes every input
final, so it bypasses only `nLockTime`; it does not bypass the protocol window.
`deadline` is a participant acceptance cutoff, not a script expiry. Previously
signed P2PKH transaction bytes do not become cryptographically invalid at the
deadline. Local wall-clock checks also do not predict node or miner admission;
wallet or node acceptance remains authoritative.

### 4.1 Authorization digest vector

The following pretty-printed tuple is illustrative. The digest uses the compact
UTF-8 bytes produced by `JSON.stringify` as specified above, not the whitespace
shown here:

```json
[
  1,
  "bsv:testnet",
  "BSV",
  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  "AQIDBAUGBwg=",
  "MTcwMDAwMDAwMDAwMA==",
  [
    [
      "payer",
      "cap",
      "ddd60c9ce45e2f236aa3d0dca3805e04d662632f212da07b66e9c2d6938b504f",
      0,
      "1001",
      "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ],
    [
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "control",
      "4db9cd33e35292077b0498e4d9517e255d57cd61687f2393afae96f5edbea18d",
      0,
      "2",
      "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac",
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    ]
  ],
  [
    ["payer", "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", "1"],
    ["payer", "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", null],
    [
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac",
      null
    ]
  ],
  ["payer"],
  [2],
  "1",
  1,
  1700000000,
  1700000300,
  1700000120
]
```

the `authorizationId` is:

```text
7a9096b069b220dfc3158c41b816f453e98d53fbe7fdaa61c6137f23e5371a1a
```

## 5. Transaction signatures

### 5.1 Reusable cap signature

Every cap input at index `i` uses:

```text
input[i].nSequence = 0xffffffff
output[i]           = fixed same-owner floor
sighash             = SINGLE | FORKID (0x43)
```

`ANYONECANPAY` MUST NOT be set. Fork-id `hashPrevouts` therefore binds every
ordered cap and control prevout. `SIGHASH_SINGLE` binds the cap input's own final
sequence and same-index floor output while leaving other input sequences and
other output values available for later transactions.

The cap signature is reused unchanged in every signed transaction, including a
cooperative close.

### 5.2 Control signatures and `nSequence`

Every control input signs each complete transaction with
`ALL | FORKID` (`0x41`) without `ANYONECANPAY`. All control inputs use one common
`nSequence` and sign again whenever that sequence or any output changes.

The first non-final transaction uses signed `sequenceStart`. Each locally
accepted next stream transaction uses the preceding retained transaction's
control sequence plus one. Amount MUST NOT decrease. A participant verifies
this progression against the previous fully signed transaction it retained;
nodes do not perform this protocol comparison.

For cooperative close, only control inputs change to `0xffffffff` and re-sign.
All cap inputs already use `0xffffffff`, so all inputs are then final and
`nLockTime` is inoperative.

## 6. Default two-party allocation

Let the payer cap input contain `floor + maxAmount`. Let recipient control
inputs contain total value `R`, and let the fixed fee be `fee`, with `R > fee`.
For actual amount `A`:

```text
payer floor output  = floor
payer refund output = maxAmount - A
recipient output    = R - fee + A
```

This needs no matching recipient liquidity. The recipient supplies only a small
input used to control the complete transaction and to prevent its output value
from being redirected. `R > fee` also leaves a positive recipient output when
`A = 0`.

Example:

```text
payer cap input = 1100, floor = 100, maxAmount = 1000
control input R = 51, fee = 50, actual A = 700

outputs: payer floor 100, payer refund 300, recipient 701
payer delta     = 1100 - (100 + 300) = 700
recipient delta = 51 - 701 = -650
sum deltas      = 50 = fee
```

## 7. Verify and settle

1. The client obtains the recipient's small control input and immutable timing
   terms through an application-supplied transport.
2. The client creates the cap input and returns an authorization payload without
   a transaction version.
3. The facilitator verifies the authorization against the maximum before the
   resource handler runs. Every source MUST carry complete BEEF ancestry, and a
   required verifier MUST validate the full graph and its PoW/SPV anchors.
4. For negotiated-once or each cumulative stream update, the recipient signs one
   complete transaction. Each party may retain and validate the exact BEEF.
5. At settlement, the resource server's existing `enrichSettlementPayload` hook
   attaches the locally selected signed transaction, and settlement requirements
   carry the actual amount.
6. The facilitator re-verifies the authorization and every transaction input,
   independently checks the recipient receipt, recomputes the amount, and
   validates the selected transaction's complete BEEF.
7. Before wallet settlement, the facilitator atomically claims
   `(authorizationId, txid)` in shared durable storage, then internalizes all
   declared recipient payment outputs.

A non-final transaction is eligible for settlement only at or after its future
`nLockTime`. A cooperative-close transaction bypasses that delay but remains
subject to `validAfter <= now < deadline`. The stock facilitator chooses:

```text
validAfter = now
nLockTime  = validAfter + nonFinalDelaySeconds
deadline   = validAfter + maxTimeoutSeconds
```

where `0 < nonFinalDelaySeconds < maxTimeoutSeconds`. One authorization is
intended for at most one successful settlement, including a zero-amount
settlement.

Because BEEF validation and the settlement-store call are asynchronous, the
facilitator rechecks the signed window after each and immediately before wallet
settlement. A claim that completes outside the window remains guarded but MUST
NOT be sent to the wallet.

Complete BEEF proves that referenced transaction dependencies are present; the
required verifier additionally validates scripts and PoW/SPV anchors. Neither
check proves that an outpoint is currently unspent, and neither implies reliable
data retention. Ordinary wallet and node submission still determine acceptance
or double-spend observation.

The transaction-selection callback and control-input exchange are deliberately
transport-neutral. HTTP streaming alone is one-way after response headers; a
full stream implementation therefore uses an application endpoint, callback,
or duplex transport to exchange newly signed transactions.

Shared outpoints prevent multiple conflicting transactions from all becoming the
chain result, but do not prevent multiple x402 callers from observing successful
wallet settlement. The facilitator MUST therefore use an atomic settlement
store keyed by `authorizationId`, shared by replicas and durable across restarts.
The claim records the selected `txid`, an opaque per-acquisition token unique
across replicas and restarts, and a Unix-millisecond deletion bound covering the
signed deadline. Only that token can release the claim, and only when the wallet
definitively returns `accepted: false` without evidence of newly internalized
satoshis. Success, wallet replay, malformed wallet results, and indeterminate
outcomes retain it. Failure to claim or release fails settlement closed.

This settlement claim does not guarantee that an application handler runs
exactly once before settlement. Applications with non-idempotent delivery MUST
separately reserve `authorizationId` in shared durable storage after verify and
before the business side effect. Both records are application/facilitator state,
not node state or new BSV protocol objects.

## 8. Node observation and conflicts

Each signed version is an ordinary BSV transaction. Because versions share
inputs, any different transaction spending one of those outpoints is a double
spend from the observing party's transaction perspective.

Node submission uses the same observation as `exact`:

```text
accepted | double-spend | invalid | unknown
```

A concrete endpoint may additionally return competing txids, node evidence, or
an observation time. `nSequence` can influence that endpoint's local admission
or conflict policy when a party submits a later transaction. The observation is
always attached to that submitted transaction; this profile adds no node state
or node query.

`double-spend` proves a transaction conflict. It does not by itself prove which
party acted dishonestly: an older signed transaction may already have
propagated, nodes may have different caches, or the parties may independently
have selected different signed results.

## 9. Final and evidence

For each party, Final means only that the party has retained and accepted one
fully signed transaction as its result. Final is not a wire object or shared
state, and one party does not need a centralized acknowledgement to recognize
its own result. If both parties independently select the same transaction they
naturally agree; otherwise both signed transactions remain evidence of
disagreement. Later PoW/SPV inclusion evidence may support a chain-consensus
result, but it does not create an evidence-retention service.

Signatures authenticate the retained bytes and PoW/SPV can prove inclusion
relative to a header-chain view. Neither signatures, blockchain inclusion, nor
SPV imply permanent or reliable data retention. No wallet, facilitator, node,
relay, database, or blockchain is appointed as an evidence archive.

## 10. Required checks

Implementations MUST reject:

- an authorization ID or authorization signature that does not match its terms;
- a changed/reordered prevout, changed cap floor, non-final cap sequence, or
  `ANYONECANPAY` cap signature;
- a transaction whose control inputs do not share one valid sequence or whose
  signatures do not validate with `0x41`;
- a source or terminal BEEF with missing ancestry, or one rejected by the
  configured complete-graph and PoW/SPV verifier;
- inputs minus outputs differing from the signed fee;
- a charged-owner output not locked to one of that owner's cap keys;
- a charged-owner delta below zero or above its cap;
- a recipient receipt below the charged-owner amount, irrespective of owner
  labels;
- timing that does not satisfy `validAfter < nLockTime < deadline`, creation or
  settlement outside the protocol window, or a non-final settlement before
  `nLockTime`;
- a settlement amount differing from the recomputed transaction amount;
- a decreasing or non-consecutive locally compared stream transaction; and
- a duplicate transaction, or a second different transaction, after settlement
  of the same authorization; and
- settlement when the facilitator cannot atomically claim the authorization.

Required positive cases include zero actual amount, cooperative close, cap
signature reuse across increasing control sequences, multiple inputs/outputs in
the authorization verifier, complete BEEF and Atomic BEEF sources, non-final
settlement between `nLockTime` and `deadline`, historical signature verification
after `deadline`, cross-replica authorization consumption, and exact-path
regression tests.

## 11. References

- [BSV `exact` scheme](../exact/scheme_exact_bsv.md)
- [Network-agnostic `upto` scheme](./scheme_upto.md)
- [BRC-29](https://bsv.brc.dev/payments/0029)
- [BRC-42](https://bsv.brc.dev/key-derivation/0042)
- [BRC-62 BEEF](https://bsv.brc.dev/transactions/0062)
- [BRC-95 Atomic BEEF](https://bsv.brc.dev/transactions/0095)
- [BRC-100](https://bsv.brc.dev/wallet/0100)
