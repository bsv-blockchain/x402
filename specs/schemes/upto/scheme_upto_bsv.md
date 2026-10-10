# Scheme: `upto` on `BSV`

## Summary

BSV `upto` extends [BSV `exact`](../exact/scheme_exact_bsv.md) with a
reusable maximum authorization and a deferred actual amount:

```text
upto = exact + reusable maximum authorization + delayed actual amount
```

The payer performs one authorization action: one authorization signature and
one reusable cap signature per cap input, never a new signature per candidate.
The cap inputs fix payer-owned floor outputs and bound aggregate exposure `E`.
The recipient contributes at least one control input; only the recipient's
derived key can complete a transaction over the shared inputs. After the
protected resource runs, the recipient forms a complete terminal transaction
for actual amount `A <= M`. Once that fully signed terminal is selected and its
evidence revalidates, settlement results carry it as Atomic BEEF so the payer
can verify the same transaction and internalize all payer-owned outputs. A
fail-closed result caused by unavailable or invalid evidence carries neither
the amount nor the terminal.

Unless this document says otherwise, BSV `exact` defines the network and asset
identifiers, wallet-chain agreement, freshness, BRC-29/BRC-42 derivation,
wallet internalization, and settlement-success semantics. This profile
supports x402 version 2 only.

### Enforcement boundary

The authorization signature binds `payTo`, maximum `M`, and the validity
window. Cap signatures bind the complete input set and payer-owned floors and
mechanically limit payer exposure to `E`. Only the key derived for `payTo` can
sign the control inputs and complete a transaction over those inputs.

Conforming participants enforce single admission, `A <= M`, recipient-output
allocation, and the validity window. Standard P2PKH does not covenant those
rules, and cap signatures do not expire. Transactions sharing the inputs remain
ordinary conflicts. Verification uses `amount = M`; settlement uses
`amount = A`, while `PaymentPayload.accepted.amount` remains `M`.
`M` bounds conforming service value; `E` is the payer-signed worst-case
exposure, and a recipient that violates this profile can consume up to `E`.

## Control offer

The recipient application prepares and reserves a control source outside the
x402 exchange, then advertises it in `PaymentRequirements.extra.control`:

```json
{
  "scheme": "upto",
  "network": "bsv:testnet",
  "asset": "BSV",
  "amount": "700",
  "payTo": "<compressed recipient identity key>",
  "maxTimeoutSeconds": 60,
  "extra": {
    "paymentFlow": "authorization",
    "control": {
      "inputs": [
        {
          "nonce": "<32-byte padded-base64 nonce>",
          "sourceTransaction": "<canonical base64 Atomic BEEF>",
          "sourceOutputIndex": 0
        }
      ],
      "validAfter": 2000000000,
      "deadline": 2000000060
    }
  }
}
```

- `inputs` is a non-empty ordered array. Each `nonce` is padded standard
  base64 for exactly 32 random bytes and is unique within the offer.
- `sourceTransaction` is canonical base64 Atomic BEEF whose subject contains
  the selected positive P2PKH output. `sourceOutputIndex` is its uint32 index.
- `validAfter` and `deadline` are safe uint32 Unix seconds with
  `500000000 <= validAfter < deadline` and
  `deadline - validAfter <= maxTimeoutSeconds`.

This profile adds no facilitator endpoint or request round. The application
MUST associate the same reserved offer with the initial PaymentRequired
response and its paid retry. The recipient retains those control outpoints,
and the payer retains its later cap outpoints, through the validity window and
any settlement call admitted within it. Spending one early makes the
authorization un-settleable; reservation and release are local wallet policy.

Before reserving cap sources or creating any payer signature, the Client MUST
validate the control-offer shape and window, each Atomic BEEF and selected
outpoint, and that each selected P2PKH output belongs to the control key derived
from `payTo`. After selecting cap sources and before signing, it MUST also
reject an outpoint repeated within or across the two roles.

## Wire format

`PaymentRequirements` has the BSV `exact` shape with these deltas:

- `scheme` MUST be `"upto"`.
- `amount` is maximum `M` at verification and actual `A` at settlement.
- `extra.control` is the control offer above.
- `extra.paymentFlow`, when present, MUST be `"authorization"`; no other
  payment flow is supported.

The corresponding `PaymentPayload` has the following field shape. Its
`accepted` member is the complete `PaymentRequirements` object above:

```json
{
  "x402Version": 2,
  "accepted": {
    "scheme": "upto",
    "network": "bsv:testnet",
    "asset": "BSV",
    "amount": "700",
    "payTo": "<compressed recipient identity key>",
    "maxTimeoutSeconds": 60,
    "extra": {
      "paymentFlow": "authorization",
      "control": {
        "inputs": [
          {
            "nonce": "<32-byte padded-base64 nonce>",
            "sourceTransaction": "<canonical base64 Atomic BEEF>",
            "sourceOutputIndex": 0
          }
        ],
        "validAfter": 2000000000,
        "deadline": 2000000060
      }
    }
  },
  "payload": {
    "senderIdentityKey": "<compressed payer identity key>",
    "derivationPrefix": "<padded base64>",
    "derivationSuffix": "<padded base64 timestamp>",
    "capInputs": [
      {
        "nonce": "<32-byte padded-base64 nonce>",
        "sourceTransaction": "<canonical base64 Atomic BEEF>",
        "sourceOutputIndex": 0,
        "floorAmount": "100",
        "transactionSignature": "<padded base64 DER>"
      }
    ],
    "authorizationSignature": "<padded base64 DER>"
  }
}
```

The Client submits that payload to the Resource Server, which forwards it to
the existing facilitator `verify` interface; `capInputs` is non-empty.
`PaymentPayload.accepted` contains the advertised control offer unchanged, and
its `amount` remains the signed `M`. At settlement the Resource Server
supplies only the settlement-time `PaymentRequirements.amount` `A` to the
facilitator. Settlement-time `requirements.extra` is not an authorization
fact.

Identity keys, derivation fields, and the timestamp encoded by
`derivationSuffix` follow BSV `exact`. Its payment-window freshness and the
control offer's `validAfter`/`deadline` are independent checks and both apply.
Amounts are canonical unsigned decimal satoshi strings. Every cap nonce is
padded standard base64 for exactly 32 random bytes and is unique among cap
inputs. Signatures are padded standard base64. `maxTimeoutSeconds` is a
positive uint32.

## Keys and signatures

| Source  | `protocolID`                   | `keyID` | owner `counterparty` | owner `forSelf` |
| ------- | ------------------------------ | ------- | -------------------- | --------------- |
| cap     | `[2, "x402 bsv upto cap"]`     | `nonce` | `"anyone"`           | `true`          |
| control | `[2, "x402 bsv upto control"]` | `nonce` | `"anyone"`           | `true`          |

These are the source owner's private/public-key derivation parameters. An
independent verifier derives the same public key through BRC-42's public
`"anyone"` derivation: the derivation root is the public `"anyone"` key and the
counterparty is the source owner's identity (`senderIdentityKey` for cap
sources or `payTo` for control sources). It MUST NOT substitute the verifier's
own wallet root.

### Cap signatures

Every cap input selects a positive payer P2PKH source and has sequence
`0xffffffff`. Its same-index output is a positive, fixed payer-owned floor of
`floorAmount`. The payer signs input `i` with
`SIGHASH_SINGLE | SIGHASH_FORKID` (`0x43`) without `ANYONECANPAY`.

The signature binds version, `nLockTime`, all input outpoints and their order,
the signed input's source value and locking script, that input's final
sequence, and output `i`. It does not bind other input sequences or later
outputs. `transactionSignature` is the strict-DER, low-S signature without
the sighash byte. The unlocking script appends byte `0x43` to those exact DER
bytes and then pushes the derived compressed public key. Every candidate
reuses the payload's exact cap signature bytes.

To create or verify these signatures before `A` is known, use the transaction
template below with all cap and control outpoints, final cap sequences,
`nLockTime = deadline`, and only the ordered floor outputs. Control sequences
may use any uint32 value for this operation because `0x43` does not bind them;
later recipient and refund outputs do not enter a cap input's signature hash.

### Control signatures

The recipient signs every control input with
`SIGHASH_ALL | SIGHASH_FORKID` (`0x41`) without `ANYONECANPAY`. The signature
binds version, `nLockTime`, every input outpoint and sequence, every output,
and the signed input's source value and locking script. It does not bind other
inputs' source values, scripts, or unlocking scripts.

The unlocking script pushes a strict-DER, low-S signature with byte `0x41`
appended, followed by the derived compressed public key. All control inputs in
an intermediate candidate use the same non-final sequence `q`; a terminal
uses `0xffffffff` for every input.

## Authorization digest

The `v1` suffix versions this signed domain; it does not mean x402 version 1.
Source txids are resolved from the Atomic BEEF subjects, so changing only an
equivalent BEEF envelope does not change the authorization. Nonces are unique
within each role. A nonce MAY occur once in each role, but a source outpoint
MUST NOT occur more than once anywhere.

After validating every field, encode the following lines as UTF-8 joined by
LF, with no trailing LF:

1. `x402-bsv-upto-authorization-v1`
2. `network`
3. `asset`
4. `maximumAmount`
5. lowercase `payTo`
6. `maxTimeoutSeconds`
7. `validAfter`
8. `deadline`
9. number of control inputs
10. for each control input in order: `nonce`, `sourceTxid`, `sourceOutputIndex`
11. lowercase `senderIdentityKey`
12. `derivationPrefix`
13. `derivationSuffix`
14. number of cap inputs
15. for each cap input in order: `nonce`, `sourceTxid`, `sourceOutputIndex`, `floorAmount`

Integers and amounts use canonical unsigned decimal. Txids are 64 lowercase
hex characters in conventional display order. Base64 fields use padded
standard base64; identity keys are valid compressed secp256k1 public keys.
No encoded field may contain LF. Hash the canonical bytes once with SHA-256.

`authorizationSignature` signs that 32-byte digest through BRC-100
`hashToDirectlySign` with protocol ID
`[2, "x402 bsv upto authorization"]`, key ID
`"<derivationPrefix> <derivationSuffix>"`, and counterparty `"anyone"`.
Verification uses the same public `"anyone"` derivation with
`senderIdentityKey` as counterparty; it does not use the verifier's wallet
root. The wire field is padded standard base64 of a canonical strict-DER,
low-S ECDSA signature and contains no transaction-sighash byte.

The digest is the authorization's local single-consumption key.

### 2x2 known-answer vector

This vector uses the public key for private key 42 as `payTo`, the public key
for private key 41 as `senderIdentityKey`, and fixed asymmetric source txids.
Implementations MUST reproduce its SHA-256 digest.

```text
x402-bsv-upto-authorization-v1
bsv:testnet
BSV
700
02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af
60
1800000000
1800000060
2
FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ=
96c435b189fd6c533b9c51472009153d56ed411714b7925235931506ae289dd7
0
FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRU=
7a7d34973ccd2d49e1d07cd619449cef9fcb57666846b55dabfc2fd9b8e201ba
0
037a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb
Q2ludlYxMjM0NTY3ODkwMTIz
MTgwMDAwMDAwMDAwMA==
2
CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=
597b3e7fa9b2dc31b27a7e751613e1f768bbe8386af96ecd32ee4b8e9376a768
0
100
CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=
315d09801593af461928d8f9b6bb683ef9067437653c5bb5b008a997fd2962ed
0
100
```

```text
sha256 = 8e34760db6a96dac832368a8d499bd45165380a82ac36b9047db3000796b3619
```

## Transaction construction

Every complete candidate uses this template:

```text
version:   1
nLockTime: deadline

inputs:
  1. payer cap inputs, in payload order
  2. recipient control inputs, in offer order

outputs:
  1. one fixed payer-owned floor per cap input, at the same index
  2. one or more recipient outputs
  3. zero or more payer-owned refund outputs
```

Let:

```text
M = PaymentPayload.accepted.amount
E = sum(cap input values) - sum(fixed floor values)
A = sum(recipient output values) - sum(control input values)
F = sum(all input values) - sum(all output values)
R = sum(payer-owned refund output values)
```

Overflow-safe arithmetic MUST establish:

```text
1 <= M <= 2100000000000000
E >= M
0 <= A <= M
0 <= F <= E - M
R = E - A - F
payerDebit = A + F <= E
```

`M` and `A` are service value net received by `payTo`; miner fee `F` belongs
to neither amount. Normally `E > M` supplies fee headroom. If `E = M`, this
template permits only `F = 0`. No `maxFee`, fee-rate rule, dust constant, or
miner-policy state is added. The recipient decides whether the available
headroom is acceptable before signing.

Every serialized output is positive. A zero refund is omitted
deterministically. If positive `R` cannot be represented under local output
policy, the recipient refuses instead of changing `A` or discarding value.
Verification enumerates every input and output and aggregates values by owner;
it does not infer ownership from an assumed input or output count.

### Output derivation

Let `t` be the decimal Unix-millisecond timestamp decoded from the exact-style
`derivationSuffix`, and `k` the global output index:

```text
recipientSuffix(t,k) = base64(UTF8("<t> upto recipient <k>"))
floorSuffix(t,k)     = base64(UTF8("<t> upto floor <k>"))
refundSuffix(t,k)    = base64(UTF8("<t> upto refund <k>"))
```

Recipient outputs are forward BRC-29 payments to `payTo`. Floors and refunds
are reverse BRC-29 payments to `senderIdentityKey`. Every BRC-100
`paymentRemittance` uses the payload `derivationPrefix` and:

| Output           | `derivationSuffix`     | `senderIdentityKey`         |
| ---------------- | ---------------------- | --------------------------- |
| recipient at `k` | `recipientSuffix(t,k)` | payload `senderIdentityKey` |
| floor at `k`     | `floorSuffix(t,k)`     | `payTo`                     |
| refund at `k`    | `refundSuffix(t,k)`    | `payTo`                     |

The recipient wallet internalizes every recipient output in one wallet
operation. From the returned BEEF, the payer may internalize every floor and
refund. A payer-side failure does not reverse recipient settlement.

Verification first matches the signed floors by index. It then classifies each
remaining output by deriving both role scripts for that global index: exactly
one role MUST match, at least one recipient output MUST occur, and no recipient
output may follow a refund. No output-count or role field is added to the wire.

## Source BEEF validation

Every source is canonical base64 Atomic BEEF whose subject is the selected
source transaction and whose selected output is positive P2PKH. Implementations
MUST apply finite local input and byte limits before expensive validation. They
then validate Atomic BEEF structure, merkle proofs against an appropriate chain
tracker, unmined ancestor scripts, unique outpoints, and consistent transaction
values and scripts across all sources. Every transaction MUST have unique input
outpoints. Across the union of complete transactions in all source subject
closures, a canonical input outpoint MUST NOT be consumed by two transactions
with different txids; the same complete transaction MAY appear in multiple
source envelopes. The canonical coinbase null outpoint is excluded from this
conflict check. A selected source outpoint MUST NOT already be consumed by any
complete transaction in the union of source subject closures.
Every complete unmined transaction in the source subject closure MUST also be
context-independently final: `nLockTime` is zero or every input sequence is
`0xffffffff`. This avoids treating script and SPV validation as proof that a
future-locked source is spendable during the authorization window. Unrelated
envelope content outside the subject closure does not enter authorization
semantics.
Parsing or independent txid lookup is insufficient. Atomic BEEF and SPV
evidence do not prove that an outpoint is globally unspent.

## Verification

`verify` is read-only and inherits BSV `exact` network, asset, `payTo`, wallet,
freshness, and chain checks. Before the protected handler runs, it MUST verify:

1. the payload and control-offer shapes, both time windows, and exact-style
   identity and derivation fields;
2. every Source BEEF validation rule, the derived P2PKH keys, and global
   outpoint uniqueness;
3. authorization canonicalization and signature against the accepted `M`;
4. cap input and floor ordering, `0x43` signatures, money ranges, and `E >= M`.

The recipient MAY reject otherwise valid authorizations whose fee headroom
`E - M` does not meet its local admission policy. This decision occurs before
the protected handler and does not redefine `M` or add a wire-level fee field.

After successful facilitator verification and before invoking the handler, the
Resource Server atomically admits the authorization digest and binds its source
outpoints. It invokes the protected handler at most once. A different
authorization already bound to any of those outpoints fails closed.

## Settlement

After the protected handler completes, the Resource Server atomically binds one
actual `A` and passes it as the settlement-time `PaymentRequirements.amount` on
the existing settle request. Choosing `A = M` needs no different protocol
shape. A pre-handler or cancellation attempt MUST fail closed before amount
binding, terminal construction, selection, signing, or wallet effects. This
adds no x402 round or facilitator endpoint.

The Resource Server determines the settlement amount `A` after the protected
handler succeeds.

Settlement MUST be invocable only through a trusted path controlled by the
recipient. A direct in-process path MAY rely on process isolation only when
untrusted callers cannot reach it. Before invoking scheme settlement, a
remotely reachable facilitator host MUST authenticate the caller and authorize
it for the referenced `payTo` and control offer. Failure to establish that
binding MUST reject the request before terminal construction, selection,
signing, or wallet effects.

This profile does not make an unauthenticated public settlement endpoint safe.
A party that holds the payer authorization and can directly invoke settlement
can otherwise select any conforming `0 <= A <= M`.

Control-input signatures prove that the derived control key authorized the
terminal transaction contents. They do not prove wallet internalization,
propagation, settlement success, caller identity, or protected-handler
execution.

### Bilateral terminal possession and propagation (non-normative)

The payer's cap signatures are reused across candidates, while the recipient's
control signatures complete each candidate and the terminal selected at
settlement. The selected terminal contains outputs controlled by both parties:
the recipient needs its complete signed subject to internalize and propagate
the recipient outputs, and the payer needs that same signed subject to verify
and internalize its floors and refunds. A txid or the payer authorization alone
is insufficient for either purpose. Each conforming party that intends to
realize those outputs therefore has an independent economic interest in
retaining the terminal and ensuring satisfactory propagation. This incentive
is not a protocol guarantee that either party will do so.

The recipient wallet retains the BSV `exact` obligation to propagate promptly
after wallet acceptance. Once the payer possesses and verifies the same fully
signed subject transaction, it MAY also propagate that identical transaction.
Their Atomic BEEF envelopes MAY contain different but valid ancestry evidence
without identifying different terminals. Propagation by either party does not
select another terminal and does not prove that the other party received,
retained, accepted, or propagated it. Signatures do not guarantee delivery or
retention; BEEF, PoW, and SPV provide evidence relative to their named proofs
and chain view, from which this profile infers neither reliable retention nor
network-wide finality.

A post-selection `success: false` result does not revoke the fully signed
terminal or make its shared input outpoints safe to authorize again. Either
holder can still propagate that terminal, so the failure represents an
unresolved signed payment rather than restoration of the pre-authorization
state.

### Settlement procedure

Each invocation first revalidates the authorization under the current wallet,
network, source-BEEF, and chain policy. Failure or unavailability fails closed,
including on replay: a replay may report an accepted terminal only after that
revalidation succeeds, and revalidation failure MUST NOT construct a replacement
terminal. When no terminal has been selected, settlement:

1. re-verifies the complete authorization against accepted `M`;
2. validates `A`, constructs the terminal without broadcasting, and has the
   recipient sign every control input;
3. re-runs all transaction invariants: sources, signatures, ordering, roles,
   derivations, owner aggregates, `A`, `E`, `F`, and `R`;
4. atomically checks the deadline and selects the terminal first-writer;
5. passes only that winner and all recipient-output remittances to the same
   BRC-100 `internalizeAction` wallet-payment path defined by BSV `exact`.

The terminal uses `0xffffffff` for every input sequence, disabling `nLockTime`;
participant admission enforces the deadline. `success: true` retains the BSV
`exact` wallet-acceptance and propagation semantics, with no separate
broadcaster. Signing or selecting alone is not success. A later failure to
persist replay information does not change an accepted original response, but
it can make a conforming replay impossible; it does not authorize repeating an
effect or omitting selected-terminal evidence that remains available and
revalidates.

## Deadline, single use, and retry

`validAfter` and `deadline` use the verifier's Unix clock. For a new
authorization, verification, protected-handler admission, amount binding, and
terminal selection require `validAfter <= now < deadline`; equality with
`deadline` is expired. The deadline check and first-writer selection are one
atomic decision. Replay of a known accepted outcome skips temporal, fee,
handler, and wallet admission, but not authorization, source-BEEF, or chain
revalidation or revalidation of the selected terminal evidence.

Retry behavior has three observable requirements:

1. The Resource Server MUST NOT rerun the protected handler for the same
   authorization.
2. When revalidation of the authorization and sources succeeds, the complete selected
   terminal remains available, and its Atomic BEEF also revalidates against the
   current chain facts, a repeated facilitator settlement invocation for the
   same authorization MUST return evidence for that selected terminal and MUST
   NOT invoke the wallet again or substitute a conflicting terminal. The
   returned evidence MUST preserve the terminal's raw subject bytes, txid, and
   `A`; the response MAY carry an equivalent or stronger currently valid Atomic
   BEEF envelope for that same terminal (Settlement response). It MUST report
   success only for a confirmed accepted outcome.
3. A role that cannot determine its prior admission, amount, terminal, or wallet
   outcome MUST fail closed and MUST NOT create a replacement or repeat an
   effect. If it knows selection occurred but cannot recover or revalidate the
   complete selected terminal, it MUST fail closed without returning an amount
   or terminal evidence for that attempt.

Once a terminal has been selected, later attempts MUST NOT reconstruct, re-
sign, re-select, or invoke the wallet again. Replay reports success only for a
confirmed accepted outcome. If the wallet explicitly rejects, throws, returns
an unknown result, or the accepted record cannot be confirmed, every
subsequent attempt for that authorization fails closed without constructing,
signing, selecting, or repeating a wallet operation. When the selected terminal
evidence revalidates, any scheme settlement failure result emitted for such an
attempt MUST carry it as specified under Settlement response without
representing wallet acceptance or propagation. Evidence that cannot be
revalidated MUST NOT be returned.

These rules govern settlement invocations and do not make a fresh verification
a settlement-evidence recovery channel: once a terminal has been selected, a
new verify request for that authorization fails closed regardless of whether
wallet acceptance was recorded, and the payer cannot retrieve a lost
settlement response's terminal through it. This profile defines no recovery
state machine or response-retention service. The resulting inability to recover
a lost first settlement response is a deployment availability risk; this
profile does not guarantee its recovery.

These requirements prescribe no cache, record layout, recovery protocol, or
exactly-once application effects. Upon receiving settlement evidence and before
internalizing payer-owned outputs, the payer locally selects the returned raw
subject bytes, txid, and `A`; while retained, uncertainty fails closed for that
selection and every conflict.

## Settlement response

When the selected evidence revalidates, a settlement result extends the
existing x402 `SettleResponse` with the actual amount and terminal Atomic BEEF.
The success form is:

```json
{
  "success": true,
  "transaction": "<terminal subject txid>",
  "network": "bsv:testnet",
  "payer": "<senderIdentityKey>",
  "amount": "300",
  "extra": { "settlementTransaction": "<base64 terminal Atomic BEEF>" }
}
```

Once a fully signed terminal has been selected and its evidence revalidates,
every settlement result emitted for that attempt, whether `success` is `true`
or `false`, MUST carry `amount = A` and `extra.settlementTransaction` as
canonical base64 Atomic BEEF whose subject is that terminal. On success,
`transaction` MUST equal the Atomic BEEF subject txid. On failure, `transaction`
MUST remain empty; carrying the signed terminal does not represent wallet
acceptance or propagation and does not turn the failure into success. In this
failure form, `amount` identifies the actual service amount encoded by the
selected terminal; it does not claim that the recipient wallet accepted the
transaction. A failure before terminal selection, or a fail-closed result caused
by unavailable or invalid selected evidence, MUST NOT carry `amount` or terminal
evidence.

Any retry result that carries terminal evidence MUST preserve the selected raw
subject bytes, txid, and amount. Those values identify the terminal; any
currently valid Atomic BEEF envelope for the same raw subject and txid MAY carry
additional evidence without becoming a different terminal. The payer MUST
fully verify the returned terminal before internalizing its outputs. A txid
alone is insufficient. This profile does not define a new pending outcome. The
evidence rule constrains settlement results that carry evidence; it does not
guarantee delivery, durable storage, or recovery after state loss.

## Stream compatibility (non-normative)

The signature layout also permits an application outside x402 to ask the
recipient to form amount-increasing complete candidates without another payer
signature. They share the version, `nLockTime`, ordered inputs, fixed floors,
and original cap signature bytes; the recipient re-signs its control inputs.
Intermediate candidates can use an increasing common control sequence
`q < 0xffffffff`, while the terminal makes every sequence `0xffffffff`.

This adds no x402 round, scheme, session, revision, or endpoint. The candidates
are ordinary shared-input conflicts, and `nSequence` can affect only a named
node's local policy, not a network-wide selection. x402 still settles one
terminal; distributing earlier candidates accepts their conflict risk.

## Security and non-goals

- Advertising reserved control inputs before payer authentication creates a
  resource-exhaustion surface; bounded pools, short windows, and rate policy
  are deployment mitigations.
- BEEF and SPV validate transaction ancestry but do not prove that a source is
  globally unspent. A conflicting cap or control spend can therefore pass
  structural verification and make post-handler settlement fail; deployments
  account for that zero-confirmation resource risk without a node-state API.
- Signatures prove signed contents, and BEEF/PoW/SPV prove validation evidence;
  none guarantees reliable data retention.
- Settlement is invocable only through a trusted path controlled by the
  recipient (see Settlement); this profile defines no scheme-level settlement
  caller credential.
- A transaction may be valid yet conflict with another spend. This profile
  defines neither a node conflict-state API nor a network-wide finality claim.
- Multiple inputs and outputs are represented only by ordered arrays and owner
  aggregates; no additional business-role hierarchy is introduced.
