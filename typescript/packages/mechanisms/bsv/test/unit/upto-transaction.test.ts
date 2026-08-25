import {
  Beef,
  BigNumber,
  ECDSA,
  LockingScript,
  PrivateKey,
  Script,
  Transaction,
  Utils,
} from "@bsv/sdk";
import { describe, expect, it } from "vitest";
import type { UptoBsvAuthorizationTerms } from "../../src/types";
import {
  assertUptoVersionProgression,
  buildUptoTransactionVersion,
  signUptoAuthorization,
  uptoAuthorizationDigest,
  uptoAuthorizationId,
  uptoP2pkhScript,
  verifyUptoAuthorization,
  verifyUptoTransactionVersion,
  type UptoBsvDigestSigner,
} from "../../src/upto/transaction";

const FINAL_SEQUENCE = 0xffffffff;

interface SingleFixture {
  terms: UptoBsvAuthorizationTerms;
  capSigner: UptoBsvDigestSigner;
  controlKey: PrivateKey;
  controlSigner: UptoBsvDigestSigner;
  outputAmounts: (amount: number) => string[];
}

/** Signs an already-computed digest without hashing it again. */
const digestSigner =
  (privateKey: PrivateKey): UptoBsvDigestSigner =>
  async digest =>
    ECDSA.sign(new BigNumber(digest), privateKey, true).toDER() as number[];

/** Creates a plain BEEF source transaction with one spendable P2PKH output. */
const sourceTransaction = (privateKey: PrivateKey, satoshis: number, tag: number): string => {
  const transaction = new Transaction(1, [], [], tag);
  transaction.addOutput({
    lockingScript: LockingScript.fromHex(uptoP2pkhScript(privateKey.toPublicKey().toString())),
    satoshis,
  });
  const beef = new Beef();
  beef.mergeTransaction(transaction);
  return Utils.toBase64(beef.toBinary());
};

/** Creates an Atomic BEEF source with one additional raw-transaction ancestor. */
const sourceWithAncestry = (
  publicKey: string,
  satoshis: number,
  tag: number,
): { encoded: string; ancestorTxid: string } => {
  const ancestor = new Transaction(1, [], [], tag);
  ancestor.addOutput({
    lockingScript: LockingScript.fromHex("51"),
    satoshis: satoshis + 1,
  });
  const source = new Transaction();
  source.addInput({
    sourceTransaction: ancestor,
    sourceOutputIndex: 0,
    unlockingScript: Script.fromHex("00"),
    sequence: FINAL_SEQUENCE,
  });
  source.addOutput({
    lockingScript: LockingScript.fromHex(uptoP2pkhScript(publicKey)),
    satoshis,
  });
  return {
    encoded: Utils.toBase64(source.toAtomicBEEF()),
    ancestorTxid: ancestor.id("hex"),
  };
};

/** Decodes the fully signed subject transaction from a transaction version. */
const decodeTransaction = (encoded: string): Transaction =>
  Transaction.fromAtomicBEEF(Utils.toArray(encoded, "base64"));

/** Returns the sighash byte appended to the first signature push. */
const signatureScope = (transaction: Transaction, inputIndex: number): number | undefined =>
  transaction.inputs[inputIndex].unlockingScript?.chunks[0]?.data?.at(-1);

/** Builds the smallest useful stream authorization: one cap and one control input. */
const makeSingleFixture = (): SingleFixture => {
  const capKey = PrivateKey.fromRandom();
  const controlKey = PrivateKey.fromRandom();
  const payerOwner = "payer";
  const payeeOwner = controlKey.toPublicKey().toString();
  const terms: UptoBsvAuthorizationTerms = {
    version: 1,
    network: "bsv:testnet",
    asset: "BSV",
    payTo: payeeOwner,
    senderIdentityKey: capKey.toPublicKey().toString(),
    derivationPrefix: "prefix",
    derivationSuffix: "suffix",
    inputs: [
      {
        owner: payerOwner,
        kind: "cap",
        sourceTransaction: sourceTransaction(capKey, 10_000, 1),
        sourceOutputIndex: 0,
        publicKey: capKey.toPublicKey().toString(),
      },
      {
        owner: payeeOwner,
        kind: "control",
        sourceTransaction: sourceTransaction(controlKey, 101, 2),
        sourceOutputIndex: 0,
        publicKey: controlKey.toPublicKey().toString(),
      },
    ],
    outputs: [
      {
        owner: payerOwner,
        lockingScript: uptoP2pkhScript(capKey.toPublicKey().toString()),
        fixedAmount: "2000",
      },
      {
        owner: payerOwner,
        lockingScript: uptoP2pkhScript(capKey.toPublicKey().toString()),
      },
      {
        owner: payeeOwner,
        lockingScript: uptoP2pkhScript(controlKey.toPublicKey().toString()),
      },
    ],
    chargedOwners: [payerOwner],
    paymentOutputIndexes: [2],
    fee: "1",
    sequenceStart: 42,
    validAfter: 1_700_000_000,
    deadline: 1_700_000_300,
    nLockTime: 1_700_000_120,
  };

  return {
    terms,
    capSigner: digestSigner(capKey),
    controlKey,
    controlSigner: digestSigner(controlKey),
    outputAmounts: amount => ["2000", String(8_000 - amount), String(100 + amount)],
  };
};

/** Builds two cap inputs, two control inputs, and several outputs per owner. */
const makeMultiFixture = () => {
  const firstCapKey = PrivateKey.fromRandom();
  const secondCapKey = PrivateKey.fromRandom();
  const firstControlKey = PrivateKey.fromRandom();
  const secondControlKey = PrivateKey.fromRandom();
  const payerOwner = "payer";
  const payeeOwner = firstControlKey.toPublicKey().toString();
  const terms: UptoBsvAuthorizationTerms = {
    version: 1,
    network: "bsv:testnet",
    asset: "BSV",
    payTo: payeeOwner,
    senderIdentityKey: firstCapKey.toPublicKey().toString(),
    derivationPrefix: "multi-prefix",
    derivationSuffix: "multi-suffix",
    inputs: [
      {
        owner: payerOwner,
        kind: "cap",
        sourceTransaction: sourceTransaction(firstCapKey, 6_000, 3),
        sourceOutputIndex: 0,
        publicKey: firstCapKey.toPublicKey().toString(),
      },
      {
        owner: payerOwner,
        kind: "cap",
        sourceTransaction: sourceTransaction(secondCapKey, 4_000, 4),
        sourceOutputIndex: 0,
        publicKey: secondCapKey.toPublicKey().toString(),
      },
      {
        owner: payeeOwner,
        kind: "control",
        sourceTransaction: sourceTransaction(firstControlKey, 101, 5),
        sourceOutputIndex: 0,
        publicKey: firstControlKey.toPublicKey().toString(),
      },
      {
        owner: payeeOwner,
        kind: "control",
        sourceTransaction: sourceTransaction(secondControlKey, 51, 6),
        sourceOutputIndex: 0,
        publicKey: secondControlKey.toPublicKey().toString(),
      },
    ],
    outputs: [
      {
        owner: payerOwner,
        lockingScript: uptoP2pkhScript(firstCapKey.toPublicKey().toString()),
        fixedAmount: "1000",
      },
      {
        owner: payerOwner,
        lockingScript: uptoP2pkhScript(secondCapKey.toPublicKey().toString()),
        fixedAmount: "500",
      },
      {
        owner: payerOwner,
        lockingScript: uptoP2pkhScript(firstCapKey.toPublicKey().toString()),
      },
      {
        owner: payerOwner,
        lockingScript: uptoP2pkhScript(secondCapKey.toPublicKey().toString()),
      },
      {
        owner: payeeOwner,
        lockingScript: uptoP2pkhScript(firstControlKey.toPublicKey().toString()),
      },
      {
        owner: payeeOwner,
        lockingScript: uptoP2pkhScript(secondControlKey.toPublicKey().toString()),
      },
    ],
    chargedOwners: [payerOwner],
    paymentOutputIndexes: [4, 5],
    fee: "2",
    sequenceStart: 7,
    validAfter: 1_700_000_000,
    deadline: 1_700_000_300,
    nLockTime: 1_700_000_120,
  };

  return {
    terms,
    payerOwner,
    payeeOwner,
    capSigners: { 0: digestSigner(firstCapKey), 1: digestSigner(secondCapKey) },
    controlSigners: { 2: digestSigner(firstControlKey), 3: digestSigner(secondControlKey) },
    outputAmounts: ["1000", "500", "4500", "1000", "2000", "1150"],
  };
};

describe("BSV upto signed transaction versions", () => {
  it("binds the transaction nLockTime independently from the authorization deadline", async () => {
    const fixture = makeSingleFixture();
    const terms = {
      ...fixture.terms,
      nLockTime: 1_700_000_120,
      deadline: 1_700_000_300,
    };
    const authorization = await signUptoAuthorization(terms, { 0: fixture.capSigner });
    const version = await buildUptoTransactionVersion(
      authorization,
      { nSequence: terms.sequenceStart, outputAmounts: fixture.outputAmounts(1_000) },
      { 1: fixture.controlSigner },
    );

    expect(decodeTransaction(version.transaction).lockTime).toBe(1_700_000_120);
  });

  it("keeps a stable authorization digest for the canonical tuple", () => {
    const capKey = PrivateKey.fromHex("01".padStart(64, "0"));
    const controlKey = PrivateKey.fromHex("02".padStart(64, "0"));
    const payTo = controlKey.toPublicKey().toString();
    const terms: UptoBsvAuthorizationTerms = {
      version: 1,
      network: "bsv:testnet",
      asset: "BSV",
      payTo,
      senderIdentityKey: capKey.toPublicKey().toString(),
      derivationPrefix: "AQIDBAUGBwg=",
      derivationSuffix: "MTcwMDAwMDAwMDAwMA==",
      inputs: [
        {
          owner: "payer",
          kind: "cap",
          sourceTransaction: sourceTransaction(capKey, 1_001, 101),
          sourceOutputIndex: 0,
          publicKey: capKey.toPublicKey().toString(),
        },
        {
          owner: payTo,
          kind: "control",
          sourceTransaction: sourceTransaction(controlKey, 2, 102),
          sourceOutputIndex: 0,
          publicKey: controlKey.toPublicKey().toString(),
        },
      ],
      outputs: [
        {
          owner: "payer",
          lockingScript: uptoP2pkhScript(capKey.toPublicKey().toString()),
          fixedAmount: "1",
        },
        { owner: "payer", lockingScript: uptoP2pkhScript(capKey.toPublicKey().toString()) },
        { owner: payTo, lockingScript: uptoP2pkhScript(payTo) },
      ],
      chargedOwners: ["payer"],
      paymentOutputIndexes: [2],
      fee: "1",
      sequenceStart: 1,
      validAfter: 1_700_000_000,
      deadline: 1_700_000_300,
      nLockTime: 1_700_000_120,
    };

    expect(uptoAuthorizationId(terms)).toBe(
      "7a9096b069b220dfc3158c41b816f453e98d53fbe7fdaa61c6137f23e5371a1a",
    );
  });

  it("preserves source ancestry when it builds the terminal Atomic BEEF", async () => {
    const fixture = makeSingleFixture();
    const chained = sourceWithAncestry(fixture.terms.inputs[0].publicKey, 10_000, 100);
    fixture.terms.inputs[0] = {
      ...fixture.terms.inputs[0],
      sourceTransaction: chained.encoded,
    };
    const authorization = await signUptoAuthorization(fixture.terms, { 0: fixture.capSigner });
    const version = await buildUptoTransactionVersion(
      authorization,
      { nSequence: 42, outputAmounts: fixture.outputAmounts(1_000) },
      { 1: fixture.controlSigner },
    );

    const beef = Beef.fromBinary(Utils.toArray(version.transaction, "base64"));
    const terminal = Transaction.fromAtomicBEEF(Utils.toArray(version.transaction, "base64"));
    expect(beef.findTxid(chained.ancestorTxid)?.tx).toBeDefined();
    expect(terminal.inputs[0].sourceTransaction?.inputs[0].sourceTransaction?.id("hex")).toBe(
      chained.ancestorTxid,
    );
  });

  it("refuses an authorization with partial source ancestry", async () => {
    const fixture = makeSingleFixture();
    const partial = new Transaction();
    partial.addInput({
      sourceTXID: "ff".repeat(32),
      sourceOutputIndex: 0,
      unlockingScript: Script.fromHex("00"),
      sequence: FINAL_SEQUENCE,
    });
    partial.addOutput({
      lockingScript: LockingScript.fromHex(uptoP2pkhScript(fixture.terms.inputs[0].publicKey)),
      satoshis: 10_000,
    });
    fixture.terms.inputs[0] = {
      ...fixture.terms.inputs[0],
      sourceTransaction: Utils.toBase64(partial.toAtomicBEEF(true)),
    };
    await expect(signUptoAuthorization(fixture.terms, { 0: fixture.capSigner })).rejects.toThrow(
      /complete source ancestry/i,
    );
  });

  it("rejects a source output outside the BSV satoshi range", async () => {
    const fixture = makeSingleFixture();
    const oversized = new Transaction(1, [], [], 999);
    oversized.addOutput({
      lockingScript: LockingScript.fromHex(uptoP2pkhScript(fixture.terms.inputs[0].publicKey)),
      satoshis: 2_100_000_000_000_001,
    });
    fixture.terms.inputs[0] = {
      ...fixture.terms.inputs[0],
      sourceTransaction: Utils.toBase64(oversized.toAtomicBEEF()),
    };

    await expect(signUptoAuthorization(fixture.terms, { 0: fixture.capSigner })).rejects.toThrow(
      /source satoshis.*range/i,
    );
  });

  it("reuses the 0x43 cap signature while sequence changes and re-signs control with 0x41", async () => {
    const fixture = makeSingleFixture();
    const authorization = await signUptoAuthorization(fixture.terms, { 0: fixture.capSigner });
    const first = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 42,
        outputAmounts: fixture.outputAmounts(1_000),
      },
      { 1: fixture.controlSigner },
    );
    const second = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 43,
        outputAmounts: fixture.outputAmounts(2_000),
      },
      { 1: fixture.controlSigner },
    );

    const firstTransaction = decodeTransaction(first.transaction);
    const secondTransaction = decodeTransaction(second.transaction);

    expect(firstTransaction.inputs[0].unlockingScript?.toHex()).toBe(
      secondTransaction.inputs[0].unlockingScript?.toHex(),
    );
    expect(signatureScope(firstTransaction, 0)).toBe(0x43);
    expect(signatureScope(secondTransaction, 0)).toBe(0x43);
    expect(firstTransaction.inputs[0].sequence).toBe(FINAL_SEQUENCE);
    expect(secondTransaction.inputs[0].sequence).toBe(FINAL_SEQUENCE);

    expect(firstTransaction.inputs[1].unlockingScript?.toHex()).not.toBe(
      secondTransaction.inputs[1].unlockingScript?.toHex(),
    );
    expect(signatureScope(firstTransaction, 1)).toBe(0x41);
    expect(signatureScope(secondTransaction, 1)).toBe(0x41);
    expect(firstTransaction.inputs[1].sequence).toBe(42);
    expect(secondTransaction.inputs[1].sequence).toBe(43);
    expect(verifyUptoTransactionVersion(authorization, first).amount).toBe("1000");
    expect(verifyUptoTransactionVersion(authorization, second).amount).toBe("2000");
  });

  it("cooperatively closes by finalizing and re-signing only the control input", async () => {
    const fixture = makeSingleFixture();
    const authorization = await signUptoAuthorization(fixture.terms, { 0: fixture.capSigner });
    const intermediate = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 42,
        outputAmounts: fixture.outputAmounts(1_500),
      },
      { 1: fixture.controlSigner },
    );
    const close = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: FINAL_SEQUENCE,
        outputAmounts: fixture.outputAmounts(1_500),
      },
      { 1: fixture.controlSigner },
    );

    const intermediateTransaction = decodeTransaction(intermediate.transaction);
    const closeTransaction = decodeTransaction(close.transaction);

    const verifiedClose = verifyUptoTransactionVersion(authorization, close);
    expect(verifiedClose.cooperativeClose).toBe(true);
    expect(verifiedClose.nSequence).toBe(FINAL_SEQUENCE);
    expect(intermediateTransaction.inputs[0].sequence).toBe(FINAL_SEQUENCE);
    expect(closeTransaction.inputs[0].sequence).toBe(FINAL_SEQUENCE);
    expect(intermediateTransaction.inputs[0].unlockingScript?.toHex()).toBe(
      closeTransaction.inputs[0].unlockingScript?.toHex(),
    );
    expect(signatureScope(closeTransaction, 0)).toBe(0x43);

    expect(intermediateTransaction.inputs[1].sequence).toBe(42);
    expect(closeTransaction.inputs[1].sequence).toBe(FINAL_SEQUENCE);
    expect(intermediateTransaction.inputs[1].unlockingScript?.toHex()).not.toBe(
      closeTransaction.inputs[1].unlockingScript?.toHex(),
    );
    expect(signatureScope(closeTransaction, 1)).toBe(0x41);
    expect(verifiedClose.amount).toBe("1500");
  });

  it("rejects authorization terms changed after the cap owner signed", async () => {
    const fixture = makeSingleFixture();
    const authorization = await signUptoAuthorization(fixture.terms, { 0: fixture.capSigner });
    const tamperedTerms: UptoBsvAuthorizationTerms = {
      ...authorization.terms,
      deadline: authorization.terms.deadline + 1,
    };

    expect(() =>
      verifyUptoAuthorization({
        ...authorization,
        terms: tamperedTerms,
      }),
    ).toThrow(/authorizationId/i);
    expect(() =>
      verifyUptoAuthorization({
        ...authorization,
        authorizationId: uptoAuthorizationId(tamperedTerms),
        terms: tamperedTerms,
      }),
    ).toThrow(/authorization signature/i);
  });

  it("does not count a charged-owner output unless a cap key controls it", async () => {
    const fixture = makeSingleFixture();
    const redirected: UptoBsvAuthorizationTerms = {
      ...fixture.terms,
      outputs: fixture.terms.outputs.map((output, index) =>
        index === 1
          ? {
              ...output,
              lockingScript: uptoP2pkhScript(fixture.controlKey.toPublicKey().toString()),
            }
          : output,
      ),
    };

    await expect(signUptoAuthorization(redirected, { 0: fixture.capSigner })).rejects.toThrow(
      /not controlled by its cap keys/i,
    );
  });

  it("computes payment from owner net deltas across multiple inputs and outputs", async () => {
    const fixture = makeMultiFixture();
    const authorization = await signUptoAuthorization(fixture.terms, fixture.capSigners);
    const version = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 7,
        outputAmounts: fixture.outputAmounts,
      },
      fixture.controlSigners,
    );

    const verified = verifyUptoTransactionVersion(authorization, version);

    expect(verified.outputAmounts).toEqual(fixture.outputAmounts);
    expect(verified.amount).toBe("3000");
    expect(verified.ownerDeltas).toEqual({
      [fixture.payeeOwner]: "-2998",
      [fixture.payerOwner]: "3000",
    });
  });

  it("allows only contiguous stream sequences whose amount never decreases", async () => {
    const fixture = makeSingleFixture();
    const authorization = await signUptoAuthorization(fixture.terms, { 0: fixture.capSigner });
    const first = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 42,
        outputAmounts: fixture.outputAmounts(1_000),
      },
      { 1: fixture.controlSigner },
    );
    const increased = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 43,
        outputAmounts: fixture.outputAmounts(2_000),
      },
      { 1: fixture.controlSigner },
    );
    const decreased = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 43,
        outputAmounts: fixture.outputAmounts(500),
      },
      { 1: fixture.controlSigner },
    );
    const skipped = await buildUptoTransactionVersion(
      authorization,
      {
        nSequence: 44,
        outputAmounts: fixture.outputAmounts(3_000),
      },
      { 1: fixture.controlSigner },
    );

    expect(() => assertUptoVersionProgression(authorization, first, increased)).not.toThrow();
    expect(() => assertUptoVersionProgression(authorization, first, decreased)).toThrow(
      /must not decrease/i,
    );
    expect(() => assertUptoVersionProgression(authorization, first, skipped)).toThrow(
      /advance by one/i,
    );
  });

  it("rejects a reused cap signature when any input prevout is replaced", async () => {
    const fixture = makeSingleFixture();
    const authorization = await signUptoAuthorization(fixture.terms, { 0: fixture.capSigner });
    const changedTerms: UptoBsvAuthorizationTerms = {
      ...authorization.terms,
      inputs: authorization.terms.inputs.map((input, index) =>
        index === 1
          ? {
              ...input,
              sourceTransaction: sourceTransaction(fixture.controlKey, 101, 99),
            }
          : input,
      ),
    };
    const changedDigest = uptoAuthorizationDigest(changedTerms);
    const resignedAuthorization = {
      ...authorization,
      authorizationId: uptoAuthorizationId(changedTerms),
      terms: changedTerms,
      capSignatures: await Promise.all(
        authorization.capSignatures.map(async signature => ({
          ...signature,
          authorizationSignature: Utils.toBase64(await fixture.capSigner(changedDigest)),
        })),
      ),
    };

    expect(() => verifyUptoAuthorization(resignedAuthorization)).toThrow(
      /invalid reusable cap signature/i,
    );
  });
});
