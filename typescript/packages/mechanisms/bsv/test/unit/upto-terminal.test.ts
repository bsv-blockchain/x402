import {
  Beef,
  Curve,
  Hash,
  LockingScript,
  P2PKH,
  PrivateKey,
  PublicKey,
  Signature,
  Transaction,
  UnlockingScript,
  Utils,
} from "@bsv/sdk";
import { describe, expect, it } from "vitest";
import { BSV_UPTO_CONTROL_PROTOCOL_ID } from "../../src/upto/constants";
import { deriveUptoOutputCandidates } from "../../src/upto/internal/outputs";
import {
  materializeVerifiedTerminal,
  verifyTerminalTransaction,
} from "../../src/upto/internal/terminal";
import {
  createCapAuthorization,
  createTerminalTransaction,
  verifyPresentedAuthorization,
  type VerifiedAuthorization,
} from "../../src/upto/internal/transaction";
import {
  admitAuthorizationFixture,
  buildAuthorizationFixture,
  combinedTracker,
  type AdmittedAuthorizationFixture,
} from "./upto-authorization-fixtures";
import { buildSourceFixture } from "./upto-source-fixtures";

type Fixture = AdmittedAuthorizationFixture;

async function fixture(capCount = 1, controlCount = 1): Promise<Fixture> {
  return admitAuthorizationFixture(
    await buildAuthorizationFixture({
      capCount,
      controlCount,
      nowSeconds: 1_800_000_000,
      validAfter: 1_999_999_940,
      deadline: 2_000_000_000,
    }),
  );
}

async function authorization(value: Fixture): Promise<VerifiedAuthorization> {
  const cap = await createCapAuthorization({
    facts: value.facts,
    capInputs: value.capInputs,
    controlInputs: value.controlInputs,
    wallet: value.payer,
  });
  return verifyPresentedAuthorization({
    facts: value.facts,
    authorizationSignature: cap.authorizationSignature,
    transactionSignatures: cap.transactionSignatures,
    capInputs: value.capInputs,
    controlInputs: value.controlInputs,
    wallet: value.recipient,
    perspective: "recipient",
  });
}

async function terminalFixture(capCount = 1, controlCount = 1) {
  const value = await fixture(capCount, controlCount);
  const verified = await authorization(value);
  const aggregate = capCount === 1;
  const actualAmount = aggregate ? 600n : 790n;
  const transaction = await createTerminalTransaction({
    authorization: verified,
    actualAmount,
    recipientAmounts: aggregate ? [610] : [410, 410],
    refundAmounts: aggregate ? [495] : [250, 255],
    wallet: value.recipient,
  });
  return {
    ...value,
    verified,
    actualAmount,
    transaction,
    encoded: Utils.toBase64(transaction.toAtomicBEEF()),
  };
}

function reencode(transaction: Transaction): string {
  return Utils.toBase64(transaction.toAtomicBEEF());
}

function cloneTransaction(transaction: Transaction): Transaction {
  return new Transaction(
    transaction.version,
    transaction.inputs.map(input => ({
      sourceTransaction: input.sourceTransaction,
      sourceTXID: input.sourceTXID,
      sourceOutputIndex: input.sourceOutputIndex,
      sequence: input.sequence,
      unlockingScript:
        input.unlockingScript === undefined
          ? undefined
          : (UnlockingScript.fromBinary(input.unlockingScript.toBinary()) as UnlockingScript),
    })),
    transaction.outputs.map(output => ({
      satoshis: output.satoshis,
      lockingScript: LockingScript.fromBinary(output.lockingScript.toBinary()),
    })),
    transaction.lockTime,
  );
}

async function resignFirstControl(
  value: Awaited<ReturnType<typeof terminalFixture>>,
  transaction: Transaction,
): Promise<void> {
  const inputIndex = value.capInputs.length;
  const { signature } = await value.recipient.createSignature({
    hashToDirectlySign: Hash.hash256(transaction.preimage(inputIndex, 0x41)),
    protocolID: BSV_UPTO_CONTROL_PROTOCOL_ID,
    keyID: value.facts.controlInputs[0].nonce,
    counterparty: "anyone",
  });
  const publicKey = PublicKey.fromString(value.controlInputs[0].publicKey).encode(true) as number[];
  transaction.inputs[inputIndex].unlockingScript = new UnlockingScript([
    { op: signature.length + 1, data: [...signature, 0x41] },
    { op: publicKey.length, data: publicKey },
  ]);
}

describe("BSV upto raw terminal verification", () => {
  it.each([
    ["payer", 1, 1, ["floor", "recipient", "refund"]],
    ["recipient", 2, 2, ["floor", "floor", "recipient", "recipient", "refund", "refund"]],
  ] as const)(
    "verifies a real %s-perspective %sx%s terminal and materializes its remittances",
    async (perspective, capCount, controlCount, roles) => {
      const value = await terminalFixture(capCount, controlCount);
      const token = await verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: value.encoded,
        wallet: perspective === "payer" ? value.payer : value.recipient,
        perspective,
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      });
      const first = materializeVerifiedTerminal(token);
      expect(first.subjectTxid).toBe(value.transaction.id("hex"));
      expect(first.actualAmount).toBe(value.actualAmount);
      expect(first.outputs.map(output => output.role)).toEqual(roles);
      expect(first.outputs.every(output => output.paymentRemittance.derivationPrefix)).toBe(true);
      const originalByte = first.atomicBeef[0];
      first.atomicBeef[0] ^= 0xff;
      first.subjectTransaction[0] ^= 0xff;
      const second = materializeVerifiedTerminal(token);
      expect(second.atomicBeef[0]).toBe(originalByte);
      expect(second.subjectTransaction[0]).toBe(1);
      expect(Object.isFrozen(second.outputs[0].paymentRemittance)).toBe(true);
    },
  );

  it.each([
    ["version", (tx: Transaction) => (tx.version = 2), /version must be 1/],
    ["locktime", (tx: Transaction) => (tx.lockTime -= 1), /lockTime/],
    ["non-final sequence", (tx: Transaction) => (tx.inputs[0].sequence = 1), /sequence/],
    [
      "wrong input order",
      (tx: Transaction) => ([tx.inputs[0], tx.inputs[1]] = [tx.inputs[1], tx.inputs[0]]),
      /outpoint/,
    ],
    [
      "changed cap signature",
      (tx: Transaction) => {
        const bytes = tx.inputs[0].unlockingScript?.toBinary();
        if (bytes !== undefined) {
          bytes[6] ^= 1;
          tx.inputs[0].unlockingScript = UnlockingScript.fromBinary(bytes) as UnlockingScript;
        }
      },
      /signature|DER|stored/,
    ],
    [
      "wrong control sighash",
      (tx: Transaction) => {
        const script = tx.inputs[1].unlockingScript;
        const data = script?.chunks[0].data;
        if (script !== undefined && data !== undefined) {
          const bytes = script.toBinary();
          bytes[data.length] = 0x43;
          tx.inputs[1].unlockingScript = UnlockingScript.fromBinary(bytes) as UnlockingScript;
        }
      },
      /sighash scope/,
    ],
  ])("rejects a terminal with %s", async (_name, mutate, error) => {
    const value = await terminalFixture();
    const changed = cloneTransaction(
      Transaction.fromAtomicBEEF(Utils.toArray(value.encoded, "base64")),
    );
    mutate(changed);
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: reencode(changed),
        wallet: value.payer,
        perspective: "payer",
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).rejects.toThrow(error);
  });

  it("rejects an arbitrary output script even after the recipient validly re-signs it", async () => {
    const value = await terminalFixture();
    const changed = cloneTransaction(
      Transaction.fromAtomicBEEF(Utils.toArray(value.encoded, "base64")),
    );
    changed.outputs[1].lockingScript = new P2PKH().lock(
      new PrivateKey(999).toPublicKey().toHash() as number[],
    );
    await resignFirstControl(value, changed);
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: reencode(changed),
        wallet: value.payer,
        perspective: "payer",
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).rejects.toThrow(/authorization-derived role/);
  });

  it("rejects a derived recipient output after a derived refund output", async () => {
    const value = await terminalFixture();
    const changed = cloneTransaction(
      Transaction.fromAtomicBEEF(Utils.toArray(value.encoded, "base64")),
    );
    const [refund, recipient] = await deriveUptoOutputCandidates({
      wallet: value.recipient,
      perspective: "recipient",
      facts: value.facts,
      candidates: [
        { role: "refund", outputIndex: 1, satoshis: 495 },
        { role: "recipient", outputIndex: 2, satoshis: 610 },
      ],
    });
    changed.outputs[1] = { satoshis: refund.satoshis, lockingScript: refund.lockingScript };
    changed.outputs[2] = { satoshis: recipient.satoshis, lockingScript: recipient.lockingScript };
    await resignFirstControl(value, changed);
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: reencode(changed),
        wallet: value.payer,
        perspective: "payer",
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).rejects.toThrow(/recipient output cannot follow/);
  });

  it("rejects a derived layout with no recipient output", async () => {
    const value = await terminalFixture();
    const changed = cloneTransaction(
      Transaction.fromAtomicBEEF(Utils.toArray(value.encoded, "base64")),
    );
    const refunds = await deriveUptoOutputCandidates({
      wallet: value.recipient,
      perspective: "recipient",
      facts: value.facts,
      candidates: [
        { role: "refund", outputIndex: 1, satoshis: 610 },
        { role: "refund", outputIndex: 2, satoshis: 495 },
      ],
    });
    changed.outputs[1] = { satoshis: refunds[0].satoshis, lockingScript: refunds[0].lockingScript };
    changed.outputs[2] = { satoshis: refunds[1].satoshis, lockingScript: refunds[1].lockingScript };
    await resignFirstControl(value, changed);
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: reencode(changed),
        wallet: value.payer,
        perspective: "payer",
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).rejects.toThrow(/at least one recipient output/);
  });

  it("rejects a high-S control signature even when it signs the same digest", async () => {
    const value = await terminalFixture();
    const changed = cloneTransaction(
      Transaction.fromAtomicBEEF(Utils.toArray(value.encoded, "base64")),
    );
    const inputIndex = value.capInputs.length;
    const chunks = changed.inputs[inputIndex].unlockingScript?.chunks;
    const signed = chunks?.[0].data;
    const publicKey = chunks?.[1].data;
    if (signed === undefined || publicKey === undefined) throw new Error("fixture unlock missing");
    const low = Signature.fromDER(signed.slice(0, -1));
    const high = new Signature(low.r, new Curve().n.sub(low.s)).toDER() as number[];
    changed.inputs[inputIndex].unlockingScript = new UnlockingScript([
      { op: high.length + 1, data: [...high, 0x41] },
      { op: publicKey.length, data: [...publicKey] },
    ]);
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: reencode(changed),
        wallet: value.payer,
        perspective: "payer",
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).rejects.toThrow(/low-S/);
  });

  it("independently rejects a validly re-signed fee above E minus M", async () => {
    const value = await terminalFixture();
    const changed = cloneTransaction(
      Transaction.fromAtomicBEEF(Utils.toArray(value.encoded, "base64")),
    );
    changed.outputs[2].satoshis = 300;
    await resignFirstControl(value, changed);
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: reencode(changed),
        wallet: value.payer,
        perspective: "payer",
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).rejects.toThrow(/fee exceeds authorized headroom/);
  });

  it("rejects a wrong claimed A", async () => {
    const value = await terminalFixture();
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount + 1n,
        transaction: value.encoded,
        wallet: value.recipient,
        perspective: "recipient",
        chainTracker: value.tracker,
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).rejects.toThrow(/recipient net amount/);
  });

  it.each(["noncanonical", "trailing", "plain", "oversize"])(
    "rejects %s terminal evidence",
    async form => {
      const value = await terminalFixture();
      const raw = Utils.toArray(value.encoded, "base64") as number[];
      const transaction =
        form === "noncanonical"
          ? `${value.encoded}\n`
          : form === "trailing"
            ? Utils.toBase64([...raw, 0])
            : form === "plain"
              ? Utils.toBase64(value.transaction.toBEEF())
              : value.encoded;
      await expect(
        verifyTerminalTransaction({
          authorization: value.verified,
          actualAmount: value.actualAmount,
          transaction,
          wallet: value.payer,
          perspective: "payer",
          chainTracker: value.tracker,
          policy: { maxAtomicBeefBytes: form === "oversize" ? raw.length - 1 : 65_536 },
        }),
      ).rejects.toThrow(/canonical|trailing|subject|policy/);
    },
  );

  it("accepts additional verified evidence without changing the atomic subject", async () => {
    const value = await terminalFixture();
    const unrelated = await buildSourceFixture(999);
    const beef = Beef.fromBinary(Utils.toArray(value.encoded, "base64"));
    beef.mergeBeef(Beef.fromBinary(Utils.toArray(unrelated.sourceTransaction, "base64")));
    const original = Utils.toArray(value.encoded, "base64") as number[];
    const withExtra = [...original.slice(0, 36), ...beef.toBinary()];
    const parsed = Beef.fromBinary(withExtra);
    expect(parsed.txs.some(entry => entry.txid === unrelated.sourceTxid)).toBe(true);
    await expect(
      verifyTerminalTransaction({
        authorization: value.verified,
        actualAmount: value.actualAmount,
        transaction: Utils.toBase64(withExtra),
        wallet: value.payer,
        perspective: "payer",
        chainTracker: combinedTracker([...value.sources, unrelated]),
        policy: { maxAtomicBeefBytes: 65_536 },
      }),
    ).resolves.toBeDefined();
  });
});
