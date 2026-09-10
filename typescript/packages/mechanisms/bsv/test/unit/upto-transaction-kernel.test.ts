import {
  BigNumber,
  Curve,
  ECDSA,
  Hash,
  P2PKH,
  PrivateKey,
  Signature,
  Transaction,
  UnlockingScript,
  Utils,
  type WalletProtocol,
} from "@bsv/sdk";
import { describe, expect, it, vi } from "vitest";
import { validateAndDigestAuthorization } from "../../src/upto/internal/authorization";
import { BSV_UPTO_CONTROL_PROTOCOL_ID } from "../../src/upto/constants";
import { deriveUptoOutputSpecs } from "../../src/upto/internal/outputs";
import { createSourceAdmitter, materializeAdmittedSource } from "../../src/upto/internal/source";
import { verifyTerminalTransaction } from "../../src/upto/internal/terminal";
import {
  createCapAuthorization,
  createTerminalTransaction,
  materializeVerifiedAuthorization,
  verifyCanonicalP2pkhInputUnlock,
  verifyPresentedAuthorization,
  type CapAuthorization,
  type VerifiedAuthorization,
} from "../../src/upto/internal/transaction";
import {
  admitAuthorizationFixture,
  buildAuthorizationFixture,
  combinedTracker,
  p2pkh,
  type AdmittedAuthorizationFixture,
} from "./upto-authorization-fixtures";
import { buildSourceFixture } from "./upto-source-fixtures";

const AUTHORIZATION_PROTOCOL: WalletProtocol = [2, "x402 bsv upto authorization"];
const CAP_SIGHASH = 0x43;
const CONTROL_SIGHASH = 0x41;

type KernelFixture = AdmittedAuthorizationFixture;

async function kernelFixture(capCount = 1, controlCount = 1): Promise<KernelFixture> {
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

async function createAndVerify(
  fixture: KernelFixture,
  perspective: "payer" | "recipient" = "recipient",
): Promise<{ cap: CapAuthorization; verified: VerifiedAuthorization }> {
  const cap = await createCapAuthorization({
    facts: fixture.facts,
    capInputs: fixture.capInputs,
    controlInputs: fixture.controlInputs,
    wallet: fixture.payer,
  });
  const verified = await verifyPresentedAuthorization({
    facts: fixture.facts,
    authorizationSignature: cap.authorizationSignature,
    transactionSignatures: cap.transactionSignatures,
    capInputs: fixture.capInputs,
    controlInputs: fixture.controlInputs,
    wallet: perspective === "payer" ? fixture.payer : fixture.recipient,
    perspective,
  });
  return { cap, verified };
}

async function terminal(
  fixture: KernelFixture,
  verified: VerifiedAuthorization,
  actualAmount = 600n,
  recipientAmounts: readonly number[] = [610],
  refundAmounts: readonly number[] = [495],
) {
  return createTerminalTransaction({
    authorization: verified,
    actualAmount,
    recipientAmounts,
    refundAmounts,
    wallet: fixture.recipient,
  });
}

function highS(encoded: string): string {
  const low = Signature.fromDER(Utils.toArray(encoded, "base64"));
  return Utils.toBase64(new Signature(low.r, new Curve().n.sub(low.s)).toDER() as number[]);
}

describe("BSV upto wire-native authorization kernel", () => {
  it("forms a real 1x1 terminal from wire DER fields and reconstructs canonical unlocks", async () => {
    const fixture = await kernelFixture();
    const { cap, verified } = await createAndVerify(fixture);
    const transaction = await terminal(fixture, verified);
    const capDer = Utils.toArray(cap.transactionSignatures[0], "base64");
    const material = materializeVerifiedAuthorization(verified);

    expect(Object.keys(cap).sort()).toEqual(["authorizationSignature", "transactionSignatures"]);
    expect(materializeVerifiedAuthorization(verified)).toBe(material);
    for (const value of [
      material,
      material.facts,
      material.facts.capInputs,
      material.facts.capInputs[0],
      material.facts.controlInputs,
      material.facts.controlInputs[0],
      material.capInputs,
      material.capInputs[0],
      material.controlInputs,
      material.controlInputs[0],
      material.capSignatures,
      material.capSignatures[0],
      material.floorOutputs,
      material.floorOutputs[0],
      material.floorOutputs[0].lockingScript,
    ]) {
      expect(Object.isFrozen(value)).toBe(true);
    }
    expect(() => Object.assign(material.facts.capInputs[0], { floorAmount: "999" })).toThrow();
    expect(() => Object.assign(material.capSignatures[0], { 0: 0xff })).toThrow();
    expect(() => Object.assign(material.floorOutputs[0].lockingScript, { 0: 0xff })).toThrow();
    expect(materializeVerifiedAuthorization(verified).facts.capInputs[0].floorAmount).toBe("100");
    expect(materializeVerifiedAuthorization(verified).capSignatures[0]).toEqual(capDer);
    expect(transaction.inputs[0].unlockingScript?.chunks[0].data).toEqual([...capDer, CAP_SIGHASH]);
    expect(transaction.inputs[1].unlockingScript?.chunks[0].data?.at(-1)).toBe(CONTROL_SIGHASH);
    expect(transaction.outputs.map(output => output.satoshis)).toEqual([100, 610, 495]);
    expect(await transaction.verify(fixture.tracker)).toBe(true);
  });

  it("reuses one payer authorization across two complete stream candidates and a terminal", async () => {
    const fixture = await kernelFixture();
    const payerSign = vi.spyOn(fixture.payer, "createSignature");
    const { cap, verified } = await createAndVerify(fixture);
    const first = await terminal(fixture, verified);
    const second = await terminal(fixture, verified, 700n, [710], [395]);
    const final = await terminal(fixture, verified, 700n, [710], [395]);
    const capDer = Utils.toArray(cap.transactionSignatures[0], "base64") as number[];
    const capKey = fixture.capInputs[0].publicKey;
    const controlKey = fixture.controlInputs[0].publicKey;
    first.inputs[1].sequence = 1;
    second.inputs[1].sequence = 2;
    for (const candidate of [first, second]) {
      const { signature } = await fixture.recipient.createSignature({
        hashToDirectlySign: Hash.hash256(candidate.preimage(1, CONTROL_SIGHASH)),
        protocolID: BSV_UPTO_CONTROL_PROTOCOL_ID,
        keyID: fixture.facts.controlInputs[0].nonce,
        counterparty: "anyone",
      });
      const publicKey = Utils.toArray(controlKey, "hex");
      candidate.inputs[1].unlockingScript = new UnlockingScript([
        { op: signature.length + 1, data: [...signature, CONTROL_SIGHASH] },
        { op: publicKey.length, data: publicKey },
      ]);
    }

    const versions = [first, second, final];
    const outpoints = [...fixture.facts.capInputs, ...fixture.facts.controlInputs].map(
      source => `${source.sourceTxid}:${source.sourceOutputIndex}`,
    );
    for (const [index, transaction] of versions.entries()) {
      expect(transaction.version).toBe(1);
      expect(transaction.lockTime).toBe(2_000_000_000);
      expect(
        transaction.inputs.map(
          input => `${input.sourceTransaction?.id("hex")}:${input.sourceOutputIndex}`,
        ),
      ).toEqual(outpoints);
      expect(transaction.inputs[0].sequence).toBe(0xffffffff);
      expect(transaction.inputs[1].sequence).toBe([1, 2, 0xffffffff][index]);
      expect(transaction.inputs[0].unlockingScript?.chunks[0].data).toEqual([
        ...capDer,
        CAP_SIGHASH,
      ]);
      verifyCanonicalP2pkhInputUnlock(transaction, 0, capKey, CAP_SIGHASH, capDer);
      verifyCanonicalP2pkhInputUnlock(transaction, 1, controlKey, CONTROL_SIGHASH);
      expect(transaction.outputs.map(output => output.satoshis)).toEqual(
        index === 0 ? [100, 610, 495] : [100, 710, 395],
      );
      const outputTotal = transaction.outputs.reduce(
        (total, output) => total + BigInt(output.satoshis!),
        0n,
      );
      expect(1_210n - outputTotal).toBe(5n);
      expect(BigInt(transaction.outputs[1].satoshis!) - 10n).toBe(index === 0 ? 600n : 700n);
      // SDK script/SPV validation does not establish a non-final candidate's
      // block eligibility or any miner's replacement policy.
      expect(await transaction.verify(fixture.tracker)).toBe(true);
    }
    expect(new Set(versions.map(transaction => transaction.id("hex"))).size).toBe(3);
    await verifyTerminalTransaction({
      authorization: verified,
      actualAmount: 700n,
      transaction: Utils.toBase64(final.toAtomicBEEF()),
      wallet: fixture.recipient,
      perspective: "recipient",
      chainTracker: fixture.tracker,
      policy: { maxAtomicBeefBytes: 65_536 },
    });
    expect(payerSign).toHaveBeenCalledTimes(2); // authorization + one cap input
  });

  it("accepts the same presented authorization from reciprocal payer and recipient views", async () => {
    const fixture = await kernelFixture();
    const cap = await createCapAuthorization({
      facts: fixture.facts,
      capInputs: fixture.capInputs,
      controlInputs: fixture.controlInputs,
      wallet: fixture.payer,
    });
    for (const perspective of ["payer", "recipient"] as const) {
      await expect(
        verifyPresentedAuthorization({
          facts: fixture.facts,
          authorizationSignature: cap.authorizationSignature,
          transactionSignatures: cap.transactionSignatures,
          capInputs: fixture.capInputs,
          controlInputs: fixture.controlInputs,
          wallet: perspective === "payer" ? fixture.payer : fixture.recipient,
          perspective,
        }),
      ).resolves.toBeTruthy();
    }
  });

  it("rejects an arbitrary source key even when it produces a valid cap signature", async () => {
    const fixture = await kernelFixture();
    const arbitraryKey = new PrivateKey(45_678);
    const badSourceFixture = await buildSourceFixture(333, {
      outputSatoshis: 1_200,
      outputScriptHex: p2pkh(arbitraryKey.toPublicKey().toString()),
    });
    const admit = createSourceAdmitter({
      chainTracker: combinedTracker([badSourceFixture, ...fixture.sources.slice(1)]),
      policy: { maxSources: 2, maxAtomicBeefBytesPerSource: 16_384 },
    });
    const [badCap, control] = await admit([
      {
        role: "cap",
        sourceTransaction: badSourceFixture.sourceTransaction,
        sourceOutputIndex: 0,
        publicKey: arbitraryKey.toPublicKey().toString(),
      },
      {
        role: "control",
        sourceTransaction: fixture.controlOffer.inputs[0].sourceTransaction,
        sourceOutputIndex: 0,
        publicKey: fixture.controlInputs[0].publicKey,
      },
    ]);
    const facts = {
      ...fixture.facts,
      capInputs: [
        {
          ...fixture.facts.capInputs[0],
          sourceTxid: badCap.sourceTxid,
          sourceOutputIndex: badCap.sourceOutputIndex,
        },
      ],
    };
    const floors = await deriveUptoOutputSpecs({
      wallet: fixture.payer,
      perspective: "payer",
      facts,
      recipientAmounts: [610],
      refundAmounts: [],
    });
    const capTemplate = new Transaction(
      1,
      [badCap, control].map(source => {
        const materialized = materializeAdmittedSource(source);
        return {
          sourceTransaction: materialized.sourceTransaction,
          sourceOutputIndex: source.sourceOutputIndex,
          sequence: 0xffffffff,
        };
      }),
      floors.slice(0, 1),
      facts.deadline,
    );
    const digest = Hash.hash256(capTemplate.preimage(0, CAP_SIGHASH));
    const capDer = ECDSA.sign(new BigNumber(digest), arbitraryKey, true).toDER() as number[];
    expect(
      ECDSA.verify(new BigNumber(digest), Signature.fromDER(capDer), arbitraryKey.toPublicKey()),
    ).toBe(true);
    const { digest: authorizationDigest } = validateAndDigestAuthorization(facts);
    const { signature: authorizationSignature } = await fixture.payer.createSignature({
      hashToDirectlySign: authorizationDigest,
      protocolID: AUTHORIZATION_PROTOCOL,
      keyID: `${facts.derivationPrefix} ${facts.derivationSuffix}`,
      counterparty: "anyone",
    });

    await expect(
      verifyPresentedAuthorization({
        facts,
        authorizationSignature: Utils.toBase64(authorizationSignature),
        transactionSignatures: [Utils.toBase64(capDer)],
        capInputs: [badCap],
        controlInputs: [control],
        wallet: fixture.payer,
        perspective: "payer",
      }),
    ).rejects.toThrow(/cap source public key does not match signed authorization/);
  });

  it.each(["derivationPrefix", "payTo"] as const)(
    "rejects a changed signed %s instead of deriving a new transaction",
    async field => {
      const fixture = await kernelFixture();
      const cap = await createCapAuthorization({
        facts: fixture.facts,
        capInputs: fixture.capInputs,
        controlInputs: fixture.controlInputs,
        wallet: fixture.payer,
      });
      const changed = {
        ...fixture.facts,
        [field]:
          field === "derivationPrefix"
            ? Utils.toBase64(Utils.toArray("changed", "utf8"))
            : new PrivateKey(999).toPublicKey().toString(),
      };
      await expect(
        verifyPresentedAuthorization({
          facts: changed,
          authorizationSignature: cap.authorizationSignature,
          transactionSignatures: cap.transactionSignatures,
          capInputs: fixture.capInputs,
          controlInputs: fixture.controlInputs,
          wallet: fixture.payer,
          perspective: "payer",
        }),
      ).rejects.toThrow();
    },
  );

  it("rejects swapped 2x2 cap signatures", async () => {
    const fixture = await kernelFixture(2, 2);
    const cap = await createCapAuthorization({
      facts: fixture.facts,
      capInputs: fixture.capInputs,
      controlInputs: fixture.controlInputs,
      wallet: fixture.payer,
    });
    await expect(
      verifyPresentedAuthorization({
        facts: fixture.facts,
        authorizationSignature: cap.authorizationSignature,
        transactionSignatures: [...cap.transactionSignatures].reverse(),
        capInputs: fixture.capInputs,
        controlInputs: fixture.controlInputs,
        wallet: fixture.recipient,
        perspective: "recipient",
      }),
    ).rejects.toThrow(/wrong digest or key/);
  });

  it.each(["noncanonical", "high-S", "sighash-appended"])(
    "rejects %s cap DER at the wire boundary",
    async form => {
      const fixture = await kernelFixture();
      const cap = await createCapAuthorization({
        facts: fixture.facts,
        capInputs: fixture.capInputs,
        controlInputs: fixture.controlInputs,
        wallet: fixture.payer,
      });
      const original = cap.transactionSignatures[0];
      const replacement =
        form === "noncanonical"
          ? `${original}\n`
          : form === "high-S"
            ? highS(original)
            : Utils.toBase64([...Utils.toArray(original, "base64"), CAP_SIGHASH]);
      await expect(
        verifyPresentedAuthorization({
          facts: fixture.facts,
          authorizationSignature: cap.authorizationSignature,
          transactionSignatures: [replacement],
          capInputs: fixture.capInputs,
          controlInputs: fixture.controlInputs,
          wallet: fixture.recipient,
          perspective: "recipient",
        }),
      ).rejects.toThrow(/cap transaction signature/);
    },
  );

  it("rejects a high-S standalone authorization signature", async () => {
    const fixture = await kernelFixture();
    const cap = await createCapAuthorization({
      facts: fixture.facts,
      capInputs: fixture.capInputs,
      controlInputs: fixture.controlInputs,
      wallet: fixture.payer,
    });
    await expect(
      verifyPresentedAuthorization({
        facts: fixture.facts,
        authorizationSignature: highS(cap.authorizationSignature),
        transactionSignatures: cap.transactionSignatures,
        capInputs: fixture.capInputs,
        controlInputs: fixture.controlInputs,
        wallet: fixture.recipient,
        perspective: "recipient",
      }),
    ).rejects.toThrow(/authorization signature must be low-S/);
  });

  it("rejects E below signed M before requesting any payer signature", async () => {
    const fixture = await kernelFixture();
    const facts = {
      ...fixture.facts,
      capInputs: [{ ...fixture.facts.capInputs[0], floorAmount: "300" }],
    };
    const createSignature = vi.spyOn(fixture.payer, "createSignature");
    await expect(
      createCapAuthorization({
        facts,
        capInputs: fixture.capInputs,
        controlInputs: fixture.controlInputs,
        wallet: fixture.payer,
      }),
    ).rejects.toThrow(/exposure is below maximumAmount/);
    expect(createSignature).not.toHaveBeenCalled();
  });

  it.each([
    ["A differs from recipient net amount", 601n, [610], [495], /recipient net amount/],
    ["A exceeds M", 1_001n, [1_011], [1], /authorized maximum/],
    ["F exceeds E minus M", 600n, [610], [399], /fee.*headroom/],
    ["outputs exceed inputs", 600n, [610], [501], /outputs exceed inputs/],
  ])(
    "rejects invalid terminal accounting before control signing: %s",
    async (_label, actual, recipientAmounts, refundAmounts, error) => {
      const fixture = await kernelFixture();
      const { verified } = await createAndVerify(fixture);
      const createSignature = vi.spyOn(fixture.recipient, "createSignature");
      await expect(
        terminal(fixture, verified, actual, recipientAmounts, refundAmounts),
      ).rejects.toThrow(error);
      expect(createSignature).not.toHaveBeenCalled();
    },
  );

  it("ignores arbitrary caller script and changed-facts fields at terminal construction", async () => {
    const fixture = await kernelFixture();
    const { verified } = await createAndVerify(fixture);
    const arbitraryScript = new P2PKH().lock(
      new PrivateKey(999).toPublicKey().toHash() as number[],
    );
    const transaction = await createTerminalTransaction({
      authorization: verified,
      actualAmount: 600n,
      recipientAmounts: [610],
      refundAmounts: [495],
      wallet: fixture.recipient,
      recipientOutputs: [{ satoshis: 610, lockingScript: arbitraryScript }],
      facts: { ...fixture.facts, payTo: new PrivateKey(999).toPublicKey().toString() },
    } as Parameters<typeof createTerminalTransaction>[0] & Record<string, unknown>);
    expect(
      transaction.outputs.every(output => output.lockingScript.toHex() !== arbitraryScript.toHex()),
    ).toBe(true);
  });

  it("forms and verifies a real aggregate 2x2 terminal", async () => {
    const fixture = await kernelFixture(2, 2);
    const { verified } = await createAndVerify(fixture);
    const transaction = await terminal(fixture, verified, 790n, [410, 410], [250, 255]);

    expect(transaction.inputs).toHaveLength(4);
    expect(transaction.outputs.map(output => output.satoshis)).toEqual([
      100, 100, 410, 410, 250, 255,
    ]);
    expect(
      transaction.inputs.slice(0, 2).map(input => input.unlockingScript?.chunks[0].data?.at(-1)),
    ).toEqual([CAP_SIGHASH, CAP_SIGHASH]);
    expect(
      transaction.inputs.slice(2).map(input => input.unlockingScript?.chunks[0].data?.at(-1)),
    ).toEqual([CONTROL_SIGHASH, CONTROL_SIGHASH]);
    expect(await transaction.verify(fixture.tracker)).toBe(true);
  });
});
