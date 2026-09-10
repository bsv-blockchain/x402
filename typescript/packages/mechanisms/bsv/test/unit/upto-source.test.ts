import { P2PKH, PrivateKey, Transaction, Utils, type ChainTracker } from "@bsv/sdk";
import { describe, expect, it, vi } from "vitest";
import {
  createSourceAdmitter,
  materializeAdmittedSource,
  type AdmittedSource,
} from "../../src/upto/internal/source";
import { buildSiblingDoubleSpendFixture, buildSourceFixture } from "./upto-source-fixtures";

describe("upto source admission", () => {
  it("admits a real signed Atomic BEEF source as immutable transaction facts", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: {
        maxSources: 2,
        maxAtomicBeefBytesPerSource: 16_384,
      },
    });

    const admitted = await admit([
      {
        role: "cap",
        sourceTransaction: fixture.sourceTransaction,
        sourceOutputIndex: fixture.sourceOutputIndex,
        publicKey: fixture.publicKey,
      },
    ]);

    expect(admitted).toEqual([
      {
        role: "cap",
        sourceTxid: fixture.sourceTxid,
        sourceOutputIndex: 0,
        satoshis: BigInt(fixture.satoshis),
        publicKey: fixture.publicKey,
        lockingScriptHex: fixture.lockingScriptHex,
      },
    ]);
    expect(Object.isFrozen(admitted)).toBe(true);
    expect(Object.isFrozen(admitted[0])).toBe(true);
    expect("transaction" in admitted[0]).toBe(false);
  });

  it.each([0, -1, -0, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid finite admission policy value %s",
    invalidLimit => {
      const chainTracker: ChainTracker = {
        currentHeight: vi.fn(async () => 1_000_000),
        isValidRootForHeight: vi.fn(async () => true),
      };

      expect(() =>
        createSourceAdmitter({
          chainTracker,
          policy: {
            maxSources: invalidLimit,
            maxAtomicBeefBytesPerSource: 16_384,
          },
        }),
      ).toThrow(/positive safe integer/);
      expect(chainTracker.isValidRootForHeight).not.toHaveBeenCalled();
    },
  );

  it("rejects an oversized source set before reading any source", async () => {
    let sourceReads = 0;
    const candidate = {
      role: "cap" as const,
      get sourceTransaction() {
        sourceReads += 1;
        return "not-base64";
      },
      sourceOutputIndex: 0,
      publicKey: "02" + "11".repeat(32),
    };
    const chainTracker: ChainTracker = {
      currentHeight: vi.fn(async () => 1_000_000),
      isValidRootForHeight: vi.fn(async () => true),
    };
    const admit = createSourceAdmitter({
      chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(admit([candidate, candidate])).rejects.toThrow(/source count exceeds policy/);
    expect(sourceReads).toBe(0);
    expect(chainTracker.isValidRootForHeight).not.toHaveBeenCalled();
  });

  it("rejects an encoded source above its byte budget before decoding or chain checks", async () => {
    const chainTracker: ChainTracker = {
      currentHeight: vi.fn(async () => 1_000_000),
      isValidRootForHeight: vi.fn(async () => true),
    };
    const admit = createSourceAdmitter({
      chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 8 },
    });

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: "!".repeat(100),
          sourceOutputIndex: 0,
          publicKey: new PrivateKey(1).toPublicKey().toString(),
        },
      ]),
    ).rejects.toThrow(/Atomic BEEF exceeds policy/);
    expect(chainTracker.isValidRootForHeight).not.toHaveBeenCalled();
  });

  it("rejects a non-canonical unpadded base64 alias of the same Atomic BEEF", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });
    const unpadded = fixture.sourceTransaction.replace(/=+$/, "");
    expect(unpadded).not.toBe(fixture.sourceTransaction);

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: unpadded,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/canonical padded base64/);
  });

  it("rejects canonical base64 with bytes after the Atomic BEEF envelope", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });
    const withTrailingByte = Utils.toBase64([
      ...Utils.toArray(fixture.sourceTransaction, "base64"),
      0,
    ]);

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: withTrailingByte,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/trailing bytes/);
  });

  it("normalizes a truncated Atomic BEEF parse failure", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });
    const decoded = Utils.toArray(fixture.sourceTransaction, "base64");
    const truncated = Utils.toBase64(decoded.slice(0, -16));

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: truncated,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/source admission failed: Atomic BEEF is malformed/);
  });

  it("normalizes invalid source script verification", async () => {
    const fixture = await buildSourceFixture(0, { signingKey: new PrivateKey(9_999) });
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/source admission failed: invalid source transaction/);
  });

  it("rejects a real signed source transaction that repeats one input outpoint", async () => {
    const fixture = await buildSourceFixture(0, {
      duplicateInput: true,
      outputSatoshis: 250_000,
    });
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/duplicate input outpoint/);
  });

  it("rejects a real signed unmined source whose future locktime is active", async () => {
    const fixture = await buildSourceFixture(0, {
      sourceInputSequence: 0,
      sourceLockTime: 2_000_000_000,
    });
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/non-final unmined transaction/);
  });

  it.each(["0", -0, -1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 32])(
    "rejects non-uint32 source output index %s",
    async invalidIndex => {
      const fixture = await buildSourceFixture();
      const admit = createSourceAdmitter({
        chainTracker: fixture.chainTracker,
        policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
      });

      await expect(
        admit([
          {
            role: "cap",
            sourceTransaction: fixture.sourceTransaction,
            sourceOutputIndex: invalidIndex as never,
            publicKey: fixture.publicKey,
          },
        ]),
      ).rejects.toThrow(/sourceOutputIndex must be a uint32 integer/);
    },
  );

  it("rejects a selected output above the BSV monetary range before script verification", async () => {
    const fixture = await buildSourceFixture(0, {
      outputSatoshis: 2_100_000_000_000_001,
    });
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/invalid source output amount/);
  });

  it("rejects a zero-valued selected output", async () => {
    const fixture = await buildSourceFixture(0, { outputSatoshis: 0 });
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "control",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/invalid source output amount/);
  });

  it("rejects a non-P2PKH selected output even when its source transaction is valid", async () => {
    const fixture = await buildSourceFixture(0, { outputScriptHex: "51" });
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "control",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/source output does not match public key/);
  });

  it("rejects a P2PKH output controlled by a different supplied key", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "control",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: new PrivateKey(8_888).toPublicKey().toString(),
        },
      ]),
    ).rejects.toThrow(/source output does not match public key/);
  });

  it("rejects a source outpoint reused across cap and control roles", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 2, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
        {
          role: "control",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/duplicate source outpoint/);
  });

  it.each([
    ["two unmined siblings", [false, false] as const],
    ["one proven and one unmined sibling", [true, false] as const],
    ["two proven siblings", [true, true] as const],
  ])("rejects conflicting source ancestry across %s", async (_label, provenSources) => {
    const fixture = await buildSiblingDoubleSpendFixture({ provenSources });
    const [first, second] = fixture.sources;
    expect(first.sourceTxid).not.toBe(second.sourceTxid);
    expect(fixture.sharedInputOutpoint).toMatch(/^[0-9a-f]{64}:0$/);
    const admit = createSourceAdmitter({
      chainTracker: first.chainTracker,
      policy: { maxSources: 2, maxAtomicBeefBytesPerSource: 16_384 },
    });
    const firstCandidate = {
      role: "cap" as const,
      sourceTransaction: first.sourceTransaction,
      sourceOutputIndex: 0,
      publicKey: first.publicKey,
    };
    const secondCandidate = {
      role: "control" as const,
      sourceTransaction: second.sourceTransaction,
      sourceOutputIndex: 0,
      publicKey: second.publicKey,
    };

    await expect(admit([firstCandidate])).resolves.toHaveLength(1);
    await expect(admit([secondCandidate])).resolves.toHaveLength(1);

    await expect(admit([firstCandidate, secondCandidate])).rejects.toThrow(
      /conflicting source ancestry/,
    );
  });

  it.each([false, true])(
    "rejects a selected source output already spent by another source (descendant first: %s)",
    async descendantFirst => {
      const fixture = await buildSourceFixture();
      const ancestor = Transaction.fromAtomicBEEF(
        Utils.toArray(fixture.sourceTransaction, "base64"),
      );
      const childKey = new PrivateKey(7_890);
      const child = new Transaction();
      child.addInput({
        sourceTransaction: ancestor,
        sourceOutputIndex: 0,
        unlockingScriptTemplate: new P2PKH().unlock(new PrivateKey(5_678)),
      });
      child.addOutput({
        satoshis: 10_000,
        lockingScript: new P2PKH().lock(childKey.toPublicKey().toHash() as number[]),
      });
      await child.sign();
      const ancestorCandidate = {
        role: "cap" as const,
        sourceTransaction: fixture.sourceTransaction,
        sourceOutputIndex: 0,
        publicKey: fixture.publicKey,
      };
      const childCandidate = {
        role: "control" as const,
        sourceTransaction: Utils.toBase64(child.toAtomicBEEF()),
        sourceOutputIndex: 0,
        publicKey: childKey.toPublicKey().toString(),
      };
      const admit = createSourceAdmitter({
        chainTracker: fixture.chainTracker,
        policy: { maxSources: 2, maxAtomicBeefBytesPerSource: 16_384 },
      });
      await expect(admit([ancestorCandidate])).resolves.toHaveLength(1);
      await expect(admit([childCandidate])).resolves.toHaveLength(1);

      await expect(
        admit(
          descendantFirst
            ? [childCandidate, ancestorCandidate]
            : [ancestorCandidate, childCandidate],
        ),
      ).rejects.toThrow(/selected source outpoint is already spent in source ancestry/);
    },
  );

  it("allows the same complete transaction to appear in two source envelopes", async () => {
    const secondOutputKey = new PrivateKey(7_777);
    const fixture = await buildSourceFixture(0, {
      additionalOutput: { key: secondOutputKey, satoshis: 31_000 },
    });
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 2, maxAtomicBeefBytesPerSource: 16_384 },
    });

    const admitted = await admit([
      {
        role: "cap",
        sourceTransaction: fixture.sourceTransaction,
        sourceOutputIndex: 0,
        publicKey: fixture.publicKey,
      },
      {
        role: "control",
        sourceTransaction: fixture.sourceTransaction,
        sourceOutputIndex: 1,
        publicKey: secondOutputKey.toPublicKey().toString(),
      },
    ]);

    expect(admitted).toHaveLength(2);
    expect(admitted[0].sourceTxid).toBe(admitted[1].sourceTxid);
    expect(admitted[0].sourceOutputIndex).toBe(0);
    expect(admitted[1].sourceOutputIndex).toBe(1);
  });

  it("materializes fresh mutable SDK values from one admitted source", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });
    const [admitted] = await admit([
      {
        role: "cap",
        sourceTransaction: fixture.sourceTransaction,
        sourceOutputIndex: 0,
        publicKey: fixture.publicKey,
      },
    ]);
    const first = materializeAdmittedSource(admitted);
    first.sourceTransaction.outputs[0].satoshis = 1;
    first.atomicBeef[0] ^= 0xff;
    const second = materializeAdmittedSource(admitted);

    expect(second.sourceTransaction).not.toBe(first.sourceTransaction);
    expect(second.atomicBeef).not.toBe(first.atomicBeef);
    expect(second.sourceTransaction.id("hex")).toBe(fixture.sourceTxid);
    expect(second.sourceTransaction.outputs[0].satoshis).toBe(fixture.satoshis);
    expect(Utils.toBase64(Array.from(second.atomicBeef))).toBe(fixture.sourceTransaction);
  });

  it("rejects a source object that admission never issued", () => {
    const forged = {
      role: "cap",
      sourceTxid: "11".repeat(32),
      sourceOutputIndex: 0,
      satoshis: 1n,
      publicKey: `02${"22".repeat(32)}`,
    } as unknown as AdmittedSource;

    expect(() => materializeAdmittedSource(forged)).toThrow(/not issued by source admission/);
  });

  it("rejects a source with an unknown authorization role", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });

    await expect(
      admit([
        {
          role: "recipient" as never,
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: fixture.publicKey,
        },
      ]),
    ).rejects.toThrow(/role must be cap or control/);
  });

  it("rejects an uncompressed source public key", async () => {
    const fixture = await buildSourceFixture();
    const admit = createSourceAdmitter({
      chainTracker: fixture.chainTracker,
      policy: { maxSources: 1, maxAtomicBeefBytesPerSource: 16_384 },
    });
    const encodedPublicKey = new PrivateKey(5_678).toPublicKey().encode(false);
    if (!Array.isArray(encodedPublicKey)) {
      throw new Error("test fixture expected an uncompressed public key byte array");
    }
    const uncompressedPublicKey = Utils.toHex(encodedPublicKey);

    await expect(
      admit([
        {
          role: "cap",
          sourceTransaction: fixture.sourceTransaction,
          sourceOutputIndex: 0,
          publicKey: uncompressedPublicKey,
        },
      ]),
    ).rejects.toThrow(/publicKey must be a compressed public key/);
  });
});
