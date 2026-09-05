import {
  Hash,
  LockingScript,
  MerklePath,
  P2PKH,
  PrivateKey,
  Transaction,
  UnlockingScript,
  Utils,
  type ChainTracker,
} from "@bsv/sdk";

export interface SourceFixture {
  sourceTransaction: string;
  sourceTxid: string;
  sourceOutputIndex: number;
  publicKey: string;
  satoshis: number;
  lockingScriptHex: string;
  chainTracker: ChainTracker;
}

export interface SourceFixtureOptions {
  additionalOutput?: {
    key: PrivateKey;
    satoshis: number;
  };
  duplicateInput?: boolean;
  signingKey?: PrivateKey;
  sourceInputSequence?: number;
  sourceLockTime?: number;
  outputSatoshis?: number;
  outputScriptHex?: string;
}

export interface SiblingDoubleSpendFixture {
  sources: readonly [SourceFixture, SourceFixture];
  sharedInputOutpoint: string;
}

export interface SiblingDoubleSpendOptions {
  provenSources?: readonly [boolean, boolean];
}

/**
 * Builds a real signed transaction whose parent is anchored by a deterministic
 * Merkle path. Only the chain facts are supplied by a test adapter.
 *
 * @param seed - Distinguishes fixed keys and proof heights between fixtures
 * @param options - Optional transaction mutations used by rejection tests
 * @returns Canonical Atomic BEEF and the facts selected by source admission
 */
export async function buildSourceFixture(
  seed = 0,
  options: SourceFixtureOptions = {},
): Promise<SourceFixture> {
  const fundingKey = new PrivateKey(1_234 + seed * 2);
  const sourceKey = new PrivateKey(5_678 + seed * 2);

  const parent = new Transaction();
  parent.addInput({
    sourceTXID: "00".repeat(32),
    sourceOutputIndex: 0xffffffff,
    unlockingScript: new UnlockingScript([]),
  });
  parent.addOutput({
    satoshis: 150_000,
    lockingScript: new P2PKH().lock(
      Hash.hash160(Utils.toArray(fundingKey.toPublicKey().toString(), "hex")),
    ),
  });

  const proofHeight = 100 + seed;
  const parentTxid = parent.id("hex");
  parent.merklePath = MerklePath.fromCoinbaseTxidAndHeight(parentTxid, proofHeight);

  const source = new Transaction(1, [], [], options.sourceLockTime ?? 0);
  const inputCount = options.duplicateInput === true ? 2 : 1;
  for (let index = 0; index < inputCount; index += 1) {
    source.addInput({
      sourceTransaction: parent,
      sourceOutputIndex: 0,
      sequence: options.sourceInputSequence,
      unlockingScriptTemplate: new P2PKH().unlock(options.signingKey ?? fundingKey),
    });
  }
  source.addOutput({
    satoshis: options.outputSatoshis ?? 30_000 + seed,
    lockingScript:
      options.outputScriptHex === undefined
        ? new P2PKH().lock(Hash.hash160(Utils.toArray(sourceKey.toPublicKey().toString(), "hex")))
        : LockingScript.fromHex(options.outputScriptHex),
  });
  if (options.additionalOutput !== undefined) {
    source.addOutput({
      satoshis: options.additionalOutput.satoshis,
      lockingScript: new P2PKH().lock(
        Hash.hash160(Utils.toArray(options.additionalOutput.key.toPublicKey().toString(), "hex")),
      ),
    });
  }
  await source.sign();

  const sourceTxid = source.id("hex");
  const lockingScriptHex = Utils.toHex(source.outputs[0].lockingScript.toBinary());
  const acceptedRoots = new Set([parentTxid]);

  return {
    sourceTransaction: Utils.toBase64(source.toAtomicBEEF()),
    sourceTxid,
    sourceOutputIndex: 0,
    publicKey: sourceKey.toPublicKey().toString(),
    satoshis: source.outputs[0].satoshis ?? 0,
    lockingScriptHex,
    chainTracker: {
      currentHeight: async () => 1_000_000,
      isValidRootForHeight: async root => acceptedRoots.has(root),
    },
  };
}

/**
 * Builds two independently valid source envelopes whose distinct subjects
 * spend the same proven parent outpoint.
 *
 * @returns Two real signed sibling transactions and their shared input
 */
export async function buildSiblingDoubleSpendFixture(
  options: SiblingDoubleSpendOptions = {},
): Promise<SiblingDoubleSpendFixture> {
  const fundingKey = new PrivateKey(12_345);
  const firstSourceKey = new PrivateKey(23_456);
  const secondSourceKey = new PrivateKey(34_567);

  const parent = new Transaction();
  parent.addInput({
    sourceTXID: "00".repeat(32),
    sourceOutputIndex: 0xffffffff,
    unlockingScript: new UnlockingScript([]),
  });
  parent.addOutput({
    satoshis: 150_000,
    lockingScript: new P2PKH().lock(
      Hash.hash160(Utils.toArray(fundingKey.toPublicKey().toString(), "hex")),
    ),
  });

  const proofHeight = 900;
  const parentTxid = parent.id("hex");
  parent.merklePath = MerklePath.fromCoinbaseTxidAndHeight(parentTxid, proofHeight);
  const acceptedRoots = new Set([parentTxid]);

  const buildSibling = async (
    sourceKey: PrivateKey,
    outputSatoshis: number,
    proven: boolean,
  ): Promise<SourceFixture> => {
    const source = new Transaction();
    source.addInput({
      sourceTransaction: parent,
      sourceOutputIndex: 0,
      unlockingScriptTemplate: new P2PKH().unlock(fundingKey),
    });
    source.addOutput({
      satoshis: outputSatoshis,
      lockingScript: new P2PKH().lock(
        Hash.hash160(Utils.toArray(sourceKey.toPublicKey().toString(), "hex")),
      ),
    });
    await source.sign();
    const sourceTxid = source.id("hex");
    if (proven) {
      source.merklePath = MerklePath.fromCoinbaseTxidAndHeight(
        sourceTxid,
        proofHeight + outputSatoshis,
      );
      acceptedRoots.add(sourceTxid);
    }

    return {
      sourceTransaction: Utils.toBase64(source.toAtomicBEEF()),
      sourceTxid,
      sourceOutputIndex: 0,
      publicKey: sourceKey.toPublicKey().toString(),
      satoshis: source.outputs[0].satoshis ?? 0,
      lockingScriptHex: Utils.toHex(source.outputs[0].lockingScript.toBinary()),
      chainTracker: {
        currentHeight: async () => 1_000_000,
        isValidRootForHeight: async root => acceptedRoots.has(root),
      },
    };
  };

  const provenSources = options.provenSources ?? [false, false];
  const first = await buildSibling(firstSourceKey, 30_000, provenSources[0]);
  const second = await buildSibling(secondSourceKey, 31_000, provenSources[1]);
  return {
    sources: [first, second],
    sharedInputOutpoint: `${parentTxid}:0`,
  };
}
