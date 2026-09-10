import {
  Hash,
  P2PKH,
  PrivateKey,
  ProtoWallet,
  PublicKey,
  Transaction,
  UnlockingScript,
  Utils,
  type ChainTracker,
  type WalletProtocol,
} from "@bsv/sdk";
import type { PaymentRequirements } from "@x402/core/types";
import type { ResolvedAuthorizationFacts } from "../../src/upto/internal/authorization";
import {
  createSourceAdmitter,
  type AdmittedSource,
  type SourceCandidate,
} from "../../src/upto/internal/source";
import type { UptoBsvCapSource, UptoBsvControlOffer } from "../../src/upto/types";
import { buildSourceFixture, type SourceFixture } from "./upto-source-fixtures";

const CAP_PROTOCOL: WalletProtocol = [2, "x402 bsv upto cap"];
const CONTROL_PROTOCOL: WalletProtocol = [2, "x402 bsv upto control"];

interface AuthorizationFixtureOptions {
  capCount?: number;
  controlCount?: number;
  nowSeconds?: number;
  validAfter?: number;
  deadline?: number;
}

export interface AuthorizationFixture {
  payer: ProtoWallet;
  recipient: ProtoWallet;
  payerIdentity: string;
  payTo: string;
  capSources: UptoBsvCapSource[];
  controlOffer: UptoBsvControlOffer;
  requirements: PaymentRequirements;
  facts: ResolvedAuthorizationFacts;
  sources: SourceFixture[];
  tracker: ChainTracker;
}

export interface AdmittedAuthorizationFixture extends AuthorizationFixture {
  capInputs: AdmittedSource[];
  controlInputs: AdmittedSource[];
}

/**
 * Encodes a compressed public key as a canonical P2PKH locking script.
 *
 * @param publicKey - Compressed public key in hexadecimal form
 * @returns Canonical P2PKH locking script in hexadecimal form
 */
export function p2pkh(publicKey: string): string {
  return new P2PKH().lock(PublicKey.fromString(publicKey).toHash() as number[]).toHex();
}

/**
 * Combines the deterministic chain facts carried by source fixtures.
 *
 * @param fixtures - Source fixtures whose proven parents should be accepted
 * @returns A tracker that delegates each root lookup to the source fixtures
 */
export function combinedTracker(fixtures: readonly SourceFixture[]): ChainTracker {
  return {
    currentHeight: async () => 1_000_000,
    isValidRootForHeight: async (root, height) => {
      for (const fixture of fixtures) {
        if (await fixture.chainTracker.isValidRootForHeight(root, height)) return true;
      }
      return false;
    },
  };
}

/**
 * Builds the common payer/recipient authorization material used by role tests.
 * It deliberately stops before authorization signing or terminal construction.
 *
 * @param options - Input cardinality and authorization-window overrides
 * @returns Real source BEEF, wire references, facts, wallets, and chain facts
 */
export async function buildAuthorizationFixture(
  options: AuthorizationFixtureOptions = {},
): Promise<AuthorizationFixture> {
  const capCount = options.capCount ?? 1;
  const controlCount = options.controlCount ?? 1;
  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1_000);
  const validAfter = options.validAfter ?? nowSeconds - 1;
  const deadline = options.deadline ?? nowSeconds + 59;
  const payer = new ProtoWallet(new PrivateKey(808));
  const recipient = new ProtoWallet(new PrivateKey(909));
  const payerIdentity = (await payer.getPublicKey({ identityKey: true })).publicKey;
  const payTo = (await recipient.getPublicKey({ identityKey: true })).publicKey;
  const capSources: UptoBsvCapSource[] = [];
  const controlInputs: UptoBsvControlOffer["inputs"][number][] = [];
  const sources: SourceFixture[] = [];

  for (let index = 0; index < capCount; index += 1) {
    const nonce = Utils.toBase64(new Array(32).fill(10 + index));
    const { publicKey } = await payer.getPublicKey({
      protocolID: CAP_PROTOCOL,
      keyID: nonce,
      counterparty: "anyone",
      forSelf: true,
    });
    const source = await buildSourceFixture(100 + index, {
      outputSatoshis: capCount === 1 ? 1_200 : index === 0 ? 800 : 700,
      outputScriptHex: p2pkh(publicKey),
    });
    sources.push(source);
    capSources.push({
      nonce,
      sourceTransaction: source.sourceTransaction,
      sourceOutputIndex: source.sourceOutputIndex,
      floorAmount: "100",
    });
  }

  for (let index = 0; index < controlCount; index += 1) {
    const nonce = Utils.toBase64(new Array(32).fill(20 + index));
    const { publicKey } = await recipient.getPublicKey({
      protocolID: CONTROL_PROTOCOL,
      keyID: nonce,
      counterparty: "anyone",
      forSelf: true,
    });
    const source = await buildSourceFixture(200 + index, {
      outputSatoshis: 10 + index * 10,
      outputScriptHex: p2pkh(publicKey),
    });
    sources.push(source);
    controlInputs.push({
      nonce,
      sourceTransaction: source.sourceTransaction,
      sourceOutputIndex: source.sourceOutputIndex,
    });
  }

  const tracker = combinedTracker(sources);
  const controlOffer: UptoBsvControlOffer = { inputs: controlInputs, validAfter, deadline };
  const requirements: PaymentRequirements = {
    scheme: "upto",
    network: "bsv:testnet",
    asset: "BSV",
    amount: "1000",
    payTo,
    maxTimeoutSeconds: 60,
    extra: { control: controlOffer, paymentFlow: "authorization" },
  };
  const facts: ResolvedAuthorizationFacts = {
    network: requirements.network,
    asset: requirements.asset,
    maximumAmount: requirements.amount,
    payTo,
    maxTimeoutSeconds: requirements.maxTimeoutSeconds,
    validAfter,
    deadline,
    controlInputs: controlInputs.map((source, index) => ({
      nonce: source.nonce,
      sourceTxid: sources[capCount + index].sourceTxid,
      sourceOutputIndex: source.sourceOutputIndex,
    })),
    senderIdentityKey: payerIdentity,
    derivationPrefix: Utils.toBase64(Utils.toArray("prefix-upto", "utf8")),
    derivationSuffix: Utils.toBase64(Utils.toArray(String(nowSeconds * 1_000), "utf8")),
    capInputs: capSources.map((source, index) => ({
      nonce: source.nonce,
      sourceTxid: sources[index].sourceTxid,
      sourceOutputIndex: source.sourceOutputIndex,
      floorAmount: source.floorAmount,
    })),
  };

  return {
    payer,
    recipient,
    payerIdentity,
    payTo,
    capSources,
    controlOffer,
    requirements,
    facts,
    sources,
    tracker,
  };
}

/**
 * Builds individually valid cap/control sources where the control spends the
 * selected cap output, making their proposed joint spend impossible.
 *
 * @returns Real signed source ancestry and matching authorization terms
 */
export async function buildAncestralConflictFixture(): Promise<AuthorizationFixture> {
  const fixture = await buildAuthorizationFixture();
  const cap = fixture.capSources[0];
  const control = fixture.controlOffer.inputs[0];
  const ancestor = Transaction.fromAtomicBEEF(Utils.toArray(cap.sourceTransaction, "base64"));
  const { publicKey: capKey } = await fixture.payer.getPublicKey({
    protocolID: CAP_PROTOCOL,
    keyID: cap.nonce,
    counterparty: "anyone",
    forSelf: true,
  });
  const { publicKey: controlKey } = await fixture.recipient.getPublicKey({
    protocolID: CONTROL_PROTOCOL,
    keyID: control.nonce,
    counterparty: "anyone",
    forSelf: true,
  });
  const child = new Transaction();
  child.addInput({ sourceTransaction: ancestor, sourceOutputIndex: 0, sequence: 0xffffffff });
  child.addOutput({
    satoshis: 10,
    lockingScript: new P2PKH().lock(PublicKey.fromString(controlKey).toHash() as number[]),
  });
  const { signature } = await fixture.payer.createSignature({
    hashToDirectlySign: Hash.hash256(child.preimage(0, 0x41)),
    protocolID: CAP_PROTOCOL,
    keyID: cap.nonce,
    counterparty: "anyone",
  });
  const publicKey = Utils.toArray(capKey, "hex");
  child.inputs[0].unlockingScript = new UnlockingScript([
    { op: signature.length + 1, data: [...signature, 0x41] },
    { op: publicKey.length, data: publicKey },
  ]);
  const sourceTransaction = Utils.toBase64(child.toAtomicBEEF());
  const controlOffer = {
    ...fixture.controlOffer,
    inputs: [{ ...control, sourceTransaction }],
  };
  return {
    ...fixture,
    controlOffer,
    requirements: {
      ...fixture.requirements,
      extra: { ...fixture.requirements.extra, control: controlOffer },
    },
    facts: {
      ...fixture.facts,
      controlInputs: [{ ...fixture.facts.controlInputs[0], sourceTxid: child.id("hex") }],
    },
  };
}

/**
 * Admits the ordered cap and control sources of an authorization fixture.
 *
 * @param fixture - Common raw authorization material
 * @returns The same fixture with validated cap and control source inputs
 */
export async function admitAuthorizationFixture(
  fixture: AuthorizationFixture,
): Promise<AdmittedAuthorizationFixture> {
  const candidates: SourceCandidate[] = [];
  for (const source of fixture.capSources) {
    const { publicKey } = await fixture.payer.getPublicKey({
      protocolID: CAP_PROTOCOL,
      keyID: source.nonce,
      counterparty: "anyone",
      forSelf: true,
    });
    candidates.push({
      role: "cap",
      sourceTransaction: source.sourceTransaction,
      sourceOutputIndex: source.sourceOutputIndex,
      publicKey,
    });
  }
  for (const source of fixture.controlOffer.inputs) {
    const { publicKey } = await fixture.recipient.getPublicKey({
      protocolID: CONTROL_PROTOCOL,
      keyID: source.nonce,
      counterparty: "anyone",
      forSelf: true,
    });
    candidates.push({
      role: "control",
      sourceTransaction: source.sourceTransaction,
      sourceOutputIndex: source.sourceOutputIndex,
      publicKey,
    });
  }

  const admitted = await createSourceAdmitter({
    chainTracker: fixture.tracker,
    policy: {
      maxSources: candidates.length,
      maxAtomicBeefBytesPerSource: 16_384,
    },
  })(candidates);
  const capCount = fixture.capSources.length;
  return {
    ...fixture,
    capInputs: admitted.slice(0, capCount),
    controlInputs: admitted.slice(capCount),
  };
}
