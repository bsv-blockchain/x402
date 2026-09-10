import { P2PKH, PrivateKey, ProtoWallet, PublicKey, Utils } from "@bsv/sdk";
import { describe, expect, it, vi } from "vitest";
import { BRC29_PROTOCOL_ID, MAX_SATOSHIS } from "../../src/constants";
import {
  validateAndDigestAuthorization,
  type ResolvedAuthorizationFacts,
} from "../../src/upto/internal/authorization";
import {
  deriveUptoOutputSpecs,
  type UptoDerivedOutputSpec,
  type UptoWalletPerspective,
} from "../../src/upto/internal/outputs";

const TIMESTAMP = "1800000000000";
const DERIVATION_PREFIX = Utils.toBase64(Utils.toArray("upto-output-test", "utf8"));

interface WalletPair {
  payer: ProtoWallet;
  recipient: ProtoWallet;
  senderIdentityKey: string;
  payTo: string;
}

function wallets(offset = 0): WalletPair {
  const payerRoot = new PrivateKey(7_001 + offset);
  const recipientRoot = new PrivateKey(7_002 + offset);
  return {
    payer: new ProtoWallet(payerRoot),
    recipient: new ProtoWallet(recipientRoot),
    senderIdentityKey: payerRoot.toPublicKey().toString(),
    payTo: recipientRoot.toPublicKey().toString(),
  };
}

function authorizationFacts(
  pair: WalletPair,
  floorAmounts: readonly number[] = [100],
): ResolvedAuthorizationFacts {
  return {
    network: "bsv:testnet",
    asset: "BSV",
    maximumAmount: "700",
    payTo: pair.payTo,
    maxTimeoutSeconds: 60,
    validAfter: 1_800_000_000,
    deadline: 1_800_000_060,
    controlInputs: [
      {
        nonce: Utils.toBase64(new Array(32).fill(20)),
        sourceTxid: "20".repeat(32),
        sourceOutputIndex: 0,
      },
    ],
    senderIdentityKey: pair.senderIdentityKey,
    derivationPrefix: DERIVATION_PREFIX,
    derivationSuffix: Utils.toBase64(Utils.toArray(TIMESTAMP, "utf8")),
    capInputs: floorAmounts.map((amount, index) => ({
      nonce: Utils.toBase64(new Array(32).fill(10 + index)),
      sourceTxid: String(10 + index)
        .padStart(2, "0")
        .repeat(32),
      sourceOutputIndex: 0,
      floorAmount: String(amount),
    })),
  };
}

function suffix(role: UptoDerivedOutputSpec["role"], outputIndex: number): string {
  return Utils.toBase64(Utils.toArray(`${TIMESTAMP} upto ${role} ${outputIndex}`, "utf8"));
}

async function derive(
  pair: WalletPair,
  perspective: UptoWalletPerspective,
  options: {
    facts?: ResolvedAuthorizationFacts;
    recipientAmounts?: readonly number[];
    refundAmounts?: readonly number[];
  } = {},
) {
  return deriveUptoOutputSpecs({
    wallet: perspective === "payer" ? pair.payer : pair.recipient,
    perspective,
    facts: validateAndDigestAuthorization(options.facts ?? authorizationFacts(pair)).snapshot,
    recipientAmounts: options.recipientAmounts ?? [610],
    refundAmounts: options.refundAmounts ?? [495],
  });
}

async function reciprocalScript(pair: WalletPair, output: UptoDerivedOutputSpec): Promise<string> {
  const { publicKey } = await pair.payer.getPublicKey({
    protocolID: BRC29_PROTOCOL_ID,
    keyID: `${DERIVATION_PREFIX} ${output.paymentRemittance.derivationSuffix}`,
    counterparty: pair.payTo,
    ...(output.role === "recipient" ? {} : { forSelf: true }),
  });
  return new P2PKH().lock(PublicKey.fromString(publicKey).toHash() as number[]).toHex();
}

describe("BSV upto authorization-bound output derivation", () => {
  it("derives the same 1x1 layout from reciprocal payer and recipient wallets", async () => {
    const pair = wallets();
    const [payerOutputs, recipientOutputs] = await Promise.all([
      derive(pair, "payer"),
      derive(pair, "recipient"),
    ]);

    expect(payerOutputs.map(output => output.lockingScript.toHex())).toEqual(
      recipientOutputs.map(output => output.lockingScript.toHex()),
    );
    expect(
      recipientOutputs.map(({ role, outputIndex, satoshis }) => ({
        role,
        outputIndex,
        satoshis,
      })),
    ).toEqual([
      { role: "floor", outputIndex: 0, satoshis: 100 },
      { role: "recipient", outputIndex: 1, satoshis: 610 },
      { role: "refund", outputIndex: 2, satoshis: 495 },
    ]);
    expect(recipientOutputs.map(output => output.paymentRemittance)).toEqual([
      {
        derivationPrefix: DERIVATION_PREFIX,
        derivationSuffix: suffix("floor", 0),
        senderIdentityKey: pair.payTo,
      },
      {
        derivationPrefix: DERIVATION_PREFIX,
        derivationSuffix: suffix("recipient", 1),
        senderIdentityKey: pair.senderIdentityKey,
      },
      {
        derivationPrefix: DERIVATION_PREFIX,
        derivationSuffix: suffix("refund", 2),
        senderIdentityKey: pair.payTo,
      },
    ]);
    for (const output of recipientOutputs) {
      expect(output.lockingScript.toHex()).toBe(await reciprocalScript(pair, output));
    }
  });

  it("takes 2x2 signed floors from the authorization and uses global output indices", async () => {
    const pair = wallets();
    const outputs = await derive(pair, "recipient", {
      facts: authorizationFacts(pair, [100, 101]),
      recipientAmounts: [400, 410],
      refundAmounts: [50, 60],
    });

    expect(outputs.map(output => `${output.role}:${output.outputIndex}`)).toEqual([
      "floor:0",
      "floor:1",
      "recipient:2",
      "recipient:3",
      "refund:4",
      "refund:5",
    ]);
    expect(outputs.map(output => output.paymentRemittance.derivationSuffix)).toEqual([
      suffix("floor", 0),
      suffix("floor", 1),
      suffix("recipient", 2),
      suffix("recipient", 3),
      suffix("refund", 4),
      suffix("refund", 5),
    ]);
  });

  it("rejects the wrong wallet perspective before deriving an output", async () => {
    const pair = wallets();
    await expect(
      deriveUptoOutputSpecs({
        wallet: pair.recipient,
        perspective: "payer",
        facts: validateAndDigestAuthorization(authorizationFacts(pair)).snapshot,
        recipientAmounts: [610],
        refundAmounts: [495],
      }),
    ).rejects.toThrow(/wallet identity does not match payer/);
  });

  it("omits zero refund only through an empty array", async () => {
    const pair = wallets();
    const outputs = await derive(pair, "recipient", { refundAmounts: [] });
    expect(outputs.map(output => output.role)).toEqual(["floor", "recipient"]);
    await expect(derive(pair, "recipient", { refundAmounts: [0] })).rejects.toThrow(
      /refundAmounts\[0\] must be a positive safe integer/,
    );
  });

  it.each([
    ["recipient", [0], []],
    ["refund", [1], [1.5]],
    ["unsafe", [Number.MAX_SAFE_INTEGER + 1], []],
    ["above BSV supply", [MAX_SATOSHIS + 1], []],
  ])("rejects invalid %s amounts before wallet derivation", async (_name, recipient, refund) => {
    const pair = wallets();
    const getPublicKey = vi.spyOn(pair.recipient, "getPublicKey");
    await expect(
      derive(pair, "recipient", { recipientAmounts: recipient, refundAmounts: refund }),
    ).rejects.toThrow(/must be a positive safe integer/);
    expect(getPublicKey).not.toHaveBeenCalled();
  });

  it("rejects a non-decimal exact-style timestamp before wallet derivation", async () => {
    const pair = wallets();
    const facts = {
      ...authorizationFacts(pair),
      derivationSuffix: Utils.toBase64(Utils.toArray("not-a-time", "utf8")),
    };
    const getPublicKey = vi.spyOn(pair.recipient, "getPublicKey");
    await expect(derive(pair, "recipient", { facts })).rejects.toThrow(
      /derivationSuffix must encode a canonical Unix-ms timestamp/,
    );
    expect(getPublicKey).not.toHaveBeenCalled();
  });

  it("captures variable amount arrays before the first wallet await", async () => {
    const pair = wallets();
    const facts = validateAndDigestAuthorization(authorizationFacts(pair)).snapshot;
    const recipientAmounts = [610];
    const refundAmounts = [495];
    let release!: () => void;
    const gate = new Promise<void>(resolve => {
      release = resolve;
    });
    let entered!: () => void;
    const called = new Promise<void>(resolve => {
      entered = resolve;
    });
    let first = true;
    const original = pair.recipient.getPublicKey.bind(pair.recipient);
    const wallet = {
      getPublicKey: async (...args: Parameters<ProtoWallet["getPublicKey"]>) => {
        if (first) {
          first = false;
          entered();
          await gate;
        }
        return original(...args);
      },
    };

    const pending = deriveUptoOutputSpecs({
      wallet,
      perspective: "recipient",
      facts,
      recipientAmounts,
      refundAmounts,
    });
    await called;
    recipientAmounts[0] = 9_000;
    refundAmounts.length = 0;
    release();

    const outputs = await pending;
    expect(outputs.map(output => output.satoshis)).toEqual([100, 610, 495]);
    expect(outputs[0].paymentRemittance.derivationPrefix).toBe(DERIVATION_PREFIX);
    expect(outputs[2].paymentRemittance.derivationSuffix).toBe(suffix("refund", 2));
  });
});
