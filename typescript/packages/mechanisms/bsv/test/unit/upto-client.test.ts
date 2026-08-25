import { Beef, BigNumber, ECDSA, LockingScript, PrivateKey, Transaction, Utils } from "@bsv/sdk";
import type { WalletInterface } from "@bsv/sdk";
import type { PaymentRequirements } from "@x402/core/types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BRC29_PROTOCOL_ID, BSV_TESTNET_CAIP2 } from "../../src/constants";
import type {
  UptoBsvControlProposal,
  UptoBsvControlRequest,
  UptoBsvPayload,
} from "../../src/types";
import { UptoBsvScheme, type UptoBsvControlProvider } from "../../src/upto/client/scheme";
import { BSV_UPTO_PROTOCOL_ID, uptoControlKeyId, p2pkhLockingScript } from "../../src/upto/shared";
import { buildUptoTransactionVersion, verifyUptoAuthorization } from "../../src/upto/transaction";

const NOW_SECONDS = 1_700_000_000;
const PAYER_KEY = PrivateKey.fromRandom();
const PAYMENT_KEY = PrivateKey.fromRandom();
const CAP_KEY = PrivateKey.fromRandom();
const PAYEE_IDENTITY_KEY = PrivateKey.fromRandom();
const CONTROL_KEY = PrivateKey.fromRandom();

const PAYER = PAYER_KEY.toPublicKey().toString();
const PAY_TO = PAYEE_IDENTITY_KEY.toPublicKey().toString();
const PAYMENT_PUBLIC_KEY = PAYMENT_KEY.toPublicKey().toString();
const CAP_PUBLIC_KEY = CAP_KEY.toPublicKey().toString();
const CONTROL_PUBLIC_KEY = CONTROL_KEY.toPublicKey().toString();

interface Fixture {
  wallet: WalletInterface;
  controlProvider: UptoBsvControlProvider;
  createControlProposal: ReturnType<typeof vi.fn>;
}

/** Builds one parseable BEEF source transaction paying a P2PKH output. */
function sourceTransaction(
  publicKey: string,
  satoshis: number,
  tag: number,
): { binary: number[]; encoded: string; txid: string } {
  const transaction = new Transaction(1, [], [], tag);
  transaction.addOutput({
    lockingScript: LockingScript.fromHex(p2pkhLockingScript(publicKey)),
    satoshis,
  });
  const beef = new Beef();
  beef.mergeTransaction(transaction);
  const binary = beef.toBinary();
  return {
    binary,
    encoded: Utils.toBase64(binary),
    txid: transaction.id("hex"),
  };
}

/** Signs an already-computed digest with the cap key. */
function signDigest(digest: number[]): number[] {
  return ECDSA.sign(new BigNumber(digest), CAP_KEY, true).toDER() as number[];
}

/** Builds valid BSV upto payment requirements. */
function requirements(overrides: Partial<PaymentRequirements> = {}): PaymentRequirements {
  return {
    scheme: "upto",
    network: BSV_TESTNET_CAIP2,
    asset: "BSV",
    amount: "1000",
    payTo: PAY_TO,
    maxTimeoutSeconds: 300,
    extra: {},
    ...overrides,
  };
}

/** Builds a valid recipient control proposal bound to the payment request. */
function controlProposal(
  request: UptoBsvControlRequest,
  overrides: Partial<UptoBsvControlProposal> = {},
): UptoBsvControlProposal {
  const source = sourceTransaction(CONTROL_PUBLIC_KEY, 2, 2);
  return {
    inputs: [
      {
        owner: request.payTo,
        kind: "control",
        sourceTransaction: source.encoded,
        sourceOutputIndex: 0,
        publicKey: CONTROL_PUBLIC_KEY,
      },
    ],
    fee: "1",
    sequenceStart: 1,
    validAfter: NOW_SECONDS,
    deadline: NOW_SECONDS + request.maxTimeoutSeconds,
    nLockTime: NOW_SECONDS + 120,
    ...overrides,
  };
}

/** Creates a wallet and recipient-provider pair for the public client flow. */
function fixture(
  proposalFactory: (request: UptoBsvControlRequest) => UptoBsvControlProposal = controlProposal,
): Fixture {
  const createControlProposal = vi.fn(async (request: UptoBsvControlRequest) =>
    proposalFactory(request),
  );
  const wallet = {
    getPublicKey: vi.fn(
      async (args: {
        identityKey?: boolean;
        protocolID?: readonly [number, string];
        keyID?: string;
      }) => {
        if (args.identityKey) return { publicKey: PAYER };
        if (args.protocolID?.[1] === BSV_UPTO_PROTOCOL_ID[1]) {
          return { publicKey: CAP_PUBLIC_KEY };
        }
        if (args.keyID?.endsWith("upto-control-0")) {
          return { publicKey: CONTROL_PUBLIC_KEY };
        }
        return { publicKey: PAYMENT_PUBLIC_KEY };
      },
    ),
    createAction: vi.fn(
      async (args: { outputs?: Array<{ lockingScript: string; satoshis: number }> }) => {
        const output = args.outputs?.[0];
        if (!output) throw new Error("test wallet expected one cap output");
        const source = sourceTransaction(CAP_PUBLIC_KEY, output.satoshis, 1);
        expect(output.lockingScript).toBe(p2pkhLockingScript(CAP_PUBLIC_KEY));
        return { tx: source.binary, txid: source.txid };
      },
    ),
    createSignature: vi.fn(async (args: { hashToDirectlySign?: number[] }) => {
      if (!args.hashToDirectlySign) throw new Error("test wallet requires direct digest signing");
      return { signature: signDigest(args.hashToDirectlySign) };
    }),
  } as unknown as WalletInterface;
  return {
    wallet,
    controlProvider: { createControlProposal },
    createControlProposal,
  };
}

describe("UptoBsvScheme (client)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(NOW_SECONDS * 1000));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("creates a verifiable maximum authorization without selecting a transaction version", async () => {
    const { wallet, controlProvider, createControlProposal } = fixture();
    const scheme = new UptoBsvScheme(wallet, { controlProvider });

    const result = await scheme.createPaymentPayload(2, requirements());
    const payload = result.payload as unknown as UptoBsvPayload;
    const verified = verifyUptoAuthorization(payload.authorization);

    expect(scheme.scheme).toBe("upto");
    expect(result.x402Version).toBe(2);
    expect(payload).not.toHaveProperty("transaction");
    expect(payload.transactionVersion).toBeUndefined();
    expect(verified.maximumAmount).toBe("1000");
    expect(payload.authorization.terms.network).toBe(BSV_TESTNET_CAIP2);
    expect(payload.authorization.terms.asset).toBe("BSV");
    expect(payload.authorization.terms.payTo).toBe(PAY_TO);
    expect(payload.authorization.terms.senderIdentityKey).toBe(PAYER);
    expect(payload.authorization.terms.inputs.map(input => input.kind)).toEqual(["cap", "control"]);
    expect(payload.authorization.terms.inputs[1].owner).toBe(PAY_TO);
    expect(payload.authorization.terms.paymentOutputIndexes).toEqual([2]);
    expect(payload.outputIndex).toBe(2);

    expect(createControlProposal).toHaveBeenCalledOnce();
    expect(createControlProposal).toHaveBeenCalledWith({
      network: BSV_TESTNET_CAIP2,
      payTo: PAY_TO,
      senderIdentityKey: PAYER,
      derivationPrefix: payload.derivationPrefix,
      derivationSuffix: payload.derivationSuffix,
      maxAmount: "1000",
      maxTimeoutSeconds: 300,
    });
    expect(wallet.getPublicKey).toHaveBeenCalledWith(
      {
        protocolID: BRC29_PROTOCOL_ID,
        keyID: `${payload.derivationPrefix} ${payload.derivationSuffix}`,
        counterparty: PAY_TO,
      },
      undefined,
    );
    expect(wallet.getPublicKey).toHaveBeenCalledWith(
      {
        protocolID: BRC29_PROTOCOL_ID,
        keyID: uptoControlKeyId(payload.derivationPrefix, payload.derivationSuffix, 0),
        counterparty: PAY_TO,
      },
      undefined,
    );

    const actionArgs = vi.mocked(wallet.createAction).mock.calls[0][0];
    expect(actionArgs.outputs?.[0].satoshis).toBe(1001);
    expect(actionArgs.options).toEqual({ noSend: true, randomizeOutputs: false });
    expect(wallet.createSignature).toHaveBeenCalledTimes(2);
    for (const [signatureArgs] of vi.mocked(wallet.createSignature).mock.calls) {
      expect(signatureArgs).toMatchObject({
        protocolID: BSV_UPTO_PROTOCOL_ID,
        keyID: `${payload.derivationPrefix} ${payload.derivationSuffix} cap-0`,
        counterparty: "self",
      });
      expect(signatureArgs.hashToDirectlySign).toHaveLength(32);
    }
  });

  it("lets the payer verify each fully signed transaction and its progression", async () => {
    const { wallet, controlProvider } = fixture();
    const scheme = new UptoBsvScheme(wallet, { controlProvider });
    const created = await scheme.createPaymentPayload(2, requirements());
    const payload = created.payload as unknown as UptoBsvPayload;
    const controlSigner = async (digest: number[]): Promise<number[]> =>
      ECDSA.sign(new BigNumber(digest), CONTROL_KEY, true).toDER() as number[];
    const first = await buildUptoTransactionVersion(
      payload.authorization,
      { nSequence: 1, outputAmounts: ["1", "600", "401"] },
      { 1: controlSigner },
    );
    const second = await buildUptoTransactionVersion(
      payload.authorization,
      { nSequence: 2, outputAmounts: ["1", "500", "501"] },
      { 1: controlSigner },
    );

    expect(scheme.verifyTransactionVersion(payload, first)).toMatchObject({
      amount: "400",
      nSequence: 1,
      cooperativeClose: false,
      ownerDeltas: { [PAYER]: "400", [PAY_TO]: "-399" },
    });
    expect(scheme.verifyTransactionVersion(payload, second, first)).toMatchObject({
      amount: "500",
      nSequence: 2,
    });
    expect(() => scheme.verifyTransactionVersion(payload, second)).toThrow(
      /first non-final.*sequenceStart/i,
    );
    expect(() => scheme.verifyTransactionVersion(payload, second, second)).toThrow(
      /advance by one/i,
    );
  });

  it("accepts a minimal control input only when its value exceeds the fee", async () => {
    const zeroFee = fixture(request => controlProposal(request, { fee: "0" }));
    await expect(
      new UptoBsvScheme(zeroFee.wallet, {
        controlProvider: zeroFee.controlProvider,
      }).createPaymentPayload(2, requirements()),
    ).resolves.toBeDefined();

    const valid = fixture(request => controlProposal(request));
    await expect(
      new UptoBsvScheme(valid.wallet, {
        controlProvider: valid.controlProvider,
      }).createPaymentPayload(2, requirements()),
    ).resolves.toBeDefined();

    const equalToFee = fixture(request => {
      const source = sourceTransaction(CONTROL_PUBLIC_KEY, 1, 3);
      const proposal = controlProposal(request);
      return {
        ...proposal,
        inputs: [
          {
            ...proposal.inputs[0],
            sourceTransaction: source.encoded,
          },
        ],
      };
    });
    await expect(
      new UptoBsvScheme(equalToFee.wallet, {
        controlProvider: equalToFee.controlProvider,
      }).createPaymentPayload(2, requirements()),
    ).rejects.toThrow(/must exceed.*fee/i);
    expect(equalToFee.wallet.createAction).not.toHaveBeenCalled();
    expect(equalToFee.wallet.createSignature).not.toHaveBeenCalled();
  });

  it("rejects a control input that is not bound to the recipient", async () => {
    const unrelatedOwner = PrivateKey.fromRandom().toPublicKey().toString();
    const invalid = fixture(request => {
      const proposal = controlProposal(request);
      return {
        ...proposal,
        inputs: [{ ...proposal.inputs[0], owner: unrelatedOwner }],
      };
    });

    await expect(
      new UptoBsvScheme(invalid.wallet, {
        controlProvider: invalid.controlProvider,
      }).createPaymentPayload(2, requirements()),
    ).rejects.toThrow(/bound to payTo/i);
    expect(invalid.wallet.createAction).not.toHaveBeenCalled();
    expect(invalid.wallet.createSignature).not.toHaveBeenCalled();
  });

  it("rejects a zero maximum before consulting the recipient or wallet", async () => {
    const { wallet, controlProvider, createControlProposal } = fixture();

    await expect(
      new UptoBsvScheme(wallet, { controlProvider }).createPaymentPayload(
        2,
        requirements({ amount: "0" }),
      ),
    ).rejects.toThrow(/amount/i);
    expect(createControlProposal).not.toHaveBeenCalled();
    expect(wallet.getPublicKey).not.toHaveBeenCalled();
    expect(wallet.createAction).not.toHaveBeenCalled();
    expect(wallet.createSignature).not.toHaveBeenCalled();
  });
});
