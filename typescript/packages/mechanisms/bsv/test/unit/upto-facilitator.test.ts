import { Beef, BigNumber, ECDSA, LockingScript, PrivateKey, Transaction, Utils } from "@bsv/sdk";
import type { WalletInterface } from "@bsv/sdk";
import { x402ResourceServer, type FacilitatorClient, type SettleContext } from "@x402/core/server";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BSV_TESTNET_CAIP2 } from "../../src/constants";
import { brc29PaymentKeyId, uptoControlKeyId } from "../../src/upto/shared";
import type {
  UptoBsvAuthorizationTerms,
  UptoBsvPayload,
  UptoBsvTransactionVersion,
} from "../../src/types";
import { UptoBsvScheme, type UptoBsvSettlementStore } from "../../src/upto/facilitator/scheme";
import { UptoBsvScheme as UptoBsvServerScheme } from "../../src/upto/server/scheme";
import {
  buildUptoTransactionVersion,
  signUptoAuthorization,
  uptoP2pkhScript,
  verifyUptoTransactionVersion,
  type UptoBsvDigestSigner,
} from "../../src/upto/transaction";

const NOW = 1_700_000_000_000;
const NOW_SECONDS = Math.floor(NOW / 1000);
const FINAL_SEQUENCE = 0xffffffff;
const MAXIMUM = "8000";
const FEE = 1;
const CONTROL_SATOSHIS = 101;
const FLOOR = 2_000;
const NON_FINAL_DELAY_SECONDS = 120;

interface FacilitatorFixture {
  scheme: UptoBsvScheme;
  wallet: WalletInterface;
  payload: UptoBsvPayload;
  maximumRequirements: PaymentRequirements;
  senderIdentityKey: string;
  capSigner: UptoBsvDigestSigner;
  controlSigner: UptoBsvDigestSigner;
}

interface TestSettlementBackend {
  entries: Map<string, { txid: string; deleteAfterMs: number; token: string }>;
  nextToken: number;
}

const testSettlementBackend = (): TestSettlementBackend => ({
  entries: new Map(),
  nextToken: 0,
});

/** Test adapter whose backend can outlive an individual facilitator instance. */
class TestSettlementStore implements UptoBsvSettlementStore {
  constructor(private readonly backend = testSettlementBackend()) {}

  async tryClaim(
    authorizationId: string,
    txid: string,
    deleteAfterMs: number,
  ): Promise<{ claimed: true; token: string } | { claimed: false; txid: string }> {
    const existing = this.backend.entries.get(authorizationId);
    if (existing && existing.deleteAfterMs > Date.now()) {
      return { claimed: false, txid: existing.txid };
    }
    const token = `claim-${this.backend.nextToken++}`;
    this.backend.entries.set(authorizationId, { txid, deleteAfterMs, token });
    return { claimed: true, token };
  }

  async release(authorizationId: string, token: string): Promise<void> {
    if (this.backend.entries.get(authorizationId)?.token === token) {
      this.backend.entries.delete(authorizationId);
    }
  }
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

/** Builds actual-amount requirements while retaining the original maximum elsewhere. */
const settlementRequirements = (
  fixture: FacilitatorFixture,
  amount: string,
): PaymentRequirements => ({
  ...fixture.maximumRequirements,
  amount,
});

/** Wraps an upto payload in the x402 envelope used by facilitator hooks. */
const paymentEnvelope = (
  fixture: FacilitatorFixture,
  transactionVersion?: UptoBsvTransactionVersion,
  accepted: PaymentRequirements = fixture.maximumRequirements,
): PaymentPayload => ({
  x402Version: 2,
  accepted,
  payload: {
    ...fixture.payload,
    ...(transactionVersion ? { transactionVersion } : {}),
  } as unknown as PaymentPayload["payload"],
});

/** Creates a valid maximum authorization and a wallet that signs control inputs for real. */
const makeFixture = async (
  verifyBeef: (beefBytes: number[], subjectTxid: string) => Promise<boolean> = vi
    .fn()
    .mockResolvedValue(true),
  settlementStore: UptoBsvSettlementStore = new TestSettlementStore(),
): Promise<FacilitatorFixture> => {
  const capKey = PrivateKey.fromRandom();
  const recipientIdentityKey = PrivateKey.fromRandom();
  const paymentKey = PrivateKey.fromRandom();
  const controlKey = PrivateKey.fromRandom();
  const senderIdentityKey = capKey.toPublicKey().toString();
  const payTo = recipientIdentityKey.toPublicKey().toString();
  const derivationPrefix = Utils.toBase64([1, 2, 3, 4, 5, 6, 7, 8]);
  const derivationSuffix = Utils.toBase64(Utils.toArray(String(NOW), "utf8"));
  const paymentKeyId = brc29PaymentKeyId(derivationPrefix, derivationSuffix);
  const controlKeyId = uptoControlKeyId(derivationPrefix, derivationSuffix, 0);
  const terms: UptoBsvAuthorizationTerms = {
    version: 1,
    network: BSV_TESTNET_CAIP2,
    asset: "BSV",
    payTo,
    senderIdentityKey,
    derivationPrefix,
    derivationSuffix,
    inputs: [
      {
        owner: senderIdentityKey,
        kind: "cap",
        sourceTransaction: sourceTransaction(capKey, 10_000, 1),
        sourceOutputIndex: 0,
        publicKey: senderIdentityKey,
      },
      {
        owner: payTo,
        kind: "control",
        sourceTransaction: sourceTransaction(controlKey, CONTROL_SATOSHIS, 2),
        sourceOutputIndex: 0,
        publicKey: controlKey.toPublicKey().toString(),
      },
    ],
    outputs: [
      {
        owner: senderIdentityKey,
        lockingScript: uptoP2pkhScript(senderIdentityKey),
        fixedAmount: String(FLOOR),
      },
      {
        owner: senderIdentityKey,
        lockingScript: uptoP2pkhScript(senderIdentityKey),
      },
      {
        owner: payTo,
        lockingScript: uptoP2pkhScript(paymentKey.toPublicKey().toString()),
      },
    ],
    chargedOwners: [senderIdentityKey],
    paymentOutputIndexes: [2],
    fee: String(FEE),
    sequenceStart: 1,
    validAfter: NOW_SECONDS,
    deadline: NOW_SECONDS + 300,
    nLockTime: NOW_SECONDS + NON_FINAL_DELAY_SECONDS,
  };
  const capSigner = digestSigner(capKey);
  const authorization = await signUptoAuthorization(terms, { 0: capSigner });
  const internalizeAction = vi.fn().mockResolvedValue({ accepted: true });
  const getPublicKey = vi.fn().mockImplementation(async (args: { keyID?: string }) => {
    if (args.keyID === paymentKeyId) return { publicKey: paymentKey.toPublicKey().toString() };
    if (args.keyID === controlKeyId) return { publicKey: controlKey.toPublicKey().toString() };
    throw new Error(`unexpected keyID ${args.keyID ?? "none"}`);
  });
  const createSignature = vi
    .fn()
    .mockImplementation(async (args: { keyID: string; hashToDirectlySign: number[] }) => {
      if (args.keyID !== controlKeyId) throw new Error(`unexpected keyID ${args.keyID}`);
      return { signature: await digestSigner(controlKey)(Array.from(args.hashToDirectlySign)) };
    });
  const wallet = {
    getNetwork: vi.fn().mockResolvedValue({ network: "testnet" }),
    getPublicKey,
    createSignature,
    internalizeAction,
  } as unknown as WalletInterface;
  const scheme = new UptoBsvScheme({
    wallet,
    identityKey: payTo,
    feeSatoshis: FEE,
    controlSatoshis: CONTROL_SATOSHIS,
    nonFinalDelaySeconds: NON_FINAL_DELAY_SECONDS,
    verifyBeef,
    settlementStore,
  });
  const maximumRequirements: PaymentRequirements = {
    scheme: "upto",
    network: BSV_TESTNET_CAIP2,
    asset: "BSV",
    amount: MAXIMUM,
    payTo,
    maxTimeoutSeconds: 300,
    extra: {},
  };
  return {
    scheme,
    wallet,
    maximumRequirements,
    senderIdentityKey,
    capSigner,
    controlSigner: digestSigner(controlKey),
    payload: {
      derivationPrefix,
      derivationSuffix,
      senderIdentityKey,
      outputIndex: 2,
      authorization,
    },
  };
};

describe("UptoBsvScheme (facilitator)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(NOW));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("verifies the reusable authorization at its maximum amount", async () => {
    const fixture = await makeFixture();

    await expect(
      fixture.scheme.verify(paymentEnvelope(fixture), fixture.maximumRequirements),
    ).resolves.toEqual({ isValid: true, payer: fixture.senderIdentityKey });

    const wrongMaximum = { ...fixture.maximumRequirements, amount: "7999" };
    const invalid = await fixture.scheme.verify(
      paymentEnvelope(fixture, undefined, wrongMaximum),
      wrongMaximum,
    );
    expect(invalid).toMatchObject({
      isValid: false,
      invalidReason: "invalid_upto_bsv_maximum_mismatch",
    });
  });

  it("rejects a client-owned settlement version before server enrichment", async () => {
    const fixture = await makeFixture();
    const envelope = paymentEnvelope(fixture);
    envelope.payload = {
      ...envelope.payload,
      transactionVersion: undefined,
    } as unknown as PaymentPayload["payload"];

    await expect(
      fixture.scheme.verify(envelope, fixture.maximumRequirements),
    ).resolves.toMatchObject({
      isValid: false,
      invalidReason: "unexpected_transaction_version",
    });
  });

  it("revalidates the recipient fee and timing policy before signing", async () => {
    const fixture = await makeFixture();
    const feeAuthorization = await signUptoAuthorization(
      { ...fixture.payload.authorization.terms, fee: "8000" },
      { 0: fixture.capSigner },
    );
    const timingAuthorization = await signUptoAuthorization(
      {
        ...fixture.payload.authorization.terms,
        nLockTime: fixture.payload.authorization.terms.nLockTime + 1,
      },
      { 0: fixture.capSigner },
    );

    for (const authorization of [feeAuthorization, timingAuthorization]) {
      const altered = {
        ...fixture,
        payload: { ...fixture.payload, authorization },
      };
      await expect(
        fixture.scheme.verify(paymentEnvelope(altered), fixture.maximumRequirements),
      ).resolves.toMatchObject({
        isValid: false,
        invalidReason: "invalid_upto_bsv_facilitator_policy",
      });
    }
  });

  it("can reject an authorization whose source BEEF fails early SPV validation", async () => {
    const verifyBeef = vi.fn().mockResolvedValue(false);
    const fixture = await makeFixture(verifyBeef);

    await expect(
      fixture.scheme.verify(paymentEnvelope(fixture), fixture.maximumRequirements),
    ).resolves.toMatchObject({
      isValid: false,
      invalidReason: "invalid_upto_bsv_source_spv",
    });
    expect(verifyBeef).toHaveBeenCalledOnce();
  });

  it("creates the default zero and partial-amount output layouts", async () => {
    const fixture = await makeFixture();

    const zero = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "0" },
    );
    const partial = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500" },
    );

    expect(verifyUptoTransactionVersion(fixture.payload.authorization, zero)).toMatchObject({
      amount: "0",
      nSequence: 1,
      outputAmounts: ["2000", "8000", "100"],
    });
    expect(verifyUptoTransactionVersion(fixture.payload.authorization, partial)).toMatchObject({
      amount: "2500",
      nSequence: 1,
      outputAmounts: ["2000", "5500", "2600"],
    });
  });

  it("rejects a signed allocation whose owner labels overstate the recipient payment", async () => {
    const fixture = await makeFixture();
    const misleadingTerms: UptoBsvAuthorizationTerms = {
      ...fixture.payload.authorization.terms,
      outputs: fixture.payload.authorization.terms.outputs.map((output, index) =>
        index === 1 ? { ...output, owner: "not-the-payer" } : output,
      ),
    };
    const authorization = await signUptoAuthorization(misleadingTerms, {
      0: fixture.capSigner,
    });
    const misleadingPayload = { ...fixture.payload, authorization };
    const outputAmounts = [String(FLOOR), "8100", "0"];

    await expect(
      fixture.scheme.createTransactionVersion(misleadingPayload, fixture.maximumRequirements, {
        amount: MAXIMUM,
        outputAmounts,
      }),
    ).rejects.toThrow("invalid_upto_bsv_recipient_amount_shortfall");

    const signed = await buildUptoTransactionVersion(
      authorization,
      { nSequence: FINAL_SEQUENCE, outputAmounts },
      { 1: fixture.controlSigner },
    );
    await expect(
      fixture.scheme.settle(
        paymentEnvelope({ ...fixture, payload: misleadingPayload }, signed),
        settlementRequirements(fixture, MAXIMUM),
      ),
    ).resolves.toMatchObject({
      success: false,
      errorReason: "invalid_upto_bsv_recipient_amount_shortfall",
    });
  });

  it("advances stream nSequence, rejects amount rollback, and cooperatively closes", async () => {
    const fixture = await makeFixture();
    const first = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "1000" },
    );
    const second = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", previous: first },
    );

    expect(verifyUptoTransactionVersion(fixture.payload.authorization, first).nSequence).toBe(1);
    expect(verifyUptoTransactionVersion(fixture.payload.authorization, second)).toMatchObject({
      amount: "2500",
      nSequence: 2,
      cooperativeClose: false,
    });
    await expect(
      fixture.scheme.createTransactionVersion(fixture.payload, fixture.maximumRequirements, {
        amount: "2499",
        previous: second,
      }),
    ).rejects.toThrow(/amount must not decrease/i);

    const close = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", previous: second, cooperativeClose: true },
    );
    const verifiedClose = verifyUptoTransactionVersion(fixture.payload.authorization, close);
    expect(verifiedClose).toMatchObject({
      amount: "2500",
      nSequence: FINAL_SEQUENCE,
      cooperativeClose: true,
    });
    expect(verifiedClose.transaction.inputs[0].sequence).toBe(FINAL_SEQUENCE);
    expect(verifiedClose.transaction.inputs[1].sequence).toBe(FINAL_SEQUENCE);
  });

  it("recomputes settlement amount, rejects a premature version, and rejects replay", async () => {
    const fixture = await makeFixture();
    const intermediate = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500" },
    );

    const premature = await fixture.scheme.settle(
      paymentEnvelope(fixture, intermediate),
      settlementRequirements(fixture, "2500"),
    );
    expect(premature).toMatchObject({ success: false, errorReason: "transaction_non_final" });

    const close = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", previous: intermediate, cooperativeClose: true },
    );
    const mismatch = await fixture.scheme.settle(
      paymentEnvelope(fixture, close),
      settlementRequirements(fixture, "2499"),
    );
    expect(mismatch).toMatchObject({
      success: false,
      errorReason: "invalid_upto_bsv_amount_mismatch",
    });

    const settlementPayload = paymentEnvelope(fixture, close);
    const actualRequirements = settlementRequirements(fixture, "2500");
    const first = await fixture.scheme.settle(settlementPayload, actualRequirements);
    const replay = await fixture.scheme.settle(settlementPayload, actualRequirements);
    const verified = verifyUptoTransactionVersion(fixture.payload.authorization, close);

    expect(first).toMatchObject({
      success: true,
      network: BSV_TESTNET_CAIP2,
      transaction: verified.txid,
      payer: fixture.senderIdentityKey,
      amount: "2500",
    });
    expect(replay).toMatchObject({ success: false, errorReason: "duplicate_settlement" });
    expect(fixture.wallet.internalizeAction).toHaveBeenCalledTimes(1);
    expect(fixture.wallet.internalizeAction).toHaveBeenCalledWith(
      {
        tx: Utils.toArray(close.transaction, "base64"),
        outputs: [
          {
            outputIndex: 2,
            protocol: "wallet payment",
            paymentRemittance: {
              derivationPrefix: fixture.payload.derivationPrefix,
              derivationSuffix: fixture.payload.derivationSuffix,
              senderIdentityKey: fixture.senderIdentityKey,
            },
          },
        ],
        description: "x402 upto payment",
      },
      undefined,
    );
  });

  it("enforces validAfter, nLockTime, and deadline as distinct settlement bounds", async () => {
    const fixture = await makeFixture();

    vi.setSystemTime(new Date(NOW - 1_000));
    await expect(
      fixture.scheme.verify(paymentEnvelope(fixture), fixture.maximumRequirements),
    ).resolves.toMatchObject({
      isValid: false,
      invalidReason: "upto_authorization_out_of_window",
    });

    vi.setSystemTime(new Date(NOW));
    const intermediate = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500" },
    );
    vi.setSystemTime(new Date((NOW_SECONDS + NON_FINAL_DELAY_SECONDS) * 1000));
    await expect(
      fixture.scheme.settle(
        paymentEnvelope(fixture, intermediate),
        settlementRequirements(fixture, "2500"),
      ),
    ).resolves.toMatchObject({ success: true, amount: "2500" });

    const laterVersion = await makeFixture();
    await expect(
      laterVersion.scheme.createTransactionVersion(
        laterVersion.payload,
        laterVersion.maximumRequirements,
        { amount: "2500" },
      ),
    ).resolves.toBeDefined();

    const expired = await makeFixture();
    vi.setSystemTime(new Date(NOW));
    const close = await expired.scheme.createTransactionVersion(
      expired.payload,
      expired.maximumRequirements,
      { amount: "2500", cooperativeClose: true },
    );
    vi.setSystemTime(new Date(expired.payload.authorization.terms.deadline * 1000));
    await expect(
      expired.scheme.settle(
        paymentEnvelope(expired, close),
        settlementRequirements(expired, "2500"),
      ),
    ).resolves.toMatchObject({
      success: false,
      errorReason: "upto_authorization_out_of_window",
    });
    await expect(
      expired.scheme.createTransactionVersion(expired.payload, expired.maximumRequirements, {
        amount: "2500",
      }),
    ).rejects.toThrow(/out_of_window/);

    expect(() => verifyUptoTransactionVersion(expired.payload.authorization, close)).not.toThrow();
  });

  it("rechecks the deadline after asynchronous transaction validation", async () => {
    const verifyBeef = vi.fn().mockResolvedValue(true);
    const fixture = await makeFixture(verifyBeef);
    const close = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", cooperativeClose: true },
    );
    verifyBeef.mockImplementationOnce(async () => {
      vi.setSystemTime(new Date(fixture.payload.authorization.terms.deadline * 1000));
      return true;
    });

    await expect(
      fixture.scheme.settle(
        paymentEnvelope(fixture, close),
        settlementRequirements(fixture, "2500"),
      ),
    ).resolves.toMatchObject({
      success: false,
      errorReason: "upto_authorization_out_of_window",
    });
    expect(fixture.wallet.internalizeAction).not.toHaveBeenCalled();
  });

  it("does not call the wallet when an atomic claim completes after the deadline", async () => {
    const backingStore = new TestSettlementStore();
    const delayedStore: UptoBsvSettlementStore = {
      tryClaim: async (authorizationId, txid, deleteAfterMs) => {
        const claim = await backingStore.tryClaim(authorizationId, txid, deleteAfterMs);
        vi.setSystemTime(new Date((NOW_SECONDS + 300) * 1000));
        return claim;
      },
      release: (authorizationId, token) => backingStore.release(authorizationId, token),
    };
    const fixture = await makeFixture(undefined, delayedStore);
    const close = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", cooperativeClose: true },
    );

    await expect(
      fixture.scheme.settle(
        paymentEnvelope(fixture, close),
        settlementRequirements(fixture, "2500"),
      ),
    ).resolves.toMatchObject({
      success: false,
      errorReason: "upto_authorization_out_of_window",
    });
    expect(fixture.wallet.internalizeAction).not.toHaveBeenCalled();
  });

  it("settles through resource-server enrichment with the selected transaction", async () => {
    const fixture = await makeFixture();
    const selected = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", cooperativeClose: true },
    );
    const settle = vi.fn((payload: PaymentPayload, requirements: PaymentRequirements) =>
      fixture.scheme.settle(payload, requirements),
    );
    const facilitatorClient: FacilitatorClient = {
      getSupported: async () => ({
        kinds: [
          {
            x402Version: 2,
            scheme: "upto",
            network: BSV_TESTNET_CAIP2,
          },
        ],
        extensions: [],
        signers: { [BSV_TESTNET_CAIP2]: [fixture.maximumRequirements.payTo] },
      }),
      verify: (payload, requirements) => fixture.scheme.verify(payload, requirements),
      settle,
    };
    const getTransactionVersion = vi.fn((_context: SettleContext) => selected);
    const resourceServer = new x402ResourceServer(facilitatorClient).register(
      BSV_TESTNET_CAIP2,
      new UptoBsvServerScheme({ getTransactionVersion }),
    );
    await resourceServer.initialize();
    const clientEnvelope = paymentEnvelope(fixture);

    const result = await resourceServer.settlePayment(
      clientEnvelope,
      fixture.maximumRequirements,
      undefined,
      undefined,
      { amount: "2500" },
    );

    expect(result).toMatchObject({
      success: true,
      network: BSV_TESTNET_CAIP2,
      amount: "2500",
      payer: fixture.senderIdentityKey,
    });
    expect(getTransactionVersion).toHaveBeenCalledOnce();
    expect(getTransactionVersion.mock.calls[0][0]).toMatchObject({
      paymentPayload: clientEnvelope,
      requirements: { amount: "2500" },
      phase: "after-handler",
    });
    expect(settle).toHaveBeenCalledOnce();
    expect(settle.mock.calls[0][0].payload).toEqual({
      ...fixture.payload,
      transactionVersion: selected,
    });
    expect(settle.mock.calls[0][1].amount).toBe("2500");
    expect(clientEnvelope.payload).toEqual(fixture.payload);
    expect(fixture.wallet.internalizeAction).toHaveBeenCalledOnce();
  });

  it("rejects a different terminal transaction after one authorization settles", async () => {
    const fixture = await makeFixture();
    const first = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", cooperativeClose: true },
    );
    const competing = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "3000", cooperativeClose: true },
    );

    await expect(
      fixture.scheme.settle(
        paymentEnvelope(fixture, first),
        settlementRequirements(fixture, "2500"),
      ),
    ).resolves.toMatchObject({ success: true, amount: "2500" });
    await expect(
      fixture.scheme.settle(
        paymentEnvelope(fixture, competing),
        settlementRequirements(fixture, "3000"),
      ),
    ).resolves.toMatchObject({ success: false, errorReason: "authorization_already_settled" });
    expect(fixture.wallet.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("consumes one authorization across facilitator replicas and restarts", async () => {
    const durableBackend = testSettlementBackend();
    const fixture = await makeFixture(undefined, new TestSettlementStore(durableBackend));
    const restarted = new UptoBsvScheme({
      wallet: fixture.wallet,
      identityKey: fixture.maximumRequirements.payTo,
      feeSatoshis: FEE,
      controlSatoshis: CONTROL_SATOSHIS,
      nonFinalDelaySeconds: NON_FINAL_DELAY_SECONDS,
      verifyBeef: vi.fn().mockResolvedValue(true),
      settlementStore: new TestSettlementStore(durableBackend),
    });
    const first = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "2500", cooperativeClose: true },
    );
    const competing = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "3000", cooperativeClose: true },
    );

    const settled = await fixture.scheme.settle(
      paymentEnvelope(fixture, first),
      settlementRequirements(fixture, "2500"),
    );
    const afterRestart = await restarted.settle(
      paymentEnvelope(fixture, competing),
      settlementRequirements(fixture, "3000"),
    );

    expect(settled).toMatchObject({ success: true, amount: "2500" });
    expect(afterRestart).toMatchObject({
      success: false,
      errorReason: "authorization_already_settled",
    });
    expect(fixture.wallet.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("honors wallet rejection and merge replay outcomes", async () => {
    const rejected = await makeFixture();
    vi.mocked(rejected.wallet.internalizeAction).mockResolvedValueOnce({
      accepted: false,
    } as never);
    const rejectedClose = await rejected.scheme.createTransactionVersion(
      rejected.payload,
      rejected.maximumRequirements,
      { amount: "1000", cooperativeClose: true },
    );
    const rejectedRequirements = settlementRequirements(rejected, "1000");

    await expect(
      rejected.scheme.settle(paymentEnvelope(rejected, rejectedClose), rejectedRequirements),
    ).resolves.toMatchObject({
      success: false,
      errorReason: "settlement_rejected_by_wallet",
    });
    await expect(
      rejected.scheme.settle(paymentEnvelope(rejected, rejectedClose), rejectedRequirements),
    ).resolves.toMatchObject({ success: true });

    const replayed = await makeFixture();
    vi.mocked(replayed.wallet.internalizeAction).mockResolvedValueOnce({
      accepted: true,
      isMerge: true,
      satoshis: 0,
    } as never);
    const replayedClose = await replayed.scheme.createTransactionVersion(
      replayed.payload,
      replayed.maximumRequirements,
      { amount: "1000", cooperativeClose: true },
    );
    const replayedPayload = paymentEnvelope(replayed, replayedClose);
    const replayedRequirements = settlementRequirements(replayed, "1000");

    await expect(
      replayed.scheme.settle(replayedPayload, replayedRequirements),
    ).resolves.toMatchObject({ success: false, errorReason: "duplicate_settlement" });
    await expect(
      replayed.scheme.settle(replayedPayload, replayedRequirements),
    ).resolves.toMatchObject({ success: false, errorReason: "duplicate_settlement" });
    expect(replayed.wallet.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("retains the authorization when the wallet result is not a definitive rejection", async () => {
    for (const walletResult of [{}, { accepted: false, satoshis: 1 }]) {
      const fixture = await makeFixture();
      vi.mocked(fixture.wallet.internalizeAction).mockResolvedValueOnce(walletResult as never);
      const first = await fixture.scheme.createTransactionVersion(
        fixture.payload,
        fixture.maximumRequirements,
        { amount: "1000", cooperativeClose: true },
      );
      const competing = await fixture.scheme.createTransactionVersion(
        fixture.payload,
        fixture.maximumRequirements,
        { amount: "2000", cooperativeClose: true },
      );

      await expect(
        fixture.scheme.settle(
          paymentEnvelope(fixture, first),
          settlementRequirements(fixture, "1000"),
        ),
      ).resolves.toMatchObject({
        success: false,
        errorReason: "settlement_indeterminate: invalid wallet result",
      });
      await expect(
        fixture.scheme.settle(
          paymentEnvelope(fixture, competing),
          settlementRequirements(fixture, "2000"),
        ),
      ).resolves.toMatchObject({
        success: false,
        errorReason: "authorization_already_settled",
      });
      expect(fixture.wallet.internalizeAction).toHaveBeenCalledTimes(1);
    }
  });

  it("keeps the authorization guarded when the wallet outcome is indeterminate", async () => {
    const fixture = await makeFixture();
    vi.mocked(fixture.wallet.internalizeAction).mockRejectedValueOnce(
      new Error("transport timed out"),
    );
    const close = await fixture.scheme.createTransactionVersion(
      fixture.payload,
      fixture.maximumRequirements,
      { amount: "1000", cooperativeClose: true },
    );
    const payload = paymentEnvelope(fixture, close);
    const actual = settlementRequirements(fixture, "1000");

    await expect(fixture.scheme.settle(payload, actual)).resolves.toMatchObject({
      success: false,
      errorReason: "settlement_indeterminate: transport timed out",
    });
    await expect(fixture.scheme.settle(payload, actual)).resolves.toMatchObject({
      success: false,
      errorReason: "duplicate_settlement",
    });
    expect(fixture.wallet.internalizeAction).toHaveBeenCalledOnce();
  });
});
