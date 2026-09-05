import { Beef, ProtoWallet, Utils, type WalletInterface } from "@bsv/sdk";
import type { PaymentPayload, SettleResponse } from "@x402/core/types";
import { describe, expect, it, vi } from "vitest";
import { UptoBsvScheme, type UptoBsvCapSourceProvider } from "../../src/upto/client/scheme";
import type { UptoBsvCapSource, UptoBsvControlOffer } from "../../src/upto/types";
import { admitPresentedAuthorization } from "../../src/upto/internal/presented";
import { createTerminalTransaction } from "../../src/upto/internal/transaction";
import { snapshotPresentedUptoPayment } from "../../src/upto/internal/wire";
import {
  buildAuthorizationFixture,
  buildAncestralConflictFixture,
  type AuthorizationFixture,
} from "./upto-authorization-fixtures";

interface ClientFixture extends AuthorizationFixture {
  wallet: WalletInterface;
  provider: UptoBsvCapSourceProvider;
  prepareCapSources: ReturnType<typeof vi.fn>;
  getPublicKey: ReturnType<typeof vi.fn>;
  createSignature: ReturnType<typeof vi.fn>;
  internalizeAction: ReturnType<typeof vi.fn>;
}

async function clientFixture(capCount = 1, controlCount = 1): Promise<ClientFixture> {
  const now = Math.floor(Date.now() / 1_000);
  const fixture = await buildAuthorizationFixture({
    capCount,
    controlCount,
    nowSeconds: now,
    validAfter: now,
    deadline: now + 60,
  });
  const { payer, capSources } = fixture;
  const prepareCapSources = vi.fn().mockResolvedValue(capSources);
  const getPublicKey = vi.fn(payer.getPublicKey.bind(payer));
  const createSignature = vi.fn(payer.createSignature.bind(payer));
  const internalizeAction = vi.fn().mockResolvedValue({ accepted: true });
  const wallet = {
    getPublicKey,
    createSignature,
    internalizeAction,
  } as unknown as WalletInterface;

  return {
    ...fixture,
    wallet,
    provider: { prepareCapSources },
    prepareCapSources,
    getPublicKey,
    createSignature,
    internalizeAction,
  };
}

function scheme(
  value: ClientFixture,
  sourcePolicy = { maxSources: 8, maxAtomicBeefBytesPerSource: 16_384 },
): UptoBsvScheme {
  return new UptoBsvScheme(value.wallet, {
    capSourceProvider: value.provider,
    chainTracker: value.tracker,
    sourcePolicy,
    terminalPolicy: { maxAtomicBeefBytes: 65_536 },
  });
}

async function payment(value: ClientFixture, client = scheme(value)): Promise<PaymentPayload> {
  const partial = await client.createPaymentPayload(2, value.requirements);
  return {
    ...partial,
    accepted: value.requirements,
  } as PaymentPayload;
}

async function settlement(
  value: ClientFixture,
  paymentPayload: PaymentPayload,
  capCount = 1,
  override?: {
    amount: string;
    recipientAmounts: readonly number[];
    refundAmounts: readonly number[];
  },
): Promise<SettleResponse> {
  const amount = override?.amount ?? (capCount === 1 ? "600" : "790");
  const recipientAmounts = override?.recipientAmounts ?? (capCount === 1 ? [610] : [410, 410]);
  const refundAmounts = override?.refundAmounts ?? (capCount === 1 ? [495] : [250, 255]);
  const presented = snapshotPresentedUptoPayment(
    paymentPayload,
    { ...value.requirements, amount },
    "settle",
  );
  const admitted = await admitPresentedAuthorization({
    presented,
    wallet: value.recipient,
    perspective: "recipient",
    chainTracker: value.tracker,
    sourcePolicy: { maxSources: 8, maxAtomicBeefBytesPerSource: 16_384 },
  });
  const transaction = await createTerminalTransaction({
    authorization: admitted.authorization,
    actualAmount: BigInt(amount),
    recipientAmounts,
    refundAmounts,
    wallet: value.recipient,
  });
  return {
    success: true,
    network: value.requirements.network,
    transaction: transaction.id("hex"),
    payer: presented.payload.senderIdentityKey,
    amount,
    extra: { settlementTransaction: Utils.toBase64(transaction.toAtomicBEEF()) },
  };
}

describe("UptoBsvScheme (client)", () => {
  it("creates one reusable maximum authorization from an external control offer", async () => {
    const value = await clientFixture();
    const client = scheme(value);

    const result = await client.createPaymentPayload(2, value.requirements);

    expect(client.scheme).toBe("upto");
    expect(result.x402Version).toBe(2);
    expect(result.payload).toMatchObject({
      senderIdentityKey: expect.stringMatching(/^0[23][0-9a-f]{64}$/),
      capInputs: [
        {
          floorAmount: "100",
          transactionSignature: expect.any(String),
        },
      ],
      authorizationSignature: expect.any(String),
    });
    expect(value.prepareCapSources).toHaveBeenCalledTimes(1);
    expect(value.createSignature).toHaveBeenCalledTimes(2);
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("reports a clear configuration error when the source policy is missing", async () => {
    const value = await clientFixture();

    expect(
      () =>
        new UptoBsvScheme(value.wallet, {
          capSourceProvider: value.provider,
          chainTracker: value.tracker,
          terminalPolicy: { maxAtomicBeefBytes: 65_536 },
        } as ConstructorParameters<typeof UptoBsvScheme>[1]),
    ).toThrow(/BSV upto client.*source policy/i);
  });

  it("rejects an invalid external control source before reserving or signing payer inputs", async () => {
    const value = await clientFixture();
    const extra = value.requirements.extra as {
      control: UptoBsvControlOffer;
      paymentFlow: string;
    };
    const requirements = {
      ...value.requirements,
      extra: {
        ...extra,
        control: {
          ...extra.control,
          inputs: [{ ...extra.control.inputs[0], sourceTransaction: "not-base64" }],
        },
      },
    };

    await expect(scheme(value).createPaymentPayload(2, requirements)).rejects.toThrow(
      /source admission|Atomic BEEF|base64/i,
    );
    expect(value.prepareCapSources).not.toHaveBeenCalled();
    expect(value.getPublicKey).not.toHaveBeenCalled();
    expect(value.createSignature).not.toHaveBeenCalled();
  });

  it("rejects a control offer with no remaining cap slot before derivation or payer effects", async () => {
    const value = await clientFixture(1, 2);
    const publicDerivation = vi.spyOn(ProtoWallet.prototype, "getPublicKey");
    const beefParse = vi.spyOn(Beef, "fromReader");
    const chainLookup = vi.spyOn(value.tracker, "isValidRootForHeight");

    try {
      await expect(
        scheme(value, { maxSources: 2, maxAtomicBeefBytesPerSource: 16_384 }).createPaymentPayload(
          2,
          value.requirements,
        ),
      ).rejects.toThrow(/source count/i);
      expect(publicDerivation).not.toHaveBeenCalled();
      expect(beefParse).not.toHaveBeenCalled();
      expect(chainLookup).not.toHaveBeenCalled();
      expect(value.getPublicKey).not.toHaveBeenCalled();
      expect(value.prepareCapSources).not.toHaveBeenCalled();
      expect(value.createSignature).not.toHaveBeenCalled();
    } finally {
      publicDerivation.mockRestore();
      beefParse.mockRestore();
      chainLookup.mockRestore();
    }
  });

  it("rejects an oversized control BEEF before derivation, parsing, or payer effects", async () => {
    const value = await clientFixture();
    const extra = value.requirements.extra as {
      control: UptoBsvControlOffer;
      paymentFlow: string;
    };
    const requirements = {
      ...value.requirements,
      extra: {
        ...extra,
        control: {
          ...extra.control,
          inputs: [{ ...extra.control.inputs[0], sourceTransaction: "!".repeat(100) }],
        },
      },
    };
    const publicDerivation = vi.spyOn(ProtoWallet.prototype, "getPublicKey");
    const beefParse = vi.spyOn(Beef, "fromReader");
    const chainLookup = vi.spyOn(value.tracker, "isValidRootForHeight");

    try {
      await expect(
        scheme(value, { maxSources: 8, maxAtomicBeefBytesPerSource: 8 }).createPaymentPayload(
          2,
          requirements,
        ),
      ).rejects.toThrow(/Atomic BEEF exceeds policy/i);
      expect(publicDerivation).not.toHaveBeenCalled();
      expect(beefParse).not.toHaveBeenCalled();
      expect(chainLookup).not.toHaveBeenCalled();
      expect(value.getPublicKey).not.toHaveBeenCalled();
      expect(value.prepareCapSources).not.toHaveBeenCalled();
      expect(value.createSignature).not.toHaveBeenCalled();
    } finally {
      publicDerivation.mockRestore();
      beefParse.mockRestore();
      chainLookup.mockRestore();
    }
  });

  it("rejects an oversized presented source set before public derivation or BEEF parsing", async () => {
    const value = await clientFixture(2, 2);
    const paymentPayload = await payment(value);
    const presented = snapshotPresentedUptoPayment(paymentPayload, value.requirements, "verify");
    const publicDerivation = vi.spyOn(ProtoWallet.prototype, "getPublicKey");
    const beefParse = vi.spyOn(Beef, "fromReader");
    const chainLookup = vi.spyOn(value.tracker, "isValidRootForHeight");

    try {
      await expect(
        admitPresentedAuthorization({
          presented,
          wallet: value.recipient,
          perspective: "recipient",
          chainTracker: value.tracker,
          sourcePolicy: { maxSources: 3, maxAtomicBeefBytesPerSource: 16_384 },
        }),
      ).rejects.toThrow(/source count/i);
      expect(publicDerivation).not.toHaveBeenCalled();
      expect(beefParse).not.toHaveBeenCalled();
      expect(chainLookup).not.toHaveBeenCalled();
    } finally {
      publicDerivation.mockRestore();
      beefParse.mockRestore();
      chainLookup.mockRestore();
    }
  });

  it("does not sign when the control window expires during cap preparation", async () => {
    const value = await clientFixture();
    const control = (value.requirements.extra as { control: UptoBsvControlOffer }).control;
    const now = vi.spyOn(Date, "now").mockReturnValue((control.deadline - 1) * 1_000);
    value.prepareCapSources.mockImplementation(async () => {
      now.mockReturnValue(control.deadline * 1_000);
      return value.capSources;
    });

    try {
      await expect(scheme(value).createPaymentPayload(2, value.requirements)).rejects.toThrow(
        /validity window/i,
      );
      expect(value.createSignature).not.toHaveBeenCalled();
    } finally {
      now.mockRestore();
    }
  });

  it("preserves ordered multi-input sources and signs only once plus once per cap", async () => {
    const value = await clientFixture(2, 2);

    const result = await scheme(value).createPaymentPayload(2, value.requirements);
    const payload = result.payload as unknown as {
      capInputs: Array<UptoBsvCapSource & { transactionSignature: string }>;
    };

    expect(payload.capInputs.map(input => input.nonce)).toEqual(
      value.capSources.map(input => input.nonce),
    );
    expect(payload.capInputs.map(input => input.sourceTransaction)).toEqual(
      value.capSources.map(input => input.sourceTransaction),
    );
    expect(value.prepareCapSources).toHaveBeenCalledTimes(1);
    expect(value.createSignature).toHaveBeenCalledTimes(3);
  });

  it("captures finite policies instead of consulting caller-owned mutable objects", async () => {
    const value = await clientFixture(2, 2);
    const sourcePolicy = { maxSources: 4, maxAtomicBeefBytesPerSource: 16_384 };
    const terminalPolicy = { maxAtomicBeefBytes: 65_536 };
    const client = new UptoBsvScheme(value.wallet, {
      capSourceProvider: value.provider,
      chainTracker: value.tracker,
      sourcePolicy,
      terminalPolicy,
    });

    sourcePolicy.maxSources = 1;
    sourcePolicy.maxAtomicBeefBytesPerSource = 1;
    terminalPolicy.maxAtomicBeefBytes = 1;

    const paymentPayload = await payment(value, client);
    const settleResponse = await settlement(value, paymentPayload, 2);
    await client.schemeHooks.onPaymentResponse!({
      paymentPayload,
      requirements: value.requirements,
      settleResponse,
    });

    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("rejects a cap output spent by the control ancestry before signing authorization", async () => {
    const fixture = await buildAncestralConflictFixture();
    const createSignature = vi.fn(fixture.payer.createSignature.bind(fixture.payer));
    const internalizeAction = vi.fn().mockResolvedValue({ accepted: true });
    const wallet = {
      getPublicKey: fixture.payer.getPublicKey.bind(fixture.payer),
      createSignature,
      internalizeAction,
    } as unknown as WalletInterface;
    const client = new UptoBsvScheme(wallet, {
      capSourceProvider: { prepareCapSources: async () => fixture.capSources },
      chainTracker: fixture.tracker,
      sourcePolicy: { maxSources: 8, maxAtomicBeefBytesPerSource: 16_384 },
      terminalPolicy: { maxAtomicBeefBytes: 65_536 },
    });

    await expect(client.createPaymentPayload(2, fixture.requirements)).rejects.toThrow(
      /selected source outpoint is already spent in source ancestry/,
    );
    expect(createSignature).not.toHaveBeenCalled();
    expect(internalizeAction).not.toHaveBeenCalled();
  });

  it("rejects payer exposure below M before asking the wallet to sign", async () => {
    const value = await clientFixture();
    value.prepareCapSources.mockResolvedValue([
      { ...value.capSources[0], floorAmount: "500" },
    ] satisfies UptoBsvCapSource[]);

    await expect(scheme(value).createPaymentPayload(2, value.requirements)).rejects.toThrow(
      /exposure.*maximum/i,
    );
    expect(value.createSignature).not.toHaveBeenCalled();
  });

  it.each([
    [1, 1, [0, 2]],
    [2, 2, [0, 1, 4, 5]],
  ] as const)(
    "validates a real %sx%s terminal and internalizes all payer outputs once",
    async (capCount, controlCount, outputIndices) => {
      const value = await clientFixture(capCount, controlCount);
      const client = scheme(value);
      const paymentPayload = await payment(value, client);
      const settleResponse = await settlement(value, paymentPayload, capCount);

      await client.schemeHooks.onPaymentResponse!({
        paymentPayload,
        requirements: value.requirements,
        settleResponse,
      });

      expect(value.internalizeAction).toHaveBeenCalledTimes(1);
      const args = value.internalizeAction.mock.calls[0][0];
      expect(args.outputs.map((output: { outputIndex: number }) => output.outputIndex)).toEqual(
        outputIndices,
      );
      expect(
        args.outputs.every(
          (output: { protocol: string; paymentRemittance?: unknown }) =>
            output.protocol === "wallet payment" && output.paymentRemittance !== undefined,
        ),
      ).toBe(true);
    },
  );

  it("does not internalize a failed response or a success without terminal evidence", async () => {
    const value = await clientFixture();
    const client = scheme(value);
    const paymentPayload = await payment(value, client);

    await client.schemeHooks.onPaymentResponse!({
      paymentPayload,
      requirements: value.requirements,
      settleResponse: {
        success: false,
        network: value.requirements.network,
        transaction: "",
      },
    });
    await expect(
      client.schemeHooks.onPaymentResponse!({
        paymentPayload,
        requirements: value.requirements,
        settleResponse: {
          success: true,
          network: value.requirements.network,
          transaction: "00".repeat(32),
          amount: "600",
        },
      }),
    ).rejects.toThrow(/terminal evidence/i);
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("selects failure evidence without wallet effects and internalizes a later identical success", async () => {
    const value = await clientFixture();
    const client = scheme(value);
    const paymentPayload = await payment(value, client);
    const terminal = await settlement(value, paymentPayload);
    const failedTerminal = {
      ...terminal,
      success: false,
      transaction: "",
      errorReason: "settlement_rejected_by_wallet",
    } satisfies SettleResponse;

    await client.schemeHooks.onPaymentResponse!({
      paymentPayload,
      requirements: value.requirements,
      settleResponse: failedTerminal,
    });
    expect(value.internalizeAction).not.toHaveBeenCalled();

    const competing = await settlement(value, paymentPayload, 1, {
      amount: "500",
      recipientAmounts: [510],
      refundAmounts: [595],
    });
    await expect(
      client.schemeHooks.onPaymentResponse!({
        paymentPayload,
        requirements: value.requirements,
        settleResponse: {
          ...competing,
          success: false,
          transaction: "",
          errorReason: "terminal_selection_unavailable",
        },
      }),
    ).rejects.toThrow(/locally selected terminal/i);
    expect(value.internalizeAction).not.toHaveBeenCalled();

    const successContext = {
      paymentPayload,
      requirements: value.requirements,
      settleResponse: terminal,
    };
    await client.schemeHooks.onPaymentResponse!(successContext);
    await client.schemeHooks.onPaymentResponse!(successContext);
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("rejects a response txid mismatch before payer wallet internalization", async () => {
    const value = await clientFixture();
    const client = scheme(value);
    const paymentPayload = await payment(value, client);
    const settleResponse = await settlement(value, paymentPayload);

    await expect(
      client.schemeHooks.onPaymentResponse!({
        paymentPayload,
        requirements: value.requirements,
        settleResponse: { ...settleResponse, transaction: "00".repeat(32) },
      }),
    ).rejects.toThrow(/txid.*Atomic BEEF/i);
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("deduplicates the same locally selected terminal and rejects a conflicting txid", async () => {
    const value = await clientFixture();
    const client = scheme(value);
    const paymentPayload = await payment(value, client);
    const settleResponse = await settlement(value, paymentPayload);
    const context = {
      paymentPayload,
      requirements: value.requirements,
      settleResponse,
    };

    await client.schemeHooks.onPaymentResponse!(context);
    await client.schemeHooks.onPaymentResponse!(context);
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
    await expect(
      client.schemeHooks.onPaymentResponse!({
        ...context,
        settleResponse: { ...settleResponse, amount: "599" },
      }),
    ).rejects.toThrow(/actualAmount|selected terminal/i);
    await expect(
      client.schemeHooks.onPaymentResponse!({
        ...context,
        settleResponse: {
          ...settleResponse,
          extra: { settlementTransaction: "not-base64" },
        },
      }),
    ).rejects.toThrow(/terminal Atomic BEEF|selected terminal/i);
    const competing = await settlement(value, paymentPayload, 1, {
      amount: "500",
      recipientAmounts: [510],
      refundAmounts: [595],
    });
    await expect(
      client.schemeHooks.onPaymentResponse!({
        ...context,
        settleResponse: competing,
      }),
    ).rejects.toThrow(/locally selected terminal/i);
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("surfaces payer wallet rejection without requesting a fresh x402 payload", async () => {
    const value = await clientFixture();
    value.internalizeAction.mockResolvedValue({ accepted: false });
    const client = scheme(value);
    const paymentPayload = await payment(value, client);
    const settleResponse = await settlement(value, paymentPayload);

    await expect(
      client.schemeHooks.onPaymentResponse!({
        paymentPayload,
        requirements: value.requirements,
        settleResponse,
      }),
    ).rejects.toThrow(/payer wallet rejected/i);
    expect(value.prepareCapSources).toHaveBeenCalledTimes(1);
  });

  it.each(["reject", "throw"] as const)(
    "keeps the first terminal selected when the payer wallet may have failed (%s)",
    async failure => {
      const value = await clientFixture();
      if (failure === "reject") {
        value.internalizeAction.mockResolvedValue({ accepted: false });
      } else {
        value.internalizeAction.mockRejectedValue(new Error("payer wallet outcome unknown"));
      }
      const client = scheme(value);
      const paymentPayload = await payment(value, client);
      const first = await settlement(value, paymentPayload);

      await expect(
        client.schemeHooks.onPaymentResponse!({
          paymentPayload,
          requirements: value.requirements,
          settleResponse: first,
        }),
      ).rejects.toThrow();
      await expect(
        client.schemeHooks.onPaymentResponse!({
          paymentPayload,
          requirements: value.requirements,
          settleResponse: first,
        }),
      ).rejects.toThrow(/wallet outcome is unavailable/i);

      const competing = await settlement(value, paymentPayload, 1, {
        amount: "500",
        recipientAmounts: [510],
        refundAmounts: [595],
      });
      await expect(
        client.schemeHooks.onPaymentResponse!({
          paymentPayload,
          requirements: value.requirements,
          settleResponse: competing,
        }),
      ).rejects.toThrow(/locally selected terminal/i);
      expect(value.internalizeAction).toHaveBeenCalledTimes(1);
    },
  );
});
