import { type WalletInterface } from "@bsv/sdk";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { x402Facilitator } from "@x402/core/facilitator";
import {
  x402HTTPResourceServer,
  x402ResourceServer,
  type FacilitatorClient,
  type HTTPAdapter,
  type HTTPResponseInstructions,
} from "@x402/core/server";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
  SupportedResponse,
  VerifyResponse,
} from "@x402/core/types";
import { describe, expect, it, vi } from "vitest";
import { BSV_TESTNET_CAIP2 } from "../../src/constants";
import { UptoBsvScheme as UptoBsvClient } from "../../src/upto/client";
import {
  InMemoryTerminalStore,
  UptoBsvScheme as UptoBsvFacilitator,
} from "../../src/upto/facilitator";
import { InMemoryAuthorizationStore, UptoBsvScheme as UptoBsvServer } from "../../src/upto/server";
import { buildAuthorizationFixture } from "./upto-authorization-fixtures";

const HEADER_LINE_LIMIT = 8 * 1024;
const HEADER_SET_LIMIT = 16 * 1024;

class LocalFacilitatorClient implements FacilitatorClient {
  readonly settlementPayloads: PaymentPayload[] = [];
  readonly settlementRequirements: PaymentRequirements[] = [];

  constructor(private readonly facilitator: x402Facilitator) {}

  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse> {
    return this.facilitator.verify(payload, requirements);
  }

  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse> {
    this.settlementPayloads.push(structuredClone(payload));
    this.settlementRequirements.push(structuredClone(requirements));
    return this.facilitator.settle(payload, requirements);
  }

  getSupported(): Promise<SupportedResponse> {
    const supported = this.facilitator.getSupported();
    return Promise.resolve({
      ...supported,
      kinds: supported.kinds.map(kind => ({ ...kind, network: kind.network as Network })),
    });
  }
}

function headerLineBytes(name: string, value: string): number {
  return Buffer.byteLength(`${name}: ${value}\r\n`, "utf8");
}

async function exerciseHttpFlow(
  sourceCount: 1 | 2,
  settleAtMaximum = false,
  recipientWalletResult: { accepted: boolean; isMerge?: boolean; satoshis?: number } = {
    accepted: true,
  },
) {
  const now = Math.floor(Date.now() / 1_000);
  const fixture = await buildAuthorizationFixture({
    capCount: sourceCount,
    controlCount: sourceCount,
    nowSeconds: now,
  });
  const { payer, recipient, payTo, capSources, tracker: chainTracker } = fixture;
  const control = fixture.controlOffer;
  const recipientInternalize = vi.fn().mockResolvedValue(recipientWalletResult);
  const payerInternalize = vi.fn().mockResolvedValue({ accepted: true });
  const recipientWallet = {
    getPublicKey: recipient.getPublicKey.bind(recipient),
    createSignature: recipient.createSignature.bind(recipient),
    getNetwork: vi.fn().mockResolvedValue({ network: "testnet" }),
    internalizeAction: recipientInternalize,
  } as unknown as WalletInterface;
  const payerWallet = {
    getPublicKey: payer.getPublicKey.bind(payer),
    createSignature: payer.createSignature.bind(payer),
    internalizeAction: payerInternalize,
  } as unknown as WalletInterface;
  const actualAmount = settleAtMaximum ? "1000" : sourceCount === 1 ? "600" : "790";
  const plan = settleAtMaximum
    ? { recipientAmounts: [1_010], refundAmounts: [95] }
    : sourceCount === 1
      ? { recipientAmounts: [610], refundAmounts: [495] }
      : { recipientAmounts: [410, 410], refundAmounts: [250, 255] };
  let feeAdmitted = true;
  const admitFee = vi.fn(async () => feeAdmitted);

  const facilitatorScheme = new UptoBsvFacilitator({
    wallet: recipientWallet,
    identityKey: payTo,
    chainTracker,
    sourcePolicy: { maxSources: 4, maxAtomicBeefBytesPerSource: 512 },
    terminalPolicy: { maxAtomicBeefBytes: 4 * 1024 },
    terminalStore: new InMemoryTerminalStore(),
    admitFee,
    planTerminal: async () => plan,
  });
  const facilitator = new x402Facilitator().register(BSV_TESTNET_CAIP2, facilitatorScheme);
  const facilitatorClient = new LocalFacilitatorClient(facilitator);
  const resourceServer = new x402ResourceServer(facilitatorClient);
  resourceServer.register(
    BSV_TESTNET_CAIP2,
    new UptoBsvServer({
      authorizationStore: new InMemoryAuthorizationStore(),
    }),
  );
  await resourceServer.initialize();

  const route = "/metered";
  const httpServer = new x402HTTPResourceServer(resourceServer, {
    [route]: {
      accepts: {
        scheme: "upto",
        network: BSV_TESTNET_CAIP2,
        payTo,
        price: { amount: "1000", asset: "BSV" },
        maxTimeoutSeconds: 60,
        extra: { paymentFlow: "authorization", control },
      },
      description: "Metered BSV resource",
      mimeType: "application/json",
    },
  });
  const prepareCapSources = vi.fn().mockResolvedValue(capSources);
  const scheme = new UptoBsvClient(payerWallet, {
    capSourceProvider: { prepareCapSources },
    chainTracker,
    sourcePolicy: { maxSources: 4, maxAtomicBeefBytesPerSource: 512 },
    terminalPolicy: { maxAtomicBeefBytes: 4 * 1024 },
  });
  const paymentResponseHook = vi.spyOn(scheme.schemeHooks, "onPaymentResponse");
  const coreClient = x402Client.fromConfig({
    schemes: [{ network: BSV_TESTNET_CAIP2, client: scheme }],
    spendControls: false,
  });
  const httpClient = new x402HTTPClient(coreClient);
  let paymentSignature: string | undefined;
  const adapter: HTTPAdapter = {
    getHeader: name => (name === "PAYMENT-SIGNATURE" ? paymentSignature : undefined),
    getMethod: () => "GET",
    getPath: () => route,
    getUrl: () => `https://example.test${route}`,
    getAcceptHeader: () => "application/json",
    getUserAgent: () => "x402-bsv-upto-test",
  };
  const context = { adapter, path: route, method: "GET" };

  const first = await httpServer.processHTTPRequest(context);
  expect(first.type).toBe("payment-error");
  const requiredResponse = (first as { type: "payment-error"; response: HTTPResponseInstructions })
    .response;
  const paymentRequired = httpClient.getPaymentRequiredResponse(
    name => requiredResponse.headers[name],
    requiredResponse.body,
  );
  const paymentPayload = await httpClient.createPaymentPayload(paymentRequired);
  expect(paymentPayload.accepted?.extra?.control).toEqual(control);
  paymentSignature = httpClient.encodePaymentSignatureHeader(paymentPayload)["PAYMENT-SIGNATURE"];

  const second = await httpServer.processHTTPRequest(context);
  expect(second.type).toBe("payment-verified");
  const verified = second as {
    type: "payment-verified";
    paymentPayload: PaymentPayload;
    paymentRequirements: PaymentRequirements;
  };
  const beforeSettlement = structuredClone(verified.paymentPayload);
  const settled = settleAtMaximum
    ? await httpServer.processSettlement(verified.paymentPayload, verified.paymentRequirements)
    : await httpServer.processSettlement(
        verified.paymentPayload,
        verified.paymentRequirements,
        undefined,
        undefined,
        { amount: actualAmount },
      );
  expect(settled.success).toBe(recipientWalletResult.accepted);
  // Settlement never mutates the payer payload and never enriches it with a
  // server-owned field: the facilitator receives the original payload, and the
  // actual amount A travels only through the settlement-time requirements.
  expect(verified.paymentPayload).toEqual(beforeSettlement);
  expect(facilitatorClient.settlementPayloads).toHaveLength(1);
  expect(facilitatorClient.settlementPayloads[0]).toEqual(beforeSettlement);
  expect(facilitatorClient.settlementRequirements[0].amount).toBe(actualAmount);
  await httpClient.processPaymentResult(paymentPayload, name => settled.headers[name], 200);

  return {
    actualAmount,
    paymentRequiredHeader: requiredResponse.headers["PAYMENT-REQUIRED"],
    paymentSignature,
    paymentResponseHeader: settled.headers["PAYMENT-RESPONSE"],
    paymentPayload,
    facilitatorClient,
    deadline: control.deadline,
    httpClient,
    httpServer,
    context,
    admitFee,
    rejectFutureFees: () => {
      feeAdmitted = false;
    },
    prepareCapSources,
    recipientInternalize,
    payerInternalize,
    paymentResponseHook,
    settled,
  };
}

describe("BSV upto through the existing x402 HTTP flow", () => {
  it.each([1, 2] as const)(
    "uses one PaymentRequired plus one paid retry and returns terminal evidence (%i source pair)",
    async sourceCount => {
      const result = await exerciseHttpFlow(sourceCount);

      expect(result.prepareCapSources).toHaveBeenCalledTimes(1);
      expect(result.recipientInternalize).toHaveBeenCalledTimes(1);
      expect(result.payerInternalize).toHaveBeenCalledTimes(1);
      expect(result.paymentPayload.payload).not.toHaveProperty("settlementClaim");
      expect(result.facilitatorClient.settlementPayloads).toHaveLength(1);
      expect(result.facilitatorClient.settlementPayloads[0].payload).toEqual(
        result.paymentPayload.payload,
      );
      expect(result.settled).toMatchObject({
        success: true,
        amount: result.actualAmount,
        transaction: expect.stringMatching(/^[0-9a-f]{64}$/),
        extra: { settlementTransaction: expect.any(String) },
      });

      const lines = [
        ["PAYMENT-REQUIRED", result.paymentRequiredHeader],
        ["PAYMENT-SIGNATURE", result.paymentSignature],
        ["PAYMENT-RESPONSE", result.paymentResponseHeader],
      ] as const;
      for (const [name, value] of lines) {
        expect(value).toBeTruthy();
        expect(headerLineBytes(name, value!)).toBeLessThanOrEqual(HEADER_LINE_LIMIT);
      }
      expect(
        lines.reduce((total, [name, value]) => total + headerLineBytes(name, value!), 0),
      ).toBeLessThanOrEqual(HEADER_SET_LIMIT);
    },
  );

  it("settles A=M when the application omits SettlementOverrides", async () => {
    const result = await exerciseHttpFlow(1, true);

    expect(result.actualAmount).toBe("1000");
    expect(result.settled).toMatchObject({ success: true, amount: "1000" });
  });

  it("delivers selected failure evidence to the payer hook without a payer wallet effect", async () => {
    const result = await exerciseHttpFlow(1, false, { accepted: false });

    expect(result.settled).toMatchObject({
      success: false,
      transaction: "",
      amount: result.actualAmount,
      extra: { settlementTransaction: expect.any(String) },
      errorReason: "settlement_rejected_by_wallet",
    });
    expect(result.paymentResponseHeader).toBeTruthy();
    expect(result.paymentResponseHook).toHaveBeenCalledWith(
      expect.objectContaining({
        paymentPayload: result.paymentPayload,
        settleResponse: expect.objectContaining({
          success: false,
          transaction: "",
          amount: result.actualAmount,
          extra: { settlementTransaction: expect.any(String) },
        }),
      }),
    );
    expect(result.recipientInternalize).toHaveBeenCalledTimes(1);
    expect(result.payerInternalize).not.toHaveBeenCalled();
  });

  it("fails a later full paid retry closed after a selected wallet failure", async () => {
    const result = await exerciseHttpFlow(1, false, { accepted: false });
    expect(result.recipientInternalize).toHaveBeenCalledTimes(1);

    const retry = await result.httpServer.processHTTPRequest(result.context);

    expect(retry.type).toBe("payment-error");
    const response = (
      retry as {
        type: "payment-error";
        response: HTTPResponseInstructions;
      }
    ).response;
    expect(response.headers["PAYMENT-RESPONSE"]).toBeUndefined();
    expect(result.recipientInternalize).toHaveBeenCalledTimes(1);
    expect(result.prepareCapSources).toHaveBeenCalledTimes(1);
    expect(result.facilitatorClient.settlementPayloads).toHaveLength(1);
    expect(result.payerInternalize).not.toHaveBeenCalled();
  });

  it("fails a later full paid retry closed after a successful settlement", async () => {
    const result = await exerciseHttpFlow(1);

    const retry = await result.httpServer.processHTTPRequest(result.context);

    expect(retry.type).toBe("payment-error");
    const response = (
      retry as {
        type: "payment-error";
        response: HTTPResponseInstructions;
      }
    ).response;
    expect(response.headers["PAYMENT-RESPONSE"]).toBeUndefined();
    expect(result.admitFee).toHaveBeenCalledTimes(1);
    expect(result.recipientInternalize).toHaveBeenCalledTimes(1);
    expect(result.payerInternalize).toHaveBeenCalledTimes(1);
    expect(result.prepareCapSources).toHaveBeenCalledTimes(1);
    expect(result.facilitatorClient.settlementPayloads).toHaveLength(1);
  });
});
