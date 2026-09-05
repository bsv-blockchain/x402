import { readFile } from "node:fs/promises";
import { HTTPWalletJSON, Transaction, Utils, WalletClient, WhatsOnChain } from "@bsv/sdk";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { x402Facilitator } from "@x402/core/facilitator";
import { x402HTTPResourceServer, x402ResourceServer, type HTTPAdapter } from "@x402/core/server";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { UptoBsvCapSource, UptoBsvSourceReference } from "../../src";
import { BSV_TESTNET_CAIP2 } from "../../src/constants";
import { ExactBsvScheme as ExactBsvClient } from "../../src/exact/client";
import { ExactBsvScheme as ExactBsvFacilitator } from "../../src/exact/facilitator";
import { ExactBsvScheme as ExactBsvServer } from "../../src/exact/server";
import { UptoBsvScheme as UptoBsvClient } from "../../src/upto/client";
import {
  InMemoryTerminalStore,
  UptoBsvScheme as UptoBsvFacilitator,
} from "../../src/upto/facilitator";
import { InMemoryAuthorizationStore, UptoBsvScheme as UptoBsvServer } from "../../src/upto/server";

interface LiveFixture {
  network: typeof BSV_TESTNET_CAIP2;
  payerIdentityKey: string;
  recipientIdentityKey: string;
  maximumAmount: string;
  actualAmount: string;
  terminalFee: string;
  exactAmount: string;
  controlInputs: UptoBsvSourceReference[];
  capSources: UptoBsvCapSource[];
}

const fixturePath = process.env.BSV_UPTO_FIXTURE_FILE;
const payerUrl = process.env.BSV_PAYER_WALLET_URL;
const recipientUrl = process.env.BSV_RECIPIENT_WALLET_URL;
const enabled =
  process.env.BSV_UPTO_INTEGRATION === "true" && !!fixturePath && !!payerUrl && !!recipientUrl;
const originator = process.env.BSV_UPTO_ORIGINATOR ?? "x402-bsv-upto-integration.test";

// Opt-in spends real testnet funds. See README.md for source reservation and wallet prerequisites.
describe.skipIf(!enabled)("BSV exact and upto with two live wallets", () => {
  let fixture: LiveFixture;
  let payer: WalletClient;
  let recipient: WalletClient;

  beforeAll(async () => {
    // The fixture is operator-owned test configuration. The schemes independently
    // validate every source, signature, amount and BEEF supplied from it.
    fixture = JSON.parse(await readFile(fixturePath!, "utf8")) as LiveFixture;
    expect(fixture.network).toBe(BSV_TESTNET_CAIP2);
    for (const amount of [
      fixture.maximumAmount,
      fixture.actualAmount,
      fixture.terminalFee,
      fixture.exactAmount,
    ]) {
      expect(amount).toMatch(/^[1-9]\d*$/);
      expect(BigInt(amount)).toBeLessThanOrEqual(BigInt(Number.MAX_SAFE_INTEGER));
    }
    expect(BigInt(fixture.actualAmount)).toBeLessThan(BigInt(fixture.maximumAmount));
    expect(fixture.capSources.length).toBeGreaterThan(0);
    expect(fixture.controlInputs.length).toBeGreaterThan(0);

    payer = new WalletClient(new HTTPWalletJSON(originator, payerUrl!), originator);
    recipient = new WalletClient(new HTTPWalletJSON(originator, recipientUrl!), originator);
    const [payerKey, recipientKey, payerNetwork, recipientNetwork] = await Promise.all([
      payer.getPublicKey({ identityKey: true }),
      recipient.getPublicKey({ identityKey: true }),
      payer.getNetwork({}),
      recipient.getNetwork({}),
    ]);
    expect(payerNetwork.network).toBe("testnet");
    expect(recipientNetwork.network).toBe("testnet");
    expect(payerKey.publicKey.toLowerCase()).toBe(fixture.payerIdentityKey.toLowerCase());
    expect(recipientKey.publicKey.toLowerCase()).toBe(fixture.recipientIdentityKey.toLowerCase());
    expect(payerKey.publicKey.toLowerCase()).not.toBe(recipientKey.publicKey.toLowerCase());
  }, 60_000);

  it("returns one upto terminal to both wallets and also settles exact through the same roles", async () => {
    const chainTracker = new WhatsOnChain("test");
    const sourcePolicy = { maxSources: 8, maxAtomicBeefBytesPerSource: 256 * 1024 };
    const terminalPolicy = { maxAtomicBeefBytes: 1024 * 1024 };
    const fee = BigInt(fixture.terminalFee);
    const recipientInternalize = vi.spyOn(recipient, "internalizeAction");
    const payerInternalize = vi.spyOn(payer, "internalizeAction");
    const uptoFacilitator = await UptoBsvFacilitator.create({
      wallet: recipient,
      chainTracker,
      sourcePolicy,
      terminalPolicy,
      terminalStore: new InMemoryTerminalStore(),
      originator,
      admitFee: ({ feeHeadroom }) => feeHeadroom >= fee,
      planTerminal: context => {
        const refund = context.exposure - context.actualAmount - fee;
        return {
          recipientAmounts: [Number(context.actualAmount + context.controlInputTotal)],
          refundAmounts: refund === 0n ? [] : [Number(refund)],
        };
      },
    });
    const facilitator = new x402Facilitator()
      .register(BSV_TESTNET_CAIP2, uptoFacilitator)
      .register(BSV_TESTNET_CAIP2, await ExactBsvFacilitator.create({ wallet: recipient }));
    const server = new x402ResourceServer({
      verify: facilitator.verify.bind(facilitator),
      settle: facilitator.settle.bind(facilitator),
      getSupported: async () => {
        const supported = facilitator.getSupported();
        return {
          ...supported,
          kinds: supported.kinds.map(kind => {
            expect(kind.network).toBe(BSV_TESTNET_CAIP2);
            return { ...kind, network: BSV_TESTNET_CAIP2 };
          }),
        };
      },
    })
      .register(BSV_TESTNET_CAIP2, new ExactBsvServer())
      .register(
        BSV_TESTNET_CAIP2,
        new UptoBsvServer({ authorizationStore: new InMemoryAuthorizationStore() }),
      );
    await server.initialize();

    const now = Math.floor(Date.now() / 1000);
    const httpServer = new x402HTTPResourceServer(server, {
      "/upto": {
        accepts: {
          scheme: "upto",
          network: BSV_TESTNET_CAIP2,
          payTo: fixture.recipientIdentityKey,
          price: { amount: fixture.maximumAmount, asset: "BSV" },
          maxTimeoutSeconds: 300,
          extra: {
            paymentFlow: "authorization",
            control: { inputs: fixture.controlInputs, validAfter: now, deadline: now + 300 },
          },
        },
      },
      "/exact": {
        accepts: {
          scheme: "exact",
          network: BSV_TESTNET_CAIP2,
          payTo: fixture.recipientIdentityKey,
          price: { amount: fixture.exactAmount, asset: "BSV" },
          maxTimeoutSeconds: 300,
        },
      },
    });
    const client = x402Client.fromConfig({
      schemes: [
        { network: BSV_TESTNET_CAIP2, client: new ExactBsvClient(payer) },
        {
          network: BSV_TESTNET_CAIP2,
          client: new UptoBsvClient(payer, {
            capSourceProvider: { prepareCapSources: async () => fixture.capSources },
            chainTracker,
            sourcePolicy,
            terminalPolicy,
            originator,
          }),
        },
      ],
      spendControls: false,
    });
    const httpClient = new x402HTTPClient(client);

    async function pay(path: "/upto" | "/exact", actualAmount?: string) {
      let paymentSignature: string | undefined;
      const adapter: HTTPAdapter = {
        getHeader: name => (name === "PAYMENT-SIGNATURE" ? paymentSignature : undefined),
        getMethod: () => "GET",
        getPath: () => path,
        getUrl: () => `https://x402-bsv-integration.test${path}`,
        getAcceptHeader: () => "application/json",
        getUserAgent: () => "x402-bsv-live-integration",
      };
      const context = { adapter, path, method: "GET" };
      const initial = await httpServer.processHTTPRequest(context);
      if (initial.type !== "payment-error") throw new Error("Expected PaymentRequired");
      const required = httpClient.getPaymentRequiredResponse(
        name => initial.response.headers[name],
        initial.response.body,
      );
      const payload = await httpClient.createPaymentPayload(required);
      paymentSignature = httpClient.encodePaymentSignatureHeader(payload)["PAYMENT-SIGNATURE"];
      const paid = await httpServer.processHTTPRequest(context);
      if (paid.type !== "payment-verified") throw new Error("Paid request was not verified");

      // Respect the existing scheme flow: exact may already settle before the
      // handler; upto binds the measured amount after this protected execution.
      let headers: Record<string, string>;
      if (paid.beforeHandlerSettlement) {
        expect(path).toBe("/exact");
        headers = httpServer.createCompletedSettlementHeaders(paid.beforeHandlerSettlement);
      } else {
        const settled = await httpServer.processSettlement(
          paid.paymentPayload,
          paid.paymentRequirements,
          undefined,
          undefined,
          actualAmount === undefined ? undefined : { amount: actualAmount },
        );
        expect(settled.success, settled.errorReason).toBe(true);
        headers = settled.headers;
      }
      const received = await httpClient.processPaymentResult(payload, name => headers[name], 200);
      expect(received.settleResponse?.success).toBe(true);
      return {
        payload,
        requirements: paid.paymentRequirements,
        headers,
        response: received.settleResponse!,
      };
    }

    try {
      const upto = await pay("/upto", fixture.actualAmount);
      expect(upto.payload.accepted.amount).toBe(fixture.maximumAmount);
      expect(upto.response.amount).toBe(fixture.actualAmount);
      const evidence = upto.response.extra?.settlementTransaction;
      expect(typeof evidence).toBe("string");
      const terminal = Transaction.fromAtomicBEEF(Utils.toArray(evidence as string, "base64"));
      expect(terminal.id("hex")).toBe(upto.response.transaction);
      expect(await terminal.verify(chainTracker)).toBe(true);
      expect(terminal.inputs).toHaveLength(
        fixture.capSources.length + fixture.controlInputs.length,
      );
      expect(terminal.inputs.every(input => input.sequence === 0xffffffff)).toBe(true);
      const capTotal = sourceTotal(fixture.capSources);
      const controlTotal = sourceTotal(fixture.controlInputs);
      const outputTotal = terminal.outputs.reduce(
        (sum, output) => sum + BigInt(output.satoshis!),
        0n,
      );
      expect(capTotal + controlTotal - outputTotal).toBe(fee);
      const recipientIndex = fixture.capSources.length;
      expect(BigInt(terminal.outputs[recipientIndex].satoshis!) - controlTotal).toBe(
        BigInt(fixture.actualAmount),
      );
      const payerIndices = terminal.outputs
        .map((_, index) => index)
        .filter(index => index !== recipientIndex);
      const payerTotal = payerIndices.reduce(
        (sum, index) => sum + BigInt(terminal.outputs[index].satoshis!),
        0n,
      );
      expect(capTotal - payerTotal).toBe(BigInt(fixture.actualAmount) + fee);
      expect(recipientInternalize).toHaveBeenCalledTimes(1);
      expect(payerInternalize).toHaveBeenCalledTimes(1);
      await expect(recipientInternalize.mock.results[0].value).resolves.toMatchObject({
        accepted: true,
      });
      await expect(payerInternalize.mock.results[0].value).resolves.toMatchObject({
        accepted: true,
      });
      expect(
        recipientInternalize.mock.calls[0][0].outputs.map(output => output.outputIndex),
      ).toEqual([recipientIndex]);
      expect(payerInternalize.mock.calls[0][0].outputs.map(output => output.outputIndex)).toEqual(
        payerIndices,
      );
      for (const call of [recipientInternalize.mock.calls[0], payerInternalize.mock.calls[0]]) {
        expect(Transaction.fromAtomicBEEF(call[0].tx).toHex()).toBe(terminal.toHex());
      }

      const replay = await facilitator.settle(upto.payload, {
        ...upto.requirements,
        amount: fixture.actualAmount,
      });
      expect(replay.success).toBe(true);
      expect(replay.transaction).toBe(upto.response.transaction);
      expect(replay.amount).toBe(fixture.actualAmount);
      await httpClient.processPaymentResult(upto.payload, name => upto.headers[name], 200);
      expect(recipientInternalize).toHaveBeenCalledTimes(1);
      expect(payerInternalize).toHaveBeenCalledTimes(1);

      const exact = await pay("/exact");
      expect(exact.payload.accepted.amount).toBe(fixture.exactAmount);
      expect(exact.response.transaction).toMatch(/^[0-9a-f]{64}$/);
      expect(exact.response.transaction).not.toBe(upto.response.transaction);
      expect(recipientInternalize).toHaveBeenCalledTimes(2);
    } finally {
      recipientInternalize.mockRestore();
      payerInternalize.mockRestore();
    }
  }, 240_000);
});

function sourceTotal(sources: readonly UptoBsvSourceReference[]): bigint {
  return sources.reduce((sum, source) => {
    const transaction = Transaction.fromAtomicBEEF(
      Utils.toArray(source.sourceTransaction, "base64"),
    );
    return sum + BigInt(transaction.outputs[source.sourceOutputIndex].satoshis!);
  }, 0n);
}
