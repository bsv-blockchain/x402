import { describe, expect, it } from "vitest";
import type { SettleContext } from "@x402/core/server";
import type { PaymentRequirements } from "@x402/core/types";
import { BSV_TESTNET_CAIP2 } from "../../src/constants";
import { ExactBsvScheme } from "../../src/exact/server/scheme";
import { UptoBsvScheme } from "../../src/upto/server/scheme";
import type { UptoBsvTransactionVersion } from "../../src/types";

const makeRequirements = (overrides: Partial<PaymentRequirements> = {}): PaymentRequirements => ({
  scheme: "upto",
  network: BSV_TESTNET_CAIP2,
  asset: "",
  amount: "1000",
  payTo: "02".padEnd(66, "a"),
  maxTimeoutSeconds: 300,
  extra: { keep: true },
  ...overrides,
});

const signedVersion: UptoBsvTransactionVersion = {
  authorizationId: "ab".repeat(32),
  transaction: "AQ==",
};

const makeScheme = (): UptoBsvScheme =>
  new UptoBsvScheme({ getTransactionVersion: () => signedVersion });

const makeSettleContext = (phase: SettleContext["phase"], amount = "750"): SettleContext => {
  const requirements = makeRequirements({ amount });
  return {
    paymentPayload: {
      x402Version: 2,
      accepted: requirements,
      payload: {
        authorization: { authorizationId: signedVersion.authorizationId },
      },
    },
    requirements,
    declaredExtensions: {},
    phase,
  };
};

describe("UptoBsvScheme (server)", () => {
  it("declares upto with the exact authorization flow", () => {
    const upto = makeScheme();
    const exact = new ExactBsvScheme();

    expect(upto.scheme).toBe("upto");
    expect(upto.defaultAssetTransferMethod).toBe(exact.defaultAssetTransferMethod);
    expect(upto.paymentFlows).toEqual({
      default: { supported: ["authorization"], default: "authorization" },
    });
  });

  it("uses the exact BSV price and asset semantics", async () => {
    const upto = makeScheme();
    const exact = new ExactBsvScheme();
    const price = { amount: "1000", asset: "bsv", extra: { note: "cap" } };

    await expect(upto.parsePrice(price, BSV_TESTNET_CAIP2)).resolves.toEqual(
      await exact.parsePrice(price, BSV_TESTNET_CAIP2),
    );
    await expect(
      upto.parsePrice({ amount: "1000", asset: "USDC" }, BSV_TESTNET_CAIP2),
    ).rejects.toThrow(/Unsupported asset/);
    await expect(upto.parsePrice("$0.10", BSV_TESTNET_CAIP2)).rejects.toThrow(
      /registerMoneyParser/,
    );
    expect(upto.getAssetDecimals("BSV", BSV_TESTNET_CAIP2)).toBe(
      exact.getAssetDecimals("BSV", BSV_TESTNET_CAIP2),
    );
  });

  it("supports a chainable exact-compatible money parser", async () => {
    const upto = makeScheme();
    const registered = upto
      .registerMoneyParser(async () => null)
      .registerMoneyParser(async (amount, network) => ({
        amount: String(Math.round(Number(amount) * 2000)),
        asset: "BSV",
        extra: { network },
      }));

    expect(registered).toBe(upto);
    await expect(upto.parsePrice(0.5, BSV_TESTNET_CAIP2)).resolves.toEqual({
      amount: "1000",
      asset: "BSV",
      extra: { network: BSV_TESTNET_CAIP2 },
    });
  });

  it("enhances with exact rules while preserving upto", async () => {
    const upto = makeScheme();
    const requirements = makeRequirements();
    const enhanced = await upto.enhancePaymentRequirements(
      requirements,
      {
        x402Version: 2,
        scheme: "upto",
        network: BSV_TESTNET_CAIP2,
        extra: { facilitator: "recipient" },
      },
      [],
    );

    expect(enhanced).toMatchObject({
      scheme: "upto",
      asset: "BSV",
      extra: { keep: true, facilitator: "recipient" },
    });
    expect(requirements).toMatchObject({ scheme: "upto", asset: "", extra: { keep: true } });
  });

  it("does not change exact scheme behavior", async () => {
    const exact = new ExactBsvScheme();
    const requirements = makeRequirements({ scheme: "exact" });
    const enhanced = await exact.enhancePaymentRequirements(
      requirements,
      { x402Version: 2, scheme: "exact", network: BSV_TESTNET_CAIP2 },
      [],
    );

    expect(exact.scheme).toBe("exact");
    expect(enhanced.scheme).toBe("exact");
    expect(enhanced.asset).toBe("BSV");
  });

  describe("settlement payload enrichment", () => {
    it("requires a transaction selector at construction", () => {
      expect(() => new UptoBsvScheme(undefined as never)).toThrow(/getTransactionVersion/);
    });

    it.each(["before-handler", "after-handler", "cancel"] as const)(
      "selects the signed transaction for the %s phase",
      async phase => {
        let receivedContext: SettleContext | undefined;
        const upto = new UptoBsvScheme({
          getTransactionVersion: context => {
            receivedContext = context;
            return signedVersion;
          },
        });
        const context = makeSettleContext(phase);

        await expect(upto.enrichSettlementPayload(context)).resolves.toEqual({
          transactionVersion: signedVersion,
        });
        expect(receivedContext).toBe(context);
      },
    );

    it("fails explicitly when the configured selector has no signed transaction", async () => {
      const upto = new UptoBsvScheme({
        getTransactionVersion: async () => undefined as unknown as UptoBsvTransactionVersion,
      });

      await expect(
        upto.enrichSettlementPayload(makeSettleContext("after-handler")),
      ).rejects.toThrow(
        "No signed BSV upto transaction version is available for after-handler settlement",
      );
    });
  });
});
