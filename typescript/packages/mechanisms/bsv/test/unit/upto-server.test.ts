import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import { describe, expect, it, vi } from "vitest";
import {
  InMemoryAuthorizationStore,
  type AuthorizationStore,
} from "../../src/upto/server/authorizationStore";
import { UptoBsvScheme } from "../../src/upto/server/scheme";

const authorizationId = "ab".repeat(32);
const payer = `02${"11".repeat(32)}`;
const payTo = `03${"22".repeat(32)}`;

function requirements(amount = "700"): PaymentRequirements {
  return {
    scheme: "upto",
    network: "bsv:testnet",
    asset: "BSV",
    amount,
    payTo,
    maxTimeoutSeconds: 60,
    extra: {},
  };
}

function payload(): PaymentPayload {
  return {
    x402Version: 2,
    accepted: requirements(),
    payload: {},
  };
}

function receipt() {
  return {
    bsvUptoAuthorization: {
      authorizationId,
      maximumAmount: "700",
      validAfter: 1_800_000_000,
      deadline: 1_800_000_060,
      outpoints: [`${"01".repeat(32)}:0`, `${"02".repeat(32)}:1`],
    },
  };
}

function makeScheme(
  authorizationStore: AuthorizationStore = new InMemoryAuthorizationStore(),
): UptoBsvScheme {
  return new UptoBsvScheme({ authorizationStore });
}

describe("BSV upto resource-server scheme", () => {
  it("requires an explicit authorization store", () => {
    expect(
      () =>
        new UptoBsvScheme({
          authorizationStore: undefined as unknown as AuthorizationStore,
        }),
    ).toThrow(/authorization store/);
  });

  it("inherits exact price parsing without changing exact", async () => {
    const scheme = makeScheme();
    await expect(
      scheme.parsePrice({ amount: "700", asset: "BSV" }, "bsv:testnet"),
    ).resolves.toEqual({ amount: "700", asset: "BSV", extra: {} });
    expect(scheme.scheme).toBe("upto");
    expect(scheme.paymentFlows.default).toEqual({
      supported: ["authorization"],
      default: "authorization",
    });
  });

  it("rejects a malformed control offer before advertising the requirement", async () => {
    const scheme = makeScheme();

    await expect(
      scheme.enhancePaymentRequirements(
        requirements(),
        { x402Version: 2, scheme: "upto", network: "bsv:testnet" },
        [],
      ),
    ).rejects.toThrow(/extra\.control/);
  });

  it("admits only a verified authorization and binds A once", async () => {
    const store = new InMemoryAuthorizationStore(() => 1_800_000_001);
    const scheme = makeScheme(store);
    const payment = payload();
    const afterVerify = scheme.schemeHooks?.onAfterVerify;
    const beforeSettle = scheme.schemeHooks?.onBeforeSettle;
    if (!afterVerify || !beforeSettle) throw new Error("hooks missing");

    await expect(
      afterVerify({
        paymentPayload: payment,
        requirements: requirements(),
        declaredExtensions: {},
        result: { isValid: true, payer, extra: receipt() },
      }),
    ).resolves.toBeUndefined();
    await expect(
      beforeSettle({
        paymentPayload: payment,
        requirements: requirements("300"),
        declaredExtensions: {},
        phase: "after-handler",
      }),
    ).resolves.toBeUndefined();
  });

  it("fails settlement when handler latency crosses the store-owned deadline", async () => {
    let now = 1_800_000_001;
    const store = new InMemoryAuthorizationStore(() => now);
    const scheme = makeScheme(store);
    const payment = payload();
    const afterVerify = scheme.schemeHooks?.onAfterVerify;
    const beforeSettle = scheme.schemeHooks?.onBeforeSettle;
    if (!afterVerify || !beforeSettle) throw new Error("hooks missing");

    await expect(
      afterVerify({
        paymentPayload: payment,
        requirements: requirements(),
        declaredExtensions: {},
        result: { isValid: true, payer, extra: receipt() },
      }),
    ).resolves.toBeUndefined();

    now = 1_800_000_060;
    await expect(
      beforeSettle({
        paymentPayload: payment,
        requirements: requirements("300"),
        declaredExtensions: {},
        phase: "after-handler",
      }),
    ).resolves.toEqual({ abort: true, reason: "upto_bsv_authorization_out_of_window" });
  });

  it("does not bind an actual amount before the protected handler completes", async () => {
    const store = new InMemoryAuthorizationStore(() => 1_800_000_001);
    const bindActualAmount = vi.spyOn(store, "bindActualAmount");
    const scheme = makeScheme(store);
    const payment = payload();
    const afterVerify = scheme.schemeHooks?.onAfterVerify;
    const beforeSettle = scheme.schemeHooks?.onBeforeSettle;
    if (!afterVerify || !beforeSettle) throw new Error("hooks missing");

    await afterVerify({
      paymentPayload: payment,
      requirements: requirements(),
      declaredExtensions: {},
      result: { isValid: true, payer, extra: receipt() },
    });

    for (const phase of ["before-handler", "cancel"] as const) {
      await expect(
        beforeSettle({
          paymentPayload: payment,
          requirements: requirements("300"),
          declaredExtensions: {},
          phase,
        }),
      ).resolves.toEqual({
        abort: true,
        reason: "upto_bsv_settlement_requires_after_handler",
      });
    }
    expect(bindActualAmount).not.toHaveBeenCalled();
  });

  it("does not admit failed verification and rejects expired or unbound settlement", async () => {
    const store: AuthorizationStore = {
      admit: vi.fn().mockResolvedValue({ kind: "out_of_window" }),
      bindActualAmount: vi.fn(),
    };
    const scheme = makeScheme(store);
    const payment = payload();
    const afterVerify = scheme.schemeHooks?.onAfterVerify;
    const beforeSettle = scheme.schemeHooks?.onBeforeSettle;
    if (!afterVerify || !beforeSettle) throw new Error("hooks missing");

    await expect(
      afterVerify({
        paymentPayload: payment,
        requirements: requirements(),
        declaredExtensions: {},
        result: { isValid: false, invalidReason: "bad" },
      }),
    ).resolves.toBeUndefined();
    expect(store.admit).not.toHaveBeenCalled();

    await expect(
      afterVerify({
        paymentPayload: payment,
        requirements: requirements(),
        declaredExtensions: {},
        result: { isValid: true, payer, extra: receipt() },
      }),
    ).resolves.toEqual({ abort: true, reason: "upto_bsv_authorization_out_of_window" });
    await expect(
      beforeSettle({
        paymentPayload: payment,
        requirements: requirements("300"),
        declaredExtensions: {},
        phase: "after-handler",
      }),
    ).resolves.toEqual(expect.objectContaining({ abort: true }));
  });

  it("fails a fresh verification closed after the authorization was admitted", async () => {
    const store = new InMemoryAuthorizationStore(() => 1_800_000_001);
    const scheme = makeScheme(store);
    const afterVerify = scheme.schemeHooks?.onAfterVerify;
    if (!afterVerify) throw new Error("hook missing");

    await expect(
      afterVerify({
        paymentPayload: payload(),
        requirements: requirements(),
        declaredExtensions: {},
        result: { isValid: true, payer, extra: receipt() },
      }),
    ).resolves.toBeUndefined();
    await expect(
      afterVerify({
        paymentPayload: payload(),
        requirements: requirements(),
        declaredExtensions: {},
        result: { isValid: true, payer, extra: receipt() },
      }),
    ).resolves.toEqual({ abort: true, reason: "upto_bsv_authorization_already_in_use" });
  });

  it("fails closed when admission or amount binding is unavailable", async () => {
    const store: AuthorizationStore = {
      admit: vi.fn().mockResolvedValue({ kind: "unavailable" }),
      bindActualAmount: vi.fn().mockResolvedValue({ kind: "unavailable" }),
    };
    const scheme = makeScheme(store);
    const afterVerify = scheme.schemeHooks?.onAfterVerify;
    if (!afterVerify) throw new Error("hook missing");
    await expect(
      afterVerify({
        paymentPayload: payload(),
        requirements: requirements(),
        declaredExtensions: {},
        result: { isValid: true, payer, extra: receipt() },
      }),
    ).resolves.toEqual(expect.objectContaining({ abort: true }));
  });
});
