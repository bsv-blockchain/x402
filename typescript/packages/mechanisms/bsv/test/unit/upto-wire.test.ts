import { PrivateKey, Utils } from "@bsv/sdk";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import { describe, expect, it } from "vitest";
import {
  snapshotPresentedUptoPayment,
  snapshotUptoRequirements,
} from "../../src/upto/internal/wire";

const payer = new PrivateKey(41).toPublicKey().toString();
const payTo = new PrivateKey(42).toPublicKey().toString();
const sourceTransaction = Utils.toBase64([1, 2, 3]);
const nonce = Utils.toBase64(new Array(32).fill(7));

function requirements(): PaymentRequirements {
  return {
    scheme: "upto",
    network: "bsv:testnet",
    asset: "BSV",
    amount: "700",
    payTo,
    maxTimeoutSeconds: 60,
    extra: {
      control: {
        inputs: [{ nonce, sourceTransaction, sourceOutputIndex: 0 }],
        validAfter: 1_800_000_000,
        deadline: 1_800_000_060,
      },
    },
  };
}

function payload(): PaymentPayload {
  return {
    x402Version: 2,
    accepted: requirements(),
    payload: {
      senderIdentityKey: payer,
      derivationPrefix: Utils.toBase64(Utils.toArray("prefix-upto", "utf8")),
      derivationSuffix: Utils.toBase64(Utils.toArray("1800000000000", "utf8")),
      capInputs: [
        {
          nonce: Utils.toBase64(new Array(32).fill(8)),
          sourceTransaction,
          sourceOutputIndex: 1,
          floorAmount: "100",
          transactionSignature: Utils.toBase64([48, 0]),
        },
      ],
      authorizationSignature: Utils.toBase64([48, 0]),
    },
  };
}

describe("BSV upto wire snapshot", () => {
  it("captures the advertised control offer and presented authorization", () => {
    const req = requirements();
    const accepted = snapshotUptoRequirements(req);
    const presented = snapshotPresentedUptoPayment(payload(), req, "verify");

    expect(accepted.control.inputs).toEqual([{ nonce, sourceTransaction, sourceOutputIndex: 0 }]);
    expect(presented.maximumAmount).toBe("700");
    expect(presented.actualAmount).toBe(700n);
    expect(presented.payload.capInputs[0].floorAmount).toBe("100");
  });

  it("returns a snapshot detached from later caller mutation", () => {
    const req = requirements();
    const accepted = snapshotUptoRequirements(req);
    const inputs = (
      req.extra.control as {
        inputs: { nonce: string; sourceTransaction: string; sourceOutputIndex: number }[];
      }
    ).inputs;
    inputs[0].nonce = Utils.toBase64(new Array(32).fill(9));
    inputs[0].sourceOutputIndex = 5;

    expect(accepted.control.inputs).toEqual([{ nonce, sourceTransaction, sourceOutputIndex: 0 }]);
  });

  it("allows a settlement amount below the accepted maximum but not above it", () => {
    const req = requirements();
    expect(
      snapshotPresentedUptoPayment(payload(), { ...req, amount: "300" }, "settle").actualAmount,
    ).toBe(300n);
    expect(() =>
      snapshotPresentedUptoPayment(payload(), { ...req, amount: "701" }, "settle"),
    ).toThrow(/exceeds maximum/);
    expect(() =>
      snapshotPresentedUptoPayment(payload(), { ...req, amount: "300" }, "verify"),
    ).toThrow(/verify amount/);
  });

  it("rejects a route whose signed terms differ from accepted", () => {
    const req = requirements();
    expect(() =>
      snapshotPresentedUptoPayment(payload(), { ...req, payTo: payer }, "verify"),
    ).toThrow(/accepted terms/);

    const changedControl = requirements();
    const control = changedControl.extra.control as {
      inputs: { nonce: string; sourceTransaction: string; sourceOutputIndex: number }[];
      validAfter: number;
      deadline: number;
    };
    control.inputs[0].sourceOutputIndex = 2;
    expect(() => snapshotPresentedUptoPayment(payload(), changedControl, "verify")).toThrow(
      /accepted control offer/,
    );
  });

  it.each([
    ["missing control", () => ({ ...requirements(), extra: {} })],
    ["wrong scheme", () => ({ ...requirements(), scheme: "exact" })],
    ["unknown network", () => ({ ...requirements(), network: "bip122:00" })],
    ["noncanonical amount", () => ({ ...requirements(), amount: "0700" })],
    [
      "expired-width window",
      () => {
        const req = requirements();
        return {
          ...req,
          extra: {
            control: {
              ...(req.extra.control as object),
              deadline: 1_800_000_061,
            },
          },
        };
      },
    ],
  ])("rejects %s before role-specific effects", (_label, build) => {
    expect(() => snapshotUptoRequirements(build() as PaymentRequirements)).toThrow();
  });
});
