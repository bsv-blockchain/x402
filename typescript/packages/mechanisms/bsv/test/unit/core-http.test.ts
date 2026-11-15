import { describe, expect, it, vi } from "vitest";
import { Beef, PrivateKey, ProtoWallet, Script, Transaction } from "@bsv/sdk";
import type { WalletInterface } from "@bsv/sdk";
import { x402Client } from "@x402/core/client";
import { x402Facilitator } from "@x402/core/facilitator";
import { x402ResourceServer } from "@x402/core/server";
import type { SupportedResponse } from "@x402/core/types";
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import { PaymentPayloadV2Schema, PaymentRequiredV2Schema } from "@x402/core/schemas";
import { ExactBsvScheme as Client } from "../../src/exact/client/scheme";
import { ExactBsvScheme as Facilitator } from "../../src/exact/facilitator/scheme";
import { ExactBsvScheme as Server } from "../../src/exact/server/scheme";
import { BSV_TESTNET_CAIP2 } from "../../src/constants";

describe("BSV exact core and HTTP compatibility", () => {
  it("round-trips a synthetic Atomic BEEF payment and rejects settlement replay", async () => {
    // Fixed fixture keys and an unfunded transaction; no RPC, signing or broadcast.
    const payer = new ProtoWallet(new PrivateKey(1));
    const recipient = new ProtoWallet(new PrivateKey(2));
    const { publicKey: payTo } = await recipient.getPublicKey({ identityKey: true });
    let subject: Transaction | undefined;
    const createAction = vi.fn<WalletInterface["createAction"]>().mockImplementation(async args => {
      subject = new Transaction();
      subject.addInput({
        sourceTXID: "00".repeat(32),
        sourceOutputIndex: 0xffffffff,
        unlockingScript: Script.fromHex("00"),
        sequence: 0xffffffff,
      });
      for (const output of args.outputs ?? []) {
        subject.addOutput({
          satoshis: output.satoshis,
          lockingScript: Script.fromHex(output.lockingScript),
        });
      }
      const beef = new Beef();
      beef.mergeTransaction(subject);
      return { tx: beef.toBinaryAtomic(subject.id("hex")), txid: subject.id("hex") };
    });
    const internalizeAction = vi
      .fn<WalletInterface["internalizeAction"]>()
      .mockResolvedValue({ accepted: true });
    const payerWallet: Partial<WalletInterface> = {
      getPublicKey: payer.getPublicKey.bind(payer),
      createAction,
    };
    const recipientWallet: Partial<WalletInterface> = {
      getPublicKey: recipient.getPublicKey.bind(recipient),
      getNetwork: async () => ({ network: "testnet" as const }),
      internalizeAction,
    };
    const facilitator = new x402Facilitator().register(
      BSV_TESTNET_CAIP2,
      new Facilitator({ wallet: recipientWallet as WalletInterface, identityKey: payTo }),
    );
    const server = new x402ResourceServer({
      getSupported: async () => facilitator.getSupported() as SupportedResponse,
      verify: (payload, requirements) => facilitator.verify(payload, requirements),
      settle: (payload, requirements) => facilitator.settle(payload, requirements),
    }).register("bsv:*", new Server());
    await server.initialize();
    const requirements = await server.buildPaymentRequirements({
      scheme: "exact",
      network: BSV_TESTNET_CAIP2,
      price: { amount: "1000", asset: "BSV" },
      payTo,
    });
    const required = decodePaymentRequiredHeader(
      encodePaymentRequiredHeader(
        await server.createPaymentRequiredResponse(requirements, {
          url: "https://fixture.invalid",
        }),
      ),
    );
    expect(PaymentRequiredV2Schema.safeParse(required).success).toBe(true);
    expect(required.accepts[0]).toMatchObject({ amount: "1000", asset: "BSV", extra: {} });
    const client = new x402Client().register("bsv:*", new Client(payerWallet as WalletInterface));
    await expect(client.createPaymentPayload(required)).rejects.toThrow(/spendControls/);
    expect(createAction).not.toHaveBeenCalled();
    client.setSpendControls({
      allowedAssets: [{ network: "bsv:*", asset: "BSV", maxAmountPerPayment: "999" }],
    });
    await expect(client.createPaymentPayload(required)).rejects.toThrow(/maxAmountPerPayment/);
    expect(createAction).not.toHaveBeenCalled();
    client.setSpendControls({
      allowedAssets: [{ network: "bsv:*", asset: "BSV", maxAmountPerPayment: "1000" }],
    });
    const payload = decodePaymentSignatureHeader(
      encodePaymentSignatureHeader(await client.createPaymentPayload(required)),
    );
    expect(PaymentPayloadV2Schema.safeParse(payload).success).toBe(true);
    expect(await server.verifyPayment(payload, requirements[0])).toMatchObject({ isValid: true });
    const result = decodePaymentResponseHeader(
      encodePaymentResponseHeader(await server.settlePayment(payload, requirements[0])),
    );
    expect(result).toMatchObject({
      success: true,
      transaction: subject!.id("hex"),
      network: BSV_TESTNET_CAIP2,
    });
    expect(await facilitator.settle(payload, requirements[0])).toMatchObject({
      success: false,
      transaction: "",
      errorReason: "duplicate_settlement",
    });
    expect(createAction).toHaveBeenCalledOnce();
    expect(internalizeAction).toHaveBeenCalledOnce();
  });
});
