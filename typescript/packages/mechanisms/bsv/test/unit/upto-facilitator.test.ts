import { MerklePath, Transaction, Utils, type ChainTracker, type WalletInterface } from "@bsv/sdk";
import type { PaymentPayload } from "@x402/core/types";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { validateAndDigestAuthorization } from "../../src/upto/internal/authorization";
import { createCapAuthorization } from "../../src/upto/internal/transaction";
import { deriveUptoSourcePublicKey } from "../../src/upto/internal/keys";
import { createSourceAdmitter } from "../../src/upto/internal/source";
import {
  InMemoryTerminalStore,
  type TerminalStore,
} from "../../src/upto/facilitator/terminalStore";
import {
  UptoBsvScheme,
  type UptoBsvFeeAdmissionContext,
  type UptoBsvTerminalPlanContext,
} from "../../src/upto/facilitator/scheme";
import {
  admitAuthorizationFixture,
  buildAuthorizationFixture,
  buildAncestralConflictFixture,
  type AdmittedAuthorizationFixture,
} from "./upto-authorization-fixtures";

const NOW_SECONDS = 1_800_000_030;
const VALID_AFTER = 1_800_000_000;
const DEADLINE = 1_800_000_060;

interface FacilitatorFixture extends AdmittedAuthorizationFixture {
  payload: PaymentPayload;
  authorizationId: string;
  wallet: WalletInterface;
  internalizeAction: ReturnType<typeof vi.fn>;
  planner: ReturnType<typeof vi.fn>;
}

async function makeFixture(options: { capCount?: number; controlCount?: number } = {}) {
  const capCount = options.capCount ?? 1;
  const controlCount = options.controlCount ?? 1;
  const fixture = await admitAuthorizationFixture(
    await buildAuthorizationFixture({
      capCount,
      controlCount,
      nowSeconds: NOW_SECONDS,
      validAfter: VALID_AFTER,
      deadline: DEADLINE,
    }),
  );
  const { payer, recipient, facts, capInputs, controlInputs } = fixture;
  const signatures = await createCapAuthorization({
    facts,
    capInputs,
    controlInputs,
    wallet: payer,
  });
  const payload: PaymentPayload = {
    x402Version: 2,
    accepted: structuredClone(fixture.requirements),
    payload: {
      senderIdentityKey: fixture.payerIdentity,
      derivationPrefix: facts.derivationPrefix,
      derivationSuffix: facts.derivationSuffix,
      capInputs: capInputs.map((source, index) => ({
        ...fixture.capSources[index],
        sourceOutputIndex: source.sourceOutputIndex,
        transactionSignature: signatures.transactionSignatures[index],
      })),
      authorizationSignature: signatures.authorizationSignature,
    },
  };
  const internalizeAction = vi.fn().mockResolvedValue({ accepted: true, satoshis: 610 });
  const wallet = {
    getPublicKey: recipient.getPublicKey.bind(recipient),
    createSignature: recipient.createSignature.bind(recipient),
    getNetwork: vi.fn().mockResolvedValue({ network: "testnet" }),
    internalizeAction,
  } as unknown as WalletInterface;
  const planner = vi
    .fn()
    .mockResolvedValue(
      capCount === 1
        ? { recipientAmounts: [610], refundAmounts: [495] }
        : { recipientAmounts: [410, 410], refundAmounts: [250, 255] },
    );
  return {
    ...fixture,
    payload,
    authorizationId: Utils.toHex(validateAndDigestAuthorization(facts).digest),
    wallet,
    internalizeAction,
    planner,
  } satisfies FacilitatorFixture;
}

function makeScheme(value: FacilitatorFixture, overrides: Record<string, unknown> = {}) {
  return new UptoBsvScheme({
    wallet: value.wallet,
    identityKey: value.payTo,
    chainTracker: value.tracker,
    sourcePolicy: { maxSources: 8, maxAtomicBeefBytesPerSource: 16_384 },
    terminalPolicy: { maxAtomicBeefBytes: 65_536 },
    terminalStore: new InMemoryTerminalStore(),
    planTerminal: value.planner,
    ...overrides,
  });
}

function reproveAtomicSource(sourceTransaction: string, proofHeight: number): string {
  const subject = Transaction.fromAtomicBEEF(Utils.toArray(sourceTransaction, "base64"));
  const parent = subject.inputs[0]?.sourceTransaction;
  if (parent === undefined) throw new Error("source fixture parent is missing");
  parent.merklePath = MerklePath.fromCoinbaseTxidAndHeight(parent.id("hex"), proofHeight);
  return Utils.toBase64(subject.toAtomicBEEF());
}

describe("BSV upto facilitator", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW_SECONDS * 1000);
  });

  it("verifies the wire authorization and returns only verified receipt facts", async () => {
    const value = await makeFixture();
    const admitFee = vi.fn().mockResolvedValue(true);
    const scheme = makeScheme(value, { admitFee });

    const result = await scheme.verify(value.payload, value.requirements);

    expect(result).toEqual({
      isValid: true,
      payer: value.payerIdentity,
      extra: {
        bsvUptoAuthorization: {
          authorizationId: value.authorizationId,
          maximumAmount: "1000",
          validAfter: VALID_AFTER,
          deadline: DEADLINE,
          outpoints: expect.arrayContaining([expect.stringMatching(/^[0-9a-f]{64}:0$/)]),
        },
      },
    });
    expect((result.extra?.bsvUptoAuthorization as { outpoints: string[] }).outpoints).toHaveLength(
      2,
    );
    expect(admitFee).toHaveBeenCalledWith(
      expect.objectContaining({
        authorizationId: value.authorizationId,
        maximumAmount: 1000n,
        exposure: 1100n,
        feeHeadroom: 100n,
      } satisfies Partial<UptoBsvFeeAdmissionContext>),
    );
    expect(value.planner).not.toHaveBeenCalled();
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("rejects signed authorization whose control ancestry already spends the cap output", async () => {
    const fixture = await buildAncestralConflictFixture();
    const sourcePolicy = { maxSources: 8, maxAtomicBeefBytesPerSource: 16_384 };
    const admit = createSourceAdmitter({ chainTracker: fixture.tracker, policy: sourcePolicy });
    const cap = fixture.capSources[0];
    const control = fixture.controlOffer.inputs[0];
    // An adversarial payer can sign individually valid sources without checking
    // whether their joint spend is possible. Facilitator admission must reject it.
    const capInputs = await admit([
      {
        ...cap,
        role: "cap",
        publicKey: await deriveUptoSourcePublicKey("cap", cap.nonce, fixture.payerIdentity),
      },
    ]);
    const controlInputs = await admit([
      {
        ...control,
        role: "control",
        publicKey: await deriveUptoSourcePublicKey("control", control.nonce, fixture.payTo),
      },
    ]);
    const signatures = await createCapAuthorization({
      facts: fixture.facts,
      capInputs,
      controlInputs,
      wallet: fixture.payer,
    });
    const payload: PaymentPayload = {
      x402Version: 2,
      accepted: fixture.requirements,
      payload: {
        senderIdentityKey: fixture.payerIdentity,
        derivationPrefix: fixture.facts.derivationPrefix,
        derivationSuffix: fixture.facts.derivationSuffix,
        capInputs: [{ ...cap, transactionSignature: signatures.transactionSignatures[0] }],
        authorizationSignature: signatures.authorizationSignature,
      },
    };
    const internalizeAction = vi.fn().mockResolvedValue({ accepted: true });
    const planner = vi.fn();
    const wallet = {
      getPublicKey: fixture.recipient.getPublicKey.bind(fixture.recipient),
      createSignature: fixture.recipient.createSignature.bind(fixture.recipient),
      getNetwork: async () => ({ network: "testnet" }),
      internalizeAction,
    } as unknown as WalletInterface;
    const scheme = new UptoBsvScheme({
      wallet,
      identityKey: fixture.payTo,
      chainTracker: fixture.tracker,
      sourcePolicy,
      terminalPolicy: { maxAtomicBeefBytes: 65_536 },
      terminalStore: new InMemoryTerminalStore(),
      planTerminal: planner,
    });

    const result = await scheme.verify(payload, fixture.requirements);
    expect(result.isValid).toBe(false);
    expect(result.invalidMessage).toMatch(/selected source outpoint is already spent/);
    expect(result.extra).toBeUndefined();
    expect(planner).not.toHaveBeenCalled();
    expect(internalizeAction).not.toHaveBeenCalled();
  });

  it("rejects accepted/requirements drift and fee policy before settlement effects", async () => {
    const value = await makeFixture();
    const drifted = structuredClone(value.requirements);
    drifted.amount = "999";
    const scheme = makeScheme(value);
    await expect(scheme.verify(value.payload, drifted)).resolves.toMatchObject({
      isValid: false,
    });

    const rejectFee = vi.fn().mockResolvedValue(false);
    const feeScheme = makeScheme(value, { admitFee: rejectFee });
    await expect(feeScheme.verify(value.payload, value.requirements)).resolves.toMatchObject({
      isValid: false,
      invalidReason: "upto_fee_not_admitted",
      payer: value.payerIdentity,
    });
    expect(value.planner).not.toHaveBeenCalled();
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("selects a fully verified terminal before one wallet operation and records before success", async () => {
    const value = await makeFixture();
    const events: string[] = [];
    const backing = new InMemoryTerminalStore();
    const store: TerminalStore = {
      read: backing.read.bind(backing),
      select: async input => {
        events.push("select");
        return backing.select(input);
      },
      recordAccepted: async input => {
        events.push("recordAccepted");
        return backing.recordAccepted(input);
      },
    };
    value.internalizeAction.mockImplementation(async () => {
      events.push("wallet");
      return { accepted: true, satoshis: 610 };
    });
    const scheme = makeScheme(value, { terminalStore: store });
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    const result = await scheme.settle(value.payload, settlement);

    expect(events).toEqual(["select", "wallet", "recordAccepted"]);
    expect(result).toMatchObject({
      success: true,
      network: "bsv:testnet",
      payer: value.payerIdentity,
      amount: "600",
      transaction: expect.stringMatching(/^[0-9a-f]{64}$/),
      extra: { settlementTransaction: expect.any(String) },
    });
    expect(value.planner).toHaveBeenCalledWith(
      expect.objectContaining({
        authorizationId: value.authorizationId,
        actualAmount: 600n,
        maximumAmount: 1000n,
        exposure: 1100n,
        controlInputTotal: 10n,
      } satisfies Partial<UptoBsvTerminalPlanContext>),
    );
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
    expect(value.internalizeAction.mock.calls[0][0]).toEqual(
      expect.objectContaining({
        tx: expect.any(Array),
        outputs: [
          expect.objectContaining({
            outputIndex: 1,
            protocol: "wallet payment",
            paymentRemittance: expect.objectContaining({
              senderIdentityKey: value.payerIdentity,
            }),
          }),
        ],
      }),
    );
  });

  it("fails an accepted replay closed when its stored terminal evidence is no longer valid", async () => {
    const value = await makeFixture();
    let useReprovedSources = false;
    const rotatingTracker: ChainTracker = {
      currentHeight: async () => 1_000_000,
      isValidRootForHeight: async (_root, height) =>
        useReprovedSources ? height >= 900_000 : height < 900_000,
    };
    const scheme = makeScheme(value, { chainTracker: rotatingTracker });
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";
    const first = await scheme.settle(value.payload, settlement);
    expect(first.success).toBe(true);
    value.planner.mockClear();
    value.internalizeAction.mockClear();
    const replayPayload = structuredClone(value.payload);
    const replayCapInputs = (
      replayPayload.payload as { capInputs: Array<{ sourceTransaction: string }> }
    ).capInputs;
    replayCapInputs.forEach((input, index) => {
      input.sourceTransaction = reproveAtomicSource(input.sourceTransaction, 900_000 + index);
    });
    const replayControlInputs = (
      replayPayload.accepted.extra as {
        control: { inputs: Array<{ sourceTransaction: string }> };
      }
    ).control.inputs;
    replayControlInputs.forEach((input, index) => {
      input.sourceTransaction = reproveAtomicSource(input.sourceTransaction, 900_100 + index);
    });
    useReprovedSources = true;

    const replay = await scheme.settle(replayPayload, settlement);

    expect(replay).toMatchObject({
      success: false,
      transaction: "",
      errorReason: "terminal_evidence_unavailable",
    });
    expect(replay.amount).toBeUndefined();
    expect(replay.extra).toBeUndefined();
    expect(value.planner).not.toHaveBeenCalled();
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("returns the accepted terminal evidence when a retry proposes a different amount", async () => {
    const value = await makeFixture();
    const scheme = makeScheme(value);
    const firstRequirements = structuredClone(value.requirements);
    firstRequirements.amount = "600";
    const first = await scheme.settle(value.payload, firstRequirements);
    const differentRequirements = structuredClone(value.requirements);
    differentRequirements.amount = "500";

    const retry = await scheme.settle(value.payload, differentRequirements);

    expect(retry).toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: first.extra?.settlementTransaction },
      errorReason: "terminal_selection_unavailable",
    });
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("does not reapply a changed fee policy to an already accepted authorization", async () => {
    const value = await makeFixture();
    const admitFee = vi.fn().mockResolvedValueOnce(true).mockResolvedValue(false);
    const scheme = makeScheme(value, { admitFee });
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    await expect(scheme.verify(value.payload, value.requirements)).resolves.toMatchObject({
      isValid: true,
    });
    await expect(scheme.settle(value.payload, settlement)).resolves.toMatchObject({
      success: true,
    });
    vi.setSystemTime((DEADLINE + 100) * 1000);
    await expect(scheme.verify(value.payload, value.requirements)).resolves.toMatchObject({
      isValid: false,
      invalidReason: "terminal_selection_unavailable",
    });

    expect(admitFee).toHaveBeenCalledTimes(1);
  });

  it("leaves a selected wallet failure fail closed and never attempts the wallet twice", async () => {
    const value = await makeFixture();
    value.internalizeAction.mockResolvedValue({ accepted: false });
    const scheme = makeScheme(value);
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    const first = await scheme.settle(value.payload, settlement);
    const second = await scheme.settle(value.payload, settlement);

    expect(first).toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: expect.any(String) },
      errorReason: "settlement_rejected_by_wallet",
    });
    expect(second).toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: first.extra?.settlementTransaction },
      errorReason: "terminal_selection_unavailable",
    });
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("gives concurrent settlement calls at most one wallet-attempt token", async () => {
    const value = await makeFixture();
    let releaseWallet!: () => void;
    const walletGate = new Promise<void>(resolve => {
      releaseWallet = resolve;
    });
    value.internalizeAction.mockImplementation(async () => {
      await walletGate;
      return { accepted: true, satoshis: 610 };
    });
    const scheme = makeScheme(value);
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    const first = scheme.settle(value.payload, settlement);
    const second = scheme.settle(value.payload, settlement);
    await vi.waitFor(() => expect(value.internalizeAction).toHaveBeenCalledTimes(1));
    releaseWallet();
    const results = await Promise.all([first, second]);
    const failed = results.find(result => !result.success);

    expect(results.filter(result => result.success)).toHaveLength(1);
    expect(results.filter(result => !result.success)).toHaveLength(1);
    expect(failed).toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: expect.any(String) },
      errorReason: "terminal_selection_unavailable",
    });
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("returns the first-writer terminal when a concurrent call proposes a different amount", async () => {
    const value = await makeFixture();
    value.planner.mockImplementation(async context => ({
      recipientAmounts: [Number(context.actualAmount) + 10],
      refundAmounts: [1095 - Number(context.actualAmount)],
    }));
    const backing = new InMemoryTerminalStore();
    let initialReadCount = 0;
    let releaseInitialReads!: () => void;
    const initialReadsReady = new Promise<void>(resolve => {
      releaseInitialReads = resolve;
    });
    let releaseFirstSelection!: () => void;
    const firstSelectionReady = new Promise<void>(resolve => {
      releaseFirstSelection = resolve;
    });
    const store: TerminalStore = {
      read: async authorizationId => {
        if (initialReadCount < 2) {
          const snapshot = await backing.read(authorizationId);
          initialReadCount += 1;
          if (initialReadCount === 2) releaseInitialReads();
          await initialReadsReady;
          return snapshot;
        }
        return backing.read(authorizationId);
      },
      select: async input => {
        if (input.terminal.amount === "500") await firstSelectionReady;
        const result = await backing.select(input);
        if (input.terminal.amount === "600") releaseFirstSelection();
        return result;
      },
      recordAccepted: backing.recordAccepted.bind(backing),
    };
    const scheme = makeScheme(value, { terminalStore: store });
    const firstRequirements = structuredClone(value.requirements);
    firstRequirements.amount = "600";
    const competingRequirements = structuredClone(value.requirements);
    competingRequirements.amount = "500";

    const first = scheme.settle(value.payload, firstRequirements);
    const competing = scheme.settle(value.payload, competingRequirements);

    const [winner, competingResult] = await Promise.all([first, competing]);

    expect(winner).toMatchObject({
      success: true,
      amount: "600",
      extra: { settlementTransaction: expect.any(String) },
    });
    expect(competingResult).toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: expect.any(String) },
      errorReason: "terminal_selection_unavailable",
    });
    expect(competingResult.extra?.settlementTransaction).toBe(winner.extra?.settlementTransaction);
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("lets the atomic store deadline reject a terminal completed at the boundary", async () => {
    const value = await makeFixture();
    value.planner.mockImplementation(async () => {
      vi.setSystemTime(DEADLINE * 1000);
      return { recipientAmounts: [610], refundAmounts: [495] };
    });
    const scheme = makeScheme(value);
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    await expect(scheme.settle(value.payload, settlement)).resolves.toMatchObject({
      success: false,
      transaction: "",
      errorReason: "terminal_selection_unavailable",
    });
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("does not retry a wallet operation that throws after terminal selection", async () => {
    const value = await makeFixture();
    value.internalizeAction.mockRejectedValue(new Error("wallet unavailable"));
    const scheme = makeScheme(value);
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    await expect(scheme.settle(value.payload, settlement)).resolves.toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: expect.any(String) },
      errorReason: "settlement_failed",
    });
    await expect(scheme.settle(value.payload, settlement)).resolves.toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: expect.any(String) },
      errorReason: "terminal_selection_unavailable",
    });
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("returns selected terminal evidence when the recipient wallet reports a duplicate", async () => {
    const value = await makeFixture();
    value.internalizeAction.mockResolvedValue({ accepted: true, isMerge: true, satoshis: 0 });
    const scheme = makeScheme(value);
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    const first = await scheme.settle(value.payload, settlement);
    const second = await scheme.settle(value.payload, settlement);

    expect(first).toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: expect.any(String) },
      errorReason: "duplicate_settlement",
    });
    expect(second).toMatchObject({
      success: false,
      transaction: "",
      amount: "600",
      extra: { settlementTransaction: first.extra?.settlementTransaction },
      errorReason: "terminal_selection_unavailable",
    });
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it.each(["unavailable", "throw"] as const)(
    "returns the wallet-accepted terminal when replay persistence is %s",
    async persistenceFailure => {
      const value = await makeFixture();
      const backing = new InMemoryTerminalStore();
      const store: TerminalStore = {
        read: backing.read.bind(backing),
        select: backing.select.bind(backing),
        recordAccepted:
          persistenceFailure === "throw"
            ? vi.fn().mockRejectedValue(new Error("persistence unavailable"))
            : vi.fn().mockResolvedValue({ kind: "unavailable" }),
      };
      const scheme = makeScheme(value, { terminalStore: store });
      const settlement = structuredClone(value.requirements);
      settlement.amount = "600";

      const first = await scheme.settle(value.payload, settlement);
      const replay = await scheme.settle(value.payload, settlement);

      expect(value.internalizeAction).toHaveBeenCalledTimes(1);
      expect(first).toMatchObject({
        success: true,
        transaction: expect.stringMatching(/^[0-9a-f]{64}$/),
        amount: "600",
        extra: { settlementTransaction: expect.any(String) },
      });
      expect(replay).toMatchObject({
        success: false,
        transaction: "",
        errorReason: "terminal_selection_unavailable",
      });
    },
  );

  it("does not trust a durable store that returns a different selected terminal", async () => {
    const value = await makeFixture();
    const backing = new InMemoryTerminalStore();
    const store: TerminalStore = {
      read: backing.read.bind(backing),
      select: async input => {
        const selected = await backing.select(input);
        if (selected.kind !== "selected") return selected;
        return {
          ...selected,
          terminal: { ...selected.terminal, txid: "ff".repeat(32) },
        };
      },
      recordAccepted: backing.recordAccepted.bind(backing),
    };
    const scheme = makeScheme(value, { terminalStore: store });
    const settlement = structuredClone(value.requirements);
    settlement.amount = "600";

    await expect(scheme.settle(value.payload, settlement)).resolves.toMatchObject({
      success: false,
      transaction: "",
      errorReason: "terminal_store_unavailable",
    });
    expect(value.internalizeAction).not.toHaveBeenCalled();
  });

  it("does not leak another authorization's selected or accepted terminal evidence", async () => {
    for (const kind of ["selected", "accepted"] as const) {
      const value = await makeFixture();
      const backing = new InMemoryTerminalStore();
      const store: TerminalStore = {
        read: async () => ({
          kind,
          terminal: {
            authorizationId: "ff".repeat(32),
            txid: "ee".repeat(32),
            amount: "600",
            subjectTransaction: "AA==",
            settlementTransaction: "AQ==",
          },
        }),
        select: backing.select.bind(backing),
        recordAccepted: backing.recordAccepted.bind(backing),
      };
      const scheme = makeScheme(value, { terminalStore: store });
      const settlement = structuredClone(value.requirements);
      settlement.amount = "600";

      const result = await scheme.settle(value.payload, settlement);
      expect(result).toMatchObject({
        success: false,
        transaction: "",
        errorReason: "terminal_store_unavailable",
      });
      expect(result.amount).toBeUndefined();
      expect(result.extra).toBeUndefined();
      expect(value.planner).not.toHaveBeenCalled();
      expect(value.internalizeAction).not.toHaveBeenCalled();
    }
  });

  it("uses one wallet operation for all recipient outputs", async () => {
    const value = await makeFixture({ capCount: 2, controlCount: 2 });
    const scheme = makeScheme(value);
    const settlement = structuredClone(value.requirements);
    settlement.amount = "790";

    const result = await scheme.settle(value.payload, settlement);

    expect(result.success).toBe(true);
    const request = value.internalizeAction.mock.calls[0][0] as { outputs: unknown[] };
    expect(request.outputs).toHaveLength(2);
    expect(value.internalizeAction).toHaveBeenCalledTimes(1);
  });

  it("requires an explicit terminal store and planner capability", async () => {
    const value = await makeFixture();

    expect(
      () =>
        new UptoBsvScheme({
          wallet: value.wallet,
          identityKey: value.payTo,
          chainTracker: value.tracker,
          sourcePolicy: { maxSources: 8, maxAtomicBeefBytesPerSource: 16_384 },
          terminalPolicy: { maxAtomicBeefBytes: 65_536 },
          terminalStore: undefined as never,
          planTerminal: value.planner,
        }),
    ).toThrow(/terminalStore/);
    expect(
      () =>
        new UptoBsvScheme({
          wallet: value.wallet,
          identityKey: value.payTo,
          chainTracker: value.tracker,
          sourcePolicy: { maxSources: 8, maxAtomicBeefBytesPerSource: 16_384 },
          terminalPolicy: { maxAtomicBeefBytes: 65_536 },
          terminalStore: new InMemoryTerminalStore(),
          planTerminal: undefined as never,
        }),
    ).toThrow(/planTerminal/);
  });
});
