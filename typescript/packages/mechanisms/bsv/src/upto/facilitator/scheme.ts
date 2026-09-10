import { PublicKey, Utils, type ChainTracker, type WalletInterface } from "@bsv/sdk";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  VerifyResponse,
} from "@x402/core/types";
import {
  BSV_WILDCARD_CAIP2,
  COMPRESSED_PUBKEY_REGEX,
  DEFAULT_PAYMENT_WINDOW_MS,
  toBsvWalletNetwork,
} from "../../constants";
import { admitPresentedAuthorization } from "../internal/presented";
import {
  BSV_UPTO_AUTHORIZATION_RECEIPT_KEY,
  createUptoVerificationReceipt,
} from "../internal/receipt";
import {
  materializeVerifiedTerminal,
  verifyTerminalTransaction,
  type MaterializedVerifiedTerminal,
} from "../internal/terminal";
import {
  createTerminalTransaction,
  materializeVerifiedAuthorization,
  type MaterializedVerifiedAuthorization,
  type VerifiedAuthorization,
} from "../internal/transaction";
import {
  snapshotPresentedUptoPayment,
  type PresentedUptoPayment,
  type UptoPaymentPhase,
} from "../internal/wire";
import {
  sameTerminalIdentity,
  type TerminalStore,
  type VerifiedTerminalRecord,
} from "./terminalStore";

/** Verified fee facts available to the recipient's local admission policy. */
export interface UptoBsvFeeAdmissionContext {
  readonly authorizationId: string;
  readonly maximumAmount: bigint;
  readonly exposure: bigint;
  readonly feeHeadroom: bigint;
}

/** Verified amounts available to the recipient's terminal-output planner. */
export interface UptoBsvTerminalPlanContext extends UptoBsvFeeAdmissionContext {
  readonly actualAmount: bigint;
  readonly capInputTotal: bigint;
  readonly controlInputTotal: bigint;
  readonly floorOutputTotal: bigint;
}

/** Amount-only terminal plan; scripts and roles are derived inside the transaction kernel. */
export interface UptoBsvTerminalPlan {
  readonly recipientAmounts: readonly number[];
  readonly refundAmounts: readonly number[];
}

/** Recipient policy that selects fee/output allocation without controlling scripts. */
export type UptoBsvTerminalPlanner = (
  context: UptoBsvTerminalPlanContext,
) => UptoBsvTerminalPlan | Promise<UptoBsvTerminalPlan>;

/** Optional pre-handler policy for the payer's verified fee headroom. */
export type UptoBsvFeeAdmission = (
  context: UptoBsvFeeAdmissionContext,
) => boolean | Promise<boolean>;

/** Finite facilitator bounds applied before parsing authorization source BEEF. */
export interface UptoBsvFacilitatorSourcePolicy {
  /** Maximum aggregate count of cap and control sources in one authorization. */
  readonly maxSources: number;
  /** Maximum decoded Atomic BEEF bytes accepted for any one source. */
  readonly maxAtomicBeefBytesPerSource: number;
}

/** Finite facilitator bound applied before parsing terminal Atomic BEEF. */
export interface UptoBsvFacilitatorTerminalPolicy {
  readonly maxAtomicBeefBytes: number;
}

/** BSV upto facilitator configuration. */
export interface UptoBsvSchemeConfig {
  /** Recipient BRC-100 wallet used for key derivation, signing, and settlement. */
  wallet: WalletInterface;
  /** Recipient wallet identity key; use {@link UptoBsvScheme.create} to fetch it. */
  identityKey: string;
  /** Chain facts used for source and terminal Atomic BEEF verification. */
  chainTracker: ChainTracker;
  /** Finite source-count and per-source BEEF limits. */
  sourcePolicy: UptoBsvFacilitatorSourcePolicy;
  /** Finite terminal Atomic BEEF limit. */
  terminalPolicy: UptoBsvFacilitatorTerminalPolicy;
  /** Durable first-writer terminal selection and accepted-outcome store. */
  terminalStore: TerminalStore;
  /** Recipient amount allocation and fee policy used for terminal construction. */
  planTerminal: UptoBsvTerminalPlanner;
  /** Optional local fee-headroom policy evaluated only during verify. */
  admitFee?: UptoBsvFeeAdmission;
  /** Exact-compatible timestamp freshness window in milliseconds. */
  paymentWindowMs?: number;
  /** Optional BRC-100 originator passed to wallet calls. */
  originator?: string;
}

interface VerifiedPayment {
  readonly presented: PresentedUptoPayment;
  readonly authorization: VerifiedAuthorization;
  readonly material: MaterializedVerifiedAuthorization;
  readonly authorizationId: string;
  readonly actualAmount: bigint;
  readonly maximumAmount: bigint;
  readonly capInputTotal: bigint;
  readonly controlInputTotal: bigint;
  readonly floorOutputTotal: bigint;
  readonly exposure: bigint;
  readonly feeHeadroom: bigint;
  readonly payer: string;
}

/**
 * Recipient-side facilitator for the BSV upto scheme.
 *
 * Verification is read-only. Settlement re-verifies the authorization, builds
 * and verifies one terminal transaction, atomically selects it, then gives the
 * first selector one token for a single recipient-wallet operation. No
 * broadcaster, outbox, or pending-settlement state is introduced.
 */
export class UptoBsvScheme implements SchemeNetworkFacilitator {
  readonly scheme = "upto";
  readonly caipFamily = BSV_WILDCARD_CAIP2;

  private readonly wallet: WalletInterface;
  private readonly identityKey: string;
  private readonly chainTracker: ChainTracker;
  private readonly sourcePolicy: UptoBsvFacilitatorSourcePolicy;
  private readonly terminalPolicy: UptoBsvFacilitatorTerminalPolicy;
  private readonly terminalStore: TerminalStore;
  private readonly planTerminal: UptoBsvTerminalPlanner;
  private readonly admitFee?: UptoBsvFeeAdmission;
  private readonly paymentWindowMs: number;
  private readonly originator?: string;
  private walletNetworkPromise: Promise<string> | undefined;

  /**
   * Creates a BSV upto facilitator with an explicit durable coordination seam.
   *
   * @param config - Recipient wallet, verification policies, store, and planner
   */
  constructor(config: UptoBsvSchemeConfig) {
    if (typeof config !== "object" || config === null) {
      throw new Error("BSV upto facilitator config is required");
    }
    if (
      typeof config.wallet?.getPublicKey !== "function" ||
      typeof config.wallet?.createSignature !== "function" ||
      typeof config.wallet?.getNetwork !== "function" ||
      typeof config.wallet?.internalizeAction !== "function"
    ) {
      throw new Error("wallet must support BRC-100 key, signing, network, and internalize actions");
    }
    this.identityKey = normalizeIdentity(config.identityKey);
    if (
      typeof config.terminalStore?.read !== "function" ||
      typeof config.terminalStore?.select !== "function" ||
      typeof config.terminalStore?.recordAccepted !== "function"
    ) {
      throw new Error("terminalStore must provide durable read/select/recordAccepted operations");
    }
    if (typeof config.planTerminal !== "function") {
      throw new Error("planTerminal must be a function");
    }
    if (config.admitFee !== undefined && typeof config.admitFee !== "function") {
      throw new Error("admitFee must be a function");
    }
    const paymentWindowMs = config.paymentWindowMs ?? DEFAULT_PAYMENT_WINDOW_MS;
    if (!Number.isSafeInteger(paymentWindowMs) || paymentWindowMs <= 0) {
      throw new Error("paymentWindowMs must be a positive safe integer");
    }
    const maxSources = readPositiveSafeInteger(config.sourcePolicy?.maxSources, "maxSources");
    const maxAtomicBeefBytesPerSource = readPositiveSafeInteger(
      config.sourcePolicy?.maxAtomicBeefBytesPerSource,
      "maxAtomicBeefBytesPerSource",
    );
    readPositiveSafeInteger(config.terminalPolicy?.maxAtomicBeefBytes, "maxAtomicBeefBytes");

    this.wallet = config.wallet;
    this.chainTracker = config.chainTracker;
    this.sourcePolicy = Object.freeze({ maxSources, maxAtomicBeefBytesPerSource });
    this.terminalPolicy = Object.freeze({
      maxAtomicBeefBytes: config.terminalPolicy.maxAtomicBeefBytes,
    });
    this.terminalStore = config.terminalStore;
    this.planTerminal = config.planTerminal;
    this.admitFee = config.admitFee;
    this.paymentWindowMs = paymentWindowMs;
    this.originator = config.originator;
  }

  /**
   * Creates a facilitator after reading the recipient identity from its wallet.
   *
   * @param config - Configuration without an explicit identity key
   * @returns Ready-to-register BSV upto facilitator
   */
  static async create(config: Omit<UptoBsvSchemeConfig, "identityKey">): Promise<UptoBsvScheme> {
    const { publicKey } = await config.wallet.getPublicKey(
      { identityKey: true },
      config.originator,
    );
    return new UptoBsvScheme({ ...config, identityKey: publicKey });
  }

  /**
   * Returns no facilitator-specific requirement metadata.
   *
   * @param _ - Network identifier, unused for BSV upto
   * @returns Undefined because the control offer is application-provided
   */
  getExtra(_: Network): undefined {
    return undefined;
  }

  /**
   * Returns the recipient identity accepted by this wallet.
   *
   * @param _ - Network identifier, unused because this wallet has one identity
   * @returns The configured recipient identity
   */
  getSigners(_: string): string[] {
    return [this.identityKey];
  }

  /**
   * Verifies one maximum authorization without selecting or internalizing a terminal.
   *
   * @param payload - Presented payment payload
   * @param requirements - Verify-time requirements whose amount is M
   * @returns Verified payer and server coordination receipt, or a structured failure
   */
  async verify(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    let checked: VerifiedPayment;
    try {
      // Static authorization verification must precede the replay lookup, but
      // temporal and fee admission apply only to a new authorization.
      checked = await this.verifyPayment(payload, requirements, "verify");
    } catch (error) {
      return this.verifyFailure(error);
    }
    let existing;
    try {
      existing = await this.terminalStore.read(checked.authorizationId);
    } catch (error) {
      return {
        isValid: false,
        invalidReason: "terminal_store_unavailable",
        invalidMessage: error instanceof Error ? error.message : String(error),
        payer: checked.payer,
      };
    }
    if (existing?.kind === "accepted") {
      if (existing.terminal.authorizationId !== checked.authorizationId) {
        return {
          isValid: false,
          invalidReason: "terminal_store_unavailable",
          invalidMessage: "terminal store returned a different authorization",
          payer: checked.payer,
        };
      }
      return {
        isValid: false,
        invalidReason: "terminal_selection_unavailable",
        invalidMessage: "the authorization already has an accepted terminal",
        payer: checked.payer,
      };
    }
    if (existing?.kind === "selected") {
      if (existing.terminal.authorizationId !== checked.authorizationId) {
        return {
          isValid: false,
          invalidReason: "terminal_store_unavailable",
          invalidMessage: "terminal store returned a selected terminal for another authorization",
          payer: checked.payer,
        };
      }
      return {
        isValid: false,
        invalidReason: "terminal_selection_unavailable",
        invalidMessage: "a terminal was selected without a recorded accepted outcome",
        payer: checked.payer,
      };
    }
    try {
      this.assertTemporalAdmission(requirements, "verify", checked.presented);
    } catch (error) {
      return this.verifyFailure(error);
    }
    if (this.admitFee !== undefined) {
      let admitted = false;
      try {
        admitted = await this.admitFee(this.feeContext(checked));
      } catch {
        admitted = false;
      }
      if (!admitted) {
        return {
          isValid: false,
          invalidReason: "upto_fee_not_admitted",
          payer: checked.payer,
        };
      }
    }
    return this.verificationSuccess(checked);
  }

  /**
   * Selects, signs, verifies, and internalizes one terminal transaction.
   *
   * @param payload - Original maximum authorization payload
   * @param requirements - Settlement requirements whose amount is actual A
   * @returns Existing x402 settlement response with terminal Atomic BEEF on success
   */
  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    const network = requirements.network;
    let checked: VerifiedPayment;
    try {
      // Static cryptographic verification precedes the accepted-record lookup;
      // temporal admission is applied below only when no success can be replayed.
      checked = await this.verifyPayment(payload, requirements, "settle");
    } catch (error) {
      return this.settleFailure(network, error);
    }

    let existing;
    try {
      existing = await this.terminalStore.read(checked.authorizationId);
    } catch (error) {
      return this.settleFailure(network, error, checked.payer, "terminal_store_unavailable");
    }
    if (existing !== undefined) {
      if (existing.terminal.authorizationId !== checked.authorizationId) {
        return this.settleFailure(
          network,
          "terminal store returned a terminal for another authorization",
          checked.payer,
          "terminal_store_unavailable",
        );
      }
      let replayTerminal: VerifiedTerminalRecord;
      try {
        replayTerminal = await this.revalidateStoredTerminal(checked, existing.terminal);
      } catch (error) {
        return this.settleFailure(network, error, checked.payer, "terminal_evidence_unavailable");
      }
      if (
        existing.kind === "accepted" &&
        replayTerminal.amount === checked.actualAmount.toString()
      ) {
        return this.success(network, checked.payer, replayTerminal);
      }
      return this.selectedTerminalFailure(
        network,
        checked.payer,
        replayTerminal,
        existing.kind === "accepted"
          ? "accepted terminal amount differs from settlement amount"
          : "a terminal was selected without a recorded accepted outcome",
        "terminal_selection_unavailable",
      );
    }

    try {
      this.assertTemporalAdmission(requirements, "settle", checked.presented);
    } catch (error) {
      return this.settleFailure(network, error, checked.payer);
    }

    let terminal: MaterializedVerifiedTerminal;
    try {
      const plan = await this.planTerminal(this.planContext(checked));
      const transaction = await createTerminalTransaction({
        authorization: checked.authorization,
        actualAmount: checked.actualAmount,
        recipientAmounts: plan.recipientAmounts,
        refundAmounts: plan.refundAmounts,
        wallet: this.wallet,
        originator: this.originator,
      });
      const encoded = Utils.toBase64(transaction.toAtomicBEEF());
      const verified = await verifyTerminalTransaction({
        authorization: checked.authorization,
        actualAmount: checked.actualAmount,
        transaction: encoded,
        wallet: this.wallet,
        perspective: "recipient",
        chainTracker: this.chainTracker,
        policy: this.terminalPolicy,
        originator: this.originator,
      });
      terminal = materializeVerifiedTerminal(verified);
    } catch (error) {
      return this.settleFailure(network, error, checked.payer, "terminal_construction_failed");
    }

    const record: VerifiedTerminalRecord = Object.freeze({
      authorizationId: checked.authorizationId,
      txid: terminal.subjectTxid,
      amount: terminal.actualAmount.toString(),
      subjectTransaction: Utils.toBase64(Array.from(terminal.subjectTransaction)),
      settlementTransaction: Utils.toBase64(Array.from(terminal.atomicBeef)),
    });
    let selection;
    try {
      selection = await this.terminalStore.select({
        terminal: record,
        validAfter: checked.material.facts.validAfter,
        deadline: checked.material.facts.deadline,
      });
    } catch (error) {
      return this.settleFailure(network, error, checked.payer, "terminal_store_unavailable");
    }
    if (selection.kind === "accepted") {
      if (!sameTerminalIdentity(selection.terminal, record)) {
        return this.settleFailure(
          network,
          "terminal store returned a different accepted terminal",
          checked.payer,
          "terminal_store_unavailable",
        );
      }
      return this.success(network, checked.payer, record);
    }
    if (selection.kind !== "selected") {
      let selectedByConcurrentCall;
      try {
        selectedByConcurrentCall = await this.terminalStore.read(checked.authorizationId);
      } catch (error) {
        return this.settleFailure(network, error, checked.payer, "terminal_store_unavailable");
      }
      if (
        selectedByConcurrentCall !== undefined &&
        selectedByConcurrentCall.terminal.authorizationId === checked.authorizationId
      ) {
        let replayTerminal: VerifiedTerminalRecord;
        try {
          replayTerminal = await this.revalidateStoredTerminal(
            checked,
            selectedByConcurrentCall.terminal,
          );
        } catch (error) {
          return this.settleFailure(network, error, checked.payer, "terminal_evidence_unavailable");
        }
        return selectedByConcurrentCall.kind === "accepted" &&
          replayTerminal.amount === checked.actualAmount.toString()
          ? this.success(network, checked.payer, replayTerminal)
          : this.selectedTerminalFailure(
              network,
              checked.payer,
              replayTerminal,
              "a terminal was selected by another settlement call",
              "terminal_selection_unavailable",
            );
      }
      return this.settleFailure(
        network,
        "terminal first-writer selection was unavailable",
        checked.payer,
        "terminal_selection_unavailable",
      );
    }
    if (!sameTerminalIdentity(selection.terminal, record)) {
      return this.settleFailure(
        network,
        "terminal store returned a different selected terminal",
        checked.payer,
        "terminal_store_unavailable",
      );
    }

    let walletResult: { accepted: boolean; isMerge?: boolean; satoshis?: number };
    try {
      walletResult = (await this.wallet.internalizeAction(
        {
          tx: Array.from(terminal.atomicBeef),
          outputs: terminal.outputs
            .filter(output => output.role === "recipient")
            .map(output => ({
              outputIndex: output.outputIndex,
              protocol: "wallet payment" as const,
              paymentRemittance: { ...output.paymentRemittance },
            })),
          description: "x402 upto payment",
        },
        this.originator,
      )) as { accepted: boolean; isMerge?: boolean; satoshis?: number };
    } catch (error) {
      return this.selectedTerminalFailure(
        network,
        checked.payer,
        record,
        error,
        "settlement_failed",
      );
    }
    const newlyInternalized =
      typeof walletResult.satoshis === "number" && walletResult.satoshis > 0;
    if (walletResult.isMerge && !newlyInternalized) {
      return this.selectedTerminalFailure(
        network,
        checked.payer,
        record,
        "recipient wallet already knew the terminal transaction",
        "duplicate_settlement",
      );
    }
    if (!walletResult.accepted) {
      return this.selectedTerminalFailure(
        network,
        checked.payer,
        record,
        "recipient wallet rejected the selected terminal",
        "settlement_rejected_by_wallet",
      );
    }

    let accepted;
    try {
      accepted = await this.terminalStore.recordAccepted({
        token: selection.token,
        txid: record.txid,
      });
    } catch {
      // The wallet has already accepted the verified terminal. Losing the
      // replay record cannot retroactively turn that exact wallet result into
      // a failure; future retries remain fail closed on the selected record.
      return this.success(network, checked.payer, record);
    }
    if (accepted.kind === "accepted" && sameTerminalIdentity(accepted.terminal, record)) {
      return this.success(network, checked.payer, record);
    }
    return this.success(network, checked.payer, record);
  }

  /**
   * Performs the common static cryptographic verification for both phases.
   *
   * @param payload - Presented maximum authorization
   * @param requirements - Verify-time maximum or settle-time actual requirements
   * @param phase - Amount interpretation phase
   * @returns A verified immutable authorization and aggregate view
   */
  private async verifyPayment(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
    phase: UptoPaymentPhase,
  ): Promise<VerifiedPayment> {
    const presented = snapshotPresentedUptoPayment(payload, requirements, phase);
    if (presented.payTo !== this.identityKey) {
      throw new Error("BSV upto payTo does not match the facilitator wallet");
    }
    await this.assertWalletNetwork(presented.network);
    const admitted = await admitPresentedAuthorization({
      presented,
      wallet: this.wallet,
      perspective: "recipient",
      chainTracker: this.chainTracker,
      sourcePolicy: this.sourcePolicy,
      originator: this.originator,
    });
    const authorization = admitted.authorization;
    const material = materializeVerifiedAuthorization(authorization);
    const authorizationId = material.authorizationId;
    const maximumAmount = BigInt(material.facts.maximumAmount);
    const exposure = material.capInputTotal - material.floorOutputTotal;
    return Object.freeze({
      presented,
      authorization,
      material,
      authorizationId,
      actualAmount: presented.actualAmount,
      maximumAmount,
      capInputTotal: material.capInputTotal,
      controlInputTotal: material.controlInputTotal,
      floorOutputTotal: material.floorOutputTotal,
      exposure,
      feeHeadroom: exposure - maximumAmount,
      payer: material.facts.senderIdentityKey,
    });
  }

  /**
   * Applies exact-style freshness and the strict local control window.
   *
   * @param requirements - Current requirements containing the settlement budget
   * @param phase - Verify or settlement freshness interpretation
   * @param presented - Closed presented-payment snapshot
   */
  private assertTemporalAdmission(
    requirements: PaymentRequirements,
    phase: UptoPaymentPhase,
    presented: PresentedUptoPayment,
  ): void {
    const nowMs = Date.now();
    const now = Math.floor(nowMs / 1000);
    if (now < presented.control.validAfter || now >= presented.control.deadline) {
      throw new Error("BSV upto authorization is outside its validity window");
    }
    let decoded: string;
    try {
      decoded = Utils.toUTF8(Utils.toArray(presented.payload.derivationSuffix, "base64"));
    } catch {
      throw new Error("BSV upto derivation timestamp is invalid");
    }
    if (!/^\d+$/.test(decoded)) throw new Error("BSV upto derivation timestamp is invalid");
    const timestamp = Number(decoded);
    if (!Number.isFinite(timestamp)) throw new Error("BSV upto derivation timestamp is invalid");
    const settleBudgetMs = phase === "settle" ? requirements.maxTimeoutSeconds * 1000 : 0;
    const age = nowMs - timestamp;
    if (age < -this.paymentWindowMs || age > this.paymentWindowMs + settleBudgetMs) {
      throw new Error("BSV upto derivation timestamp is outside the exact payment window");
    }
  }

  /**
   * Confirms that the recipient wallet is connected to the requested BSV chain.
   *
   * @param network - Registered BSV CAIP-2 identifier
   */
  private async assertWalletNetwork(network: Network): Promise<void> {
    const expected = toBsvWalletNetwork(network);
    if (expected === undefined) throw new Error("BSV upto network is unsupported");
    let actual: string;
    try {
      this.walletNetworkPromise ??= this.wallet.getNetwork({}).then(result => result.network);
      actual = await this.walletNetworkPromise;
    } catch {
      this.walletNetworkPromise = undefined;
      throw new Error("recipient wallet network could not be read");
    }
    if (actual !== expected)
      throw new Error("recipient wallet network does not match requirements");
  }

  /**
   * Creates a detached immutable fee-admission view.
   *
   * @param checked - Fully verified payment facts
   * @returns Local fee-policy inputs
   */
  private feeContext(checked: VerifiedPayment): UptoBsvFeeAdmissionContext {
    return Object.freeze({
      authorizationId: checked.authorizationId,
      maximumAmount: checked.maximumAmount,
      exposure: checked.exposure,
      feeHeadroom: checked.feeHeadroom,
    });
  }

  /**
   * Builds the resource-server receipt only from a fully verified authorization.
   *
   * @param checked - Fully verified payment facts
   * @returns Successful verification response
   */
  private verificationSuccess(checked: VerifiedPayment): VerifyResponse {
    return {
      isValid: true,
      payer: checked.payer,
      extra: {
        [BSV_UPTO_AUTHORIZATION_RECEIPT_KEY]: createUptoVerificationReceipt(checked.authorization),
      },
    };
  }

  /**
   * Creates a detached immutable terminal-planning view.
   *
   * @param checked - Fully verified payment facts
   * @returns Amount-only planner context
   */
  private planContext(checked: VerifiedPayment): UptoBsvTerminalPlanContext {
    return Object.freeze({
      ...this.feeContext(checked),
      actualAmount: checked.actualAmount,
      capInputTotal: checked.capInputTotal,
      controlInputTotal: checked.controlInputTotal,
      floorOutputTotal: checked.floorOutputTotal,
    });
  }

  /**
   * Revalidates stored terminal evidence against current chain facts.
   *
   * The durable store selects terminal identity, not the continuing validity
   * of its BEEF envelope. Replay therefore crosses the terminal verification
   * boundary again before returning any stored evidence.
   *
   * @param checked - Currently revalidated authorization and amount context
   * @param stored - Previously selected terminal record
   * @returns The stored record after its envelope and identity revalidate
   */
  private async revalidateStoredTerminal(
    checked: VerifiedPayment,
    stored: VerifiedTerminalRecord,
  ): Promise<VerifiedTerminalRecord> {
    let actualAmount: bigint;
    try {
      actualAmount = BigInt(stored.amount);
    } catch {
      throw new Error("stored terminal amount is invalid");
    }
    const verified = await verifyTerminalTransaction({
      authorization: checked.authorization,
      actualAmount,
      transaction: stored.settlementTransaction,
      wallet: this.wallet,
      perspective: "recipient",
      chainTracker: this.chainTracker,
      policy: this.terminalPolicy,
      originator: this.originator,
    });
    const material = materializeVerifiedTerminal(verified);
    const current: VerifiedTerminalRecord = {
      authorizationId: checked.authorizationId,
      txid: material.subjectTxid,
      amount: material.actualAmount.toString(),
      subjectTransaction: Utils.toBase64(Array.from(material.subjectTransaction)),
      settlementTransaction: stored.settlementTransaction,
    };
    if (!sameTerminalIdentity(stored, current)) {
      throw new Error("stored terminal evidence does not match its selected identity");
    }
    return stored;
  }

  /**
   * Formats one accepted terminal as the existing x402 settlement response.
   *
   * @param network - BSV network identifier
   * @param payer - Verified payer identity
   * @param terminal - Stored accepted terminal facts
   * @returns Successful response carrying terminal Atomic BEEF
   */
  private success(
    network: Network,
    payer: string,
    terminal: VerifiedTerminalRecord,
  ): SettleResponse {
    return {
      success: true,
      network,
      payer,
      transaction: terminal.txid,
      amount: terminal.amount,
      extra: { settlementTransaction: terminal.settlementTransaction },
    };
  }

  /**
   * Reports a failed settlement while preserving the already-selected terminal evidence.
   *
   * @param network - BSV network identifier
   * @param payer - Verified payer identity
   * @param terminal - Previously selected verified terminal
   * @param error - Failure detail
   * @param reason - Stable mechanism failure code
   * @returns Failed response carrying the selected amount and Atomic BEEF
   */
  private selectedTerminalFailure(
    network: Network,
    payer: string,
    terminal: VerifiedTerminalRecord,
    error: unknown,
    reason: string,
  ): SettleResponse {
    return {
      ...this.settleFailure(network, error, payer, reason),
      amount: terminal.amount,
      extra: { settlementTransaction: terminal.settlementTransaction },
    };
  }

  /**
   * Formats an ordinary structured settlement failure without evidence fields.
   *
   * @param network - Requested network
   * @param error - Underlying failure
   * @param payer - Verified payer when available
   * @param reason - Stable mechanism failure code
   * @returns Failed response with an empty transaction field
   */
  private settleFailure(
    network: Network,
    error: unknown,
    payer = "",
    reason = "invalid_upto_bsv_payload",
  ): SettleResponse {
    return {
      success: false,
      network,
      payer,
      transaction: "",
      errorReason: reason,
      errorMessage: error instanceof Error ? error.message : String(error),
    };
  }

  /**
   * Formats a read-only verification failure.
   *
   * @param error - Underlying validation failure
   * @returns Failed verification response
   */
  private verifyFailure(error: unknown): VerifyResponse {
    return {
      isValid: false,
      invalidReason: "invalid_upto_bsv_payload",
      invalidMessage: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Normalizes and validates one compressed identity key.
 *
 * @param value - Candidate identity key
 * @returns Canonical compressed public key
 */
function normalizeIdentity(value: string): string {
  if (typeof value !== "string" || !COMPRESSED_PUBKEY_REGEX.test(value)) {
    throw new Error("identityKey must be a compressed secp256k1 public key");
  }
  try {
    return PublicKey.fromString(value).toString();
  } catch {
    throw new Error("identityKey must be a compressed secp256k1 public key");
  }
}

/**
 * Validates one finite positive policy bound.
 *
 * @param value - Candidate bound
 * @param field - Field name for failures
 * @returns Validated bound
 */
function readPositiveSafeInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || Object.is(value, -0)) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  return value;
}
