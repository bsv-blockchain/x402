import type {
  AssetAmount,
  MoneyParser,
  Network,
  PaymentFlowConfig,
  PaymentRequirements,
  Price,
  SchemeNetworkServer,
  SchemeServerHooks,
} from "@x402/core/types";
import { ExactBsvScheme } from "../../exact/server/scheme";
import { MAX_SATOSHIS } from "../../constants";
import { readUptoVerificationReceipt, type UptoBsvVerificationReceipt } from "../internal/receipt";
import { snapshotUptoRequirements } from "../internal/wire";
import type { AuthorizationStore, AuthorizationStoreToken } from "./authorizationStore";

const CANONICAL_AMOUNT = /^(?:0|[1-9]\d*)$/;
const AFTER_HANDLER_REQUIRED = "upto_bsv_settlement_requires_after_handler";

/** Configuration for the BSV upto resource-server role. */
export interface UptoBsvServerConfig {
  /** Durable atomic admission store. No production default is supplied. */
  readonly authorizationStore: AuthorizationStore;
}

interface RequestReservation {
  readonly token: AuthorizationStoreToken;
  readonly maximumAmount: string;
  readonly amount?: string;
}

/**
 * BSV resource-server implementation for the `upto` payment scheme.
 *
 * Pricing delegates to the existing exact implementation. The only added
 * responsibility is request-local orchestration around a durable, atomic
 * authorization admission seam; transaction verification and custody remain
 * facilitator responsibilities.
 */
export class UptoBsvScheme implements SchemeNetworkServer {
  readonly scheme = "upto";
  readonly defaultAssetTransferMethod = "default";
  readonly paymentFlows = {
    default: { supported: ["authorization"], default: "authorization" },
  } as const satisfies Record<string, PaymentFlowConfig>;
  readonly schemeHooks: SchemeServerHooks;

  private readonly exact = new ExactBsvScheme();
  private readonly store: AuthorizationStore;
  private readonly requests = new WeakMap<object, RequestReservation>();

  /**
   * Creates the resource-server role.
   *
   * @param config - Required durable authorization store
   */
  constructor(config: UptoBsvServerConfig) {
    const store = config?.authorizationStore;
    if (typeof store?.admit !== "function" || typeof store.bindActualAmount !== "function") {
      throw new Error("BSV upto requires an authorization store");
    }
    this.store = store;
    const hooks: SchemeServerHooks = {
      onAfterVerify: context => this.afterVerify(context),
      onBeforeSettle: context => this.beforeSettle(context),
    };
    this.schemeHooks = Object.freeze(hooks);
  }

  /**
   * Registers the same money parser used by BSV exact.
   *
   * @param parser - BSV money parser
   * @returns This scheme
   */
  registerMoneyParser(parser: MoneyParser): this {
    this.exact.registerMoneyParser(parser);
    return this;
  }

  /**
   * Delegates BSV price parsing to the exact implementation.
   *
   * @param price - User price or explicit asset amount
   * @param network - BSV network
   * @returns Parsed native BSV amount
   */
  parsePrice(price: Price, network: Network): Promise<AssetAmount> {
    return this.exact.parsePrice(price, network);
  }

  /**
   * Delegates native-asset decimal lookup to BSV exact.
   *
   * @param asset - Native asset identifier
   * @param network - BSV network
   * @returns Native BSV decimal count
   */
  getAssetDecimals(asset: string, network: Network): number {
    return this.exact.getAssetDecimals(asset, network);
  }

  /**
   * Preserves exact requirement enhancement while retaining scheme `upto`.
   *
   * @param requirements - Base payment requirements
   * @param supportedKind - Facilitator-announced support record
   * @param supportedKind.x402Version - Supported x402 version
   * @param supportedKind.scheme - Supported scheme
   * @param supportedKind.network - Supported network
   * @param supportedKind.extra - Optional facilitator metadata
   * @param extensionKeys - Active extension keys
   * @returns Enhanced requirements
   */
  async enhancePaymentRequirements(
    requirements: PaymentRequirements,
    supportedKind: {
      x402Version: number;
      scheme: string;
      network: Network;
      extra?: Record<string, unknown>;
    },
    extensionKeys: string[],
  ): Promise<PaymentRequirements> {
    const enhanced = await this.exact.enhancePaymentRequirements(
      requirements,
      supportedKind,
      extensionKeys,
    );
    snapshotUptoRequirements(enhanced);
    return enhanced;
  }

  /**
   * Handles verified authorization admission before the protected handler.
   *
   * @param context - Successful facilitator verification context
   * @returns Handler-skip, abort, or normal continuation
   */
  private async afterVerify(
    context: Parameters<NonNullable<SchemeServerHooks["onAfterVerify"]>>[0],
  ): ReturnType<NonNullable<SchemeServerHooks["onAfterVerify"]>> {
    if (context.result.isValid !== true) return undefined;
    let receipt: UptoBsvVerificationReceipt;
    try {
      receipt = readUptoVerificationReceipt(context.result.extra, context.requirements.amount);
    } catch (error) {
      return abort("invalid_upto_bsv_verification_receipt", error);
    }

    try {
      const admitted = await this.store.admit({
        authorizationId: receipt.authorizationId,
        outpoints: receipt.outpoints,
        validAfter: receipt.validAfter,
        deadline: receipt.deadline,
      });
      if (admitted.kind === "out_of_window") {
        return { abort: true, reason: "upto_bsv_authorization_out_of_window" };
      }
      if (admitted.kind === "unavailable") {
        return { abort: true, reason: "upto_bsv_authorization_already_in_use" };
      }
      this.requests.set(context.paymentPayload, {
        token: admitted.token,
        maximumAmount: receipt.maximumAmount,
      });
      return undefined;
    } catch (error) {
      return abort("upto_bsv_authorization_unavailable", error);
    }
  }

  /**
   * Binds the post-handler actual amount.
   *
   * @param context - Effective settlement context
   * @returns Settlement-skip, abort, or normal continuation
   */
  private async beforeSettle(
    context: Parameters<NonNullable<SchemeServerHooks["onBeforeSettle"]>>[0],
  ): ReturnType<NonNullable<SchemeServerHooks["onBeforeSettle"]>> {
    if (context.phase !== "after-handler") {
      return { abort: true, reason: AFTER_HANDLER_REQUIRED };
    }
    const reservation = this.requests.get(context.paymentPayload);
    if (reservation === undefined) {
      return { abort: true, reason: "upto_bsv_authorization_unavailable" };
    }
    if (reservation.amount !== undefined) {
      return { abort: true, reason: "upto_bsv_amount_already_bound" };
    }
    let amount: string;
    try {
      amount = readAmount(context.requirements.amount, true);
    } catch (error) {
      return abort("invalid_upto_bsv_settlement_amount", error);
    }
    if (BigInt(amount) > BigInt(reservation.maximumAmount)) {
      return { abort: true, reason: "upto_bsv_settlement_amount_exceeds_maximum" };
    }
    try {
      const bound = await this.store.bindActualAmount({ token: reservation.token, amount });
      if (bound.kind === "out_of_window") {
        return { abort: true, reason: "upto_bsv_authorization_out_of_window" };
      }
      if (bound.kind === "unavailable") {
        return { abort: true, reason: "upto_bsv_authorization_unavailable" };
      }
      this.requests.set(context.paymentPayload, { ...reservation, amount });
      return undefined;
    } catch (error) {
      return abort("upto_bsv_authorization_unavailable", error);
    }
  }
}

/**
 * Validates a canonical amount within the BSV supply.
 *
 * @param value - Candidate amount
 * @param allowZero - Whether zero is accepted
 * @returns Canonical amount
 */
function readAmount(value: unknown, allowZero: boolean): string {
  if (
    typeof value !== "string" ||
    !CANONICAL_AMOUNT.test(value) ||
    (!allowZero && value === "0") ||
    BigInt(value) > BigInt(MAX_SATOSHIS)
  ) {
    throw new Error("amount is not a canonical BSV amount");
  }
  return value;
}

/**
 * Creates an abort directive without exposing thrown values to protocol fields.
 *
 * @param reason - Stable protocol failure reason
 * @param error - Internal validation error
 * @returns Core abort directive
 */
function abort(reason: string, error: unknown): { abort: true; reason: string; message?: string } {
  return {
    abort: true,
    reason,
    ...(error instanceof Error ? { message: error.message } : {}),
  };
}
