import type {
  AssetAmount,
  MoneyParser,
  Network,
  PaymentRequirements,
  Price,
  SchemeNetworkServer,
} from "@x402/core/types";
import type { SettleContext } from "@x402/core/server";
import { ExactBsvScheme } from "../../exact/server/scheme";
import type { UptoBsvTransactionVersion } from "../../types";

/** Resolves the fully signed transaction selected for one settle call. */
export type UptoBsvTransactionVersionProvider = (
  context: SettleContext,
) => UptoBsvTransactionVersion | Promise<UptoBsvTransactionVersion>;

/** Application integration used to select the transaction to settle. */
export interface UptoBsvServerConfig {
  getTransactionVersion: UptoBsvTransactionVersionProvider;
}

/**
 * BSV server scheme for upto payments.
 *
 * Upto changes when the final amount is selected, not how BSV prices or
 * assets are represented. This adapter therefore delegates those rules to
 * the exact scheme and only preserves the `upto` scheme identity.
 */
export class UptoBsvScheme implements SchemeNetworkServer {
  readonly scheme = "upto";
  private readonly exact = new ExactBsvScheme();
  private readonly getTransactionVersion: UptoBsvTransactionVersionProvider;

  /**
   * Creates a BSV upto server adapter.
   *
   * @param config - Required signed-transaction selector
   */
  constructor(config: UptoBsvServerConfig) {
    if (!config || typeof config.getTransactionVersion !== "function") {
      throw new Error("getTransactionVersion is required for BSV upto settlement");
    }
    this.getTransactionVersion = config.getTransactionVersion;
  }

  /**
   * The exact-compatible BSV asset transfer method.
   *
   * @returns The default transfer method
   */
  get defaultAssetTransferMethod(): string {
    return this.exact.defaultAssetTransferMethod;
  }

  /**
   * The exact-compatible authorization payment flow.
   *
   * @returns The supported payment flow map
   */
  get paymentFlows(): ExactBsvScheme["paymentFlows"] {
    return this.exact.paymentFlows;
  }

  /**
   * Registers an exact-compatible money parser.
   *
   * @param parser - Custom function returning an asset amount or null
   * @returns This instance for chaining
   */
  registerMoneyParser(parser: MoneyParser): this {
    this.exact.registerMoneyParser(parser);
    return this;
  }

  /**
   * Parses a BSV price using the exact scheme's native-satoshi rules.
   *
   * @param price - Price to parse
   * @param network - BSV network identifier
   * @returns Parsed asset amount
   */
  parsePrice(price: Price, network: Network): Promise<AssetAmount> {
    return this.exact.parsePrice(price, network);
  }

  /**
   * Returns the exact scheme's precision for a BSV asset.
   *
   * @param asset - Asset identifier
   * @param network - BSV network identifier
   * @returns The asset precision
   */
  getAssetDecimals(asset: string, network: Network): number {
    return this.exact.getAssetDecimals(asset, network);
  }

  /**
   * Applies the exact scheme's BSV asset and facilitator-extra rules while
   * retaining `upto` as the payment scheme.
   *
   * @param requirements - Payment requirements to enhance
   * @param supportedKind - Facilitator-supported scheme and network metadata
   * @param supportedKind.x402Version - X402 protocol version
   * @param supportedKind.scheme - Payment scheme identifier
   * @param supportedKind.network - BSV network identifier
   * @param supportedKind.extra - Optional facilitator metadata
   * @param extensionKeys - Extension keys to apply
   * @returns Enhanced upto requirements
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
      { ...requirements, scheme: this.scheme },
      supportedKind,
      extensionKeys,
    );

    return { ...enhanced, scheme: this.scheme };
  }

  /**
   * Adds the signed transaction selected by the application to a settle-local payload.
   *
   * The core settlement phase is passed through unchanged; the application selects
   * one ordinary, fully signed transaction for that settle call.
   *
   * @param context - The settlement invocation being enriched
   * @returns The selected transaction version
   */
  enrichSettlementPayload = async (context: SettleContext): Promise<Record<string, unknown>> => {
    const transactionVersion = await this.getTransactionVersion(context);
    if (!transactionVersion) {
      throw new Error(
        `No signed BSV upto transaction version is available for ${context.phase} settlement`,
      );
    }
    return { transactionVersion };
  };
}
