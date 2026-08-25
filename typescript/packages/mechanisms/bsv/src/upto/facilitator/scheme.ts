import { Utils } from "@bsv/sdk";
import type { WalletInterface } from "@bsv/sdk";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeNetworkFacilitator,
  SettleResponse,
  VerifyResponse,
} from "@x402/core/types";
import type {
  UptoBsvControlProposal,
  UptoBsvControlRequest,
  UptoBsvPayload,
  UptoBsvTransactionVersion,
} from "../../types";
import {
  BRC29_PROTOCOL_ID,
  BSV_ASSET_IDENTIFIER,
  BSV_WILDCARD_CAIP2,
  COMPRESSED_PUBKEY_REGEX,
  DEFAULT_PAYMENT_WINDOW_MS,
  MAX_SATOSHIS,
  MIN_DERIVATION_PREFIX_BYTES,
  isBsvNetwork,
  toBsvWalletNetwork,
} from "../../constants";
import { brc29PaymentKeyId, p2pkhLockingScript, uptoControlKeyId } from "../shared";
import {
  assertUptoVersionProgression,
  buildUptoTransactionVersion,
  findBeefOutput,
  uptoInputSatoshis,
  verifyUptoAuthorization,
  verifyUptoTransactionVersion,
  type BuildUptoBsvTransactionVersionArgs,
  type UptoBsvDigestSigner,
  type VerifiedUptoBsvAuthorization,
  type VerifiedUptoBsvTransactionVersion,
} from "../transaction";

const FINAL_SEQUENCE = 0xffffffff;
const SETTLEMENT_CACHE_TTL_FLOOR_MS = 600_000;
const SETTLEMENT_CACHE_TTL_MARGIN_MS = 60_000;

export interface UptoBsvSchemeConfig {
  /** Recipient BRC-100 wallet used for control signatures and settlement. */
  wallet: WalletInterface;
  /** Recipient identity key; must equal PaymentRequirements.payTo. */
  identityKey: string;
  /** Fixed miner fee reserved by every transaction version. */
  feeSatoshis: number;
  /** Value of the recipient control input; defaults to fee + 1 satoshi. */
  controlSatoshis?: number;
  /** Seconds before a non-final transaction becomes eligible; must be below maxTimeoutSeconds. */
  nonFinalDelaySeconds: number;
  paymentWindowMs?: number;
  originator?: string;
  /** Required full BEEF graph and PoW/SPV-anchor verifier. */
  verifyBeef: (beefBytes: number[], subjectTxid: string) => Promise<boolean>;
  /** Shared durable guard that atomically consumes one authorization at settlement. */
  settlementStore: UptoBsvSettlementStore;
}

/**
 * Atomic storage boundary for single-use BSV `upto` authorizations.
 *
 * Implementations must share claims between facilitator replicas and retain
 * them across restarts until at least `deleteAfterMs`. `tryClaim` atomically
 * inserts `(authorizationId, txid)` only when no unexpired claim exists.
 * `release` atomically removes only the acquisition identified by its opaque
 * token, which must be unique across replicas and restarts so a delayed release
 * cannot remove a later claim.
 */
export interface UptoBsvSettlementStore {
  tryClaim(
    authorizationId: string,
    txid: string,
    /** Earliest deletion time as Unix milliseconds. */
    deleteAfterMs: number,
  ): Promise<{ claimed: true; token: string } | { claimed: false; txid: string }>;
  release(authorizationId: string, token: string): Promise<void>;
}

export interface CreateUptoBsvVersionArgs {
  /** Expected charged-owner net delta. */
  amount: string;
  /** Last fully signed version accepted locally; required to advance a stream. */
  previous?: UptoBsvTransactionVersion;
  /** Finalize every control input so nLockTime no longer delays settlement. */
  cooperativeClose?: boolean;
  /** Advanced multi-input/output allocation; default two-party allocation when omitted. */
  outputAmounts?: readonly string[];
}

interface AuthorizationCheck {
  parsed: UptoBsvPayload;
  verified: VerifiedUptoBsvAuthorization;
  payer: string;
}

/**
 * BSV facilitator for `upto` authorizations and their terminal transaction.
 *
 * The recipient wallet supplies only a small control input. It signs each
 * ordinary transaction version with `ALL|FORKID`; the payer's reusable cap
 * signature fixes the maximum debit. Settlement uses the same BRC-29 remittance,
 * BEEF transport, wallet network, and `internalizeAction` path as BSV exact.
 * The settlement store consumes an authorization across replicas and restarts.
 * It does not make a pre-settlement application handler exactly-once;
 * non-idempotent handlers need a separate application-level shared reservation.
 */
export class UptoBsvScheme implements SchemeNetworkFacilitator {
  readonly scheme = "upto";
  readonly caipFamily = BSV_WILDCARD_CAIP2;

  private readonly wallet: WalletInterface;
  private readonly identityKey: string;
  private readonly feeSatoshis: number;
  private readonly controlSatoshis: number;
  private readonly nonFinalDelaySeconds: number;
  private readonly paymentWindowMs: number;
  private readonly originator?: string;
  private readonly verifyBeef: (beefBytes: number[], subjectTxid: string) => Promise<boolean>;
  private readonly settlementStore: UptoBsvSettlementStore;
  private walletNetworkPromise: Promise<string> | undefined;

  /**
   * Creates a recipient-wallet facilitator.
   *
   * @param config - Recipient wallet, fixed fee, and validation options
   */
  constructor(config: UptoBsvSchemeConfig) {
    if (!config.identityKey || !COMPRESSED_PUBKEY_REGEX.test(config.identityKey)) {
      throw new Error("identityKey must be a compressed secp256k1 public key");
    }
    if (!Number.isSafeInteger(config.feeSatoshis) || config.feeSatoshis < 0) {
      throw new Error("feeSatoshis must be a non-negative safe integer");
    }
    if (!Number.isSafeInteger(config.nonFinalDelaySeconds) || config.nonFinalDelaySeconds <= 0) {
      throw new Error("nonFinalDelaySeconds must be a positive safe integer");
    }
    if (typeof config.verifyBeef !== "function") {
      throw new Error("verifyBeef is required for BSV upto authorization");
    }
    if (
      !config.settlementStore ||
      typeof config.settlementStore.tryClaim !== "function" ||
      typeof config.settlementStore.release !== "function"
    ) {
      throw new Error("settlementStore is required for BSV upto settlement");
    }
    const controlSatoshis = config.controlSatoshis ?? config.feeSatoshis + 1;
    if (
      !Number.isSafeInteger(controlSatoshis) ||
      controlSatoshis <= config.feeSatoshis ||
      controlSatoshis > MAX_SATOSHIS
    ) {
      throw new Error("controlSatoshis must be a safe integer greater than feeSatoshis");
    }
    this.wallet = config.wallet;
    this.identityKey = config.identityKey.toLowerCase();
    this.feeSatoshis = config.feeSatoshis;
    this.controlSatoshis = controlSatoshis;
    this.nonFinalDelaySeconds = config.nonFinalDelaySeconds;
    this.paymentWindowMs = config.paymentWindowMs ?? DEFAULT_PAYMENT_WINDOW_MS;
    this.originator = config.originator;
    this.verifyBeef = config.verifyBeef;
    this.settlementStore = config.settlementStore;
  }

  /**
   * Fetches the recipient identity key from its BRC-100 wallet.
   *
   * @param config - Configuration without identityKey
   * @returns Ready-to-register upto facilitator
   */
  static async create(config: Omit<UptoBsvSchemeConfig, "identityKey">): Promise<UptoBsvScheme> {
    const { publicKey } = await config.wallet.getPublicKey(
      { identityKey: true },
      config.originator,
    );
    return new UptoBsvScheme({ ...config, identityKey: publicKey });
  }

  /**
   * Returns no static fee-payer metadata; the control proposal is per payment.
   *
   * @param _ - Network identifier
   * @returns Undefined
   */
  getExtra(_: Network): Record<string, unknown> | undefined {
    return undefined;
  }

  /**
   * Returns the recipient wallet identity key.
   *
   * @param _ - Network identifier
   * @returns One recipient identity key
   */
  getSigners(_: string): string[] {
    return [this.identityKey];
  }

  /**
   * Creates the recipient's small, no-send control input.
   *
   * This transport-neutral method is intended to be exposed by the recipient's
   * own service and supplied to the client as its `controlProvider`.
   *
   * @param request - Payer identity, BRC-29 derivation, maximum, and timeout
   * @returns Recipient-owned control input and immutable timing terms
   */
  async createControlProposal(request: UptoBsvControlRequest): Promise<UptoBsvControlProposal> {
    await this.validateControlRequest(request);
    const keyId = uptoControlKeyId(request.derivationPrefix, request.derivationSuffix, 0);
    const { publicKey } = await this.wallet.getPublicKey(
      {
        protocolID: BRC29_PROTOCOL_ID,
        keyID: keyId,
        counterparty: request.senderIdentityKey,
        forSelf: true,
      },
      this.originator,
    );
    const lockingScript = p2pkhLockingScript(publicKey);
    const action = await this.wallet.createAction(
      {
        description: "x402 upto control input",
        outputs: [
          {
            satoshis: this.controlSatoshis,
            lockingScript,
            outputDescription: "x402 upto control",
            customInstructions: JSON.stringify({
              senderIdentityKey: request.senderIdentityKey,
              derivationPrefix: request.derivationPrefix,
              derivationSuffix: request.derivationSuffix,
              keyId,
            }),
            tags: ["x402", "upto"],
          },
        ],
        labels: ["x402", "upto"],
        options: { noSend: true, randomizeOutputs: false },
      },
      this.originator,
    );
    if (!action.tx) throw new Error("Wallet createAction did not return a control transaction");
    const sourceTransaction = Utils.toBase64(Array.from(action.tx));
    const { outputIndex } = findBeefOutput(sourceTransaction, lockingScript, this.controlSatoshis);
    const validAfter = Math.floor(Date.now() / 1000);
    const nLockTime = validAfter + this.nonFinalDelaySeconds;
    const deadline = validAfter + request.maxTimeoutSeconds;
    if (deadline > 0xffffffff) throw new Error("authorization timeout exceeds uint32 time");
    return {
      inputs: [
        {
          owner: this.identityKey,
          kind: "control",
          sourceTransaction,
          sourceOutputIndex: outputIndex,
          publicKey,
        },
      ],
      fee: String(this.feeSatoshis),
      sequenceStart: 1,
      validAfter,
      deadline,
      nLockTime,
    };
  }

  /**
   * Creates one fully signed transaction version for a negotiated amount or chunk.
   *
   * @param payload - Client authorization payload
   * @param requirements - Original requirements whose amount is the maximum
   * @param args - Actual amount, prior version, close flag, and optional output allocation
   * @returns Fully signed BEEF transaction version retained by both sides
   */
  async createTransactionVersion(
    payload: UptoBsvPayload,
    requirements: PaymentRequirements,
    args: CreateUptoBsvVersionArgs,
  ): Promise<UptoBsvTransactionVersion> {
    const check = await this.checkAuthorizationPayload(payload, requirements, "create");
    if (!/^\d+$/.test(args.amount) || BigInt(args.amount) > BigInt(check.verified.maximumAmount)) {
      throw new Error("transaction amount exceeds the authorized maximum");
    }
    const outputAmounts =
      args.outputAmounts ?? this.defaultOutputAmounts(check.verified, args.amount);
    this.assertRecipientReceipt(check.verified, outputAmounts, args.amount);
    const prior = args.previous
      ? verifyUptoTransactionVersion(check.verified.authorization, args.previous)
      : undefined;
    if (prior?.cooperativeClose) {
      throw new Error("a cooperatively closed transaction cannot advance");
    }
    if (!args.cooperativeClose && prior?.nSequence === FINAL_SEQUENCE - 1) {
      throw new Error("control nSequence is exhausted; cooperatively close instead");
    }
    const nSequence = args.cooperativeClose
      ? FINAL_SEQUENCE
      : prior
        ? prior.nSequence + 1
        : check.verified.terms.sequenceStart;
    const controlSigners: Record<number, UptoBsvDigestSigner> = {};
    let controlOrdinal = 0;
    check.verified.terms.inputs.forEach((input, index) => {
      if (input.kind !== "control") return;
      const expectedKeyId = uptoControlKeyId(
        payload.derivationPrefix,
        payload.derivationSuffix,
        controlOrdinal,
      );
      controlOrdinal += 1;
      controlSigners[index] = async digest => {
        const { signature } = await this.wallet.createSignature(
          {
            protocolID: BRC29_PROTOCOL_ID,
            keyID: expectedKeyId,
            counterparty: payload.senderIdentityKey,
            hashToDirectlySign: digest,
          },
          this.originator,
        );
        return Array.from(signature);
      };
    });
    const buildArgs: BuildUptoBsvTransactionVersionArgs = {
      nSequence,
      outputAmounts,
    };
    const version = await buildUptoTransactionVersion(
      check.verified.authorization,
      buildArgs,
      controlSigners,
    );
    const verifiedVersion = verifyUptoTransactionVersion(check.verified.authorization, version);
    if (verifiedVersion.amount !== args.amount) {
      throw new Error("output allocation does not equal the requested net amount");
    }
    if (args.previous) {
      assertUptoVersionProgression(check.verified.authorization, args.previous, version);
    }
    return version;
  }

  /**
   * Verifies a cap authorization before the resource handler runs.
   *
   * @param payload - x402 payload containing the signed authorization
   * @param requirements - Requirements whose amount is the maximum
   * @returns Verification result and payer identity
   */
  async verify(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<VerifyResponse> {
    try {
      const parsed = this.parsePayload(payload.payload);
      const checked = await this.checkAuthorizationPayload(parsed, requirements, "verify", payload);
      return { isValid: true, payer: checked.payer };
    } catch (error) {
      return {
        isValid: false,
        invalidReason: this.invalidReason(error),
        payer: this.payerFrom(payload.payload),
      };
    }
  }

  /**
   * Settles one locally unconsumed, fully signed transaction.
   *
   * @param payload - x402 payload enriched with transactionVersion
   * @param requirements - Settlement requirements whose amount is the actual charge
   * @returns Settlement response including the recomputed amount
   */
  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): Promise<SettleResponse> {
    const network = requirements.network;
    let parsed: UptoBsvPayload;
    let checked: AuthorizationCheck;
    try {
      parsed = this.parsePayload(payload.payload);
      checked = await this.checkAuthorizationPayload(parsed, requirements, "settle", payload);
    } catch (error) {
      return this.failure(network, this.payerFrom(payload.payload), this.invalidReason(error));
    }
    const version = parsed.transactionVersion;
    if (!version) return this.failure(network, checked.payer, "missing_transaction_version");

    let verifiedVersion: VerifiedUptoBsvTransactionVersion;
    try {
      verifiedVersion = verifyUptoTransactionVersion(checked.verified.authorization, version);
      if (!/^\d+$/.test(requirements.amount) || verifiedVersion.amount !== requirements.amount) {
        return this.failure(network, checked.payer, "invalid_upto_bsv_amount_mismatch");
      }
      this.assertRecipientReceipt(
        checked.verified,
        verifiedVersion.outputAmounts,
        verifiedVersion.amount,
      );
      if (
        !verifiedVersion.cooperativeClose &&
        Math.floor(Date.now() / 1000) < checked.verified.terms.nLockTime
      ) {
        return this.failure(network, checked.payer, "transaction_non_final");
      }
      const beefBytes = Utils.toArray(version.transaction, "base64");
      if (!(await this.verifyBeef(beefBytes, verifiedVersion.txid))) {
        return this.failure(network, checked.payer, "invalid_upto_bsv_spv");
      }
      const claimTime = Math.floor(Date.now() / 1000);
      if (
        claimTime < checked.verified.terms.validAfter ||
        claimTime >= checked.verified.terms.deadline
      ) {
        return this.failure(network, checked.payer, "upto_authorization_out_of_window");
      }
      if (!verifiedVersion.cooperativeClose && claimTime < checked.verified.terms.nLockTime) {
        return this.failure(network, checked.payer, "transaction_non_final");
      }
    } catch (error) {
      return this.failure(network, checked.payer, this.invalidReason(error));
    }

    const authorizationId = checked.verified.authorization.authorizationId;
    let claim: { claimed: true; token: string } | { claimed: false; txid: string };
    try {
      claim = await this.settlementStore.tryClaim(
        authorizationId,
        verifiedVersion.txid,
        this.settlementDeleteAfter(checked.verified.terms.deadline),
      );
    } catch {
      return this.failure(network, checked.payer, "settlement_store_unavailable");
    }
    if (!claim.claimed) {
      const reason =
        claim.txid === verifiedVersion.txid
          ? "duplicate_settlement"
          : "authorization_already_settled";
      return this.failure(network, checked.payer, reason);
    }
    const walletTime = Math.floor(Date.now() / 1000);
    if (
      walletTime < checked.verified.terms.validAfter ||
      walletTime >= checked.verified.terms.deadline
    ) {
      return this.failure(network, checked.payer, "upto_authorization_out_of_window");
    }
    if (!verifiedVersion.cooperativeClose && walletTime < checked.verified.terms.nLockTime) {
      return this.failure(network, checked.payer, "transaction_non_final");
    }
    const result = await this.internalize(
      parsed,
      checked,
      verifiedVersion,
      requirements,
      network,
      checked.payer,
    );
    if (!result.success && result.errorReason === "settlement_rejected_by_wallet") {
      try {
        await this.settlementStore.release(authorizationId, claim.token);
      } catch {
        return this.failure(network, checked.payer, "settlement_store_unavailable");
      }
    }
    return result;
  }

  /**
   * Builds the default two-party output allocation.
   *
   * @param authorization - Verified maximum-payment authorization
   * @param amount - Actual charged-owner net delta
   * @returns One satoshi value for every authorized output slot
   */
  private defaultOutputAmounts(
    authorization: VerifiedUptoBsvAuthorization,
    amount: string,
  ): string[] {
    const { terms, maximumAmount } = authorization;
    if (
      terms.inputs.filter(input => input.kind === "cap").length !== 1 ||
      terms.outputs.length !== 3 ||
      terms.paymentOutputIndexes.length !== 1 ||
      terms.paymentOutputIndexes[0] !== 2
    ) {
      throw new Error("multi-input/output authorization requires explicit outputAmounts");
    }
    const controlTotal = terms.inputs
      .filter(input => input.kind === "control")
      .reduce((sum, input) => sum + BigInt(uptoInputSatoshis(input)), 0n);
    const recipientAmount = controlTotal - BigInt(terms.fee) + BigInt(amount);
    if (recipientAmount < 0n) throw new Error("control inputs do not cover the fee");
    return [
      terms.outputs[0].fixedAmount ?? "0",
      (BigInt(maximumAmount) - BigInt(amount)).toString(),
      recipientAmount.toString(),
    ];
  }

  /**
   * Ensures the recipient's proven outputs cover the amount inferred from owner labels.
   *
   * `owner` is signed accounting metadata, not independent proof of script control. The
   * recipient therefore checks its BRC-29 payment outputs against its real control-input
   * contribution before signing or accepting a transaction.
   *
   * @param authorization - Verified authorization with resolved control input values
   * @param outputAmounts - Proposed or verified transaction output values
   * @param amount - Charged-owner amount inferred from the transaction
   */
  private assertRecipientReceipt(
    authorization: VerifiedUptoBsvAuthorization,
    outputAmounts: readonly string[],
    amount: string,
  ): void {
    const paymentTotal = authorization.terms.paymentOutputIndexes.reduce((sum, index) => {
      const value = outputAmounts[index];
      if (value === undefined || !/^\d+$/.test(value)) {
        throw new Error("invalid_upto_bsv_recipient_amount_shortfall");
      }
      return sum + BigInt(value);
    }, 0n);
    const controlTotal = authorization.terms.inputs
      .filter(input => input.kind === "control")
      .reduce((sum, input) => sum + BigInt(input.sourceSatoshis), 0n);
    const available = paymentTotal - controlTotal + BigInt(authorization.terms.fee);
    if (available < BigInt(amount)) {
      throw new Error("invalid_upto_bsv_recipient_amount_shortfall");
    }
  }

  /**
   * Parses the stable JSON payload shape.
   *
   * @param payload - Scheme-specific x402 payload object
   * @returns Parsed BSV upto payload
   */
  private parsePayload(payload: Record<string, unknown>): UptoBsvPayload {
    if (!payload || typeof payload !== "object") throw new Error("invalid_upto_bsv_payload_format");
    const parsed = payload as unknown as UptoBsvPayload;
    if (
      typeof parsed.derivationPrefix !== "string" ||
      typeof parsed.derivationSuffix !== "string" ||
      typeof parsed.senderIdentityKey !== "string" ||
      !Number.isInteger(parsed.outputIndex) ||
      !parsed.authorization ||
      typeof parsed.authorization !== "object"
    ) {
      throw new Error("invalid_upto_bsv_payload_format");
    }
    return parsed;
  }

  /**
   * Runs inherited exact checks plus maximum-authorization checks.
   *
   * @param parsed - Parsed BSV upto payload
   * @param requirements - Verification or settlement requirements
   * @param phase - Current facilitator phase
   * @param envelope - Optional full x402 payload for accepted-requirement checks
   * @returns Verified authorization context
   */
  private async checkAuthorizationPayload(
    parsed: UptoBsvPayload,
    requirements: PaymentRequirements,
    phase: "verify" | "create" | "settle",
    envelope?: PaymentPayload,
  ): Promise<AuthorizationCheck> {
    if (phase === "verify" && Object.prototype.hasOwnProperty.call(parsed, "transactionVersion")) {
      throw new Error("unexpected_transaction_version");
    }
    if (envelope && envelope.accepted.scheme !== this.scheme) throw new Error("unsupported_scheme");
    if (requirements.scheme !== this.scheme) throw new Error("unsupported_scheme");
    if (envelope && envelope.accepted.network !== requirements.network) {
      throw new Error("invalid_network");
    }
    if (!isBsvNetwork(requirements.network)) throw new Error("invalid_network");
    const asset = requirements.asset ?? BSV_ASSET_IDENTIFIER;
    if (asset !== "" && asset.toUpperCase() !== BSV_ASSET_IDENTIFIER) {
      throw new Error("invalid_upto_bsv_payload_asset");
    }
    if (!COMPRESSED_PUBKEY_REGEX.test(parsed.senderIdentityKey)) {
      throw new Error("invalid_upto_bsv_payload_sender_key");
    }
    if ((requirements.payTo ?? "").toLowerCase() !== this.identityKey) {
      throw new Error("invalid_upto_bsv_payload_payee_mismatch");
    }
    await this.assertWalletNetwork(requirements.network);
    this.assertTimestamp(parsed.derivationSuffix, requirements, phase);
    const prefix = Utils.toArray(parsed.derivationPrefix, "base64");
    if (prefix.length < MIN_DERIVATION_PREFIX_BYTES) {
      throw new Error("invalid_upto_bsv_payload_derivation_prefix");
    }
    const verified = verifyUptoAuthorization(parsed.authorization);
    const terms = verified.terms;
    if (
      terms.network !== requirements.network ||
      terms.asset !== "BSV" ||
      terms.payTo.toLowerCase() !== this.identityKey ||
      terms.senderIdentityKey.toLowerCase() !== parsed.senderIdentityKey.toLowerCase() ||
      terms.derivationPrefix !== parsed.derivationPrefix ||
      terms.derivationSuffix !== parsed.derivationSuffix ||
      terms.paymentOutputIndexes[0] !== parsed.outputIndex
    ) {
      throw new Error("invalid_upto_bsv_authorization_context");
    }
    const controlTotal = terms.inputs
      .filter(input => input.kind === "control")
      .reduce((sum, input) => sum + BigInt(input.sourceSatoshis), 0n);
    const lifetime = terms.deadline - terms.validAfter;
    if (
      terms.fee !== String(this.feeSatoshis) ||
      controlTotal !== BigInt(this.controlSatoshis) ||
      terms.sequenceStart !== 1 ||
      terms.nLockTime - terms.validAfter !== this.nonFinalDelaySeconds ||
      !Number.isSafeInteger(requirements.maxTimeoutSeconds) ||
      requirements.maxTimeoutSeconds <= 0 ||
      lifetime <= 0 ||
      lifetime > requirements.maxTimeoutSeconds
    ) {
      throw new Error("invalid_upto_bsv_facilitator_policy");
    }
    const maximum = envelope?.accepted.amount ?? requirements.amount;
    if (!/^\d+$/.test(maximum) || verified.maximumAmount !== maximum) {
      throw new Error("invalid_upto_bsv_maximum_mismatch");
    }
    const now = Math.floor(Date.now() / 1000);
    if (now < terms.validAfter || now >= terms.deadline) {
      throw new Error("upto_authorization_out_of_window");
    }
    if (phase !== "settle") {
      const checkedSources = new Set<string>();
      for (const input of terms.inputs) {
        const txid = input.source.id("hex");
        if (checkedSources.has(txid)) continue;
        checkedSources.add(txid);
        const valid = await this.verifyBeef(Utils.toArray(input.sourceTransaction, "base64"), txid);
        if (!valid) throw new Error("invalid_upto_bsv_source_spv");
      }
    }
    await this.assertRecipientKeys(parsed, verified);
    return { parsed, verified, payer: parsed.senderIdentityKey };
  }

  /**
   * Verifies that BRC-42 payment and control keys belong to payTo.
   *
   * @param parsed - Parsed payload carrying exact-compatible derivation data
   * @param authorization - Verified authorization whose scripts are checked
   */
  private async assertRecipientKeys(
    parsed: UptoBsvPayload,
    authorization: VerifiedUptoBsvAuthorization,
  ): Promise<void> {
    const paymentKey = await this.wallet.getPublicKey(
      {
        protocolID: BRC29_PROTOCOL_ID,
        keyID: brc29PaymentKeyId(parsed.derivationPrefix, parsed.derivationSuffix),
        counterparty: parsed.senderIdentityKey,
        forSelf: true,
      },
      this.originator,
    );
    const paymentScript = p2pkhLockingScript(paymentKey.publicKey);
    for (const index of authorization.terms.paymentOutputIndexes) {
      if (
        authorization.terms.outputs[index].lockingScript.toLowerCase() !==
        paymentScript.toLowerCase()
      ) {
        throw new Error("invalid_upto_bsv_payload_destination_mismatch");
      }
    }
    let ordinal = 0;
    for (const input of authorization.terms.inputs) {
      if (input.kind !== "control") continue;
      const keyId = uptoControlKeyId(parsed.derivationPrefix, parsed.derivationSuffix, ordinal);
      ordinal += 1;
      if (input.owner.toLowerCase() !== this.identityKey) {
        throw new Error("invalid_upto_bsv_control_identity");
      }
      const { publicKey } = await this.wallet.getPublicKey(
        {
          protocolID: BRC29_PROTOCOL_ID,
          keyID: keyId,
          counterparty: parsed.senderIdentityKey,
          forSelf: true,
        },
        this.originator,
      );
      if (publicKey.toLowerCase() !== input.publicKey.toLowerCase()) {
        throw new Error("invalid_upto_bsv_control_identity");
      }
    }
  }

  /**
   * Checks a control request before allocating a wallet output.
   *
   * @param request - Client request for a recipient-owned control input
   */
  private async validateControlRequest(request: UptoBsvControlRequest): Promise<void> {
    if (
      request.payTo.toLowerCase() !== this.identityKey ||
      !COMPRESSED_PUBKEY_REGEX.test(request.senderIdentityKey) ||
      !isBsvNetwork(request.network as Network) ||
      !/^\d+$/.test(request.maxAmount) ||
      BigInt(request.maxAmount) <= 0n ||
      BigInt(request.maxAmount) > BigInt(MAX_SATOSHIS) ||
      !Number.isSafeInteger(request.maxTimeoutSeconds) ||
      request.maxTimeoutSeconds <= this.nonFinalDelaySeconds
    ) {
      throw new Error("invalid BSV upto control request");
    }
    await this.assertWalletNetwork(request.network as Network);
    this.assertTimestamp(
      request.derivationSuffix,
      {
        scheme: this.scheme,
        network: request.network as Network,
        amount: request.maxAmount,
        asset: "BSV",
        payTo: request.payTo,
        maxTimeoutSeconds: request.maxTimeoutSeconds,
        extra: {},
      },
      "verify",
    );
  }

  /**
   * Ensures that wallet and requested BSV network agree.
   *
   * @param network - Requested BSV CAIP-2 network
   */
  private async assertWalletNetwork(network: Network): Promise<void> {
    const expected = toBsvWalletNetwork(network);
    if (!expected) throw new Error("invalid_network");
    try {
      this.walletNetworkPromise ??= this.wallet
        .getNetwork({}, this.originator)
        .then(result => result.network);
      if ((await this.walletNetworkPromise) !== expected) throw new Error("invalid_network");
    } catch (error) {
      if (error instanceof Error && error.message === "invalid_network") throw error;
      this.walletNetworkPromise = undefined;
      throw new Error("unexpected_verify_error");
    }
  }

  /**
   * Enforces the inherited BRC-121 freshness window.
   *
   * @param suffix - Base64 timestamp derivation suffix
   * @param requirements - Requirements supplying the settlement time budget
   * @param phase - Verification or settlement phase
   */
  private assertTimestamp(
    suffix: string,
    requirements: PaymentRequirements,
    phase: "verify" | "create" | "settle",
  ): void {
    let decoded: string;
    try {
      decoded = Utils.toUTF8(Utils.toArray(suffix, "base64"));
    } catch {
      throw new Error("invalid_upto_bsv_payload_timestamp");
    }
    if (!/^\d+$/.test(decoded)) throw new Error("invalid_upto_bsv_payload_timestamp");
    const timestamp = Number(decoded);
    const settleBudget = phase === "verify" ? 0 : requirements.maxTimeoutSeconds * 1000;
    const age = Date.now() - timestamp;
    if (
      !Number.isFinite(timestamp) ||
      age < -this.paymentWindowMs ||
      age > this.paymentWindowMs + settleBudget
    ) {
      throw new Error("invalid_upto_bsv_payload_timestamp_out_of_window");
    }
  }

  /**
   * Internalizes every recipient-owned BRC-29 output.
   *
   * @param parsed - Parsed BRC-29 remittance fields
   * @param checked - Verified authorization context
   * @param version - Verified fully signed transaction
   * @param requirements - Settlement requirements carrying the actual amount
   * @param network - BSV settlement network
   * @param payer - Verified payer identity key
   * @returns x402 settlement response
   */
  private async internalize(
    parsed: UptoBsvPayload,
    checked: AuthorizationCheck,
    version: VerifiedUptoBsvTransactionVersion,
    requirements: PaymentRequirements,
    network: Network,
    payer: string,
  ): Promise<SettleResponse> {
    try {
      const result = (await this.wallet.internalizeAction(
        {
          tx: Utils.toArray(version.version.transaction, "base64"),
          outputs: checked.verified.terms.paymentOutputIndexes.map(outputIndex => ({
            outputIndex,
            protocol: "wallet payment" as const,
            paymentRemittance: {
              derivationPrefix: parsed.derivationPrefix,
              derivationSuffix: parsed.derivationSuffix,
              senderIdentityKey: parsed.senderIdentityKey,
            },
          })),
          description: "x402 upto payment",
        },
        this.originator,
      )) as { accepted: boolean; isMerge?: boolean; satoshis?: number };
      const newlyInternalized = typeof result.satoshis === "number" && result.satoshis > 0;
      if (result.isMerge && !newlyInternalized) {
        return this.failure(network, payer, "duplicate_settlement");
      }
      if (result.accepted === false && !newlyInternalized) {
        return this.failure(network, payer, "settlement_rejected_by_wallet");
      }
      if (result.accepted !== true) {
        return this.failure(network, payer, "settlement_indeterminate: invalid wallet result");
      }
      return {
        success: true,
        network,
        transaction: version.txid,
        payer,
        amount: requirements.amount,
      };
    } catch (error) {
      return this.failure(
        network,
        payer,
        `settlement_indeterminate: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Retains a settlement claim past the signed authorization deadline.
   *
   * @param deadline - Signed authorization deadline in Unix seconds
   * @returns Earliest safe deletion time in Unix milliseconds
   */
  private settlementDeleteAfter(deadline: number): number {
    return Math.max(
      deadline * 1000 + SETTLEMENT_CACHE_TTL_MARGIN_MS,
      Date.now() + SETTLEMENT_CACHE_TTL_FLOOR_MS,
    );
  }

  /**
   * Converts one internal error into a stable invalidReason.
   *
   * @param error - Caught verification error
   * @returns Stable invalid reason string
   */
  private invalidReason(error: unknown): string {
    return error instanceof Error ? error.message : "unexpected_verify_error";
  }

  /**
   * Reads a claimed payer for failure responses only.
   *
   * @param payload - Untrusted scheme payload
   * @returns Claimed payer key or an empty string
   */
  private payerFrom(payload: Record<string, unknown>): string {
    return typeof payload?.senderIdentityKey === "string" ? payload.senderIdentityKey : "";
  }

  /**
   * Builds a failed settlement response.
   *
   * @param network - Requested settlement network
   * @param payer - Verified or claimed payer key
   * @param errorReason - Stable failure reason
   * @returns Failed x402 settlement response
   */
  private failure(network: Network, payer: string, errorReason: string): SettleResponse {
    return { success: false, network, transaction: "", payer, errorReason };
  }
}
