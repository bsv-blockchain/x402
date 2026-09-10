import { PublicKey, Utils } from "@bsv/sdk";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import {
  BSV_ASSET_IDENTIFIER,
  COMPRESSED_PUBKEY_REGEX,
  MAX_SATOSHIS,
  MIN_DERIVATION_PREFIX_BYTES,
  isBsvNetwork,
} from "../../constants";
import type {
  UptoBsvCapInput,
  UptoBsvCapSource,
  UptoBsvControlOffer,
  UptoBsvPayload,
  UptoBsvSourceReference,
} from "../types";

const UINT32_MAX = 0xffffffff;
const CANONICAL_UNSIGNED_DECIMAL = /^(?:0|[1-9]\d*)$/;

/** Closed PaymentRequirements fields covered by a BSV upto authorization. */
export interface UptoBsvRequirementsSnapshot {
  readonly network: PaymentRequirements["network"];
  readonly asset: string;
  readonly maximumAmount: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  readonly control: UptoBsvControlOffer;
}

/** Closed wire data used by a role to admit and verify one authorization. */
export interface PresentedUptoPayment {
  readonly x402Version: 2;
  readonly network: PaymentRequirements["network"];
  readonly asset: string;
  readonly maximumAmount: string;
  readonly actualAmount: bigint;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  readonly control: UptoBsvControlOffer;
  readonly payload: UptoBsvPayload;
}

/** Whether requirements.amount is the signed maximum or the post-handler actual value. */
export type UptoPaymentPhase = "verify" | "settle";

/**
 * Captures and validates one advertised BSV upto requirement.
 *
 * Expensive BEEF parsing deliberately remains in source admission. This
 * boundary validates the complete cheap wire shape before role-specific
 * providers, signatures, stores, or wallets can be invoked.
 *
 * @param requirements - Candidate route or accepted requirement
 * @returns Detached, normalized signed terms
 */
export function snapshotUptoRequirements(
  requirements: PaymentRequirements,
): UptoBsvRequirementsSnapshot {
  if (typeof requirements !== "object" || requirements === null) {
    throw new Error("BSV upto requirements must be an object");
  }
  const raw = requirements as unknown as Record<string, unknown>;
  const scheme = raw.scheme;
  const network = raw.network;
  const asset = raw.asset;
  const amount = raw.amount;
  const payTo = raw.payTo;
  const maxTimeoutSeconds = raw.maxTimeoutSeconds;
  const extra = raw.extra;

  if (scheme !== "upto") throw new Error("BSV upto requirements scheme must be upto");
  if (typeof network !== "string" || !isBsvNetwork(network as PaymentRequirements["network"])) {
    throw new Error("BSV upto requirements network is unsupported");
  }
  const validatedNetwork = network as PaymentRequirements["network"];
  if (asset !== BSV_ASSET_IDENTIFIER) {
    throw new Error(`BSV upto requirements asset must be ${BSV_ASSET_IDENTIFIER}`);
  }
  const maximumAmount = readAmount(amount, "amount", false);
  const maximum = BigInt(maximumAmount);
  if (maximum === 0n || maximum > BigInt(MAX_SATOSHIS)) {
    throw new Error(`BSV upto requirements amount must be between 1 and ${MAX_SATOSHIS}`);
  }
  const normalizedPayTo = readPublicKey(payTo, "payTo");
  const timeout = readUint32(maxTimeoutSeconds, "maxTimeoutSeconds");
  if (timeout === 0) throw new Error("BSV upto maxTimeoutSeconds must be positive");
  const extraRecord = readRecord(extra, "extra");
  const controlRaw = extraRecord.control;
  const paymentFlow = extraRecord.paymentFlow;
  if (paymentFlow !== undefined && paymentFlow !== "authorization") {
    throw new Error("BSV upto paymentFlow must be authorization");
  }
  const control = snapshotControlOffer(controlRaw, timeout);

  return Object.freeze({
    network: validatedNetwork,
    asset,
    maximumAmount,
    payTo: normalizedPayTo,
    maxTimeoutSeconds: timeout,
    control,
  });
}

/**
 * Captures a complete presented payment and compares it with the route terms.
 *
 * @param payment - PaymentPayload carrying the signed maximum authorization
 * @param requirements - Route terms at verify, or amount-overridden terms at settle
 * @param phase - Determines whether requirements.amount is M or A
 * @returns Detached signed wire snapshot and phase amount
 */
export function snapshotPresentedUptoPayment(
  payment: PaymentPayload,
  requirements: PaymentRequirements,
  phase: UptoPaymentPhase,
): PresentedUptoPayment {
  if (typeof payment !== "object" || payment === null) {
    throw new Error("BSV upto payment payload must be an object");
  }
  const rawPayment = payment as unknown as Record<string, unknown>;
  const x402Version = rawPayment.x402Version;
  const acceptedRaw = rawPayment.accepted;
  const payloadRaw = rawPayment.payload;
  if (x402Version !== 2) throw new Error("BSV upto supports x402 version 2 only");
  if (phase !== "verify" && phase !== "settle") {
    throw new Error("BSV upto payment phase is invalid");
  }
  const accepted = snapshotUptoRequirements(acceptedRaw as unknown as PaymentRequirements);
  const current =
    phase === "verify"
      ? (() => {
          const verified = snapshotUptoRequirements(requirements);
          if (!sameControlOffer(verified.control, accepted.control)) {
            throw new Error("BSV upto requirements do not match accepted control offer");
          }
          return {
            scheme: "upto",
            network: verified.network,
            asset: verified.asset,
            amount: verified.maximumAmount,
            payTo: verified.payTo,
            maxTimeoutSeconds: verified.maxTimeoutSeconds,
          };
        })()
      : snapshotCommonRequirements(requirements);
  if (
    current.scheme !== "upto" ||
    current.network !== accepted.network ||
    current.asset !== accepted.asset ||
    current.payTo !== accepted.payTo ||
    current.maxTimeoutSeconds !== accepted.maxTimeoutSeconds
  ) {
    throw new Error("BSV upto requirements do not match accepted terms");
  }
  const currentAmount = readAmount(current.amount, "requirements.amount", true);
  const actualAmount = BigInt(currentAmount);
  const maximum = BigInt(accepted.maximumAmount);
  if (phase === "verify" && currentAmount !== accepted.maximumAmount) {
    throw new Error("BSV upto verify amount must equal the accepted maximum");
  }
  if (actualAmount > maximum) {
    throw new Error("BSV upto settlement amount exceeds maximum");
  }
  const parsedPayload = snapshotUptoPayload(payloadRaw);
  return Object.freeze({
    x402Version: 2,
    network: accepted.network,
    asset: accepted.asset,
    maximumAmount: accepted.maximumAmount,
    actualAmount,
    payTo: accepted.payTo,
    maxTimeoutSeconds: accepted.maxTimeoutSeconds,
    control: accepted.control,
    payload: parsedPayload,
  });
}

/**
 * Compares every signed control-offer field in its canonical order.
 *
 * @param left - First closed control offer
 * @param right - Second closed control offer
 * @returns Whether the offers are byte-field equivalent
 */
function sameControlOffer(left: UptoBsvControlOffer, right: UptoBsvControlOffer): boolean {
  if (
    left.validAfter !== right.validAfter ||
    left.deadline !== right.deadline ||
    left.inputs.length !== right.inputs.length
  ) {
    return false;
  }
  for (let index = 0; index < left.inputs.length; index += 1) {
    const a = left.inputs[index];
    const b = right.inputs[index];
    if (
      a.nonce !== b.nonce ||
      a.sourceTransaction !== b.sourceTransaction ||
      a.sourceOutputIndex !== b.sourceOutputIndex
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Validates one scheme-specific payload and returns a detached snapshot
 * of its validated wire fields.
 *
 * @param value - Candidate PaymentPayload.payload
 * @returns Detached validated wire fields
 */
export function snapshotUptoPayload(value: unknown): UptoBsvPayload {
  const record = readRecord(value, "payload");
  const senderIdentityKey = record.senderIdentityKey;
  const derivationPrefix = record.derivationPrefix;
  const derivationSuffix = record.derivationSuffix;
  const capInputsRaw = record.capInputs;
  const authorizationSignature = record.authorizationSignature;

  const capInputs = snapshotCapInputs(capInputsRaw);
  const prefix = readCanonicalBase64(derivationPrefix, "derivationPrefix");
  if (Utils.toArray(prefix, "base64").length < MIN_DERIVATION_PREFIX_BYTES) {
    throw new Error(
      `BSV upto derivationPrefix must contain at least ${MIN_DERIVATION_PREFIX_BYTES} bytes`,
    );
  }
  return Object.freeze({
    senderIdentityKey: readPublicKey(senderIdentityKey, "senderIdentityKey"),
    derivationPrefix: prefix,
    derivationSuffix: readCanonicalBase64(derivationSuffix, "derivationSuffix"),
    capInputs,
    authorizationSignature: readCanonicalBase64(authorizationSignature, "authorizationSignature"),
  });
}

/**
 * Captures cap sources returned by an application-owned reservation provider.
 *
 * @param value - Candidate ordered cap source list
 * @returns Detached cap source snapshot
 */
export function snapshotUptoCapSources(value: unknown): readonly UptoBsvCapSource[] {
  if (!Array.isArray(value)) throw new Error("BSV upto cap sources must be a non-empty array");
  const length = value.length;
  if (length === 0) throw new Error("BSV upto cap sources must be a non-empty array");
  const result = new Array<UptoBsvCapSource>(length);
  const nonces = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const record = readRecord(value[index], `capSources[${index}]`);
    const nonceRaw = record.nonce;
    const sourceTransaction = record.sourceTransaction;
    const sourceOutputIndex = record.sourceOutputIndex;
    const floorAmount = record.floorAmount;
    const nonce = readNonce(nonceRaw, `capSources[${index}].nonce`);
    if (nonces.has(nonce)) throw new Error("BSV upto cap source nonces must be unique");
    nonces.add(nonce);
    result[index] = Object.freeze({
      nonce,
      sourceTransaction: readNonEmptyString(
        sourceTransaction,
        `capSources[${index}].sourceTransaction`,
      ),
      sourceOutputIndex: readUint32(sourceOutputIndex, `capSources[${index}].sourceOutputIndex`),
      floorAmount: readAmount(floorAmount, `capSources[${index}].floorAmount`, false),
    });
  }
  return Object.freeze(result);
}

/**
 * Captures common settlement requirements without interpreting extra.
 *
 * @param requirements - Current facilitator requirements
 * @returns Detached common fields
 */
function snapshotCommonRequirements(requirements: PaymentRequirements) {
  if (typeof requirements !== "object" || requirements === null) {
    throw new Error("BSV upto requirements must be an object");
  }
  const raw = requirements as unknown as Record<string, unknown>;
  return {
    scheme: raw.scheme,
    network: raw.network,
    asset: raw.asset,
    amount: raw.amount,
    payTo: readPublicKey(raw.payTo, "payTo"),
    maxTimeoutSeconds: readUint32(raw.maxTimeoutSeconds, "maxTimeoutSeconds"),
  };
}

/**
 * Captures the recipient control offer.
 *
 * @param value - Candidate control object
 * @param maxTimeoutSeconds - Signed maximum authorization duration
 * @returns Detached control offer
 */
function snapshotControlOffer(value: unknown, maxTimeoutSeconds: number): UptoBsvControlOffer {
  const record = readRecord(value, "extra.control");
  const inputsRaw = record.inputs;
  const validAfterRaw = record.validAfter;
  const deadlineRaw = record.deadline;
  const inputs = snapshotSourceReferences(inputsRaw, "control.inputs");
  const validAfter = readUint32(validAfterRaw, "control.validAfter");
  const deadline = readUint32(deadlineRaw, "control.deadline");
  if (validAfter < 500_000_000 || validAfter >= deadline) {
    throw new Error("BSV upto control window is invalid");
  }
  if (deadline - validAfter > maxTimeoutSeconds) {
    throw new Error("BSV upto control window exceeds maxTimeoutSeconds");
  }
  return Object.freeze({ inputs, validAfter, deadline });
}

/**
 * Captures payer cap inputs and their wire signatures.
 *
 * @param value - Candidate cap input array
 * @returns Detached cap inputs
 */
function snapshotCapInputs(value: unknown): readonly UptoBsvCapInput[] {
  if (!Array.isArray(value)) throw new Error("BSV upto capInputs must be a non-empty array");
  const length = value.length;
  if (length === 0) throw new Error("BSV upto capInputs must be a non-empty array");
  const result = new Array<UptoBsvCapInput>(length);
  const nonces = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const record = readRecord(value[index], `capInputs[${index}]`);
    const nonce = readNonce(record.nonce, `capInputs[${index}].nonce`);
    const sourceTransaction = record.sourceTransaction;
    const sourceOutputIndex = record.sourceOutputIndex;
    const floorAmount = record.floorAmount;
    const transactionSignature = record.transactionSignature;
    if (nonces.has(nonce)) throw new Error("BSV upto cap source nonces must be unique");
    nonces.add(nonce);
    result[index] = Object.freeze({
      nonce,
      sourceTransaction: readNonEmptyString(
        sourceTransaction,
        `capInputs[${index}].sourceTransaction`,
      ),
      sourceOutputIndex: readUint32(sourceOutputIndex, `capInputs[${index}].sourceOutputIndex`),
      floorAmount: readAmount(floorAmount, `capInputs[${index}].floorAmount`, false),
      transactionSignature: readCanonicalBase64(
        transactionSignature,
        `capInputs[${index}].transactionSignature`,
      ),
    });
  }
  return Object.freeze(result);
}

/**
 * Captures an ordered non-empty list of source references.
 *
 * @param value - Candidate source array
 * @param field - Field name used in failures
 * @returns Detached source references
 */
function snapshotSourceReferences(
  value: unknown,
  field: string,
): readonly UptoBsvSourceReference[] {
  if (!Array.isArray(value)) throw new Error(`BSV upto ${field} must be a non-empty array`);
  const length = value.length;
  if (length === 0) throw new Error(`BSV upto ${field} must be a non-empty array`);
  const result = new Array<UptoBsvSourceReference>(length);
  const nonces = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const record = readRecord(value[index], `${field}[${index}]`);
    const nonceRaw = record.nonce;
    const sourceTransaction = record.sourceTransaction;
    const sourceOutputIndex = record.sourceOutputIndex;
    const nonce = readNonce(nonceRaw, `${field}[${index}].nonce`);
    if (nonces.has(nonce)) throw new Error(`BSV upto ${field} nonces must be unique`);
    nonces.add(nonce);
    result[index] = Object.freeze({
      nonce,
      sourceTransaction: readNonEmptyString(
        sourceTransaction,
        `${field}[${index}].sourceTransaction`,
      ),
      sourceOutputIndex: readUint32(sourceOutputIndex, `${field}[${index}].sourceOutputIndex`),
    });
  }
  return Object.freeze(result);
}

/**
 * Validates a non-array object and reads it as a field record.
 *
 * @param value - Candidate object
 * @param field - Field name used in failures
 * @returns Property record
 */
function readRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`BSV upto ${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Validates a canonical satoshi amount.
 *
 * @param value - Candidate amount
 * @param field - Field name used in failures
 * @param allowZero - Whether zero is accepted
 * @returns Canonical amount
 */
function readAmount(value: unknown, field: string, allowZero: boolean): string {
  if (typeof value !== "string" || !CANONICAL_UNSIGNED_DECIMAL.test(value)) {
    throw new Error(`BSV upto ${field} must be a canonical unsigned decimal`);
  }
  if (!allowZero && value === "0") throw new Error(`BSV upto ${field} must be positive`);
  if (BigInt(value) > BigInt(MAX_SATOSHIS)) {
    throw new Error(`BSV upto ${field} exceeds the maximum BSV supply`);
  }
  return value;
}

/**
 * Validates a uint32 JavaScript number.
 *
 * @param value - Candidate integer
 * @param field - Field name used in failures
 * @returns Valid uint32
 */
function readUint32(value: unknown, field: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0 ||
    value > UINT32_MAX
  ) {
    throw new Error(`BSV upto ${field} must be a uint32 integer`);
  }
  return value;
}

/**
 * Validates a compressed secp256k1 point and normalizes its spelling.
 *
 * @param value - Candidate public key
 * @param field - Field name used in failures
 * @returns Canonical compressed public key
 */
function readPublicKey(value: unknown, field: string): string {
  const encoded = readNonEmptyString(value, field).toLowerCase();
  if (!COMPRESSED_PUBKEY_REGEX.test(encoded)) {
    throw new Error(`BSV upto ${field} must be a compressed public key`);
  }
  try {
    return PublicKey.fromString(encoded).toString();
  } catch {
    throw new Error(`BSV upto ${field} must be a compressed public key`);
  }
}

/**
 * Validates a canonical 32-byte nonce.
 *
 * @param value - Candidate nonce
 * @param field - Field name used in failures
 * @returns Canonical base64 nonce
 */
function readNonce(value: unknown, field: string): string {
  const encoded = readCanonicalBase64(value, field);
  if (Utils.toArray(encoded, "base64").length !== 32) {
    throw new Error(`BSV upto ${field} must encode exactly 32 bytes`);
  }
  return encoded;
}

/**
 * Validates canonical padded standard base64.
 *
 * @param value - Candidate encoding
 * @param field - Field name used in failures
 * @returns Canonical base64
 */
function readCanonicalBase64(value: unknown, field: string): string {
  const encoded = readNonEmptyString(value, field);
  let decoded: number[];
  try {
    decoded = Utils.toArray(encoded, "base64");
  } catch {
    throw new Error(`BSV upto ${field} must be canonical base64`);
  }
  if (Utils.toBase64(decoded) !== encoded) {
    throw new Error(`BSV upto ${field} must be canonical base64`);
  }
  return encoded;
}

/**
 * Validates a non-empty string.
 *
 * @param value - Candidate string
 * @param field - Field name used in failures
 * @returns Non-empty string
 */
function readNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`BSV upto ${field} must be a non-empty string`);
  }
  return value;
}
