import { MAX_SATOSHIS } from "../../constants";
import { materializeVerifiedAuthorization, type VerifiedAuthorization } from "./transaction";

export const BSV_UPTO_AUTHORIZATION_RECEIPT_KEY = "bsvUptoAuthorization";

const LOWERCASE_DIGEST = /^[0-9a-f]{64}$/;
const CANONICAL_AMOUNT = /^(?:0|[1-9]\d*)$/;
const CANONICAL_OUTPOINT = /^[0-9a-f]{64}:(?:0|[1-9]\d{0,9})$/;

/** Verified authorization facts carried from facilitator to resource server. */
export interface UptoBsvVerificationReceipt {
  readonly authorizationId: string;
  readonly maximumAmount: string;
  readonly validAfter: number;
  readonly deadline: number;
  readonly outpoints: readonly string[];
}

/**
 * Creates a server receipt exclusively from an opaque verified authorization.
 *
 * @param authorization - Token issued by presented-authorization verification
 * @returns Detached JSON-safe receipt
 */
export function createUptoVerificationReceipt(
  authorization: VerifiedAuthorization,
): UptoBsvVerificationReceipt {
  const material = materializeVerifiedAuthorization(authorization);
  const authorizationId = material.authorizationId;
  return Object.freeze({
    authorizationId,
    maximumAmount: material.facts.maximumAmount,
    validAfter: material.facts.validAfter,
    deadline: material.facts.deadline,
    outpoints: Object.freeze(
      [...material.capInputs, ...material.controlInputs].map(
        source => `${source.sourceTxid}:${source.sourceOutputIndex}`,
      ),
    ),
  });
}

/**
 * Parses the trusted facilitator receipt consumed by the server hook.
 *
 * @param extra - VerifyResponse.extra
 * @param expectedMaximum - Resource-server maximum amount
 * @returns Closed verified authorization receipt
 */
export function readUptoVerificationReceipt(
  extra: unknown,
  expectedMaximum: string,
): UptoBsvVerificationReceipt {
  const container = readRecord(extra, "verification extra");
  const record = readRecord(container[BSV_UPTO_AUTHORIZATION_RECEIPT_KEY], "authorization receipt");
  const authorizationId = record.authorizationId;
  const maximumAmount = record.maximumAmount;
  const validAfter = record.validAfter;
  const deadline = record.deadline;
  const outpointsRaw = record.outpoints;
  if (typeof authorizationId !== "string" || !LOWERCASE_DIGEST.test(authorizationId)) {
    throw new Error("authorizationId is invalid");
  }
  const maximum = readAmount(maximumAmount);
  if (maximum !== expectedMaximum) throw new Error("authorization maximum differs from verify");
  const start = readUint32(validAfter, "validAfter");
  const end = readUint32(deadline, "deadline");
  if (start < 500_000_000 || start >= end) throw new Error("authorization window is invalid");
  return Object.freeze({
    authorizationId,
    maximumAmount: maximum,
    validAfter: start,
    deadline: end,
    outpoints: readOutpoints(outpointsRaw),
  });
}

/**
 * Reads one plain property record.
 *
 * @param value - Candidate object
 * @param field - Field name used in failures
 * @returns Property record
 */
function readRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${field} is missing`);
  }
  return value as Record<string, unknown>;
}

/**
 * Captures canonical source outpoints from a verified receipt.
 *
 * @param value - Candidate outpoint array
 * @returns Detached canonical outpoints
 */
function readOutpoints(value: unknown): readonly string[] {
  if (!Array.isArray(value)) throw new Error("authorization outpoints must be non-empty");
  const length = value.length;
  if (length === 0) throw new Error("authorization outpoints must be non-empty");
  const result = new Array<string>(length);
  const seen = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const outpoint = value[index];
    if (typeof outpoint !== "string" || !CANONICAL_OUTPOINT.test(outpoint)) {
      throw new Error("authorization outpoint is invalid");
    }
    const outputIndex = outpoint.slice(outpoint.indexOf(":") + 1);
    if (BigInt(outputIndex) > 0xffffffffn || seen.has(outpoint)) {
      throw new Error("authorization outpoint is invalid");
    }
    seen.add(outpoint);
    result[index] = outpoint;
  }
  return Object.freeze(result);
}

/**
 * Validates a positive canonical amount within the BSV supply.
 *
 * @param value - Candidate maximum amount
 * @returns Canonical amount
 */
function readAmount(value: unknown): string {
  if (
    typeof value !== "string" ||
    !CANONICAL_AMOUNT.test(value) ||
    value === "0" ||
    BigInt(value) > BigInt(MAX_SATOSHIS)
  ) {
    throw new Error("maximum amount is not a canonical BSV amount");
  }
  return value;
}

/**
 * Validates one uint32 window value.
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
    value > 0xffffffff
  ) {
    throw new Error(`${field} must be a uint32 integer`);
  }
  return value;
}
