import { Random, Utils } from "@bsv/sdk";
import { MAX_SATOSHIS } from "../../constants";

const LOWERCASE_DIGEST = /^[0-9a-f]{64}$/;
const CANONICAL_AMOUNT = /^(?:0|[1-9]\d*)$/;
const CANONICAL_OUTPOINT = /^([0-9a-f]{64}):(0|[1-9]\d{0,9})$/;
const UINT32_MAX = 0xffffffffn;

/** Store-issued opaque token returned only to the admitted request. */
export type AuthorizationStoreToken = string;

/** Facts needed to reserve one authorization and all source outpoints it consumes. */
export interface AuthorizationAdmission {
  readonly authorizationId: string;
  readonly outpoints: readonly string[];
  /** Inclusive Unix-second start of the authorization window. */
  readonly validAfter: number;
  /** Exclusive Unix-second end of the authorization window. */
  readonly deadline: number;
}

/** Result of atomically admitting an authorization. */
export type AuthorizationAdmissionResult =
  | { readonly kind: "admitted"; readonly token: AuthorizationStoreToken }
  | { readonly kind: "unavailable" }
  | { readonly kind: "out_of_window" };

/** Result of binding the handler's actual amount. */
export type AmountBindingResult =
  | { readonly kind: "bound" }
  | { readonly kind: "unavailable" }
  | { readonly kind: "out_of_window" };

/**
 * Durable coordination seam for resource-server authorization admission.
 *
 * This interface coordinates only authorization/outpoint admission, one
 * actual-amount binding, and no settlement-response recovery. It does not provide
 * an outbox, recover handler side effects, or make wallet operations exactly once.
 * Implementations MUST use their own authoritative clock and evaluate each window
 * predicate atomically with its corresponding first write.
 */
export interface AuthorizationStore {
  admit(admission: AuthorizationAdmission): Promise<AuthorizationAdmissionResult>;
  bindActualAmount(input: {
    readonly token: AuthorizationStoreToken;
    readonly amount: string;
  }): Promise<AmountBindingResult>;
}

interface AuthorizationEntry {
  readonly validAfter: number;
  readonly deadline: number;
  amount?: string;
}

/**
 * Single-process reference implementation of {@link AuthorizationStore}.
 *
 * Production deployments that span processes or must survive restarts need a
 * durable implementation providing equivalent atomic first-writer behavior.
 * This class deliberately has no eviction, lease, retry, or recovery policy.
 */
export class InMemoryAuthorizationStore implements AuthorizationStore {
  private readonly authorizations = new Map<string, AuthorizationEntry>();
  private readonly outpointOwners = new Map<string, string>();
  private readonly tokens = new Map<AuthorizationStoreToken, AuthorizationEntry>();

  /**
   * Creates an in-memory store with an authoritative clock.
   *
   * @param clock - Unix-second clock used inside atomic store operations
   */
  constructor(private readonly clock: () => number = () => Math.floor(Date.now() / 1000)) {}

  /**
   * Atomically reserves one authorization and every supplied outpoint.
   *
   * The store evaluates `validAfter <= now < deadline` with its authoritative
   * clock in the same synchronous first-writer operation. Durable adapters MUST
   * provide the equivalent predicate in their storage transaction.
   *
   * @param admission - Canonical authorization, consumed outpoints, and validity window
   * @returns An opaque store token, an unavailable key, or an out-of-window result
   */
  async admit(admission: AuthorizationAdmission): Promise<AuthorizationAdmissionResult> {
    const authorizationId = readDigest(admission.authorizationId, "authorizationId");
    const outpoints = captureOutpoints(admission.outpoints);
    const validAfter = readUint32(admission.validAfter, "validAfter");
    const deadline = readUint32(admission.deadline, "deadline");
    if (validAfter >= deadline) throw new Error("authorization window must be non-empty");
    const now = readUint32(this.clock(), "now");
    if (now < validAfter || now >= deadline) return { kind: "out_of_window" };

    if (
      this.authorizations.has(authorizationId) ||
      outpoints.some(outpoint => this.outpointOwners.has(outpoint))
    ) {
      return { kind: "unavailable" };
    }

    const token = this.createToken();
    const entry: AuthorizationEntry = { validAfter, deadline };
    this.authorizations.set(authorizationId, entry);
    this.tokens.set(token, entry);
    for (const outpoint of outpoints) this.outpointOwners.set(outpoint, authorizationId);

    return { kind: "admitted", token };
  }

  /**
   * Binds one actual amount to the request holding the admission token.
   *
   * The store evaluates `validAfter <= now < deadline` in the same atomic
   * operation that first binds the amount.
   *
   * @param input - Opaque admission token and canonical actual amount
   * @param input.token - Token returned by the successful admission
   * @param input.amount - Canonical actual amount to bind
   * @returns Bound, unavailable, or out of window
   */
  async bindActualAmount(input: {
    readonly token: AuthorizationStoreToken;
    readonly amount: string;
  }): Promise<AmountBindingResult> {
    const token = input.token;
    const amount = readAmount(input.amount);
    const entry = this.tokens.get(token);
    if (!entry || entry.amount !== undefined) return { kind: "unavailable" };
    const now = readUint32(this.clock(), "now");
    if (now < entry.validAfter || now >= entry.deadline) return { kind: "out_of_window" };

    entry.amount = amount;
    this.tokens.delete(token);
    return { kind: "bound" };
  }

  /**
   * Generates a unique opaque token for this store instance.
   *
   * @returns A new store token
   */
  private createToken(): AuthorizationStoreToken {
    let token: AuthorizationStoreToken;
    do {
      token = Utils.toBase64(Random(32));
    } while (this.tokens.has(token));
    return token;
  }
}

/**
 * Validates canonical outpoints and stores an independent copy.
 *
 * @param raw - Candidate outpoint list
 * @returns A detached canonical outpoint list
 */
function captureOutpoints(raw: readonly string[]): string[] {
  if (!Array.isArray(raw)) {
    throw new Error("outpoints must be a non-empty array");
  }
  const length = raw.length;
  if (length === 0) {
    throw new Error("outpoints must be a non-empty array");
  }
  const outpoints = new Array<string>(length);
  const seen = new Set<string>();
  for (let index = 0; index < length; index += 1) {
    const outpoint = raw[index];
    if (typeof outpoint !== "string") throw new Error("outpoint must be a string");
    const match = CANONICAL_OUTPOINT.exec(outpoint);
    if (!match || BigInt(match[2]) > UINT32_MAX) {
      throw new Error("outpoint must use <lowercase txid>:<canonical uint32 vout>");
    }
    if (seen.has(outpoint)) throw new Error("outpoints must not contain duplicates");
    seen.add(outpoint);
    outpoints[index] = outpoint;
  }
  return outpoints;
}

/**
 * Validates a canonical authorization digest or transaction id.
 *
 * @param value - Candidate digest
 * @param field - Field name used in failures
 * @returns The unchanged digest
 */
function readDigest(value: string, field: string): string {
  if (typeof value !== "string" || !LOWERCASE_DIGEST.test(value)) {
    throw new Error(`${field} must be 64 lowercase hex characters`);
  }
  return value;
}

/**
 * Validates one uint32 clock or window value.
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

/**
 * Validates a canonical non-negative BSV amount.
 *
 * @param value - Candidate amount
 * @returns The unchanged canonical amount
 */
function readAmount(value: string): string {
  if (
    typeof value !== "string" ||
    !CANONICAL_AMOUNT.test(value) ||
    value.length > String(MAX_SATOSHIS).length ||
    BigInt(value) > BigInt(MAX_SATOSHIS)
  ) {
    throw new Error("amount must be a canonical amount within the BSV supply");
  }
  return value;
}
