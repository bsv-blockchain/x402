import { Random, Utils } from "@bsv/sdk";
import { MAX_SATOSHIS } from "../../constants";

const LOWERCASE_DIGEST = /^[0-9a-f]{64}$/;
const CANONICAL_AMOUNT = /^(?:0|[1-9]\d*)$/;
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const UINT32_MAX = 0xffffffff;

/** Store-issued opaque token for the one wallet attempt associated with a selection. */
export type TerminalStoreToken = string;

/** Verified facts identifying one exact terminal transaction. */
export interface VerifiedTerminalRecord {
  readonly authorizationId: string;
  readonly txid: string;
  readonly amount: string;
  readonly subjectTransaction: string;
  readonly settlementTransaction: string;
}

/** Observable terminal selection stored by the facilitator. */
export type TerminalStoreRecord =
  | { readonly kind: "selected"; readonly terminal: VerifiedTerminalRecord }
  | { readonly kind: "accepted"; readonly terminal: VerifiedTerminalRecord };

/** Result of atomically selecting a verified terminal. */
export type TerminalSelectionResult =
  | {
      readonly kind: "selected";
      readonly token: TerminalStoreToken;
      readonly terminal: VerifiedTerminalRecord;
    }
  | { readonly kind: "accepted"; readonly terminal: VerifiedTerminalRecord }
  | { readonly kind: "unavailable" };

/** Result of recording wallet acceptance for later terminal replay. */
export type TerminalAcceptanceResult =
  | { readonly kind: "accepted"; readonly terminal: VerifiedTerminalRecord }
  | { readonly kind: "unavailable" };

/**
 * Durable first-writer seam for facilitator terminal selection and replay.
 *
 * A terminal's identity is its authorization id, txid, amount, and raw subject
 * transaction bytes. Its settlement transaction is an Atomic BEEF transport
 * envelope and may differ when a later verified envelope carries stronger
 * proof for the same subject. An adapter MUST retain the first selected
 * identity and return it for that authorization; it MUST NOT substitute or
 * re-synthesize terminal facts. When an accepted record and a proposal have
 * the same identity, `select` returns the stored record even if their envelopes
 * differ.
 *
 * Selection MUST atomically evaluate `validAfter <= now < deadline` against an
 * authoritative clock. Its opaque token grants one caller one wallet attempt;
 * `recordAccepted` records the result for later replay. The store is trusted
 * to preserve the selected identity and evidence bytes but is not authoritative
 * for the continuing validity of a BEEF envelope; callers revalidate evidence
 * before replay. The store may be unavailable, in which case callers fail
 * closed. It does not verify transactions, enhance BEEF, invoke wallets,
 * provide an outbox, or make wallet effects exactly once.
 */
export interface TerminalStore {
  read(authorizationId: string): Promise<TerminalStoreRecord | undefined>;
  select(input: {
    readonly terminal: VerifiedTerminalRecord;
    readonly validAfter: number;
    readonly deadline: number;
  }): Promise<TerminalSelectionResult>;
  recordAccepted(input: {
    readonly token: TerminalStoreToken;
    readonly txid: string;
  }): Promise<TerminalAcceptanceResult>;
}

interface TerminalEntry {
  readonly terminal: VerifiedTerminalRecord;
  accepted: boolean;
}

/** Clock used by the single-process terminal-store reference implementation. */
export interface InMemoryTerminalStoreOptions {
  readonly now?: () => number;
}

/**
 * Single-process reference implementation of {@link TerminalStore}.
 *
 * Production deployments that span processes or must survive restarts need a
 * durable implementation providing equivalent atomic first-writer behavior.
 * This class deliberately stores no wallet journal, outbox, lease, or retry
 * state beyond the selected terminal and accepted outcome, and it retains the
 * originally selected Atomic BEEF verbatim rather than re-synthesizing or
 * enhancing envelopes.
 */
export class InMemoryTerminalStore implements TerminalStore {
  private readonly entries = new Map<string, TerminalEntry>();
  private readonly tokens = new Map<TerminalStoreToken, TerminalEntry>();
  private readonly clock: () => number;

  /**
   * Creates an in-memory store whose clock is read inside terminal selection.
   *
   * @param options - Optional deterministic Unix-second clock for tests
   */
  constructor(options: InMemoryTerminalStoreOptions = {}) {
    const clock = options.now ?? (() => Math.floor(Date.now() / 1000));
    if (typeof clock !== "function") throw new Error("terminal store now must be a function");
    this.clock = clock;
  }

  /**
   * Reads the local selected or accepted terminal record.
   *
   * @param authorizationId - Canonical authorization digest
   * @returns A detached record when this store selected a terminal
   */
  async read(authorizationId: string): Promise<TerminalStoreRecord | undefined> {
    const id = readDigest(authorizationId, "authorizationId");
    const entry = this.entries.get(id);
    return entry === undefined ? undefined : snapshotStoreRecord(entry);
  }

  /**
   * Atomically selects the first verified terminal within its validity window.
   *
   * The store reads its authoritative clock as part of the same synchronous
   * first-writer operation. Durable adapters MUST provide the equivalent
   * atomic window predicate in their storage transaction.
   *
   * @param input - Verified terminal and its Unix-second validity window
   * @param input.terminal - Fully verified terminal facts to select
   * @param input.validAfter - Inclusive authorization start
   * @param input.deadline - Strict authorization deadline in Unix seconds
   * @returns A one-use wallet-attempt token, an accepted replay, or unavailable
   */
  async select(input: {
    readonly terminal: VerifiedTerminalRecord;
    readonly validAfter: number;
    readonly deadline: number;
  }): Promise<TerminalSelectionResult> {
    const terminal = snapshotTerminal(input.terminal);
    const validAfter = readUint32(input.validAfter, "validAfter");
    const deadline = readUint32(input.deadline, "deadline");
    if (validAfter >= deadline) throw new Error("terminal selection window must be non-empty");
    const existing = this.entries.get(terminal.authorizationId);

    if (existing !== undefined) {
      if (existing.accepted && sameTerminalIdentity(existing.terminal, terminal)) {
        return { kind: "accepted", terminal: cloneTerminal(existing.terminal) };
      }
      return { kind: "unavailable" };
    }
    const now = readUint32(this.clock(), "now");
    if (now < validAfter || now >= deadline) return { kind: "unavailable" };

    const token = this.createToken();
    const entry: TerminalEntry = { terminal, accepted: false };
    this.entries.set(terminal.authorizationId, entry);
    this.tokens.set(token, entry);
    return { kind: "selected", token, terminal: cloneTerminal(terminal) };
  }

  /**
   * Records the one accepted outcome for later replay of the selected transaction.
   *
   * @param input - Selection token and wallet-accepted transaction id
   * @param input.token - Token returned to the terminal's first selector
   * @param input.txid - Transaction id accepted by the wallet operation
   * @returns The detached accepted terminal, or unavailable on any mismatch or replay
   */
  async recordAccepted(input: {
    readonly token: TerminalStoreToken;
    readonly txid: string;
  }): Promise<TerminalAcceptanceResult> {
    const token = input.token;
    const txid = readDigest(input.txid, "txid");
    const entry = this.tokens.get(token);
    if (entry === undefined || entry.accepted || entry.terminal.txid !== txid) {
      return { kind: "unavailable" };
    }

    entry.accepted = true;
    this.tokens.delete(token);
    return { kind: "accepted", terminal: cloneTerminal(entry.terminal) };
  }

  /**
   * Generates a unique opaque token for this store instance.
   *
   * @returns A new store token
   */
  private createToken(): TerminalStoreToken {
    let token: TerminalStoreToken;
    do {
      token = Utils.toBase64(Random(32));
    } while (this.tokens.has(token));
    return token;
  }
}

/**
 * Captures and structurally validates one already-verified terminal record.
 *
 * @param raw - Verified facts supplied by the transaction layer
 * @returns A detached terminal snapshot
 */
function snapshotTerminal(raw: VerifiedTerminalRecord): VerifiedTerminalRecord {
  const snapshot = {
    authorizationId: raw.authorizationId,
    txid: raw.txid,
    amount: raw.amount,
    subjectTransaction: raw.subjectTransaction,
    settlementTransaction: raw.settlementTransaction,
  };
  return {
    authorizationId: readDigest(snapshot.authorizationId, "authorizationId"),
    txid: readDigest(snapshot.txid, "txid"),
    amount: readAmount(snapshot.amount),
    subjectTransaction: readBase64(snapshot.subjectTransaction, "subjectTransaction"),
    settlementTransaction: readBase64(snapshot.settlementTransaction, "settlementTransaction"),
  };
}

/**
 * Returns a detached terminal object.
 *
 * @param terminal - Stored terminal facts
 * @returns A detached terminal record
 */
function cloneTerminal(terminal: VerifiedTerminalRecord): VerifiedTerminalRecord {
  return { ...terminal };
}

/**
 * Converts a private entry into a detached observable record.
 *
 * @param entry - Stored terminal entry
 * @returns A selected or accepted terminal record
 */
function snapshotStoreRecord(entry: TerminalEntry): TerminalStoreRecord {
  return {
    kind: entry.accepted ? "accepted" : "selected",
    terminal: cloneTerminal(entry.terminal),
  };
}

/**
 * Compares every selected terminal identity field.
 *
 * @param left - Previously selected terminal
 * @param right - Candidate terminal
 * @returns Whether the records identify the same exact terminal
 */
export function sameTerminalIdentity(
  left: VerifiedTerminalRecord,
  right: VerifiedTerminalRecord,
): boolean {
  return (
    left.authorizationId === right.authorizationId &&
    left.txid === right.txid &&
    left.amount === right.amount &&
    left.subjectTransaction === right.subjectTransaction
  );
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

/**
 * Validates a non-negative uint32 integer time value.
 *
 * @param value - Candidate Unix-second value
 * @param field - Field name used in failures
 * @returns The unchanged integer
 */
function readUint32(value: number, field: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < 0 ||
    value > UINT32_MAX
  ) {
    throw new Error(`${field} must be a uint32 integer`);
  }
  return value;
}

/**
 * Validates padded canonical base64 without interpreting its payload.
 *
 * @param value - Candidate base64 value
 * @param field - Field name used in failures
 * @returns The unchanged canonical value
 */
function readBase64(value: string, field: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !CANONICAL_BASE64.test(value) ||
    Utils.toBase64(Utils.toArray(value, "base64")) !== value
  ) {
    throw new Error(`${field} must be non-empty canonical base64`);
  }
  return value;
}
