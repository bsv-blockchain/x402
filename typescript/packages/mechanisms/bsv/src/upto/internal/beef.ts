import { Beef, Utils, type Transaction } from "@bsv/sdk";
import { BoundedReader } from "./boundedReader";

/** One complete transaction reachable from an Atomic BEEF subject. */
export interface AtomicSubjectTransaction {
  readonly txid: string;
  readonly transaction: Transaction;
  readonly isProven: boolean;
}

/**
 * Decodes canonical padded base64 within a finite Atomic BEEF budget.
 *
 * @param value - Candidate wire value
 * @param maximumBytes - Maximum decoded bytes
 * @param label - Error-message subject
 * @returns Independent decoded bytes
 */
export function decodeCanonicalAtomicBeef(
  value: unknown,
  maximumBytes: number,
  label: string,
): Uint8Array {
  const maximumEncodedLength = Math.ceil(maximumBytes / 3) * 4;
  if (typeof value !== "string") {
    throw new Error(`${label} must be canonical padded base64`);
  }
  if (value.length > maximumEncodedLength) {
    throw new Error(`${label} exceeds policy`);
  }
  let decoded: number[];
  try {
    decoded = Utils.toArray(value, "base64");
  } catch {
    throw new Error(`${label} must be canonical padded base64`);
  }
  if (decoded.length > maximumBytes) throw new Error(`${label} exceeds policy`);
  if (Utils.toBase64(decoded) !== value) {
    throw new Error(`${label} must be canonical padded base64`);
  }
  return Uint8Array.from(decoded);
}

/**
 * Parses exactly one bounded Atomic BEEF envelope.
 *
 * @param bytes - Captured Atomic BEEF bytes
 * @param label - Error-message subject
 * @returns Parsed BEEF with exact consumption
 */
export function parseAtomicBeef(bytes: Uint8Array, label: string): Beef {
  const reader = new BoundedReader(bytes);
  let beef: Beef;
  try {
    beef = Beef.fromReader(reader);
  } catch {
    throw new Error(`${label} is malformed`);
  }
  if (reader.pos !== bytes.length) throw new Error(`${label} has trailing bytes`);
  return beef;
}

/**
 * Resolves the complete ancestry needed by an Atomic BEEF subject.
 *
 * @param beef - Parsed Atomic BEEF
 * @param subjectTxid - Atomic subject transaction id
 * @param label - Error-message prefix for the calling boundary
 * @returns Complete transactions in the subject closure
 */
export function collectAtomicSubjectClosure(
  beef: Beef,
  subjectTxid: string,
  label: string,
): readonly AtomicSubjectTransaction[] {
  const entries = new Map<string, (typeof beef.txs)[number]>();
  for (const entry of beef.txs) {
    if (entries.has(entry.txid)) {
      throw new Error(`${label} contains duplicate transactions`);
    }
    entries.set(entry.txid, entry);
  }

  const reachable = new Set<string>();
  const pending = [subjectTxid];
  const transactions: AtomicSubjectTransaction[] = [];
  while (pending.length > 0) {
    const txid = pending.pop() as string;
    if (reachable.has(txid)) continue;
    const entry = entries.get(txid);
    if (entry === undefined || entry.tx === undefined) {
      throw new Error(`${label} is missing subject ancestry`);
    }
    reachable.add(txid);
    transactions.push({
      txid,
      transaction: entry.tx,
      isProven: entry.bumpIndex !== undefined,
    });
    const bumpIndex = entry.bumpIndex;
    if (bumpIndex !== undefined) {
      const bump = beef.bumps[bumpIndex];
      if (bump === undefined || !bump.path[0]?.some(leaf => leaf.hash === txid)) {
        throw new Error(`${label} has an invalid proof association`);
      }
      continue;
    }
    for (const input of entry.tx.inputs) {
      const parent = input.sourceTXID ?? input.sourceTransaction?.id("hex");
      if (parent === undefined) throw new Error(`${label} is missing input ancestry`);
      pending.push(parent);
    }
  }
  return Object.freeze(transactions);
}
