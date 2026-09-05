import { P2PKH, PublicKey, Utils, type ChainTracker } from "@bsv/sdk";
import { COMPRESSED_PUBKEY_REGEX, MAX_SATOSHIS } from "../../constants";
import {
  collectAtomicSubjectClosure,
  decodeCanonicalAtomicBeef,
  parseAtomicBeef,
  type AtomicSubjectTransaction,
} from "./beef";

const FINAL_SEQUENCE = 0xffffffff;
const NULL_TXID = "00".repeat(32);
declare const admittedSourceBrand: unique symbol;

export interface SourceAdmissionPolicy {
  /** Maximum aggregate count of cap and control sources in one authorization. */
  maxSources: number;
  /** Maximum decoded Atomic BEEF bytes accepted for any one source. */
  maxAtomicBeefBytesPerSource: number;
}

export interface SourceCandidate {
  role: "cap" | "control";
  sourceTransaction: string;
  sourceOutputIndex: number;
  publicKey: string;
}

export interface AdmittedSource {
  readonly [admittedSourceBrand]: true;
  role: "cap" | "control";
  sourceTxid: string;
  sourceOutputIndex: number;
  satoshis: bigint;
  publicKey: string;
  lockingScriptHex: string;
}

interface SourceAdmitterOptions {
  chainTracker: ChainTracker;
  policy: SourceAdmissionPolicy;
}

interface SourceReferencePreflight {
  readonly sourceTransaction: unknown;
}

interface SourceCandidateSnapshot {
  role: "cap" | "control";
  sourceTransaction: string;
  sourceOutputIndex: number;
  publicKey: string;
}

interface SourceAuthority {
  atomicBeef: readonly number[];
  role: "cap" | "control";
  sourceTxid: string;
  sourceOutputIndex: number;
  publicKey: string;
}

const sourceAuthorities = new WeakMap<AdmittedSource, SourceAuthority>();

/**
 * Creates the internal seam that validates ordered cap and control sources.
 *
 * @param options - Chain facts and finite deployment limits
 * @returns A function that admits one ordered source set
 */
export function createSourceAdmitter(options: SourceAdmitterOptions) {
  const chainTracker = options.chainTracker;
  const rawPolicy = options.policy;
  const maxSources = readPositiveSafeInteger(rawPolicy.maxSources, "maxSources");
  const maxAtomicBeefBytesPerSource = readPositiveSafeInteger(
    rawPolicy.maxAtomicBeefBytesPerSource,
    "maxAtomicBeefBytesPerSource",
  );
  const maximumEncodedLength = Math.ceil(maxAtomicBeefBytesPerSource / 3) * 4;

  const preflight = (
    groups: readonly (readonly SourceReferencePreflight[])[],
    requiredAdditionalSources = 0,
  ): void => {
    if (!Array.isArray(groups)) {
      throw new Error("BSV upto source admission failed: source groups must be an array");
    }
    if (
      !Number.isSafeInteger(requiredAdditionalSources) ||
      requiredAdditionalSources < 0 ||
      Object.is(requiredAdditionalSources, -0)
    ) {
      throw new Error(
        "BSV upto source admission failed: reserved source count must be non-negative",
      );
    }
    const groupCount = groups.length;
    const lengths = new Array<number>(groupCount);
    let sourceCount = requiredAdditionalSources;
    for (let groupIndex = 0; groupIndex < groupCount; groupIndex += 1) {
      const group = groups[groupIndex];
      if (!Array.isArray(group)) {
        throw new Error("BSV upto source admission failed: source group must be an array");
      }
      const length = group.length;
      lengths[groupIndex] = length;
      if (length > maxSources - sourceCount) {
        throw new Error("BSV upto source admission failed: source count exceeds policy");
      }
      sourceCount += length;
    }
    for (let groupIndex = 0; groupIndex < groupCount; groupIndex += 1) {
      const group = groups[groupIndex];
      const length = lengths[groupIndex];
      for (let sourceIndex = 0; sourceIndex < length; sourceIndex += 1) {
        const source = group[sourceIndex];
        if (typeof source !== "object" || source === null) {
          throw new Error("BSV upto source admission failed: source must be an object");
        }
        const sourceTransaction = source.sourceTransaction;
        if (typeof sourceTransaction !== "string") {
          throw new Error("BSV upto source admission failed: sourceTransaction must be a string");
        }
        if (sourceTransaction.length > maximumEncodedLength) {
          throw new Error("BSV upto source admission failed: Atomic BEEF exceeds policy");
        }
      }
    }
  };

  const admit = async (
    candidates: readonly SourceCandidate[],
  ): Promise<readonly AdmittedSource[]> => {
    if (!Array.isArray(candidates)) {
      throw new Error("BSV upto source admission failed: sources must be an array");
    }
    const sourceCount = candidates.length;
    if (sourceCount > maxSources) {
      throw new Error("BSV upto source admission failed: source count exceeds policy");
    }
    const snapshots = new Array<SourceCandidateSnapshot>(sourceCount);
    for (let index = 0; index < sourceCount; index += 1) {
      const candidate = candidates[index];
      const role = candidate.role;
      if (role !== "cap" && role !== "control") {
        throw new Error("BSV upto source admission failed: role must be cap or control");
      }
      const sourceTransaction = candidate.sourceTransaction;
      if (typeof sourceTransaction !== "string") {
        throw new Error("BSV upto source admission failed: sourceTransaction must be a string");
      }
      const sourceOutputIndex = readUint32(candidate.sourceOutputIndex, "sourceOutputIndex");
      const publicKey = normalizeCompressedPublicKey(candidate.publicKey);
      if (sourceTransaction.length > maximumEncodedLength) {
        throw new Error("BSV upto source admission failed: Atomic BEEF exceeds policy");
      }
      snapshots[index] = { role, sourceTransaction, sourceOutputIndex, publicKey };
    }

    const admitted: AdmittedSource[] = [];
    const seenOutpoints = new Set<string>();
    const spendersByOutpoint = new Map<string, string>();

    for (let index = 0; index < sourceCount; index += 1) {
      const candidate = snapshots[index];
      const atomicBeefBytes = decodeCanonicalAtomicBeef(
        candidate.sourceTransaction,
        maxAtomicBeefBytesPerSource,
        "BSV upto source admission failed: Atomic BEEF",
      );
      const beef = parseAtomicBeef(
        atomicBeefBytes,
        "BSV upto source admission failed: Atomic BEEF",
      );
      const sourceTxid = beef.atomicTxid;
      if (sourceTxid === undefined) {
        throw new Error("BSV upto source admission failed: Atomic BEEF subject is missing");
      }
      const subjectClosure = collectAtomicSubjectClosure(
        beef,
        sourceTxid,
        "BSV upto source admission failed: Atomic BEEF",
      );
      assertTransactionInvariants(subjectClosure);
      let beefVerified = false;
      try {
        beefVerified = await beef.verify(chainTracker, false);
      } catch {
        beefVerified = false;
      }
      if (!beefVerified) {
        throw new Error("BSV upto source admission failed: invalid Atomic BEEF");
      }
      const outpoint = `${sourceTxid}:${candidate.sourceOutputIndex}`;
      if (seenOutpoints.has(outpoint)) {
        throw new Error("BSV upto source admission failed: duplicate source outpoint");
      }
      seenOutpoints.add(outpoint);

      const subject = beef.findAtomicTransaction(sourceTxid);
      if (subject === undefined) {
        throw new Error("BSV upto source admission failed: invalid source transaction");
      }
      const output = subject.outputs[candidate.sourceOutputIndex];
      if (output === undefined) {
        throw new Error("BSV upto source admission failed: source output is missing");
      }
      const satoshis = output.satoshis;
      if (
        satoshis === undefined ||
        !Number.isSafeInteger(satoshis) ||
        satoshis <= 0 ||
        satoshis > MAX_SATOSHIS
      ) {
        throw new Error("BSV upto source admission failed: invalid source output amount");
      }

      const publicKey = candidate.publicKey;
      const lockingScriptHex = Utils.toHex(output.lockingScript.toBinary());
      const expectedScriptHex = Utils.toHex(
        new P2PKH().lock(PublicKey.fromString(publicKey).toHash() as number[]).toBinary(),
      );
      if (lockingScriptHex !== expectedScriptHex) {
        throw new Error(
          "BSV upto source admission failed: source output does not match public key",
        );
      }

      let subjectVerified = false;
      try {
        subjectVerified = await subject.verify(chainTracker);
      } catch {
        subjectVerified = false;
      }
      if (!subjectVerified) {
        throw new Error("BSV upto source admission failed: invalid source transaction");
      }
      recordTransactionSpends(subjectClosure, spendersByOutpoint);

      const artifact = Object.freeze({
        role: candidate.role,
        sourceTxid,
        sourceOutputIndex: candidate.sourceOutputIndex,
        satoshis: BigInt(satoshis),
        publicKey,
        lockingScriptHex,
      }) as AdmittedSource;
      sourceAuthorities.set(artifact, {
        atomicBeef: Object.freeze(Array.from(atomicBeefBytes)),
        role: candidate.role,
        sourceTxid,
        sourceOutputIndex: candidate.sourceOutputIndex,
        publicKey,
      });
      admitted.push(artifact);
    }

    for (const outpoint of seenOutpoints) {
      if (spendersByOutpoint.has(outpoint)) {
        throw new Error(
          "BSV upto source admission failed: selected source outpoint is already spent in source ancestry",
        );
      }
    }
    return Object.freeze(admitted);
  };

  return Object.assign(admit, { preflight });
}

/**
 * Recreates mutable SDK values only from an artifact issued by this module.
 *
 * @param source - An admitted source authority
 * @returns Fresh Atomic BEEF bytes and a fresh hydrated subject transaction
 */
export function materializeAdmittedSource(source: AdmittedSource) {
  const authority = sourceAuthorities.get(source);
  if (authority === undefined) {
    throw new Error("BSV upto source artifact was not issued by source admission");
  }
  const atomicBeef = Uint8Array.from(authority.atomicBeef);
  const beef = parseAtomicBeef(atomicBeef, "BSV upto admitted source snapshot: Atomic BEEF");
  const sourceTransaction = beef.findAtomicTransaction(authority.sourceTxid);
  if (sourceTransaction === undefined) {
    throw new Error("BSV upto admitted source snapshot is internally inconsistent");
  }
  return Object.freeze({
    atomicBeef,
    role: authority.role,
    sourceTransaction,
    sourceOutputIndex: authority.sourceOutputIndex,
    publicKey: authority.publicKey,
  });
}

/**
 * Validates a finite positive deployment limit.
 *
 * @param value - Candidate limit
 * @param name - Policy field name
 * @returns A finite positive safe integer
 */
function readPositiveSafeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || Object.is(value, -0)) {
    throw new Error(`BSV upto source admission policy ${name} must be a positive safe integer`);
  }
  return value;
}

/**
 * Validates a transaction output index.
 *
 * @param value - Candidate output index
 * @param name - Field name
 * @returns A canonical uint32
 */
function readUint32(value: number, name: string): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 0 ||
    value > 0xffffffff ||
    Object.is(value, -0)
  ) {
    throw new Error(`BSV upto source admission failed: ${name} must be a uint32 integer`);
  }
  return value;
}

/**
 * Parses and normalizes a compressed secp256k1 public key.
 *
 * @param value - Candidate public key
 * @returns The normalized compressed key
 */
function normalizeCompressedPublicKey(value: string): string {
  if (typeof value !== "string" || !COMPRESSED_PUBKEY_REGEX.test(value)) {
    throw new Error("BSV upto source admission failed: publicKey must be a compressed public key");
  }
  try {
    return PublicKey.fromString(value).toString();
  } catch {
    throw new Error("BSV upto source admission failed: publicKey must be a compressed public key");
  }
}

/**
 * Rejects context-independently non-final unmined transactions and repeated
 * serialized input outpoints before any source can become admitted authority.
 *
 * @param transactions - Complete transactions in one atomic subject closure
 */
function assertTransactionInvariants(transactions: readonly AtomicSubjectTransaction[]): void {
  for (const entry of transactions) {
    const transaction = entry.transaction;
    if (
      !entry.isProven &&
      transaction.lockTime !== 0 &&
      transaction.inputs.some(input => (input.sequence ?? FINAL_SEQUENCE) !== FINAL_SEQUENCE)
    ) {
      throw new Error("BSV upto source admission failed: non-final unmined transaction");
    }
    const seen = new Set<string>();
    for (const input of transaction.inputs) {
      const key = `${input.sourceTXID}:${input.sourceOutputIndex}`;
      if (seen.has(key)) {
        throw new Error("BSV upto source admission failed: duplicate input outpoint");
      }
      seen.add(key);
    }
  }
}

/**
 * Rejects different complete transactions that claim the same input outpoint.
 * Identical transactions may be repeated across source envelopes.
 *
 * @param transactions - Complete transactions in one atomic subject closure
 * @param spendersByOutpoint - Aggregate claims from prior source envelopes
 */
function recordTransactionSpends(
  transactions: readonly AtomicSubjectTransaction[],
  spendersByOutpoint: Map<string, string>,
): void {
  for (const entry of transactions) {
    for (const input of entry.transaction.inputs) {
      const sourceTxid = input.sourceTXID ?? input.sourceTransaction?.id("hex");
      const sourceOutputIndex = input.sourceOutputIndex;
      if (
        sourceTxid === undefined ||
        sourceOutputIndex === undefined ||
        (sourceTxid === NULL_TXID && sourceOutputIndex === 0xffffffff)
      ) {
        continue;
      }
      const outpoint = `${sourceTxid}:${sourceOutputIndex}`;
      const priorSpender = spendersByOutpoint.get(outpoint);
      if (priorSpender !== undefined && priorSpender !== entry.txid) {
        throw new Error("BSV upto source admission failed: conflicting source ancestry");
      }
      spendersByOutpoint.set(outpoint, entry.txid);
    }
  }
}
