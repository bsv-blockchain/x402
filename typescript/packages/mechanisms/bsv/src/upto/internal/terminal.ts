import { type ChainTracker, type WalletInterface } from "@bsv/sdk";
import { MAX_SATOSHIS } from "../../constants";
import { collectAtomicSubjectClosure, decodeCanonicalAtomicBeef, parseAtomicBeef } from "./beef";
import {
  deriveUptoFloorSpecs,
  deriveUptoOutputCandidates,
  type UptoPaymentRemittance,
  type UptoWalletPerspective,
} from "./outputs";
import { materializeAdmittedSource } from "./source";
import {
  materializeVerifiedAuthorization,
  verifyCanonicalP2pkhInputUnlock,
  type VerifiedAuthorization,
} from "./transaction";

const FINAL_SEQUENCE = 0xffffffff;
const CAP_SIGHASH = 0x43;
const CONTROL_SIGHASH = 0x41;
declare const verifiedTerminalBrand: unique symbol;

/** Finite deployment limit applied before decoding a terminal envelope. */
export interface TerminalVerificationPolicy {
  maxAtomicBeefBytes: number;
}

/** Opaque authority representing one fully verified terminal transaction. */
export interface VerifiedTerminal {
  readonly [verifiedTerminalBrand]: true;
}

/** Immutable metadata for one authorization-derived terminal output. */
export interface VerifiedTerminalOutput {
  readonly role: "floor" | "recipient" | "refund";
  readonly outputIndex: number;
  readonly paymentRemittance: UptoPaymentRemittance;
}

/** Fresh mutable byte values plus immutable facts from a verified terminal. */
export interface MaterializedVerifiedTerminal {
  readonly atomicBeef: Uint8Array;
  readonly subjectTransaction: Uint8Array;
  readonly subjectTxid: string;
  readonly actualAmount: bigint;
  readonly outputs: readonly VerifiedTerminalOutput[];
}

interface VerifyTerminalArgs {
  authorization: VerifiedAuthorization;
  actualAmount: bigint;
  transaction: string;
  wallet: Pick<WalletInterface, "getPublicKey">;
  perspective: UptoWalletPerspective;
  chainTracker: ChainTracker;
  policy: TerminalVerificationPolicy;
  originator?: string;
}

interface StoredTerminal {
  atomicBeef: readonly number[];
  subjectTransaction: readonly number[];
  subjectTxid: string;
  actualAmount: bigint;
  outputs: readonly VerifiedTerminalOutput[];
}

interface DerivedRecordInput {
  role: "floor" | "recipient" | "refund";
  paymentRemittance: UptoPaymentRemittance;
}

const verifiedTerminals = new WeakMap<VerifiedTerminal, StoredTerminal>();

/**
 * Verifies one raw terminal Atomic BEEF against an already verified authorization.
 *
 * Both wallet perspectives call this same boundary. Wire data supplies neither
 * output roles nor scripts: those are re-derived from signed authorization facts.
 *
 * @param rawArgs - Raw terminal evidence and its authorization/chain context
 * @returns Opaque verified terminal authority
 */
export async function verifyTerminalTransaction(
  rawArgs: VerifyTerminalArgs,
): Promise<VerifiedTerminal> {
  const maximumBytes = readPositiveSafeInteger(
    rawArgs.policy?.maxAtomicBeefBytes,
    "maxAtomicBeefBytes",
  );
  const authorization = rawArgs.authorization;
  const actualAmount = rawArgs.actualAmount;
  const encoded = rawArgs.transaction;
  const wallet = rawArgs.wallet;
  const perspective = rawArgs.perspective;
  const chainTracker = rawArgs.chainTracker;
  const originator = rawArgs.originator;
  if (typeof actualAmount !== "bigint" || actualAmount < 0n) {
    throw new Error("terminal actualAmount must be a non-negative bigint");
  }
  if (typeof encoded !== "string") {
    throw new Error("terminal Atomic BEEF must be canonical padded base64");
  }
  if (perspective !== "payer" && perspective !== "recipient") {
    throw new Error("terminal wallet perspective must be payer or recipient");
  }
  if (typeof wallet?.getPublicKey !== "function") {
    throw new Error("terminal wallet.getPublicKey must be a function");
  }
  const material = materializeVerifiedAuthorization(authorization);
  const bytes = decodeCanonicalAtomicBeef(encoded, maximumBytes, "terminal Atomic BEEF");
  const beef = parseAtomicBeef(bytes, "terminal Atomic BEEF");
  const subjectTxid = beef.atomicTxid;
  if (subjectTxid === undefined) {
    throw new Error("terminal Atomic BEEF subject is missing");
  }
  collectAtomicSubjectClosure(beef, subjectTxid, "terminal Atomic BEEF");
  let beefValid = false;
  try {
    beefValid = await beef.verify(chainTracker, false);
  } catch {
    beefValid = false;
  }
  if (!beefValid) {
    throw new Error("terminal Atomic BEEF is invalid");
  }
  const subject = beef.findAtomicTransaction(subjectTxid);
  if (subject === undefined || subject.id("hex") !== subjectTxid) {
    throw new Error("terminal Atomic BEEF subject transaction is invalid");
  }

  if (subject.version !== 1) throw new Error("terminal transaction version must be 1");
  if (subject.lockTime !== material.facts.deadline) {
    throw new Error("terminal transaction lockTime does not match the authorization deadline");
  }
  const sources = [...material.capInputs, ...material.controlInputs];
  if (subject.inputs.length !== sources.length) {
    throw new Error("terminal input count does not match the authorization");
  }
  let inputTotal = 0n;
  for (let index = 0; index < sources.length; index += 1) {
    const expected = sources[index];
    const input = subject.inputs[index];
    const expectedRole = index < material.capInputs.length ? "cap" : "control";
    const admitted = materializeAdmittedSource(expected);
    if (admitted.role !== expectedRole) {
      throw new Error(`terminal input ${index} has the wrong authorization role`);
    }
    const wireSource = input.sourceTransaction;
    if (
      wireSource === undefined ||
      wireSource.id("hex") !== expected.sourceTxid ||
      input.sourceOutputIndex !== expected.sourceOutputIndex
    ) {
      throw new Error(`terminal input ${index} outpoint does not match the authorization`);
    }
    if (!bytesEqual(wireSource.toBinary(), admitted.sourceTransaction.toBinary())) {
      throw new Error(`terminal input ${index} source transaction differs from admission`);
    }
    const sourceOutput = wireSource.outputs[input.sourceOutputIndex];
    if (
      sourceOutput?.satoshis !== Number(expected.satoshis) ||
      sourceOutput.lockingScript.toHex() !== expected.lockingScriptHex
    ) {
      throw new Error(`terminal input ${index} source value or script differs from admission`);
    }
    if ((input.sequence ?? FINAL_SEQUENCE) !== FINAL_SEQUENCE) {
      throw new Error(`terminal input ${index} sequence must be final`);
    }
    verifyCanonicalP2pkhInputUnlock(
      subject,
      index,
      admitted.publicKey,
      expectedRole === "cap" ? CAP_SIGHASH : CONTROL_SIGHASH,
      expectedRole === "cap" ? material.capSignatures[index] : undefined,
    );
    inputTotal += expected.satoshis;
  }

  const floors = await deriveUptoFloorSpecs({
    wallet,
    perspective,
    facts: material.facts,
    originator,
  });
  if (subject.outputs.length <= floors.length) {
    throw new Error("terminal transaction must contain at least one recipient output");
  }
  const outputRecords: VerifiedTerminalOutput[] = [];
  let floorTotal = 0n;
  let outputTotal = 0n;
  for (let index = 0; index < floors.length; index += 1) {
    const output = subject.outputs[index];
    const expected = floors[index];
    const stored = material.floorOutputs[index];
    const satoshis = readOutputAmount(output.satoshis, index);
    if (
      stored === undefined ||
      stored.satoshis !== expected.satoshis ||
      !bytesEqual(stored.lockingScript, expected.lockingScript.toBinary()) ||
      satoshis !== expected.satoshis ||
      output.lockingScript.toHex() !== expected.lockingScript.toHex()
    ) {
      throw new Error(`terminal floor output ${index} differs from the authorization`);
    }
    floorTotal += BigInt(satoshis);
    outputTotal += BigInt(satoshis);
    outputRecords.push(outputRecord(expected, index));
  }

  const variableCandidates: {
    role: "recipient" | "refund";
    outputIndex: number;
    satoshis: number;
  }[] = [];
  for (let index = floors.length; index < subject.outputs.length; index += 1) {
    const satoshis = readOutputAmount(subject.outputs[index].satoshis, index);
    variableCandidates.push({ role: "recipient", outputIndex: index, satoshis });
    variableCandidates.push({ role: "refund", outputIndex: index, satoshis });
  }
  const derivedCandidates = await deriveUptoOutputCandidates({
    wallet,
    perspective,
    facts: material.facts,
    candidates: variableCandidates,
    originator,
  });
  let recipientCount = 0;
  let refundStarted = false;
  let recipientTotal = 0n;
  let refundTotal = 0n;
  for (let index = floors.length; index < subject.outputs.length; index += 1) {
    const output = subject.outputs[index];
    const recipient = derivedCandidates[(index - floors.length) * 2];
    const refund = derivedCandidates[(index - floors.length) * 2 + 1];
    const recipientMatch = output.lockingScript.toHex() === recipient.lockingScript.toHex();
    const refundMatch = output.lockingScript.toHex() === refund.lockingScript.toHex();
    if (recipientMatch === refundMatch) {
      throw new Error(`terminal output ${index} does not have one authorization-derived role`);
    }
    const selected = recipientMatch ? recipient : refund;
    if (selected.role === "recipient") {
      if (refundStarted) {
        throw new Error("terminal recipient output cannot follow a refund output");
      }
      recipientCount += 1;
      recipientTotal += BigInt(selected.satoshis);
    } else {
      refundStarted = true;
      refundTotal += BigInt(selected.satoshis);
    }
    outputTotal += BigInt(selected.satoshis);
    outputRecords.push(outputRecord(selected, index));
  }
  if (recipientCount === 0) {
    throw new Error("terminal transaction must contain at least one recipient output");
  }

  const capTotal = material.capInputs.reduce((sum, source) => sum + source.satoshis, 0n);
  const controlTotal = material.controlInputs.reduce((sum, source) => sum + source.satoshis, 0n);
  const exposure = capTotal - floorTotal;
  const maximum = BigInt(material.facts.maximumAmount);
  const derivedActual = recipientTotal - controlTotal;
  const fee = inputTotal - outputTotal;
  if (derivedActual !== actualAmount) {
    throw new Error("terminal recipient net amount does not equal actualAmount");
  }
  if (actualAmount > maximum) throw new Error("terminal actualAmount exceeds maximumAmount");
  if (fee < 0n) throw new Error("terminal outputs exceed inputs");
  if (fee > exposure - maximum) throw new Error("terminal fee exceeds authorized headroom");
  if (refundTotal !== exposure - actualAmount - fee) {
    throw new Error("terminal refund total does not equal authorized remainder");
  }
  if (actualAmount + fee > exposure) {
    throw new Error("terminal payer debit exceeds authorized exposure");
  }
  let subjectValid = false;
  try {
    subjectValid = await subject.verify(chainTracker);
  } catch {
    subjectValid = false;
  }
  if (!subjectValid) throw new Error("terminal transaction is invalid");

  const token = Object.freeze(Object.create(null)) as VerifiedTerminal;
  verifiedTerminals.set(token, {
    atomicBeef: Object.freeze(Array.from(bytes)),
    subjectTransaction: Object.freeze(subject.toBinary()),
    subjectTxid,
    actualAmount,
    outputs: Object.freeze(outputRecords.map(record => freezeOutput(record))),
  });
  return token;
}

/**
 * Returns fresh wire bytes and immutable metadata from an issued terminal token.
 *
 * @param terminal - Opaque token returned by terminal verification
 * @returns Independent material safe for wallet internalization/response encoding
 */
export function materializeVerifiedTerminal(
  terminal: VerifiedTerminal,
): MaterializedVerifiedTerminal {
  const stored = verifiedTerminals.get(terminal);
  if (stored === undefined) throw new Error("terminal was not issued by terminal verification");
  return Object.freeze({
    atomicBeef: Uint8Array.from(stored.atomicBeef),
    subjectTransaction: Uint8Array.from(stored.subjectTransaction),
    subjectTxid: stored.subjectTxid,
    actualAmount: stored.actualAmount,
    outputs: Object.freeze(stored.outputs.map(output => freezeOutput(output))),
  });
}

/**
 * Validates one finite deployment bound.
 *
 * @param value - Candidate policy value
 * @param name - Policy field name
 * @returns Captured positive safe integer
 */
function readPositiveSafeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || Object.is(value, -0)) {
    throw new Error(`terminal verification policy ${name} must be a positive safe integer`);
  }
  return value;
}

/**
 * Reads one positive money-range output amount.
 *
 * @param value - SDK output amount
 * @param outputIndex - Output index used in errors
 * @returns Validated satoshi amount
 */
function readOutputAmount(value: number | undefined, outputIndex: number): number {
  if (
    value === undefined ||
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > MAX_SATOSHIS ||
    Object.is(value, -0)
  ) {
    throw new Error(`terminal output ${outputIndex} amount must be a positive safe integer`);
  }
  return value;
}

/**
 * Projects one derived output into immutable terminal metadata.
 *
 * @param output - Authorization-derived output
 * @param outputIndex - Subject transaction output index
 * @returns Terminal output record
 */
function outputRecord(output: DerivedRecordInput, outputIndex: number): VerifiedTerminalOutput {
  return {
    role: output.role,
    outputIndex,
    paymentRemittance: { ...output.paymentRemittance },
  };
}

/**
 * Copies and deep-freezes one output record.
 *
 * @param output - Output record to detach
 * @returns Independent immutable record
 */
function freezeOutput(output: VerifiedTerminalOutput): VerifiedTerminalOutput {
  return Object.freeze({
    ...output,
    paymentRemittance: Object.freeze({ ...output.paymentRemittance }),
  });
}

/**
 * Compares two byte sequences without coercion.
 *
 * @param left - First sequence
 * @param right - Second sequence
 * @returns Whether all bytes match
 */
function bytesEqual(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}
