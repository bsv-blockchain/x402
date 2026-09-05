import { Hash, PublicKey, Utils } from "@bsv/sdk";
import { COMPRESSED_PUBKEY_REGEX, MAX_SATOSHIS } from "../../constants";

const AUTHORIZATION_DOMAIN = "x402-bsv-upto-authorization-v1";
const CANONICAL_UNSIGNED_DECIMAL = /^(?:0|[1-9]\d*)$/;
const LOWERCASE_TXID = /^[0-9a-f]{64}$/;
const UINT32_MAX = 0xffffffff;

/** A control source after its Atomic BEEF subject has been resolved. */
export interface ResolvedControlInput {
  readonly nonce: string;
  readonly sourceTxid: string;
  readonly sourceOutputIndex: number;
}

/** A cap source after its Atomic BEEF subject has been resolved. */
export interface ResolvedCapInput extends ResolvedControlInput {
  readonly floorAmount: string;
}

/** Facts covered by the payer's upto authorization signature. */
export interface ResolvedAuthorizationFacts {
  readonly network: string;
  readonly asset: string;
  readonly maximumAmount: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  readonly validAfter: number;
  readonly deadline: number;
  readonly controlInputs: readonly ResolvedControlInput[];
  readonly senderIdentityKey: string;
  readonly derivationPrefix: string;
  readonly derivationSuffix: string;
  readonly capInputs: readonly ResolvedCapInput[];
}

/** Validated signature projection and SHA-256 digest. */
export interface ValidatedAuthorization {
  readonly snapshot: ResolvedAuthorizationFacts;
  readonly canonicalText: string;
  readonly digest: number[];
}

/**
 * Validates and hashes the facts covered by a BSV upto authorization.
 *
 * @param facts - Authorization facts with Atomic BEEF subjects already resolved to txids
 * @returns A closed facts snapshot, canonical UTF-8 text, and its SHA-256 digest
 */
export function validateAndDigestAuthorization(
  facts: ResolvedAuthorizationFacts,
): ValidatedAuthorization {
  if (typeof facts !== "object" || facts === null) {
    throw new Error("authorization facts must be an object");
  }

  // Collect every signed top-level field for the validation below; the
  // canonical projection consumes only the validated copies built here.
  const raw = {
    network: facts.network,
    asset: facts.asset,
    maximumAmount: facts.maximumAmount,
    payTo: facts.payTo,
    maxTimeoutSeconds: facts.maxTimeoutSeconds,
    validAfter: facts.validAfter,
    deadline: facts.deadline,
    controlInputs: facts.controlInputs,
    senderIdentityKey: facts.senderIdentityKey,
    derivationPrefix: facts.derivationPrefix,
    derivationSuffix: facts.derivationSuffix,
    capInputs: facts.capInputs,
  };

  const maximumAmount = readPositiveAmount(raw.maximumAmount, "maximumAmount");
  if (
    maximumAmount.length > String(MAX_SATOSHIS).length ||
    BigInt(maximumAmount) > BigInt(MAX_SATOSHIS)
  ) {
    throw new Error("maximumAmount exceeds the maximum BSV supply");
  }
  const maxTimeoutSeconds = readUint32(raw.maxTimeoutSeconds, "maxTimeoutSeconds");
  if (maxTimeoutSeconds === 0) {
    throw new Error("maxTimeoutSeconds must be a positive uint32");
  }
  const validAfter = readUint32(raw.validAfter, "validAfter");
  const deadline = readUint32(raw.deadline, "deadline");
  if (validAfter < 500_000_000) {
    throw new Error("validAfter must be at least 500000000");
  }
  if (validAfter >= deadline) {
    throw new Error("authorization window must be positive");
  }
  if (deadline - validAfter > maxTimeoutSeconds) {
    throw new Error("authorization window exceeds maxTimeoutSeconds");
  }
  const controlInputsRaw = captureNonEmptyArray(raw.controlInputs, "controlInputs");
  const capInputsRaw = captureNonEmptyArray(raw.capInputs, "capInputs");
  const controlInputs = new Array<ResolvedControlInput>(controlInputsRaw.length);
  for (let index = 0; index < controlInputsRaw.length; index += 1) {
    const field = `controlInputs[${index}]`;
    const input = readRecord(controlInputsRaw.values[index], field);
    const nonce = input.nonce;
    const sourceTxid = input.sourceTxid;
    const sourceOutputIndex = input.sourceOutputIndex;
    controlInputs[index] = Object.freeze({
      nonce: readNonce(nonce, `${field}.nonce`),
      sourceTxid: readTxid(sourceTxid, `${field}.sourceTxid`),
      sourceOutputIndex: readUint32(sourceOutputIndex, `${field}.sourceOutputIndex`),
    });
  }
  const capInputs = new Array<ResolvedCapInput>(capInputsRaw.length);
  for (let index = 0; index < capInputsRaw.length; index += 1) {
    const field = `capInputs[${index}]`;
    const input = readRecord(capInputsRaw.values[index], field);
    const nonce = input.nonce;
    const sourceTxid = input.sourceTxid;
    const sourceOutputIndex = input.sourceOutputIndex;
    const floorAmount = input.floorAmount;
    capInputs[index] = Object.freeze({
      nonce: readNonce(nonce, `${field}.nonce`),
      sourceTxid: readTxid(sourceTxid, `${field}.sourceTxid`),
      sourceOutputIndex: readUint32(sourceOutputIndex, `${field}.sourceOutputIndex`),
      floorAmount: readPositiveAmount(floorAmount, `${field}.floorAmount`),
    });
  }
  assertUniqueNonces(controlInputs, "controlInputs");
  assertUniqueNonces(capInputs, "capInputs");
  assertUniqueOutpoints(controlInputs, capInputs);
  const snapshot: ResolvedAuthorizationFacts = Object.freeze({
    network: readLine(raw.network, "network"),
    asset: readLine(raw.asset, "asset"),
    maximumAmount,
    payTo: readPublicKey(raw.payTo, "payTo"),
    maxTimeoutSeconds,
    validAfter,
    deadline,
    controlInputs: Object.freeze(controlInputs),
    senderIdentityKey: readPublicKey(raw.senderIdentityKey, "senderIdentityKey"),
    derivationPrefix: readCanonicalBase64(raw.derivationPrefix, "derivationPrefix"),
    derivationSuffix: readCanonicalBase64(raw.derivationSuffix, "derivationSuffix"),
    capInputs: Object.freeze(capInputs),
  });
  const lines = [
    AUTHORIZATION_DOMAIN,
    snapshot.network,
    snapshot.asset,
    snapshot.maximumAmount,
    snapshot.payTo,
    String(snapshot.maxTimeoutSeconds),
    String(snapshot.validAfter),
    String(snapshot.deadline),
    String(snapshot.controlInputs.length),
  ];
  for (const input of snapshot.controlInputs) {
    lines.push(input.nonce, input.sourceTxid, String(input.sourceOutputIndex));
  }
  lines.push(
    snapshot.senderIdentityKey,
    snapshot.derivationPrefix,
    snapshot.derivationSuffix,
    String(snapshot.capInputs.length),
  );
  for (const input of snapshot.capInputs) {
    lines.push(input.nonce, input.sourceTxid, String(input.sourceOutputIndex), input.floorAmount);
  }
  const canonicalText = lines.join("\n");
  return Object.freeze({
    snapshot,
    canonicalText,
    digest: Hash.sha256(canonicalText, "utf8"),
  });
}

/**
 * Validates a positive canonical unsigned-decimal satoshi amount.
 *
 * @param value - Candidate amount
 * @param field - Field name used in rejection messages
 * @returns The unchanged canonical amount
 */
function readPositiveAmount(value: unknown, field: string): string {
  if (typeof value !== "string" || !CANONICAL_UNSIGNED_DECIMAL.test(value)) {
    throw new Error(`${field} must be a canonical unsigned decimal`);
  }
  if (value === "0") {
    throw new Error(`${field} must be positive`);
  }
  return value;
}

/**
 * Validates a JavaScript number as an unsigned 32-bit integer.
 *
 * @param value - Candidate integer
 * @param field - Field name used in rejection messages
 * @returns The unchanged integer
 */
function readUint32(value: unknown, field: string): number {
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
 * Validates a required ordered input collection.
 *
 * @param value - Candidate input collection
 * @param field - Field name used in rejection messages
 * @returns The non-empty input collection
 */
function captureNonEmptyArray(
  value: unknown,
  field: string,
): { readonly values: readonly unknown[]; readonly length: number } {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be non-empty`);
  }
  const length = value.length;
  if (length === 0) {
    throw new Error(`${field} must be non-empty`);
  }
  return { values: value, length };
}

/**
 * Validates an input entry before any of its signed fields are captured.
 *
 * @param value - Candidate entry
 * @param field - Field name used in rejection messages
 * @returns The entry as a property record
 */
function readRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    throw new Error(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

/**
 * Validates a non-empty signed text line.
 *
 * @param value - Candidate line
 * @param field - Field name used in rejection messages
 * @returns The unchanged line
 */
function readLine(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  if (value.includes("\n")) {
    throw new Error(`${field} must not contain LF`);
  }
  return value;
}

/**
 * Validates and normalizes a compressed secp256k1 public key.
 *
 * @param value - Candidate key
 * @param field - Field name used in rejection messages
 * @returns Lowercase compressed public-key hex
 */
function readPublicKey(value: unknown, field: string): string {
  const key = readLine(value, field).toLowerCase();
  if (!COMPRESSED_PUBKEY_REGEX.test(key)) {
    throw new Error(`${field} must be a valid compressed secp256k1 public key`);
  }
  try {
    PublicKey.fromString(key);
  } catch {
    throw new Error(`${field} must be a valid compressed secp256k1 public key`);
  }
  return key;
}

/**
 * Validates a source transaction id in conventional display order.
 *
 * @param value - Candidate txid
 * @param field - Field name used in rejection messages
 * @returns The unchanged lowercase txid
 */
function readTxid(value: unknown, field: string): string {
  const txid = readLine(value, field);
  if (!LOWERCASE_TXID.test(txid)) {
    throw new Error(`${field} must be 64 lowercase hex characters`);
  }
  return txid;
}

/**
 * Validates padded standard base64 by decode/re-encode equality.
 *
 * @param value - Candidate base64 text
 * @param field - Field name used in rejection messages
 * @returns The unchanged canonical text
 */
function readCanonicalBase64(value: unknown, field: string): string {
  const encoded = readLine(value, field);
  let decoded: number[];
  try {
    decoded = Utils.toArray(encoded, "base64") as number[];
  } catch {
    throw new Error(`${field} must be canonical base64`);
  }
  if (Utils.toBase64(decoded) !== encoded) {
    throw new Error(`${field} must be canonical base64`);
  }
  return encoded;
}

/**
 * Validates a 32-byte authorization nonce.
 *
 * @param value - Candidate nonce
 * @param field - Field name used in rejection messages
 * @returns The unchanged canonical nonce
 */
function readNonce(value: unknown, field: string): string {
  let nonce: string;
  try {
    nonce = readCanonicalBase64(value, field);
  } catch {
    throw new Error(`${field} must be padded canonical base64 for 32 bytes`);
  }
  if ((Utils.toArray(nonce, "base64") as number[]).length !== 32) {
    throw new Error(`${field} must be padded canonical base64 for 32 bytes`);
  }
  return nonce;
}

/**
 * Enforces nonce uniqueness within one source role.
 *
 * @param inputs - Validated sources from one role
 * @param role - Role name used in rejection messages
 */
function assertUniqueNonces(inputs: readonly { readonly nonce: string }[], role: string): void {
  const seen = new Set<string>();
  for (const input of inputs) {
    if (seen.has(input.nonce)) {
      throw new Error(`${role} nonces must be unique`);
    }
    seen.add(input.nonce);
  }
}

/**
 * Enforces global outpoint uniqueness across both source roles.
 *
 * @param controlInputs - Validated recipient control sources
 * @param capInputs - Validated payer cap sources
 */
function assertUniqueOutpoints(
  controlInputs: readonly ResolvedControlInput[],
  capInputs: readonly ResolvedCapInput[],
): void {
  const seen = new Set<string>();
  for (const input of [...controlInputs, ...capInputs]) {
    const outpoint = `${input.sourceTxid}:${input.sourceOutputIndex}`;
    if (seen.has(outpoint)) {
      throw new Error("source outpoints must be unique across the authorization");
    }
    seen.add(outpoint);
  }
}
