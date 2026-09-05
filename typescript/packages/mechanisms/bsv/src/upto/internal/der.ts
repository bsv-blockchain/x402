import { Curve, Signature, Utils } from "@bsv/sdk";

/**
 * Decode canonical padded base64 and validate strict-DER/low-S.
 *
 * @param encoded - Candidate canonical base64
 * @param name - Field name for errors
 * @returns Validated independent DER bytes
 */
export function readEncodedDer(encoded: unknown, name: string): number[] {
  // A strict secp256k1 DER signature is at most 72 bytes (96 base64 chars).
  // Bound the wire string before asking the decoder to allocate.
  if (typeof encoded !== "string" || encoded.length === 0 || encoded.length > 96) {
    throw new Error(`${name} must be canonical base64 strict-DER bytes`);
  }
  let bytes: number[];
  try {
    bytes = Utils.toArray(encoded, "base64") as number[];
  } catch {
    throw new Error(`${name} must be canonical base64 strict-DER bytes`);
  }
  if (Utils.toBase64(bytes) !== encoded) {
    throw new Error(`${name} must be canonical base64 strict-DER bytes`);
  }
  return readDerBytes(bytes, name);
}

/**
 * Capture and validate canonical strict-DER, low-S bytes.
 *
 * @param raw - Candidate signer byte array
 * @param name - Field name for errors
 * @returns Validated independent DER bytes
 */
export function readDerBytes(raw: unknown, name: string): number[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error(`${name} must be strict-DER bytes`);
  }
  const length = raw.length;
  const bytes = new Array<number>(length);
  for (let index = 0; index < length; index += 1) {
    const byte = raw[index];
    if (!Number.isInteger(byte) || byte < 0 || byte > 0xff) {
      throw new Error(`${name} must be strict-DER bytes`);
    }
    bytes[index] = byte;
  }
  let signature: Signature;
  try {
    signature = Signature.fromDER(bytes);
  } catch {
    throw new Error(`${name} must be strict-DER bytes`);
  }
  if (!bytesEqual(signature.toDER() as number[], bytes)) {
    throw new Error(`${name} must be canonical strict-DER bytes`);
  }
  if (signature.s.cmp(new Curve().n.ushrn(1)) > 0) {
    throw new Error(`${name} must be low-S`);
  }
  return bytes;
}

/**
 * Compares two byte sequences element by element.
 *
 * @param left - First byte sequence
 * @param right - Second byte sequence
 * @returns Whether both sequences are equal
 */
function bytesEqual(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}
