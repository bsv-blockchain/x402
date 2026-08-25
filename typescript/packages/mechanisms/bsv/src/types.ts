/**
 * BSV x402 payload types.
 *
 * The payload mirrors the BRC-29 payment message (as used by BRC-121
 * "Simple 402 Payments"): a fully-signed, fully-funded BSV transaction in
 * BEEF format plus the BRC-42 derivation metadata the recipient's wallet
 * needs to take custody of the payment output via `internalizeAction`.
 */

/**
 * x402 V2 payment payload for the BSV `exact` scheme.
 *
 * Sent as the `payload` field of `PaymentPayload` (x402Version: 2).
 *
 * @example
 * ```json
 * {
 *   "transaction": "AQEBAQ...",
 *   "derivationPrefix": "aGVsbG8gd28=",
 *   "derivationSuffix": "MTcwMDAwMDAwMDAwMA==",
 *   "senderIdentityKey": "02ab...ef",
 *   "outputIndex": 0
 * }
 * ```
 */
export interface ExactBsvPayloadV2 {
  /**
   * Base64-encoded BEEF (BRC-62) / Atomic BEEF (BRC-95) transaction as
   * returned by BRC-100 `createAction`. Fully signed and funded by the
   * client, including SPV ancestry.
   */
  transaction: string;

  /** Base64-encoded BRC-29 derivation prefix (payment-wide random nonce) */
  derivationPrefix: string;

  /**
   * Base64-encoded BRC-29 derivation suffix. Per BRC-121, the decoded value
   * MUST be a decimal Unix timestamp in milliseconds; verifiers reject
   * payloads whose timestamp falls outside the freshness window.
   */
  derivationSuffix: string;

  /** Client identity public key (compressed secp256k1 hex) */
  senderIdentityKey: string;

  /** Zero-based index of the payment output in the transaction */
  outputIndex: number;
}

/** An immutable input included in a BSV `upto` authorization. */
export interface UptoBsvInput {
  /** Identity that owns the input for net-delta accounting. */
  owner: string;
  /** Cap signatures are reusable; control inputs sign every transaction version. */
  kind: "cap" | "control";
  /** Base64 BEEF or Atomic BEEF containing the source transaction. */
  sourceTransaction: string;
  sourceOutputIndex: number;
  /** Compressed public key matching the source P2PKH output. */
  publicKey: string;
}

/** An immutable output slot included in a BSV `upto` authorization. */
export interface UptoBsvOutput {
  /** Identity that owns the output for net-delta accounting. */
  owner: string;
  /** Hex-encoded locking script; its value is supplied by each signed version. */
  lockingScript: string;
  /** Fixed value for a cap input's same-index floor output. */
  fixedAmount?: string;
}

/** Canonical fields approved before the actual amount is known. */
export interface UptoBsvAuthorizationTerms {
  version: 1;
  network: string;
  asset: "BSV";
  payTo: string;
  senderIdentityKey: string;
  derivationPrefix: string;
  derivationSuffix: string;
  inputs: UptoBsvInput[];
  outputs: UptoBsvOutput[];
  /** Owners whose positive net deltas form the x402 amount. */
  chargedOwners: string[];
  /** Outputs internalized by the recipient wallet under the BRC-29 remittance. */
  paymentOutputIndexes: number[];
  fee: string;
  sequenceStart: number;
  /** Unix seconds before which the authorization is not accepted. */
  validAfter: number;
  /** Unix seconds at or after which the authorization is no longer accepted. */
  deadline: number;
  /** Absolute transaction lock time used by non-final control inputs. */
  nLockTime: number;
}

/** Reusable signatures made by one cap input owner. */
export interface UptoBsvCapSignature {
  inputIndex: number;
  /** Base64 DER signature for `SIGHASH_SINGLE | SIGHASH_FORKID`. */
  transactionSignature: string;
  /** Base64 DER signature over the canonical authorization digest. */
  authorizationSignature: string;
}

/** A single-use maximum-payment authorization. */
export interface UptoBsvAuthorization {
  /** Lowercase SHA-256 digest of the canonical terms. */
  authorizationId: string;
  terms: UptoBsvAuthorizationTerms;
  capSignatures: UptoBsvCapSignature[];
}

/** One ordinary, fully signed transaction produced under an authorization. */
export interface UptoBsvTransactionVersion {
  authorizationId: string;
  /** Base64 BEEF or Atomic BEEF for the fully signed transaction. */
  transaction: string;
}

/** Pure-data result of verifying one signed transaction version locally. */
export interface UptoBsvTransactionVerification {
  txid: string;
  amount: string;
  nSequence: number;
  cooperativeClose: boolean;
  ownerDeltas: Readonly<Record<string, string>>;
}

/** x402 payload for the BSV `upto` scheme. */
export interface UptoBsvPayload {
  /** Inherited BRC-29 fields, kept top-level for exact-path compatibility. */
  derivationPrefix: string;
  derivationSuffix: string;
  senderIdentityKey: string;
  outputIndex: number;
  authorization: UptoBsvAuthorization;
  /** Added for settlement when one fully signed transaction is selected. */
  transactionVersion?: UptoBsvTransactionVersion;
}

/** Request sent to the recipient when obtaining its small control input. */
export interface UptoBsvControlRequest {
  network: string;
  payTo: string;
  senderIdentityKey: string;
  derivationPrefix: string;
  derivationSuffix: string;
  maxAmount: string;
  maxTimeoutSeconds: number;
}

/** Recipient-provided control input and transaction timing terms. */
export interface UptoBsvControlProposal {
  inputs: UptoBsvInput[];
  fee: string;
  sequenceStart: number;
  validAfter: number;
  deadline: number;
  nLockTime: number;
}
