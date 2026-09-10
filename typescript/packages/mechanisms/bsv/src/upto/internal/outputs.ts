import { P2PKH, PublicKey, Utils, type LockingScript, type WalletInterface } from "@bsv/sdk";
import { BRC29_PROTOCOL_ID, MAX_SATOSHIS } from "../../constants";
import type { ResolvedAuthorizationFacts } from "./authorization";

/** The wallet whose view is used to derive reciprocal BRC-29 keys. */
export type UptoWalletPerspective = "payer" | "recipient";

/** Output roles in their required terminal transaction order. */
export type UptoOutputRole = "floor" | "recipient" | "refund";

/** BRC-29 metadata used to internalize one derived output. */
export interface UptoPaymentRemittance {
  readonly derivationPrefix: string;
  readonly derivationSuffix: string;
  readonly senderIdentityKey: string;
}

/** One authorization-bound output and its wallet-internalization metadata. */
export interface UptoDerivedOutputSpec {
  readonly role: UptoOutputRole;
  readonly outputIndex: number;
  readonly satoshis: number;
  readonly lockingScript: LockingScript;
  readonly paymentRemittance: UptoPaymentRemittance;
}

interface DeriveUptoOutputSpecsArgs {
  wallet: Pick<WalletInterface, "getPublicKey">;
  perspective: UptoWalletPerspective;
  facts: ResolvedAuthorizationFacts;
  recipientAmounts: readonly number[];
  refundAmounts: readonly number[];
  originator?: string;
}

interface DeriveUptoFloorSpecsArgs {
  wallet: Pick<WalletInterface, "getPublicKey">;
  perspective: UptoWalletPerspective;
  facts: ResolvedAuthorizationFacts;
  originator?: string;
}

interface DeriveUptoOutputCandidatesArgs {
  wallet: Pick<WalletInterface, "getPublicKey">;
  perspective: UptoWalletPerspective;
  facts: ResolvedAuthorizationFacts;
  candidates: readonly {
    role: "recipient" | "refund";
    outputIndex: number;
    satoshis: number;
  }[];
  originator?: string;
}

interface PlannedOutput {
  role: UptoOutputRole;
  outputIndex: number;
  satoshis: number;
}

interface OutputDerivationSnapshot {
  getPublicKey: WalletInterface["getPublicKey"];
  perspective: UptoWalletPerspective;
  payTo: string;
  senderIdentityKey: string;
  derivationPrefix: string;
  timestamp: string;
  originator?: string;
  plan: PlannedOutput[];
}

/**
 * Derives the complete ordered BRC-29 output layout from signed authorization facts.
 *
 * Payer and recipient wallets arrive at the same scripts through reciprocal
 * BRC-42 derivation. Fixed floors are read only from the signed cap facts;
 * callers supply amounts only for recipient and optional refund outputs.
 *
 * @param rawArgs - Validated authorization, wallet perspective, and variable output amounts
 * @returns Floors, recipients, then refunds with stable global indices and remittances
 */
export async function deriveUptoOutputSpecs(
  rawArgs: DeriveUptoOutputSpecsArgs,
): Promise<UptoDerivedOutputSpec[]> {
  return deriveOutputs(snapshotArguments(rawArgs, true));
}

/**
 * Derives only the same-index floors needed by the reusable cap template.
 *
 * @param rawArgs - Validated authorization and the wallet perspective deriving it
 * @returns Exactly one signed floor per cap input
 */
export async function deriveUptoFloorSpecs(
  rawArgs: DeriveUptoFloorSpecsArgs,
): Promise<UptoDerivedOutputSpec[]> {
  return deriveOutputs(
    snapshotArguments(
      {
        ...rawArgs,
        recipientAmounts: [],
        refundAmounts: [],
      },
      false,
    ),
  );
}

/**
 * Derives candidate recipient/refund scripts at fixed transaction indices.
 *
 * This is the narrow sibling seam used when a verifier must classify an
 * already serialized output without trusting wire-provided role counts.
 *
 * @param rawArgs - Validated authorization and candidate roles at wire indices
 * @returns Authorization-bound scripts and remittances in candidate order
 */
export async function deriveUptoOutputCandidates(
  rawArgs: DeriveUptoOutputCandidatesArgs,
): Promise<UptoDerivedOutputSpec[]> {
  const wallet = rawArgs.wallet;
  const perspective = rawArgs.perspective;
  const facts = rawArgs.facts;
  const payTo = facts.payTo;
  const senderIdentityKey = facts.senderIdentityKey;
  const derivationPrefix = facts.derivationPrefix;
  const derivationSuffix = facts.derivationSuffix;
  const originator = rawArgs.originator;
  const getPublicKey = wallet?.getPublicKey;
  if (typeof getPublicKey !== "function") {
    throw new Error("wallet.getPublicKey must be a function");
  }
  if (perspective !== "payer" && perspective !== "recipient") {
    throw new Error("wallet perspective must be payer or recipient");
  }
  if (!Array.isArray(rawArgs.candidates)) {
    throw new Error("output candidates must be an array");
  }
  const timestamp = decodeTimestamp(derivationSuffix);
  const plan = new Array<PlannedOutput>(rawArgs.candidates.length);
  for (let index = 0; index < plan.length; index += 1) {
    const candidate = rawArgs.candidates[index];
    const role = candidate?.role;
    const outputIndex = candidate?.outputIndex;
    const satoshis = candidate?.satoshis;
    if (role !== "recipient" && role !== "refund") {
      throw new Error(`output candidates[${index}].role must be recipient or refund`);
    }
    if (!Number.isSafeInteger(outputIndex) || outputIndex < 0 || Object.is(outputIndex, -0)) {
      throw new Error(`output candidates[${index}].outputIndex must be a non-negative integer`);
    }
    if (
      !Number.isSafeInteger(satoshis) ||
      satoshis <= 0 ||
      satoshis > MAX_SATOSHIS ||
      Object.is(satoshis, -0)
    ) {
      throw new Error(`output candidates[${index}].satoshis must be a positive safe integer`);
    }
    plan[index] = {
      role,
      outputIndex,
      satoshis,
    };
  }
  return deriveOutputs({
    getPublicKey: getPublicKey.bind(wallet),
    perspective,
    payTo,
    senderIdentityKey,
    derivationPrefix,
    timestamp,
    originator,
    plan,
  });
}

/**
 * Resolves a closed output plan through one wallet perspective.
 *
 * @param args - Closed authorization and output plan
 * @returns Derived scripts and remittances
 */
async function deriveOutputs(args: OutputDerivationSnapshot): Promise<UptoDerivedOutputSpec[]> {
  const { publicKey: walletIdentity } = await args.getPublicKey(
    { identityKey: true },
    args.originator,
  );
  const expectedIdentity = args.perspective === "payer" ? args.senderIdentityKey : args.payTo;
  if (normalizePublicKey(walletIdentity) !== expectedIdentity) {
    throw new Error(`wallet identity does not match ${args.perspective} authorization identity`);
  }

  const outputs = new Array<UptoDerivedOutputSpec>(args.plan.length);
  for (let index = 0; index < args.plan.length; index += 1) {
    const planned = args.plan[index];
    const derivationSuffix = Utils.toBase64(
      Utils.toArray(`${args.timestamp} upto ${planned.role} ${planned.outputIndex}`, "utf8"),
    );
    const { publicKey } = await args.getPublicKey(
      keyRequest(args, planned.role, derivationSuffix),
      args.originator,
    );
    const lockingScript = new P2PKH().lock(PublicKey.fromString(publicKey).toHash() as number[]);
    outputs[index] = {
      ...planned,
      lockingScript,
      paymentRemittance: {
        derivationPrefix: args.derivationPrefix,
        derivationSuffix,
        senderIdentityKey: planned.role === "recipient" ? args.senderIdentityKey : args.payTo,
      },
    };
  }
  return outputs;
}

/**
 * Detaches the validated derivation inputs before the first wallet call.
 *
 * @param rawArgs - Mutable caller input
 * @param requireRecipient - Whether at least one recipient amount is required
 * @returns A closed authorization and output-plan snapshot
 */
function snapshotArguments(
  rawArgs: DeriveUptoOutputSpecsArgs,
  requireRecipient: boolean,
): OutputDerivationSnapshot {
  const wallet = rawArgs.wallet;
  const perspective = rawArgs.perspective;
  const factsRaw = rawArgs.facts;
  const recipientAmountsRaw = rawArgs.recipientAmounts;
  const refundAmountsRaw = rawArgs.refundAmounts;
  const originator = rawArgs.originator;
  const getPublicKey = wallet?.getPublicKey;
  if (typeof getPublicKey !== "function") {
    throw new Error("wallet.getPublicKey must be a function");
  }
  if (perspective !== "payer" && perspective !== "recipient") {
    throw new Error("wallet perspective must be payer or recipient");
  }

  const payTo = factsRaw.payTo;
  const senderIdentityKey = factsRaw.senderIdentityKey;
  const derivationPrefix = factsRaw.derivationPrefix;
  const derivationSuffix = factsRaw.derivationSuffix;
  const floorAmounts = new Array<number>(factsRaw.capInputs.length);
  for (let index = 0; index < factsRaw.capInputs.length; index += 1) {
    floorAmounts[index] = readSignedAmount(
      factsRaw.capInputs[index].floorAmount,
      `capInputs[${index}].floorAmount`,
    );
  }
  const recipientAmounts = captureAmounts(
    recipientAmountsRaw,
    "recipientAmounts",
    requireRecipient,
  );
  const refundAmounts = captureAmounts(refundAmountsRaw, "refundAmounts", false);
  const timestamp = decodeTimestamp(derivationSuffix);
  const plan = new Array<PlannedOutput>(
    floorAmounts.length + recipientAmounts.length + refundAmounts.length,
  );
  let outputIndex = appendPlan(plan, 0, "floor", floorAmounts);
  outputIndex = appendPlan(plan, outputIndex, "recipient", recipientAmounts);
  appendPlan(plan, outputIndex, "refund", refundAmounts);

  return {
    getPublicKey: getPublicKey.bind(wallet),
    perspective,
    payTo,
    senderIdentityKey,
    derivationPrefix,
    timestamp,
    originator,
    plan,
  };
}

/**
 * Selects the reciprocal BRC-42 derivation for one output role.
 *
 * @param args - Closed derivation context
 * @param role - Output owner role
 * @param derivationSuffix - Globally indexed role suffix
 * @returns Wallet public-key request
 */
function keyRequest(
  args: OutputDerivationSnapshot,
  role: UptoOutputRole,
  derivationSuffix: string,
): Parameters<WalletInterface["getPublicKey"]>[0] {
  const recipientOutput = role === "recipient";
  if (args.perspective === "payer") {
    return {
      protocolID: BRC29_PROTOCOL_ID,
      keyID: `${args.derivationPrefix} ${derivationSuffix}`,
      counterparty: args.payTo,
      ...(recipientOutput ? {} : { forSelf: true }),
    };
  }
  return {
    protocolID: BRC29_PROTOCOL_ID,
    keyID: `${args.derivationPrefix} ${derivationSuffix}`,
    counterparty: args.senderIdentityKey,
    ...(recipientOutput ? { forSelf: true } : {}),
  };
}

/**
 * Validates one amount array and detaches it before wallet derivation.
 *
 * @param value - Candidate amount array
 * @param field - Field name for rejection messages
 * @param nonEmpty - Whether the role requires at least one output
 * @returns A validated independent amount array
 */
function captureAmounts(value: unknown, field: string, nonEmpty: boolean): number[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array`);
  }
  const length = value.length;
  if (nonEmpty && length === 0) {
    throw new Error(`${field} must be non-empty`);
  }
  const amounts = new Array<number>(length);
  for (let index = 0; index < length; index += 1) {
    const amount = value[index];
    if (
      typeof amount !== "number" ||
      !Number.isSafeInteger(amount) ||
      Object.is(amount, -0) ||
      amount <= 0 ||
      amount > MAX_SATOSHIS
    ) {
      throw new Error(
        `${field}[${index}] must be a positive safe integer at or below the maximum BSV supply`,
      );
    }
    amounts[index] = amount;
  }
  return amounts;
}

/**
 * Converts a signed canonical amount to the SDK's safe integer representation.
 *
 * @param amount - Canonical decimal from a cap fact
 * @param field - Field name for rejection messages
 * @returns Safe positive satoshi value
 */
function readSignedAmount(amount: string, field: string): number {
  if (amount.length > String(MAX_SATOSHIS).length) {
    throw new Error(`${field} exceeds the supported BSV money range`);
  }
  const value = BigInt(amount);
  if (value <= 0n || value > BigInt(MAX_SATOSHIS)) {
    throw new Error(`${field} exceeds the supported BSV money range`);
  }
  return Number(value);
}

/**
 * Decodes the exact-style payment timestamp used to derive all role suffixes.
 *
 * @param derivationSuffix - Canonical base64 from the signed authorization
 * @returns Canonical decimal Unix-millisecond timestamp
 */
function decodeTimestamp(derivationSuffix: string): string {
  const timestamp = Utils.toUTF8(Utils.toArray(derivationSuffix, "base64"));
  if (!/^(?:0|[1-9]\d*)$/.test(timestamp) || !Number.isSafeInteger(Number(timestamp))) {
    throw new Error("derivationSuffix must encode a canonical Unix-ms timestamp");
  }
  return timestamp;
}

/**
 * Appends one role to the closed global output plan.
 *
 * @param plan - Preallocated result plan
 * @param outputIndex - First global output index for this role
 * @param role - Output role
 * @param amounts - Validated role amounts
 * @returns The next unused global output index
 */
function appendPlan(
  plan: PlannedOutput[],
  outputIndex: number,
  role: UptoOutputRole,
  amounts: number[],
): number {
  for (let amountIndex = 0; amountIndex < amounts.length; amountIndex += 1) {
    plan[outputIndex] = { role, outputIndex, satoshis: amounts[amountIndex] };
    outputIndex += 1;
  }
  return outputIndex;
}

/**
 * Parses and normalizes a wallet-returned compressed public key.
 *
 * @param value - Wallet result
 * @returns Lowercase compressed public key
 */
function normalizePublicKey(value: string): string {
  try {
    return PublicKey.fromString(value).toString().toLowerCase();
  } catch {
    throw new Error("wallet returned an invalid public key");
  }
}
