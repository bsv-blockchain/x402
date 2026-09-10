import {
  BigNumber,
  ECDSA,
  Hash,
  LockingScript,
  ProtoWallet,
  PublicKey,
  Signature,
  Transaction,
  UnlockingScript,
  Utils,
  type WalletInterface,
} from "@bsv/sdk";
import { validateAndDigestAuthorization, type ResolvedAuthorizationFacts } from "./authorization";
import { readDerBytes, readEncodedDer } from "./der";
import {
  deriveUptoFloorSpecs,
  deriveUptoOutputSpecs,
  type UptoDerivedOutputSpec,
  type UptoWalletPerspective,
} from "./outputs";
import { materializeAdmittedSource, type AdmittedSource } from "./source";
import {
  UPTO_AUTHORIZATION_PROTOCOL,
  UPTO_CAP_PROTOCOL,
  UPTO_CONTROL_PROTOCOL,
  deriveUptoSourcePublicKey,
  uptoSourceProtocol,
} from "./keys";

const FINAL_SEQUENCE = 0xffffffff;
const CAP_SIGHASH = 0x43;
const CONTROL_SIGHASH = 0x41;
const PUBLIC_DERIVER = new ProtoWallet("anyone");
declare const verifiedAuthorizationBrand: unique symbol;

type PublicKeyWallet = Pick<WalletInterface, "getPublicKey">;
type SigningWallet = Pick<WalletInterface, "getPublicKey" | "createSignature">;

/** Wire-ready signatures created by the payer in one authorization action. */
export interface CapAuthorization {
  readonly authorizationSignature: string;
  readonly transactionSignatures: readonly string[];
}

/** Opaque proof that signed wire fields, sources, keys, and floors agree. */
export interface VerifiedAuthorization {
  readonly [verifiedAuthorizationBrand]: true;
}

/** Fresh internal material exposed only to sibling deep-module validators. */
export interface MaterializedVerifiedAuthorization {
  readonly authorizationId: string;
  readonly facts: ResolvedAuthorizationFacts;
  readonly capInputs: readonly AdmittedSource[];
  readonly controlInputs: readonly AdmittedSource[];
  readonly capSignatures: readonly (readonly number[])[];
  readonly capInputTotal: bigint;
  readonly controlInputTotal: bigint;
  readonly floorOutputTotal: bigint;
  readonly floorOutputs: readonly {
    readonly satoshis: number;
    readonly lockingScript: readonly number[];
  }[];
}

interface CreateCapAuthorizationArgs {
  facts: ResolvedAuthorizationFacts;
  capInputs: readonly AdmittedSource[];
  controlInputs: readonly AdmittedSource[];
  wallet: SigningWallet;
  originator?: string;
}

interface VerifyPresentedAuthorizationArgs {
  facts: ResolvedAuthorizationFacts;
  authorizationSignature: string;
  transactionSignatures: readonly string[];
  capInputs: readonly AdmittedSource[];
  controlInputs: readonly AdmittedSource[];
  wallet: PublicKeyWallet;
  perspective: UptoWalletPerspective;
  originator?: string;
}

interface CreateTerminalTransactionArgs {
  authorization: VerifiedAuthorization;
  actualAmount: bigint;
  recipientAmounts: readonly number[];
  refundAmounts: readonly number[];
  wallet: SigningWallet;
  originator?: string;
}

interface MaterializedSource {
  source: AdmittedSource;
  sourceTransaction: Transaction;
  sourceTxid: string;
  sourceOutputIndex: number;
  satoshis: bigint;
  publicKey: string;
}

interface ResolvedAuthorization {
  facts: ResolvedAuthorizationFacts;
  digest: number[];
  capInputs: MaterializedSource[];
  controlInputs: MaterializedSource[];
  floorOutputs: UptoDerivedOutputSpec[];
}

const verifiedAuthorizations = new WeakMap<
  VerifiedAuthorization,
  MaterializedVerifiedAuthorization
>();

/**
 * Creates the payer's standalone authorization and reusable cap signatures.
 *
 * Source ownership, signed facts, and fixed floor derivation are checked before
 * the wallet is asked to sign. The result contains canonical base64 DER only;
 * unlocking scripts are reconstructed inside the transaction kernel.
 *
 * @param rawArgs - Signed facts, admitted ordered sources, and payer wallet
 * @returns Wire-ready standalone and per-cap signatures
 */
export async function createCapAuthorization(
  rawArgs: CreateCapAuthorizationArgs,
): Promise<CapAuthorization> {
  const facts = rawArgs.facts;
  const capInputs = captureSources(rawArgs.capInputs, "capInputs");
  const controlInputs = captureSources(rawArgs.controlInputs, "controlInputs");
  const wallet = captureSigningWallet(rawArgs.wallet);
  const originator = rawArgs.originator;
  const resolved = await resolveAuthorization({
    facts,
    capInputs,
    controlInputs,
    wallet,
    perspective: "payer",
    originator,
  });
  const template = capTemplate(resolved);

  const authorizationSignature = await walletSignDer(
    wallet.createSignature,
    {
      hashToDirectlySign: [...resolved.digest],
      protocolID: UPTO_AUTHORIZATION_PROTOCOL,
      keyID: `${resolved.facts.derivationPrefix} ${resolved.facts.derivationSuffix}`,
      counterparty: "anyone",
    },
    originator,
    "authorization signature",
  );
  await verifyAuthorizationSignature(resolved.facts, resolved.digest, authorizationSignature);

  const transactionSignatures = new Array<string>(resolved.capInputs.length);
  for (let index = 0; index < resolved.capInputs.length; index += 1) {
    const digest = Array.from(Hash.hash256(template.preimage(index, CAP_SIGHASH)));
    const der = await walletSignDer(
      wallet.createSignature,
      {
        hashToDirectlySign: [...digest],
        protocolID: UPTO_CAP_PROTOCOL,
        keyID: resolved.facts.capInputs[index].nonce,
        counterparty: "anyone",
      },
      originator,
      `cap transaction signature ${index}`,
    );
    verifiedUnlockingScript(
      resolved.capInputs[index].publicKey,
      der,
      digest,
      CAP_SIGHASH,
      "cap transaction signature",
    );
    transactionSignatures[index] = Utils.toBase64(der);
  }

  return Object.freeze({
    authorizationSignature: Utils.toBase64(authorizationSignature),
    transactionSignatures: Object.freeze(transactionSignatures),
  });
}

/**
 * Verifies a wire-native authorization without asking role code to build scripts.
 *
 * @param rawArgs - Presented canonical DER fields, signed facts, and admitted sources
 * @returns Opaque authority for terminal construction
 */
export async function verifyPresentedAuthorization(
  rawArgs: VerifyPresentedAuthorizationArgs,
): Promise<VerifiedAuthorization> {
  const facts = rawArgs.facts;
  const authorizationSignatureRaw = rawArgs.authorizationSignature;
  const transactionSignaturesRaw = captureStrings(
    rawArgs.transactionSignatures,
    "transactionSignatures",
  );
  const capInputs = captureSources(rawArgs.capInputs, "capInputs");
  const controlInputs = captureSources(rawArgs.controlInputs, "controlInputs");
  const wallet = capturePublicKeyWallet(rawArgs.wallet);
  const perspective = rawArgs.perspective;
  const originator = rawArgs.originator;

  const authorizationSignature = readEncodedDer(
    authorizationSignatureRaw,
    "authorization signature",
  );
  const capSignatures = transactionSignaturesRaw.map((signature, index) =>
    readEncodedDer(signature, `cap transaction signature ${index}`),
  );
  const resolved = await resolveAuthorization({
    facts,
    capInputs,
    controlInputs,
    wallet,
    perspective,
    originator,
  });
  if (capSignatures.length !== resolved.capInputs.length) {
    throw new Error("cap transaction signature count does not match cap inputs");
  }
  await verifyAuthorizationSignature(resolved.facts, resolved.digest, authorizationSignature);

  const template = capTemplate(resolved);
  for (let index = 0; index < resolved.capInputs.length; index += 1) {
    const digest = Array.from(Hash.hash256(template.preimage(index, CAP_SIGHASH)));
    verifiedUnlockingScript(
      resolved.capInputs[index].publicKey,
      capSignatures[index],
      digest,
      CAP_SIGHASH,
      "cap transaction signature",
    );
  }

  const token = Object.create(null) as VerifiedAuthorization;
  verifiedAuthorizations.set(
    token,
    Object.freeze({
      authorizationId: Utils.toHex(resolved.digest),
      facts: resolved.facts,
      capInputTotal: sumSources(resolved.capInputs),
      controlInputTotal: sumSources(resolved.controlInputs),
      floorOutputTotal: sumOutputs(resolved.floorOutputs),
      capInputs: Object.freeze(resolved.capInputs.map(source => source.source)),
      controlInputs: Object.freeze(resolved.controlInputs.map(source => source.source)),
      capSignatures: Object.freeze(capSignatures.map(bytes => Object.freeze([...bytes]))),
      floorOutputs: Object.freeze(
        resolved.floorOutputs.map(output =>
          Object.freeze({
            satoshis: output.satoshis,
            lockingScript: Object.freeze([...output.lockingScript.toBinary()]),
          }),
        ),
      ),
    }),
  );
  return token;
}

/**
 * Reads immutable material for a sibling terminal validator.
 *
 * @param authorization - Opaque verified authorization token
 * @returns Verified signed facts, source authorities, DER bytes, and fixed floors
 */
export function materializeVerifiedAuthorization(
  authorization: VerifiedAuthorization,
): MaterializedVerifiedAuthorization {
  const material = verifiedAuthorizations.get(authorization);
  if (material === undefined) {
    throw new Error("authorization was not issued by presented-authorization verification");
  }
  return material;
}

/**
 * Verifies one canonical P2PKH transaction unlock against its source key.
 *
 * Cap verification additionally supplies the exact DER bytes retained from
 * presentation, preventing a different valid signature from replacing the
 * payer's signed evidence.
 *
 * @param transaction - Hydrated transaction containing the signed input
 * @param inputIndex - Input whose canonical unlock is verified
 * @param publicKeyHex - Source P2PKH compressed public key
 * @param scope - Required sighash byte
 * @param expectedDer - Exact required DER bytes for a stored cap signature
 * @returns Independent validated DER bytes
 */
export function verifyCanonicalP2pkhInputUnlock(
  transaction: Transaction,
  inputIndex: number,
  publicKeyHex: string,
  scope: 0x41 | 0x43,
  expectedDer?: readonly number[],
): readonly number[] {
  const input = transaction.inputs[inputIndex];
  const unlockingScript = input?.unlockingScript;
  if (unlockingScript === undefined) {
    throw new Error(`terminal input ${inputIndex} is missing its unlocking script`);
  }
  const chunks = unlockingScript.chunks;
  if (chunks.length !== 2) {
    throw new Error(`terminal input ${inputIndex} must use a canonical P2PKH unlock`);
  }
  const signatureWithScope = chunks[0].data;
  const encodedPublicKey = chunks[1].data;
  if (
    signatureWithScope === undefined ||
    signatureWithScope.length < 2 ||
    chunks[0].op !== signatureWithScope.length ||
    encodedPublicKey === undefined ||
    chunks[1].op !== encodedPublicKey.length
  ) {
    throw new Error(`terminal input ${inputIndex} must use canonical direct pushes`);
  }
  if (signatureWithScope.at(-1) !== scope) {
    throw new Error(`terminal input ${inputIndex} uses the wrong sighash scope`);
  }
  const der = readDerBytes(
    signatureWithScope.slice(0, -1),
    `terminal input ${inputIndex} signature`,
  );
  if (expectedDer !== undefined && !bytesEqual(der, expectedDer)) {
    throw new Error(`terminal cap input ${inputIndex} does not preserve its stored signature`);
  }
  const publicKey = PublicKey.fromString(publicKeyHex);
  const expectedPublicKey = publicKey.encode(true) as number[];
  if (!bytesEqual(encodedPublicKey, expectedPublicKey)) {
    throw new Error(`terminal input ${inputIndex} public key does not match its source`);
  }
  const canonical = new UnlockingScript([
    { op: signatureWithScope.length, data: [...signatureWithScope] },
    { op: expectedPublicKey.length, data: [...expectedPublicKey] },
  ]).toBinary();
  if (!bytesEqual(unlockingScript.toBinary(), canonical)) {
    throw new Error(`terminal input ${inputIndex} must use a canonical P2PKH unlock`);
  }
  const digest = Array.from(Hash.hash256(transaction.preimage(inputIndex, scope)));
  if (!ECDSA.verify(new BigNumber(digest), Signature.fromDER(der), publicKey)) {
    throw new Error(`terminal input ${inputIndex} signature is invalid`);
  }
  return Object.freeze([...der]);
}

/**
 * Completes one terminal transaction from a verified authorization.
 *
 * All scripts are derived from the stored signed facts. The recipient supplies
 * only positive recipient/refund amount arrays and its wallet capability.
 *
 * @param rawArgs - Verified authorization, actual amount, variable amounts, and recipient wallet
 * @returns Fully signed terminal transaction
 */
export async function createTerminalTransaction(
  rawArgs: CreateTerminalTransactionArgs,
): Promise<Transaction> {
  const record = verifiedAuthorizations.get(rawArgs.authorization);
  if (record === undefined) {
    throw new Error("terminal construction requires a verified authorization");
  }
  const actualAmount = rawArgs.actualAmount;
  const recipientAmounts = captureNumbers(rawArgs.recipientAmounts, "recipientAmounts");
  const refundAmounts = captureNumbers(rawArgs.refundAmounts, "refundAmounts");
  const wallet = captureSigningWallet(rawArgs.wallet);
  const originator = rawArgs.originator;
  if (typeof actualAmount !== "bigint" || actualAmount < 0n) {
    throw new Error("actualAmount must be a non-negative bigint");
  }

  const outputs = await deriveUptoOutputSpecs({
    wallet,
    perspective: "recipient",
    facts: record.facts,
    recipientAmounts,
    refundAmounts,
    originator,
  });
  assertStoredFloors(record.floorOutputs, outputs.slice(0, record.capInputs.length));
  const capInputs = record.capInputs.map((source, index) =>
    materializedSource(source, "cap", `capInputs[${index}]`),
  );
  const controlInputs = record.controlInputs.map((source, index) =>
    materializedSource(source, "control", `controlInputs[${index}]`),
  );
  const transaction = new Transaction(
    1,
    [...capInputs, ...controlInputs].map(transactionInput),
    outputs.map(output => ({
      satoshis: output.satoshis,
      lockingScript: LockingScript.fromBinary(output.lockingScript.toBinary()),
    })),
    record.facts.deadline,
  );

  assertTerminalAccounting(record, capInputs, controlInputs, outputs, actualAmount);
  for (let index = 0; index < capInputs.length; index += 1) {
    const digest = Array.from(Hash.hash256(transaction.preimage(index, CAP_SIGHASH)));
    transaction.inputs[index].unlockingScript = verifiedUnlockingScript(
      capInputs[index].publicKey,
      [...record.capSignatures[index]],
      digest,
      CAP_SIGHASH,
      "stored cap transaction signature",
    );
  }
  for (let index = 0; index < controlInputs.length; index += 1) {
    const inputIndex = capInputs.length + index;
    const digest = Array.from(Hash.hash256(transaction.preimage(inputIndex, CONTROL_SIGHASH)));
    const der = await walletSignDer(
      wallet.createSignature,
      {
        hashToDirectlySign: [...digest],
        protocolID: UPTO_CONTROL_PROTOCOL,
        keyID: record.facts.controlInputs[index].nonce,
        counterparty: "anyone",
      },
      originator,
      `control transaction signature ${index}`,
    );
    transaction.inputs[inputIndex].unlockingScript = verifiedUnlockingScript(
      controlInputs[index].publicKey,
      der,
      digest,
      CONTROL_SIGHASH,
      "control transaction signature",
    );
  }
  return transaction;
}

/**
 * Resolve and cross-bind all fixed authorization material.
 *
 * @param args - Fixed authorization material
 * @param args.facts - Signed authorization facts
 * @param args.capInputs - Ordered admitted payer sources
 * @param args.controlInputs - Ordered admitted recipient sources
 * @param args.wallet - Wallet public-key capability
 * @param args.perspective - Wallet owner's protocol role
 * @param args.originator - Optional wallet originator
 * @returns Cross-bound authorization context
 */
async function resolveAuthorization(args: {
  facts: ResolvedAuthorizationFacts;
  capInputs: readonly AdmittedSource[];
  controlInputs: readonly AdmittedSource[];
  wallet: PublicKeyWallet;
  perspective: UptoWalletPerspective;
  originator?: string;
}): Promise<ResolvedAuthorization> {
  const validated = validateAndDigestAuthorization(args.facts);
  const capInputs = args.capInputs.map((source, index) =>
    materializedSource(source, "cap", `capInputs[${index}]`),
  );
  const controlInputs = args.controlInputs.map((source, index) =>
    materializedSource(source, "control", `controlInputs[${index}]`),
  );
  assertSourcesMatchFacts(validated.snapshot, capInputs, controlInputs);
  await assertSourceKeyBindings(
    validated.snapshot,
    capInputs,
    controlInputs,
    args.wallet,
    args.perspective,
    args.originator,
  );
  const floorOutputs = await deriveUptoFloorSpecs({
    wallet: args.wallet,
    perspective: args.perspective,
    facts: validated.snapshot,
    originator: args.originator,
  });
  assertAuthorizationAmounts(validated.snapshot, capInputs, floorOutputs);
  return {
    facts: validated.snapshot,
    digest: validated.digest,
    capInputs,
    controlInputs,
    floorOutputs,
  };
}

/**
 * Verify role, source authority, and return a fresh transaction.
 *
 * @param source - Admitted source artifact
 * @param role - Required source role
 * @param name - Field name for errors
 * @returns Fresh source transaction and immutable facts
 */
function materializedSource(
  source: AdmittedSource,
  role: "cap" | "control",
  name: string,
): MaterializedSource {
  const materialized = materializeAdmittedSource(source);
  if (materialized.role !== role) {
    throw new Error(`${name} must have role ${role}`);
  }
  return {
    source,
    sourceTransaction: materialized.sourceTransaction,
    sourceTxid: source.sourceTxid,
    sourceOutputIndex: materialized.sourceOutputIndex,
    satoshis: source.satoshis,
    publicKey: materialized.publicKey,
  };
}

/**
 * Bind source ordering and outpoints to the signed projection.
 *
 * @param facts - Signed authorization facts
 * @param capInputs - Ordered cap sources
 * @param controlInputs - Ordered control sources
 */
function assertSourcesMatchFacts(
  facts: ResolvedAuthorizationFacts,
  capInputs: MaterializedSource[],
  controlInputs: MaterializedSource[],
): void {
  if (
    capInputs.length !== facts.capInputs.length ||
    controlInputs.length !== facts.controlInputs.length
  ) {
    throw new Error("admitted source counts do not match signed authorization");
  }
  for (let index = 0; index < capInputs.length; index += 1) {
    assertSourceFact(capInputs[index], facts.capInputs[index], `cap source ${index}`);
  }
  for (let index = 0; index < controlInputs.length; index += 1) {
    assertSourceFact(controlInputs[index], facts.controlInputs[index], `control source ${index}`);
  }
}

/**
 * Verify every admitted P2PKH key is the signed role's BRC-42 key.
 *
 * @param facts - Signed authorization facts
 * @param capInputs - Ordered cap sources
 * @param controlInputs - Ordered control sources
 * @param wallet - Wallet public-key capability
 * @param perspective - Wallet owner's protocol role
 * @param originator - Optional wallet originator
 */
async function assertSourceKeyBindings(
  facts: ResolvedAuthorizationFacts,
  capInputs: MaterializedSource[],
  controlInputs: MaterializedSource[],
  wallet: PublicKeyWallet,
  perspective: UptoWalletPerspective,
  originator?: string,
): Promise<void> {
  const groups = [
    {
      role: "cap" as const,
      protocolID: uptoSourceProtocol("cap"),
      owner: facts.senderIdentityKey,
      facts: facts.capInputs,
      sources: capInputs,
    },
    {
      role: "control" as const,
      protocolID: uptoSourceProtocol("control"),
      owner: facts.payTo,
      facts: facts.controlInputs,
      sources: controlInputs,
    },
  ];
  for (const group of groups) {
    for (let index = 0; index < group.sources.length; index += 1) {
      const expected = await deriveUptoSourcePublicKey(
        group.role,
        group.facts[index].nonce,
        group.owner,
      );
      if (normalizePublicKey(group.sources[index].publicKey) !== expected) {
        throw new Error(`${group.role} source public key does not match signed authorization`);
      }
      const owned =
        (perspective === "payer" && group.role === "cap") ||
        (perspective === "recipient" && group.role === "control");
      if (owned) {
        const { publicKey: ownerDerived } = await wallet.getPublicKey(
          {
            protocolID: group.protocolID,
            keyID: group.facts[index].nonce,
            counterparty: "anyone",
            forSelf: true,
          },
          originator,
        );
        if (normalizePublicKey(ownerDerived) !== expected) {
          throw new Error(`${perspective} wallet cannot derive its signed ${group.role} source`);
        }
      }
    }
  }
}

/**
 * Build the fixed cap signing template.
 *
 * @param authorization - Resolved fixed authorization
 * @returns Unsigned cap transaction template
 */
function capTemplate(authorization: ResolvedAuthorization): Transaction {
  return new Transaction(
    1,
    [...authorization.capInputs, ...authorization.controlInputs].map(transactionInput),
    authorization.floorOutputs.map(output => ({
      satoshis: output.satoshis,
      lockingScript: LockingScript.fromBinary(output.lockingScript.toBinary()),
    })),
    authorization.facts.deadline,
  );
}

/**
 * Convert a source snapshot to a final-sequence input.
 *
 * @param source - Materialized admitted source
 * @returns Final-sequence transaction input
 */
function transactionInput(source: MaterializedSource) {
  return {
    sourceTransaction: source.sourceTransaction,
    sourceOutputIndex: source.sourceOutputIndex,
    sequence: FINAL_SEQUENCE,
  };
}

/**
 * Enforce E >= M after signed floors have been derived.
 *
 * @param facts - Signed authorization facts
 * @param capInputs - Payer cap sources
 * @param floors - Derived fixed floor outputs
 */
function assertAuthorizationAmounts(
  facts: ResolvedAuthorizationFacts,
  capInputs: MaterializedSource[],
  floors: UptoDerivedOutputSpec[],
): void {
  const maximum = BigInt(facts.maximumAmount);
  const exposure = sumSources(capInputs) - sumOutputs(floors);
  if (exposure < maximum) {
    throw new Error("payer exposure is below maximumAmount");
  }
}

/**
 * Enforce A/M/E/F/R accounting before any control signature is requested.
 *
 * @param record - Verified authorization record
 * @param capInputs - Payer cap sources
 * @param controlInputs - Recipient control sources
 * @param outputs - Complete derived terminal outputs
 * @param actualAmount - Claimed service amount
 */
function assertTerminalAccounting(
  record: MaterializedVerifiedAuthorization,
  capInputs: MaterializedSource[],
  controlInputs: MaterializedSource[],
  outputs: UptoDerivedOutputSpec[],
  actualAmount: bigint,
): void {
  const maximum = BigInt(record.facts.maximumAmount);
  if (actualAmount > maximum) {
    throw new Error("actualAmount exceeds the authorized maximum");
  }
  const floors = outputs.filter(output => output.role === "floor");
  const recipients = outputs.filter(output => output.role === "recipient");
  const refunds = outputs.filter(output => output.role === "refund");
  const capTotal = sumSources(capInputs);
  const controlTotal = sumSources(controlInputs);
  const floorTotal = sumOutputs(floors);
  const recipientTotal = sumOutputs(recipients);
  const refundTotal = sumOutputs(refunds);
  const exposure = capTotal - floorTotal;
  if (recipientTotal - controlTotal !== actualAmount) {
    throw new Error("recipient net amount does not equal actualAmount");
  }
  const fee = capTotal + controlTotal - floorTotal - recipientTotal - refundTotal;
  if (fee < 0n) {
    throw new Error("terminal outputs exceed inputs");
  }
  if (fee > exposure - maximum) {
    throw new Error("terminal fee exceeds authorized headroom");
  }
}

/**
 * Ensure re-derived terminal floors are the exact stored signed floors.
 *
 * @param stored - Floors fixed during presentation verification
 * @param derived - Floors re-derived for terminal construction
 */
function assertStoredFloors(
  stored: MaterializedVerifiedAuthorization["floorOutputs"],
  derived: UptoDerivedOutputSpec[],
): void {
  if (stored.length !== derived.length) {
    throw new Error("derived floor count differs from the verified authorization");
  }
  for (let index = 0; index < stored.length; index += 1) {
    if (
      stored[index].satoshis !== derived[index].satoshis ||
      !bytesEqual(stored[index].lockingScript, derived[index].lockingScript.toBinary())
    ) {
      throw new Error("derived floor differs from the verified authorization");
    }
  }
}

/**
 * Verify the standalone authorization through the public anyone derivation.
 *
 * @param facts - Signed authorization facts
 * @param digest - Canonical authorization digest
 * @param signature - Validated DER signature bytes
 */
async function verifyAuthorizationSignature(
  facts: ResolvedAuthorizationFacts,
  digest: number[],
  signature: number[],
): Promise<void> {
  let valid = false;
  try {
    valid = (
      await PUBLIC_DERIVER.verifySignature({
        signature: [...signature],
        hashToDirectlyVerify: [...digest],
        protocolID: UPTO_AUTHORIZATION_PROTOCOL,
        keyID: `${facts.derivationPrefix} ${facts.derivationSuffix}`,
        counterparty: facts.senderIdentityKey,
      })
    ).valid;
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new Error("authorization signature is invalid");
  }
}

/**
 * Ask a wallet to sign one digest and validate its returned DER.
 *
 * @param createSignature - Bound wallet signing method
 * @param request - BRC-100 signature request
 * @param originator - Optional wallet originator
 * @param name - Field name for errors
 * @returns Validated independent DER bytes
 */
async function walletSignDer(
  createSignature: WalletInterface["createSignature"],
  request: Parameters<WalletInterface["createSignature"]>[0],
  originator: string | undefined,
  name: string,
): Promise<number[]> {
  const result = await createSignature(request, originator);
  return readDerBytes(result.signature, name);
}

/**
 * Validate a DER signature and build the canonical two-push P2PKH unlock.
 *
 * @param publicKeyHex - Expected compressed public key
 * @param der - Exact validated DER signature bytes
 * @param digest - Transaction signature digest
 * @param scope - Required sighash byte
 * @param name - Field name for errors
 * @returns Canonical two-push unlocking script
 */
function verifiedUnlockingScript(
  publicKeyHex: string,
  der: number[],
  digest: number[],
  scope: number,
  name: string,
): UnlockingScript {
  const signature = Signature.fromDER(der);
  const publicKey = PublicKey.fromString(publicKeyHex);
  if (!ECDSA.verify(new BigNumber(digest), signature, publicKey)) {
    throw new Error(`${name} is for the wrong digest or key`);
  }
  const checksig = [...der, scope];
  const encodedPublicKey = publicKey.encode(true) as number[];
  return new UnlockingScript([
    { op: checksig.length, data: checksig },
    { op: encodedPublicKey.length, data: encodedPublicKey },
  ]);
}

/**
 * Detach one admitted-source array before terminal construction.
 *
 * @param raw - Candidate source array
 * @param name - Field name for errors
 * @returns Independent ordered source references
 */
function captureSources(raw: readonly AdmittedSource[], name: string): AdmittedSource[] {
  if (!Array.isArray(raw)) throw new Error(`${name} must be an array`);
  const length = raw.length;
  const result = new Array<AdmittedSource>(length);
  for (let index = 0; index < length; index += 1) result[index] = raw[index];
  return result;
}

/**
 * Validate and detach one wire string array before terminal construction.
 *
 * @param raw - Candidate string array
 * @param name - Field name for errors
 * @returns Independent ordered strings
 */
function captureStrings(raw: readonly string[], name: string): string[] {
  if (!Array.isArray(raw)) throw new Error(`${name} must be an array`);
  const length = raw.length;
  const result = new Array<string>(length);
  for (let index = 0; index < length; index += 1) {
    const value = raw[index];
    if (typeof value !== "string") throw new Error(`${name}[${index}] must be a string`);
    result[index] = value;
  }
  return result;
}

/**
 * Detach one output-amount array before any wallet await.
 *
 * @param raw - Candidate amount array
 * @param name - Field name for errors
 * @returns Independent ordered values
 */
function captureNumbers(raw: readonly number[], name: string): number[] {
  if (!Array.isArray(raw)) throw new Error(`${name} must be an array`);
  const length = raw.length;
  const result = new Array<number>(length);
  for (let index = 0; index < length; index += 1) result[index] = raw[index];
  return result;
}

/**
 * Bind the wallet public-key capability before signing.
 *
 * @param wallet - Candidate wallet capability
 * @returns Bound public-key capability
 */
function capturePublicKeyWallet(wallet: PublicKeyWallet): PublicKeyWallet {
  const getPublicKey = wallet?.getPublicKey;
  if (typeof getPublicKey !== "function") throw new Error("wallet.getPublicKey must be a function");
  return { getPublicKey: getPublicKey.bind(wallet) };
}

/**
 * Bind the wallet key and signature capabilities before signing.
 *
 * @param wallet - Candidate wallet capability
 * @returns Bound public-key and signing capabilities
 */
function captureSigningWallet(wallet: SigningWallet): SigningWallet {
  const publicWallet = capturePublicKeyWallet(wallet);
  const createSignature = wallet?.createSignature;
  if (typeof createSignature !== "function") {
    throw new Error("wallet.createSignature must be a function");
  }
  return { ...publicWallet, createSignature: createSignature.bind(wallet) };
}

/**
 * Assert one admitted source matches its signed outpoint.
 *
 * @param source - Admitted source facts
 * @param fact - Signed outpoint fact
 * @param fact.sourceTxid - Signed subject txid
 * @param fact.sourceOutputIndex - Signed output index
 * @param name - Field name for errors
 */
function assertSourceFact(
  source: MaterializedSource,
  fact: { readonly sourceTxid: string; readonly sourceOutputIndex: number },
  name: string,
): void {
  if (
    source.sourceTxid !== fact.sourceTxid ||
    source.sourceOutputIndex !== fact.sourceOutputIndex
  ) {
    throw new Error(`${name} does not match signed authorization`);
  }
}

/**
 * Sum source satoshis with bigint arithmetic.
 *
 * @param sources - Materialized sources
 * @returns Aggregate input value
 */
function sumSources(sources: MaterializedSource[]): bigint {
  return sources.reduce((sum, source) => sum + source.satoshis, 0n);
}

/**
 * Sum output satoshis with bigint arithmetic.
 *
 * @param outputs - Derived outputs
 * @returns Aggregate output value
 */
function sumOutputs(outputs: Array<{ satoshis: number }>): bigint {
  return outputs.reduce((sum, output) => sum + BigInt(output.satoshis), 0n);
}

/**
 * Parse and normalize a compressed public key.
 *
 * @param value - Candidate compressed public key
 * @returns Normalized compressed public key
 */
function normalizePublicKey(value: string): string {
  try {
    return PublicKey.fromString(value).toString().toLowerCase();
  } catch {
    throw new Error("wallet returned an invalid public key");
  }
}

/**
 * Compare byte arrays without coercion.
 *
 * @param left - First byte sequence
 * @param right - Second byte sequence
 * @returns Whether byte sequences are equal
 */
function bytesEqual(left: readonly number[], right: readonly number[]): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}
