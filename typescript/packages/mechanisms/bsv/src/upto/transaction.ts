import {
  Beef,
  BigNumber,
  ECDSA,
  Hash,
  LockingScript,
  PublicKey,
  Signature,
  Spend,
  Transaction,
  TransactionSignature,
  UnlockingScript,
  Utils,
} from "@bsv/sdk";
import type {
  UptoBsvAuthorizationTerms,
  UptoBsvAuthorization,
  UptoBsvCapSignature,
  UptoBsvInput,
  UptoBsvTransactionVersion,
} from "../types";
import { BSV_ASSET_IDENTIFIER, COMPRESSED_PUBKEY_REGEX, MAX_SATOSHIS } from "../constants";

const AUTHORIZATION_DOMAIN = "x402-bsv-upto-authorization-v1";
const FINAL_SEQUENCE = 0xffffffff;
const LOCKTIME_TIMESTAMP_THRESHOLD = 500_000_000;
const CAP_SIGHASH = TransactionSignature.SIGHASH_SINGLE | TransactionSignature.SIGHASH_FORKID;
const CONTROL_SIGHASH = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_FORKID;

export type UptoBsvDigestSigner = (digest: number[]) => Promise<number[]>;
export type UptoBsvInputSigners = Readonly<Record<number, UptoBsvDigestSigner>>;

interface DecodedInput extends UptoBsvInput {
  source: Transaction;
  sourceSatoshis: number;
  sourceLockingScript: string;
}

interface DecodedTerms extends Omit<UptoBsvAuthorizationTerms, "inputs"> {
  inputs: DecodedInput[];
}

export interface VerifiedUptoBsvAuthorization {
  authorization: UptoBsvAuthorization;
  terms: DecodedTerms;
  maximumAmount: string;
}

export interface VerifiedUptoBsvTransactionVersion {
  version: UptoBsvTransactionVersion;
  transaction: Transaction;
  txid: string;
  /** Common nSequence used by every control input. */
  nSequence: number;
  /** True when final control sequences make nLockTime inoperative. */
  cooperativeClose: boolean;
  outputAmounts: string[];
  ownerDeltas: Readonly<Record<string, string>>;
  amount: string;
}

export interface BuildUptoBsvTransactionVersionArgs {
  /** Common nSequence for every control input. */
  nSequence: number;
  outputAmounts: readonly string[];
}

const decodeBeefSubject = (encoded: string): Transaction => {
  const bytes = Utils.toArray(encoded, "base64");
  if (!Beef.fromBinary(bytes).isValid()) {
    throw new Error("BEEF must contain complete source ancestry");
  }
  return Transaction.fromBEEF(bytes);
};

const sourceOutpoint = (input: DecodedInput): string =>
  `${input.source.id("hex")}:${input.sourceOutputIndex}`;

const parseSatoshis = (value: string, name: string): bigint => {
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be decimal satoshis`);
  const parsed = BigInt(value);
  if (parsed < 0n || parsed > BigInt(MAX_SATOSHIS)) {
    throw new Error(`${name} is outside the BSV satoshi range`);
  }
  return parsed;
};

const toSafeSatoshis = (value: bigint, name: string): number => {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${name} cannot be represented safely`);
  }
  return Number(value);
};

const assertIdentifier = (value: string, name: string): void => {
  if (typeof value !== "string" || value.length < 1 || value.length > 512) {
    throw new Error(`${name} must contain 1..512 characters`);
  }
};

const assertPublicKey = (value: string, name: string): void => {
  if (!COMPRESSED_PUBKEY_REGEX.test(value)) throw new Error(`${name} is not a compressed key`);
  PublicKey.fromString(value);
};

const p2pkhHash = (lockingScript: string): string | undefined =>
  /^76a914([0-9a-f]{40})88ac$/i.exec(lockingScript)?.[1]?.toLowerCase();

const assertInputKey = (input: DecodedInput, index: number): void => {
  const expected = PublicKey.fromString(input.publicKey).toHash("hex") as string;
  if (p2pkhHash(input.sourceLockingScript) !== expected.toLowerCase()) {
    throw new Error(`input ${index} source is not P2PKH for its publicKey`);
  }
};

const decodeTerms = (terms: UptoBsvAuthorizationTerms): DecodedTerms => {
  if (terms.version !== 1) throw new Error("unsupported BSV upto authorization version");
  assertIdentifier(terms.network, "network");
  if (terms.asset.toUpperCase() !== BSV_ASSET_IDENTIFIER) {
    throw new Error("BSV upto supports native BSV only");
  }
  assertPublicKey(terms.payTo, "payTo");
  assertPublicKey(terms.senderIdentityKey, "senderIdentityKey");
  assertIdentifier(terms.derivationPrefix, "derivationPrefix");
  assertIdentifier(terms.derivationSuffix, "derivationSuffix");
  if (!Array.isArray(terms.inputs) || terms.inputs.length < 2) {
    throw new Error("authorization requires cap and control inputs");
  }
  if (!Array.isArray(terms.outputs) || terms.outputs.length < 2) {
    throw new Error("authorization requires outputs");
  }
  if (!Number.isInteger(terms.sequenceStart) || terms.sequenceStart < 1) {
    throw new Error("sequenceStart must be a positive uint32");
  }
  if (terms.sequenceStart >= FINAL_SEQUENCE) {
    throw new Error("sequenceStart must leave room for non-final sequences");
  }
  if (
    !Number.isSafeInteger(terms.validAfter) ||
    !Number.isSafeInteger(terms.deadline) ||
    !Number.isSafeInteger(terms.nLockTime) ||
    terms.validAfter < 0 ||
    terms.nLockTime <= terms.validAfter ||
    terms.deadline <= terms.nLockTime ||
    terms.nLockTime < LOCKTIME_TIMESTAMP_THRESHOLD ||
    terms.deadline > FINAL_SEQUENCE
  ) {
    throw new Error("validAfter, nLockTime, and deadline must define a time-based uint32 window");
  }
  parseSatoshis(terms.fee, "fee");

  const inputs: DecodedInput[] = terms.inputs.map((input, index) => {
    assertIdentifier(input.owner, `input ${index} owner`);
    if (input.kind !== "cap" && input.kind !== "control") {
      throw new Error(`input ${index} has an invalid kind`);
    }
    assertPublicKey(input.publicKey, `input ${index} publicKey`);
    if (!Number.isInteger(input.sourceOutputIndex) || input.sourceOutputIndex < 0) {
      throw new Error(`input ${index} has an invalid sourceOutputIndex`);
    }
    const source = decodeBeefSubject(input.sourceTransaction);
    const output = source.outputs[input.sourceOutputIndex];
    if (!output || output.satoshis === undefined) {
      throw new Error(`input ${index} source output is missing`);
    }
    if (
      !Number.isSafeInteger(output.satoshis) ||
      output.satoshis < 0 ||
      output.satoshis > MAX_SATOSHIS
    ) {
      throw new Error(`input ${index} source satoshis are outside the BSV satoshi range`);
    }
    const decoded: DecodedInput = {
      ...input,
      source,
      sourceSatoshis: output.satoshis,
      sourceLockingScript: output.lockingScript.toHex(),
    };
    assertInputKey(decoded, index);
    return decoded;
  });
  const inputTotal = inputs.reduce((sum, input) => sum + BigInt(input.sourceSatoshis), 0n);
  if (inputTotal > BigInt(MAX_SATOSHIS)) {
    throw new Error("authorization input total is outside the BSV satoshi range");
  }

  const firstControl = inputs.findIndex(input => input.kind === "control");
  if (firstControl < 1 || inputs.slice(firstControl).some(input => input.kind !== "control")) {
    throw new Error("cap inputs must precede control inputs");
  }
  if (terms.outputs.length < firstControl) {
    throw new Error("every cap input requires a same-index floor output");
  }
  const seenOutpoints = new Set<string>();
  inputs.forEach(input => {
    const outpoint = sourceOutpoint(input);
    if (seenOutpoints.has(outpoint)) throw new Error(`duplicate input ${outpoint}`);
    seenOutpoints.add(outpoint);
  });

  const owners = new Set(inputs.map(input => input.owner));
  terms.outputs.forEach((output, index) => {
    assertIdentifier(output.owner, `output ${index} owner`);
    owners.add(output.owner);
    if (!/^(?:[0-9a-f]{2})+$/i.test(output.lockingScript)) {
      throw new Error(`output ${index} lockingScript must be hex`);
    }
    if (index < firstControl) {
      if (
        output.owner !== inputs[index].owner ||
        output.fixedAmount === undefined ||
        output.lockingScript.toLowerCase() !== inputs[index].sourceLockingScript.toLowerCase()
      ) {
        throw new Error(`output ${index} must be its cap input's same-owner floor`);
      }
      const floor = parseSatoshis(output.fixedAmount, `output ${index} fixedAmount`);
      if (floor > BigInt(inputs[index].sourceSatoshis)) {
        throw new Error(`output ${index} floor exceeds its cap input`);
      }
    } else if (output.fixedAmount !== undefined) {
      parseSatoshis(output.fixedAmount, `output ${index} fixedAmount`);
    }
  });

  if (!Array.isArray(terms.chargedOwners) || terms.chargedOwners.length < 1) {
    throw new Error("chargedOwners must not be empty");
  }
  const uniqueCharged = new Set(terms.chargedOwners);
  if (
    uniqueCharged.size !== terms.chargedOwners.length ||
    terms.chargedOwners.some(owner => !owners.has(owner))
  ) {
    throw new Error("chargedOwners must be unique known owners");
  }
  for (const owner of terms.chargedOwners) {
    if (!inputs.some(input => input.kind === "cap" && input.owner === owner)) {
      throw new Error(`charged owner ${owner} has no cap input`);
    }
    const ownerScripts = new Set(
      inputs
        .filter(input => input.kind === "cap" && input.owner === owner)
        .map(input => input.sourceLockingScript.toLowerCase()),
    );
    if (
      terms.outputs.some(
        output => output.owner === owner && !ownerScripts.has(output.lockingScript.toLowerCase()),
      )
    ) {
      throw new Error(`charged owner ${owner} has an output not controlled by its cap keys`);
    }
  }

  if (!Array.isArray(terms.paymentOutputIndexes) || terms.paymentOutputIndexes.length < 1) {
    throw new Error("paymentOutputIndexes must not be empty");
  }
  const paymentIndexes = new Set(terms.paymentOutputIndexes);
  if (
    paymentIndexes.size !== terms.paymentOutputIndexes.length ||
    terms.paymentOutputIndexes.some(
      index =>
        !Number.isInteger(index) ||
        index < 0 ||
        index >= terms.outputs.length ||
        terms.outputs[index].owner.toLowerCase() !== terms.payTo.toLowerCase(),
    )
  ) {
    throw new Error("payment outputs must be unique outputs owned by payTo");
  }

  return { ...terms, asset: "BSV", inputs };
};

const canonicalTerms = (terms: DecodedTerms): unknown[] => [
  terms.version,
  terms.network,
  terms.asset,
  terms.payTo.toLowerCase(),
  terms.senderIdentityKey.toLowerCase(),
  terms.derivationPrefix,
  terms.derivationSuffix,
  terms.inputs.map(input => [
    input.owner,
    input.kind,
    input.source.id("hex"),
    input.sourceOutputIndex,
    String(input.sourceSatoshis),
    input.sourceLockingScript.toLowerCase(),
    input.publicKey.toLowerCase(),
  ]),
  terms.outputs.map(output => [
    output.owner,
    output.lockingScript.toLowerCase(),
    output.fixedAmount === undefined
      ? null
      : parseSatoshis(output.fixedAmount, "fixedAmount").toString(),
  ]),
  terms.chargedOwners,
  terms.paymentOutputIndexes,
  parseSatoshis(terms.fee, "fee").toString(),
  terms.sequenceStart,
  terms.validAfter,
  terms.deadline,
  terms.nLockTime,
];

export const uptoAuthorizationDigest = (terms: UptoBsvAuthorizationTerms): number[] => {
  const decoded = decodeTerms(terms);
  return Hash.sha256([
    ...Utils.toArray(AUTHORIZATION_DOMAIN, "utf8"),
    0,
    ...Utils.toArray(JSON.stringify(canonicalTerms(decoded)), "utf8"),
  ]);
};

export const uptoAuthorizationId = (terms: UptoBsvAuthorizationTerms): string =>
  Utils.toHex(uptoAuthorizationDigest(terms));

const sourceSatoshisByOwner = (terms: DecodedTerms): Map<string, bigint> => {
  const result = new Map<string, bigint>();
  terms.inputs.forEach(input => {
    result.set(input.owner, (result.get(input.owner) ?? 0n) + BigInt(input.sourceSatoshis));
  });
  return result;
};

const maximumByOwner = (terms: DecodedTerms): Map<string, bigint> => {
  const result = new Map<string, bigint>();
  terms.inputs.forEach((input, index) => {
    if (input.kind !== "cap") return;
    const floor = parseSatoshis(terms.outputs[index].fixedAmount ?? "", `floor ${index}`);
    result.set(input.owner, (result.get(input.owner) ?? 0n) + BigInt(input.sourceSatoshis) - floor);
  });
  return result;
};

export const uptoMaximumAmount = (terms: UptoBsvAuthorizationTerms): string => {
  const decoded = decodeTerms(terms);
  const maxima = maximumByOwner(decoded);
  return decoded.chargedOwners
    .reduce((sum, owner) => sum + (maxima.get(owner) ?? 0n), 0n)
    .toString();
};

const signatureDigest = (transaction: Transaction, inputIndex: number, scope: number): number[] =>
  Hash.hash256(transaction.preimage(inputIndex, scope));

const unlockingScript = (
  signature: number[],
  publicKey: string,
  scope: number,
): UnlockingScript => {
  const signatureWithScope = [...signature, scope & 0xff];
  const key = PublicKey.fromString(publicKey).encode(true) as number[];
  return new UnlockingScript([
    { op: signatureWithScope.length, data: signatureWithScope },
    { op: key.length, data: key },
  ]);
};

const buildTemplate = (terms: DecodedTerms, sequence: number): Transaction => {
  const transaction = new Transaction(1, [], [], terms.nLockTime);
  terms.inputs.forEach(input => {
    transaction.addInput({
      sourceTransaction: input.source,
      sourceOutputIndex: input.sourceOutputIndex,
      unlockingScript: new UnlockingScript(),
      sequence: input.kind === "cap" ? FINAL_SEQUENCE : sequence,
    });
  });
  terms.outputs.forEach(output => {
    transaction.addOutput({
      lockingScript: LockingScript.fromHex(output.lockingScript),
      satoshis: toSafeSatoshis(
        output.fixedAmount === undefined ? 0n : parseSatoshis(output.fixedAmount, "fixedAmount"),
        "fixedAmount",
      ),
    });
  });
  return transaction;
};

const capIndexes = (terms: DecodedTerms): number[] =>
  terms.inputs.flatMap((input, index) => (input.kind === "cap" ? [index] : []));

const controlIndexes = (terms: DecodedTerms): number[] =>
  terms.inputs.flatMap((input, index) => (input.kind === "control" ? [index] : []));

const requireSigner = (signers: UptoBsvInputSigners, index: number): UptoBsvDigestSigner => {
  const signer = signers[index];
  if (!signer) throw new Error(`missing signer for input ${index}`);
  return signer;
};

const validateSpend = (transaction: Transaction, inputIndex: number): boolean => {
  const input = transaction.inputs[inputIndex];
  const source = input.sourceTransaction;
  const sourceOutput = source?.outputs[input.sourceOutputIndex];
  if (!source || !sourceOutput || !input.unlockingScript) return false;
  try {
    return new Spend({
      sourceTXID: input.sourceTXID ?? source.id("hex"),
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: sourceOutput.satoshis ?? 0,
      lockingScript: sourceOutput.lockingScript,
      transactionVersion: transaction.version,
      otherInputs: transaction.inputs.filter((_, index) => index !== inputIndex),
      outputs: transaction.outputs,
      unlockingScript: input.unlockingScript,
      inputSequence: input.sequence ?? FINAL_SEQUENCE,
      inputIndex,
      lockTime: transaction.lockTime,
    }).validate();
  } catch {
    return false;
  }
};

const directSignatureValid = (digest: number[], encoded: string, publicKey: string): boolean => {
  try {
    return ECDSA.verify(
      new BigNumber(digest),
      Signature.fromDER(encoded, "base64"),
      PublicKey.fromString(publicKey),
    );
  } catch {
    return false;
  }
};

export const signUptoAuthorization = async (
  terms: UptoBsvAuthorizationTerms,
  signers: UptoBsvInputSigners,
): Promise<UptoBsvAuthorization> => {
  const decoded = decodeTerms(terms);
  const digest = uptoAuthorizationDigest(terms);
  const template = buildTemplate(decoded, decoded.sequenceStart);
  const capSignatures: UptoBsvCapSignature[] = [];
  for (const index of capIndexes(decoded)) {
    const signer = requireSigner(signers, index);
    const transactionSignature = await signer(signatureDigest(template, index, CAP_SIGHASH));
    const authorizationSignature = await signer(digest);
    capSignatures.push({
      inputIndex: index,
      transactionSignature: Utils.toBase64(transactionSignature),
      authorizationSignature: Utils.toBase64(authorizationSignature),
    });
  }
  return { authorizationId: Utils.toHex(digest), terms, capSignatures };
};

export const verifyUptoAuthorization = (
  authorization: UptoBsvAuthorization,
): VerifiedUptoBsvAuthorization => {
  const terms = decodeTerms(authorization.terms);
  const digest = uptoAuthorizationDigest(authorization.terms);
  if (authorization.authorizationId !== Utils.toHex(digest)) {
    throw new Error("authorizationId does not match its canonical terms");
  }
  const indexes = capIndexes(terms);
  if (authorization.capSignatures.length !== indexes.length) {
    throw new Error("authorization must contain one signature pair per cap input");
  }
  const byIndex = new Map<number, UptoBsvCapSignature>();
  authorization.capSignatures.forEach(signature => {
    if (byIndex.has(signature.inputIndex)) throw new Error("duplicate cap signature");
    byIndex.set(signature.inputIndex, signature);
  });
  const template = buildTemplate(terms, terms.sequenceStart);
  indexes.forEach(index => {
    const signature = byIndex.get(index);
    if (!signature) throw new Error(`missing cap signature for input ${index}`);
    if (
      !directSignatureValid(digest, signature.authorizationSignature, terms.inputs[index].publicKey)
    ) {
      throw new Error(`invalid authorization signature for input ${index}`);
    }
    template.inputs[index].unlockingScript = unlockingScript(
      Utils.toArray(signature.transactionSignature, "base64"),
      terms.inputs[index].publicKey,
      CAP_SIGHASH,
    );
    if (!validateSpend(template, index)) {
      throw new Error(`invalid reusable cap signature for input ${index}`);
    }
  });
  return {
    authorization,
    terms,
    maximumAmount: uptoMaximumAmount(authorization.terms),
  };
};

const computeDeltas = (
  terms: DecodedTerms,
  outputAmounts: readonly bigint[],
): Map<string, bigint> => {
  const deltas = sourceSatoshisByOwner(terms);
  terms.outputs.forEach((output, index) => {
    deltas.set(output.owner, (deltas.get(output.owner) ?? 0n) - outputAmounts[index]);
  });
  return deltas;
};

const validateAmounts = (
  terms: DecodedTerms,
  outputAmounts: readonly string[],
): { parsed: bigint[]; deltas: Map<string, bigint>; amount: bigint } => {
  if (outputAmounts.length !== terms.outputs.length) {
    throw new Error("outputAmounts length does not match the authorization");
  }
  const parsed = outputAmounts.map((amount, index) =>
    parseSatoshis(amount, `outputAmounts[${index}]`),
  );
  terms.outputs.forEach((output, index) => {
    if (output.fixedAmount !== undefined && parsed[index] !== BigInt(output.fixedAmount)) {
      throw new Error(`fixed output ${index} changed`);
    }
  });
  const inputTotal = terms.inputs.reduce((sum, input) => sum + BigInt(input.sourceSatoshis), 0n);
  const outputTotal = parsed.reduce((sum, amount) => sum + amount, 0n);
  if (outputTotal > BigInt(MAX_SATOSHIS)) {
    throw new Error("transaction output total is outside the BSV satoshi range");
  }
  if (inputTotal - outputTotal !== BigInt(terms.fee)) {
    throw new Error("inputs minus outputs does not equal the authorized fee");
  }
  const deltas = computeDeltas(terms, parsed);
  const maxima = maximumByOwner(terms);
  let amount = 0n;
  terms.chargedOwners.forEach(owner => {
    const delta = deltas.get(owner) ?? 0n;
    const maximum = maxima.get(owner) ?? 0n;
    if (delta < 0n || delta > maximum) {
      throw new Error(`owner ${owner} net delta is outside its authorized maximum`);
    }
    amount += delta;
  });
  return { parsed, deltas, amount };
};

const validateControlSequence = (terms: DecodedTerms, nSequence: number): void => {
  if (
    !Number.isSafeInteger(nSequence) ||
    nSequence < terms.sequenceStart ||
    nSequence > FINAL_SEQUENCE
  ) {
    throw new Error("control nSequence is outside the authorized range");
  }
};

const attachCapSignatures = (
  transaction: Transaction,
  authorization: UptoBsvAuthorization,
  terms: DecodedTerms,
): void => {
  const signatures = new Map(
    authorization.capSignatures.map(signature => [signature.inputIndex, signature]),
  );
  capIndexes(terms).forEach(index => {
    const signature = signatures.get(index);
    if (!signature) throw new Error(`missing cap signature for input ${index}`);
    transaction.inputs[index].unlockingScript = unlockingScript(
      Utils.toArray(signature.transactionSignature, "base64"),
      terms.inputs[index].publicKey,
      CAP_SIGHASH,
    );
  });
};

export const buildUptoTransactionVersion = async (
  authorization: UptoBsvAuthorization,
  args: BuildUptoBsvTransactionVersionArgs,
  controlSigners: UptoBsvInputSigners,
): Promise<UptoBsvTransactionVersion> => {
  const verified = verifyUptoAuthorization(authorization);
  const { terms } = verified;
  validateControlSequence(terms, args.nSequence);
  const { parsed } = validateAmounts(terms, args.outputAmounts);
  const transaction = buildTemplate(terms, args.nSequence);
  transaction.outputs.forEach((output, index) => {
    output.satoshis = toSafeSatoshis(parsed[index], `output ${index}`);
  });
  attachCapSignatures(transaction, authorization, terms);
  for (const index of controlIndexes(terms)) {
    const signature = await requireSigner(
      controlSigners,
      index,
    )(signatureDigest(transaction, index, CONTROL_SIGHASH));
    transaction.inputs[index].unlockingScript = unlockingScript(
      signature,
      terms.inputs[index].publicKey,
      CONTROL_SIGHASH,
    );
  }
  transaction.inputs.forEach((_, index) => {
    if (!validateSpend(transaction, index)) {
      throw new Error(`constructed transaction input ${index} failed validation`);
    }
  });
  return {
    authorizationId: authorization.authorizationId,
    transaction: Utils.toBase64(transaction.toAtomicBEEF()),
  };
};

export const verifyUptoTransactionVersion = (
  authorization: UptoBsvAuthorization,
  version: UptoBsvTransactionVersion,
): VerifiedUptoBsvTransactionVersion => {
  const verified = verifyUptoAuthorization(authorization);
  const { terms } = verified;
  if (version.authorizationId !== authorization.authorizationId) {
    throw new Error("transaction version belongs to a different authorization");
  }
  const transaction = decodeBeefSubject(version.transaction);
  if (
    transaction.version !== 1 ||
    transaction.lockTime !== terms.nLockTime ||
    transaction.inputs.length !== terms.inputs.length ||
    transaction.outputs.length !== terms.outputs.length
  ) {
    throw new Error("signed transaction shape differs from its authorization");
  }
  const sequences = controlIndexes(terms).map(
    index => transaction.inputs[index].sequence ?? FINAL_SEQUENCE,
  );
  const nSequence = sequences[0];
  if (nSequence === undefined || sequences.some(sequence => sequence !== nSequence)) {
    throw new Error("control inputs must use one common nSequence");
  }
  validateControlSequence(terms, nSequence);
  transaction.inputs.forEach((input, index) => {
    const expected = terms.inputs[index];
    input.sourceTransaction = expected.source;
    const sourceTxid = input.sourceTXID ?? input.sourceTransaction.id("hex");
    const inputSequence = expected.kind === "cap" ? FINAL_SEQUENCE : nSequence;
    if (
      sourceTxid !== expected.source.id("hex") ||
      input.sourceOutputIndex !== expected.sourceOutputIndex ||
      input.sequence !== inputSequence
    ) {
      throw new Error(`transaction input ${index} differs from its authorization`);
    }
    const scope = input.unlockingScript?.chunks[0]?.data?.at(-1);
    const expectedScope = expected.kind === "cap" ? CAP_SIGHASH : CONTROL_SIGHASH;
    if (scope !== (expectedScope & 0xff) || !validateSpend(transaction, index)) {
      throw new Error(`transaction input ${index} has an invalid signature`);
    }
  });
  transaction.outputs.forEach((output, index) => {
    if (output.lockingScript.toHex() !== terms.outputs[index].lockingScript.toLowerCase()) {
      throw new Error(`transaction output ${index} script changed`);
    }
  });
  const outputAmounts = transaction.outputs.map(output => String(output.satoshis ?? 0));
  const { deltas, amount } = validateAmounts(terms, outputAmounts);
  return {
    version,
    transaction,
    txid: transaction.id("hex"),
    nSequence,
    cooperativeClose: nSequence === FINAL_SEQUENCE,
    outputAmounts,
    ownerDeltas: Object.fromEntries(
      [...deltas.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([owner, delta]) => [owner, delta.toString()]),
    ),
    amount: amount.toString(),
  };
};

export const assertUptoVersionProgression = (
  authorization: UptoBsvAuthorization,
  previous: UptoBsvTransactionVersion,
  next: UptoBsvTransactionVersion,
): void => {
  const prior = verifyUptoTransactionVersion(authorization, previous);
  const current = verifyUptoTransactionVersion(authorization, next);
  if (prior.cooperativeClose) {
    throw new Error("a cooperatively closed transaction cannot advance");
  }
  if (prior.nSequence === FINAL_SEQUENCE - 1 || current.nSequence !== prior.nSequence + 1) {
    if (current.nSequence !== FINAL_SEQUENCE) {
      throw new Error("control nSequence must advance by one or cooperatively close");
    }
  }
  if (BigInt(current.amount) < BigInt(prior.amount)) {
    throw new Error("stream amount must not decrease");
  }
};

export const uptoP2pkhScript = (publicKey: string): string => {
  assertPublicKey(publicKey, "publicKey");
  const hash = PublicKey.fromString(publicKey).toHash("hex") as string;
  return `76a914${hash}88ac`;
};

export const findBeefOutput = (
  encoded: string,
  lockingScript: string,
  satoshis: number,
): { transaction: Transaction; outputIndex: number } => {
  const transaction = decodeBeefSubject(encoded);
  const indexes = transaction.outputs.flatMap((output, index) =>
    output.satoshis === satoshis && output.lockingScript.toHex() === lockingScript ? [index] : [],
  );
  if (indexes.length !== 1) throw new Error("BEEF must contain one matching source output");
  return { transaction, outputIndex: indexes[0] };
};

export const inspectUptoInput = (
  input: UptoBsvInput,
): { txid: string; satoshis: string; lockingScript: string } => {
  const transaction = decodeBeefSubject(input.sourceTransaction);
  const output = transaction.outputs[input.sourceOutputIndex];
  if (!output || output.satoshis === undefined) throw new Error("input source output is missing");
  return {
    txid: transaction.id("hex"),
    satoshis: String(output.satoshis),
    lockingScript: output.lockingScript.toHex(),
  };
};

export const uptoInputSatoshis = (input: UptoBsvInput): string => {
  return inspectUptoInput(input).satoshis;
};
