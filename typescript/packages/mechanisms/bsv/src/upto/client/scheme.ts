import { PublicKey, Random, Utils, type ChainTracker, type WalletInterface } from "@bsv/sdk";
import type { PaymentResponseContext } from "@x402/core/client";
import type {
  Network,
  PaymentPayload,
  PaymentRequirements,
  SchemeClientHooks,
  SchemeNetworkClient,
} from "@x402/core/types";
import { COMPRESSED_PUBKEY_REGEX } from "../../constants";
import { deriveUptoSourcePublicKey } from "../internal/keys";
import { admitPresentedAuthorization } from "../internal/presented";
import {
  createSourceAdmitter,
  type SourceAdmissionPolicy,
  type SourceCandidate,
} from "../internal/source";
import { createCapAuthorization, type CapAuthorization } from "../internal/transaction";
import {
  materializeVerifiedTerminal,
  verifyTerminalTransaction,
  type MaterializedVerifiedTerminal,
} from "../internal/terminal";
import {
  snapshotPresentedUptoPayment,
  snapshotUptoCapSources,
  snapshotUptoRequirements,
} from "../internal/wire";
import type {
  UptoBsvCapInput,
  UptoBsvCapSource,
  UptoBsvControlOffer,
  UptoBsvPayload,
  UptoBsvSourceReference,
} from "../types";

/** Facts supplied to the payer's cap-source reservation boundary. */
export interface UptoBsvCapPreparationContext {
  readonly x402Version: 2;
  readonly network: Network;
  readonly asset: string;
  readonly maximumAmount: string;
  readonly payTo: string;
  readonly maxTimeoutSeconds: number;
  readonly control: UptoBsvControlOffer;
  readonly derivationPrefix: string;
  readonly derivationSuffix: string;
  readonly senderIdentityKey: string;
}

/** Application-owned source inventory used to reserve payer cap outpoints. */
export interface UptoBsvCapSourceProvider {
  /**
   * Returns cap sources already reserved through the advertised deadline.
   *
   * @param context - Validated immutable authorization context
   * @returns Ordered payer cap sources and their fixed floor amounts
   */
  prepareCapSources(context: UptoBsvCapPreparationContext): Promise<readonly UptoBsvCapSource[]>;
}

/** Finite local bounds applied before parsing payer or recipient BEEF. */
export type UptoBsvClientSourcePolicy = SourceAdmissionPolicy;

/** Finite local bound applied before parsing returned terminal BEEF. */
export interface UptoBsvClientTerminalPolicy {
  readonly maxAtomicBeefBytes: number;
}

/** Client dependencies for one BSV upto scheme instance. */
export interface UptoBsvClientConfig {
  readonly capSourceProvider: UptoBsvCapSourceProvider;
  readonly chainTracker: ChainTracker;
  readonly sourcePolicy: UptoBsvClientSourcePolicy;
  readonly terminalPolicy: UptoBsvClientTerminalPolicy;
  readonly originator?: string;
}

interface SelectedTerminalRecord {
  readonly subjectTxid: string;
  readonly subjectTransaction: readonly number[];
  readonly actualAmount: bigint;
  readonly walletOutcome: "unattempted" | "accepted" | "failed";
}

/** BSV client implementation for one reusable `upto` authorization. */
export class UptoBsvScheme implements SchemeNetworkClient {
  readonly scheme = "upto";
  readonly schemeHooks: SchemeClientHooks = {
    onPaymentResponse: context => this.handlePaymentResponse(context),
  };

  private readonly wallet: Pick<
    WalletInterface,
    "getPublicKey" | "createSignature" | "internalizeAction"
  >;
  private readonly config: UptoBsvClientConfig;
  private readonly admitSources: ReturnType<typeof createSourceAdmitter>;
  private readonly selectedTerminals = new Map<string, SelectedTerminalRecord>();
  private readonly terminalTasks = new Map<string, Promise<void>>();

  /**
   * Creates a client scheme around a payer wallet and application-owned cap inventory.
   *
   * @param wallet - Payer BRC-100 wallet
   * @param config - Source provider, chain facts, finite limits, and originator
   */
  constructor(wallet: WalletInterface, config: UptoBsvClientConfig) {
    const getPublicKey = wallet?.getPublicKey;
    const createSignature = wallet?.createSignature;
    const internalizeAction = wallet?.internalizeAction;
    if (
      typeof getPublicKey !== "function" ||
      typeof createSignature !== "function" ||
      typeof internalizeAction !== "function"
    ) {
      throw new Error("BSV upto client wallet is missing a required capability");
    }
    const provider = config?.capSourceProvider;
    if (typeof provider?.prepareCapSources !== "function") {
      throw new Error("BSV upto client requires a cap source provider");
    }
    if (typeof config.sourcePolicy !== "object" || config.sourcePolicy === null) {
      throw new Error("BSV upto client requires a source policy");
    }
    if (typeof config.terminalPolicy !== "object" || config.terminalPolicy === null) {
      throw new Error("BSV upto client requires a terminal policy");
    }
    const sourcePolicy: UptoBsvClientSourcePolicy = Object.freeze({
      maxSources: config.sourcePolicy.maxSources,
      maxAtomicBeefBytesPerSource: config.sourcePolicy.maxAtomicBeefBytesPerSource,
    });
    const terminalPolicy: UptoBsvClientTerminalPolicy = Object.freeze({
      maxAtomicBeefBytes: config.terminalPolicy.maxAtomicBeefBytes,
    });
    this.wallet = {
      getPublicKey: getPublicKey.bind(wallet),
      createSignature: createSignature.bind(wallet),
      internalizeAction: internalizeAction.bind(wallet),
    };
    this.config = Object.freeze({
      capSourceProvider: {
        prepareCapSources: provider.prepareCapSources.bind(provider),
      },
      chainTracker: config.chainTracker,
      sourcePolicy,
      terminalPolicy,
      originator: config.originator,
    });
    this.admitSources = createSourceAdmitter({
      chainTracker: this.config.chainTracker,
      policy: sourcePolicy,
    });
  }

  /**
   * Validates the external control offer, reserves payer sources, and signs one cap.
   *
   * @param x402Version - x402 protocol version (must be 2)
   * @param requirements - Selected BSV upto requirements
   * @returns Scheme-specific reusable authorization payload
   */
  async createPaymentPayload(
    x402Version: number,
    requirements: PaymentRequirements,
  ): Promise<Pick<PaymentPayload, "x402Version" | "payload">> {
    if (x402Version !== 2) throw new Error("BSV upto requires x402 version 2");
    const accepted = snapshotUptoRequirements(requirements);
    assertControlWindowActive(accepted.control);

    // A valid authorization needs at least one payer cap source. Reject an
    // oversized recipient offer before key derivation, payer wallet access,
    // source reservation, or BEEF parsing.
    this.admitSources.preflight([accepted.control.inputs], 1);

    // The recipient offer is fully verified before payer inventory is reserved
    // or any payer signature is requested.
    const controlCandidates = await sourceCandidates(
      "control",
      accepted.control.inputs,
      accepted.payTo,
    );
    await this.admitSources(controlCandidates);

    const originator = this.config.originator;
    const { publicKey: rawIdentity } = await this.wallet.getPublicKey(
      { identityKey: true },
      originator,
    );
    const senderIdentityKey = normalizePublicKey(rawIdentity, "payer wallet identity key");
    const derivationPrefix = Utils.toBase64(Random(8));
    const derivationSuffix = Utils.toBase64(Utils.toArray(String(Date.now()), "utf8"));
    const preparation = Object.freeze({
      x402Version: 2 as const,
      network: accepted.network,
      asset: accepted.asset,
      maximumAmount: accepted.maximumAmount,
      payTo: accepted.payTo,
      maxTimeoutSeconds: accepted.maxTimeoutSeconds,
      control: accepted.control,
      derivationPrefix,
      derivationSuffix,
      senderIdentityKey,
    });
    const rawCapSources = await this.config.capSourceProvider.prepareCapSources(preparation);
    const capSources = snapshotUptoCapSources(rawCapSources);
    this.admitSources.preflight([accepted.control.inputs, capSources]);
    const capCandidates = await sourceCandidates("cap", capSources, senderIdentityKey);
    // Newly reserved cap sources must also agree with the control ancestry.
    const admitted = await this.admitSources([...capCandidates, ...controlCandidates]);
    const capInputs = admitted.slice(0, capCandidates.length);
    const controlInputs = admitted.slice(capCandidates.length);

    const facts = {
      network: String(accepted.network),
      asset: accepted.asset,
      maximumAmount: accepted.maximumAmount,
      payTo: accepted.payTo,
      maxTimeoutSeconds: accepted.maxTimeoutSeconds,
      validAfter: accepted.control.validAfter,
      deadline: accepted.control.deadline,
      controlInputs: controlInputs.map((source, index) => ({
        nonce: accepted.control.inputs[index].nonce,
        sourceTxid: source.sourceTxid,
        sourceOutputIndex: source.sourceOutputIndex,
      })),
      senderIdentityKey,
      derivationPrefix,
      derivationSuffix,
      capInputs: capInputs.map((source, index) => ({
        nonce: capSources[index].nonce,
        sourceTxid: source.sourceTxid,
        sourceOutputIndex: source.sourceOutputIndex,
        floorAmount: capSources[index].floorAmount,
      })),
    };
    assertControlWindowActive(accepted.control);
    const signatures: CapAuthorization = await createCapAuthorization({
      facts,
      capInputs,
      controlInputs,
      wallet: this.wallet,
      originator,
    });
    const wireCapInputs: UptoBsvCapInput[] = capSources.map((source, index) =>
      Object.freeze({
        ...source,
        transactionSignature: signatures.transactionSignatures[index],
      }),
    );
    const payload: UptoBsvPayload = Object.freeze({
      senderIdentityKey,
      derivationPrefix,
      derivationSuffix,
      capInputs: Object.freeze(wireCapInputs),
      authorizationSignature: signatures.authorizationSignature,
    });
    return { x402Version: 2, payload: payload as unknown as PaymentPayload["payload"] };
  }

  /**
   * Selects any returned terminal evidence and takes custody only after success.
   *
   * @param context - Existing x402 paid-response hook context
   */
  private async handlePaymentResponse(context: PaymentResponseContext): Promise<void> {
    const response = context.settleResponse;
    if (response === undefined) return;
    const extra = response.extra;
    const encodedTerminal =
      typeof extra === "object" && extra !== null ? extra.settlementTransaction : undefined;
    const presentsTerminalEvidence = response.amount !== undefined || encodedTerminal !== undefined;
    if (response.success !== true && !presentsTerminalEvidence) return;
    if (response.network !== context.requirements.network) {
      throw new Error("BSV upto settlement network differs from the authorization");
    }
    if (typeof response.amount !== "string") {
      throw new Error("BSV upto settlement evidence is missing actual amount");
    }
    if (typeof extra !== "object" || extra === null) {
      throw new Error("BSV upto settlement is missing terminal evidence");
    }
    if (typeof encodedTerminal !== "string") {
      throw new Error("BSV upto settlement is missing terminal evidence");
    }
    if (response.success !== true && response.transaction !== "") {
      throw new Error("BSV upto failed settlement evidence must use an empty transaction field");
    }
    const presented = snapshotPresentedUptoPayment(
      context.paymentPayload,
      { ...context.requirements, amount: response.amount },
      "settle",
    );
    if (
      response.payer !== undefined &&
      normalizePublicKey(response.payer, "settlement payer") !== presented.payload.senderIdentityKey
    ) {
      throw new Error("BSV upto settlement payer differs from the authorization");
    }
    const admitted = await admitPresentedAuthorization({
      presented,
      wallet: this.wallet,
      perspective: "payer",
      chainTracker: this.config.chainTracker,
      sourcePolicy: this.config.sourcePolicy,
      originator: this.config.originator,
    });
    const authorizationId = admitted.authorizationId;
    const terminal = await verifyTerminalTransaction({
      authorization: admitted.authorization,
      actualAmount: presented.actualAmount,
      transaction: encodedTerminal,
      wallet: this.wallet,
      perspective: "payer",
      chainTracker: this.config.chainTracker,
      policy: this.config.terminalPolicy,
      originator: this.config.originator,
    });
    const material = materializeVerifiedTerminal(terminal);
    if (response.success === true && material.subjectTxid !== response.transaction) {
      throw new Error("BSV upto settlement txid does not match its Atomic BEEF subject");
    }
    const selected = this.selectedTerminals.get(authorizationId);
    if (selected !== undefined) {
      assertSameTerminal(selected, material);
      if (response.success !== true) return;
      if (selected.walletOutcome === "accepted") return;
      if (selected.walletOutcome === "failed") {
        throw new Error("BSV upto payer wallet outcome is unavailable for the selected terminal");
      }
      const inFlight = this.terminalTasks.get(authorizationId);
      if (inFlight !== undefined) {
        await inFlight;
        const completed = this.selectedTerminals.get(authorizationId);
        if (completed?.walletOutcome !== "accepted") {
          throw new Error("BSV upto payer wallet outcome is unavailable");
        }
        assertSameTerminal(completed, material);
        return;
      }
    } else {
      this.selectedTerminals.set(authorizationId, selectedTerminal(material, "unattempted"));
      if (response.success !== true) return;
    }
    const task = this.internalizeTerminal(material, authorizationId);
    this.terminalTasks.set(authorizationId, task);
    try {
      await task;
    } finally {
      this.terminalTasks.delete(authorizationId);
    }
  }

  /**
   * Internalizes all payer-owned outputs for the already selected terminal.
   *
   * The first-writer identity is stored before this wallet effect begins. A
   * rejection or indeterminate exception therefore remains fail closed for
   * both the same evidence and any later conflicting terminal.
   *
   * @param material - Independently verified terminal bytes and output records
   * @param authorizationId - Local first-writer key
   */
  private async internalizeTerminal(
    material: MaterializedVerifiedTerminal,
    authorizationId: string,
  ): Promise<void> {
    try {
      const payerOutputs = material.outputs
        .filter(output => output.role === "floor" || output.role === "refund")
        .map(output => ({
          outputIndex: output.outputIndex,
          protocol: "wallet payment" as const,
          paymentRemittance: { ...output.paymentRemittance },
        }));
      const result = await this.wallet.internalizeAction(
        {
          tx: Array.from(material.atomicBeef),
          outputs: payerOutputs,
          description: "x402 upto payer outputs",
        },
        this.config.originator,
      );
      if (result.accepted !== true) {
        throw new Error("BSV upto payer wallet rejected terminal outputs");
      }
      const selected = this.selectedTerminals.get(authorizationId);
      if (selected === undefined) {
        throw new Error("BSV upto locally selected terminal record is unavailable");
      }
      assertSameTerminal(selected, material);
      this.selectedTerminals.set(authorizationId, selectedTerminal(material, "accepted"));
    } catch (error) {
      const selected = this.selectedTerminals.get(authorizationId);
      if (selected !== undefined) {
        assertSameTerminal(selected, material);
        this.selectedTerminals.set(authorizationId, selectedTerminal(material, "failed"));
      }
      throw error;
    }
  }
}

/**
 * Creates a detached local first-writer record.
 *
 * @param material - Verified terminal material
 * @param walletOutcome - Whether payer internalization is unattempted, accepted, or failed
 * @returns Immutable terminal identity and wallet outcome
 */
function selectedTerminal(
  material: MaterializedVerifiedTerminal,
  walletOutcome: SelectedTerminalRecord["walletOutcome"],
): SelectedTerminalRecord {
  return Object.freeze({
    subjectTxid: material.subjectTxid,
    subjectTransaction: Object.freeze(Array.from(material.subjectTransaction)),
    actualAmount: material.actualAmount,
    walletOutcome,
  });
}

/**
 * Requires a replay to preserve the locally selected subject bytes and amount.
 *
 * @param selected - Previously internalized local terminal record
 * @param candidate - Newly verified response terminal
 */
function assertSameTerminal(
  selected: SelectedTerminalRecord,
  candidate: MaterializedVerifiedTerminal,
): void {
  if (
    selected.subjectTxid !== candidate.subjectTxid ||
    selected.actualAmount !== candidate.actualAmount ||
    !bytesEqual(selected.subjectTransaction, candidate.subjectTransaction)
  ) {
    throw new Error("BSV upto settlement conflicts with the locally selected terminal");
  }
}

/**
 * Compares two detached byte sequences.
 *
 * @param left - First byte sequence
 * @param right - Second byte sequence
 * @returns Whether every byte matches
 */
function bytesEqual(left: ArrayLike<number>, right: ArrayLike<number>): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * Projects wire source references into independently derived admission candidates.
 *
 * @param role - Cap or control source role
 * @param sources - Ordered wire source references
 * @param ownerIdentity - Payer identity for cap or payTo for control
 * @returns Ordered source-admission candidates
 */
async function sourceCandidates(
  role: "cap" | "control",
  sources: readonly UptoBsvSourceReference[],
  ownerIdentity: string,
): Promise<SourceCandidate[]> {
  const result = new Array<SourceCandidate>(sources.length);
  for (let index = 0; index < sources.length; index += 1) {
    const source = sources[index];
    result[index] = {
      role,
      sourceTransaction: source.sourceTransaction,
      sourceOutputIndex: source.sourceOutputIndex,
      publicKey: await deriveUptoSourcePublicKey(role, source.nonce, ownerIdentity),
    };
  }
  return result;
}

/**
 * Requires a newly created authorization to fall within its local Unix window.
 *
 * @param control - Validated external control offer
 */
function assertControlWindowActive(control: UptoBsvControlOffer): void {
  const now = Math.floor(Date.now() / 1_000);
  if (now < control.validAfter || now >= control.deadline) {
    throw new Error("BSV upto control offer is outside its validity window");
  }
}

/**
 * Validates and normalizes one compressed identity public key.
 *
 * @param value - Candidate public key
 * @param name - Field name used in failures
 * @returns Canonical compressed public key
 */
function normalizePublicKey(value: unknown, name: string): string {
  if (typeof value !== "string" || !COMPRESSED_PUBKEY_REGEX.test(value)) {
    throw new Error(`${name} must be a compressed secp256k1 public key`);
  }
  try {
    return PublicKey.fromString(value).toString().toLowerCase();
  } catch {
    throw new Error(`${name} must be a compressed secp256k1 public key`);
  }
}
