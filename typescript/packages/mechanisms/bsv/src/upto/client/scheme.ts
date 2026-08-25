import { Utils } from "@bsv/sdk";
import type { WalletInterface } from "@bsv/sdk";
import type { PaymentPayload, PaymentRequirements, SchemeNetworkClient } from "@x402/core/types";
import type {
  UptoBsvControlProposal,
  UptoBsvControlRequest,
  UptoBsvPayload,
  UptoBsvTransactionVerification,
  UptoBsvTransactionVersion,
} from "../../types";
import { BRC29_PROTOCOL_ID, DEFAULT_PAYMENT_WINDOW_MS, MAX_SATOSHIS } from "../../constants";
import {
  BSV_UPTO_PROTOCOL_ID,
  createBrc29PaymentContext,
  p2pkhLockingScript,
  uptoControlKeyId,
  validateUptoBsvPaymentRequirements,
} from "../shared";
import {
  assertUptoVersionProgression,
  findBeefOutput,
  inspectUptoInput,
  signUptoAuthorization,
  uptoMaximumAmount,
  verifyUptoTransactionVersion,
} from "../transaction";

export interface UptoBsvControlProvider {
  /**
   * Obtains the recipient's small control input after both BRC-42 identities
   * and the per-payment derivation are known.
   *
   * @param request - Exact-compatible payment and timing context
   * @returns Recipient-owned control inputs and immutable timing terms
   */
  createControlProposal(request: UptoBsvControlRequest): Promise<UptoBsvControlProposal>;
}

export interface UptoBsvClientConfig {
  controlProvider: UptoBsvControlProvider;
  /** Same-index amount the reusable cap signature returns to the payer. */
  floorSatoshis?: number;
  /** Optional BRC-100 originator passed to wallet calls. */
  originator?: string;
}

/**
 * BSV client implementation for `upto`.
 *
 * It reuses exact's BRC-29 identity/payment derivation, then signs one maximum
 * debit input with `SINGLE|FORKID`. The actual amount is absent from the client
 * payload and is supplied later by a fully signed transaction version.
 */
export class UptoBsvScheme implements SchemeNetworkClient {
  readonly scheme = "upto";

  /**
   * Creates a BSV upto client.
   *
   * @param wallet - Payer BRC-100 wallet
   * @param config - Control-input transport and local authorization options
   */
  constructor(
    private readonly wallet: WalletInterface,
    private readonly config: UptoBsvClientConfig,
  ) {}

  /**
   * Creates a maximum-payment authorization without choosing the actual amount.
   *
   * @param x402Version - x402 protocol version
   * @param requirements - Requirements whose amount is the maximum satoshi debit
   * @returns Exact-compatible BRC-29 context plus the upto authorization
   */
  async createPaymentPayload(
    x402Version: number,
    requirements: PaymentRequirements,
  ): Promise<Pick<PaymentPayload, "x402Version" | "payload">> {
    validateUptoBsvPaymentRequirements(requirements);
    const originator = this.config.originator;
    const floorSatoshis = this.config.floorSatoshis ?? 1;
    if (!Number.isSafeInteger(floorSatoshis) || floorSatoshis < 0) {
      throw new Error("floorSatoshis must be a non-negative safe integer");
    }
    const maximum = BigInt(requirements.amount);
    if (maximum + BigInt(floorSatoshis) > BigInt(MAX_SATOSHIS)) {
      throw new Error("amount plus floorSatoshis exceeds the BSV satoshi range");
    }

    const payment = await createBrc29PaymentContext(this.wallet, requirements.payTo, originator);
    const controlRequest: UptoBsvControlRequest = {
      network: requirements.network,
      payTo: requirements.payTo,
      senderIdentityKey: payment.senderIdentityKey,
      derivationPrefix: payment.derivationPrefix,
      derivationSuffix: payment.derivationSuffix,
      maxAmount: requirements.amount,
      maxTimeoutSeconds: requirements.maxTimeoutSeconds,
    };
    const proposal = await this.config.controlProvider.createControlProposal(controlRequest);
    await this.validateControlProposal(proposal, controlRequest, originator);

    const capKeyId = `${payment.derivationPrefix} ${payment.derivationSuffix} cap-0`;
    const { publicKey: capPublicKey } = await this.wallet.getPublicKey(
      {
        protocolID: BSV_UPTO_PROTOCOL_ID,
        keyID: capKeyId,
        counterparty: "self",
      },
      originator,
    );
    const capScript = p2pkhLockingScript(capPublicKey);
    const capSatoshis = Number(maximum + BigInt(floorSatoshis));
    const action = await this.wallet.createAction(
      {
        description: "x402 upto authorization",
        outputs: [
          {
            satoshis: capSatoshis,
            lockingScript: capScript,
            outputDescription: "x402 upto cap",
            customInstructions: JSON.stringify({
              derivationPrefix: payment.derivationPrefix,
              derivationSuffix: payment.derivationSuffix,
              payee: requirements.payTo,
              keyId: capKeyId,
            }),
            tags: ["x402", "upto"],
          },
        ],
        labels: ["x402", "upto"],
        options: { noSend: true, randomizeOutputs: false },
      },
      originator,
    );
    if (!action.tx) throw new Error("Wallet createAction did not return a cap transaction");
    const capSource = Utils.toBase64(Array.from(action.tx));
    const { outputIndex: capOutputIndex } = findBeefOutput(capSource, capScript, capSatoshis);

    const terms = {
      version: 1 as const,
      network: requirements.network,
      asset: "BSV" as const,
      payTo: requirements.payTo,
      senderIdentityKey: payment.senderIdentityKey,
      derivationPrefix: payment.derivationPrefix,
      derivationSuffix: payment.derivationSuffix,
      inputs: [
        {
          owner: payment.senderIdentityKey,
          kind: "cap" as const,
          sourceTransaction: capSource,
          sourceOutputIndex: capOutputIndex,
          publicKey: capPublicKey,
        },
        ...proposal.inputs,
      ],
      outputs: [
        {
          owner: payment.senderIdentityKey,
          lockingScript: capScript,
          fixedAmount: String(floorSatoshis),
        },
        { owner: payment.senderIdentityKey, lockingScript: capScript },
        { owner: requirements.payTo, lockingScript: payment.lockingScript },
      ],
      chargedOwners: [payment.senderIdentityKey],
      paymentOutputIndexes: [2],
      fee: proposal.fee,
      sequenceStart: proposal.sequenceStart,
      validAfter: proposal.validAfter,
      deadline: proposal.deadline,
      nLockTime: proposal.nLockTime,
    };
    if (uptoMaximumAmount(terms) !== requirements.amount) {
      throw new Error("constructed authorization does not equal requirements.amount");
    }
    const authorization = await signUptoAuthorization(terms, {
      0: async digest => {
        const { signature } = await this.wallet.createSignature(
          {
            protocolID: BSV_UPTO_PROTOCOL_ID,
            keyID: capKeyId,
            counterparty: "self",
            hashToDirectlySign: digest,
          },
          originator,
        );
        return Array.from(signature);
      },
    });
    const payload: UptoBsvPayload = {
      derivationPrefix: payment.derivationPrefix,
      derivationSuffix: payment.derivationSuffix,
      senderIdentityKey: payment.senderIdentityKey,
      outputIndex: 2,
      authorization,
    };
    return { x402Version, payload: payload as unknown as PaymentPayload["payload"] };
  }

  /**
   * Verifies a recipient-signed transaction before the payer accepts or retains it.
   *
   * When `previous` is supplied, the method also requires the next control
   * sequence and a nondecreasing cumulative amount. The return value contains
   * only facts derived from the signed transaction.
   *
   * @param payload - Payer's maximum authorization payload
   * @param version - Fully signed transaction to verify
   * @param previous - Optional previously accepted signed transaction
   * @returns Derived transaction facts with no SDK transaction object
   */
  verifyTransactionVersion(
    payload: UptoBsvPayload,
    version: UptoBsvTransactionVersion,
    previous?: UptoBsvTransactionVersion,
  ): UptoBsvTransactionVerification {
    const verified = verifyUptoTransactionVersion(payload.authorization, version);
    if (previous) {
      assertUptoVersionProgression(payload.authorization, previous, version);
    } else if (
      !verified.cooperativeClose &&
      verified.nSequence !== payload.authorization.terms.sequenceStart
    ) {
      throw new Error("first non-final transaction must use sequenceStart");
    }
    return {
      txid: verified.txid,
      amount: verified.amount,
      nSequence: verified.nSequence,
      cooperativeClose: verified.cooperativeClose,
      ownerDeltas: verified.ownerDeltas,
    };
  }

  /**
   * Checks that the recipient proposal is small, identity-bound, and time-bounded.
   *
   * @param proposal - Recipient-provided control inputs
   * @param request - Context sent to the recipient
   * @param originator - Optional BRC-100 originator
   */
  private async validateControlProposal(
    proposal: UptoBsvControlProposal,
    request: UptoBsvControlRequest,
    originator?: string,
  ): Promise<void> {
    if (!proposal || !Array.isArray(proposal.inputs) || proposal.inputs.length < 1) {
      throw new Error("control proposal must contain at least one input");
    }
    if (!/^\d+$/.test(proposal.fee)) {
      throw new Error("control proposal fee must be non-negative decimal satoshis");
    }
    const seenOutpoints = new Set<string>();
    let total = 0n;
    const sources = proposal.inputs.map(input => {
      const source = inspectUptoInput(input);
      const outpoint = `${source.txid}:${input.sourceOutputIndex}`;
      if (seenOutpoints.has(outpoint)) throw new Error(`duplicate control input ${outpoint}`);
      seenOutpoints.add(outpoint);
      total += BigInt(source.satoshis);
      return source;
    });
    if (total <= BigInt(proposal.fee)) {
      throw new Error("control input value must exceed the terminal transaction fee");
    }
    for (const [index, input] of proposal.inputs.entries()) {
      const expectedKeyId = uptoControlKeyId(
        request.derivationPrefix,
        request.derivationSuffix,
        index,
      );
      if (input.kind !== "control" || input.owner.toLowerCase() !== request.payTo.toLowerCase()) {
        throw new Error(`control input ${index} is not bound to payTo`);
      }
      const { publicKey } = await this.wallet.getPublicKey(
        {
          protocolID: BRC29_PROTOCOL_ID,
          keyID: expectedKeyId,
          counterparty: request.payTo,
        },
        originator,
      );
      if (publicKey.toLowerCase() !== input.publicKey.toLowerCase()) {
        throw new Error(`control input ${index} BRC-42 key mismatch`);
      }
      if (sources[index].lockingScript !== p2pkhLockingScript(input.publicKey)) {
        throw new Error(`control input ${index} source script does not match its public key`);
      }
    }
    const now = Math.floor(Date.now() / 1000);
    const skew = Math.ceil(DEFAULT_PAYMENT_WINDOW_MS / 1000);
    if (
      proposal.sequenceStart !== 1 ||
      !Number.isSafeInteger(proposal.validAfter) ||
      !Number.isSafeInteger(proposal.deadline) ||
      !Number.isSafeInteger(proposal.nLockTime) ||
      proposal.validAfter < 0 ||
      proposal.nLockTime <= proposal.validAfter ||
      proposal.deadline <= proposal.nLockTime ||
      proposal.nLockTime < 500_000_000 ||
      proposal.deadline > 0xffffffff ||
      proposal.validAfter > now + skew ||
      proposal.deadline <= now - skew ||
      proposal.deadline > now + request.maxTimeoutSeconds + skew ||
      proposal.deadline - proposal.validAfter > request.maxTimeoutSeconds
    ) {
      throw new Error("control proposal has invalid authorization timing");
    }
  }
}
