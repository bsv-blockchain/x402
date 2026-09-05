import type { ChainTracker, WalletInterface } from "@bsv/sdk";
import type { ResolvedAuthorizationFacts } from "./authorization";
import { deriveUptoSourcePublicKey } from "./keys";
import { createSourceAdmitter, type SourceAdmissionPolicy, type SourceCandidate } from "./source";
import {
  materializeVerifiedAuthorization,
  verifyPresentedAuthorization,
  type VerifiedAuthorization,
} from "./transaction";
import type { PresentedUptoPayment } from "./wire";

/** Opaque verified authorization and its canonical identifier. */
export interface AdmittedPresentedAuthorization {
  readonly authorization: VerifiedAuthorization;
  readonly authorizationId: string;
}

interface AdmitPresentedAuthorizationArgs {
  readonly presented: PresentedUptoPayment;
  readonly wallet: Pick<WalletInterface, "getPublicKey">;
  readonly perspective: "payer" | "recipient";
  readonly chainTracker: ChainTracker;
  readonly sourcePolicy: SourceAdmissionPolicy;
  readonly originator?: string;
}

/**
 * Admits every signed source and verifies one presented wire authorization.
 *
 * This is the shared client/facilitator boundary: wire data supplies only
 * nonces and source evidence; expected P2PKH keys are independently derived
 * from the signed payer and recipient identities before source admission.
 *
 * @param args - Presented wire snapshot, wallet perspective, and chain policy
 * @returns Opaque verified authorization and canonical identifier
 */
export async function admitPresentedAuthorization(
  args: AdmitPresentedAuthorizationArgs,
): Promise<AdmittedPresentedAuthorization> {
  const presented = args.presented;
  const admit = createSourceAdmitter({
    chainTracker: args.chainTracker,
    policy: args.sourcePolicy,
  });
  admit.preflight([presented.payload.capInputs, presented.control.inputs]);
  const capCandidates = new Array<SourceCandidate>(presented.payload.capInputs.length);
  for (let index = 0; index < capCandidates.length; index += 1) {
    const input = presented.payload.capInputs[index];
    capCandidates[index] = {
      role: "cap",
      sourceTransaction: input.sourceTransaction,
      sourceOutputIndex: input.sourceOutputIndex,
      publicKey: await deriveUptoSourcePublicKey(
        "cap",
        input.nonce,
        presented.payload.senderIdentityKey,
      ),
    };
  }
  const controlCandidates = new Array<SourceCandidate>(presented.control.inputs.length);
  for (let index = 0; index < controlCandidates.length; index += 1) {
    const input = presented.control.inputs[index];
    controlCandidates[index] = {
      role: "control",
      sourceTransaction: input.sourceTransaction,
      sourceOutputIndex: input.sourceOutputIndex,
      publicKey: await deriveUptoSourcePublicKey("control", input.nonce, presented.payTo),
    };
  }
  const admitted = await admit([...capCandidates, ...controlCandidates]);
  const capInputs = Object.freeze(admitted.slice(0, capCandidates.length));
  const controlInputs = Object.freeze(admitted.slice(capCandidates.length));
  const facts: ResolvedAuthorizationFacts = {
    network: presented.network,
    asset: presented.asset,
    maximumAmount: presented.maximumAmount,
    payTo: presented.payTo,
    maxTimeoutSeconds: presented.maxTimeoutSeconds,
    validAfter: presented.control.validAfter,
    deadline: presented.control.deadline,
    controlInputs: controlInputs.map((source, index) => ({
      nonce: presented.control.inputs[index].nonce,
      sourceTxid: source.sourceTxid,
      sourceOutputIndex: source.sourceOutputIndex,
    })),
    senderIdentityKey: presented.payload.senderIdentityKey,
    derivationPrefix: presented.payload.derivationPrefix,
    derivationSuffix: presented.payload.derivationSuffix,
    capInputs: capInputs.map((source, index) => ({
      nonce: presented.payload.capInputs[index].nonce,
      sourceTxid: source.sourceTxid,
      sourceOutputIndex: source.sourceOutputIndex,
      floorAmount: presented.payload.capInputs[index].floorAmount,
    })),
  };
  const authorization = await verifyPresentedAuthorization({
    facts,
    authorizationSignature: presented.payload.authorizationSignature,
    transactionSignatures: presented.payload.capInputs.map(input => input.transactionSignature),
    capInputs,
    controlInputs,
    wallet: args.wallet,
    perspective: args.perspective,
    originator: args.originator,
  });
  const material = materializeVerifiedAuthorization(authorization);
  return Object.freeze({
    authorization,
    authorizationId: material.authorizationId,
  });
}
