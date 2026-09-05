/** One reserved P2PKH source represented by canonical Atomic BEEF. */
export interface UptoBsvSourceReference {
  /** Padded base64 for the 32-byte BRC-42 key nonce. */
  readonly nonce: string;
  /** Canonical padded-base64 Atomic BEEF naming the source transaction. */
  readonly sourceTransaction: string;
  /** Selected output in the Atomic BEEF subject transaction. */
  readonly sourceOutputIndex: number;
}

/** Recipient material prepared outside the x402 exchange and advertised in PaymentRequired. */
export interface UptoBsvControlOffer {
  readonly inputs: readonly UptoBsvSourceReference[];
  /** Inclusive Unix-second start of the local authorization window. */
  readonly validAfter: number;
  /** Exclusive Unix-second end of the local authorization window. */
  readonly deadline: number;
}

/** Reserved payer source before the scheme adds its reusable cap signature. */
export interface UptoBsvCapSource extends UptoBsvSourceReference {
  /** Positive payer-owned same-index output fixed by SIGHASH_SINGLE. */
  readonly floorAmount: string;
}

/** One payer source and its reusable SIGHASH_SINGLE|FORKID signature. */
export interface UptoBsvCapInput extends UptoBsvCapSource {
  /** Canonical padded-base64 strict-DER signature without a sighash byte. */
  readonly transactionSignature: string;
}

/** Scheme-specific PaymentPayload.payload for BSV upto. */
export interface UptoBsvPayload {
  readonly senderIdentityKey: string;
  readonly derivationPrefix: string;
  readonly derivationSuffix: string;
  readonly capInputs: readonly UptoBsvCapInput[];
  /** Canonical padded-base64 strict-DER signature over the authorization digest. */
  readonly authorizationSignature: string;
}

/** Selected-terminal evidence returned through SettleResponse.extra. */
export interface UptoBsvSettlementExtra {
  readonly settlementTransaction: string;
}
