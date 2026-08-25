import { PublicKey, Random, Utils } from "@bsv/sdk";
import type { WalletInterface, WalletProtocol } from "@bsv/sdk";
import type { PaymentRequirements } from "@x402/core/types";
import {
  BRC29_PROTOCOL_ID,
  BSV_ASSET_IDENTIFIER,
  COMPRESSED_PUBKEY_REGEX,
  MAX_SATOSHIS,
  isBsvNetwork,
} from "../constants";

/** Internal wallet protocol used for payer-owned `upto` cap keys. */
export const BSV_UPTO_PROTOCOL_ID: WalletProtocol = [2, "x402 BSV upto"];

export interface Brc29PaymentContext {
  derivationPrefix: string;
  derivationSuffix: string;
  senderIdentityKey: string;
  recipientPublicKey: string;
  lockingScript: string;
}

export const brc29PaymentKeyId = (prefix: string, suffix: string): string => `${prefix} ${suffix}`;

export const uptoControlKeyId = (prefix: string, suffix: string, index: number): string =>
  `${prefix} ${suffix} upto-control-${index}`;

export const p2pkhLockingScript = (publicKey: string): string => {
  const pkh = PublicKey.fromString(publicKey).toHash("hex") as string;
  return `76a914${pkh}88ac`;
};

export const createBrc29PaymentContext = async (
  wallet: WalletInterface,
  payTo: string,
  originator?: string,
): Promise<Brc29PaymentContext> => {
  const derivationPrefix = Utils.toBase64(Random(8));
  const derivationSuffix = Utils.toBase64(Utils.toArray(String(Date.now()), "utf8"));
  const { publicKey: recipientPublicKey } = await wallet.getPublicKey(
    {
      protocolID: BRC29_PROTOCOL_ID,
      keyID: brc29PaymentKeyId(derivationPrefix, derivationSuffix),
      counterparty: payTo,
    },
    originator,
  );
  const { publicKey: senderIdentityKey } = await wallet.getPublicKey(
    { identityKey: true },
    originator,
  );
  return {
    derivationPrefix,
    derivationSuffix,
    senderIdentityKey,
    recipientPublicKey,
    lockingScript: p2pkhLockingScript(recipientPublicKey),
  };
};

export const validateUptoBsvPaymentRequirements = (requirements: PaymentRequirements): void => {
  if (requirements.scheme !== "upto") {
    throw new Error(`Unsupported scheme: ${requirements.scheme}`);
  }
  if (!isBsvNetwork(requirements.network)) {
    throw new Error(`Unsupported BSV network: ${requirements.network}`);
  }
  const asset = requirements.asset ?? BSV_ASSET_IDENTIFIER;
  if (asset !== "" && asset.toUpperCase() !== BSV_ASSET_IDENTIFIER) {
    throw new Error(
      `Unsupported asset "${requirements.asset}": only native ${BSV_ASSET_IDENTIFIER} (satoshis) is supported`,
    );
  }
  if (!requirements.amount || !/^\d+$/.test(requirements.amount)) {
    throw new Error("amount must be a non-empty decimal string of satoshis");
  }
  const satoshis = BigInt(requirements.amount);
  if (satoshis <= 0n || satoshis > BigInt(MAX_SATOSHIS)) {
    throw new Error(`amount must be between 1 and ${MAX_SATOSHIS} satoshis`);
  }
  if (
    !Number.isSafeInteger(requirements.maxTimeoutSeconds) ||
    requirements.maxTimeoutSeconds <= 0
  ) {
    throw new Error("maxTimeoutSeconds must be a positive safe integer");
  }
  if (!requirements.payTo || !COMPRESSED_PUBKEY_REGEX.test(requirements.payTo)) {
    throw new Error(
      "payTo must be the recipient's identity public key (33-byte compressed secp256k1 hex)",
    );
  }
};
