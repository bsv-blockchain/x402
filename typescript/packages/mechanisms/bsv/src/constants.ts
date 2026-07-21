import type { Network } from "@x402/core/types";
import type { WalletProtocol } from "@bsv/sdk";

/**
 * CAIP-2 style network identifier for the BSV mainnet.
 *
 * Note: BSV has no entry in the ChainAgnostic namespaces registry. The
 * `bip122` namespace (genesis-block reference) is ambiguous for BSV because
 * BSV shares its genesis block with BTC and BCH, so this implementation
 * defines a dedicated `bsv` namespace instead.
 */
export const BSV_MAINNET_CAIP2: Network = "bsv:mainnet";

/** CAIP-2 style network identifier for the BSV testnet */
export const BSV_TESTNET_CAIP2: Network = "bsv:testnet";

/** Wildcard matching all BSV networks */
export const BSV_WILDCARD_CAIP2: Network = "bsv:*";

/** Native BSV satoshis use "BSV" as the asset identifier (ticker convention) */
export const BSV_ASSET_IDENTIFIER = "BSV";

/** Number of decimals for native BSV (1 BSV = 100,000,000 satoshis) */
export const BSV_DECIMALS = 8;

/** Maximum number of satoshis that can ever exist (21e14) */
export const MAX_SATOSHIS = 2_100_000_000_000_000;

/**
 * BRC-29 protocol ID used for BRC-42 payment key derivation.
 * Security level 2 with the BRC-29 magic number.
 */
export const BRC29_PROTOCOL_ID: WalletProtocol = [2, "3241645161d8"];

/**
 * Minimum number of bytes for the BRC-29 derivation prefix (the payment
 * nonce). BRC-121 mandates a fresh random prefix of at least 8 bytes.
 */
export const MIN_DERIVATION_PREFIX_BYTES = 8;

/**
 * Default payment freshness window in milliseconds (BRC-121: ±30 seconds).
 * The timestamp encoded in the payload's `derivationSuffix` must be within
 * this window of the verifier's clock.
 */
export const DEFAULT_PAYMENT_WINDOW_MS = 30_000;

/** Regex for a compressed secp256k1 public key (33 bytes hex, 02/03 prefix) */
export const COMPRESSED_PUBKEY_REGEX = /^0[23][0-9a-fA-F]{64}$/;

/** WhatsOnChain USD/BSV exchange-rate endpoint (mainnet) */
export const WOC_MAINNET_EXCHANGE_RATE_URL =
  "https://api.whatsonchain.com/v1/bsv/main/exchangerate";

/** WhatsOnChain USD/BSV exchange-rate endpoint (testnet) */
export const WOC_TESTNET_EXCHANGE_RATE_URL =
  "https://api.whatsonchain.com/v1/bsv/test/exchangerate";

/** Mainnet block explorer base URL */
export const BSV_MAINNET_EXPLORER = "https://whatsonchain.com";

/** Testnet block explorer base URL */
export const BSV_TESTNET_EXPLORER = "https://test.whatsonchain.com";

/** Maps CAIP-2 identifiers to explorer base URLs */
export const BSV_NETWORK_TO_EXPLORER: ReadonlyMap<Network, string> = new Map([
  [BSV_MAINNET_CAIP2, BSV_MAINNET_EXPLORER],
  [BSV_TESTNET_CAIP2, BSV_TESTNET_EXPLORER],
]);

/**
 * Checks whether a network identifier belongs to the BSV family.
 *
 * @param network - CAIP-2 network identifier
 * @returns True when the namespace is `bsv`
 */
export function isBsvNetwork(network: Network): boolean {
  return network === BSV_MAINNET_CAIP2 || network === BSV_TESTNET_CAIP2;
}

/**
 * Gets the block explorer URL for a transaction.
 *
 * @param network - CAIP-2 network identifier
 * @param txid - Transaction id (hex)
 * @returns Full explorer URL, or undefined if network not recognized
 */
export function getExplorerTxUrl(network: Network, txid: string): string | undefined {
  const base = BSV_NETWORK_TO_EXPLORER.get(network);
  return base ? `${base}/tx/${txid}` : undefined;
}
