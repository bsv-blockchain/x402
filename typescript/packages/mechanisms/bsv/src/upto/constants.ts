import type { WalletProtocol } from "@bsv/sdk";

/** BRC-42 protocol used by payer applications when reserving cap sources. */
export const BSV_UPTO_CAP_PROTOCOL_ID = Object.freeze([
  2,
  "x402 bsv upto cap",
] as const) as unknown as WalletProtocol;

/** BRC-42 protocol used by recipient applications when reserving control sources. */
export const BSV_UPTO_CONTROL_PROTOCOL_ID = Object.freeze([
  2,
  "x402 bsv upto control",
] as const) as unknown as WalletProtocol;
