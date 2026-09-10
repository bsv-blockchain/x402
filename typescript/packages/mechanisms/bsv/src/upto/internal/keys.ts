import { ProtoWallet, PublicKey, type WalletProtocol } from "@bsv/sdk";
import { BSV_UPTO_CAP_PROTOCOL_ID, BSV_UPTO_CONTROL_PROTOCOL_ID } from "../constants";

export type UptoSourceRole = "cap" | "control";

export const UPTO_AUTHORIZATION_PROTOCOL: WalletProtocol = [2, "x402 bsv upto authorization"];
export const UPTO_CAP_PROTOCOL = BSV_UPTO_CAP_PROTOCOL_ID;
export const UPTO_CONTROL_PROTOCOL = BSV_UPTO_CONTROL_PROTOCOL_ID;

const PUBLIC_DERIVER = new ProtoWallet("anyone");

/**
 * Returns the BRC-42 protocol identifier for a source role.
 *
 * @param role - Cap or control source role
 * @returns The role's fixed wallet protocol identifier
 */
export function uptoSourceProtocol(role: UptoSourceRole): WalletProtocol {
  return role === "cap" ? UPTO_CAP_PROTOCOL : UPTO_CONTROL_PROTOCOL;
}

/**
 * Publicly derives the P2PKH key committed by one source reference.
 *
 * This uses the BRC-42 public "anyone" root and the source owner's identity;
 * it never depends on the verifier wallet's private root.
 *
 * @param role - Cap or control source role
 * @param nonce - Canonical 32-byte nonce in padded base64
 * @param ownerIdentity - Payer identity for cap or payTo identity for control
 * @returns Canonical compressed source public key
 */
export async function deriveUptoSourcePublicKey(
  role: UptoSourceRole,
  nonce: string,
  ownerIdentity: string,
): Promise<string> {
  const { publicKey } = await PUBLIC_DERIVER.getPublicKey({
    protocolID: uptoSourceProtocol(role),
    keyID: nonce,
    counterparty: ownerIdentity,
  });
  return PublicKey.fromString(publicKey).toString();
}
