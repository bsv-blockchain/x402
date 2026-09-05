import { Utils } from "@bsv/sdk";
import { describe, expect, it } from "vitest";
import { validateAndDigestAuthorization } from "../../src/upto/internal/authorization";

const EXPECTED_CANONICAL_TEXT = [
  "x402-bsv-upto-authorization-v1",
  "bsv:testnet",
  "BSV",
  "700",
  "02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af",
  "60",
  "1800000000",
  "1800000060",
  "2",
  "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ=",
  "96c435b189fd6c533b9c51472009153d56ed411714b7925235931506ae289dd7",
  "0",
  "FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRU=",
  "7a7d34973ccd2d49e1d07cd619449cef9fcb57666846b55dabfc2fd9b8e201ba",
  "0",
  "037a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb",
  "Q2ludlYxMjM0NTY3ODkwMTIz",
  "MTgwMDAwMDAwMDAwMA==",
  "2",
  "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=",
  "597b3e7fa9b2dc31b27a7e751613e1f768bbe8386af96ecd32ee4b8e9376a768",
  "0",
  "100",
  "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=",
  "315d09801593af461928d8f9b6bb683ef9067437653c5bb5b008a997fd2962ed",
  "0",
  "100",
].join("\n");

function knownAuthorization() {
  return {
    network: "bsv:testnet",
    asset: "BSV",
    maximumAmount: "700",
    payTo: "02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af",
    maxTimeoutSeconds: 60,
    validAfter: 1_800_000_000,
    deadline: 1_800_000_060,
    controlInputs: [
      {
        nonce: "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ=",
        sourceTxid: "96c435b189fd6c533b9c51472009153d56ed411714b7925235931506ae289dd7",
        sourceOutputIndex: 0,
      },
      {
        nonce: "FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRU=",
        sourceTxid: "7a7d34973ccd2d49e1d07cd619449cef9fcb57666846b55dabfc2fd9b8e201ba",
        sourceOutputIndex: 0,
      },
    ],
    senderIdentityKey: "037a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb",
    derivationPrefix: "Q2ludlYxMjM0NTY3ODkwMTIz",
    derivationSuffix: "MTgwMDAwMDAwMDAwMA==",
    capInputs: [
      {
        nonce: "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=",
        sourceTxid: "597b3e7fa9b2dc31b27a7e751613e1f768bbe8386af96ecd32ee4b8e9376a768",
        sourceOutputIndex: 0,
        floorAmount: "100",
      },
      {
        nonce: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=",
        sourceTxid: "315d09801593af461928d8f9b6bb683ef9067437653c5bb5b008a997fd2962ed",
        sourceOutputIndex: 0,
        floorAmount: "100",
      },
    ],
  };
}

describe("BSV upto authorization digest", () => {
  it("reproduces the specification 2x2 known-answer vector", () => {
    const facts = knownAuthorization();
    const result = validateAndDigestAuthorization(facts);

    expect(result.canonicalText).toBe(EXPECTED_CANONICAL_TEXT);
    expect(result.canonicalText.endsWith("\n")).toBe(false);
    expect(Utils.toHex(result.digest)).toBe(
      "8e34760db6a96dac832368a8d499bd45165380a82ac36b9047db3000796b3619",
    );

    facts.network = "changed";
    facts.controlInputs[0].nonce = "changed";
    expect(result.snapshot.network).toBe("bsv:testnet");
    expect(result.snapshot.controlInputs[0].nonce).toBe(
      "FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ=",
    );
  });

  it.each([
    ["a zero maximum", "0", /maximumAmount must be positive/],
    ["a maximum above the BSV supply", "2100000000000001", /maximumAmount exceeds/],
    ["a non-canonical maximum", "0700", /maximumAmount must be a canonical/],
  ])("rejects %s", (_name, maximumAmount, expected) => {
    const facts = knownAuthorization();
    facts.maximumAmount = maximumAmount;

    expect(() => validateAndDigestAuthorization(facts)).toThrow(expected);
  });

  it.each([
    ["zero", "0"],
    ["non-canonical", "0100"],
  ])("rejects a %s floor amount", (_name, floorAmount) => {
    const facts = knownAuthorization();
    facts.capInputs[0].floorAmount = floorAmount;

    expect(() => validateAndDigestAuthorization(facts)).toThrow(/floorAmount/);
  });

  it.each([
    [
      "an LF in a signed text field",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.network = "bsv:\ntestnet";
      },
      /network must not contain LF/,
    ],
    [
      "an uppercase source txid",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.controlInputs[0].sourceTxid = facts.controlInputs[0].sourceTxid.toUpperCase();
      },
      /sourceTxid must be 64 lowercase hex/,
    ],
    [
      "an invalid compressed identity key",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.payTo = `02${"00".repeat(32)}`;
      },
      /payTo must be a valid compressed secp256k1 public key/,
    ],
    [
      "an unpadded nonce",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.capInputs[0].nonce = facts.capInputs[0].nonce.slice(0, -1);
      },
      /nonce must be padded canonical base64 for 32 bytes/,
    ],
    [
      "non-canonical derivation base64",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.derivationSuffix = "MTgwMDAwMDAwMDAwMA";
      },
      /derivationSuffix must be canonical base64/,
    ],
  ])("rejects %s", (_name, mutate, expected) => {
    const facts = knownAuthorization();
    mutate(facts);

    expect(() => validateAndDigestAuthorization(facts)).toThrow(expected);
  });

  it.each([
    [
      "a zero timeout",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.maxTimeoutSeconds = 0;
      },
    ],
    [
      "a non-uint32 deadline",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.deadline = 2 ** 32;
      },
    ],
    [
      "a pre-timestamp validAfter",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.validAfter = 499_999_999;
      },
    ],
    [
      "a non-positive window",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.deadline = facts.validAfter;
      },
    ],
    [
      "a window larger than maxTimeoutSeconds",
      (facts: ReturnType<typeof knownAuthorization>) => {
        facts.maxTimeoutSeconds = 59;
      },
    ],
  ])("rejects %s", (_name, mutate) => {
    const facts = knownAuthorization();
    mutate(facts);

    expect(() => validateAndDigestAuthorization(facts)).toThrow(/timeout|uint32|window|validAfter/);
  });

  it.each(["controlInputs", "capInputs"] as const)("rejects empty %s", role => {
    const facts = knownAuthorization();
    facts[role] = [];

    expect(() => validateAndDigestAuthorization(facts)).toThrow(`${role} must be non-empty`);
  });

  it("rejects a duplicate nonce within one input role", () => {
    const facts = knownAuthorization();
    facts.controlInputs[1].nonce = facts.controlInputs[0].nonce;

    expect(() => validateAndDigestAuthorization(facts)).toThrow(/controlInputs nonces/);
  });

  it("allows the same nonce once in each input role", () => {
    const facts = knownAuthorization();
    facts.capInputs[0].nonce = facts.controlInputs[0].nonce;

    expect(validateAndDigestAuthorization(facts).snapshot.capInputs[0].nonce).toBe(
      facts.controlInputs[0].nonce,
    );
  });

  it("rejects a source outpoint reused across roles", () => {
    const facts = knownAuthorization();
    facts.capInputs[0].sourceTxid = facts.controlInputs[0].sourceTxid;
    facts.capInputs[0].sourceOutputIndex = facts.controlInputs[0].sourceOutputIndex;

    expect(() => validateAndDigestAuthorization(facts)).toThrow(/source outpoints must be unique/);
  });
});
