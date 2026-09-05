import type {
  UptoBsvCapSource,
  UptoBsvControlOffer,
  UptoBsvSourceReference,
} from "@x402/bsv";
import {
  BlockHeadersService,
  HTTPWalletJSON,
  Transaction,
  Utils,
} from "@bsv/sdk";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { isDeepStrictEqual } from "node:util";

export interface BsvFixtureInventory {
  network: string;
  payTo: string;
  fee: string;
  entries: {
    controlInputs: UptoBsvSourceReference[];
    capSources: UptoBsvCapSource[];
  }[];
}

/** Local E2E fixtures, never an application payment or recovery store. */
export class BsvInventory {
  readonly data: BsvFixtureInventory;
  readonly directory: string;
  private readonly quotes = new Map<string, UptoBsvControlOffer>();

  constructor(data: BsvFixtureInventory, directory: string) {
    if (
      data.network !== "bsv:testnet" ||
      (process.env.BSV_NETWORK && process.env.BSV_NETWORK !== data.network)
    ) {
      throw new Error("BSV E2E supports bsv:testnet only");
    }
    if (!/^(0|[1-9]\d*)$/.test(data.fee) || !data.entries.length)
      throw new Error("invalid BSV inventory");
    const outpoints = new Set<string>();
    for (const entry of data.entries) {
      if (!entry.controlInputs.length || !entry.capSources.length)
        throw new Error("empty BSV source pair");
      for (const source of [...entry.controlInputs, ...entry.capSources]) {
        const key = sourceOutpoint(source);
        if (outpoints.has(key))
          throw new Error("BSV inventory repeats an outpoint");
        outpoints.add(key);
      }
    }
    this.data = data;
    this.directory = directory;
    mkdirSync(directory, { recursive: true });
  }

  offer(
    quote: string,
    presented: boolean,
    now = Math.floor(Date.now() / 1000),
  ): UptoBsvControlOffer {
    if (!quote || quote.length > 128)
      throw new Error("BSV E2E quote is required");
    const existing = this.quotes.get(quote);
    if (existing) return existing;
    if (presented) throw new Error("unknown paid quote");
    for (const entry of this.data.entries) {
      let fd: number;
      try {
        fd = openSync(this.claimPath(entry), "wx");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") continue;
        throw error;
      }
      const offer = {
        inputs: entry.controlInputs,
        validAfter: now,
        deadline: now + 60,
      };
      try {
        writeFileSync(fd, JSON.stringify({ quote, offer }));
      } finally {
        closeSync(fd);
      }
      this.quotes.set(quote, offer);
      return offer;
    }
    throw new Error("BSV inventory exhausted; prepare new sources");
  }

  authorize(
    header: string | undefined,
    token: string,
    accepted: {
      scheme: string;
      payTo: string;
      extra?: Record<string, unknown>;
    },
  ): void {
    const expected = Buffer.from(`Bearer ${token}`);
    const supplied = Buffer.from(header ?? "");
    if (
      !token ||
      supplied.length !== expected.length ||
      !timingSafeEqual(supplied, expected) ||
      accepted.payTo.toLowerCase() !== this.data.payTo.toLowerCase()
    ) {
      throw new Error("unauthorized BSV settlement caller");
    }
    if (accepted.scheme === "exact") return;
    const control = accepted.extra?.control;
    for (const entry of this.data.entries) {
      try {
        const claim = JSON.parse(readFileSync(this.claimPath(entry), "utf8"));
        if (isDeepStrictEqual(claim.offer, control)) return;
      } catch {
        /* Unallocated or incomplete fixture claims are not authorized. */
      }
    }
    throw new Error("unauthorized BSV control offer");
  }

  capSources(control: UptoBsvControlOffer): readonly UptoBsvCapSource[] {
    const entry = this.data.entries.find((item) =>
      isDeepStrictEqual(item.controlInputs, control.inputs),
    );
    if (!entry)
      throw new Error("control offer is outside the BSV fixture inventory");
    return entry.capSources;
  }

  private claimPath(entry: BsvFixtureInventory["entries"][number]): string {
    const key = createHash("sha256")
      .update(
        [...entry.controlInputs, ...entry.capSources]
          .map(sourceOutpoint)
          .sort()
          .join("\n"),
      )
      .digest("hex");
    return join(this.directory, `${key}.claim`);
  }
}

function sourceOutpoint(source: UptoBsvSourceReference): string {
  if (
    source.sourceTransaction.length > 90_000 ||
    !Number.isSafeInteger(source.sourceOutputIndex) ||
    source.sourceOutputIndex < 0
  )
    throw new Error("invalid BSV fixture source");
  const tx = Transaction.fromAtomicBEEF(
    Utils.toArray(source.sourceTransaction, "base64"),
  );
  if (!tx.outputs[source.sourceOutputIndex])
    throw new Error("missing BSV fixture output");
  return `${tx.id("hex")}:${source.sourceOutputIndex}`;
}

export function bsvEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`BSV E2E requires ${name}`);
  return value;
}

let inventory: BsvInventory | undefined;
export function bsvInventory(): BsvInventory | undefined {
  if (!process.env.BSV_INVENTORY_FILE) return undefined;
  return (inventory ??= new BsvInventory(
    JSON.parse(readFileSync(process.env.BSV_INVENTORY_FILE, "utf8")),
    bsvEnv("BSV_CLAIMS_DIRECTORY"),
  ));
}

export function bsvWallet(role: "CLIENT" | "FACILITATOR"): HTTPWalletJSON {
  return new HTTPWalletJSON(
    process.env.BSV_ORIGINATOR ?? "x402-bsv-e2e.test",
    bsvEnv(`${role}_BSV_WALLET_URL`),
  );
}

export function bsvChainTracker(): BlockHeadersService {
  return new BlockHeadersService(bsvEnv("BSV_HEADERS_URL"), {
    apiKey: process.env.BSV_HEADERS_API_KEY,
  });
}

export const bsvPolicies = {
  sourcePolicy: { maxSources: 4, maxAtomicBeefBytesPerSource: 64 * 1024 },
  terminalPolicy: { maxAtomicBeefBytes: 256 * 1024 },
};
