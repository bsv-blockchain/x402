import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { LockingScript, Transaction, Utils } from "@bsv/sdk";
import { sdkRoutesFor } from "./src/mechanisms.ts";
import { loadComponentConfig } from "./src/component.ts";
import { BsvInventory } from "./bsv.ts";

test("one quote retains its offer and a paid request cannot allocate a new offer", () => {
  const inventory = new BsvInventory(
    fixture(),
    mkdtempSync(join(tmpdir(), "bsv-e2e-")),
  );
  const offer = inventory.offer("quote-1", false, 1800000000);
  assert.deepEqual(inventory.offer("quote-1", true, 1800000001), offer);
  assert.deepEqual(
    inventory.capSources(reordered(offer)),
    fixture().entries[0].capSources,
  );
  assert.throws(() => inventory.offer("unknown", true), /unknown paid quote/);
});

test("another process cannot reserve an inventory entry already assigned to a quote", () => {
  const directory = mkdtempSync(join(tmpdir(), "bsv-e2e-"));
  new BsvInventory(fixture(), directory).offer("first", false, 1800000000);
  const code = `import { BsvInventory } from ${JSON.stringify(new URL("./bsv.ts", import.meta.url).href)};
    try { new BsvInventory(${JSON.stringify(fixture())}, ${JSON.stringify(directory)}).offer("second", false);
      process.stdout.write("reused"); } catch (error) { process.stdout.write(error.message); }`;
  assert.match(
    execFileSync(
      process.execPath,
      ["--experimental-strip-types", "--input-type=module", "-e", code],
      { encoding: "utf8" },
    ),
    /inventory exhausted/,
  );
});

test("settlement rejects missing credentials, other payees, and unallocated offers before effects", () => {
  const inventory = new BsvInventory(
    fixture(),
    mkdtempSync(join(tmpdir(), "bsv-e2e-")),
  );
  const control = inventory.offer("quote-1", false, 1800000000);
  let effects = 0;
  const settle = (
    header: string | undefined,
    payTo: string,
    offer = control,
  ) => {
    inventory.authorize(header, "test-secret", {
      scheme: "upto",
      payTo,
      extra: { control: offer },
    });
    effects++;
  };
  assert.throws(() => settle(undefined, "recipient"), /unauthorized/);
  assert.throws(() => settle("Bearer test-secret", "another"), /unauthorized/);
  assert.throws(
    () =>
      settle("Bearer test-secret", "recipient", {
        ...control,
        deadline: control.deadline + 1,
      }),
    /unauthorized/,
  );
  assert.equal(effects, 0);
  settle("Bearer test-secret", "recipient", reordered(control));
  assert.equal(effects, 1);
});

test("the catalog discovers TypeScript exact and upto for HTTP while MCP excludes BSV", () => {
  assert.deepEqual(
    sdkRoutesFor("typescript")
      .filter((route) => route.network === "bsv")
      .map((route) => route.scheme),
    ["exact", "upto"],
  );
  const previous = process.env.BSV_INVENTORY_FILE;
  process.env.BSV_INVENTORY_FILE = "fixture-present";
  try {
    for (const role of ["clients", "servers"]) {
      const http = loadComponentConfig(
        new URL(
          `./${role}/typescript/http/${role === "clients" ? "fetch" : "express"}/`,
          import.meta.url,
        ).pathname,
        `typescript/http/${role === "clients" ? "fetch" : "express"}`,
      );
      assert.equal((http?.protocolFamilies as string[]).includes("bsv"), true);
      const config = loadComponentConfig(
        new URL(`./${role}/typescript/mcp/`, import.meta.url).pathname,
        "typescript/mcp",
      );
      assert.equal(
        (config?.protocolFamilies as string[]).includes("bsv"),
        false,
      );
    }
  } finally {
    if (previous === undefined) delete process.env.BSV_INVENTORY_FILE;
    else process.env.BSV_INVENTORY_FILE = previous;
  }
});

function fixture() {
  // These serialize inventory identities only; they are not spendable chain evidence.
  const source = (satoshis: number) =>
    Utils.toBase64(
      new Transaction(
        1,
        [],
        [{ satoshis, lockingScript: new LockingScript([]) }],
        0,
      ).toAtomicBEEF(),
    );
  return {
    network: "bsv:testnet",
    payTo: "recipient",
    fee: "10",
    entries: [
      {
        controlInputs: [
          {
            nonce: "control",
            sourceTransaction: source(10),
            sourceOutputIndex: 0,
          },
        ],
        capSources: [
          {
            nonce: "cap",
            sourceTransaction: source(1200),
            sourceOutputIndex: 0,
            floorAmount: "100",
          },
        ],
      },
    ],
  };
}

function reordered(offer: ReturnType<BsvInventory["offer"]>) {
  return {
    deadline: offer.deadline,
    validAfter: offer.validAfter,
    inputs: offer.inputs.map((source) => ({
      sourceOutputIndex: source.sourceOutputIndex,
      sourceTransaction: source.sourceTransaction,
      nonce: source.nonce,
    })),
  };
}
