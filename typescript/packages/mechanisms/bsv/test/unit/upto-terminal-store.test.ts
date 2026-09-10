import { describe, expect, it } from "vitest";
import {
  InMemoryTerminalStore,
  type VerifiedTerminalRecord,
} from "../../src/upto/facilitator/terminalStore";

const AUTHORIZATION_A = "11".repeat(32);
const AUTHORIZATION_B = "22".repeat(32);
const TXID_A = "aa".repeat(32);
const TXID_B = "bb".repeat(32);

function terminal(overrides: Partial<VerifiedTerminalRecord> = {}): VerifiedTerminalRecord {
  return {
    authorizationId: AUTHORIZATION_A,
    txid: TXID_A,
    amount: "300",
    subjectTransaction: "Aw==",
    settlementTransaction: "AA==",
    ...overrides,
  };
}

describe("in-memory upto facilitator terminal store", () => {
  it("atomically selects only one terminal before the strict deadline", async () => {
    const store = new InMemoryTerminalStore({ now: () => 100 });
    const candidates = [
      terminal(),
      terminal({ txid: TXID_B, subjectTransaction: "BA==", settlementTransaction: "AQ==" }),
    ];

    const results = await Promise.all(
      candidates.map(terminal => store.select({ terminal, validAfter: 100, deadline: 101 })),
    );

    expect(results.filter(result => result.kind === "selected")).toHaveLength(1);
    expect(results.filter(result => result.kind === "unavailable")).toHaveLength(1);
    const selected = await store.read(AUTHORIZATION_A);
    expect(selected?.kind).toBe("selected");
    expect([TXID_A, TXID_B]).toContain(selected?.terminal.txid);
  });

  it("rejects a new selection at or after the deadline", async () => {
    let now = 100;
    const store = new InMemoryTerminalStore({ now: () => now });

    await expect(
      store.select({ terminal: terminal(), validAfter: 99, deadline: 100 }),
    ).resolves.toEqual({ kind: "unavailable" });
    now = 101;
    await expect(
      store.select({
        terminal: terminal({ authorizationId: AUTHORIZATION_B }),
        validAfter: 99,
        deadline: 100,
      }),
    ).resolves.toEqual({ kind: "unavailable" });
    expect(await store.read(AUTHORIZATION_A)).toBeUndefined();
  });

  it("rejects a new selection when the authoritative clock is before validAfter", async () => {
    let now = 99;
    const store = new InMemoryTerminalStore({ now: () => now });

    await expect(
      store.select({ terminal: terminal(), validAfter: 100, deadline: 101 }),
    ).resolves.toEqual({ kind: "unavailable" });
    now = 100;
    await expect(
      store.select({ terminal: terminal(), validAfter: 100, deadline: 101 }),
    ).resolves.toMatchObject({ kind: "selected" });
  });

  it("does not issue a second wallet-attempt token for a selected terminal", async () => {
    const store = new InMemoryTerminalStore({ now: () => 100 });
    const first = await store.select({ terminal: terminal(), validAfter: 100, deadline: 101 });
    expect(first.kind).toBe("selected");

    await expect(
      store.select({ terminal: terminal(), validAfter: 100, deadline: 101 }),
    ).resolves.toEqual({ kind: "unavailable" });
    await expect(
      store.select({
        terminal: terminal({
          txid: TXID_B,
          subjectTransaction: "BA==",
          settlementTransaction: "AQ==",
        }),
        validAfter: 100,
        deadline: 101,
      }),
    ).resolves.toEqual({ kind: "unavailable" });
  });

  it("records acceptance once for the matching selection token and txid", async () => {
    const store = new InMemoryTerminalStore({ now: () => 100 });
    const selection = await store.select({
      terminal: terminal(),
      validAfter: 100,
      deadline: 101,
    });
    if (selection.kind !== "selected") throw new Error("expected a terminal selection token");

    const forged = "not-a-store-token";
    await expect(store.recordAccepted({ token: forged, txid: TXID_A })).resolves.toEqual({
      kind: "unavailable",
    });
    await expect(store.recordAccepted({ token: selection.token, txid: TXID_B })).resolves.toEqual({
      kind: "unavailable",
    });

    const accepted = await store.recordAccepted({ token: selection.token, txid: TXID_A });
    expect(accepted).toEqual({ kind: "accepted", terminal: terminal() });
    await expect(store.recordAccepted({ token: selection.token, txid: TXID_A })).resolves.toEqual({
      kind: "unavailable",
    });
    expect(await store.read(AUTHORIZATION_A)).toEqual({
      kind: "accepted",
      terminal: terminal(),
    });
  });

  it("replays the stored accepted terminal identity without adopting a new envelope", async () => {
    let now = 100;
    const store = new InMemoryTerminalStore({ now: () => now });
    const selection = await store.select({
      terminal: terminal(),
      validAfter: 100,
      deadline: 101,
    });
    if (selection.kind !== "selected") throw new Error("expected a terminal selection token");
    await store.recordAccepted({ token: selection.token, txid: TXID_A });

    now = 500;
    await expect(
      store.select({
        terminal: terminal({ settlementTransaction: "AQ==" }),
        validAfter: 100,
        deadline: 101,
      }),
    ).resolves.toEqual({
      kind: "accepted",
      terminal: terminal(),
    });
    await expect(
      store.select({
        terminal: terminal({
          txid: TXID_B,
          subjectTransaction: "BA==",
          settlementTransaction: "AQ==",
        }),
        validAfter: 100,
        deadline: 101,
      }),
    ).resolves.toEqual({ kind: "unavailable" });
  });

  it("snapshots a terminal on selection and on every returned read", async () => {
    const store = new InMemoryTerminalStore({ now: () => 100 });
    const candidate = terminal();
    const selection = await store.select({ terminal: candidate, validAfter: 100, deadline: 101 });
    expect(selection.kind).toBe("selected");
    if (selection.kind !== "selected") throw new Error("expected a selected terminal");
    Object.assign(selection.terminal, { txid: TXID_B, settlementTransaction: "Ag==" });
    Object.assign(candidate, { txid: TXID_B, settlementTransaction: "AQ==" });

    const firstRead = await store.read(AUTHORIZATION_A);
    expect(firstRead?.terminal).toEqual(terminal());
    if (!firstRead) throw new Error("expected a selected terminal");
    Object.assign(firstRead.terminal, { txid: TXID_B });

    expect((await store.read(AUTHORIZATION_A))?.terminal).toEqual(terminal());
  });

  it("rejects structurally non-canonical terminal facts and times", async () => {
    const store = new InMemoryTerminalStore({ now: () => 100 });

    await expect(
      store.select({ terminal: terminal({ amount: "0300" }), validAfter: 100, deadline: 101 }),
    ).rejects.toThrow(/canonical amount/);
    await expect(
      store.select({
        terminal: terminal({ txid: TXID_A.toUpperCase() }),
        validAfter: 100,
        deadline: 101,
      }),
    ).rejects.toThrow(/txid/);
    await expect(
      store.select({
        terminal: terminal({ settlementTransaction: "not base64" }),
        validAfter: 100,
        deadline: 101,
      }),
    ).rejects.toThrow(/canonical base64/);
    await expect(
      store.select({ terminal: terminal(), validAfter: 101, deadline: 101 }),
    ).rejects.toThrow(/window/);
    const invalidClock = new InMemoryTerminalStore({ now: () => -0 });
    await expect(
      invalidClock.select({ terminal: terminal(), validAfter: 100, deadline: 101 }),
    ).rejects.toThrow(/now/);
  });
});
