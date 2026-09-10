import { describe, expect, it } from "vitest";
import { InMemoryAuthorizationStore } from "../../src/upto/server/authorizationStore";

const AUTHORIZATION_A = "ab".repeat(32);
const AUTHORIZATION_B = "cd".repeat(32);
const OUTPOINT_A = `${"aa".repeat(32)}:0`;
const OUTPOINT_B = `${"bb".repeat(32)}:7`;
const VALID_AFTER = 1_800_000_000;
const DEADLINE = 1_800_000_060;

function admission(authorizationId: string, outpoints: readonly string[]) {
  return { authorizationId, outpoints, validAfter: VALID_AFTER, deadline: DEADLINE };
}

describe("in-memory upto authorization store", () => {
  it("atomically rejects authorization admission outside its validity window", async () => {
    let now = VALID_AFTER - 1;
    const store = new InMemoryAuthorizationStore(() => now);
    const admission = {
      authorizationId: AUTHORIZATION_A,
      outpoints: [OUTPOINT_A],
      validAfter: VALID_AFTER,
      deadline: DEADLINE,
    };

    await expect(store.admit(admission)).resolves.toEqual({ kind: "out_of_window" });

    now = VALID_AFTER;
    await expect(store.admit(admission)).resolves.toMatchObject({ kind: "admitted" });

    now = DEADLINE;
    await expect(
      store.admit({
        authorizationId: AUTHORIZATION_B,
        outpoints: [OUTPOINT_B],
        validAfter: VALID_AFTER,
        deadline: DEADLINE,
      }),
    ).resolves.toEqual({ kind: "out_of_window" });
  });

  it("atomically admits one authorization for a shared outpoint", async () => {
    const store = new InMemoryAuthorizationStore(() => VALID_AFTER);

    const results = await Promise.all([
      store.admit(admission(AUTHORIZATION_A, [OUTPOINT_A, OUTPOINT_B])),
      store.admit(admission(AUTHORIZATION_B, [OUTPOINT_A])),
    ]);

    expect(results.filter(result => result.kind === "admitted")).toHaveLength(1);
    expect(results.filter(result => result.kind === "unavailable")).toHaveLength(1);

    const winningAuthorization = results[0].kind === "admitted" ? AUTHORIZATION_A : AUTHORIZATION_B;
    const repeated = await store.admit(admission(winningAuthorization, [`${"ee".repeat(32)}:1`]));
    expect(repeated).toEqual({ kind: "unavailable" });
  });

  it("captures the admitted outpoints before the caller can mutate them", async () => {
    const store = new InMemoryAuthorizationStore(() => VALID_AFTER);
    const outpoints = [OUTPOINT_A];

    const admitted = await store.admit(admission(AUTHORIZATION_A, outpoints));
    expect(admitted.kind).toBe("admitted");
    outpoints[0] = OUTPOINT_B;

    const conflict = await store.admit(admission(AUTHORIZATION_B, [OUTPOINT_A]));
    expect(conflict).toEqual({ kind: "unavailable" });
  });

  it("binds one canonical actual amount only for the opaque admission token", async () => {
    const store = new InMemoryAuthorizationStore(() => VALID_AFTER);
    const admitted = await store.admit(admission(AUTHORIZATION_A, [OUTPOINT_A]));
    expect(admitted.kind).toBe("admitted");
    if (admitted.kind !== "admitted") throw new Error("expected an admission token");

    const forged = "not-a-store-token";
    await expect(store.bindActualAmount({ token: forged, amount: "300" })).resolves.toEqual({
      kind: "unavailable",
    });
    await expect(store.bindActualAmount({ token: admitted.token, amount: "0300" })).rejects.toThrow(
      /canonical amount/,
    );
    await expect(store.bindActualAmount({ token: admitted.token, amount: "300" })).resolves.toEqual(
      { kind: "bound" },
    );
    await expect(store.bindActualAmount({ token: admitted.token, amount: "301" })).resolves.toEqual(
      { kind: "unavailable" },
    );
  });

  it("atomically rejects amount binding after the admitted deadline", async () => {
    let now = VALID_AFTER;
    const store = new InMemoryAuthorizationStore(() => now);
    const admitted = await store.admit(admission(AUTHORIZATION_A, [OUTPOINT_A]));
    if (admitted.kind !== "admitted") throw new Error("expected an admission token");

    now = DEADLINE;
    await expect(store.bindActualAmount({ token: admitted.token, amount: "300" })).resolves.toEqual(
      { kind: "out_of_window" },
    );
  });

  it("atomically rejects amount binding when the authoritative clock rolls before validAfter", async () => {
    let now = VALID_AFTER;
    const store = new InMemoryAuthorizationStore(() => now);
    const admitted = await store.admit(admission(AUTHORIZATION_A, [OUTPOINT_A]));
    if (admitted.kind !== "admitted") throw new Error("expected an admission token");

    now = VALID_AFTER - 1;
    await expect(store.bindActualAmount({ token: admitted.token, amount: "300" })).resolves.toEqual(
      { kind: "out_of_window" },
    );

    now = VALID_AFTER;
    await expect(store.bindActualAmount({ token: admitted.token, amount: "300" })).resolves.toEqual(
      { kind: "bound" },
    );
  });

  it("rejects structurally non-canonical store keys", async () => {
    const store = new InMemoryAuthorizationStore(() => VALID_AFTER);

    await expect(
      store.admit(admission(AUTHORIZATION_A.toUpperCase(), [OUTPOINT_A])),
    ).rejects.toThrow(/authorizationId/);
    await expect(
      store.admit(admission(AUTHORIZATION_A, [`${"aa".repeat(32)}:00`])),
    ).rejects.toThrow(/outpoint/);
  });
});
