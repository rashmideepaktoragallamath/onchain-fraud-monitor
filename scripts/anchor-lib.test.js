"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { reconcile, validateItem, MAX_PER_RUN } = require("./anchor-lib");

const W = (n) => "0x" + n.toString(16).padStart(40, "0");
const H = (n) => "0x" + n.toString(16).padStart(64, "0");
const item = (n, over = {}) => ({ subject: W(n), tx_hash: H(n), risk_score: 82, reason_mask: 5, status: "open", ...over });

/** In-memory stand-in for the RiskRegistry contract. */
function fakeContract() {
  const alerts = []; // {txHash, status}
  const calls = { raise: 0, update: 0 };
  const receipt = (h) => ({ wait: async () => ({ hash: h, gasUsed: 159435n }) });
  return {
    calls,
    alerts,
    alertIdOf: async (hash) => {
      const i = alerts.findIndex((a) => a.txHash === hash);
      return [i >= 0, BigInt(Math.max(i, 0))];
    },
    raiseAlert: async (hash) => {
      calls.raise++;
      alerts.push({ txHash: hash, status: 0 });
      return receipt("0xraise" + calls.raise);
    },
    getAlert: async (id) => ({ status: BigInt(alerts[Number(id)].status) }),
    updateStatus: async (id, status) => {
      calls.update++;
      alerts[Number(id)].status = Number(status);
      return receipt("0xupdate" + calls.update);
    },
  };
}
const quiet = () => {};

test("anchors a new case and records gas and tx hash", async () => {
  const c = fakeContract();
  const out = await reconcile(c, [item(1)], {}, quiet);
  assert.equal(c.calls.raise, 1);
  assert.deepEqual(
    { id: out[W(1)].alertId, gas: out[W(1)].gasUsed, tx: out[W(1)].anchorTx, st: out[W(1)].onchainStatus },
    { id: 0, gas: "159435", tx: "0xraise1", st: "open" }
  );
});

test("is idempotent: a second run sends no transactions and keeps earlier proof", async () => {
  const c = fakeContract();
  const first = await reconcile(c, [item(1)], {}, quiet);
  const second = await reconcile(c, [item(1)], first, quiet);
  assert.equal(c.calls.raise, 1);
  assert.equal(c.calls.update, 0);
  assert.equal(second[W(1)].anchorTx, "0xraise1");
});

test("moves on-chain status to the analyst's decision", async () => {
  const c = fakeContract();
  const first = await reconcile(c, [item(1)], {}, quiet);
  const out = await reconcile(c, [item(1, { status: "reviewed" })], first, quiet);
  assert.equal(c.calls.update, 1);
  assert.equal(out[W(1)].onchainStatus, "reviewed");
  assert.equal(out[W(1)].statusTx, "0xupdate1");
});

test("open -> escalated in one step when the case was decided before anchoring", async () => {
  const c = fakeContract();
  const out = await reconcile(c, [item(1, { status: "escalated" })], {}, quiet);
  assert.equal(out[W(1)].onchainStatus, "escalated");
});

test("never attempts a transition the contract would revert", async () => {
  const c = fakeContract();
  const first = await reconcile(c, [item(1, { status: "escalated" })], {}, quiet);
  const logs = [];
  const out = await reconcile(c, [item(1, { status: "dismissed" })], first, (m) => logs.push(m));
  assert.equal(c.calls.update, 1); // only the first move; escalated is final
  assert.equal(out[W(1)].onchainStatus, "escalated");
  assert.ok(logs.some((m) => m.includes("cannot move")));
});

test("skips malformed items without touching the chain", async () => {
  const c = fakeContract();
  const bad = [
    item(1, { subject: "nope" }),
    item(2, { tx_hash: "0x12" }),
    item(3, { risk_score: 0 }),
    item(4, { risk_score: 101 }),
    item(5, { reason_mask: 0 }),
    item(6, { reason_mask: 70000 }),
    item(7, { status: "open; DROP" }),
    null,
    "string",
  ];
  const out = await reconcile(c, bad, {}, quiet);
  assert.equal(c.calls.raise, 0);
  assert.deepEqual(out, {});
});

test("caps the number of transactions per run", async () => {
  const c = fakeContract();
  const items = Array.from({ length: MAX_PER_RUN + 3 }, (_, i) => item(i + 1));
  const logs = [];
  const out = await reconcile(c, items, {}, (m) => logs.push(m));
  assert.equal(c.calls.raise, MAX_PER_RUN);
  assert.equal(Object.keys(out).length, MAX_PER_RUN);
  assert.ok(logs.some((m) => m.includes("3 more")));
});

test("validateItem lower-cases the wallet", () => {
  const upper = "0x" + "AB".repeat(20);
  assert.equal(validateItem(item(1, { subject: upper })).subject, upper.toLowerCase());
});
