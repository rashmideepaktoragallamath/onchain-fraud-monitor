"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { keccak256, leafHash, buildTree, proofFor, verifyProof, buildBatch, hex } = require("./merkle-lib");

const W = (n) => "0x" + n.toString(16).padStart(40, "0");
const H = (n) => "0x" + n.toString(16).padStart(64, "0");
const alert = (n, over = {}) => ({ txHash: H(n), subject: W(n), score: 60 + (n % 40), mask: 1 + (n % 500), ...over });

test("keccak256 matches the published Ethereum test vectors", () => {
  assert.equal(hex(keccak256(Buffer.alloc(0))), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(hex(keccak256(Buffer.from("abc"))), "0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
});

test("keccak256 handles inputs at and across the 136-byte block boundary", () => {
  // Lengths 135, 136, 137 exercise single-byte padding, an extra block, and a spill-over block.
  const outs = [135, 136, 137, 272].map((n) => hex(keccak256(Buffer.alloc(n, 0x61))));
  assert.equal(new Set(outs).size, 4);
  outs.forEach((o) => assert.match(o, /^0x[0-9a-f]{64}$/));
});

test("every alert in batches of many sizes verifies against the root", () => {
  for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 16, 31, 100]) {
    const batch = buildBatch(Array.from({ length: n }, (_, i) => alert(i + 1)));
    assert.equal(batch.count, n);
    for (const p of batch.proofs) {
      const proof = p.proof.map((h) => Buffer.from(h.slice(2), "hex"));
      assert.ok(verifyProof(Buffer.from(batch.root.slice(2), "hex"), Buffer.from(p.leaf.slice(2), "hex"), proof), `n=${n}`);
    }
  }
});

test("proof length is at most ceil(log2 n)", () => {
  const batch = buildBatch(Array.from({ length: 100 }, (_, i) => alert(i + 1)));
  assert.ok(Math.max(...batch.proofs.map((p) => p.proof.length)) <= 7);
});

test("a single-alert batch has the leaf as its root and an empty proof", () => {
  const batch = buildBatch([alert(1)]);
  assert.equal(batch.root, batch.proofs[0].leaf);
  assert.deepEqual(batch.proofs[0].proof, []);
});

test("changing any field of an alert breaks its proof", () => {
  const alerts = Array.from({ length: 6 }, (_, i) => alert(i + 1));
  const batch = buildBatch(alerts);
  const root = Buffer.from(batch.root.slice(2), "hex");
  const p = batch.proofs[2];
  const proof = p.proof.map((h) => Buffer.from(h.slice(2), "hex"));
  for (const tampered of [{ score: p.score + 1 }, { mask: p.mask ^ 1 }, { subject: W(999) }, { txHash: H(999) }]) {
    const leaf = leafHash({ ...alerts[2], ...tampered });
    assert.equal(verifyProof(root, leaf, proof), false);
  }
});

test("a proof from one batch does not verify against another batch's root", () => {
  const a = buildBatch([1, 2, 3, 4].map((n) => alert(n)));
  const b = buildBatch([5, 6, 7, 8].map((n) => alert(n)));
  const p = a.proofs[0];
  assert.equal(
    verifyProof(Buffer.from(b.root.slice(2), "hex"), Buffer.from(p.leaf.slice(2), "hex"), p.proof.map((h) => Buffer.from(h.slice(2), "hex"))),
    false
  );
});

test("the root does not depend on how the tree is walked: tree and proofs agree", () => {
  const leaves = [1, 2, 3, 4, 5].map((n) => leafHash(alert(n)));
  const levels = buildTree(leaves);
  const root = levels[levels.length - 1][0];
  leaves.forEach((leaf, i) => assert.ok(verifyProof(root, leaf, proofFor(levels, i))));
});

test("invalid inputs are rejected", () => {
  assert.throws(() => buildBatch([]), /no leaves/);
  assert.throws(() => leafHash(alert(1, { score: 0 })), /1-100/);
  assert.throws(() => leafHash(alert(1, { mask: 0x10000 })), /16 bits/);
  assert.throws(() => leafHash(alert(1, { txHash: "0x12" })), /32 bytes/);
});
