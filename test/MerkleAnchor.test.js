const { expect } = require("chai");
const { ethers } = require("hardhat");
const { buildBatch, keccak256, leafHash } = require("../scripts/merkle-lib");

const H = (n) => ethers.keccak256(ethers.toUtf8Bytes(`tx-${n}`));
const alerts = (n) =>
  Array.from({ length: n }, (_, i) => ({
    txHash: H(i + 1),
    subject: ethers.getAddress("0x" + (i + 1).toString(16).padStart(40, "0")),
    score: 50 + (i % 50),
    mask: 1 + (i % 500),
  }));

describe("MerkleAnchor", () => {
  let anchor, owner, analyst, outsider;

  beforeEach(async () => {
    [owner, analyst, outsider] = await ethers.getSigners();
    anchor = await ethers.deployContract("MerkleAnchor");
    await anchor.setAnalyst(analyst.address, true);
  });

  it("MA-01 the JavaScript Keccak matches ethers on assorted inputs", () => {
    for (const len of [0, 1, 55, 135, 136, 137, 300]) {
      const data = ethers.randomBytes(len);
      expect("0x" + keccak256(Buffer.from(data)).toString("hex")).to.equal(ethers.keccak256(data));
    }
  });

  it("MA-02 the JavaScript leaf equals the contract's leafOf", async () => {
    const a = alerts(1)[0];
    const onChain = await anchor.leafOf(a.txHash, a.subject, a.score, a.mask);
    expect("0x" + leafHash(a).toString("hex")).to.equal(onChain);
  });

  it("MA-03 an analyst anchors a batch and an event is emitted", async () => {
    const batch = buildBatch(alerts(10));
    await expect(anchor.connect(analyst).anchorBatch(batch.root, batch.count))
      .to.emit(anchor, "BatchAnchored")
      .withArgs(0, batch.root, 10, analyst.address);
    const b = await anchor.getBatch(0);
    expect(b.root).to.equal(batch.root);
    expect(b.count).to.equal(10);
  });

  it("MA-04 every alert of a batch verifies on-chain", async () => {
    const list = alerts(13);
    const batch = buildBatch(list);
    await anchor.anchorBatch(batch.root, batch.count);
    for (const p of batch.proofs) {
      expect(await anchor.verifyAlert(0, p.txHash, p.subject, p.score, p.mask, p.proof)).to.equal(true);
    }
  });

  it("MA-05 a tampered alert does not verify", async () => {
    const batch = buildBatch(alerts(8));
    await anchor.anchorBatch(batch.root, batch.count);
    const p = batch.proofs[3];
    expect(await anchor.verifyAlert(0, p.txHash, p.subject, p.score + 1, p.mask, p.proof)).to.equal(false);
    expect(await anchor.verifyAlert(0, p.txHash, p.subject, p.score, p.mask ^ 1, p.proof)).to.equal(false);
    expect(await anchor.verifyAlert(0, H(999), p.subject, p.score, p.mask, p.proof)).to.equal(false);
  });

  it("MA-06 a non-analyst cannot anchor", async () => {
    const batch = buildBatch(alerts(2));
    await expect(anchor.connect(outsider).anchorBatch(batch.root, 2)).to.be.revertedWithCustomError(anchor, "NotAnalyst");
  });

  it("MA-07 empty root, empty batch and duplicate roots are rejected", async () => {
    const batch = buildBatch(alerts(2));
    await expect(anchor.anchorBatch(ethers.ZeroHash, 2)).to.be.revertedWithCustomError(anchor, "EmptyRoot");
    await expect(anchor.anchorBatch(batch.root, 0)).to.be.revertedWithCustomError(anchor, "EmptyBatch");
    await anchor.anchorBatch(batch.root, 2);
    await expect(anchor.anchorBatch(batch.root, 2)).to.be.revertedWithCustomError(anchor, "AlreadyAnchored");
  });

  it("MA-08 verifying against an unknown batch reverts", async () => {
    await expect(anchor.verify(5, ethers.ZeroHash, [])).to.be.revertedWithCustomError(anchor, "UnknownBatch");
  });

  it("MA-09 only the owner manages analysts", async () => {
    await expect(anchor.connect(outsider).setAnalyst(outsider.address, true)).to.be.revertedWithCustomError(anchor, "NotOwner");
  });

  // Prints the gas-per-alert table used in the paper. Run:  npx hardhat test test/MerkleAnchor.test.js
  it("MA-10 gas per alert falls as the batch grows (table for the paper)", async () => {
    const sizes = [1, 10, 50, 100, 500, 1000];
    const rows = [];
    for (const n of sizes) {
      const batch = buildBatch(alerts(n).map((a, i) => ({ ...a, txHash: ethers.keccak256(ethers.toUtf8Bytes(`g-${n}-${i}`)) })));
      const rcpt = await (await anchor.anchorBatch(batch.root, batch.count)).wait();
      const proofLen = Math.max(...batch.proofs.map((p) => p.proof.length));
      rows.push({ alerts_in_batch: n, anchor_gas: Number(rcpt.gasUsed), gas_per_alert: Math.round(Number(rcpt.gasUsed) / n), proof_hashes: proofLen });
    }
    console.table(rows);
    // The single batch cost is roughly flat, so cost per alert must shrink with batch size.
    expect(rows[rows.length - 1].gas_per_alert).to.be.lessThan(rows[0].gas_per_alert / 10);
  });
});
