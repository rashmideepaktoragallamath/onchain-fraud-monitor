const { expect } = require("chai");
const { ethers } = require("hardhat");

// Reason-code bits (kept in sync with monitor/reasons.py)
const LARGE_VALUE = 1 << 0;
const HIGH_VELOCITY = 1 << 1;
const STRUCTURING = 1 << 2;

const Status = { Open: 0, Reviewed: 1, Escalated: 2, Dismissed: 3 };
const txHash = (n) => ethers.keccak256(ethers.toUtf8Bytes(`tx-${n}`));
const tag = (s) => ethers.encodeBytes32String(s);

describe("RiskRegistry", () => {
  let registry, owner, analyst, outsider, subject;

  beforeEach(async () => {
    [owner, analyst, outsider, subject] = await ethers.getSigners();
    registry = await ethers.deployContract("RiskRegistry");
    await registry.setAnalyst(analyst.address, true);
  });

  describe("deployment", () => {
    it("TC-01 sets deployer as owner and analyst", async () => {
      expect(await registry.owner()).to.equal(owner.address);
      expect(await registry.isAnalyst(owner.address)).to.equal(true);
      expect(await registry.alertCount()).to.equal(0);
    });
  });

  describe("raising alerts", () => {
    it("TC-02 analyst anchors an alert and an event is emitted", async () => {
      await expect(
        registry.connect(analyst).raiseAlert(txHash(1), subject.address, 87, LARGE_VALUE | HIGH_VELOCITY)
      )
        .to.emit(registry, "AlertRaised")
        .withArgs(0, txHash(1), subject.address, 87, LARGE_VALUE | HIGH_VELOCITY);

      const a = await registry.getAlert(0);
      expect(a.txHash).to.equal(txHash(1));
      expect(a.subject).to.equal(subject.address);
      expect(a.riskScore).to.equal(87);
      expect(a.reasonMask).to.equal(LARGE_VALUE | HIGH_VELOCITY);
      expect(a.status).to.equal(Status.Open);
      expect(a.raisedBy).to.equal(analyst.address);
      expect(await registry.alertCount()).to.equal(1);
    });

    it("TC-03 looks an alert up by transaction hash", async () => {
      await registry.connect(analyst).raiseAlert(txHash(1), subject.address, 50, STRUCTURING);
      await registry.connect(analyst).raiseAlert(txHash(2), subject.address, 60, STRUCTURING);
      const [found, id] = await registry.alertIdOf(txHash(2));
      expect(found).to.equal(true);
      expect(id).to.equal(1n);
      const [missing] = await registry.alertIdOf(txHash(99));
      expect(missing).to.equal(false);
    });

    it("TC-04 NEGATIVE: non-analyst cannot raise an alert", async () => {
      await expect(
        registry.connect(outsider).raiseAlert(txHash(1), subject.address, 70, LARGE_VALUE)
      ).to.be.revertedWithCustomError(registry, "NotAnalyst");
    });

    it("TC-05 NEGATIVE: the same transaction cannot be reported twice", async () => {
      await registry.connect(analyst).raiseAlert(txHash(1), subject.address, 70, LARGE_VALUE);
      await expect(
        registry.connect(analyst).raiseAlert(txHash(1), subject.address, 90, LARGE_VALUE)
      )
        .to.be.revertedWithCustomError(registry, "AlreadyReported")
        .withArgs(txHash(1), 0);
    });

    it("TC-06 NEGATIVE: rejects invalid score, empty reasons, zero hash, zero address", async () => {
      const r = registry.connect(analyst);
      await expect(r.raiseAlert(txHash(1), subject.address, 0, LARGE_VALUE))
        .to.be.revertedWithCustomError(registry, "InvalidRiskScore")
        .withArgs(0);
      await expect(r.raiseAlert(txHash(1), subject.address, 101, LARGE_VALUE))
        .to.be.revertedWithCustomError(registry, "InvalidRiskScore")
        .withArgs(101);
      await expect(r.raiseAlert(txHash(1), subject.address, 50, 0)).to.be.revertedWithCustomError(
        registry,
        "NoReasonGiven"
      );
      await expect(
        r.raiseAlert(ethers.ZeroHash, subject.address, 50, LARGE_VALUE)
      ).to.be.revertedWithCustomError(registry, "EmptyTxHash");
      await expect(
        r.raiseAlert(txHash(1), ethers.ZeroAddress, 50, LARGE_VALUE)
      ).to.be.revertedWithCustomError(registry, "ZeroAddress");
    });
  });

  describe("review workflow", () => {
    beforeEach(async () => {
      await registry.connect(analyst).raiseAlert(txHash(1), subject.address, 80, LARGE_VALUE);
    });

    it("TC-07 Open -> Reviewed -> Escalated emits events", async () => {
      await expect(registry.connect(analyst).updateStatus(0, Status.Reviewed))
        .to.emit(registry, "AlertStatusChanged")
        .withArgs(0, Status.Open, Status.Reviewed, analyst.address);
      await expect(registry.connect(analyst).updateStatus(0, Status.Escalated))
        .to.emit(registry, "AlertStatusChanged")
        .withArgs(0, Status.Reviewed, Status.Escalated, analyst.address);
      expect((await registry.getAlert(0)).status).to.equal(Status.Escalated);
    });

    it("TC-08 NEGATIVE: final states cannot be changed", async () => {
      await registry.connect(analyst).updateStatus(0, Status.Dismissed);
      await expect(registry.connect(analyst).updateStatus(0, Status.Open))
        .to.be.revertedWithCustomError(registry, "InvalidTransition")
        .withArgs(Status.Dismissed, Status.Open);
      await expect(registry.connect(analyst).updateStatus(0, Status.Escalated))
        .to.be.revertedWithCustomError(registry, "InvalidTransition")
        .withArgs(Status.Dismissed, Status.Escalated);
    });

    it("TC-09 NEGATIVE: cannot move back to Open or stay in the same state", async () => {
      await registry.connect(analyst).updateStatus(0, Status.Reviewed);
      await expect(
        registry.connect(analyst).updateStatus(0, Status.Open)
      ).to.be.revertedWithCustomError(registry, "InvalidTransition");
      await expect(
        registry.connect(analyst).updateStatus(0, Status.Reviewed)
      ).to.be.revertedWithCustomError(registry, "InvalidTransition");
    });

    it("TC-10 NEGATIVE: outsider cannot update; unknown alert id reverts", async () => {
      await expect(
        registry.connect(outsider).updateStatus(0, Status.Reviewed)
      ).to.be.revertedWithCustomError(registry, "NotAnalyst");
      await expect(
        registry.connect(analyst).updateStatus(5, Status.Reviewed)
      ).to.be.revertedWithCustomError(registry, "UnknownAlert");
      await expect(registry.getAlert(5)).to.be.revertedWithCustomError(registry, "UnknownAlert");
    });
  });

  describe("watchlist", () => {
    it("TC-11 owner adds and removes a watchlisted address", async () => {
      await expect(registry.addToWatchlist(subject.address, tag("SANCTIONED")))
        .to.emit(registry, "WatchlistUpdated")
        .withArgs(subject.address, true, tag("SANCTIONED"));
      expect(await registry.isWatchlisted(subject.address)).to.equal(true);

      await registry.removeFromWatchlist(subject.address);
      expect(await registry.isWatchlisted(subject.address)).to.equal(false);
    });

    it("TC-12 NEGATIVE: analyst (non-owner) cannot edit watchlist; empty reason rejected", async () => {
      await expect(
        registry.connect(analyst).addToWatchlist(subject.address, tag("X"))
      ).to.be.revertedWithCustomError(registry, "NotOwner");
      await expect(
        registry.addToWatchlist(subject.address, ethers.ZeroHash)
      ).to.be.revertedWithCustomError(registry, "EmptyReason");
    });
  });

  describe("access control", () => {
    it("TC-13 revoked analyst loses write access", async () => {
      await registry.setAnalyst(analyst.address, false);
      await expect(
        registry.connect(analyst).raiseAlert(txHash(1), subject.address, 70, LARGE_VALUE)
      ).to.be.revertedWithCustomError(registry, "NotAnalyst");
    });

    it("TC-14 two-step ownership transfer", async () => {
      await registry.transferOwnership(outsider.address);
      expect(await registry.owner()).to.equal(owner.address); // not yet
      await expect(registry.connect(analyst).acceptOwnership()).to.be.revertedWithCustomError(
        registry,
        "NotPendingOwner"
      );
      await registry.connect(outsider).acceptOwnership();
      expect(await registry.owner()).to.equal(outsider.address);
      expect(await registry.pendingOwner()).to.equal(ethers.ZeroAddress);
      await expect(registry.setAnalyst(analyst.address, true)).to.be.revertedWithCustomError(
        registry,
        "NotOwner"
      ); // old owner is locked out
    });

    it("TC-15 NEGATIVE: only owner manages analysts; zero address rejected", async () => {
      await expect(
        registry.connect(analyst).setAnalyst(outsider.address, true)
      ).to.be.revertedWithCustomError(registry, "NotOwner");
      await expect(registry.setAnalyst(ethers.ZeroAddress, true)).to.be.revertedWithCustomError(
        registry,
        "ZeroAddress"
      );
    });
  });
});
