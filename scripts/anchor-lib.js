"use strict";
// Pure logic for anchoring cases on the RiskRegistry contract. No Hardhat import here, so it
// can be unit-tested with a fake contract (see anchor-lib.test.js).

const MAX_PER_RUN = 10; // cap per run so a test wallet's ETH is never drained by accident

const STATUS_INDEX = { open: 0, reviewed: 1, escalated: 2, dismissed: 3 }; // = Solidity enum order
const STATUS_NAME = Object.keys(STATUS_INDEX);
// Same table as RiskRegistry.updateStatus: Escalated and Dismissed are final.
const ALLOWED = { 0: [1, 2, 3], 1: [2, 3], 2: [], 3: [] };

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HASH_RE = /^0x[0-9a-fA-F]{64}$/;

/** Validate one outbox item (the file is untrusted input). Throws with the reason. */
function validateItem(item) {
  if (!item || typeof item !== "object") throw new Error("not an object");
  const { subject, tx_hash: txHash, risk_score: score, reason_mask: mask, status } = item;
  if (!ADDRESS_RE.test(subject)) throw new Error("bad subject address");
  if (!HASH_RE.test(txHash)) throw new Error("bad tx hash");
  if (!Number.isInteger(score) || score < 1 || score > 100) throw new Error("risk score must be 1-100");
  if (!Number.isInteger(mask) || mask < 1 || mask > 0xffff) throw new Error("reason mask must fit in 16 bits");
  if (!(status in STATUS_INDEX)) throw new Error("unknown status");
  return { subject: subject.toLowerCase(), txHash, score, mask, status };
}

/**
 * Bring the chain in line with the outbox, idempotently:
 *   1. anchor the case's top alert if its transaction is not on-chain yet;
 *   2. move the on-chain status to the analyst's decision when the contract allows it.
 * Returns the updated anchored.json content (keyed by wallet).
 */
async function reconcile(contract, items, previous = {}, log = console.log) {
  const results = { ...previous };

  for (const raw of items.slice(0, MAX_PER_RUN)) {
    let v;
    try {
      v = validateItem(raw);
    } catch (err) {
      log(`skip invalid item: ${err.message}`);
      continue;
    }

    const rec = { ...(results[v.subject] || {}) };
    const [found, existingId] = await contract.alertIdOf(v.txHash);
    let alertId;

    if (found) {
      alertId = Number(existingId);
      log(`${v.subject}: already on-chain as alert #${alertId}`);
    } else {
      const receipt = await (await contract.raiseAlert(v.txHash, v.subject, v.score, v.mask)).wait();
      alertId = Number((await contract.alertIdOf(v.txHash))[1]);
      rec.anchorTx = receipt.hash;
      rec.gasUsed = receipt.gasUsed.toString();
      log(`${v.subject}: anchored as alert #${alertId} (gas ${rec.gasUsed}, tx ${receipt.hash})`);
    }
    rec.alertId = alertId;

    let onchain = Number((await contract.getAlert(alertId)).status);
    const wanted = STATUS_INDEX[v.status];
    if (wanted !== onchain) {
      if (ALLOWED[onchain].includes(wanted)) {
        const receipt = await (await contract.updateStatus(alertId, wanted)).wait();
        rec.statusTx = receipt.hash;
        onchain = wanted;
        log(`${v.subject}: status -> ${v.status} (tx ${receipt.hash})`);
      } else {
        log(`${v.subject}: cannot move ${STATUS_NAME[onchain]} -> ${v.status} on-chain; left as is`);
      }
    }
    rec.onchainStatus = STATUS_NAME[onchain];
    results[v.subject] = rec;
  }

  if (items.length > MAX_PER_RUN) log(`${items.length - MAX_PER_RUN} more item(s) wait for the next run`);
  return results;
}

module.exports = { reconcile, validateItem, MAX_PER_RUN, STATUS_INDEX };
