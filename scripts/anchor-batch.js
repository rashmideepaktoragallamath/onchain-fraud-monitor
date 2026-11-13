// Anchor every queued case as ONE Merkle batch on MerkleAnchor, and save a proof per alert.
//
//   data/outbox.json -> this script -> MerkleAnchor.anchorBatch(root)   (1 transaction)
//                                   -> data/batch_proofs.json           (a proof for each alert)
//
// Run:  npm run anchor:batch        (deploy first: npm run deploy:batch)
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const { validateItem } = require("./anchor-lib");
const { buildBatch } = require("./merkle-lib");

const DATA = path.join(__dirname, "..", "data");

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

async function main() {
  const network = hre.network.name;
  const deployment = readJson(path.join(__dirname, "..", "deployments", `${network}-merkle.json`), null);
  if (!deployment) throw new Error(`No deployments/${network}-merkle.json. Run: npm run deploy:batch`);

  const outbox = readJson(path.join(DATA, "outbox.json"), { items: [] });
  const alerts = [];
  for (const item of Array.isArray(outbox.items) ? outbox.items : []) {
    try {
      const v = validateItem(item);
      alerts.push({ txHash: v.txHash, subject: v.subject, score: v.score, mask: v.mask });
    } catch (err) {
      console.log(`skipped an invalid queued item: ${err.message}`);
    }
  }
  if (alerts.length === 0) {
    console.log("Nothing queued. Queue cases in the dashboard first.");
    return;
  }

  const batch = buildBatch(alerts);
  const [signer] = await hre.ethers.getSigners();
  const contract = await hre.ethers.getContractAt("MerkleAnchor", deployment.address, signer);
  console.log(`Network: ${network}\nContract: ${deployment.address}\nSigner: ${signer.address}`);
  console.log(`Alerts in batch: ${batch.count}\nMerkle root: ${batch.root}`);

  const tx = await contract.anchorBatch(batch.root, batch.count);
  const receipt = await tx.wait();
  const batchId = (await contract.batchCount()) - 1n;
  console.log(`Anchored as batch #${batchId} in tx ${receipt.hash}`);
  console.log(`Gas used: ${receipt.gasUsed} for ${batch.count} alert(s) = ${Math.round(Number(receipt.gasUsed) / batch.count)} gas per alert`);

  const out = path.join(DATA, "batch_proofs.json");
  const existing = readJson(out, { batches: [] });
  existing.batches.push({
    batchId: batchId.toString(),
    root: batch.root,
    count: batch.count,
    txHash: receipt.hash,
    gasUsed: receipt.gasUsed.toString(),
    proofs: batch.proofs,
  });
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(out, JSON.stringify(existing, null, 2));
  console.log(`Saved ${path.relative(process.cwd(), out)} (keep it: it is the proof for each alert)`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
