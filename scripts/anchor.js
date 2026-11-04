// Anchor queued cases on the RiskRegistry contract (Sepolia) and record the proof.
//
//   dashboard  -> data/outbox.json   (cases the analyst queued)
//   this script ->  RiskRegistry     (raiseAlert / updateStatus, signed by DEPLOYER_PRIVATE_KEY)
//   this script -> data/anchored.json (alert id, tx hash, gas used) -> shown in the dashboard
//
// Run:  npm run anchor
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const { reconcile } = require("./anchor-lib");

const DATA = path.join(__dirname, "..", "data");
const OUTBOX = path.join(DATA, "outbox.json");
const ANCHORED = path.join(DATA, "anchored.json");

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

async function main() {
  const network = hre.network.name;
  const deployment = readJson(path.join(__dirname, "..", "deployments", `${network}.json`), null);
  if (!deployment || !deployment.address) {
    throw new Error(`No deployments/${network}.json. Deploy first: npm run deploy:${network}`);
  }

  const outbox = readJson(OUTBOX, { items: [] });
  const items = Array.isArray(outbox.items) ? outbox.items : [];
  if (items.length === 0) {
    console.log("Nothing queued. In the dashboard, open a case and click 'Queue for on-chain anchoring'.");
    return;
  }

  const [signer] = await hre.ethers.getSigners();
  const contract = await hre.ethers.getContractAt("RiskRegistry", deployment.address, signer);
  console.log(`Network:  ${network}`);
  console.log(`Contract: ${deployment.address}`);
  console.log(`Signer:   ${signer.address}`);
  console.log(`Queued:   ${items.length} case(s)\n`);

  const results = await reconcile(contract, items, readJson(ANCHORED, {}));
  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(ANCHORED, JSON.stringify(results, null, 2));
  console.log(`\nSaved ${path.relative(process.cwd(), ANCHORED)}. Refresh the dashboard to see the proof.`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
