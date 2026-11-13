const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const c = await hre.ethers.deployContract("MerkleAnchor");
  await c.waitForDeployment();
  const address = await c.getAddress();
  const receipt = await c.deploymentTransaction().wait();
  console.log(`MerkleAnchor deployed to: ${address}`);
  console.log(`Deployment gas used:      ${receipt.gasUsed}`);

  const artifact = await hre.artifacts.readArtifact("MerkleAnchor");
  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(
    path.join(outDir, `${hre.network.name}-merkle.json`),
    JSON.stringify({ network: hre.network.name, address, deployer: deployer.address, txHash: receipt.hash, blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed.toString(), abi: artifact.abi }, null, 2)
  );
  console.log(`Saved deployments/${hre.network.name}-merkle.json`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
