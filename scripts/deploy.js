const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log(`Network:  ${hre.network.name}`);
  console.log(`Deployer: ${deployer.address}`);

  const registry = await hre.ethers.deployContract("RiskRegistry");
  await registry.waitForDeployment();
  const address = await registry.getAddress();
  const receipt = await registry.deploymentTransaction().wait();

  console.log(`RiskRegistry deployed to: ${address}`);
  console.log(`Deployment gas used:      ${receipt.gasUsed}`);

  // Persist address + ABI so the Python backend can load them (no hand-copying).
  const artifact = await hre.artifacts.readArtifact("RiskRegistry");
  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(
    path.join(outDir, `${hre.network.name}.json`),
    JSON.stringify(
      {
        network: hre.network.name,
        address,
        deployer: deployer.address,
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        abi: artifact.abi,
      },
      null,
      2
    )
  );
  console.log(`Saved deployments/${hre.network.name}.json`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
