require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

// Secrets come from .env only (never commit it). See .env.example.
const { SEPOLIA_RPC_URL, DEPLOYER_PRIVATE_KEY, ETHERSCAN_API_KEY } = process.env;

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 } },
  },
  networks: {
    // Only registered when both values are present, so local tests never need secrets.
    ...(SEPOLIA_RPC_URL && DEPLOYER_PRIVATE_KEY
      ? { sepolia: { url: SEPOLIA_RPC_URL, accounts: [DEPLOYER_PRIVATE_KEY] } }
      : {}),
  },
  etherscan: { apiKey: ETHERSCAN_API_KEY || "" },
  gasReporter: { enabled: process.env.REPORT_GAS === "true", currency: "USD" },
};
