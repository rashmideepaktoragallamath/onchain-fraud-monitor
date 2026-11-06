# Fraud Detection & Transaction Monitoring Layer for On-Chain Finance

Mini project for **CS2614 Fundamentals of Blockchain**, School of Computer Science and Engineering, RV University, Bengaluru.

**Team:** Rashmi DT (USN0362), Bhoomika P (USN0090), Anita (USN0055)
**Guide:** Cynthia J

A prototype that watches live Ethereum transactions, scores wallets from 0 to 100 with named, explainable reasons, lets an analyst review the cases, and anchors alerts and review decisions in a tamper-evident smart contract on the Sepolia testnet.

- Demo video: https://drive.google.com/file/d/1XM5nRSkE7Bwcg5PfBr3fC0w2XQcKWQ9K/view?usp=sharing
- Contract on Sepolia: [`0x1D5a2F95057EFbbb596b9E14A7dAD3975190924b`](https://sepolia.etherscan.io/address/0x1D5a2F95057EFbbb596b9E14A7dAD3975190924b)
- Report, slides and IEEE paper: see the [`docs`](docs) folder

## The problem

Public blockchains let anyone move funds through new pseudonymous wallets, and nothing screens those transfers for money-laundering behaviour. Compliance teams review raw chain data by hand or rely on opaque scores, and the alert records they keep can be edited afterwards. This project detects suspicious patterns, explains every alert in plain language, and records alerts and decisions in a contract that nobody can silently change.

## How it works

```
Ethereum mainnet (read-only JSON-RPC)
        |
   Ingestion (Python, SQLite)
        |
   Features -> 8 rules + Isolation Forest -> noisy-OR score 0-100 + reason codes
        |
   Dashboard (one case per wallet, review workflow)
        |  analyst queues a case
   data/outbox.json -> npm run anchor (only component that signs)
        |
   RiskRegistry.sol on Sepolia  (AlertRaised, AlertStatusChanged events)
```

**Detection rules:** structuring, fan-out, fan-in, round-trip, high velocity, watchlist hit, large value, new-wallet burst, plus an Isolation Forest outlier signal. Signals combine as `score = 100 x (1 - product(1 - w_i))`, so every score decomposes into the reasons that produced it. Alerts start at a score of 50.

**Smart contract (`RiskRegistry`)**
- Roles: owner and analysts; two-step ownership transfer.
- `raiseAlert` stores a transaction hash, a wallet, a score (1-100) and a reason bitmask; one alert per transaction.
- `updateStatus` follows Open -> Reviewed / Escalated / Dismissed; Escalated and Dismissed are final.
- Custom errors and events for every action. No personal data is stored.

**Security**
- Secrets live only in `.env` (git-ignored). Use a throwaway testnet wallet.
- Mainnet access is read-only; no mainnet keys or funds are involved.
- The dashboard server binds to localhost, checks Host and Origin, needs a custom header on writes, sets a strict content-security policy, limits request sizes, and renders data as text only.
- Only the anchor script signs transactions. The web server holds no private key.

## Results

| Item | Result |
|---|---|
| Contract tests (Hardhat) | 15 of 15 pass (8 negative tests) |
| Anchoring tests | 8 of 8 pass |
| Python tests | 54 pass |
| Detector on simulated fraud | 42 of 42 injected scenarios detected |
| Alert precision (simulated) | 0.996 with exchange allowlist, 0.606 without |
| Deployment gas (Sepolia) | 6,426,712 |
| `raiseAlert` gas (Sepolia) | 683,007 (alert #0), 585,087 (alert #1) |
| `updateStatus` gas (Sepolia) | about 35,300 (derived from the fee) |
| Live mainnet run | 2,365 transfers ingested, 665 alerts raised |

The detection figures come from **simulated** fraud written alongside the rules, and the allowlist holds the simulator's own exchange addresses. They show the pipeline works as designed, not accuracy on real laundering. Live mainnet data has no ground truth and raises false positives on exchanges, which is why the dashboard labels likely exchanges and an analyst reviews every case.

## Quick start

Requirements: Python 3.10+, Node.js 18+.

```bash
# Python side
python -m venv .venv
.venv\Scripts\activate            # Windows;  macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# Contract side
npm install
```

Create `.env` from `.env.example` and fill it in (never commit `.env`):

```
SEPOLIA_RPC_URL=...          # Ethereum Sepolia RPC URL
DEPLOYER_PRIVATE_KEY=...     # throwaway testnet wallet
MAINNET_RPC_URL=...          # read-only, for live monitoring
```

### Run the tests

```bash
npx hardhat test             # 15 contract tests
npm run test:gas             # gas report
npm run test:anchor          # 8 anchoring tests
python -m pytest             # 54 Python, dashboard and security tests
python -m monitor.evaluate   # detector metrics on simulated fraud
```

### Run the dashboard

```bash
python -m monitor.serve --demo   # simulated fraud, no internet needed
python -m monitor.serve --live   # real mainnet blocks, refreshed every 12 s
python -m monitor.serve          # view the stored live database
```

Open http://127.0.0.1:8000. Alerts are grouped into one case per wallet. An analyst can mark a case reviewed, escalated or dismissed, allowlist a known exchange, and queue it for anchoring. Then, in a second terminal:

```bash
npm run anchor      # writes queued cases to RiskRegistry on Sepolia; saves alert ID, tx hash and gas
```

Refresh the dashboard to see the on-chain proof.

### Deploy your own copy of the contract

```bash
npm run deploy:sepolia      # prints the address and saves deployments/sepolia.json
```

## Project structure

```
contracts/      RiskRegistry.sol
test/           Hardhat contract tests
scripts/        deploy.js, anchor.js, anchor-lib.js and its tests
deployments/    sepolia.json (public address and ABI)
monitor/        Python engine: ingestion, rules, scoring, cases, dashboard server, web UI
monitor_tests/  Python tests
reports/        evaluation.json
docs/           report, slides, IEEE paper
data/           local databases and queue files (git-ignored), watchlist/allowlist examples
```

## Limitations

- Evaluation uses simulated fraud; thresholds are hand-chosen and uncalibrated.
- Only native ETH transfers are monitored (no ERC-20, internal or cross-chain transfers).
- The exchange allowlist is a manual file.
- Anchoring depends on one signing key.
- The contract runs on a testnet and has not had a formal audit.

## Future work

ERC-20 and internal transfers, graph features and labelled data for calibrated thresholds, batched anchoring to cut gas, multi-signature approval, deployment on a low-cost layer-2 network, and webhooks to compliance tools.