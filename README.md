# Fraud Detection & Transaction Monitoring Layer for On-Chain Finance

Mini project — Fundamentals of Blockchain, RV University.
Team: Bhoomika P (USN0090), Anita (USN0055), Rashmi DT (USN0362)

A prototype that watches live Ethereum transactions, scores each one 0–100 with
explainable reason codes, and anchors alerts in a tamper-evident on-chain registry that
analysts review through a dashboard.

## Architecture (planned)

```
Ethereum mainnet (read-only RPC) ──► ingestion ──► features ──► rules + Isolation Forest
                                                                      │
                                                         risk score + reason codes
                                                                      │
                          dashboard ◄── API ◄── alerts DB ◄───────────┤
                                                                      ▼
                                                      RiskRegistry.sol (Sepolia)
                                                      audit trail of alerts + reviews
```

## Progress

| Step | Status |
|------|--------|
| 1. Scaffold | done |
| 2. `RiskRegistry.sol` + tests + deploy script | done (15/15 tests pass) |
| 3. Live ingestion (JSON-RPC, SQLite, cursor) | done |
| 4-5. Detection engine + explainable risk score | done (32 Python tests pass) |
| 6. API + on-chain anchoring | todo |
| 7. Dashboard | todo |
| 8. Evaluation write-up | numbers in `reports/evaluation.json` |

## Quick start (smart contract)

```bash
npm install
npx hardhat compile
npx hardhat test            # 15 test cases incl. negative (revert) tests
npm run test:gas            # gas report for the slides
cp .env.example .env        # then fill in Sepolia RPC + a throwaway wallet key
npm run deploy:sepolia      # prints the contract address; saves deployments/sepolia.json
```

## Security notes

- Secrets live in `.env` only (git-ignored). Use a throwaway testnet wallet.
- The contract uses role-based access (owner / analyst), custom errors, two-step ownership
  transfer, and stores no personal data — only hashes, public addresses, a score and a bitmask.
- Monitoring uses a read-only mainnet RPC; no mainnet keys or funds are ever involved.

## Quick start (Python monitoring engine)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows;  macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python -m pytest                 # 32 tests
python -m monitor.evaluate       # detector metrics on simulated fraud
python -m monitor.run --demo     # offline demo, no RPC needed
python -m monitor.run --once     # live: needs MAINNET_RPC_URL in .env
python -m monitor.run --follow   # live, continuous (Ctrl+C to stop)
```

`data/allowlist.json` (known exchanges/routers) and `data/watchlist.json` (flagged addresses)
are plain JSON: `{"addresses": ["0x..."]}`. See `data/watchlist.example.json`.
