"""Command-line runner.

    python -m monitor.run --demo      offline: load simulated activity, score it, show alerts
    python -m monitor.run --once      live: ingest the latest blocks once, then score
    python -m monitor.run --follow    live: repeat every 12 s (one Ethereum block time)
"""

from __future__ import annotations

import argparse
import json
import logging
import time

from monitor.config import Settings, load_address_file, load_settings
from monitor.ingest import Ingestor
from monitor.models import Alert
from monitor.pipeline import analyze
from monitor.reasons import describe
from monitor.rpc import JsonRpcClient, RpcError
from monitor.scoring import severity
from monitor.simulator import generate
from monitor.storage import Store

log = logging.getLogger("monitor")
POLL_SECONDS = 12


def print_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        print("  no new alerts")
        return
    for a in sorted(alerts, key=lambda x: -x.risk_score)[:15]:
        reasons = ", ".join(describe(a.reason_mask))
        print(f"  [{severity(a.risk_score):<8}] score {a.risk_score:>3}  {a.tx_hash[:14]}…  wallet {a.subject[:10]}…  {reasons}")
    if len(alerts) > 15:
        print(f"  … and {len(alerts) - 15} more")


def run_demo(settings: Settings, store: Store) -> None:
    now = int(time.time())
    sim = generate(end_ts=now)
    store.insert_txs(sim.txs)
    # Seed the watchlist/allowlist files the first time so the demo matches the evaluation.
    for path, addrs in ((settings.watchlist_path, sim.watchlist), (settings.allowlist_path, sim.allowlist)):
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"addresses": sorted(addrs)}, indent=2), encoding="utf-8")
    alerts = analyze(store, settings.detection, load_address_file(settings.watchlist_path), load_address_file(settings.allowlist_path))
    print(f"Loaded {len(sim.txs)} simulated transactions, raised {len(alerts)} alerts:")
    print_alerts(alerts)


def cycle(settings: Settings, ingestor: Ingestor, store: Store) -> None:
    new_txs = ingestor.poll()
    alerts = analyze(store, settings.detection, load_address_file(settings.watchlist_path), load_address_file(settings.allowlist_path))
    print(f"{time.strftime('%H:%M:%S')}  +{new_txs} transfers  (db: {store.count_txs()})  +{len(alerts)} alerts")
    print_alerts(alerts)


def main() -> None:
    parser = argparse.ArgumentParser(description="On-chain transaction monitor")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--demo", action="store_true", help="offline demo with simulated data")
    mode.add_argument("--once", action="store_true", help="one live ingest + analysis cycle")
    mode.add_argument("--follow", action="store_true", help="continuous live monitoring")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    store = Store(settings.db_path)

    if args.demo:
        run_demo(settings, store)
        return

    if not settings.rpc_url:
        raise SystemExit("MAINNET_RPC_URL is not set. Copy .env.example to .env and fill it in.")
    ingestor = Ingestor(JsonRpcClient(settings.rpc_url), store)
    try:
        while True:
            try:
                cycle(settings, ingestor, store)
            except RpcError as exc:
                log.warning("RPC problem, will retry: %s", exc)
            if args.once:
                break
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
