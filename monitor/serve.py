"""Start the dashboard.

    python -m monitor.serve --demo     simulated fraud in its own database (no internet needed)
    python -m monitor.serve --live     ingest real Ethereum mainnet blocks while serving
    python -m monitor.serve            just view whatever is already in the live database

Then open http://127.0.0.1:8000
"""

from __future__ import annotations

import argparse
import json
import logging
import threading
import time

from monitor.config import ROOT, Settings, load_address_file, load_settings
from monitor.demo import rebuild_demo
from monitor.ingest import Ingestor
from monitor.pipeline import analyze
from monitor.rpc import JsonRpcClient, RpcError
from monitor.server import AppContext, create_server
from monitor.storage import Store

log = logging.getLogger("monitor.serve")
POLL_SECONDS = 12  # one Ethereum block time
ANALYSIS_LOOKBACK = 2 * 3600


class LiveWorker(threading.Thread):
    """Background loop: fetch new blocks, then re-score the recent window."""

    def __init__(self, settings: Settings, ctx: AppContext) -> None:
        super().__init__(daemon=True, name="live-ingest")
        self._settings = settings
        self._ctx = ctx
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        store = Store(self._settings.db_path)  # SQLite connections belong to one thread
        ingestor = Ingestor(JsonRpcClient(self._settings.rpc_url), store)
        while not self._stop_event.is_set():
            try:
                new_txs = ingestor.poll()
                store.set_meta("last_poll_ts", str(int(time.time())))
                alerts = analyze(
                    store,
                    self._ctx.cfg,
                    load_address_file(self._ctx.watchlist_path),
                    load_address_file(self._ctx.allowlist_path),
                    lookback_seconds=ANALYSIS_LOOKBACK,
                )
                log.info("cycle done: +%s transfers, +%s alerts", new_txs, len(alerts))
            except RpcError as exc:
                log.warning("RPC problem, will retry: %s", exc)
            except Exception:
                log.exception("unexpected error in live worker; continuing")
            self._stop_event.wait(POLL_SECONDS)
        store.close()


def load_contract_info() -> dict[str, str] | None:
    """Public deployment details (address + network) for the dashboard header."""
    path = ROOT / "deployments" / "sepolia.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {
            "address": data["address"],
            "network": data["network"],
            "explorer": "https://sepolia.etherscan.io",
        }
    except (OSError, KeyError, json.JSONDecodeError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Transaction monitoring dashboard")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--demo", action="store_true", help="simulated data, separate database")
    mode.add_argument("--live", action="store_true", help="ingest live mainnet blocks while serving")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings()
    data_dir = ROOT / "data"
    name = "demo" if args.demo else "live" if args.live else "view"

    ctx = AppContext(
        db_path=data_dir / "demo.db" if args.demo else settings.db_path,
        watchlist_path=data_dir / "demo_watchlist.json" if args.demo else settings.watchlist_path,
        allowlist_path=data_dir / "demo_allowlist.json" if args.demo else settings.allowlist_path,
        outbox_path=data_dir / "outbox.json",
        anchored_path=data_dir / "anchored.json",
        cfg=settings.detection,
        mode=name,
        port=args.port,
        contract=load_contract_info(),
    )

    worker: LiveWorker | None = None
    if args.demo:
        alerts = rebuild_demo(ctx.db_path, ctx.watchlist_path, ctx.allowlist_path, ctx.cfg)
        print(f"Demo database rebuilt: {len(alerts)} alerts from simulated activity.")
    elif args.live:
        if not settings.rpc_url:
            raise SystemExit("MAINNET_RPC_URL is not set. Copy .env.example to .env and fill it in.")
        worker = LiveWorker(settings, ctx)
        worker.start()

    server = create_server(ctx)
    print(f"\nDashboard ({name} mode): http://127.0.0.1:{args.port}   (Ctrl+C to stop)\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        if worker:
            worker.stop()
        server.server_close()


if __name__ == "__main__":
    main()
