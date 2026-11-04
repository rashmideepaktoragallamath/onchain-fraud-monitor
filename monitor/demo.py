"""Offline demo data: simulated activity with injected fraud, in its own database."""

from __future__ import annotations

import time
from pathlib import Path

from monitor.config import DetectionConfig, write_json_atomic
from monitor.models import Alert
from monitor.pipeline import analyze
from monitor.simulator import SimResult, generate
from monitor.storage import Store


def load_demo_data(store: Store, now: int | None = None) -> SimResult:
    """Insert simulated transactions timed to end 'now'."""
    sim = generate(end_ts=int(time.time()) if now is None else now)
    store.insert_txs(sim.txs)
    return sim


def rebuild_demo(db_path: Path, watchlist_path: Path, allowlist_path: Path, cfg: DetectionConfig) -> list[Alert]:
    """Recreate the demo database from scratch and score it.

    The allowlist starts EMPTY on purpose: the simulated exchange wallets then show up as
    cases, so the analyst can see the false-positive problem and fix it with one click.
    """
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)

    store = Store(db_path)
    try:
        sim = load_demo_data(store)
        write_json_atomic(watchlist_path, {"addresses": sorted(sim.watchlist)})
        write_json_atomic(allowlist_path, {"addresses": []})
        return analyze(store, cfg, sim.watchlist, frozenset())
    finally:
        store.close()
