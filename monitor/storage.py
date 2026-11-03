"""SQLite persistence. Every query is parameterised (no string-built SQL)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from monitor.models import Alert, Tx

_SCHEMA = """
CREATE TABLE IF NOT EXISTS txs (
    tx_hash TEXT PRIMARY KEY,
    block_number INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    value_eth REAL NOT NULL,
    nonce INTEGER NOT NULL,
    gas_price_gwei REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_txs_ts ON txs(timestamp);
CREATE TABLE IF NOT EXISTS alerts (
    tx_hash TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    reason_mask INTEGER NOT NULL,
    explanation TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    anchored_tx TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

_TX_COLS = "tx_hash, block_number, timestamp, sender, receiver, value_eth, nonce, gas_price_gwei"
_ALERT_COLS = "tx_hash, subject, risk_score, reason_mask, explanation, created_at, status, anchored_tx"


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path))
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    # --- transactions -------------------------------------------------
    def insert_txs(self, txs: Iterable[Tx]) -> int:
        rows = [
            (t.tx_hash, t.block_number, t.timestamp, t.sender, t.receiver, t.value_eth, t.nonce, t.gas_price_gwei)
            for t in txs
        ]
        before = self._db.total_changes
        with self._db:
            self._db.executemany(f"INSERT OR IGNORE INTO txs ({_TX_COLS}) VALUES (?,?,?,?,?,?,?,?)", rows)
        return self._db.total_changes - before

    def txs_since(self, since_ts: int) -> list[Tx]:
        cur = self._db.execute(
            f"SELECT {_TX_COLS} FROM txs WHERE timestamp >= ? ORDER BY timestamp, tx_hash", (since_ts,)
        )
        return [Tx(*row) for row in cur]

    def latest_timestamp(self) -> int | None:
        row = self._db.execute("SELECT MAX(timestamp) FROM txs").fetchone()
        return row[0]

    def count_txs(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM txs").fetchone()[0]

    # --- alerts ---------------------------------------------------------
    def save_alert(self, a: Alert) -> bool:
        """Insert an alert once per transaction. Returns False if it already existed."""
        before = self._db.total_changes
        with self._db:
            self._db.execute(
                f"INSERT OR IGNORE INTO alerts ({_ALERT_COLS}) VALUES (?,?,?,?,?,?,?,?)",
                (a.tx_hash, a.subject, a.risk_score, a.reason_mask, a.explanation, a.created_at, a.status, a.anchored_tx),
            )
        return self._db.total_changes > before

    def list_alerts(self, limit: int = 100, min_score: int = 0) -> list[Alert]:
        cur = self._db.execute(
            f"SELECT {_ALERT_COLS} FROM alerts WHERE risk_score >= ? "
            "ORDER BY risk_score DESC, created_at DESC LIMIT ?",
            (min_score, limit),
        )
        return [Alert(*row) for row in cur]

    def count_alerts(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    # --- key/value (ingestion cursor) ----------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._db:
            self._db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
