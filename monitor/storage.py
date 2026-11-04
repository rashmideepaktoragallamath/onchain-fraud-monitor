"""SQLite persistence. Every query is parameterised (no user data is ever put into SQL text)."""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from monitor.models import ALLOWED_TRANSITIONS, STATUSES, Alert, CaseState, CaseSummary, Tx

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
    anchored_tx TEXT,
    chain_alert_id INTEGER,
    chain_status TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_subject ON alerts(subject);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cases (
    subject TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'open',
    queued INTEGER NOT NULL DEFAULT 0,
    alert_id INTEGER,
    anchor_tx TEXT,
    anchor_gas INTEGER,
    note TEXT,
    updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_txs_sender ON txs(sender);
CREATE INDEX IF NOT EXISTS idx_txs_receiver ON txs(receiver);
"""

# Columns added after the first release; older database files are upgraded in place.
_MIGRATIONS = {"chain_alert_id": "INTEGER", "chain_status": "TEXT"}

_TX_COLS = "tx_hash, block_number, timestamp, sender, receiver, value_eth, nonce, gas_price_gwei"
_ALERT_COLS = (
    "tx_hash, subject, risk_score, reason_mask, explanation, created_at, status, "
    "anchored_tx, chain_alert_id, chain_status"
)


def _case_status(counts: dict[str, int]) -> str:
    for status in ("open", "escalated", "reviewed"):
        if counts.get(status):
            return status
    return "dismissed"


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        in_memory = str(path) == ":memory:"
        if not in_memory:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path))
        if not in_memory:
            # WAL lets the dashboard read while the live monitor writes.
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        existing = {row[1] for row in self._db.execute("PRAGMA table_info(alerts)")}
        with self._db:
            for column, ctype in _MIGRATIONS.items():
                if column not in existing:
                    self._db.execute(f"ALTER TABLE alerts ADD COLUMN {column} {ctype}")  # constants only

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

    def get_tx(self, tx_hash: str) -> Tx | None:
        row = self._db.execute(f"SELECT {_TX_COLS} FROM txs WHERE tx_hash = ?", (tx_hash,)).fetchone()
        return Tx(*row) if row else None

    def latest_timestamp(self) -> int | None:
        return self._db.execute("SELECT MAX(timestamp) FROM txs").fetchone()[0]

    def count_txs(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM txs").fetchone()[0]

    # --- alerts ---------------------------------------------------------
    def save_alert(self, a: Alert) -> bool:
        """Insert an alert once per transaction. Returns False if it already existed."""
        before = self._db.total_changes
        with self._db:
            self._db.execute(
                f"INSERT OR IGNORE INTO alerts ({_ALERT_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    a.tx_hash, a.subject, a.risk_score, a.reason_mask, a.explanation, a.created_at,
                    a.status, a.anchored_tx, a.chain_alert_id, a.chain_status,
                ),
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

    def reason_mask_counts(self) -> dict[int, int]:
        cur = self._db.execute("SELECT reason_mask, COUNT(*) FROM alerts GROUP BY reason_mask")
        return {mask: n for mask, n in cur}

    # --- cases (alerts grouped by wallet) ------------------------------
    def list_cases(
        self, *, status: str | None = None, min_score: int = 0, search: str | None = None, limit: int = 200
    ) -> list[CaseSummary]:
        cur = self._db.execute(
            "SELECT a.subject, a.risk_score, a.reason_mask, a.status, a.chain_alert_id, a.anchored_tx, t.timestamp "
            "FROM alerts a LEFT JOIN txs t ON t.tx_hash = a.tx_hash"
        )
        groups: dict[str, list[tuple]] = defaultdict(list)
        for row in cur:
            groups[row[0]].append(row)

        cases: list[CaseSummary] = []
        needle = search.lower() if search else None
        for wallet, rows in groups.items():
            if needle and needle not in wallet:
                continue
            counts: dict[str, int] = defaultdict(int)
            mask = 0
            for _, _, reason_mask, st, _, _, _ in rows:
                counts[st] += 1
                mask |= reason_mask
            stamps = [r[6] for r in rows if r[6] is not None]
            anchors = [r[5] for r in rows if r[4] is not None]
            case = CaseSummary(
                wallet=wallet,
                alert_count=len(rows),
                max_score=max(r[1] for r in rows),
                reason_mask=mask,
                status=_case_status(counts),
                first_seen=min(stamps) if stamps else None,
                last_seen=max(stamps) if stamps else None,
                anchored=any(r[4] is not None for r in rows),
                anchor_tx=anchors[0] if anchors else None,
            )
            if case.max_score < min_score or (status and case.status != status):
                continue
            cases.append(case)
        cases.sort(key=lambda c: (-c.max_score, -(c.last_seen or 0), c.wallet))
        return cases[:limit]

    def get_case(self, wallet: str) -> CaseSummary | None:
        found = self.list_cases(search=wallet, limit=10**6)
        return next((c for c in found if c.wallet == wallet), None)

    def case_alerts(self, wallet: str, limit: int = 25) -> list[tuple[Alert, Tx | None]]:
        cur = self._db.execute(
            f"SELECT {', '.join('a.' + c.strip() for c in _ALERT_COLS.split(','))}, "
            "t.block_number, t.timestamp, t.sender, t.receiver, t.value_eth, t.nonce, t.gas_price_gwei "
            "FROM alerts a LEFT JOIN txs t ON t.tx_hash = a.tx_hash "
            "WHERE a.subject = ? ORDER BY a.risk_score DESC, t.timestamp DESC LIMIT ?",
            (wallet, limit),
        )
        n = len(_ALERT_COLS.split(","))
        out: list[tuple[Alert, Tx | None]] = []
        for row in cur:
            alert = Alert(*row[:n])
            tx = Tx(alert.tx_hash, row[n], row[n + 1], row[n + 2], row[n + 3], row[n + 4], row[n + 5], row[n + 6]) \
                if row[n] is not None else None
            out.append((alert, tx))
        return out

    def update_case_status(self, wallet: str, new_status: str) -> int:
        """Move every alert of a wallet that is allowed to move to ``new_status``.

        Uses the same transition table as the smart contract, so local review decisions can
        always be replayed on-chain. Returns the number of alerts changed.
        """
        if new_status not in STATUSES or new_status == "open":
            raise ValueError(f"invalid target status: {new_status!r}")
        sources = [s for s in STATUSES if new_status in ALLOWED_TRANSITIONS[s]]
        marks = ",".join("?" * len(sources))
        with self._db:
            cur = self._db.execute(
                f"UPDATE alerts SET status = ? WHERE subject = ? AND status IN ({marks})",  # marks = "?,?" only
                (new_status, wallet, *sources),
            )
        return cur.rowcount

    # --- on-chain anchoring --------------------------------------------
    def pending_anchor(self, min_score: int, limit: int) -> list[Alert]:
        """Best (highest-score) not-yet-anchored alert per wallet; skips dismissed alerts and
        wallets that already have one alert anchored."""
        cur = self._db.execute(
            f"SELECT {_ALERT_COLS} FROM alerts a "
            "WHERE a.risk_score >= ? AND a.chain_alert_id IS NULL AND a.status != 'dismissed' "
            "AND NOT EXISTS (SELECT 1 FROM alerts b WHERE b.subject = a.subject AND b.chain_alert_id IS NOT NULL) "
            "ORDER BY a.risk_score DESC, a.created_at DESC, a.tx_hash",
            (min_score,),
        )
        picked: dict[str, Alert] = {}
        for row in cur:
            alert = Alert(*row)
            picked.setdefault(alert.subject, alert)
            if len(picked) >= limit:
                break
        return list(picked.values())

    def mark_anchored(self, tx_hash: str, chain_alert_id: int, anchor_tx: str | None) -> None:
        with self._db:
            self._db.execute(
                "UPDATE alerts SET chain_alert_id = ?, anchored_tx = COALESCE(?, anchored_tx), "
                "chain_status = 'open' WHERE tx_hash = ?",
                (chain_alert_id, anchor_tx, tx_hash),
            )

    def needing_status_sync(self) -> list[Alert]:
        cur = self._db.execute(
            f"SELECT {_ALERT_COLS} FROM alerts WHERE chain_alert_id IS NOT NULL AND chain_status != status "
            "ORDER BY chain_alert_id"
        )
        return [Alert(*row) for row in cur]

    def mark_chain_status(self, tx_hash: str, status: str) -> None:
        with self._db:
            self._db.execute("UPDATE alerts SET chain_status = ? WHERE tx_hash = ?", (status, tx_hash))

    def count_anchored(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM alerts WHERE chain_alert_id IS NOT NULL").fetchone()[0]

    # --- key/value (ingestion cursor) ----------------------------------
    def get_meta(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._db:
            self._db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    # --- dashboard queries ----------------------------------------------
    def alerts_with_time(self, min_score: int = 0) -> list[tuple[Alert, int]]:
        """Every alert paired with the timestamp of the transaction it is about."""
        cols = ", ".join(f"a.{c.strip()}" for c in _ALERT_COLS.split(","))
        cur = self._db.execute(
            f"SELECT {cols}, t.timestamp FROM alerts a JOIN txs t ON t.tx_hash = a.tx_hash "
            "WHERE a.risk_score >= ?",
            (min_score,),
        )
        return [(Alert(*row[:-1]), row[-1]) for row in cur]

    def alerts_for_subject(self, subject: str, limit: int = 25) -> list[tuple[Alert, Tx]]:
        a_cols = ", ".join(f"a.{c.strip()}" for c in _ALERT_COLS.split(","))
        t_cols = ", ".join(f"t.{c.strip()}" for c in _TX_COLS.split(","))
        n_alert = len(_ALERT_COLS.split(","))
        cur = self._db.execute(
            f"SELECT {a_cols}, {t_cols} FROM alerts a JOIN txs t ON t.tx_hash = a.tx_hash "
            "WHERE a.subject = ? ORDER BY a.risk_score DESC, t.timestamp DESC LIMIT ?",
            (subject, limit),
        )
        return [(Alert(*row[:n_alert]), Tx(*row[n_alert:])) for row in cur]

    def txs_for_wallet(self, wallet: str, limit: int = 15) -> list[Tx]:
        cur = self._db.execute(
            f"SELECT {_TX_COLS} FROM txs WHERE sender = ? OR receiver = ? ORDER BY timestamp DESC LIMIT ?",
            (wallet, wallet, limit),
        )
        return [Tx(*row) for row in cur]

    def timeline(self, buckets: int = 24) -> list[dict]:
        """Transactions and alerts per equal time bucket across the stored data."""
        lo, hi = self._db.execute("SELECT MIN(timestamp), MAX(timestamp) FROM txs").fetchone()
        if lo is None:
            return []
        size = max(60, -(-(hi - lo + 1) // buckets))  # ceil division, at least a minute
        n_tx = dict(self._db.execute("SELECT (timestamp - ?) / ?, COUNT(*) FROM txs GROUP BY 1", (lo, size)))
        n_alert = dict(
            self._db.execute(
                "SELECT (t.timestamp - ?) / ?, COUNT(*) FROM alerts a JOIN txs t ON t.tx_hash = a.tx_hash GROUP BY 1",
                (lo, size),
            )
        )
        return [{"t": lo + i * size, "txs": n_tx.get(i, 0), "alerts": n_alert.get(i, 0)} for i in range(buckets)]

    # --- case workflow state ---------------------------------------------
    @staticmethod
    def _state(row: tuple) -> CaseState:
        subject, status, queued, alert_id, anchor_tx, anchor_gas, note, updated_at = row
        return CaseState(subject, status, bool(queued), alert_id, anchor_tx, anchor_gas, note, updated_at)

    _STATE_COLS = "subject, status, queued, alert_id, anchor_tx, anchor_gas, note, updated_at"

    def get_case_state(self, subject: str) -> CaseState:
        row = self._db.execute(f"SELECT {self._STATE_COLS} FROM cases WHERE subject = ?", (subject,)).fetchone()
        return self._state(row) if row else CaseState(subject)

    def all_case_states(self) -> dict[str, CaseState]:
        cur = self._db.execute(f"SELECT {self._STATE_COLS} FROM cases")
        return {row[0]: self._state(row) for row in cur}

    def queued_subjects(self) -> list[str]:
        return [r[0] for r in self._db.execute("SELECT subject FROM cases WHERE queued = 1 ORDER BY subject")]

    def _ensure_case(self, subject: str) -> None:
        self._db.execute("INSERT OR IGNORE INTO cases (subject) VALUES (?)", (subject,))

    def set_case_status(self, subject: str, status: str, note: str | None, ts: int, *, queue_sync: bool) -> None:
        with self._db:
            self._ensure_case(subject)
            self._db.execute(
                "UPDATE cases SET status = ?, note = COALESCE(?, note), updated_at = ?, "
                "queued = CASE WHEN ? THEN 1 ELSE queued END WHERE subject = ?",
                (status, note, ts, int(queue_sync), subject),
            )

    def set_case_queued(self, subject: str, queued: bool, ts: int) -> None:
        with self._db:
            self._ensure_case(subject)
            self._db.execute("UPDATE cases SET queued = ?, updated_at = ? WHERE subject = ?", (int(queued), ts, subject))

    def set_case_anchor(self, subject: str, alert_id: int, anchor_tx: str | None, anchor_gas: int | None) -> None:
        with self._db:
            self._ensure_case(subject)
            self._db.execute(
                "UPDATE cases SET alert_id = ?, anchor_tx = COALESCE(?, anchor_tx), "
                "anchor_gas = COALESCE(?, anchor_gas), queued = 0 WHERE subject = ?",
                (alert_id, anchor_tx, anchor_gas, subject),
            )
