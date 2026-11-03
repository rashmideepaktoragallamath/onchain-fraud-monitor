"""Behavioural feature extraction over a sliding time window.

One pass over time-ordered transactions keeps per-wallet state (deques and counters),
so cost is linear in the number of transactions.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict, deque
from typing import Iterable

import pandas as pd

from monitor.config import DetectionConfig
from monitor.models import Tx

ML_FEATURES = [
    "log_value",
    "velocity",
    "fan_out",
    "fan_in",
    "near_threshold",
    "log_nonce",
    "round_trip",
    "log_window_value",
]


class _Window:
    """Rolling per-wallet state for one direction (as sender or as receiver)."""

    __slots__ = ("events", "counterparties", "value_sum", "near_count")

    def __init__(self) -> None:
        self.events: deque[tuple[int, str, float, bool]] = deque()  # (ts, counterparty, value, near)
        self.counterparties: Counter[str] = Counter()
        self.value_sum = 0.0
        self.near_count = 0

    def add(self, ts: int, other: str, value: float, near: bool) -> None:
        self.events.append((ts, other, value, near))
        self.counterparties[other] += 1
        self.value_sum += value
        self.near_count += int(near)

    def expire(self, cutoff: int) -> None:
        while self.events and self.events[0][0] <= cutoff:
            _, other, value, near = self.events.popleft()
            self.counterparties[other] -= 1
            if self.counterparties[other] == 0:
                del self.counterparties[other]
            self.value_sum -= value
            self.near_count -= int(near)


def build_features(
    txs: Iterable[Tx],
    cfg: DetectionConfig,
    watchlist: frozenset[str] = frozenset(),
    allowlist: frozenset[str] = frozenset(),
) -> pd.DataFrame:
    """Return one feature row per transaction, indexed by ``tx_hash`` in time order."""
    ordered = sorted(txs, key=lambda t: (t.timestamp, t.tx_hash))
    window = cfg.window_seconds
    low = cfg.structuring_band * cfg.structuring_threshold_eth
    high = cfg.structuring_threshold_eth

    as_sender: dict[str, _Window] = defaultdict(_Window)
    as_receiver: dict[str, _Window] = defaultdict(_Window)
    last_pair: dict[tuple[str, str], tuple[int, float]] = {}
    rows: list[dict] = []

    for t in ordered:
        cutoff = t.timestamp - window
        near = low <= t.value_eth < high

        sw = as_sender[t.sender]
        sw.expire(cutoff)
        sw.add(t.timestamp, t.receiver, t.value_eth, near)

        rw = as_receiver[t.receiver]
        rw.expire(cutoff)
        rw.add(t.timestamp, t.sender, t.value_eth, near)

        # Round trip: did the receiver recently send us (roughly) this amount back?
        prior = last_pair.get((t.receiver, t.sender))
        round_trip = 0
        if prior and t.timestamp - prior[0] <= window and prior[1] > 0:
            ratio = t.value_eth / prior[1]
            round_trip = int(abs(1 - ratio) <= cfg.round_trip_tolerance)
        last_pair[(t.sender, t.receiver)] = (t.timestamp, t.value_eth)

        rows.append(
            {
                "tx_hash": t.tx_hash,
                "timestamp": t.timestamp,
                "sender": t.sender,
                "receiver": t.receiver,
                "value_eth": t.value_eth,
                "nonce": t.nonce,
                "velocity": len(sw.events),
                "fan_out": len(sw.counterparties),
                "fan_in": len(rw.counterparties),
                "near_threshold": sw.near_count,
                "window_value": sw.value_sum,
                "round_trip": round_trip,
                "watchlisted": int(t.sender in watchlist or t.receiver in watchlist),
                "allowlisted": int(t.sender in allowlist or t.receiver in allowlist),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df.set_index("tx_hash") if "tx_hash" in df else df
    df["log_value"] = df["value_eth"].map(math.log1p)
    df["log_nonce"] = df["nonce"].map(math.log1p)
    df["log_window_value"] = df["window_value"].clip(lower=0).map(math.log1p)
    return df.set_index("tx_hash")
