"""Synthetic transaction generator with injected, labelled fraud patterns.

Used for (1) objective evaluation of the detector and (2) an offline demo when no RPC is
available. Results on synthetic data show the detector does what it is designed to do; they
are NOT a claim about accuracy on real mainnet traffic.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from monitor.models import Tx

PATTERNS = (
    "structuring",
    "fan_out",
    "fan_in",
    "round_trip",
    "watchlisted",
    "new_wallet_burst",
    "high_velocity",
)


@dataclass(frozen=True)
class SimResult:
    txs: list[Tx]
    labels: dict[str, tuple[str, int]]  # tx_hash -> (pattern, group id) for injected fraud only
    watchlist: frozenset[str]
    allowlist: frozenset[str]  # known exchange / infrastructure wallets


class _Gen:
    def __init__(self, seed: int, end_ts: int, hours: float) -> None:
        self.rng = random.Random(seed)
        self.end_ts = end_ts
        self.start_ts = end_ts - int(hours * 3600)
        self.txs: list[Tx] = []
        self.labels: dict[str, tuple[str, int]] = {}
        self._n = 0
        self._block = 20_000_000

    def addr(self) -> str:
        return "0x" + "".join(self.rng.choices("0123456789abcdef", k=40))

    def emit(self, ts: int, sender: str, receiver: str, value: float, nonce: int, label: tuple[str, int] | None = None) -> None:
        self._n += 1
        h = f"0x{self._n:064x}"
        self._block += 1
        self.txs.append(Tx(h, self._block, ts, sender, receiver, round(value, 6), nonce, 20.0))
        if label:
            self.labels[h] = label

    def when(self, span: int) -> int:
        """A random start time that leaves room for a pattern lasting `span` seconds."""
        return self.rng.randint(self.start_ts, self.end_ts - span)


def generate(*, n_normal: int = 3000, groups_per_pattern: int = 6, hours: float = 6, seed: int = 7, end_ts: int = 1_760_000_000) -> SimResult:
    g = _Gen(seed, end_ts, hours)
    rng = g.rng

    # --- normal behaviour: a population with heavy-tailed activity and values ---
    wallets = [g.addr() for _ in range(700)]
    weights = [1 / (i + 1) ** 0.7 for i in range(len(wallets))]  # a few busy wallets
    exchanges = frozenset(wallets[:3])  # the busiest wallets behave like exchange hot wallets
    nonce = {w: rng.randint(5, 1500) for w in wallets}
    for _ in range(n_normal):
        s, r = rng.choices(wallets, weights)[0], rng.choice(wallets)
        if s == r:
            continue
        value = math.exp(rng.gauss(-0.7, 1.3))
        nonce[s] += 1
        g.emit(g.when(1), s, r, value, nonce[s])

    watchlist = frozenset(g.addr() for _ in range(3))
    wl = sorted(watchlist)
    gid = 0

    for _ in range(groups_per_pattern):
        # structuring: repeated amounts just under the 10 ETH review limit
        gid += 1
        s, r, t0, n0 = g.addr(), g.addr(), g.when(1800), rng.randint(20, 300)
        for k in range(6):
            g.emit(t0 + k * 240, s, r, rng.uniform(9.2, 9.95), n0 + k, ("structuring", gid))

        # fan-out: one wallet distributing to many fresh addresses
        gid += 1
        s, t0, n0 = g.addr(), g.when(1500), rng.randint(20, 300)
        for k in range(20):
            g.emit(t0 + k * 60, s, g.addr(), rng.uniform(2, 5), n0 + k, ("fan_out", gid))

        # fan-in: many wallets consolidating into one
        gid += 1
        r, t0 = g.addr(), g.when(1500)
        for k in range(20):
            g.emit(t0 + k * 60, g.addr(), r, rng.uniform(1, 4), rng.randint(20, 300), ("fan_in", gid))

        # round trip: A -> B then B -> A for almost the same amount
        gid += 1
        a, b, t0, amt = g.addr(), g.addr(), g.when(1500), rng.uniform(40, 80)
        g.emit(t0, a, b, amt, rng.randint(20, 300), ("round_trip", gid))
        g.emit(t0 + rng.randint(300, 1200), b, a, amt * rng.uniform(0.95, 0.99), rng.randint(20, 300), ("round_trip", gid))

        # watchlisted counterparty, otherwise ordinary amount
        gid += 1
        g.emit(g.when(1), g.addr(), rng.choice(wl), rng.uniform(1, 5), rng.randint(20, 300), ("watchlisted", gid))

        # brand-new wallet moving a lot of value quickly
        gid += 1
        s, t0 = g.addr(), g.when(1200)
        for k in range(3):
            g.emit(t0 + k * 300, s, g.addr(), rng.uniform(30, 60), k, ("new_wallet_burst", gid))

        # bot-like velocity: dozens of tiny transfers in minutes
        gid += 1
        s, t0, n0 = g.addr(), g.when(700), rng.randint(20, 300)
        targets = [g.addr() for _ in range(3)]
        for k in range(40):
            g.emit(t0 + k * 15, s, rng.choice(targets), rng.uniform(0.01, 0.1), n0 + k, ("high_velocity", gid))

    return SimResult(g.txs, g.labels, watchlist, exchanges)
