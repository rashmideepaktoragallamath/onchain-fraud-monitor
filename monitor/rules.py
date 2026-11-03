"""Transparent detection rules. Each rule returns a human-readable reason when it fires."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping

from monitor.config import DetectionConfig
from monitor.reasons import Reason


@dataclass(frozen=True)
class Hit:
    reason: Reason
    detail: str


Row = Mapping[str, float]
Rule = Callable[[Row, DetectionConfig], Hit | None]


def large_value(r: Row, c: DetectionConfig) -> Hit | None:
    if r["value_eth"] >= c.large_value_eth:
        return Hit(Reason.LARGE_VALUE, f"{r['value_eth']:.2f} ETH is at or above the {c.large_value_eth:g} ETH limit")
    return None


def high_velocity(r: Row, c: DetectionConfig) -> Hit | None:
    if r["velocity"] >= c.velocity_min:
        return Hit(Reason.HIGH_VELOCITY, f"{int(r['velocity'])} transfers by one wallet within {c.window_seconds // 60} min")
    return None


def structuring(r: Row, c: DetectionConfig) -> Hit | None:
    if r["near_threshold"] >= c.structuring_min_count:
        lo = c.structuring_band * c.structuring_threshold_eth
        return Hit(
            Reason.STRUCTURING,
            f"{int(r['near_threshold'])} transfers of {lo:g}-{c.structuring_threshold_eth:g} ETH, just under the "
            f"{c.structuring_threshold_eth:g} ETH review limit",
        )
    return None


def fan_out(r: Row, c: DetectionConfig) -> Hit | None:
    if r["fan_out"] >= c.fan_min:
        return Hit(Reason.FAN_OUT, f"funds split across {int(r['fan_out'])} recipients within {c.window_seconds // 60} min")
    return None


def fan_in(r: Row, c: DetectionConfig) -> Hit | None:
    if r["fan_in"] >= c.fan_min:
        return Hit(Reason.FAN_IN, f"{int(r['fan_in'])} different wallets paid the same recipient within {c.window_seconds // 60} min")
    return None


def round_trip(r: Row, c: DetectionConfig) -> Hit | None:
    if r["round_trip"]:
        return Hit(Reason.ROUND_TRIP, "funds returned to their origin in a similar amount (A -> B -> A)")
    return None


def watchlisted(r: Row, c: DetectionConfig) -> Hit | None:
    if r["watchlisted"]:
        return Hit(Reason.WATCHLISTED, "a counterparty is on the watchlist")
    return None


def new_wallet_burst(r: Row, c: DetectionConfig) -> Hit | None:
    if r["nonce"] <= c.new_wallet_max_nonce and r["window_value"] >= c.new_wallet_value_eth:
        return Hit(
            Reason.NEW_WALLET_BURST,
            f"wallet with only {int(r['nonce'])} prior transactions moved {r['window_value']:.1f} ETH within "
            f"{c.window_seconds // 60} min",
        )
    return None


# Rules that depend on behaviour of busy infrastructure (exchanges, routers) and are
# therefore skipped for allow-listed counterparties to avoid false positives.
BEHAVIOURAL_RULES: tuple[Rule, ...] = (
    large_value,
    high_velocity,
    structuring,
    fan_out,
    fan_in,
    round_trip,
    new_wallet_burst,
)
ALWAYS_RULES: tuple[Rule, ...] = (watchlisted,)


def evaluate_rules(row: Row, cfg: DetectionConfig) -> list[Hit]:
    rules = ALWAYS_RULES if row["allowlisted"] else ALWAYS_RULES + BEHAVIOURAL_RULES
    return [hit for rule in rules if (hit := rule(row, cfg)) is not None]
