"""Plain data types shared across the monitoring engine."""

from __future__ import annotations

import re
from dataclasses import dataclass

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def normalize_address(value: str) -> str:
    """Lower-case a 20-byte hex address, rejecting anything malformed."""
    if not isinstance(value, str) or not ADDRESS_RE.match(value):
        raise ValueError(f"invalid address: {value!r}")
    return value.lower()


@dataclass(frozen=True)
class Tx:
    """A native-ETH transfer observed on-chain."""

    tx_hash: str
    block_number: int
    timestamp: int  # unix seconds
    sender: str
    receiver: str
    value_eth: float
    nonce: int  # sender's nonce at this tx (low => young wallet)
    gas_price_gwei: float = 0.0


@dataclass(frozen=True)
class Alert:
    """A scored transaction that crossed the alert threshold."""

    tx_hash: str
    subject: str  # wallet the alert is about
    risk_score: int  # 1..100
    reason_mask: int  # bitmask of monitor.reasons.Reason
    explanation: str  # JSON list of {reason, detail}
    created_at: int
    status: str = "open"
    anchored_tx: str | None = None  # tx hash of the on-chain RiskRegistry write
