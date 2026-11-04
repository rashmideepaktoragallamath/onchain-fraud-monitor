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


# Review workflow. Mirrors RiskRegistry.updateStatus: Escalated and Dismissed are final.
# The index of each status is its value in the contract's `Status` enum.
STATUSES = ("open", "reviewed", "escalated", "dismissed")
ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"reviewed", "escalated", "dismissed"}),
    "reviewed": frozenset({"escalated", "dismissed"}),
    "escalated": frozenset(),
    "dismissed": frozenset(),
}
STATUS_TO_CHAIN = {name: index for index, name in enumerate(STATUSES)}


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
    chain_alert_id: int | None = None  # id assigned by the contract (None = not anchored)
    chain_status: str | None = None  # status last written on-chain


@dataclass(frozen=True)
class CaseSummary:
    """All alerts about one wallet, grouped so analysts review wallets, not single transfers."""

    wallet: str
    alert_count: int
    max_score: int
    reason_mask: int
    status: str  # open if any alert is open, else escalated > reviewed > dismissed
    first_seen: int | None
    last_seen: int | None
    anchored: bool
    anchor_tx: str | None


@dataclass(frozen=True)
class CaseState:
    """Analyst-workflow state for one wallet (a "case" groups all alerts about that wallet)."""

    subject: str
    status: str = "open"  # open | reviewed | escalated | dismissed (mirrors the contract's enum)
    queued: bool = False  # waiting to be synced to the on-chain RiskRegistry
    alert_id: int | None = None  # RiskRegistry alert id once anchored
    anchor_tx: str | None = None  # Sepolia tx that anchored the alert
    anchor_gas: int | None = None  # gas used by that tx
    note: str | None = None
    updated_at: int = 0
