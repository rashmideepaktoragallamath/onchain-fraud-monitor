"""Reason codes shared between the detection engine and the on-chain registry.

Each code is one bit of the ``reasonMask`` stored by ``RiskRegistry.raiseAlert``.
Keep in sync with test/RiskRegistry.test.js (first three bits) and the README.
"""

from __future__ import annotations

from enum import IntFlag


class Reason(IntFlag):
    LARGE_VALUE = 1 << 0  # value far above the wallet's / network's norm
    HIGH_VELOCITY = 1 << 1  # many transfers in a short window
    STRUCTURING = 1 << 2  # repeated amounts just under a reporting threshold
    FAN_OUT = 1 << 3  # one wallet splitting funds across many recipients
    FAN_IN = 1 << 4  # many wallets consolidating into one
    ROUND_TRIP = 1 << 5  # funds returning to origin (A -> B -> A)
    WATCHLISTED = 1 << 6  # counterparty on the on-chain watchlist
    NEW_WALLET_BURST = 1 << 7  # freshly created wallet moving large volume
    ML_ANOMALY = 1 << 8  # Isolation Forest flags the feature vector as an outlier


def describe(mask: int) -> list[str]:
    """Human-readable names for every bit set in ``mask`` (used in alert explanations)."""
    return [r.name for r in Reason if r.name and mask & r.value]
