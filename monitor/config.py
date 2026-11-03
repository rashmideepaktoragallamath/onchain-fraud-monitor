"""Configuration: environment, file locations and detection thresholds."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from monitor.models import normalize_address

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class DetectionConfig:
    """Every tunable threshold lives here so rules stay free of magic numbers."""

    window_seconds: int = 3600  # sliding window for behavioural features
    large_value_eth: float = 100.0
    structuring_threshold_eth: float = 10.0  # internal "review above this" limit
    structuring_band: float = 0.9  # amounts in [band*T, T) count as "just under"
    structuring_min_count: int = 3
    velocity_min: int = 20  # transfers by one sender within the window
    fan_min: int = 15  # distinct counterparties within the window
    round_trip_tolerance: float = 0.25  # returned amount within +/-25%
    new_wallet_max_nonce: int = 5
    new_wallet_value_eth: float = 20.0
    ml_percentile: float = 0.99  # top 1% most isolated => ML_ANOMALY
    ml_min_samples: int = 200  # below this the ML layer is skipped
    alert_threshold: int = 50  # score >= this becomes an alert


@dataclass(frozen=True)
class Settings:
    rpc_url: str
    db_path: Path
    watchlist_path: Path
    allowlist_path: Path
    detection: DetectionConfig = field(default_factory=DetectionConfig)


def load_env_file(path: Path) -> None:
    """Minimal .env reader. Never overrides variables already set in the environment."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def load_address_file(path: Path) -> frozenset[str]:
    """Load a JSON list of addresses (lower-cased). A missing file means an empty set."""
    if not path.is_file():
        return frozenset()
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("addresses", []) if isinstance(data, dict) else data
    return frozenset(normalize_address(a) for a in entries)


def load_settings() -> Settings:
    load_env_file(ROOT / ".env")
    return Settings(
        rpc_url=os.environ.get("MAINNET_RPC_URL", ""),
        db_path=Path(os.environ.get("MONITOR_DB_PATH", ROOT / "data" / "monitor.db")),
        watchlist_path=ROOT / "data" / "watchlist.json",
        allowlist_path=ROOT / "data" / "allowlist.json",
    )
