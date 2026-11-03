"""Risk scoring: transparent rules + Isolation Forest, combined with a noisy-OR.

Each signal i carries a weight w_i in (0,1) read as "how strongly this alone suggests
risk". Independent signals combine as  score = 100 * (1 - prod(1 - w_i)).
Properties that make the score explainable and defensible:
  * it is bounded below 100 and monotonic: more evidence never lowers the score;
  * one weak signal stays below the alert threshold, so alerts need corroboration;
  * the score decomposes into the exact reasons that produced it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from monitor.config import DetectionConfig
from monitor.features import ML_FEATURES
from monitor.reasons import Reason
from monitor.rules import Hit, evaluate_rules

# Pattern rules describe suspicious *behaviour* and are strong enough to alert on their own.
# Context rules (large value, young wallet, ML outlier) are common in legitimate activity,
# so each stays below the alert threshold and needs corroboration.
WEIGHTS: dict[Reason, float] = {
    Reason.STRUCTURING: 0.55,
    Reason.FAN_OUT: 0.50,
    Reason.FAN_IN: 0.50,
    Reason.ROUND_TRIP: 0.50,
    Reason.HIGH_VELOCITY: 0.50,
    Reason.WATCHLISTED: 0.75,
    Reason.LARGE_VALUE: 0.35,
    Reason.NEW_WALLET_BURST: 0.35,
    Reason.ML_ANOMALY: 0.30,
}


def combine(reasons: list[Reason]) -> int:
    """Noisy-OR of the weights of ``reasons``; 0 when empty, else clamped to 1..100."""
    if not reasons:
        return 0
    miss = 1.0
    for r in reasons:
        miss *= 1.0 - WEIGHTS[r]
    return max(1, min(100, round(100 * (1.0 - miss))))


def severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


@dataclass(frozen=True)
class RiskResult:
    tx_hash: str
    score: int
    mask: int
    hits: tuple[Hit, ...]
    ml_percentile: float | None  # share of the baseline that is LESS anomalous (None if ML skipped)

    @property
    def explanation(self) -> str:
        return json.dumps([{"reason": h.reason.name, "detail": h.detail} for h in self.hits])


class RiskScorer:
    def __init__(self, cfg: DetectionConfig, *, random_state: int = 42) -> None:
        self._cfg = cfg
        self._model = IsolationForest(n_estimators=200, contamination="auto", random_state=random_state)
        self._baseline: np.ndarray | None = None  # sorted anomaly scores of the fit sample

    @property
    def ml_ready(self) -> bool:
        return self._baseline is not None

    def fit(self, features: pd.DataFrame) -> bool:
        """Learn the normal feature distribution. Skipped (returns False) on tiny samples."""
        if len(features) < self._cfg.ml_min_samples:
            self._baseline = None
            return False
        x = features[ML_FEATURES].to_numpy(dtype=float)
        self._model.fit(x)
        self._baseline = np.sort(-self._model.score_samples(x))  # higher = more anomalous
        return True

    def _percentiles(self, features: pd.DataFrame) -> np.ndarray | None:
        if self._baseline is None:
            return None
        raw = -self._model.score_samples(features[ML_FEATURES].to_numpy(dtype=float))
        return np.searchsorted(self._baseline, raw, side="right") / len(self._baseline)

    def score(self, features: pd.DataFrame) -> list[RiskResult]:
        percentiles = self._percentiles(features)
        results: list[RiskResult] = []
        for i, (tx_hash, row) in enumerate(features.iterrows()):
            hits = evaluate_rules(row, self._cfg)
            pct = None if percentiles is None else float(percentiles[i])
            if pct is not None and pct >= self._cfg.ml_percentile and not row["allowlisted"]:
                hits.append(Hit(Reason.ML_ANOMALY, f"behaviour is more unusual than {pct:.1%} of recent activity"))
            reasons = [h.reason for h in hits]
            mask = 0
            for r in reasons:
                mask |= int(r)
            results.append(RiskResult(str(tx_hash), combine(reasons), mask, tuple(hits), pct))
        return results
