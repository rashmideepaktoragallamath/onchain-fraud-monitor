"""Glue: read recent transactions, score them, persist new alerts."""

from __future__ import annotations

import time

from monitor.config import DetectionConfig
from monitor.features import build_features
from monitor.models import Alert, Tx
from monitor.reasons import Reason
from monitor.scoring import RiskResult, RiskScorer
from monitor.storage import Store


def score_transactions(
    txs: list,
    cfg: DetectionConfig,
    watchlist: frozenset[str] = frozenset(),
    allowlist: frozenset[str] = frozenset(),
) -> list[RiskResult]:
    """Pure function (no I/O): transactions in, risk results out. Used by tests and evaluation."""
    features = build_features(txs, cfg, watchlist, allowlist)
    if features.empty:
        return []
    scorer = RiskScorer(cfg)
    scorer.fit(features)
    return scorer.score(features)


# Signals that describe what the SENDER did. If none fired, a fan-in alert is about the wallet
# that collected the money, so the case belongs to the receiver (one case for the whole ring).
_SENDER_SIGNALS = (
    Reason.FAN_OUT | Reason.HIGH_VELOCITY | Reason.STRUCTURING | Reason.ROUND_TRIP | Reason.NEW_WALLET_BURST
)


def alert_subject(tx: Tx, reason_mask: int) -> str:
    """The wallet an alert is about."""
    if reason_mask & Reason.FAN_IN and not reason_mask & _SENDER_SIGNALS:
        return tx.receiver
    return tx.sender


def analyze(
    store: Store,
    cfg: DetectionConfig,
    watchlist: frozenset[str] = frozenset(),
    allowlist: frozenset[str] = frozenset(),
    *,
    lookback_seconds: int = 6 * 3600,
    now: int | None = None,
) -> list[Alert]:
    """Score the recent window and save any alert not seen before. Returns the NEW alerts."""
    newest = store.latest_timestamp()
    if newest is None:
        return []
    txs = store.txs_since(newest - lookback_seconds)
    by_hash = {t.tx_hash: t for t in txs}
    created = int(time.time()) if now is None else now

    new_alerts: list[Alert] = []
    for r in score_transactions(txs, cfg, watchlist, allowlist):
        if r.score < cfg.alert_threshold:
            continue
        alert = Alert(
            tx_hash=r.tx_hash,
            subject=alert_subject(by_hash[r.tx_hash], r.mask),
            risk_score=r.score,
            reason_mask=r.mask,
            explanation=r.explanation,
            created_at=created,
        )
        if store.save_alert(alert):
            new_alerts.append(alert)
    return new_alerts
