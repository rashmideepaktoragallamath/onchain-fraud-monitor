"""Cases: all alerts about one wallet, plus the analyst's review state.

Hundreds of alerts about one busy wallet are one question for an analyst, not hundreds, so
the dashboard works on cases. Review states and allowed moves mirror RiskRegistry.sol.
"""

from __future__ import annotations

from dataclasses import dataclass

from monitor.models import ALLOWED_TRANSITIONS as TRANSITIONS  # noqa: F401 (re-exported)
from monitor.models import STATUSES, Alert, CaseState  # noqa: F401 (STATUSES re-exported)
from monitor.reasons import Reason, describe
from monitor.scoring import severity

# A wallet whose alerts are only about volume (no structuring / round-trip / watchlist /
# fresh-wallet signal) is often an exchange or bot: worth checking before escalating.
_NON_VOLUME = Reason.STRUCTURING | Reason.ROUND_TRIP | Reason.WATCHLISTED | Reason.NEW_WALLET_BURST
LIKELY_SERVICE_MIN_ALERTS = 10


def can_transition(current: str, new: str) -> bool:
    return new in TRANSITIONS.get(current, frozenset())


@dataclass(frozen=True)
class Case:
    subject: str
    alert_count: int
    top_score: int
    severity: str
    reason_mask: int
    top_tx_hash: str
    first_seen: int
    last_seen: int
    state: CaseState

    @property
    def reasons(self) -> list[str]:
        return describe(self.reason_mask)

    @property
    def likely_service(self) -> bool:
        return self.alert_count >= LIKELY_SERVICE_MIN_ALERTS and not (self.reason_mask & _NON_VOLUME)

    def to_dict(self) -> dict:
        st = self.state
        return {
            "subject": self.subject,
            "status": st.status,
            "severity": self.severity,
            "top_score": self.top_score,
            "alert_count": self.alert_count,
            "reasons": self.reasons,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "top_tx": self.top_tx_hash,
            "likely_service": self.likely_service,
            "queued": st.queued,
            "anchored": st.alert_id is not None,
            "alert_id": st.alert_id,
            "anchor_tx": st.anchor_tx,
            "anchor_gas": st.anchor_gas,
            "note": st.note,
        }


def build_cases(rows: list[tuple[Alert, int]], states: dict[str, CaseState]) -> list[Case]:
    """Group (alert, tx_timestamp) rows by wallet. Sorted by score, then recency."""
    grouped: dict[str, list[tuple[Alert, int]]] = {}
    for alert, ts in rows:
        grouped.setdefault(alert.subject, []).append((alert, ts))

    cases = []
    for subject, items in grouped.items():
        top_alert = max(items, key=lambda x: (x[0].risk_score, x[1]))[0]
        mask = 0
        for alert, _ in items:
            mask |= alert.reason_mask
        stamps = [ts for _, ts in items]
        cases.append(
            Case(
                subject=subject,
                alert_count=len(items),
                top_score=top_alert.risk_score,
                severity=severity(top_alert.risk_score),
                reason_mask=mask,
                top_tx_hash=top_alert.tx_hash,
                first_seen=min(stamps),
                last_seen=max(stamps),
                state=states.get(subject, CaseState(subject)),
            )
        )
    cases.sort(key=lambda c: (-c.top_score, -c.last_seen, c.subject))
    return cases
