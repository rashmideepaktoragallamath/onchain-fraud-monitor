import pytest

from monitor.config import DetectionConfig
from monitor.evaluate import evaluate
from monitor.features import build_features
from monitor.models import Tx
from monitor.pipeline import analyze, score_transactions
from monitor.reasons import Reason
from monitor.scoring import WEIGHTS, combine, severity
from monitor.simulator import generate
from monitor.storage import Store

CFG = DetectionConfig()


def addr(n: int) -> str:
    return "0x" + f"{n:040x}"


_counter = iter(range(1, 10**6))


def tx(ts, s, r, v, nonce=100) -> Tx:
    return Tx(f"0x{next(_counter):064x}", 1, ts, addr(s), addr(r), v, nonce)


def reasons_of(txs, **kw):
    out = {}
    for r in score_transactions(txs, CFG, **kw):
        out[r.tx_hash] = {h.reason for h in r.hits}
    return out


# --------------------------------------------------------------- features
def test_window_expires_old_activity():
    txs = [tx(0, 1, 2, 1.0), tx(10_000, 1, 3, 1.0)]  # 10,000 s apart > 3,600 s window
    f = build_features(txs, CFG)
    assert list(f["velocity"]) == [1, 1]


def test_fan_out_and_fan_in_counts_distinct_counterparties():
    txs = [tx(i, 1, 100 + i, 1.0) for i in range(5)] + [tx(i, 200 + i, 9, 1.0) for i in range(4)]
    f = build_features(txs, CFG)
    assert f["fan_out"].max() == 5
    assert f["fan_in"].max() == 4


def test_round_trip_detected_only_on_return_leg_with_similar_amount():
    f = build_features([tx(0, 1, 2, 50.0), tx(600, 2, 1, 48.0)], CFG)
    assert list(f["round_trip"]) == [0, 1]
    f = build_features([tx(0, 1, 2, 50.0), tx(600, 2, 1, 5.0)], CFG)  # very different amount
    assert list(f["round_trip"]) == [0, 0]


# ------------------------------------------------------------------ rules
def test_structuring_requires_repeated_just_under_threshold():
    txs = [tx(i * 60, 1, 2, 9.5) for i in range(3)]
    assert Reason.STRUCTURING in reasons_of(txs)[txs[-1].tx_hash]
    two = [tx(i * 60, 1, 2, 9.5) for i in range(2)]
    assert Reason.STRUCTURING not in reasons_of(two)[two[-1].tx_hash]


def test_amounts_at_or_above_threshold_are_not_structuring():
    txs = [tx(i * 60, 1, 2, 10.0) for i in range(5)]
    assert all(Reason.STRUCTURING not in r for r in reasons_of(txs).values())


def test_high_velocity():
    txs = [tx(i * 10, 1, 2, 0.05) for i in range(CFG.velocity_min)]
    assert Reason.HIGH_VELOCITY in reasons_of(txs)[txs[-1].tx_hash]


def test_new_wallet_burst_needs_low_nonce_and_volume():
    young = [tx(0, 1, 2, 30.0, nonce=0), tx(60, 1, 3, 30.0, nonce=1)]
    assert Reason.NEW_WALLET_BURST in reasons_of(young)[young[-1].tx_hash]
    old = [tx(0, 5, 2, 30.0, nonce=500), tx(60, 5, 3, 30.0, nonce=501)]
    assert Reason.NEW_WALLET_BURST not in reasons_of(old)[old[-1].tx_hash]


def test_watchlist_hit_on_either_side():
    bad = addr(666)
    txs = [tx(0, 1, 666, 1.0), tx(10, 666, 2, 1.0)]
    out = reasons_of(txs, watchlist=frozenset({bad}))
    assert all(Reason.WATCHLISTED in r for r in out.values())


def test_allowlist_suppresses_behavioural_rules_but_not_watchlist():
    hot = addr(7)
    txs = [tx(i, 7, 100 + i, 1.0) for i in range(30)]  # exchange-like fan-out + velocity
    plain = reasons_of(txs)[txs[-1].tx_hash]
    assert {Reason.FAN_OUT, Reason.HIGH_VELOCITY} <= plain
    allowed = reasons_of(txs, allowlist=frozenset({hot}))[txs[-1].tx_hash]
    assert allowed == set()
    flagged = reasons_of(txs, allowlist=frozenset({hot}), watchlist=frozenset({addr(100 + 29)}))[txs[-1].tx_hash]
    assert flagged == {Reason.WATCHLISTED}


# ---------------------------------------------------------------- scoring
def test_score_is_bounded_and_monotonic():
    assert combine([]) == 0
    prev = 0
    chosen = []
    for r in sorted(WEIGHTS, key=WEIGHTS.get):
        chosen.append(r)
        s = combine(chosen)
        assert prev <= s <= 100
        prev = s


def test_context_rules_alone_do_not_alert_but_together_do():
    t = CFG.alert_threshold
    for r in (Reason.LARGE_VALUE, Reason.NEW_WALLET_BURST, Reason.ML_ANOMALY):
        assert combine([r]) < t
    assert combine([Reason.LARGE_VALUE, Reason.NEW_WALLET_BURST]) >= t
    assert combine([Reason.FAN_OUT]) >= t  # a behavioural pattern alerts on its own


def test_severity_bands():
    assert [severity(s) for s in (10, 50, 65, 80)] == ["low", "medium", "high", "critical"]


def test_explanations_name_each_reason():
    txs = [tx(i * 60, 1, 2, 9.5) for i in range(3)]
    res = {r.tx_hash: r for r in score_transactions(txs, CFG)}[txs[-1].tx_hash]
    assert "STRUCTURING" in res.explanation and res.score >= CFG.alert_threshold


def test_empty_input():
    assert score_transactions([], CFG) == []


# --------------------------------------------------------------- pipeline
def test_analyze_saves_each_alert_once():
    store = Store()
    txs = [tx(1_000_000 + i * 60, 1, 2, 9.5) for i in range(4)]
    store.insert_txs(txs)
    first = analyze(store, CFG, now=1)
    second = analyze(store, CFG, now=2)
    assert len(first) >= 1 and second == []
    assert store.count_alerts() == len(first)


def test_analyze_empty_store():
    assert analyze(Store(), CFG) == []


# --------------------------------------------- end-to-end regression guard
def test_simulation_is_reproducible():
    a, b = generate(seed=3), generate(seed=3)
    assert [t.tx_hash for t in a.txs] == [t.tx_hash for t in b.txs]


def test_detector_regression_on_simulated_fraud():
    r = evaluate(seed=7)["with_allowlist"]
    assert r["scenario_recall"] >= 0.9
    assert r["false_positive_rate_pct"] <= 1.0
    assert r["alert_precision"] >= 0.9


def test_fan_in_alerts_are_filed_under_the_collecting_wallet():
    """20 wallets paying one recipient must be ONE case about the recipient, not 20 cases."""
    store = Store()
    collector = 900
    store.insert_txs([tx(1_000_000 + i * 30, 100 + i, collector, 2.0) for i in range(20)])
    alerts = analyze(store, CFG, now=1)
    assert alerts, "fan-in should raise alerts"
    assert {a.subject for a in alerts} == {addr(collector)}


def test_fan_out_alerts_stay_with_the_sender():
    store = Store()
    store.insert_txs([tx(1_000_000 + i * 30, 7, 100 + i, 2.0) for i in range(20)])
    assert {a.subject for a in analyze(store, CFG, now=1)} == {addr(7)}
