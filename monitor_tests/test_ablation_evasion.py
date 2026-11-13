"""Tests for the ablation / sensitivity / evasion studies (monitor.ablation, monitor.evasion)."""

from dataclasses import replace

from monitor import ablation, evasion, scoring
from monitor.config import DetectionConfig
from monitor.evaluate import _run
from monitor.reasons import Reason
from monitor.simulator import generate


def test_default_generator_is_unchanged_by_the_inject_hook():
    # The hook must not alter normal behaviour: the standard seed-7 data set keeps its size.
    sim = generate(seed=7)
    assert (len(sim.txs), len(sim.labels)) == (3546, 552)  # the figures in reports/evaluation.json
    assert generate(seed=7).labels == sim.labels


def test_without_restores_weights_even_after_an_error():
    before = dict(scoring.WEIGHTS)
    try:
        with ablation.without(Reason.STRUCTURING):
            assert scoring.WEIGHTS[Reason.STRUCTURING] == 0.0
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert scoring.WEIGHTS == before


def test_removing_the_watchlist_signal_loses_the_watchlisted_scenarios():
    cfg = DetectionConfig()
    sim = generate(seed=7)
    full = _run(sim, cfg, use_allowlist=True)
    with ablation.without(Reason.WATCHLISTED):
        cut = _run(sim, cfg, use_allowlist=True)
    assert full["per_pattern"]["watchlisted"]["detected"] == full["per_pattern"]["watchlisted"]["scenarios"]
    assert cut["per_pattern"]["watchlisted"]["detected"] < full["per_pattern"]["watchlisted"]["detected"]


def test_ablation_baseline_matches_a_plain_run():
    out = ablation.ablation()
    assert set(out["without"]) == {r.name for r in Reason}
    assert out["baseline"]["scenario_recall"] >= 0.95


def test_raising_the_threshold_never_adds_alerts():
    sim = generate(seed=7)
    counts = [_run(sim, replace(DetectionConfig(), alert_threshold=t), use_allowlist=True)["alerts"] for t in (30, 50, 70, 90)]
    assert counts == sorted(counts, reverse=True)


def test_evasion_scenarios_are_labelled_and_deterministic():
    a, b = evasion.build(7), evasion.build(7)
    assert a.labels == b.labels
    names = {key[0] for key in a.labels.values()}
    assert names == set(evasion.VARIANTS)
    # none of the standard patterns leak into the evasion set
    assert not names & {"structuring", "fan_out", "fan_in", "round_trip", "watchlisted", "new_wallet_burst", "high_velocity"}


def test_evasion_result_is_reported_not_tuned():
    out = evasion.evaluate(7)
    assert out["scenarios"] == len(evasion.VARIANTS) * evasion.GROUPS
    # The detector is not tuned to these variants: most must slip through the fixed thresholds.
    assert out["recall"] < 0.5
