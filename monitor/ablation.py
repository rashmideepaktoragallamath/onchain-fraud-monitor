"""Ablation and threshold-sensitivity study.

Run:  python -m monitor.ablation
Writes reports/ablation.json.

Ablation: switch ONE signal off (its weight becomes 0, so it can no longer add to a score) and
re-run the whole evaluation. The drop in scenario recall / change in precision shows what that
signal contributes. Sensitivity: sweep the alert threshold and watch precision and recall trade
off. Everything runs on the simulated data of monitor.evaluate, so it shows how the design
behaves, not accuracy on real laundering.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import replace

from monitor import scoring
from monitor.config import ROOT, DetectionConfig
from monitor.evaluate import _run
from monitor.reasons import Reason
from monitor.simulator import generate

SEEDS = (7, 11, 23)
THRESHOLDS = (30, 40, 50, 60, 70, 80)


@contextmanager
def without(reason: Reason | None):
    """Temporarily give ``reason`` zero weight; always restores the original weights."""
    saved = dict(scoring.WEIGHTS)
    try:
        if reason is not None:
            scoring.WEIGHTS[reason] = 0.0
        yield
    finally:
        scoring.WEIGHTS.clear()
        scoring.WEIGHTS.update(saved)


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 3)


def _summarise(cfg: DetectionConfig, reason: Reason | None) -> dict:
    runs = []
    with without(reason):
        for seed in SEEDS:
            runs.append(_run(generate(seed=seed), cfg, use_allowlist=True))
    return {
        "scenario_recall": _mean([r["scenario_recall"] for r in runs]),
        "alert_precision": _mean([r["alert_precision"] for r in runs]),
        "false_positive_rate_pct": _mean([r["false_positive_rate_pct"] for r in runs]),
        "alerts": round(sum(r["alerts"] for r in runs) / len(runs)),
    }


def ablation(cfg: DetectionConfig | None = None) -> dict:
    cfg = cfg or DetectionConfig()
    base = _summarise(cfg, None)
    rows = {}
    for reason in Reason:
        s = _summarise(cfg, reason)
        s["recall_change"] = round(s["scenario_recall"] - base["scenario_recall"], 3)
        s["precision_change"] = round(s["alert_precision"] - base["alert_precision"], 3)
        rows[reason.name] = s
    return {"seeds": list(SEEDS), "baseline": base, "without": rows}


def sensitivity(cfg: DetectionConfig | None = None) -> dict:
    cfg = cfg or DetectionConfig()
    return {str(t): _summarise(replace(cfg, alert_threshold=t), None) for t in THRESHOLDS}


def main() -> None:
    out = {"ablation": ablation(), "threshold_sensitivity": sensitivity()}
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "ablation.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    base = out["ablation"]["baseline"]
    print(f"\nBaseline (mean of seeds {SEEDS}): recall={base['scenario_recall']} precision={base['alert_precision']} "
          f"FP rate={base['false_positive_rate_pct']}%")
    print("\nSwitching one signal off:")
    print(f"  {'signal removed':<18} {'recall':>7} {'(chg)':>8} {'precision':>10} {'(chg)':>8}")
    for name, r in out["ablation"]["without"].items():
        print(f"  {name:<18} {r['scenario_recall']:>7} {r['recall_change']:>+8} {r['alert_precision']:>10} {r['precision_change']:>+8}")
    print("\nAlert threshold sweep:")
    print(f"  {'threshold':<10} {'recall':>7} {'precision':>10} {'FP rate %':>10} {'alerts':>7}")
    for t, r in out["threshold_sensitivity"].items():
        print(f"  {t:<10} {r['scenario_recall']:>7} {r['alert_precision']:>10} {r['false_positive_rate_pct']:>10} {r['alerts']:>7}")
    print(f"\nSaved {reports / 'ablation.json'}")


if __name__ == "__main__":
    main()
