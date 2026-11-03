"""Evaluate the detector on synthetic data with injected fraud patterns.

Run:  python -m monitor.evaluate
Writes reports/evaluation.json (numbers for the report, paper and slides).

Metrics
- group recall: share of injected fraud *scenarios* (e.g. one structuring ring) in which at
  least one transaction raised an alert. A scenario only becomes visible once enough
  activity has accumulated, so per-transaction recall would understate real detection.
- alert precision: share of alerts that belong to an injected scenario.
- false-positive rate: alerts on normal transactions per 100 normal transactions.
Synthetic data shows the detector behaves as designed; it is not a claim about mainnet accuracy.
"""

from __future__ import annotations

import json
from collections import defaultdict

from monitor.config import ROOT, DetectionConfig
from monitor.pipeline import score_transactions
from monitor.reasons import Reason
from monitor.simulator import PATTERNS, SimResult, generate

# Which detector reason is the "intended" one for each injected pattern.
EXPECTED = {
    "structuring": Reason.STRUCTURING,
    "fan_out": Reason.FAN_OUT,
    "fan_in": Reason.FAN_IN,
    "round_trip": Reason.ROUND_TRIP,
    "watchlisted": Reason.WATCHLISTED,
    "new_wallet_burst": Reason.NEW_WALLET_BURST,
    "high_velocity": Reason.HIGH_VELOCITY,
}


def _run(sim: SimResult, cfg: DetectionConfig, *, use_allowlist: bool) -> dict:
    allow = sim.allowlist if use_allowlist else frozenset()
    results = score_transactions(sim.txs, cfg, watchlist=sim.watchlist, allowlist=allow)
    flagged = {r.tx_hash: r for r in results if r.score >= cfg.alert_threshold}

    fraud = set(sim.labels)
    normal_total = len(sim.txs) - len(fraud)
    false_pos = [h for h in flagged if h not in fraud]
    true_pos = [h for h in flagged if h in fraud]

    groups: dict[tuple[str, int], list[str]] = defaultdict(list)
    for h, key in sim.labels.items():
        groups[key].append(h)

    per_pattern = {}
    for pattern in PATTERNS:
        keys = [k for k in groups if k[0] == pattern]
        detected = sum(any(h in flagged for h in groups[k]) for k in keys)
        right = sum(any(h in flagged and (flagged[h].mask & EXPECTED[pattern]) for h in groups[k]) for k in keys)
        per_pattern[pattern] = {"scenarios": len(keys), "detected": detected, "with_expected_reason": right}

    detected_total = sum(v["detected"] for v in per_pattern.values())
    return {
        "allowlist_used": use_allowlist,
        "alerts": len(flagged),
        "alerts_in_fraud_scenarios": len(true_pos),
        "false_positive_alerts": len(false_pos),
        "false_positive_rate_pct": round(100 * len(false_pos) / normal_total, 2),
        "alert_precision": round(len(true_pos) / len(flagged), 3) if flagged else 0.0,
        "scenario_recall": round(detected_total / len(groups), 3),
        "scenarios_detected": f"{detected_total}/{len(groups)}",
        "per_pattern": per_pattern,
    }


def evaluate(seed: int = 7, cfg: DetectionConfig | None = None) -> dict:
    cfg = cfg or DetectionConfig()
    sim = generate(seed=seed)
    return {
        "seed": seed,
        "alert_threshold": cfg.alert_threshold,
        "transactions": len(sim.txs),
        "fraud_transactions": len(sim.labels),
        "normal_transactions": len(sim.txs) - len(sim.labels),
        "with_allowlist": _run(sim, cfg, use_allowlist=True),
        "without_allowlist": _run(sim, cfg, use_allowlist=False),
    }


def main() -> None:
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    runs = [evaluate(seed) for seed in (7, 11, 23)]
    (reports / "evaluation.json").write_text(json.dumps(runs, indent=2), encoding="utf-8")

    for run in runs:
        print(f"\nseed {run['seed']}: {run['transactions']} transactions "
              f"({run['fraud_transactions']} in injected fraud scenarios)")
        for key in ("with_allowlist", "without_allowlist"):
            r = run[key]
            print(f"  [{key.replace('_', ' ')}] alerts={r['alerts']}  precision={r['alert_precision']}  "
                  f"scenario recall={r['scenario_recall']} ({r['scenarios_detected']})  "
                  f"false-positive rate={r['false_positive_rate_pct']}%")
        for name, v in run["with_allowlist"]["per_pattern"].items():
            print(f"      {name:<18} {v['detected']}/{v['scenarios']} detected "
                  f"({v['with_expected_reason']} with expected reason)")
    print(f"\nSaved {reports / 'evaluation.json'}")


if __name__ == "__main__":
    main()
