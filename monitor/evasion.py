"""Held-out evasion test: fraud written to slip past the thresholds on purpose.

Run:  python -m monitor.evasion
Writes reports/evasion.json.

monitor.simulator injects patterns that the rules were designed to catch, so detecting them
shows the pipeline works, not that it is robust. Here each scenario is a *variant* a launderer
could use to stay under a threshold (slower, smaller, split further, amounts spread out, an
extra hop). The detector is NOT tuned to these; the point is to measure honestly where it
fails. Scenarios are kept deliberately close to the rule thresholds so the result shows how
sharp those thresholds are.
"""

from __future__ import annotations

import json
from collections import defaultdict

from monitor.config import ROOT, DetectionConfig
from monitor.pipeline import score_transactions
from monitor.simulator import SimResult, _Gen, generate

GROUPS = 6
VARIANTS = {
    "structuring_spread": "8 transfers spread over 7.5-9.95 ETH instead of clustering just under 10",
    "structuring_few": "only 2 transfers just under the limit (rule needs 3)",
    "fan_out_slow": "20 recipients spread over 3 hours instead of 25 minutes",
    "fan_out_small": "12 recipients (rule needs 15)",
    "velocity_slow": "40 tiny transfers over 3 hours instead of 10 minutes",
    "round_trip_lossy": "funds return at 55% of the amount (rule tolerates +/-25%)",
    "round_trip_three_hop": "A -> B -> C -> A instead of A -> B -> A",
    "new_wallet_small": "new wallet moves 3 x 6 ETH (rule needs 20 ETH in an hour)",
}


def _inject(g: _Gen) -> None:
    rng = g.rng
    gid = 1000
    for _ in range(GROUPS):
        gid += 1
        s, r, t0, n0 = g.addr(), g.addr(), g.when(2400), rng.randint(20, 300)
        for k in range(8):
            g.emit(t0 + k * 300, s, r, rng.uniform(7.5, 9.95), n0 + k, ("structuring_spread", gid))

        gid += 1
        s, r, t0, n0 = g.addr(), g.addr(), g.when(600), rng.randint(20, 300)
        for k in range(2):
            g.emit(t0 + k * 240, s, r, rng.uniform(9.2, 9.95), n0 + k, ("structuring_few", gid))

        gid += 1
        s, t0, n0 = g.addr(), g.when(10800), rng.randint(20, 300)
        for k in range(20):
            g.emit(t0 + k * 540, s, g.addr(), rng.uniform(2, 5), n0 + k, ("fan_out_slow", gid))

        gid += 1
        s, t0, n0 = g.addr(), g.when(1500), rng.randint(20, 300)
        for k in range(12):
            g.emit(t0 + k * 60, s, g.addr(), rng.uniform(2, 5), n0 + k, ("fan_out_small", gid))

        gid += 1
        s, t0, n0 = g.addr(), g.when(10800), rng.randint(20, 300)
        targets = [g.addr() for _ in range(3)]
        for k in range(40):
            g.emit(t0 + k * 270, s, rng.choice(targets), rng.uniform(0.01, 0.1), n0 + k, ("velocity_slow", gid))

        gid += 1
        a, b, t0, amt = g.addr(), g.addr(), g.when(1500), rng.uniform(40, 80)
        g.emit(t0, a, b, amt, rng.randint(20, 300), ("round_trip_lossy", gid))
        g.emit(t0 + rng.randint(300, 1200), b, a, amt * 0.55, rng.randint(20, 300), ("round_trip_lossy", gid))

        gid += 1
        a, b, c, t0, amt = g.addr(), g.addr(), g.addr(), g.when(2400), rng.uniform(40, 80)
        g.emit(t0, a, b, amt, rng.randint(20, 300), ("round_trip_three_hop", gid))
        g.emit(t0 + 600, b, c, amt * 0.98, rng.randint(20, 300), ("round_trip_three_hop", gid))
        g.emit(t0 + 1200, c, a, amt * 0.96, rng.randint(20, 300), ("round_trip_three_hop", gid))

        gid += 1
        s, t0 = g.addr(), g.when(1200)
        for k in range(3):
            g.emit(t0 + k * 300, s, g.addr(), 6.0, k, ("new_wallet_small", gid))


def build(seed: int = 7) -> SimResult:
    # groups_per_pattern=0 keeps the normal background only, so every label is an evasion variant.
    return generate(seed=seed, groups_per_pattern=0, inject=_inject)


def evaluate(seed: int = 7, cfg: DetectionConfig | None = None) -> dict:
    cfg = cfg or DetectionConfig()
    sim = build(seed)
    results = score_transactions(sim.txs, cfg, watchlist=sim.watchlist, allowlist=sim.allowlist)
    flagged = {r.tx_hash for r in results if r.score >= cfg.alert_threshold}
    groups: dict[tuple[str, int], list[str]] = defaultdict(list)
    for h, key in sim.labels.items():
        groups[key].append(h)
    per = {}
    for name, desc in VARIANTS.items():
        keys = [k for k in groups if k[0] == name]
        caught = sum(any(h in flagged for h in groups[k]) for k in keys)
        per[name] = {"description": desc, "scenarios": len(keys), "detected": caught}
    total = sum(v["scenarios"] for v in per.values())
    caught = sum(v["detected"] for v in per.values())
    return {"seed": seed, "scenarios": total, "detected": caught, "recall": round(caught / total, 3), "per_variant": per}


def main() -> None:
    runs = [evaluate(seed) for seed in (7, 11, 23)]
    # Pool the three seeds so each variant has 3 x 6 scenarios.
    pooled = {n: {"description": d, "scenarios": 0, "detected": 0} for n, d in VARIANTS.items()}
    for run in runs:
        for n, v in run["per_variant"].items():
            pooled[n]["scenarios"] += v["scenarios"]
            pooled[n]["detected"] += v["detected"]
    total = sum(v["scenarios"] for v in pooled.values())
    caught = sum(v["detected"] for v in pooled.values())
    out = {"seeds": [7, 11, 23], "pooled": pooled, "scenarios": total, "detected": caught, "recall": round(caught / total, 3), "runs": runs}
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "evasion.json").write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(f"\nEvasion variants, 3 seeds pooled: {caught}/{total} scenarios detected (recall {out['recall']})\n")
    for n, v in pooled.items():
        print(f"  {n:<22} {v['detected']:>2}/{v['scenarios']:<2}  {v['description']}")
    print(f"\nSaved {reports / 'evasion.json'}")


if __name__ == "__main__":
    main()
