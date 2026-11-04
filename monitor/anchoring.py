"""File bridge between the dashboard and the on-chain anchoring script.

    dashboard  --writes-->  data/outbox.json    (cases waiting to be synced)
    npm run anchor          reads it, writes to RiskRegistry on Sepolia, then writes
                            data/anchored.json  (alert id, tx hash, gas used)
    dashboard  --reads-->   data/anchored.json  (shows the on-chain proof)

The transaction signer (private key) therefore lives only in the Hardhat process that
needs it; the web server never touches a key.
"""

from __future__ import annotations

import json
from pathlib import Path

from monitor.cases import build_cases
from monitor.config import write_json_atomic
from monitor.models import ADDRESS_RE, TX_HASH_RE
from monitor.storage import Store


def sync_outbox(store: Store, path: Path) -> int:
    """Rewrite the outbox from every case marked as waiting. Returns the number of items."""
    queued = set(store.queued_subjects())
    cases = [c for c in build_cases(store.alerts_with_time(), store.all_case_states()) if c.subject in queued]
    items = [
        {
            "subject": c.subject,
            "tx_hash": c.top_tx_hash,
            "risk_score": c.top_score,
            "reason_mask": c.reason_mask,
            "status": c.state.status,
        }
        for c in cases
    ]
    write_json_atomic(path, {"items": items})
    return len(items)


def merge_anchored(store: Store, path: Path) -> int:
    """Copy on-chain proof from anchored.json into the database. Malformed entries are ignored."""
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    if not isinstance(data, dict):
        return 0

    merged = 0
    for subject, rec in data.items():
        if not (isinstance(subject, str) and ADDRESS_RE.match(subject) and isinstance(rec, dict)):
            continue
        alert_id = rec.get("alertId")
        tx = rec.get("anchorTx")
        gas = rec.get("gasUsed")
        if not isinstance(alert_id, int) or isinstance(alert_id, bool) or alert_id < 0:
            continue
        if tx is not None and not (isinstance(tx, str) and TX_HASH_RE.match(tx)):
            continue
        gas_int = int(gas) if isinstance(gas, (int, str)) and str(gas).isdigit() else None
        store.set_case_anchor(subject.lower(), alert_id, tx, gas_int)
        merged += 1
    return merged
