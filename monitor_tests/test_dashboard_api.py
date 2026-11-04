import http.client
import json
import socket
import threading
from pathlib import Path

import pytest

from monitor.anchoring import merge_anchored, sync_outbox
from monitor.cases import STATUSES, TRANSITIONS, build_cases, can_transition
from monitor.config import DetectionConfig
from monitor.models import Tx
from monitor.pipeline import analyze
from monitor.server import AppContext, create_server
from monitor.storage import Store

CFG = DetectionConfig()
WALLET_A = "0x" + "a1" * 20  # structuring ring
WALLET_B = "0x" + "b2" * 20  # sends to a watchlisted address
BAD = "0x" + "ee" * 20
RECV = "0x" + "c3" * 20
H = {"Content-Type": "application/json", "X-Requested-With": "fetch"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def app(tmp_path: Path):
    db = tmp_path / "t.db"
    store = Store(db)
    txs = [Tx(f"0x{i:064x}", 1, 1_000_000 + i * 60, WALLET_A, RECV, 9.5, 50 + i) for i in range(1, 5)]
    txs.append(Tx(f"0x{99:064x}", 1, 1_000_400, WALLET_B, BAD, 2.0, 70))
    store.insert_txs(txs)
    analyze(store, CFG, watchlist=frozenset({BAD}), now=1)
    store.close()

    ctx = AppContext(
        db_path=db,
        watchlist_path=tmp_path / "wl.json",
        allowlist_path=tmp_path / "al.json",
        outbox_path=tmp_path / "outbox.json",
        anchored_path=tmp_path / "anchored.json",
        cfg=CFG,
        mode="demo",
        port=_free_port(),
        contract={"address": "0x" + "1" * 40, "network": "sepolia", "explorer": "https://sepolia.etherscan.io"},
    )
    server = create_server(ctx)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield ctx
    server.shutdown()
    server.server_close()


def call(ctx, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", ctx.port, timeout=5)
    hdrs = dict(headers if headers is not None else (H if method == "POST" else {}))
    conn.request(method, path, body=None if body is None else json.dumps(body), headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    ctype = resp.getheader("Content-Type", "")
    data = json.loads(raw) if "json" in ctype and raw else raw
    out = (resp.status, data, dict(resp.getheaders()))
    conn.close()
    return out


# ---------------------------------------------------------------- read API
def test_alerts_are_grouped_into_one_case_per_wallet(app):
    status, data, _ = call(app, "GET", "/api/cases?status=all")
    assert status == 200
    subjects = [c["subject"] for c in data["cases"]]
    assert subjects.count(WALLET_A) == 1  # several alerts, one case
    a = next(c for c in data["cases"] if c["subject"] == WALLET_A)
    assert a["alert_count"] >= 2 and "STRUCTURING" in a["reasons"] and a["status"] == "open"


def test_summary_counts(app):
    _, s, _ = call(app, "GET", "/api/summary")
    assert s["transactions"] == 5 and s["cases"] >= 2 and s["mode"] == "demo"
    assert sum(s["severity"].values()) == s["active_cases"]
    assert s["signals"] and len(s["timeline"]) == 24


def test_case_detail_explains_in_aml_terms(app):
    _, d, _ = call(app, "GET", f"/api/cases/{WALLET_A}")
    assert d["case"]["subject"] == WALLET_A
    assert d["typologies"][0]["title"].startswith("Structuring")
    assert d["alerts"] and d["alerts"][0]["reasons"]
    assert d["recent_transfers"]


def test_filters_and_validation(app):
    _, d, _ = call(app, "GET", "/api/cases?status=all&min_score=100")
    assert d["total"] == 0
    assert call(app, "GET", "/api/cases?status=bogus")[0] == 400
    assert call(app, "GET", "/api/cases?min_score=abc")[0] == 400
    _, d, _ = call(app, "GET", f"/api/cases?status=all&q={WALLET_B[:8]}")
    assert [c["subject"] for c in d["cases"]] == [WALLET_B]


def test_unknown_wallet_and_routes(app):
    assert call(app, "GET", "/api/cases/0x" + "00" * 20)[0] == 404
    assert call(app, "GET", "/api/cases/not-an-address")[0] == 404
    assert call(app, "GET", "/api/nope")[0] == 404


def test_static_page_has_security_headers(app):
    status, body, hdrs = call(app, "GET", "/")
    assert status == 200 and b"<html" in body.lower()
    assert "default-src 'none'" in hdrs["Content-Security-Policy"]
    assert hdrs["X-Content-Type-Options"] == "nosniff"


def test_path_traversal_is_not_served(app):
    for p in ("/../server.py", "/%2e%2e/server.py", "/web/../server.py", "/monitor/server.py"):
        assert call(app, "GET", p)[0] == 404


# ------------------------------------------------------------ write + review
def test_review_workflow_mirrors_contract(app):
    s, d, _ = call(app, "POST", f"/api/cases/{WALLET_A}/status", {"status": "reviewed", "note": "checked"})
    assert s == 200 and d["case"]["status"] == "reviewed" and d["case"]["note"] == "checked"
    assert call(app, "POST", f"/api/cases/{WALLET_A}/status", {"status": "open"})[0] == 400
    assert call(app, "POST", f"/api/cases/{WALLET_A}/status", {"status": "escalated"})[0] == 200
    s, d, _ = call(app, "POST", f"/api/cases/{WALLET_A}/status", {"status": "dismissed"})
    assert s == 409 and "cannot become" in d["error"]  # escalated is final


def test_transition_table_matches_contract_rules():
    assert not TRANSITIONS["escalated"] and not TRANSITIONS["dismissed"]
    assert can_transition("open", "dismissed") and can_transition("reviewed", "escalated")
    assert not can_transition("reviewed", "reviewed") and not can_transition("reviewed", "open")
    assert STATUSES == ("open", "reviewed", "escalated", "dismissed")  # index order = Solidity enum


def test_queue_writes_outbox_for_the_anchor_script(app):
    s, d, _ = call(app, "POST", f"/api/cases/{WALLET_A}/queue", {"queued": True})
    assert s == 200 and d["case"]["queued"] is True
    items = json.loads(app.outbox_path.read_text())["items"]
    assert [i["subject"] for i in items] == [WALLET_A]
    assert items[0]["risk_score"] >= 50 and items[0]["reason_mask"] & 4  # STRUCTURING bit
    call(app, "POST", f"/api/cases/{WALLET_A}/queue", {"queued": False})
    assert json.loads(app.outbox_path.read_text())["items"] == []


def test_allowlist_dismisses_case_and_persists_address(app):
    s, d, _ = call(app, "POST", f"/api/cases/{WALLET_A}/allowlist", {})
    assert s == 200 and d["case"]["status"] == "dismissed"
    assert WALLET_A in json.loads(app.allowlist_path.read_text())["addresses"]
    _, active, _ = call(app, "GET", "/api/cases")
    assert WALLET_A not in [c["subject"] for c in active["cases"]]  # hidden from the default view


def test_anchored_case_is_queued_again_when_status_changes(app):
    store = Store(app.db_path)
    store.set_case_anchor(WALLET_A, 0, "0x" + "ab" * 32, 159435)
    store.close()
    _, d, _ = call(app, "POST", f"/api/cases/{WALLET_A}/status", {"status": "reviewed"})
    assert d["case"]["queued"] is True and d["case"]["anchored"] is True  # needs an on-chain status sync
    assert json.loads(app.outbox_path.read_text())["items"][0]["status"] == "reviewed"


# -------------------------------------------------------------- security
def test_writes_need_custom_header_and_same_origin(app):
    path = f"/api/cases/{WALLET_A}/status"
    no_header = {"Content-Type": "application/json"}
    assert call(app, "POST", path, {"status": "reviewed"}, headers=no_header)[0] == 403
    evil = {**H, "Origin": "http://evil.example"}
    assert call(app, "POST", path, {"status": "reviewed"}, headers=evil)[0] == 403
    good = {**H, "Origin": f"http://127.0.0.1:{app.port}"}
    assert call(app, "POST", path, {"status": "reviewed"}, headers=good)[0] == 200


def test_dns_rebinding_host_is_refused(app):
    s, _, _ = call(app, "GET", "/api/summary", headers={"Host": "evil.example"})
    assert s == 403


def test_bad_bodies_are_rejected(app):
    path = f"/api/cases/{WALLET_A}/status"
    assert call(app, "POST", path, headers={**H, "Content-Type": "text/plain"})[0] == 415
    conn = http.client.HTTPConnection("127.0.0.1", app.port, timeout=5)
    conn.request("POST", path, body="{not json", headers=H)
    assert conn.getresponse().status == 400
    conn.close()
    assert call(app, "POST", path, [1, 2])[0] == 400  # JSON but not an object
    assert call(app, "POST", path, {"status": "reviewed", "note": "x" * 5000})[0] == 413
    assert call(app, "POST", path, {"status": "reviewed", "note": 5})[0] == 400


def test_note_is_sanitised_and_capped(app):
    _, d, _ = call(app, "POST", f"/api/cases/{WALLET_A}/status", {"status": "reviewed", "note": "ok\x00\x07" + "y" * 400})
    assert "\x00" not in d["case"]["note"] and len(d["case"]["note"]) <= 200


# ------------------------------------------------------ anchored.json merge
def test_merge_anchored_accepts_valid_and_ignores_garbage(tmp_path):
    store = Store()
    good_tx = "0x" + "cd" * 32
    path = tmp_path / "anchored.json"
    path.write_text(
        json.dumps(
            {
                WALLET_A: {"alertId": 3, "anchorTx": good_tx, "gasUsed": "159435"},
                WALLET_B: {"alertId": -1, "anchorTx": good_tx},  # negative id
                "not-an-address": {"alertId": 1},
                BAD: {"alertId": 2, "anchorTx": "0xnothash"},  # malformed tx
                RECV: "string",
            }
        )
    )
    assert merge_anchored(store, path) == 1
    st = store.get_case_state(WALLET_A)
    assert (st.alert_id, st.anchor_tx, st.anchor_gas, st.queued) == (3, good_tx, 159435, False)
    assert store.get_case_state(WALLET_B).alert_id is None

    path.write_text("{ broken")
    assert merge_anchored(store, path) == 0
    assert merge_anchored(store, tmp_path / "missing.json") == 0


def test_build_cases_orders_by_score(app):
    store = Store(app.db_path)
    cases = build_cases(store.alerts_with_time(), store.all_case_states())
    assert [c.top_score for c in cases] == sorted((c.top_score for c in cases), reverse=True)
    store.close()


def test_refused_large_posts_still_get_an_error_response(app):
    """Regression (seen on Windows): a rejected request with an unread body must not reset the connection."""
    big = {"status": "reviewed", "note": "x" * 60000}
    path = f"/api/cases/{WALLET_A}/status"
    assert call(app, "POST", path, big)[0] == 413  # too large
    assert call(app, "POST", path, big, headers={"Content-Type": "application/json"})[0] == 403  # no custom header
    assert call(app, "POST", path, big, headers={**H, "Origin": "http://evil.example"})[0] == 403  # wrong origin
    assert call(app, "POST", path, big, headers={**H, "Host": "evil.example"})[0] == 403  # rebinding host
    assert call(app, "POST", path, big, headers={**H, "Content-Type": "text/plain"})[0] == 415
