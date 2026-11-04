"""Local dashboard server: JSON API + static page, standard library only.

Threat model: a tool run by one analyst on their own machine. It therefore
  * binds to 127.0.0.1 only,
  * rejects requests whose Host header is not localhost (DNS-rebinding defence),
  * requires a custom header + same-origin Origin on every write (blocks cross-site forms/fetch),
  * validates every wallet address and request body, and caps body size,
  * sends a strict Content-Security-Policy and never reflects input into HTML,
  * holds no private keys: on-chain writes happen in a separate Hardhat script.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from monitor.anchoring import merge_anchored, sync_outbox
from monitor.cases import STATUSES, build_cases, can_transition
from monitor.config import DetectionConfig, add_address, load_address_file
from monitor.models import ADDRESS_RE
from monitor.storage import Store
from monitor.typologies import TYPOLOGIES, for_reasons

log = logging.getLogger("monitor.server")

WEB_DIR = Path(__file__).resolve().parent / "web"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
MAX_BODY = 4096
MAX_DRAIN = 1 << 20  # never read more than 1 MiB of a request we are going to refuse
MAX_NOTE = 200
_CASE_ROUTE = re.compile(r"^/api/cases/(0x[0-9a-fA-F]{40})(?:/(status|queue|allowlist))?$")


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class AppContext:
    db_path: Path
    watchlist_path: Path
    allowlist_path: Path
    outbox_path: Path
    anchored_path: Path
    cfg: DetectionConfig
    mode: str  # "live" | "demo" | "view"
    port: int
    contract: dict[str, str] | None = None
    _anchored_mtime: float = field(default=0.0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset({f"127.0.0.1:{self.port}", f"localhost:{self.port}"})

    def open_store(self) -> Store:
        store = Store(self.db_path)
        self._refresh_anchored(store)
        return store

    def _refresh_anchored(self, store: Store) -> None:
        """Pick up on-chain proof written by `npm run anchor` (only when the file changed)."""
        try:
            mtime = self.anchored_path.stat().st_mtime
        except OSError:
            return
        with self._lock:
            if mtime != self._anchored_mtime:
                merge_anchored(store, self.anchored_path)
                self._anchored_mtime = mtime


# ------------------------------------------------------------------ API logic
def api_config(ctx: AppContext) -> dict[str, Any]:
    return {
        "mode": ctx.mode,
        "contract": ctx.contract,
        "alert_threshold": ctx.cfg.alert_threshold,
        "typologies": {k: v.title for k, v in TYPOLOGIES.items()},
    }


def api_summary(ctx: AppContext, store: Store) -> dict[str, Any]:
    cases = build_cases(store.alerts_with_time(), store.all_case_states())
    active = [c for c in cases if c.state.status != "dismissed"]
    severity = {"critical": 0, "high": 0, "medium": 0}
    reason_counts: dict[str, int] = {}
    for c in active:
        severity[c.severity] = severity.get(c.severity, 0) + 1
        for r in c.reasons:
            reason_counts[r] = reason_counts.get(r, 0) + 1
    signals = [
        {"reason": r, "title": TYPOLOGIES[r].title if r in TYPOLOGIES else r, "cases": n}
        for r, n in sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    return {
        "mode": ctx.mode,
        "transactions": store.count_txs(),
        "alerts": store.count_alerts(),
        "cases": len(cases),
        "active_cases": len(active),
        "open_cases": sum(c.state.status == "open" for c in cases),
        "escalated_cases": sum(c.state.status == "escalated" for c in cases),
        "anchored_cases": sum(c.state.alert_id is not None for c in cases),
        "pending_sync": sum(c.state.queued for c in cases),
        "severity": severity,
        "signals": signals,
        "timeline": store.timeline(),
        "latest_tx_ts": store.latest_timestamp(),
        "last_block": store.get_meta("last_block"),
        "last_poll_ts": store.get_meta("last_poll_ts"),
        "server_time": int(time.time()),
    }


def _int_param(query: dict[str, list[str]], name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(query.get(name, [default])[0])))
    except ValueError:
        raise ApiError(HTTPStatus.BAD_REQUEST, f"{name} must be an integer") from None


def api_cases(store: Store, query: dict[str, list[str]]) -> dict[str, Any]:
    status = query.get("status", ["active"])[0]
    if status not in ("active", "all", *STATUSES):
        raise ApiError(HTTPStatus.BAD_REQUEST, "unknown status filter")
    min_score = _int_param(query, "min_score", 0, 0, 100)
    limit = _int_param(query, "limit", 200, 1, 500)
    needle = query.get("q", [""])[0].strip().lower()[:42]

    cases = build_cases(store.alerts_with_time(), store.all_case_states())
    out = []
    for c in cases:
        if status == "active" and c.state.status == "dismissed":
            continue
        if status in STATUSES and c.state.status != status:
            continue
        if c.top_score < min_score or (needle and needle not in c.subject):
            continue
        out.append(c.to_dict())
    return {"total": len(out), "cases": out[:limit]}


def _find_case(store: Store, subject: str):
    for c in build_cases(store.alerts_with_time(), store.all_case_states()):
        if c.subject == subject:
            return c
    raise ApiError(HTTPStatus.NOT_FOUND, "no case for that wallet")


def api_case_detail(store: Store, subject: str) -> dict[str, Any]:
    case = _find_case(store, subject)
    alerts = []
    for alert, tx in store.alerts_for_subject(subject, 15):
        try:
            reasons = json.loads(alert.explanation)
        except json.JSONDecodeError:
            reasons = []
        alerts.append(
            {
                "tx_hash": alert.tx_hash,
                "score": alert.risk_score,
                "timestamp": tx.timestamp,
                "value_eth": tx.value_eth,
                "sender": tx.sender,
                "receiver": tx.receiver,
                "reasons": reasons,
            }
        )
    recent = [
        {"tx_hash": t.tx_hash, "timestamp": t.timestamp, "value_eth": t.value_eth, "sender": t.sender, "receiver": t.receiver}
        for t in store.txs_for_wallet(subject, 10)
    ]
    return {
        "case": case.to_dict(),
        "typologies": for_reasons(case.reasons),
        "alerts": alerts,
        "recent_transfers": recent,
    }


def _clean_note(body: dict[str, Any]) -> str | None:
    note = body.get("note")
    if note is None:
        return None
    if not isinstance(note, str):
        raise ApiError(HTTPStatus.BAD_REQUEST, "note must be text")
    note = "".join(ch for ch in note if ch.isprintable()).strip()
    return note[:MAX_NOTE] or None


def api_set_status(ctx: AppContext, store: Store, subject: str, body: dict[str, Any]) -> dict[str, Any]:
    case = _find_case(store, subject)
    new = body.get("status")
    if new not in STATUSES or new == "open":
        raise ApiError(HTTPStatus.BAD_REQUEST, "status must be reviewed, escalated or dismissed")
    current = case.state.status
    if not can_transition(current, new):
        raise ApiError(HTTPStatus.CONFLICT, f"a {current} case cannot become {new}")
    store.set_case_status(subject, new, _clean_note(body), int(time.time()), queue_sync=case.state.alert_id is not None)
    sync_outbox(store, ctx.outbox_path)
    return {"case": _find_case(store, subject).to_dict()}


def api_set_queue(ctx: AppContext, store: Store, subject: str, body: dict[str, Any]) -> dict[str, Any]:
    _find_case(store, subject)
    queued = body.get("queued", True)
    if not isinstance(queued, bool):
        raise ApiError(HTTPStatus.BAD_REQUEST, "queued must be true or false")
    store.set_case_queued(subject, queued, int(time.time()))
    sync_outbox(store, ctx.outbox_path)
    return {"case": _find_case(store, subject).to_dict()}


def api_allowlist(ctx: AppContext, store: Store, subject: str, body: dict[str, Any]) -> dict[str, Any]:
    case = _find_case(store, subject)
    size = len(add_address(ctx.allowlist_path, subject))
    note = _clean_note(body) or "Allowlisted as known infrastructure"
    if can_transition(case.state.status, "dismissed"):
        store.set_case_status(subject, "dismissed", note, int(time.time()), queue_sync=case.state.alert_id is not None)
        sync_outbox(store, ctx.outbox_path)
    return {"case": _find_case(store, subject).to_dict(), "allowlist_size": size}


# ------------------------------------------------------------------- HTTP layer
def make_handler(ctx: AppContext) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "FraudMonitor"
        sys_version = ""

        # -- plumbing --------------------------------------------------------
        def log_message(self, fmt: str, *args: Any) -> None:  # route access logs through logging
            log.debug("%s - %s", self.address_string(), fmt % args)

        def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: HTTPStatus, payload: Any) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json; charset=utf-8")

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in ctx.allowed_hosts

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            return origin is None or origin in {f"http://{h}" for h in ctx.allowed_hosts}

        def _drain_body(self) -> None:
            """Discard (a bounded amount of) the unread request body before replying with an error.

            Closing a socket that still holds unread data makes Windows reset the connection, so
            the client would see a dropped connection instead of our error message.
            """
            try:
                remaining = min(max(int(self.headers.get("Content-Length", "0")), 0), MAX_DRAIN)
            except ValueError:
                return
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)

        def _read_body(self) -> dict[str, Any]:
            if self.headers.get("X-Requested-With") != "fetch":
                raise ApiError(HTTPStatus.FORBIDDEN, "missing X-Requested-With header")
            if not self._origin_ok():
                raise ApiError(HTTPStatus.FORBIDDEN, "cross-origin request refused")
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send application/json")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                raise ApiError(HTTPStatus.BAD_REQUEST, "bad Content-Length") from None
            if length > MAX_BODY:
                raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
            raw = self.rfile.read(length) if length else b"{}"
            self._body_read = True
            try:
                body = json.loads(raw.decode() or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid JSON") from None
            if not isinstance(body, dict):
                raise ApiError(HTTPStatus.BAD_REQUEST, "JSON object expected")
            return body

        def _dispatch(self, handler: Callable[[], tuple[HTTPStatus, Any]]) -> None:
            if not self._host_ok():
                if self.command == "POST":
                    self._drain_body()
                self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
                return
            try:
                status, payload = handler()
            except ApiError as err:
                if self.command == "POST" and not getattr(self, "_body_read", False):
                    self._drain_body()
                self._json(err.status, {"error": err.message})
                return
            except Exception:  # never leak internals to the client
                log.exception("unhandled error for %s", self.path)
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})
                return
            if isinstance(payload, tuple):  # static file: (bytes, content_type)
                self._send(status, payload[0], payload[1])
            else:
                self._json(status, payload)

        # -- verbs -----------------------------------------------------------
        def do_GET(self) -> None:
            self._dispatch(self._get)

        def do_POST(self) -> None:
            self._body_read = False
            self._dispatch(self._post)

        def _get(self) -> tuple[HTTPStatus, Any]:
            url = urlsplit(self.path)
            path, query = url.path, parse_qs(url.query)

            if path in STATIC_FILES:
                name, ctype = STATIC_FILES[path]
                return HTTPStatus.OK, ((WEB_DIR / name).read_bytes(), ctype)
            if path == "/favicon.ico":
                return HTTPStatus.NO_CONTENT, (b"", "image/x-icon")
            if path == "/api/config":
                return HTTPStatus.OK, api_config(ctx)

            store = ctx.open_store()
            try:
                if path == "/api/summary":
                    return HTTPStatus.OK, api_summary(ctx, store)
                if path == "/api/cases":
                    return HTTPStatus.OK, api_cases(store, query)
                m = _CASE_ROUTE.match(path)
                if m and m.group(2) is None:
                    return HTTPStatus.OK, api_case_detail(store, m.group(1).lower())
            finally:
                store.close()
            raise ApiError(HTTPStatus.NOT_FOUND, "not found")

        def _post(self) -> tuple[HTTPStatus, Any]:
            path = urlsplit(self.path).path
            m = _CASE_ROUTE.match(path)
            if not (m and m.group(2)):
                raise ApiError(HTTPStatus.NOT_FOUND, "not found")
            body = self._read_body()
            subject = m.group(1).lower()
            action = {"status": api_set_status, "queue": api_set_queue, "allowlist": api_allowlist}[m.group(2)]
            store = ctx.open_store()
            try:
                return HTTPStatus.OK, action(ctx, store, subject, body)
            finally:
                store.close()

    return Handler


def create_server(ctx: AppContext) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", ctx.port), make_handler(ctx))
    server.daemon_threads = True
    return server


def load_watchlist(ctx: AppContext) -> frozenset[str]:
    return load_address_file(ctx.watchlist_path)
