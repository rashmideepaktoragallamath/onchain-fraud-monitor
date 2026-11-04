"""Minimal, dependency-free Ethereum JSON-RPC client (read-only).

Security notes
- HTTPS is mandatory (plain HTTP only for a local node on localhost).
- RPC URLs usually embed an API key, so only scheme+host is ever logged or put in errors.
- All data from the node is validated before it becomes a ``Tx``.
"""

from __future__ import annotations

import gzip
import http.client
import json
import time
import urllib.error
import urllib.request
import zlib
from typing import Any, Callable
from urllib.parse import urlparse

from monitor.models import ADDRESS_RE, TX_HASH_RE, Tx

Transport = Callable[[dict[str, Any]], dict[str, Any]]
WEI_PER_ETH = 10**18
GWEI = 10**9
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Errors worth retrying: dropped/short reads (full blocks can be ~0.5 MB), timeouts,
# truncated or corrupt compressed bodies and half-delivered JSON.
_TRANSIENT_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    OSError,
    http.client.HTTPException,  # includes IncompleteRead
    EOFError,
    zlib.error,
    json.JSONDecodeError,
)


class RpcError(RuntimeError):
    """Raised when the node returns an error or cannot be reached."""


def safe_url(url: str) -> str:
    """Strip path/query (where API keys live) from a URL for logging."""
    p = urlparse(url)
    return f"{p.scheme}://{p.hostname}"


class JsonRpcClient:
    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        retries: int = 3,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme == "https":
            pass
        elif parsed.scheme == "http" and parsed.hostname in _LOCAL_HOSTS:
            pass
        else:
            raise ValueError("RPC URL must be https:// (http:// allowed only for localhost)")
        self._url = url
        self._timeout = timeout
        self._retries = max(1, retries)
        self._sleep = sleep
        self._transport = transport or self._http_post
        self._id = 0

    def _http_post(self, payload: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            self._url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Accept-Encoding": "gzip"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 (scheme checked)
            body = resp.read()
            if resp.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
        return json.loads(body.decode())

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}
        last: Exception | None = None
        for attempt in range(self._retries):
            try:
                reply = self._transport(payload)
            except _TRANSIENT_ERRORS as exc:
                last = exc
                self._sleep(0.5 * 2**attempt)
                continue
            if "error" in reply:
                raise RpcError(f"{method} failed: {reply['error']}")
            return reply.get("result")
        raise RpcError(f"{method} unreachable at {safe_url(self._url)} after {self._retries} tries: {last}")

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def get_block(self, number: int) -> dict[str, Any] | None:
        return self.call("eth_getBlockByNumber", [hex(number), True])


def parse_block(block: dict[str, Any]) -> list[Tx]:
    """Convert a full block (transactions included) into validated ETH-transfer ``Tx`` rows.

    Skips contract creations (no ``to``) and zero-value calls: this prototype monitors
    native-ETH value movement only.
    """
    ts = int(block["timestamp"], 16)
    number = int(block["number"], 16)
    out: list[Tx] = []
    for t in block.get("transactions", []):
        to = t.get("to")
        value_wei = int(t["value"], 16)
        if to is None or value_wei == 0:
            continue
        if not (TX_HASH_RE.match(t["hash"]) and ADDRESS_RE.match(t["from"]) and ADDRESS_RE.match(to)):
            continue  # malformed record from the node: drop rather than trust
        price = t.get("gasPrice")
        out.append(
            Tx(
                tx_hash=t["hash"].lower(),
                block_number=number,
                timestamp=ts,
                sender=t["from"].lower(),
                receiver=to.lower(),
                value_eth=value_wei / WEI_PER_ETH,
                nonce=int(t["nonce"], 16),
                gas_price_gwei=int(price, 16) / GWEI if price else 0.0,
            )
        )
    return out
