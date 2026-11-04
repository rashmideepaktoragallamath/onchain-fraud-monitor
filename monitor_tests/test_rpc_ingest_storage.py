import urllib.error

import pytest

from monitor.ingest import CURSOR_KEY, Ingestor
from monitor.models import Alert, Tx, normalize_address
from monitor.rpc import JsonRpcClient, RpcError, parse_block, safe_url
from monitor.storage import Store

A = "0x" + "a" * 40
B = "0x" + "B" * 40  # mixed case on purpose


def raw_tx(n: int, value_wei: int = 10**18, to: str | None = B) -> dict:
    return {
        "hash": f"0x{n:064x}",
        "from": A,
        "to": to,
        "value": hex(value_wei),
        "nonce": hex(n),
        "gasPrice": hex(20 * 10**9),
    }


def raw_block(number: int, txs: list[dict]) -> dict:
    return {"number": hex(number), "timestamp": hex(1_700_000_000 + number), "transactions": txs}


# ---------------------------------------------------------------- rpc
def test_parse_block_keeps_eth_transfers_only():
    block = raw_block(5, [raw_tx(1), raw_tx(2, value_wei=0), raw_tx(3, to=None)])
    txs = parse_block(block)
    assert len(txs) == 1
    t = txs[0]
    assert t.sender == A and t.receiver == B.lower()  # normalised to lower-case
    assert t.value_eth == pytest.approx(1.0) and t.gas_price_gwei == pytest.approx(20.0)


def test_parse_block_drops_malformed_records():
    bad = raw_tx(1)
    bad["from"] = "0xnothex"
    assert parse_block(raw_block(5, [bad])) == []


def test_client_requires_https():
    with pytest.raises(ValueError):
        JsonRpcClient("http://example.com/rpc")
    JsonRpcClient("https://example.com/v2/KEY")
    JsonRpcClient("http://localhost:8545")  # local node is fine


def test_safe_url_hides_api_key():
    assert safe_url("https://eth-mainnet.g.alchemy.com/v2/SECRETKEY") == "https://eth-mainnet.g.alchemy.com"


def test_client_retries_then_succeeds():
    calls = {"n": 0}

    def flaky(payload):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("boom")
        return {"jsonrpc": "2.0", "id": payload["id"], "result": "0x10"}

    client = JsonRpcClient("https://x.example/KEY", transport=flaky, sleep=lambda _s: None)
    assert client.block_number() == 16 and calls["n"] == 3


def test_client_retries_when_response_is_cut_off_mid_download():
    """Regression: a large block whose download is cut short (IncompleteRead) must be retried."""
    import http.client

    calls = {"n": 0}

    def cut_off_once(payload):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http.client.IncompleteRead(b"partial", 260)
        return {"jsonrpc": "2.0", "id": payload["id"], "result": "0x2a"}

    client = JsonRpcClient("https://x.example/KEY", transport=cut_off_once, sleep=lambda _s: None)
    assert client.block_number() == 42 and calls["n"] == 2


def test_client_gives_up_without_leaking_key():
    def down(_payload):
        raise urllib.error.URLError("down")

    client = JsonRpcClient("https://x.example/SECRETKEY", transport=down, retries=2, sleep=lambda _s: None)
    with pytest.raises(RpcError) as err:
        client.block_number()
    assert "SECRETKEY" not in str(err.value)


def test_client_raises_on_rpc_error_reply():
    client = JsonRpcClient("https://x.example/K", transport=lambda p: {"error": {"code": -32000, "message": "nope"}})
    with pytest.raises(RpcError):
        client.block_number()


def test_normalize_address_rejects_garbage():
    assert normalize_address(B) == B.lower()
    for bad in ("0x123", "", None, "0x" + "g" * 40):
        with pytest.raises(ValueError):
            normalize_address(bad)


# ------------------------------------------------------------ storage
def make_tx(n: int, ts: int = 1000) -> Tx:
    return Tx(f"0x{n:064x}", 1, ts, A, B.lower(), 1.0, n)


def test_insert_is_idempotent():
    s = Store()
    assert s.insert_txs([make_tx(1), make_tx(2)]) == 2
    assert s.insert_txs([make_tx(1), make_tx(3)]) == 1  # duplicate ignored
    assert s.count_txs() == 3


def test_txs_since_filters_and_orders():
    s = Store()
    s.insert_txs([make_tx(1, 100), make_tx(2, 300), make_tx(3, 200)])
    assert [t.timestamp for t in s.txs_since(150)] == [200, 300]
    assert s.latest_timestamp() == 300


def test_alert_saved_once_per_transaction():
    s = Store()
    a = Alert("0x" + "1" * 64, A, 80, 3, "[]", 1)
    assert s.save_alert(a) is True
    assert s.save_alert(a) is False
    assert s.count_alerts() == 1 and s.list_alerts()[0].risk_score == 80


def test_sql_injection_attempt_is_inert():
    s = Store()
    s.set_meta("k'; DROP TABLE txs;--", "v")
    assert s.get_meta("k'; DROP TABLE txs;--") == "v"
    assert s.count_txs() == 0  # table still exists


# ------------------------------------------------------------- ingest
class FakeClient:
    def __init__(self, head: int):
        self.head = head
        self.fetched: list[int] = []

    def block_number(self):
        return self.head

    def get_block(self, n):
        self.fetched.append(n)
        return raw_block(n, [raw_tx(n)])


def test_ingest_resumes_from_cursor_without_gaps_or_repeats():
    store = Store()
    client = FakeClient(head=100)
    ing = Ingestor(client, store, start_back=3, max_per_poll=10)

    assert ing.poll() == 3  # blocks 98, 99, 100
    assert store.get_meta(CURSOR_KEY) == "100"

    client.head = 103
    client.fetched.clear()
    assert ing.poll() == 3
    assert client.fetched == [101, 102, 103]


def test_ingest_bounded_per_poll():
    store = Store()
    ing = Ingestor(FakeClient(head=1000), store, start_back=500, max_per_poll=5)
    assert ing.poll() == 5
    assert store.get_meta(CURSOR_KEY) == "505"
