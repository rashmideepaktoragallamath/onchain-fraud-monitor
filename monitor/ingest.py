"""Live ingestion: poll new blocks from an Ethereum RPC into the local store."""

from __future__ import annotations

import logging

from monitor.rpc import JsonRpcClient, parse_block
from monitor.storage import Store

log = logging.getLogger(__name__)
CURSOR_KEY = "last_block"


class Ingestor:
    """Remembers the last block it stored, so restarts neither skip nor repeat blocks."""

    def __init__(self, client: JsonRpcClient, store: Store, *, start_back: int = 25, max_per_poll: int = 25) -> None:
        self._client = client
        self._store = store
        self._start_back = start_back
        self._max_per_poll = max_per_poll

    def poll(self) -> int:
        """Fetch any new blocks (bounded per call). Returns the number of new transactions stored."""
        head = self._client.block_number()
        cursor = self._store.get_meta(CURSOR_KEY)
        last = int(cursor) if cursor is not None else head - self._start_back
        end = min(head, last + self._max_per_poll)

        stored = 0
        for number in range(last + 1, end + 1):
            block = self._client.get_block(number)
            if block is None:  # node has not served this block yet; retry next poll
                break
            stored += self._store.insert_txs(parse_block(block))
            self._store.set_meta(CURSOR_KEY, str(number))
        log.info("ingested up to block %s (head %s), %s new transfers", end, head, stored)
        return stored
