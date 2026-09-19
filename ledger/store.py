"""Persistent storage: blockchain and pending transaction set (JSON file).

The whole state lives in one JSON file written atomically (temp file plus
``os.replace`` plus an fsync of the file and its directory), which is
sufficient for a single-process ledger. A re-entrant lock guards state so the
threaded HTTP server serializes updates.

Blocks carry a lifecycle ``status`` (``confirmed`` or ``pending``): only the
chain tail may be pending, and at most one block may be pending at a time.
On startup the transaction index is rebuilt from confirmed blocks only, so
pending blocks and any orphaned transactions are excluded.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading

from .models import STATUS_CONFIRMED, Block, Transaction

# Previous hash of the genesis block.
GENESIS_PREV_HASH = "0" * 64


class LedgerStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self.chain: list[Block] = []
        self.pending: dict[str, Transaction] = {}
        # tx_id -> height of the confirmed block containing it. Rebuilt on
        # every load and kept in memory afterwards (the service updates it).
        self.tx_index: dict[str, int] = {}
        self._lock = threading.RLock()
        self.load()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def load(self) -> None:
        """Load state from disk, creating a genesis block on first start."""
        if not os.path.exists(self.path):
            self.chain = [self.create_genesis()]
            self.pending = {}
            self.rebuild_index()
            self.save()
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.chain = [Block.from_dict(b) for b in data.get("chain", [])]
        self.pending = {
            tx.tx_id: tx
            for tx in (Transaction.from_dict(t) for t in data.get("pending", []))
        }
        if not self.chain:
            self.chain = [self.create_genesis()]
        self.rebuild_index()

    def rebuild_index(self) -> None:
        """Rebuild the confirmed-transaction index from the loaded chain.

        Only confirmed blocks are indexed; pending blocks and any orphaned
        transactions below them are deliberately excluded.
        """
        index: dict[str, int] = {}
        for block in self.chain:
            if block.status != STATUS_CONFIRMED:
                break
            for tx in block.transactions:
                index[tx.tx_id] = block.height
        self.tx_index = index

    @staticmethod
    def create_genesis() -> Block:
        # The genesis block is always confirmed and carries no transactions.
        return Block.create(
            height=0,
            prev_hash=GENESIS_PREV_HASH,
            transactions=[],
            status=STATUS_CONFIRMED,
        )

    def save(self) -> None:
        """Atomically persist chain, pending set and derived index state."""
        data = {
            "chain": [block.to_dict() for block in self.chain],
            "pending": [tx.to_dict() for tx in self.pending.values()],
        }
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".ledger-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
            # Make the rename durable as well.
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def tip(self) -> Block:
        return self.chain[-1]

    def tip_hash(self) -> str:
        return self.chain[-1].block_hash

    def next_height(self) -> int:
        return self.chain[-1].height + 1
