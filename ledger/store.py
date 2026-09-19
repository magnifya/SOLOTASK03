"""Persistent storage: blockchain and pending transaction set (JSON file).

The whole state lives in one JSON file written atomically (temp file plus
``os.replace``), which is sufficient for a single-process ledger. A
re-entrant lock guards state so the threaded HTTP server serializes updates.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading

from .models import Block, Transaction

# Previous hash of the genesis block.
GENESIS_PREV_HASH = "0" * 64


class LedgerStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self.chain: list[Block] = []
        self.pending: dict[str, Transaction] = {}
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

    @staticmethod
    def create_genesis() -> Block:
        return Block.create(height=0, prev_hash=GENESIS_PREV_HASH, transactions=[])

    def save(self) -> None:
        """Atomically persist chain and pending transactions."""
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
            os.replace(tmp_path, self.path)
        except BaseException:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def tip_hash(self) -> str:
        return self.chain[-1].block_hash

    def next_height(self) -> int:
        return self.chain[-1].height + 1
