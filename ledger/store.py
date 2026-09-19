"""Persistent storage: blockchain, pending set and derived indexes (JSON file).

The whole state lives in one JSON file written atomically (temp file plus
``os.replace``), which is sufficient for a single-process ledger. A
re-entrant lock guards state so the threaded HTTP server serializes updates.

One atomic write persists everything: the chain (each block carries its
confirm/rollback ``status``), a small ``state`` summary, the mempool
(``pending``), the confirmed-transaction ``index`` and the confirmed
``accounts`` activity. Derived data (index/accounts) is *rebuilt* from the
chain on every load and every save — pending blocks are excluded, so a
restart never resurrects unconfirmed transactions into balances, and the
prev-hash linkage is validated so no orphan blocks can sneak in.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading

from .models import STATUS_CONFIRMED, STATUS_PENDING, Block, Transaction

# Previous hash of the genesis block.
GENESIS_PREV_HASH = "0" * 64

# On-disk schema version, stored under "state" so future migrations are possible.
STATE_VERSION = 2


class LedgerStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self.chain: list[Block] = []
        self.pending: dict[str, Transaction] = {}
        # Derived, confirmed-only views; rebuilt by rebuild_derived().
        self.tx_index: dict[str, int] = {}
        self.accounts: dict[str, dict] = {}
        self._lock = threading.RLock()
        self.load()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def load(self) -> None:
        """Load state from disk, creating a genesis block on first start.

        Derived indexes are always rebuilt from the chain (pending blocks
        excluded) rather than trusted from disk, and the chain linkage is
        validated so no orphan blocks survive a restart.
        """
        if not os.path.exists(self.path):
            self.chain = [self.create_genesis()]
            self.pending = {}
            self.rebuild_derived()
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
        self._validate_linkage()
        self.rebuild_derived()

    def _validate_linkage(self) -> None:
        """Ensure heights are consecutive and every prev_hash matches its parent."""
        for i, block in enumerate(self.chain):
            if block.height != i:
                raise ValueError(
                    f"orphan block: height {block.height} at chain position {i}"
                )
            expected_prev = GENESIS_PREV_HASH if i == 0 else self.chain[i - 1].block_hash
            if block.prev_hash != expected_prev:
                raise ValueError(f"orphan block at height {block.height}: prev_hash mismatch")

    @staticmethod
    def create_genesis() -> Block:
        # The genesis block is born confirmed.
        return Block.create(
            height=0,
            prev_hash=GENESIS_PREV_HASH,
            transactions=[],
            status=STATUS_CONFIRMED,
        )

    def rebuild_derived(self) -> None:
        """Rebuild the confirmed-only transaction index and account activity.

        Pending blocks are excluded: only confirmed blocks contribute to
        balances and to the tx_id -> height index.
        """
        self.tx_index = {}
        self.accounts = {}
        for block in self.chain:
            if block.status != STATUS_CONFIRMED:
                continue
            for tx in block.transactions:
                self.tx_index[tx.tx_id] = block.height
                for account in (tx.sender, tx.recipient):
                    entry = self.accounts.setdefault(
                        account, {"sent": 0, "received": 0, "transactions": []}
                    )
                    entry["transactions"].append(tx.tx_id)
                self.accounts[tx.sender]["sent"] += tx.amount
                self.accounts[tx.recipient]["received"] += tx.amount

    def save(self) -> None:
        """Atomically persist chain, state, pending set, index and accounts."""
        self.rebuild_derived()
        data = {
            "state": {
                "version": STATE_VERSION,
                "height": self.chain[-1].height,
                "tip_hash": self.chain[-1].block_hash,
                "tip_status": self.chain[-1].status,
            },
            "chain": [block.to_dict() for block in self.chain],
            "pending": [tx.to_dict() for tx in self.pending.values()],
            "index": dict(self.tx_index),
            "accounts": self.accounts,
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

    # -- chain helpers --------------------------------------------------------

    def tip(self) -> Block:
        return self.chain[-1]

    def tip_hash(self) -> str:
        return self.chain[-1].block_hash

    def next_height(self) -> int:
        return self.chain[-1].height + 1

    def tip_is_pending(self) -> bool:
        return self.chain[-1].status == STATUS_PENDING

    def block_at(self, height: int) -> Block | None:
        if 0 <= height < len(self.chain) and self.chain[height].height == height:
            return self.chain[height]
        return None

    def rollback_tip(self) -> Block:
        """Remove the pending tip block and return its transactions to the mempool.

        Transactions are restored de-duplicated: an id already present in the
        pending set (resubmitted while the block was unconfirmed) is kept as
        is, not overwritten. Caller must hold the lock and must have checked
        that the tip is a pending block. Does not save; callers persist.
        """
        block = self.chain.pop()
        for tx in block.transactions:
            self.pending.setdefault(tx.tx_id, tx)
        return block
