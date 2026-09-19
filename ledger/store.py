"""持久化存储与账本状态。

布局（均为确定性 JSON，原子写）：
- block_{height:08d}.json  每个区块一个文件
- mempool.json             待打包交易
- genesis.json             创世余额 {account: amount}

余额由创世余额重放全部已确认交易得到。
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Dict, List, Optional

from .models import Block, Transaction

GENESIS_PREV_HASH = "0" * 64


class Store:
    def __init__(self, data_dir: str, genesis_balances: Optional[Dict[str, int]] = None) -> None:
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._genesis_path = os.path.join(self.data_dir, "genesis.json")
        self._mempool_path = os.path.join(self.data_dir, "mempool.json")
        self._genesis_balances = self._load_genesis(genesis_balances)
        if not os.path.exists(self._block_path(0)):
            self._create_genesis_block()

    # ---------- 基础 ----------
    def _block_path(self, height: int) -> str:
        return os.path.join(self.data_dir, f"block_{height:08d}.json")

    def _atomic_write_json(self, path: str, obj) -> None:
        directory = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, sort_keys=True, ensure_ascii=False)
                fh.write("\n")
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def _load_genesis(self, genesis_balances: Optional[Dict[str, int]]) -> Dict[str, int]:
        with self._lock:
            if os.path.exists(self._genesis_path):
                with open(self._genesis_path, "r", encoding="utf-8") as fh:
                    balances = json.load(fh)
                return {str(k): int(v) for k, v in balances.items()}
            balances = {str(k): int(v) for k, v in (genesis_balances or {}).items()}
            self._atomic_write_json(self._genesis_path, balances)
            return dict(balances)

    def _create_genesis_block(self) -> None:
        from .models import compute_block_hash, merkle_root

        ids: List[str] = []
        merkle = merkle_root(ids)
        block_hash = compute_block_hash(0, GENESIS_PREV_HASH, merkle, ids)
        block = Block(
            height=0,
            prev_hash=GENESIS_PREV_HASH,
            merkle_root=merkle,
            block_hash=block_hash,
            transaction_ids=ids,
            transactions=[],
        )
        self.save_block(block)

    # ---------- 区块 ----------
    def save_block(self, block: Block) -> None:
        with self._lock:
            self._atomic_write_json(self._block_path(block.height), block.to_dict())

    def get_block(self, height: int) -> Optional[Block]:
        with self._lock:
            path = self._block_path(height)
            if not os.path.exists(path):
                return None
            with open(path, "r", encoding="utf-8") as fh:
                return Block.from_dict(json.load(fh))

    def latest_height(self) -> int:
        with self._lock:
            height = -1
            for name in os.listdir(self.data_dir):
                if name.startswith("block_") and name.endswith(".json"):
                    try:
                        height = max(height, int(name[len("block_"):-len(".json")]))
                    except ValueError:
                        continue
            return height

    def iter_blocks(self) -> List[Block]:
        """按高度升序返回全部区块（含创世区块）。"""
        with self._lock:
            top = self.latest_height()
            blocks = []
            for height in range(0, top + 1):
                block = self.get_block(height)
                if block is not None:
                    blocks.append(block)
            return blocks

    # ---------- 内存池 ----------
    def add_mempool_tx(self, tx: Transaction) -> None:
        with self._lock:
            txs = self.mempool_txs()
            txs = [t for t in txs if t.tx_id != tx.tx_id]
            txs.append(tx)
            self._atomic_write_json(
                self._mempool_path, [t.to_dict() for t in txs]
            )

    def mempool_txs(self) -> List[Transaction]:
        with self._lock:
            if not os.path.exists(self._mempool_path):
                return []
            with open(self._mempool_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return [Transaction.from_dict(d) for d in data]

    def clear_mempool(self, tx_ids: List[str]) -> None:
        with self._lock:
            remove = set(tx_ids)
            remaining = [t for t in self.mempool_txs() if t.tx_id not in remove]
            self._atomic_write_json(
                self._mempool_path, [t.to_dict() for t in remaining]
            )

    # ---------- 账户 ----------
    def known_accounts(self) -> set:
        with self._lock:
            accounts = set(self._genesis_balances.keys())
            for block in self.iter_blocks():
                for tx in block.transactions:
                    accounts.add(tx.sender)
                    accounts.add(tx.recipient)
            return accounts

    def confirmed_transactions(self, account: str) -> List[str]:
        """按确认顺序返回与该账户相关的已确认 tx_id。"""
        with self._lock:
            result = []
            for block in self.iter_blocks():
                for tx in block.transactions:
                    if tx.sender == account or tx.recipient == account:
                        result.append(tx.tx_id)
            return result

    def balances(self) -> Dict[str, int]:
        """重放创世余额与全部区块得到各账户余额。"""
        with self._lock:
            balances: Dict[str, int] = dict(self._genesis_balances)
            for block in self.iter_blocks():
                for tx in block.transactions:
                    balances[tx.sender] = balances.get(tx.sender, 0) - tx.amount
                    balances[tx.recipient] = balances.get(tx.recipient, 0) + tx.amount
            return balances
