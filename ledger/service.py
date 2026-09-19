"""账本业务逻辑：提交交易、打包区块、查询。

所有方法返回 (HTTP 状态码, 响应体 dict)，与传输层无关。
"""
from __future__ import annotations

from typing import Optional, Tuple

from .crypto import verify_signature
from .models import (
    Block,
    Transaction,
    compute_block_hash,
    merkle_root,
)
from .store import Store

REQUIRED_FIELDS = ("from", "to", "amount", "signature")


class LedgerService:
    def __init__(self, store: Store) -> None:
        self.store = store

    # ---------- 交易 ----------
    def submit_transaction(self, payload: dict) -> Tuple[int, dict]:
        if not isinstance(payload, dict):
            return 400, {"error": "请求体必须是 JSON 对象"}

        for field_name in REQUIRED_FIELDS:
            if field_name not in payload:
                return 400, {"error": f"缺少必填字段: {field_name}"}

        sender = payload["from"]
        recipient = payload["to"]
        amount = payload["amount"]
        signature = payload["signature"]

        if not isinstance(sender, str) or not sender:
            return 400, {"error": "字段 from 必须是非空字符串"}
        if not isinstance(recipient, str) or not recipient:
            return 400, {"error": "字段 to 必须是非空字符串"}
        if isinstance(amount, bool) or not isinstance(amount, int):
            return 400, {"error": "字段 amount 必须是整数"}
        if amount <= 0:
            return 400, {"error": "字段 amount 必须是正整数"}
        if not isinstance(signature, str) or not signature:
            return 400, {"error": "字段 signature 必须是非空十六进制字符串"}

        tx_id = Transaction.make_id(sender, recipient, amount, signature)

        # 已在内存池中的同一交易幂等返回
        if any(t.tx_id == tx_id for t in self.store.mempool_txs()):
            return 202, {"tx_id": tx_id}

        message = Transaction(sender, recipient, amount, signature, tx_id).signing_message()
        if not verify_signature(sender, message, signature):
            return 400, {"error": "签名不合法"}

        balances = self.store.balances()
        confirmed = balances.get(sender, 0)
        pending_out = sum(
            t.amount for t in self.store.mempool_txs() if t.sender == sender
        )
        if confirmed - pending_out < amount:
            return 400, {
                "error": "余额不足",
                "balance": confirmed,
                "pending_spent": pending_out,
            }

        tx = Transaction(sender, recipient, amount, signature, tx_id)
        self.store.add_mempool_tx(tx)
        return 202, {"tx_id": tx_id}

    # ---------- 打包 ----------
    def mine_block(self) -> Tuple[int, dict]:
        pending = self.store.mempool_txs()
        if not pending:
            return 409, {"error": "没有待打包交易"}

        ordered = sorted(pending, key=lambda t: t.tx_id)
        tx_ids = [t.tx_id for t in ordered]

        top = self.store.latest_height()
        prev_block = self.store.get_block(top)
        prev_hash = prev_block.block_hash if prev_block else "0" * 64
        height = top + 1

        merkle = merkle_root(tx_ids)
        block_hash = compute_block_hash(height, prev_hash, merkle, tx_ids)
        block = Block(
            height=height,
            prev_hash=prev_hash,
            merkle_root=merkle,
            block_hash=block_hash,
            transaction_ids=tx_ids,
            transactions=ordered,
        )
        self.store.save_block(block)
        self.store.clear_mempool(tx_ids)
        return 201, {
            "height": height,
            "block_hash": block_hash,
            "merkle_root": merkle,
        }

    # ---------- 查询 ----------
    def get_block(self, height: int) -> Tuple[int, dict]:
        block = self.store.get_block(height)
        if block is None:
            return 404, {"error": f"区块不存在: height={height}"}
        return 200, {
            "height": block.height,
            "block_hash": block.block_hash,
            "prev_hash": block.prev_hash,
            "merkle_root": block.merkle_root,
            "transaction_ids": list(block.transaction_ids),
        }

    def get_account(self, account: str) -> Tuple[int, dict]:
        if account not in self.store.known_accounts():
            return 404, {"error": f"账户不存在: {account}"}
        balance = self.store.balances().get(account, 0)
        return 200, {
            "account": account,
            "balance": balance,
            "confirmed_transactions": self.store.confirmed_transactions(account),
        }
