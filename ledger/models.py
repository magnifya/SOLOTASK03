"""数据模型：交易、区块，以及确定性的序列化与哈希工具。

约定：
- 待签名报文 canonical_message = b"<from>|<to>|<amount>"
- tx_id = sha256(报文 + 十六进制签名)，使不同签名得到不同 id
- Merkle 树奇数节点复制最后一个；单子节点的根即其自身
- 区块哈希 = sha256(确定性 JSON 的区块头)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import List


def canonical_message(sender: str, recipient: str, amount: int) -> bytes:
    """交易的待签名报文。确定性，不含签名本身。"""
    return f"{sender}|{recipient}|{amount}".encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def merkle_root(tx_ids: List[str]) -> str:
    """对 tx_id 序列计算 Merkle 根。

    每层相邻两项配对取 sha256(left+right)；奇数个时复制最后一项；
    单子节点直接上移。空列表返回空串。
    """
    if not tx_ids:
        return ""
    level = list(tx_ids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_sha256_hex((level[i] + level[i + 1]).encode("ascii")))
        level = nxt
    return level[0]


def compute_block_hash(height: int, prev_hash: str, merkle: str, tx_ids: List[str]) -> str:
    """根据区块头与交易 id 列表（按打包顺序）计算区块哈希。"""
    header = {
        "height": height,
        "prev_hash": prev_hash,
        "merkle_root": merkle,
        "transaction_ids": list(tx_ids),
    }
    blob = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_hex(blob)


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    signature: str
    tx_id: str

    @staticmethod
    def make_id(sender: str, recipient: str, amount: int, signature: str) -> str:
        data = canonical_message(sender, recipient, amount) + signature.encode("ascii")
        return _sha256_hex(data)

    def signing_message(self) -> bytes:
        return canonical_message(self.sender, self.recipient, self.amount)

    def to_dict(self) -> dict:
        return {
            "from": self.sender,
            "to": self.recipient,
            "amount": self.amount,
            "signature": self.signature,
            "tx_id": self.tx_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "Transaction":
        return Transaction(
            sender=d["from"],
            recipient=d["to"],
            amount=int(d["amount"]),
            signature=d["signature"],
            tx_id=d["tx_id"],
        )


@dataclass
class Block:
    height: int
    prev_hash: str
    merkle_root: str
    block_hash: str
    transaction_ids: List[str] = field(default_factory=list)
    transactions: List[Transaction] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "height": self.height,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "block_hash": self.block_hash,
            "transaction_ids": list(self.transaction_ids),
            "transactions": [t.to_dict() for t in self.transactions],
        }

    @staticmethod
    def from_dict(d: dict) -> "Block":
        return Block(
            height=int(d["height"]),
            prev_hash=d["prev_hash"],
            merkle_root=d["merkle_root"],
            block_hash=d["block_hash"],
            transaction_ids=list(d.get("transaction_ids", [])),
            transactions=[Transaction.from_dict(t) for t in d.get("transactions", [])],
        )
