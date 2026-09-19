"""Data models for transactions and blocks."""
from __future__ import annotations

import json
from dataclasses import dataclass

from . import crypto


@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    signature: str

    @property
    def message(self) -> bytes:
        return crypto.canonical_message(self.sender, self.recipient, self.amount)

    @property
    def tx_id(self) -> str:
        return crypto.compute_tx_id(self.message)

    def to_dict(self) -> dict:
        """JSON-safe representation used both for storage and API output."""
        return {
            "from": self.sender,
            "to": self.recipient,
            "amount": self.amount,
            "signature": self.signature,
            "tx_id": self.tx_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        return cls(
            sender=data["from"],
            recipient=data["to"],
            amount=int(data["amount"]),
            signature=data["signature"],
        )


def block_header_bytes(height: int, prev_hash: str, merkle: str) -> bytes:
    """Deterministic serialization of the fields covered by the block hash.

    No timestamp is included: a block with the same parent and the same ordered
    transactions must always hash identically.
    """
    header = {"height": height, "merkle_root": merkle, "prev_hash": prev_hash}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_block_hash(height: int, prev_hash: str, merkle: str) -> str:
    return crypto.sha256_hex(block_header_bytes(height, prev_hash, merkle))


@dataclass
class Block:
    height: int
    prev_hash: str
    merkle_root: str
    transactions: list[Transaction]
    block_hash: str

    @classmethod
    def create(
        cls, height: int, prev_hash: str, transactions: list[Transaction]
    ) -> "Block":
        ordered = sorted(transactions, key=lambda tx: tx.tx_id)
        merkle = crypto.merkle_root([tx.tx_id for tx in ordered])
        block_hash = compute_block_hash(height, prev_hash, merkle)
        return cls(
            height=height,
            prev_hash=prev_hash,
            merkle_root=merkle,
            transactions=ordered,
            block_hash=block_hash,
        )

    def to_dict(self) -> dict:
        return {
            "height": self.height,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "block_hash": self.block_hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        return cls(
            height=int(data["height"]),
            prev_hash=data["prev_hash"],
            merkle_root=data["merkle_root"],
            block_hash=data["block_hash"],
            transactions=[Transaction.from_dict(t) for t in data["transactions"]],
        )

    def to_summary(self) -> dict:
        """Response shape for GET /v1/blocks/{height}."""
        return {
            "height": self.height,
            "block_hash": self.block_hash,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "transaction_ids": [tx.tx_id for tx in self.transactions],
        }
