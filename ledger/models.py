"""Data models for transactions and blocks."""
from __future__ import annotations

import json
from dataclasses import dataclass

from . import crypto

# Block lifecycle states for the confirm/rollback state machine.
STATUS_PENDING = "pending"
STATUS_CONFIRMED = "confirmed"
BLOCK_STATUSES = (STATUS_PENDING, STATUS_CONFIRMED)


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
    status: str = STATUS_CONFIRMED

    @classmethod
    def create(
        cls,
        height: int,
        prev_hash: str,
        transactions: list[Transaction],
        status: str = STATUS_CONFIRMED,
    ) -> "Block":
        if status not in BLOCK_STATUSES:
            raise ValueError(f"unknown block status: {status}")
        ordered = sorted(transactions, key=lambda tx: tx.tx_id)
        merkle = crypto.merkle_root([tx.tx_id for tx in ordered])
        block_hash = compute_block_hash(height, prev_hash, merkle)
        return cls(
            height=height,
            prev_hash=prev_hash,
            merkle_root=merkle,
            transactions=ordered,
            block_hash=block_hash,
            status=status,
        )

    def to_dict(self) -> dict:
        return {
            "height": self.height,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "block_hash": self.block_hash,
            "status": self.status,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        # State files written before the status machine existed have no
        # "status" key; every block in such a file was final, so they load
        # as confirmed.
        status = data.get("status", STATUS_CONFIRMED)
        if status not in BLOCK_STATUSES:
            raise ValueError(f"unknown block status: {status}")
        return cls(
            height=int(data["height"]),
            prev_hash=data["prev_hash"],
            merkle_root=data["merkle_root"],
            block_hash=data["block_hash"],
            transactions=[Transaction.from_dict(t) for t in data["transactions"]],
            status=status,
        )

    def to_summary(self) -> dict:
        """Response shape for GET /v1/blocks/{height}."""
        return {
            "height": self.height,
            "block_hash": self.block_hash,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "status": self.status,
            "transaction_ids": [tx.tx_id for tx in self.transactions],
        }


@dataclass
class SyncRecord:
    """A candidate chain received from a peer via POST /v1/forks/sync.

    The sync metadata (source peer, client-supplied idempotency key and expiry
    instant) is persisted atomically together with the full, re-validated
    candidate block list.
    """

    source: str
    request_id: str
    expires_at: int
    blocks: list[Block]

    @property
    def key(self) -> tuple[str, str]:
        return (self.source, self.request_id)

    @property
    def tip_hash(self) -> str:
        return self.blocks[-1].block_hash

    def metadata_dict(self) -> dict:
        """The metadata fields persisted alongside the candidate blocks."""
        return {
            "source": self.source,
            "request_id": self.request_id,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict:
        """Storage shape: metadata plus the full candidate block list."""
        data = self.metadata_dict()
        data["blocks"] = [block.to_dict() for block in self.blocks]
        return data

    def descriptor(self) -> dict:
        """Public descriptor returned by the sync endpoints."""
        tip = self.blocks[-1]
        return {
            "source": self.source,
            "request_id": self.request_id,
            "tip_hash": tip.block_hash,
            "height": tip.height,
            "length": len(self.blocks),
            "status": tip.status,
            "expires_at": self.expires_at,
        }
