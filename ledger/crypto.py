"""Cryptographic helpers: Ed25519 verification, SHA-256 ids and Merkle roots."""
from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_message(sender: str, recipient: str, amount: int) -> bytes:
    """Deterministic byte representation of a transaction payload.

    The payload is serialized as compact JSON with sorted keys so the same
    (from, to, amount) triple always yields identical bytes on every client.
    """
    payload = {"amount": amount, "from": sender, "to": recipient}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_tx_id(message: bytes) -> str:
    """SHA-256 hex digest of the canonical transaction message."""
    return sha256_hex(message)


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify an Ed25519 signature (public key and signature are hex strings).

    Returns False for malformed hex or wrong key/signature lengths rather than
    raising, so callers can treat every verification failure uniformly.
    """
    try:
        public_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(public_bytes) != 32 or len(signature_bytes) != 64:
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature_bytes, message)
    except (InvalidSignature, ValueError):
        return False
    return True


# Merkle root of an empty transaction list; fixed so genesis blocks are identical.
EMPTY_MERKLE_ROOT = sha256_hex(b"")


def merkle_root(tx_ids: list[str]) -> str:
    """SHA-256 Merkle root of the given tx ids.

    Levels are built by hashing ``sha256(left + right)`` hex-string pairs;
    a lone odd node at a level is promoted by pairing it with itself.
    Callers normally pass ids already sorted ascending.
    """
    if not tx_ids:
        return EMPTY_MERKLE_ROOT
    level = list(tx_ids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            sha256_hex((level[i] + level[i + 1]).encode("ascii"))
            for i in range(0, len(level), 2)
        ]
    return level[0]


def _is_hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def is_tx_id_format(value: object) -> bool:
    """True if ``value`` looks like a SHA-256 hex transaction id."""
    return _is_hex64(value)


def merkle_proof(tx_ids: list[str], index: int) -> list[dict]:
    """Merkle proof for the leaf at ``index``, ordered leaf-to-root.

    Each entry is ``{"direction": "left"|"right", "hash": <64-hex>}`` and
    tells where the sibling node sits relative to the running hash: "left"
    means the sibling is hashed on the left (``sha256(sibling + current)``),
    "right" means it is hashed on the right. A lone odd node is paired with
    itself, mirroring :func:`merkle_root`.

    Raises ValueError if ``index`` is out of range.
    """
    if not tx_ids or not isinstance(index, int) or isinstance(index, bool):
        raise ValueError("index out of range")
    if index < 0 or index >= len(tx_ids):
        raise ValueError("index out of range")
    proof: list[dict] = []
    level = list(tx_ids)
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling = idx + 1 if idx % 2 == 0 else idx - 1
        proof.append(
            {
                "direction": "right" if idx % 2 == 0 else "left",
                "hash": level[sibling],
            }
        )
        level = [
            sha256_hex((level[i] + level[i + 1]).encode("ascii"))
            for i in range(0, len(level), 2)
        ]
        idx //= 2
    return proof


def verify_merkle_proof(
    tx_id: object,
    siblings: object,
    merkle_root: object,
    block_hash: object,
    expected_block_hash: object,
) -> bool:
    """Verify a Merkle proof produced by :func:`merkle_proof`.

    Recomputes the root from ``tx_id`` and ``siblings`` and compares it with
    ``merkle_root``; ``block_hash`` must equal ``expected_block_hash``.
    Returns False for any mismatch or malformed input (bad direction, hash
    not 64 lowercase hex chars, non-list siblings, etc.) — never raises.
    """
    if not _is_hex64(tx_id):
        return False
    if not _is_hex64(merkle_root):
        return False
    if not _is_hex64(block_hash) or not _is_hex64(expected_block_hash):
        return False
    if block_hash != expected_block_hash:
        return False
    if not isinstance(siblings, (list, tuple)):
        return False
    current = tx_id
    for item in siblings:
        if not isinstance(item, dict):
            return False
        direction = item.get("direction")
        sibling_hash = item.get("hash")
        if direction not in ("left", "right"):
            return False
        if not _is_hex64(sibling_hash):
            return False
        if direction == "left":
            current = sha256_hex((sibling_hash + current).encode("ascii"))
        else:
            current = sha256_hex((current + sibling_hash).encode("ascii"))
    return current == merkle_root
