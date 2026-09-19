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
