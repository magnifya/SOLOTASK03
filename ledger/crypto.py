"""Cryptographic helpers: Ed25519 verification, SHA-256 ids and Merkle roots."""
from __future__ import annotations

import hashlib
import hmac
import json
import re

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


# Previous hash of the first event in the append-only audit hash chain.
AUDIT_GENESIS_PREV_HASH = "0" * 64


def audit_event_payload(event: dict) -> dict:
    """Event object with the two hash-link fields removed.

    ``prev_hash`` and ``event_hash`` are the chaining envelope; everything
    else (event_id, kind, at and the event payload) is covered by the hash.
    """
    return {key: value for key, value in event.items()
            if key not in ("prev_hash", "event_hash")}


def audit_event_hash(prev_hash: str, event: dict) -> str:
    """Hash of one audit event in the append-only chain.

    ``event_hash = sha256(prev_hash ASCII || event-without-the-two-hash-fields
    serialized as sorted-key compact UTF-8 JSON)``.
    """
    payload = json.dumps(
        audit_event_payload(event),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(prev_hash.encode("ascii") + payload).hexdigest()


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


# A SHA-256 digest rendered as 64 lowercase hexadecimal characters.
_HEX64_RE = re.compile(r"[0-9a-f]{64}")

# Maximum Merkle depth we accept: 64 sibling levels already cover trees with up
# to 2**64 leaves, so a longer sibling path is necessarily malformed.
MAX_MERKLE_DEPTH = 64


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64_RE.fullmatch(value) is not None


def is_hex64(value: object) -> bool:
    """True iff ``value`` is a 64-char lowercase SHA-256 hex string."""
    return _is_hex64(value)


def merkle_proof(tx_ids: list[str], index: int) -> list[dict]:
    """Sibling path from the leaf at ``index`` up to the Merkle root.

    Mirrors :func:`merkle_root`: levels hash ``sha256(left + right)`` hex pairs
    and a lone odd node is paired with itself. Each returned item has a
    ``direction`` ("left" or "right") recording which side the *sibling* sits
    on relative to the path node, and the sibling's ``hash``. Items are ordered
    from the leaf level toward the root. Raises ValueError for an empty list or
    an out-of-range index.
    """
    if not tx_ids:
        raise ValueError("cannot build a Merkle proof for an empty tree")
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError("index must be an integer")
    if index < 0 or index >= len(tx_ids):
        raise ValueError("transaction index out of range")

    level = list(tx_ids)
    position = index
    siblings: list[dict] = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if position % 2 == 0:
            # Path node is the left child; sibling sits on its right.
            siblings.append({"direction": "right", "hash": level[position + 1]})
        else:
            # Path node is the right child; sibling sits on its left.
            siblings.append({"direction": "left", "hash": level[position - 1]})
        level = [
            sha256_hex((level[i] + level[i + 1]).encode("ascii"))
            for i in range(0, len(level), 2)
        ]
        position //= 2
    return siblings


def verify_merkle_proof(
    tx_id: str,
    siblings: list[dict],
    merkle_root: str,
    block_hash: str,
    expected_block_hash: str,
) -> bool:
    """Verify a Merkle proof and bind it to a specific block hash.

    Re-hashes the leaf (``tx_id``) with the sibling path from leaf to root and
    compares the result with ``merkle_root``; ``block_hash`` must additionally
    equal ``expected_block_hash``. Every malformed input (non-64-char lowercase
    hex hash, illegal direction, non-list path, excessive depth) and every
    mismatch returns False rather than raising.
    """
    try:
        if not _is_hex64(tx_id):
            return False
        if not _is_hex64(merkle_root):
            return False
        if not _is_hex64(block_hash) or not _is_hex64(expected_block_hash):
            return False
        if not isinstance(siblings, list) or len(siblings) > MAX_MERKLE_DEPTH:
            return False

        current = tx_id
        for item in siblings:
            if not isinstance(item, dict):
                return False
            direction = item.get("direction")
            sibling_hash = item.get("hash")
            if not _is_hex64(sibling_hash):
                return False
            if direction == "left":
                pair = sibling_hash + current
            elif direction == "right":
                pair = current + sibling_hash
            else:
                return False
            current = sha256_hex(pair.encode("ascii"))

        if not hmac.compare_digest(current, merkle_root):
            return False
        if not hmac.compare_digest(block_hash, expected_block_hash):
            return False
        return True
    except (TypeError, ValueError):
        return False
