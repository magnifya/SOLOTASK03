"""Cryptographic helpers: Ed25519 verification, SHA-256 ids and Merkle roots."""
from __future__ import annotations

import hashlib
import hmac
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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


def generate_private_key() -> str:
    """Generate a fresh Ed25519 private seed as 64 lowercase hex chars."""
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


def derive_public_key(private_key_hex: str) -> str | None:
    """Derive the 64-hex Ed25519 public key from a 64-hex private seed.

    Returns None for malformed hex or a wrong-length seed rather than raising,
    so callers can treat every malformed key uniformly as a 400.
    """
    try:
        seed = bytes.fromhex(private_key_hex)
    except ValueError:
        return None
    if len(seed) != 32:
        return None
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return _public_hex(private_key)


def _public_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def sign_message(private_key_hex: str, message: bytes) -> str | None:
    """Sign ``message`` with an Ed25519 seed (64 hex chars); hex signature.

    Returns None for a malformed private key rather than raising.
    """
    try:
        seed = bytes.fromhex(private_key_hex)
    except ValueError:
        return None
    if len(seed) != 32:
        return None
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key.sign(message).hex()


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

# A 64-byte Ed25519 signature rendered as 128 lowercase hex characters.
_HEX128_RE = re.compile(r"[0-9a-f]{128}")

# Maximum Merkle depth we accept: 64 sibling levels already cover trees with up
# to 2**64 leaves, so a longer sibling path is necessarily malformed.
MAX_MERKLE_DEPTH = 64


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64_RE.fullmatch(value) is not None


def is_hex64(value: object) -> bool:
    """True iff ``value`` is a 64-char lowercase SHA-256 hex string."""
    return _is_hex64(value)


def is_hex128(value: object) -> bool:
    """True iff ``value`` is a 128-char lowercase Ed25519 signature hex string."""
    return isinstance(value, str) and _HEX128_RE.fullmatch(value) is not None


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


# -- account state Merkle tree ----------------------------------------------


def account_state_leaf(
    account: str, balance: int, confirmed_transactions: list[str]
) -> str:
    """SHA-256 leaf of one account's confirmed state.

    The leaf is ``sha256(utf8(JSON))`` of the canonical compact JSON document
    ``{"account":a,"balance":b,"confirmed_transactions":T}`` serialized with
    ``sort_keys=True``, ``ensure_ascii=False`` and ``separators=(",",":")``.
    ``T`` keeps its original (on-chain) order; ``sort_keys`` only orders the
    three top-level keys.
    """
    document = {
        "account": account,
        "balance": balance,
        "confirmed_transactions": confirmed_transactions,
    }
    raw = json.dumps(
        document, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return sha256_hex(raw)


def account_state_root(leaves: list[str]) -> str:
    """Merkle root of account-state leaves ordered by ascending account.

    Uses the same pairing rules as :func:`merkle_root` (hex-string pairs
    hashed ``sha256(left + right)``, a lone odd node paired with itself); an
    empty account set has the same root as an empty tx list.
    """
    return merkle_root(leaves)


def verify_account_proof(
    proof: object,
    expected_root: object,
    expected_height: object,
    expected_hash: object,
) -> bool:
    """Verify an account-state Merkle proof offline.

    Recomputes the account leaf from
    ``{account, balance, confirmed_transactions}``, walks the leaf-to-root
    ``siblings`` path, and requires the recomputed root to equal both the
    proof's ``state_root`` and ``expected_root``, while ``height`` /
    ``block_hash`` anchor the tree to the expected confirmed tip. Every
    malformed input — a non-64-char lowercase hex hash or anchor, an illegal
    direction, an illegal index, a malformed leaf/balance/transaction list, a
    path inconsistent with the index, excessive depth — returns False rather
    than raising.
    """
    try:
        if not isinstance(proof, dict):
            return False
        account = proof.get("account")
        balance = proof.get("balance")
        transactions = proof.get("confirmed_transactions")
        index = proof.get("index")
        state_root = proof.get("state_root")
        height = proof.get("height")
        block_hash = proof.get("block_hash")
        siblings = proof.get("siblings")

        if not isinstance(account, str) or not account:
            return False
        if isinstance(balance, bool) or not isinstance(balance, int) or balance < 0:
            return False
        if not isinstance(transactions, list):
            return False
        if any(not _is_hex64(tx_id) for tx_id in transactions):
            return False
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            return False
        if not isinstance(height, bool) and isinstance(height, int):
            if height < 0:
                return False
        else:
            return False
        if not _is_hex64(state_root):
            return False
        if not _is_hex64(block_hash) or not _is_hex64(expected_hash):
            return False
        if not _is_hex64(expected_root):
            return False
        if not isinstance(siblings, list) or len(siblings) > MAX_MERKLE_DEPTH:
            return False

        # The leaf is always recomputed from the proof's own triple; a
        # client-supplied leaf value is never trusted.
        depth = len(siblings)
        # A depth-D path addresses one of 2**D leaf slots; a single-leaf tree
        # (D == 0) can only ever be index 0. An index outside that range is
        # illegal regardless of any hashes the caller supplies.
        if index >= (1 << depth):
            return False
        current = account_state_leaf(account, balance, transactions)
        position = index
        for item in siblings:
            if not isinstance(item, dict):
                return False
            direction = item.get("direction")
            sibling_hash = item.get("hash")
            if not _is_hex64(sibling_hash):
                return False
            # The odd-node promotion pairs the last (even-positioned) node
            # with a copy of itself, so a genuine self-pair always points at a
            # right sibling. A left sibling equal to the current node addresses
            # the phantom duplicate slot, which is never a real account.
            if direction == "left" and sibling_hash == current:
                return False
            # The path must agree with the index: at every level an even
            # position is the left child (sibling on its right) and an odd
            # position the right child.
            if direction == "left":
                if position % 2 == 0:
                    return False
                pair = sibling_hash + current
            elif direction == "right":
                if position % 2 == 1:
                    return False
                pair = current + sibling_hash
            else:
                return False
            current = sha256_hex(pair.encode("ascii"))
            position //= 2

        if not hmac.compare_digest(current, state_root):
            return False
        if not hmac.compare_digest(current, expected_root):
            return False
        if height != expected_height:
            return False
        if not hmac.compare_digest(block_hash, expected_hash):
            return False
        return True
    except (TypeError, ValueError):
        return False
