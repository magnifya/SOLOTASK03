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


def _hash_merkle_path(leaf: str, siblings: list[dict]) -> str | None:
    """Hash a leaf up through a leaf-to-root sibling path.

    Returns the recomputed root, or None when the path is not a list, is
    deeper than :data:`MAX_MERKLE_DEPTH`, contains a non-dict entry, an
    illegal direction or a malformed sibling hash.
    """
    if not isinstance(siblings, list) or len(siblings) > MAX_MERKLE_DEPTH:
        return None
    current = leaf
    for item in siblings:
        if not isinstance(item, dict):
            return None
        direction = item.get("direction")
        sibling_hash = item.get("hash")
        if not _is_hex64(sibling_hash):
            return None
        if direction == "left":
            pair = sibling_hash + current
        elif direction == "right":
            pair = current + sibling_hash
        else:
            return None
        current = sha256_hex(pair.encode("ascii"))
    return current


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

        current = _hash_merkle_path(tx_id, siblings)
        if current is None:
            return False

        if not hmac.compare_digest(current, merkle_root):
            return False
        if not hmac.compare_digest(block_hash, expected_block_hash):
            return False
        return True
    except (TypeError, ValueError):
        return False


# -- account state Merkle tree ----------------------------------------------


def account_leaf(account: str, balance: int, confirmed_transactions: list[str]) -> str:
    """SHA-256 hex digest of one account state's canonical JSON.

    The leaf document is exactly
    ``{"account": a, "balance": b, "confirmed_transactions": T}`` serialized
    with sort_keys=True, ensure_ascii=False and separators=(",", ":"); T keeps
    its stored (chain-replay) order and is never sorted here.
    """
    payload = {
        "account": account,
        "balance": balance,
        "confirmed_transactions": confirmed_transactions,
    }
    data = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return sha256_hex(data)


def account_leaves(accounts: list[tuple[str, int, list[str]]]) -> list[str]:
    """Account leaves in ascending-account order (the state tree order)."""
    ordered = sorted(accounts, key=lambda entry: entry[0])
    return [
        account_leaf(account, balance, transactions)
        for account, balance, transactions in ordered
    ]


def account_state_root(accounts: list[tuple[str, int, list[str]]]) -> str:
    """Merkle root of the account state leaves in ascending-account order.

    Uses the same tree construction as :func:`merkle_root`; an empty account
    set hashes to :data:`EMPTY_MERKLE_ROOT`.
    """
    return merkle_root(account_leaves(accounts))


def account_proof(
    accounts: list[tuple[str, int, list[str]]], account: str
) -> tuple[int, list[dict], str]:
    """Build ``(index, siblings, state_root)`` for ``account``.

    Accounts are ordered ascending. Raises ValueError when the account is
    absent; mirrors :func:`merkle_proof` for a single-account (empty-path)
    tree.
    """
    leaves = account_leaves(accounts)
    names = sorted(entry[0] for entry in accounts)
    if account not in names:
        raise ValueError("unknown account")
    index = names.index(account)
    return index, merkle_proof(leaves, index), merkle_root(leaves)


def verify_account_proof(
    proof: dict,
    expected_root: str,
    expected_height: int,
    expected_hash: str,
) -> bool:
    """Verify an account-state Merkle proof against an expected anchor.

    Recomputes the account leaf from the proof's
    account/balance/confirmed_transactions triple, walks the leaf-to-root
    sibling path, and requires the recomputed root to equal both the proof's
    ``state_root`` and ``expected_root``; ``height``/``block_hash`` must equal
    ``expected_height``/``expected_hash`` and ``index`` must match the binary
    path the siblings describe. Every malformed value (bad hash, illegal
    direction, wrong index/type, malformed leaf, wrong anchor) returns False
    rather than raising.
    """
    try:
        if not isinstance(proof, dict):
            return False
        account = proof.get("account")
        balance = proof.get("balance")
        confirmed_transactions = proof.get("confirmed_transactions")
        index = proof.get("index")
        state_root = proof.get("state_root")
        height = proof.get("height")
        block_hash = proof.get("block_hash")
        siblings = proof.get("siblings")

        if not isinstance(account, str) or not account:
            return False
        if isinstance(balance, bool) or not isinstance(balance, int):
            return False
        if not isinstance(confirmed_transactions, list) or any(
            not isinstance(tx_id, str) for tx_id in confirmed_transactions
        ):
            return False
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            return False
        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            return False
        if isinstance(expected_height, bool) or not isinstance(expected_height, int):
            return False
        if not _is_hex64(state_root) or not _is_hex64(expected_root):
            return False
        if not _is_hex64(block_hash) or not _is_hex64(expected_hash):
            return False

        # The index must agree with the sibling path: at level i the path node
        # is a left child (sibling on its right -> bit 0) or a right child
        # (sibling on its left -> bit 1), and every bit above the tree depth
        # must be zero. This rejects an index that does not describe the path.
        if not isinstance(siblings, list) or len(siblings) > MAX_MERKLE_DEPTH:
            return False
        for level, item in enumerate(siblings):
            if not isinstance(item, dict):
                return False
            if item.get("direction") not in ("left", "right"):
                return False
            expected_bit = 1 if item["direction"] == "left" else 0
            if ((index >> level) & 1) != expected_bit:
                return False
        if index >> len(siblings):
            return False

        if height != expected_height:
            return False
        if not hmac.compare_digest(block_hash, expected_hash):
            return False
        if not hmac.compare_digest(state_root, expected_root):
            return False

        leaf = account_leaf(account, balance, confirmed_transactions)
        current = _hash_merkle_path(leaf, siblings)
        if current is None:
            return False
        return hmac.compare_digest(current, state_root)
    except (TypeError, ValueError):
        return False
