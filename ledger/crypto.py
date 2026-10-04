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


# Domain prefix of a sequenced-transfer signature message: the UTF-8 prefix
# line (including its trailing LF) followed by the compact JSON payload. It
# binds a sequenced signature to this protocol and keeps it disjoint from the
# legacy canonical-message signature domain.
SEQUENCED_MESSAGE_PREFIX = "ledger-sequenced-transfer-v1\n"


def sequenced_message(
    sender: str, recipient: str, amount: int, nonce: int
) -> bytes:
    """Deterministic byte representation of a sequenced-transfer payload.

    The message is the UTF-8 text ``ledger-sequenced-transfer-v1`` followed by
    a single LF and the compact JSON document
    ``{"amount":A,"from":F,"nonce":N,"to":T}`` with its keys sorted
    (amount, from, nonce, to) and no whitespace, so the same
    (from, to, amount, nonce) tuple always yields identical bytes.
    """
    payload = {
        "amount": amount,
        "from": sender,
        "nonce": nonce,
        "to": recipient,
    }
    body = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return (SEQUENCED_MESSAGE_PREFIX + body).encode("utf-8")


# Domain prefix of a transaction-cancel signature message: the UTF-8 prefix
# line (including its trailing LF) followed by the bare tx_id. It binds a
# cancellation to this protocol and keeps it disjoint from the transfer
# signature domains (canonical and sequenced).
CANCEL_MESSAGE_PREFIX = "ledger-cancel-v1\n"


def cancel_message(tx_id: str) -> bytes:
    """Deterministic byte representation of a transaction-cancel request.

    The message is the UTF-8 text ``ledger-cancel-v1`` followed by a single
    LF and the target transaction id (64 lowercase hex characters), so the
    same tx_id always yields identical bytes on every client.
    """
    return (CANCEL_MESSAGE_PREFIX + tx_id).encode("utf-8")


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


# Exact, ordered key sets of a batch Merkle-proof response document. They let
# verify_merkle_proof_bundle reject missing/extra keys *and* a wrong key order.
_BUNDLE_TOP_KEYS = ("height", "block_hash", "merkle_root", "transaction_ids", "proofs")
_BUNDLE_PROOF_KEYS = ("tx_id", "index", "siblings")
_BUNDLE_SIBLING_KEYS = ("direction", "hash")


def _exact_keys(value: object, keys: tuple[str, ...]) -> bool:
    """True iff ``value`` is a dict with exactly ``keys``, in that insertion order."""
    return isinstance(value, dict) and tuple(value.keys()) == keys


def verify_merkle_proof_bundle(
    bundle: object,
    expected_block_hash: object,
    expected_merkle_root: object,
) -> bool:
    """Strictly verify a batch Merkle-proof bundle offline.

    The bundle mirrors POST /v1/blocks/{height}/proofs::

        {"height": H, "block_hash": B, "merkle_root": R,
         "transaction_ids": [id, ...],     # ALL block leaves, ascending
         "proofs": [{"tx_id", "index", "siblings"}, ...]}  # requested subset

    ``transaction_ids`` is the block's complete, ascending leaf list; ``proofs``
    covers the requested tx_ids (a subset of it), itself sorted by tx_id. Every
    proof's leaf-to-root sibling path is re-hashed with the same pairing rules
    as :func:`merkle_root` (``sha256(left + right)`` hex pairs, a lone odd node
    paired with itself); the root is additionally recomputed directly from
    ``transaction_ids`` and must equal both the bundle's ``merkle_root`` and
    ``expected_merkle_root``, while ``block_hash`` must equal
    ``expected_block_hash``. Each proof ``index`` must be the tx_id's exact
    position in ``transaction_ids`` and its path must agree with that index at
    every level.

    Every defect — a missing/extra key, a wrong key order, a wrong type, a
    non-boolean/negative height, a duplicate/non-hex/non-string/unsorted tx_id,
    an unknown or duplicated proof tx_id, an out-of-range index, a path
    inconsistent with the index (including the phantom self-pair slot), an
    illegal direction or hash, excessive depth, an empty proof list, a tampered
    leaf list/root or block hash — returns False rather than raising.
    """
    try:
        if not _exact_keys(bundle, _BUNDLE_TOP_KEYS):
            return False
        if not _is_hex64(expected_block_hash) or not _is_hex64(expected_merkle_root):
            return False
        height = bundle["height"]
        block_hash = bundle["block_hash"]
        bundle_root = bundle["merkle_root"]
        transaction_ids = bundle["transaction_ids"]
        proofs = bundle["proofs"]

        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            return False
        if not _is_hex64(block_hash):
            return False
        if not _is_hex64(bundle_root):
            return False
        if not isinstance(transaction_ids, list) or not transaction_ids:
            return False
        if not isinstance(proofs, list) or not proofs:
            return False
        if any(not _is_hex64(tx_id) for tx_id in transaction_ids):
            return False
        # Unique leaves ...
        if len(set(transaction_ids)) != len(transaction_ids):
            return False
        # ... in ascending tx_id order, matching the block's leaf ordering.
        if transaction_ids != sorted(transaction_ids):
            return False
        # The root is recomputed straight from the claimed leaf list, so the
        # list can never be tampered with independently of the paths.
        if not hmac.compare_digest(merkle_root(transaction_ids), bundle_root):
            return False

        positions = {tx_id: i for i, tx_id in enumerate(transaction_ids)}
        proof_ids: list[str] = []
        leaf_count = len(transaction_ids)
        for proof in proofs:
            if not _exact_keys(proof, _BUNDLE_PROOF_KEYS):
                return False
            tx_id = proof["tx_id"]
            index = proof["index"]
            siblings = proof["siblings"]
            if not _is_hex64(tx_id) or tx_id not in positions:
                return False
            if tx_id in proof_ids:
                return False
            if isinstance(index, bool) or not isinstance(index, int):
                return False
            # The index must be exactly the tx_id's leaf position; anything
            # else is a mismatch or out of range regardless of supplied hashes.
            if index != positions[tx_id] or not 0 <= index < leaf_count:
                return False
            if not isinstance(siblings, list) or len(siblings) > MAX_MERKLE_DEPTH:
                return False

            # A depth-D path addresses one of 2**D leaf slots.
            depth = len(siblings)
            if index >= (1 << depth):
                return False
            current = tx_id
            position = index
            for item in siblings:
                if not _exact_keys(item, _BUNDLE_SIBLING_KEYS):
                    return False
                direction = item["direction"]
                sibling_hash = item["hash"]
                if not _is_hex64(sibling_hash):
                    return False
                # The odd-node promotion pairs the last (even-positioned) node
                # with a copy of itself, so a genuine self-pair always points
                # at a right sibling. A left sibling equal to the current node
                # addresses the phantom duplicate slot, which is never a real
                # leaf. The path must also agree with the index at every
                # level: an even position is the left child (sibling on its
                # right), an odd position the right child.
                if direction == "left":
                    if position % 2 == 0 or sibling_hash == current:
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

            if not hmac.compare_digest(current, bundle_root):
                return False
            proof_ids.append(tx_id)

        # Proofs must be unique and ordered by tx_id ascending.
        if proof_ids != sorted(proof_ids):
            return False

        if not hmac.compare_digest(bundle_root, expected_merkle_root):
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


# Exact key shapes of the account-absence proof document and its parts.
_ABSENCE_DOC_KEYS = ("account", "state", "lower", "upper")
_ABSENCE_STATE_KEYS = (
    "state_root",
    "height",
    "block_hash",
    "account_count",
)
_ABSENCE_NEIGHBOR_KEYS = (
    "account",
    "balance",
    "confirmed_transactions",
    "index",
    "state_root",
    "height",
    "block_hash",
    "siblings",
)


def verify_account_absence_proof(
    document: object, account: object, expected_state: object
) -> bool:
    """Verify an account-absence (non-membership) proof offline.

    The document mirrors
    ``GET /v1/accounts/{account}/absence-proof``::

        {"account": A, "state": state-anchor-document,
         "lower": neighbor-inclusion-proof | None,
         "upper": neighbor-inclusion-proof | None}

    ``account`` is the caller-pinned target (a non-empty string) and
    ``expected_state`` is the caller-pinned full state-root document
    (``state_root, height, block_hash, account_count``). The proof is valid
    only when:

    * every document/state/neighbor field is present exactly once with the
      right type and format (booleans are never integers; neighbor sibling
      items carry exactly ``direction``/``hash``);
    * the document account equals the pinned account and the embedded state
      anchor exactly equals ``expected_state`` (root, height, block hash and
      account count);
    * each non-null neighbor is a valid inclusion proof against the same
      anchor, with its index in ``[0, account_count)``;
    * the neighbors genuinely frame the target in ascending account order:
      a present ``lower`` sits one slot below it (``lower.account < account``,
      index ``i``), a present ``upper`` one slot above
      (``account < upper.account``, index ``i + 1``), with both present
      adjacent (``i, i + 1``); a boundary proof uses only index 0 (target
      before the first account) or ``account_count - 1`` (target after the
      last); an empty tree has ``account_count == 0`` and both sides null;
    * the empty-tree root is the fixed empty Merkle root.

    Returns False — never raises — for any malformed or tampered input,
    including mixed anchors, non-adjacent neighbors, out-of-range indices and
    phantom slots derived from odd-node self-pairing. Key order is
    irrelevant (but missing/extra keys still fail).
    """
    try:
        if not isinstance(document, dict):
            return False
        # Key order is irrelevant for the absence document, but the four
        # keys must be present with none missing or extra.
        if set(document.keys()) != set(_ABSENCE_DOC_KEYS):
            return False
        target = document["account"]
        state = document["state"]
        lower = document["lower"]
        upper = document["upper"]

        if not isinstance(account, str) or not account:
            return False
        if not isinstance(target, str) or not target or target != account:
            return False

        state = _validated_absence_state(state, expected_state)
        if state is None:
            return False
        root = state["state_root"]
        height = state["height"]
        block_hash = state["block_hash"]
        account_count = state["account_count"]

        if account_count == 0:
            if root != EMPTY_MERKLE_ROOT:
                return False
            return lower is None and upper is None

        lower_result = None
        upper_result = None
        if lower is not None:
            lower_result = _validated_absence_neighbor(
                lower, root, height, block_hash, account_count
            )
            if lower_result is None:
                return False
            name, _index = lower_result
            if not name < account:
                return False
        if upper is not None:
            upper_result = _validated_absence_neighbor(
                upper, root, height, block_hash, account_count
            )
            if upper_result is None:
                return False
            name, _index = upper_result
            if not account < name:
                return False

        if lower_result is not None and upper_result is not None:
            if lower_result[1] + 1 != upper_result[1]:
                return False
        elif lower_result is not None:
            # Target past the last account: the only neighbor is the last row.
            if lower_result[1] != account_count - 1:
                return False
        elif upper_result is not None:
            # Target before the first account: the only neighbor is row zero.
            if upper_result[1] != 0:
                return False
        else:
            # A non-empty tree must name at least one framing neighbor.
            return False
        return True
    except (TypeError, ValueError):
        return False


def _validated_absence_state(state: object, expected_state: object) -> dict | None:
    """Validate and return the embedded state anchor iff it exactly matches
    the caller-pinned ``expected_state`` document (same four keys/types)."""
    if not isinstance(state, dict):
        return None
    if set(state.keys()) != set(_ABSENCE_STATE_KEYS):
        return None
    if not isinstance(expected_state, dict):
        return None
    if set(expected_state.keys()) != set(_ABSENCE_STATE_KEYS):
        return None
    expected_root = expected_state["state_root"]
    expected_height = expected_state["height"]
    expected_hash = expected_state["block_hash"]
    expected_count = expected_state["account_count"]
    if not _is_hex64(expected_root) or not _is_hex64(expected_hash):
        return None
    if (
        isinstance(expected_height, bool)
        or not isinstance(expected_height, int)
        or expected_height < 0
    ):
        return None
    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count < 0
    ):
        return None
    root = state["state_root"]
    height = state["height"]
    block_hash = state["block_hash"]
    account_count = state["account_count"]
    if not _is_hex64(root) or not _is_hex64(block_hash):
        return None
    if isinstance(height, bool) or not isinstance(height, int) or height < 0:
        return None
    if (
        isinstance(account_count, bool)
        or not isinstance(account_count, int)
        or account_count < 0
    ):
        return None
    if root != expected_root:
        return None
    if height != expected_height:
        return None
    if block_hash != expected_hash:
        return None
    if account_count != expected_count:
        return None
    return {
        "state_root": root,
        "height": height,
        "block_hash": block_hash,
        "account_count": account_count,
    }


def _validated_absence_neighbor(
    neighbor: object,
    root: str,
    height: int,
    block_hash: str,
    account_count: int,
) -> tuple[str, int] | None:
    """Validate one framing neighbor inclusion proof against the shared
    anchor; return ``(account, index)`` on success."""
    if not isinstance(neighbor, dict):
        return None
    if set(neighbor.keys()) != set(_ABSENCE_NEIGHBOR_KEYS):
        return None
    siblings = neighbor["siblings"]
    if not isinstance(siblings, list):
        return None
    for item in siblings:
        if not isinstance(item, dict) or set(item.keys()) != {"direction", "hash"}:
            return None
    name = neighbor["account"]
    index = neighbor["index"]
    if not isinstance(name, str) or not name:
        return None
    if isinstance(index, bool) or not isinstance(index, int):
        return None
    if index < 0 or index >= account_count:
        return None
    if not verify_account_proof(neighbor, root, height, block_hash):
        return None
    return name, index
