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


# -- compact multi-leaf inclusion proofs ------------------------------------

# Exact key sets of a compact Merkle multiproof response document. Unlike the
# batch bundle, object key order is not semantically significant to the
# verifier, but the sets themselves are fixed.
_MULTIPROOF_TOP_KEYS = frozenset(
    ("height", "block_hash", "merkle_root", "leaf_count", "leaves", "nodes")
)
_MULTIPROOF_LEAF_KEYS = frozenset(("tx_id", "index"))
_MULTIPROOF_NODE_KEYS = frozenset(("level", "index", "hash"))


def _merkle_levels(tx_ids: list[str]) -> list[list[str]]:
    """Every level of the block Merkle tree, level 0 being the leaves.

    Mirrors :func:`merkle_root`: levels hash ``sha256(left + right)`` hex
    pairs and a lone odd node is paired with itself; the duplicated copy is a
    phantom slot and is never stored as its own node.
    """
    levels = [list(tx_ids)]
    while len(levels[-1]) > 1:
        level = levels[-1]
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        levels.append([
            sha256_hex((level[i] + level[i + 1]).encode("ascii"))
            for i in range(0, len(level), 2)
        ])
    return levels


def _merkle_multiproof_coordinates(
    leaf_count: int, selected: list[int]
) -> set[tuple[int, int]]:
    """Coordinates of the minimal sibling set for ``selected`` leaf indices.

    A coordinate is required iff it sits immediately outside the union of the
    selected leaves' root paths: walking the frontier upward level by level,
    every known subtree whose paired neighbour is a real position (below the
    level's real size, which excludes the odd-node phantom self-pair slot)
    that is not itself on the frontier contributes exactly that neighbour.
    The coordinate set is fully determined by ``leaf_count`` and the selected
    indices, so a verifier can recompute it and demand an exact match.
    """
    needed: set[tuple[int, int]] = set()
    frontier = set(selected)
    size = leaf_count
    level = 0
    while size > 1:
        for position in frontier:
            sibling = position ^ 1
            if sibling < size and sibling not in frontier:
                needed.add((level, sibling))
        frontier = {position // 2 for position in frontier}
        size = (size + 1) // 2
        level += 1
    return needed


def merkle_multiproof(
    tx_ids: list[str], indices: list[int]
) -> tuple[list[dict], list[dict]]:
    """Build a compact multi-leaf inclusion proof.

    Returns ``(leaves, nodes)`` where ``leaves`` is one ``{tx_id, index}``
    item per selected leaf (ascending index) and ``nodes`` is the minimal set
    of sibling subtree roots just outside the union of the selected leaves'
    root paths, each ``{level, index, hash}`` sorted by level then index
    (level 0 is the leaf layer, index the real zero-based position on that
    level). Nodes derivable from the selected leaves and the other nodes are
    omitted, as is the root itself; a phantom self-pair sibling is never
    emitted. Selecting every leaf (the only possibility for a single-leaf
    block) yields an empty node list. Raises ValueError for an empty tree, a
    non-integer/out-of-range index or an empty selection.
    """
    if not tx_ids:
        raise ValueError("cannot build a Merkle multiproof for an empty tree")
    for index in indices:
        if isinstance(index, bool) or not isinstance(index, int):
            raise ValueError("indices must be integers")
        if index < 0 or index >= len(tx_ids):
            raise ValueError("transaction index out of range")
    selected = sorted(set(indices))
    if not selected:
        raise ValueError("a multiproof must select at least one leaf")

    levels = _merkle_levels(tx_ids)
    leaves = [{"tx_id": tx_ids[index], "index": index} for index in selected]
    needed = _merkle_multiproof_coordinates(len(tx_ids), selected)
    nodes = [
        {"level": level, "index": index, "hash": levels[level][index]}
        for level, index in sorted(needed)
    ]
    return leaves, nodes


def verify_merkle_multiproof(
    document: object,
    expected_block_hash: object,
    expected_merkle_root: object,
    expected_leaf_count: object,
) -> bool:
    """Strictly verify a compact Merkle multiproof offline.

    The document mirrors POST /v1/blocks/{height}/multiproof::

        {"height": H, "block_hash": B, "merkle_root": R,
         "leaf_count": N,                    # the block's real leaf count
         "leaves": [{"tx_id", "index"}, ...],   # selected leaves only
         "nodes": [{"level", "index", "hash"}, ...]}  # minimal sibling set

    Validation succeeds only when every field is present with the right type
    (booleans are never integers; ``leaf_count`` positive, all other integers
    non-negative; every hash and tx_id a 64-char lowercase hex string),
    ``leaves`` is non-empty with strictly ascending indices *and* tx_ids in
    range of ``leaf_count``, ``nodes`` has strictly ascending (level, index)
    coordinates that are all real positions on the tree, no coordinate is
    repeated or shared with a leaf and the node set is exactly the minimal
    sibling set determined by ``leaf_count`` and the selected indices (so a
    missing node, a redundant/derivable node or an unrelated extra subtree
    all fail), the root recomputed with the block pairing rules
    (``sha256(left + right)`` hex pairs, a lone odd node paired with itself,
    no phantom sibling) equals both the document's ``merkle_root`` and
    ``expected_merkle_root``, ``leaf_count`` equals
    ``expected_leaf_count`` and ``block_hash`` equals
    ``expected_block_hash``.

    Every defect — missing/extra/repeated fields or coordinates, a wrong
    type or sort order, out-of-range indices, missing or redundant nodes,
    any hash/anchor mismatch — returns False rather than raising. Object key
    order does not affect verification.
    """
    try:
        if not isinstance(document, dict):
            return False
        if set(document.keys()) != set(_MULTIPROOF_TOP_KEYS):
            return False
        if not _is_hex64(expected_block_hash) or not _is_hex64(expected_merkle_root):
            return False
        if (
            isinstance(expected_leaf_count, bool)
            or not isinstance(expected_leaf_count, int)
            or not 0 < expected_leaf_count <= 1 << MAX_MERKLE_DEPTH
        ):
            return False

        height = document["height"]
        block_hash = document["block_hash"]
        document_root = document["merkle_root"]
        leaf_count = document["leaf_count"]
        leaves = document["leaves"]
        nodes = document["nodes"]

        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            return False
        if not _is_hex64(block_hash):
            return False
        if not _is_hex64(document_root):
            return False
        if (
            isinstance(leaf_count, bool)
            or not isinstance(leaf_count, int)
            or leaf_count != expected_leaf_count
        ):
            return False
        if not isinstance(leaves, list) or not leaves:
            return False
        if not isinstance(nodes, list):
            return False

        # Real level sizes of the claimed tree (phantom slots excluded).
        sizes: list[int] = []
        size = leaf_count
        while True:
            sizes.append(size)
            if size == 1:
                break
            size = (size + 1) // 2
        tree_depth = len(sizes) - 1
        if tree_depth > MAX_MERKLE_DEPTH:
            return False

        # Selected leaves: strictly ascending index and strictly ascending
        # tx_id, every coordinate a real leaf position.
        leaf_hashes: dict[int, str] = {}
        previous_index = -1
        previous_tx_id: str | None = None
        for leaf in leaves:
            if not isinstance(leaf, dict) or set(leaf.keys()) != set(
                _MULTIPROOF_LEAF_KEYS
            ):
                return False
            tx_id = leaf["tx_id"]
            index = leaf["index"]
            if not _is_hex64(tx_id):
                return False
            if isinstance(index, bool) or not isinstance(index, int):
                return False
            if index <= previous_index or not 0 <= index < leaf_count:
                return False
            if previous_tx_id is not None and tx_id <= previous_tx_id:
                return False
            leaf_hashes[index] = tx_id
            previous_index = index
            previous_tx_id = tx_id

        # Nodes: strictly ascending (level, index), coordinates real and
        # unique, never sharing a selected-leaf coordinate.
        node_hashes: dict[tuple[int, int], str] = {}
        previous_coord: tuple[int, int] | None = None
        for node in nodes:
            if not isinstance(node, dict) or set(node.keys()) != set(
                _MULTIPROOF_NODE_KEYS
            ):
                return False
            level = node["level"]
            index = node["index"]
            node_hash = node["hash"]
            if isinstance(level, bool) or not isinstance(level, int) or level < 0:
                return False
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                return False
            if not _is_hex64(node_hash):
                return False
            if level >= len(sizes) or index >= sizes[level]:
                return False
            coord = (level, index)
            if previous_coord is not None and coord <= previous_coord:
                return False
            if level == 0 and index in leaf_hashes:
                return False
            node_hashes[coord] = node_hash
            previous_coord = coord

        # The minimal sibling coordinate set is fully determined by the leaf
        # count and the selected indices; an exact match rules out missing,
        # redundant, derivable and wholly unrelated nodes in one step.
        expected_nodes = _merkle_multiproof_coordinates(
            leaf_count, sorted(leaf_hashes)
        )
        if set(node_hashes) != expected_nodes:
            return False

        def nodes_at(level: int) -> dict[int, str]:
            return {
                index: value
                for (node_level, index), value in node_hashes.items()
                if node_level == level
            }

        # Recompute the root level by level: hash every coordinate pair whose
        # both members are available, self-pair an odd level's lone last node,
        # and bridge uncovered subtrees with the supplied nodes of the next
        # level. Every supplied coordinate must be consumed in exactly one
        # pairing; the frontier must converge on the single root coordinate.
        available: dict[int, str] = dict(leaf_hashes)
        available.update(nodes_at(0))
        known_coordinates = {(0, i) for i in leaf_hashes} | set(node_hashes)
        consumed: set[tuple[int, int]] = set()
        for level, level_size in enumerate(sizes[:-1]):
            parents: dict[int, str] = {}
            pair_count = (level_size + 1) // 2
            for pair in range(pair_count):
                left = 2 * pair
                right = left + 1
                if right < level_size:
                    if left in available and right in available:
                        parents[pair] = sha256_hex(
                            (available[left] + available[right]).encode("ascii")
                        )
                        # Only coordinates originally supplied (a selected
                        # leaf or a proof node) count as consumed; parents
                        # computed this round are intermediate values.
                        if (level, left) in known_coordinates:
                            consumed.add((level, left))
                        if (level, right) in known_coordinates:
                            consumed.add((level, right))
                elif left in available:
                    # Odd level's lone last node pairs with itself; the
                    # phantom sibling carries no node.
                    value = available[left]
                    parents[pair] = sha256_hex((value + value).encode("ascii"))
                    if (level, left) in known_coordinates:
                        consumed.add((level, left))
            for index, value in nodes_at(level + 1).items():
                if index in parents:
                    # A node that the leaves already derive is redundant.
                    return False
                parents[index] = value
            available = parents

        if set(available) != {0}:
            return False
        if tree_depth == 0:
            # A single-leaf block: the one selected leaf is itself the root,
            # so it is trivially "consumed" with no pairing.
            consumed = set(known_coordinates)
        if consumed != known_coordinates:
            return False
        recomputed_root = available[0]

        if not hmac.compare_digest(recomputed_root, document_root):
            return False
        if not hmac.compare_digest(document_root, expected_merkle_root):
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
