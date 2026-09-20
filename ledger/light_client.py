"""Offline light-client verification of externally supplied proof bundles.

A proof bundle lets a client verify ledger responses without trusting the
serving node or holding any chain state:

    bundle = {
        "source": str,
        "expires_at": int,            # Unix seconds
        "response": object,           # the attested response object
        "candidate": [...],           # full block list starting at genesis
        "proofs": [                   # optional Merkle inclusion proofs
            {"height": int, "proof": {height, tx_id, index, merkle_root,
                                      block_hash, siblings}},
            ...
        ],
        "signature": str,             # optional Ed25519 signature hex
    }

The local trust document pins the genesis block hash and records, per source,
an optional Ed25519 public key with its own expiry, plus an allowlist of
sources accepted without signatures:

    trust = {
        "genesis_hash": "<64 lowercase hex chars>",
        "sources": {source: {"public_key": hex, "expires_at": int}},
        "allowlist": {source: expires_at_int},
    }

Verification, in order:

1. **input** — bundle and trust must have the documented shape; every numeric
   field must be a plain (non-boolean) integer.
2. **auth** — the source must be trusted (a ``sources`` entry or the
   ``allowlist``). A source with a public key must sign the bundle; a bundle
   carrying a signature for a key-less source, or an unsigned bundle from a
   non-allowlisted source, fails.
3. **expired** — neither the bundle deadline nor the trust entry's deadline
   may have passed (``expires_at <= now`` counts as expired).
4. **integrity** — the signature (when required) is verified over
   Ed25519(sha256(sorted-compact UTF-8 JSON of the bundle without
   ``signature``)); the candidate chain is recomputed from the pinned genesis
   (heights, prev_hash linkage, every transaction's tx_id and Ed25519
   signature, unique tx_ids, Merkle roots, block hashes, pending-only-at-tip)
   and the response's descriptor fields are checked against the recomputed
   tip descriptor ``S``.
5. **proof** — every proof must be unique, its tx_id/height/index and block
   fields must agree with the candidate block, the Merkle path must verify
   under the existing rules, and its block must not be the pending tip.

On success :func:`verify_bundle` returns
``{"ok": True, "source", "S", "verified_tx_ids"}``; on failure
``{"ok": False, "error": category}`` with category one of
``input/auth/expired/integrity/proof``.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

from . import crypto
from .models import STATUS_CONFIRMED, Block, compute_block_hash
from .store import GENESIS_PREV_HASH

# Stable error categories returned to callers.
ERR_INPUT = "input"
ERR_AUTH = "auth"
ERR_EXPIRED = "expired"
ERR_INTEGRITY = "integrity"
ERR_PROOF = "proof"

# Descriptor fields of a chain tip, exactly as GET /v1/chain reports them.
DESCRIPTOR_FIELDS = ("tip_hash", "height", "length", "status")

# An Ed25519 public key rendered as 64 lowercase hexadecimal characters.
_HEX32_RE = re.compile(r"[0-9a-f]{64}")


class _Failure(Exception):
    """Internal control-flow exception carrying the public error category."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _is_int(value: object) -> bool:
    """Plain integer test; booleans are rejected (bool subclasses int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_bundle_bytes(bundle: dict) -> bytes:
    """Sorted, compact UTF-8 JSON of the bundle with its signature removed.

    This is the exact byte document whose SHA-256 the source signs, so signers
    and verifiers always agree regardless of incoming key order. The
    serialization mirrors :func:`ledger.crypto.canonical_message`: sorted keys,
    compact separators, UTF-8 bytes.
    """
    unsigned = {key: value for key, value in bundle.items() if key != "signature"}
    return json.dumps(
        unsigned, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def bundle_signing_digest(bundle: dict) -> bytes:
    """The 32-byte SHA-256 digest covered by a bundle Ed25519 signature."""
    return hashlib.sha256(canonical_bundle_bytes(bundle)).digest()


def verify_bundle(bundle: object, trust: object, now: float | None = None) -> dict:
    """Verify an offline proof bundle against the local trust document.

    Returns ``{"ok": True, "source": ..., "S": ..., "verified_tx_ids": [...]}``
    on success or ``{"ok": False, "error": category}`` on failure. Never raises
    for malformed input: every defect maps to one of the five categories.
    """
    current = time.time() if now is None else now
    try:
        source, candidate = _validate_inputs(bundle, trust)
        _authenticate(bundle, trust, source, current)
        blocks_raw = candidate["blocks"] if isinstance(candidate, dict) else candidate
        blocks = _recompute_chain(blocks_raw, trust)
        descriptor = _tip_descriptor(blocks)
        _check_candidate_summary(candidate, descriptor)
        _check_response(bundle["response"], descriptor)
        verified_ids = _verify_proofs(bundle["proofs"], blocks)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {
        "ok": True,
        "source": source,
        "S": descriptor,
        "verified_tx_ids": verified_ids,
    }


# -- stage 1: shape -----------------------------------------------------------


def _validate_inputs(bundle: object, trust: object) -> tuple[str, object]:
    """Structural validation of bundle and trust.

    Returns ``(source, candidate)`` where ``candidate`` is the raw candidate
    value (a bare block list or an export-format object carrying ``blocks``).
    The bundle itself is never mutated: the signature covers it verbatim.
    """
    if not isinstance(bundle, dict):
        raise _Failure(ERR_INPUT)
    for field in ("source", "expires_at", "response", "candidate", "proofs"):
        if field not in bundle:
            raise _Failure(ERR_INPUT)
    source = bundle["source"]
    if not isinstance(source, str) or not source:
        raise _Failure(ERR_INPUT)
    if not _is_int(bundle["expires_at"]):
        raise _Failure(ERR_INPUT)
    # The response is itself a JSON object; anything else cannot be checked
    # against the recomputed chain descriptor.
    if not isinstance(bundle["response"], dict):
        raise _Failure(ERR_INPUT)
    candidate = bundle["candidate"]
    blocks_raw = candidate.get("blocks") if isinstance(candidate, dict) else candidate
    if not isinstance(blocks_raw, list) or not blocks_raw:
        raise _Failure(ERR_INPUT)
    if not isinstance(bundle["proofs"], list):
        raise _Failure(ERR_INPUT)
    signature = bundle.get("signature")
    if signature is not None and (not isinstance(signature, str) or not signature):
        raise _Failure(ERR_INPUT)

    if not isinstance(trust, dict):
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(trust.get("genesis_hash")):
        raise _Failure(ERR_INPUT)
    sources = trust.get("sources", {})
    if not isinstance(sources, dict):
        raise _Failure(ERR_INPUT)
    for name, entry in sources.items():
        if not isinstance(name, str) or not name or not isinstance(entry, dict):
            raise _Failure(ERR_INPUT)
        if not _is_int(entry.get("expires_at")):
            raise _Failure(ERR_INPUT)
        public_key = entry.get("public_key")
        # Ed25519 public keys are 32 raw bytes, i.e. 64 hex characters.
        if not isinstance(public_key, str) or not _HEX32_RE.fullmatch(public_key):
            raise _Failure(ERR_INPUT)
    allowlist = trust.get("allowlist", {})
    if not isinstance(allowlist, dict):
        raise _Failure(ERR_INPUT)
    for name, expires_at in allowlist.items():
        if not isinstance(name, str) or not name or not _is_int(expires_at):
            raise _Failure(ERR_INPUT)
    return source, candidate


# -- stage 2/3: trust, expiry and signature -----------------------------------


def _authenticate(
    bundle: dict, trust: dict, source: str, now: float
) -> None:
    """Check source trust, every deadline and the optional Ed25519 signature."""
    sources = trust.get("sources", {})
    allowlist = trust.get("allowlist", {})
    source_entry = sources.get(source)
    allowlist_expiry = allowlist.get(source)
    if source_entry is None and allowlist_expiry is None:
        raise _Failure(ERR_AUTH)

    # All deadlines are checked before any signature work: an expired,
    # correctly-signed bundle is still unusable. A source listed in both
    # ``sources`` and ``allowlist`` is bound by both deadlines.
    if bundle["expires_at"] <= now:
        raise _Failure(ERR_EXPIRED)
    if source_entry is not None and source_entry["expires_at"] <= now:
        raise _Failure(ERR_EXPIRED)
    if allowlist_expiry is not None and allowlist_expiry <= now:
        raise _Failure(ERR_EXPIRED)

    public_key = source_entry.get("public_key") if source_entry else None
    signature = bundle.get("signature")
    if public_key is not None:
        # A keyed source must sign: a missing signature cannot authenticate.
        if signature is None:
            raise _Failure(ERR_AUTH)
        if not crypto.verify_signature(
            public_key, bundle_signing_digest(bundle), signature
        ):
            raise _Failure(ERR_INTEGRITY)
        return
    # The source reached this point only through the allowlist (every sources
    # entry pins a key). An unsigned allowlisted bundle is therefore accepted;
    # a signature with no pinned key to check it against is meaningless.
    if signature is not None:
        raise _Failure(ERR_AUTH)


# -- stage 4: chain recomputation and response cross-check --------------------


def _tip_descriptor(blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
    }


def _recompute_chain(candidate_raw: list, trust: dict) -> list[Block]:
    """Recompute and validate the whole candidate chain from the pinned genesis.

    Mirrors the node's own candidate rules except the endowment balance replay
    (an offline client holds no balance convention): genesis anchor, heights,
    prev_hash linkage, per-transaction tx_id and Ed25519 signatures, unique
    tx_id-sorted transactions, Merkle roots, block hashes and the
    pending-only-at-tip rule. Every field is checked on the *raw* JSON value so
    coercions such as ``"1"`` or ``1.0`` heights are rejected outright.
    """
    blocks: list[Block] = []
    seen_tx_ids: set[str] = set()
    for position, block_raw in enumerate(candidate_raw):
        if not isinstance(block_raw, dict):
            raise _Failure(ERR_INTEGRITY)
        height = block_raw.get("height")
        prev_hash = block_raw.get("prev_hash")
        merkle_root = block_raw.get("merkle_root")
        block_hash = block_raw.get("block_hash")
        status = block_raw.get("status")
        txs_raw = block_raw.get("transactions")
        if not _is_int(height) or not isinstance(prev_hash, str):
            raise _Failure(ERR_INTEGRITY)
        if not crypto.is_hex64(merkle_root) or not crypto.is_hex64(block_hash):
            raise _Failure(ERR_INTEGRITY)
        if status not in ("pending", "confirmed") or not isinstance(txs_raw, list):
            raise _Failure(ERR_INTEGRITY)
        if height != position:
            raise _Failure(ERR_INTEGRITY)
        expected_prev = (
            GENESIS_PREV_HASH if position == 0 else blocks[position - 1].block_hash
        )
        if prev_hash != expected_prev:
            raise _Failure(ERR_INTEGRITY)
        if position == 0:
            # Genesis must be the exact block the client pinned: confirmed,
            # empty, and carrying the trusted hash (recomputed below too).
            if status != STATUS_CONFIRMED or txs_raw:
                raise _Failure(ERR_INTEGRITY)
            if block_hash != trust["genesis_hash"]:
                raise _Failure(ERR_INTEGRITY)
        elif position < len(candidate_raw) - 1 and status != STATUS_CONFIRMED:
            # A pending block may only sit at the chain tip.
            raise _Failure(ERR_INTEGRITY)

        tx_ids: list[str] = []
        for raw_tx in txs_raw:
            if not isinstance(raw_tx, dict):
                raise _Failure(ERR_INTEGRITY)
            sender = raw_tx.get("from")
            recipient = raw_tx.get("to")
            amount = raw_tx.get("amount")
            signature = raw_tx.get("signature")
            stored_tx_id = raw_tx.get("tx_id")
            if not isinstance(sender, str) or not sender:
                raise _Failure(ERR_INTEGRITY)
            if not isinstance(recipient, str) or not recipient:
                raise _Failure(ERR_INTEGRITY)
            if not _is_int(amount) or amount <= 0:
                raise _Failure(ERR_INTEGRITY)
            if not isinstance(signature, str) or not signature:
                raise _Failure(ERR_INTEGRITY)
            message = crypto.canonical_message(sender, recipient, amount)
            tx_id = crypto.compute_tx_id(message)
            if stored_tx_id != tx_id or not crypto.is_hex64(stored_tx_id):
                raise _Failure(ERR_INTEGRITY)
            if not crypto.verify_signature(sender, message, signature):
                raise _Failure(ERR_INTEGRITY)
            if tx_id in seen_tx_ids:
                raise _Failure(ERR_INTEGRITY)
            seen_tx_ids.add(tx_id)
            tx_ids.append(tx_id)
        if tx_ids != sorted(tx_ids):
            raise _Failure(ERR_INTEGRITY)
        if crypto.merkle_root(tx_ids) != merkle_root:
            raise _Failure(ERR_INTEGRITY)
        recomputed = compute_block_hash(height, prev_hash, merkle_root)
        if recomputed != block_hash:
            raise _Failure(ERR_INTEGRITY)
        # Parsed only after every raw field has checked out; never trusted for
        # the comparison decisions above.
        try:
            blocks.append(Block.from_dict(block_raw))
        except (KeyError, TypeError, ValueError):
            raise _Failure(ERR_INTEGRITY) from None
    return blocks


def _check_candidate_summary(candidate: object, descriptor: dict) -> None:
    """Cross-check an export-format candidate's own tip summary fields.

    A bare block list has nothing to check. A five-field export document's
    supplied ``tip_hash/height/length/status`` must equal the recomputed tip
    descriptor, exactly as the node requires on resubmission.
    """
    if not isinstance(candidate, dict):
        return
    for field in DESCRIPTOR_FIELDS:
        if field in candidate and candidate[field] != descriptor[field]:
            raise _Failure(ERR_INTEGRITY)


def _check_response(response: dict, descriptor: dict) -> None:
    """Every descriptor field present in the response must equal the tip's.

    A response carrying none of the descriptor fields cannot be bound to the
    recomputed chain at all, so it is rejected rather than vacuously accepted.
    """
    matched = False
    for field in DESCRIPTOR_FIELDS:
        if field in response:
            matched = True
            if response[field] != descriptor[field]:
                raise _Failure(ERR_INTEGRITY)
    if not matched:
        raise _Failure(ERR_INTEGRITY)


# -- stage 5: proofs ----------------------------------------------------------


def _verify_proofs(proofs_raw: list, blocks: list[Block]) -> list[str]:
    """Validate uniqueness and cross-block consistency of every proof.

    Each entry is ``{"height": int, "proof": doc}`` and the proof document
    follows the server shape ``{height, tx_id, index, merkle_root, block_hash,
    siblings}``. Proofs for the pending tip are forbidden. The verified
    transaction ids are returned sorted ascending.
    """
    verified: list[str] = []
    seen: set[tuple] = set()
    for item in proofs_raw:
        if not isinstance(item, dict):
            raise _Failure(ERR_PROOF)
        height = item.get("height")
        proof = item.get("proof")
        if not _is_int(height) or not isinstance(proof, dict):
            raise _Failure(ERR_PROOF)
        if height < 0 or height >= len(blocks):
            raise _Failure(ERR_PROOF)
        block = blocks[height]
        if block.height != height:
            raise _Failure(ERR_PROOF)
        # Pending tips never carry trustworthy proofs.
        if block.status != STATUS_CONFIRMED:
            raise _Failure(ERR_PROOF)

        tx_id = proof.get("tx_id")
        index = proof.get("index")
        if not crypto.is_hex64(tx_id) or not _is_int(index):
            raise _Failure(ERR_PROOF)
        # The item height and the proof document's own fields must agree with
        # the candidate block they claim inclusion in.
        if proof.get("height") != height or proof.get("block_hash") != block.block_hash:
            raise _Failure(ERR_PROOF)
        if proof.get("merkle_root") != block.merkle_root:
            raise _Failure(ERR_PROOF)
        if index < 0 or index >= len(block.transactions):
            raise _Failure(ERR_PROOF)
        if block.transactions[index].tx_id != tx_id:
            raise _Failure(ERR_PROOF)

        key = (height, tx_id)
        if key in seen:
            raise _Failure(ERR_PROOF)
        seen.add(key)

        if not crypto.verify_merkle_proof(
            tx_id,
            proof.get("siblings"),
            block.merkle_root,
            block.block_hash,
            block.block_hash,
        ):
            raise _Failure(ERR_PROOF)
        verified.append(tx_id)
    return sorted(verified)
