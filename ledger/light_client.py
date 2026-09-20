"""Offline light-client verification of signed ledger response bundles.

A bundle lets a client verify a ledger node response without trusting the node
that served it or even being online: the candidate fork chain is recomputed
from a trusted genesis hash, every cited transaction carries a Merkle
inclusion proof, and the response claims are cross-checked against the
recomputed state.

Bundle document
---------------
``{source, expires_at, response, candidate, proofs[, signature]}``:

* ``source``      -- serving node identifier; must be trusted and unexpired.
* ``expires_at``  -- Unix-second deadline after which the bundle is stale.
* ``response``    -- the ledger API response object being vouched for. The
                     cross-checker understands the transaction-bearing shapes
                     (a proof object, an index row or an ``{"items": [...]}``
                     listing), a block summary and a fork descriptor S; any
                     other object is accepted only if it makes no claims.
* ``candidate``   -- the chain backing the response: an export-format fork
                     document ``{tip_hash, height, length, status, blocks}``,
                     a ``{"blocks": [...]}`` wrapper or a bare block list.
* ``proofs``      -- list of ``{"height": H, "proof": P}`` items where P is the
                     standard proof object
                     ``{tx_id, index, merkle_root, block_hash, siblings}``
                     (an optional inner ``height`` must match the outer one).
* ``signature``   -- optional Ed25519 signature (hex) over
                     ``SHA256(canonical JSON of the bundle without
                     "signature")``; the signed digest is the raw 32 bytes.

Trust document
--------------
``{genesis_hash, sources, allowlist}`` with
``sources[source] = [public_key_hex, expires_at]`` (either member may be
``null``: a null key means the source cannot sign, a null deadline never
expires) and ``allowlist[source] = expires_at``. A source with a public key
*must* sign; an unsigned bundle is accepted from an allowlisted source that
has no public key registered.

Every failure is reported with one of the machine-readable categories
``input`` / ``auth`` / ``expired`` / ``integrity`` / ``proof``.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

from . import crypto
from .models import (
    STATUS_CONFIRMED,
    STATUS_PENDING,
    Block,
    compute_block_hash,
)
from .store import GENESIS_PREV_HASH

# Machine-readable error categories returned in a failed verification report.
ERR_INPUT = "input"
ERR_AUTH = "auth"
ERR_EXPIRED = "expired"
ERR_INTEGRITY = "integrity"
ERR_PROOF = "proof"

# An Ed25519 public key rendered as 64 lowercase hexadecimal characters.
_HEX32_RE = re.compile(r"[0-9a-f]{64}")


def _failure(category: str) -> dict:
    return {"ok": False, "error": category}


def _is_int(value: object) -> bool:
    """Plain JSON integer (bool is rejected)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_deadline(value: object) -> bool:
    """A Unix-second deadline is a plain int or null (null never expires)."""
    return value is None or _is_int(value)


def _deadline_live(deadline: object, now: float) -> bool:
    """True iff an int-or-null deadline has not elapsed (null = never)."""
    return deadline is None or deadline > now


def _parse_trust_entry(entry: object) -> tuple[str | None, object] | None:
    """Normalize a sources value to (public_key, expires_at).

    Accepts the canonical ``[public_key, expires_at]`` pair and the equivalent
    ``{"public_key": ..., "expires_at": ...}`` object. Returns None when the
    entry is structurally unusable.
    """
    if isinstance(entry, list) and len(entry) == 2:
        public_key, expires_at = entry
    elif isinstance(entry, dict):
        public_key = entry.get("public_key")
        expires_at = entry.get("expires_at")
    else:
        return None
    if public_key is not None:
        if not isinstance(public_key, str) or not _HEX32_RE.fullmatch(public_key):
            return None
    if not _is_deadline(expires_at):
        return None
    return public_key, expires_at


def _blocks_of(candidate: object) -> list | None:
    if isinstance(candidate, list):
        return candidate
    if isinstance(candidate, dict) and isinstance(candidate.get("blocks"), list):
        return candidate["blocks"]
    return None


def _raw_block_types_ok(block_raw: object) -> bool:
    """Strict JSON-type check before the (int-coercing) model parser runs."""
    if not isinstance(block_raw, dict):
        return False
    if not _is_int(block_raw.get("height")):
        return False
    for field in ("prev_hash", "merkle_root", "block_hash", "status"):
        if not isinstance(block_raw.get(field), str):
            return False
    txs = block_raw.get("transactions")
    if not isinstance(txs, list):
        return False
    for tx in txs:
        if not isinstance(tx, dict):
            return False
        if not _is_int(tx.get("amount")):
            return False
        for field in ("from", "to", "signature", "tx_id"):
            if not isinstance(tx.get(field), str):
                return False
    return True


def _valid_tx(tx: Block, raw_tx: dict) -> bool:
    """Structural, stored-id and Ed25519 checks for one candidate tx."""
    if not tx.sender or not tx.recipient or not tx.signature:
        return False
    if tx.amount <= 0:
        return False
    if raw_tx.get("tx_id") != tx.tx_id:
        return False
    return crypto.verify_signature(tx.sender, tx.message, tx.signature)


def _recompute_chain(
    blocks_raw: list, genesis_hash: str
) -> tuple[list[Block] | None, str | None]:
    """Recompute the candidate chain exactly as a trusting node would.

    Checks the canonical genesis (whose hash must equal ``genesis_hash``),
    consecutive heights and prev_hash linkage, per-transaction tx_id and
    Ed25519 signatures, globally unique ascending tx_ids, recomputed Merkle
    roots and block hashes, and the pending-only-at-tip rule. Returns
    ``(blocks, None)`` on success or ``(None, reason)``.
    """
    if not blocks_raw:
        return None, "candidate must contain a non-empty block list"

    blocks: list[Block] = []
    seen_tx_ids: set[str] = set()
    for i, block_raw in enumerate(blocks_raw):
        if not _raw_block_types_ok(block_raw):
            return None, f"block at position {i} has malformed field types"
        try:
            block = Block.from_dict(block_raw)
        except (KeyError, TypeError, ValueError):
            return None, f"block {i} is malformed"

        if block.height != i:
            return None, f"block at position {i} has non-consecutive height"
        expected_prev = GENESIS_PREV_HASH if i == 0 else blocks[i - 1].block_hash
        if block.prev_hash != expected_prev:
            return None, f"block {i} has a mismatched prev_hash"
        if block.status not in (STATUS_PENDING, STATUS_CONFIRMED):
            return None, f"block {i} has an unknown status"
        if i == 0 and (block.status != STATUS_CONFIRMED or block.transactions):
            return None, "first block must be the empty confirmed genesis"
        if i < len(blocks_raw) - 1 and block.status == STATUS_PENDING:
            return None, f"pending block {i} is not the chain tip"

        tx_ids: list[str] = []
        for j, tx in enumerate(block.transactions):
            if not _valid_tx(tx, block_raw["transactions"][j]):
                return None, f"block {i} transaction {j} failed verification"
            if tx.tx_id in seen_tx_ids:
                return None, f"duplicate transaction {tx.tx_id} in candidate"
            seen_tx_ids.add(tx.tx_id)
            tx_ids.append(tx.tx_id)
        if tx_ids != sorted(tx_ids):
            return None, f"block {i} transactions are not tx_id sorted"

        if crypto.merkle_root(tx_ids) != block.merkle_root:
            return None, f"block {i} Merkle root mismatch"
        if (
            compute_block_hash(block.height, block.prev_hash, block.merkle_root)
            != block.block_hash
        ):
            return None, f"block {i} block_hash mismatch"
        blocks.append(block)

    if blocks[0].block_hash != genesis_hash:
        return None, "candidate genesis does not match the trusted genesis hash"
    return blocks, None


def _fork_descriptor(blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
    }


def _verify_proofs(
    proofs_raw: object, blocks: list[Block]
) -> tuple[dict[str, dict] | None, str | None]:
    """Validate every proof item against the recomputed chain.

    Proofs must be unique by tx_id (and by height/index), the cited block must
    exist and be confirmed (a pending tip never anchors a proof), the proof's
    block fields must match the block, the index must point at the cited
    tx_id, and the sibling path must verify under the existing Merkle rules.
    Returns ``({tx_id: {"height", "index", "proof"}}, None)`` on success.
    """
    if not isinstance(proofs_raw, list):
        return None, "proofs must be a list"

    by_height = {block.height: block for block in blocks}
    proven: dict[str, dict] = {}
    seen_positions: set[tuple[int, int]] = set()
    for item in proofs_raw:
        if not isinstance(item, dict) or "height" not in item or "proof" not in item:
            return None, "each proof item must carry height and proof"
        height = item["height"]
        proof = item["proof"]
        if not _is_int(height) or height < 0:
            return None, "proof height must be a non-negative integer"
        if not isinstance(proof, dict):
            return None, "proof must be a JSON object"
        tx_id = proof.get("tx_id")
        index = proof.get("index")
        siblings = proof.get("siblings")
        merkle_root = proof.get("merkle_root")
        block_hash = proof.get("block_hash")
        if not crypto.is_hex64(tx_id):
            return None, "proof tx_id must be 64 lowercase hex characters"
        if not _is_int(index) or index < 0:
            return None, "proof index must be a non-negative integer"
        if not crypto.is_hex64(merkle_root) or not crypto.is_hex64(block_hash):
            return None, "proof block hashes must be 64 lowercase hex characters"
        if "height" in proof:
            if not _is_int(proof["height"]) or proof["height"] != height:
                return None, "proof height disagrees with its wrapping item"

        block = by_height.get(height)
        if block is None:
            return None, f"no block at proof height {height}"
        if block.status != STATUS_CONFIRMED:
            return None, "proofs may not anchor to the pending tip"
        if block.merkle_root != merkle_root or block.block_hash != block_hash:
            return None, "proof block fields disagree with the recomputed block"
        if index >= len(block.transactions):
            return None, "proof index is out of range"
        if block.transactions[index].tx_id != tx_id:
            return None, "proof index does not point at the cited tx_id"
        if (height, index) in seen_positions or tx_id in proven:
            return None, f"duplicate proof for transaction {tx_id}"
        if not crypto.verify_merkle_proof(
            tx_id, siblings, merkle_root, block_hash, block.block_hash
        ):
            return None, f"Merkle proof for {tx_id} does not verify"

        seen_positions.add((height, index))
        proven[tx_id] = {"height": height, "index": index, "proof": proof}
    return proven, None


def _check_tx_claim(claim: dict, blocks: list[Block], entry: dict) -> bool:
    """Cross-check one transaction-bearing response object.

    Only fields actually present are compared, so proof objects, index rows
    and listing items share one checker.
    """
    height = entry["height"]
    index = entry["index"]
    proof = entry["proof"]
    block = blocks[height]
    tx = block.transactions[index]
    if claim["tx_id"] != tx.tx_id:
        return False
    if "height" in claim and claim["height"] != height:
        return False
    if "index" in claim and claim["index"] != index:
        return False
    if "block_hash" in claim and claim["block_hash"] != block.block_hash:
        return False
    if "merkle_root" in claim and claim["merkle_root"] != block.merkle_root:
        return False
    if "siblings" in claim and claim["siblings"] != proof.get("siblings"):
        return False
    if "from" in claim and claim["from"] != tx.sender:
        return False
    if "to" in claim and claim["to"] != tx.recipient:
        return False
    if "amount" in claim and claim["amount"] != tx.amount:
        return False
    return True


def _check_block_summary(response: dict, blocks: list[Block]) -> bool:
    """Cross-check a GET-block style response against the recomputed chain."""
    height = response.get("height")
    if not _is_int(height) or height < 0 or height >= len(blocks):
        return False
    block = blocks[height]
    if response.get("block_hash") != block.block_hash:
        return False
    if "prev_hash" in response and response["prev_hash"] != block.prev_hash:
        return False
    if "merkle_root" in response and response["merkle_root"] != block.merkle_root:
        return False
    if "status" in response and response["status"] != block.status:
        return False
    if "transaction_ids" in response and response["transaction_ids"] != [
        tx.tx_id for tx in block.transactions
    ]:
        return False
    return True


def _check_descriptor(response: dict, blocks: list[Block]) -> bool:
    """Cross-check a fork descriptor S embedded in the response."""
    descriptor = _fork_descriptor(blocks)
    if response.get("tip_hash") != descriptor["tip_hash"]:
        return False
    for field in ("height", "length", "status"):
        if field in response and response[field] != descriptor[field]:
            return False
    return True


def _cross_check_response(
    response: dict, blocks: list[Block], proven: dict[str, dict]
) -> bool:
    """Cross-check every claim the response makes against chain and proofs."""
    # Transaction-bearing shapes: an index listing, or a single proof/row.
    if "items" in response:
        items = response["items"]
        if not isinstance(items, list):
            return False
        for item in items:
            if not isinstance(item, dict) or not crypto.is_hex64(item.get("tx_id")):
                return False
            entry = proven.get(item["tx_id"])
            if entry is None or not _check_tx_claim(item, blocks, entry):
                return False
    elif crypto.is_hex64(response.get("tx_id")):
        entry = proven.get(response["tx_id"])
        if entry is None or not _check_tx_claim(response, blocks, entry):
            return False

    # A block summary (height + block_hash) is checked against its block.
    if "block_hash" in response and "height" in response and "tx_id" not in response:
        if not _check_block_summary(response, blocks):
            return False

    # A fork descriptor S is checked against the chain tip.
    if crypto.is_hex64(response.get("tip_hash")):
        if not _check_descriptor(response, blocks):
            return False
    return True


def verify_bundle(bundle: Any, trust: Any, now: float | None = None) -> dict:
    """Verify an offline light-client bundle against a trust document.

    Returns ``{"ok": True, "source", "S", "verified_tx_ids"}`` on success or
    ``{"ok": False, "error": category}`` where category is one of
    input/auth/expired/integrity/proof.
    """
    current = time.time() if now is None else now

    # -- trust document structure (input) -----------------------------------
    if not isinstance(trust, dict) or not crypto.is_hex64(trust.get("genesis_hash")):
        return _failure(ERR_INPUT)
    genesis_hash = trust["genesis_hash"]
    sources = trust.get("sources", {})
    allowlist = trust.get("allowlist", {})
    if not isinstance(sources, dict) or not isinstance(allowlist, dict):
        return _failure(ERR_INPUT)

    # -- bundle structure (input) -------------------------------------------
    if not isinstance(bundle, dict):
        return _failure(ERR_INPUT)
    for field in ("source", "expires_at", "response", "candidate", "proofs"):
        if field not in bundle:
            return _failure(ERR_INPUT)
    source = bundle["source"]
    expires_at = bundle["expires_at"]
    response = bundle["response"]
    candidate = bundle["candidate"]
    proofs_raw = bundle["proofs"]
    signature = bundle.get("signature")
    if not isinstance(source, str) or not source:
        return _failure(ERR_INPUT)
    if not _is_int(expires_at):
        return _failure(ERR_INPUT)
    if not isinstance(response, dict):
        return _failure(ERR_INPUT)
    blocks_raw = _blocks_of(candidate)
    if blocks_raw is None:
        return _failure(ERR_INPUT)
    if not isinstance(proofs_raw, list):
        return _failure(ERR_INPUT)
    if signature is not None and (not isinstance(signature, str) or not signature):
        return _failure(ERR_INPUT)
    allow_present = source in allowlist
    allow_deadline = allowlist.get(source)
    if not _is_deadline(allow_deadline):
        return _failure(ERR_INPUT)

    entry_present = source in sources
    parsed_entry = None
    if entry_present:
        parsed_entry = _parse_trust_entry(sources[source])
        if parsed_entry is None:
            return _failure(ERR_INPUT)
    public_key = parsed_entry[0] if parsed_entry is not None else None
    entry_expiry = parsed_entry[1] if parsed_entry is not None else None

    # -- source must be trusted and unexpired (auth / expired) --------------
    entry_live = parsed_entry is not None and _deadline_live(entry_expiry, current)
    allow_live = allow_present and _deadline_live(allow_deadline, current)
    if not entry_present and not allow_present:
        return _failure(ERR_AUTH)
    if not entry_live and not allow_live:
        return _failure(ERR_EXPIRED)
    if expires_at <= current:
        return _failure(ERR_EXPIRED)

    # -- signature policy and verification ----------------------------------
    if signature is None:
        # No signature: only an allowlisted source without a registered key
        # may serve an unsigned bundle.
        if not allow_live or public_key is not None:
            return _failure(ERR_AUTH)
    else:
        # A registered, unexpired public key is mandatory for a signed bundle.
        if public_key is None:
            return _failure(ERR_AUTH)
        if not entry_live:
            return _failure(ERR_EXPIRED)
        covered = {key: value for key, value in bundle.items() if key != "signature"}
        canonical = json.dumps(
            covered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).digest()
        if not crypto.verify_signature(public_key, digest, signature):
            return _failure(ERR_INTEGRITY)

    # -- recompute the candidate chain (integrity) --------------------------
    blocks, _reason = _recompute_chain(blocks_raw, genesis_hash)
    if blocks is None:
        return _failure(ERR_INTEGRITY)

    # Summary fields on an export-style candidate must not overstate the chain.
    if isinstance(candidate, dict):
        descriptor = _fork_descriptor(blocks)
        for field in ("tip_hash", "height", "length", "status"):
            if field in candidate and candidate[field] != descriptor[field]:
                return _failure(ERR_INTEGRITY)

    # -- proofs (proof) ------------------------------------------------------
    proven, _reason = _verify_proofs(proofs_raw, blocks)
    if proven is None:
        return _failure(ERR_PROOF)

    # -- cross-check the response against chain and proofs (integrity) ------
    if not _cross_check_response(response, blocks, proven):
        return _failure(ERR_INTEGRITY)

    return {
        "ok": True,
        "source": source,
        "S": _fork_descriptor(blocks),
        "verified_tx_ids": sorted(proven),
    }


# Short operation name matching the ``verify`` CLI subcommand.
verify = verify_bundle
