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
        # Optional account-state extension: all four fields are either present
        # together or absent together, and state_proofs is a non-empty list.
        "state_root": str,            # 64 lowercase hex, anchored state root
        "state_height": int,          # confirmed anchor block height
        "state_block_hash": str,      # 64 lowercase hex anchor block hash
        "state_proofs": [             # account-state inclusion proofs
            {"height": int, "proof": {account, balance,
                                      confirmed_transactions, index,
                                      state_root, height, block_hash,
                                      siblings}},
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
   under the existing rules, and its block must not be the pending tip. When
   the state extension is present, its anchor (``state_height`` /
   ``state_block_hash``) must name a confirmed candidate block (integrity) and
   every state proof must agree with both anchor heights, the state root and
   the anchor hash; each account must sit at its ``index`` in the ascending
   account set of the anchor height's confirmed transactions, ``height`` +
   ``account`` pairs must be unique, and every proof must pass
   ``crypto.verify_account_proof`` against the bundle's anchors.

On success :func:`verify_bundle` returns
``{"ok": True, "source", "S", "verified_tx_ids"}`` — plus
``"verified_accounts"`` (ascending) when the state extension was verified —
on failure ``{"ok": False, "error": category}`` with category one of
``input/auth/expired/integrity/proof``.

:func:`verify_range_export` verifies one exported incremental range delivery
(the ``GET /v1/forks/sync/range/export`` document, top-level key order
``source, request_id, mode, expires_at, anchor, blocks, tip, attestation``)
offline against a caller-pinned expected anchor and the local trust document.
The expected anchor must strictly equal the document's ``anchor``; the
delivered tail is recomputed standalone from that anchor (consecutive
heights, prev_hash linkage, per-transaction tx_id and Ed25519 signatures,
unique and block-ascending tx_ids, Merkle roots, block hashes,
pending-only-at-tip) and the closed ``tip`` summary must recompute. A
``plain`` export must come from an unexpired ``allowlist`` entry and carry
``attestation: null``. An ``attested`` export is authenticated by key
version: when the trust document carries a ``source_key_history`` mapping,
the attestation's ``version`` selects that source's historical public key
(which must equal the attestation's ``public_key``); an unknown source or
version, or a mismatched key, is ``auth`` and a signature that fails to
verify is ``integrity`` — so an export signed under a since-rotated key
stays verifiable. A trust document without ``source_key_history`` keeps the
legacy rule: the source must be an unexpired ``trust.sources`` entry whose
pinned key matches the attestation and verifies the Ed25519 signature over
the SHA-256 digest of the canonical ``ledger-sync-range-v1`` message.
Failures map to ``input`` (structure), ``auth`` (authorization), ``expired``
(deadlines) and ``integrity`` (anchor/chain/signature); nothing is raised.
Success returns ``{"ok": True, "source", "request_id", "mode", "anchor",
"tip", "verified_tx_ids"}`` with ``verified_tx_ids`` ascending.

:func:`verify_range_exports` verifies an ordered, non-empty batch of such
range deliveries as one continuous chain. The first page's anchor must equal
the caller-pinned ``expected_anchor``; every later page's anchor must equal
the previous page's closed tip's ``{height, block_hash}``. Each page is
re-verified under the same input/auth/expired/integrity rules, transaction
ids are unique across the whole batch, and a pending block may only appear on
the last page — a broken anchor, a height jump, a duplicate transaction or any
block after a pending one is an ``integrity`` failure. Success returns
``{"ok": True, "anchor", "tip", "pages", "verified_tx_ids"}`` with ``tip``
the last page's tip, ``pages`` the page count and ``verified_tx_ids``
ascending; failure is ``{"ok": False, "error": category}`` with category one
of ``input/auth/expired/integrity``.

:func:`advance` persists one verified batch as a monotonic *range checkpoint*
file so a light client can resume across restarts without re-pinning the
anchor by hand. The checkpoint document is a single compact JSON object with
the declared key order ``generation, anchor, tip, context, state_hash`` —
``generation`` a counter starting at 1 and advancing by one per successful
call, ``anchor``/``tip`` the verified batch boundaries, ``context`` (key order
``verified_at, trust, documents, verified_tx_ids``) everything needed to
re-verify the batch offline, and ``state_hash`` the SHA-256 of the canonical
JSON bytes of every other field. The file is written compact UTF-8 with
non-ASCII characters unescaped and a single trailing newline, atomically
(temp file, fsync, ``os.replace``) under a per-path lock shared by every
``advance`` call in the process; a failed call never advances the generation.
On every call the existing checkpoint is reloaded and strictly validated —
declared key orders, field types, the ``state_hash`` digest, and a full
re-verification of the stored ``context`` at its recorded ``verified_at`` —
and any mismatch is a ``state`` failure: a corrupt checkpoint is never
truncated, rebuilt or silently reset. The first call pins the batch anchor
from the caller's ``anchor`` argument; later calls must pass ``None`` or the
stored tip (as the ``{height, block_hash}`` anchor or the full tip
descriptor), and a conflicting anchor is a ``state`` failure. ``now`` must be
a non-boolean non-negative integer. Success returns the verifier's
``{"ok": True, "anchor", "tip", "pages", "verified_tx_ids"}`` with
``generation`` appended; failure returns exactly ``{"ok": False, "error"}``
with category one of ``input/auth/expired/integrity/state/io``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time

from . import crypto
from .models import STATUS_CONFIRMED, STATUS_PENDING, Block, compute_block_hash
from .store import GENESIS_PREV_HASH, attested_range_message

# Stable error categories returned to callers.
ERR_INPUT = "input"
ERR_AUTH = "auth"
ERR_EXPIRED = "expired"
ERR_INTEGRITY = "integrity"
ERR_PROOF = "proof"

# Descriptor fields of a chain tip, exactly as GET /v1/chain reports them.
DESCRIPTOR_FIELDS = ("tip_hash", "height", "length", "status")

# The optional account-state extension: these four bundle fields are either
# all present or all absent.
STATE_FIELDS = ("state_root", "state_height", "state_block_hash", "state_proofs")

# The exact key set of one state-proof document (mirrors the server's
# GET /v1/accounts/{account}/proof response).
_STATE_PROOF_KEYS = frozenset(
    (
        "account",
        "balance",
        "confirmed_transactions",
        "index",
        "state_root",
        "height",
        "block_hash",
        "siblings",
    )
)

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
    on success — extended bundles also carry ``"verified_accounts"`` — or
    ``{"ok": False, "error": category}`` on failure. Never raises for
    malformed input: every defect maps to one of the five categories.
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
        has_state = "state_root" in bundle
        if has_state:
            _check_state_anchor(bundle, blocks)
        verified_ids = _verify_proofs(bundle["proofs"], blocks)
        verified_accounts = (
            _verify_state_proofs(bundle, blocks) if has_state else None
        )
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    result = {
        "ok": True,
        "source": source,
        "S": descriptor,
        "verified_tx_ids": verified_ids,
    }
    if verified_accounts is not None:
        result["verified_accounts"] = verified_accounts
    return result


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
    _validate_state_fields(bundle)

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


def _validate_state_fields(bundle: dict) -> None:
    """Structural validation of the optional account-state extension.

    The four state fields are all-or-nothing; when present, ``state_root`` and
    ``state_block_hash`` must be 64-char lowercase hex, ``state_height`` a
    non-boolean non-negative integer and ``state_proofs`` a non-empty list.
    Every item must carry exactly ``{height, proof}`` and every proof document
    exactly the eight documented keys with the right JSON types. Only shape
    and type are judged here — domain defects (bad hex, negative balances,
    illegal directions) are reported later as integrity/proof failures.
    """
    present = [field for field in STATE_FIELDS if field in bundle]
    if not present:
        return
    if len(present) != len(STATE_FIELDS):
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(bundle["state_root"]):
        raise _Failure(ERR_INPUT)
    if not _is_int(bundle["state_height"]) or bundle["state_height"] < 0:
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(bundle["state_block_hash"]):
        raise _Failure(ERR_INPUT)
    state_proofs = bundle["state_proofs"]
    if not isinstance(state_proofs, list) or not state_proofs:
        raise _Failure(ERR_INPUT)
    for item in state_proofs:
        if not isinstance(item, dict) or set(item) != {"height", "proof"}:
            raise _Failure(ERR_INPUT)
        if not _is_int(item["height"]):
            raise _Failure(ERR_INPUT)
        proof = item["proof"]
        if not isinstance(proof, dict) or set(proof) != _STATE_PROOF_KEYS:
            raise _Failure(ERR_INPUT)
        if not isinstance(proof["account"], str) or not proof["account"]:
            raise _Failure(ERR_INPUT)
        if not _is_int(proof["balance"]):
            raise _Failure(ERR_INPUT)
        transactions = proof["confirmed_transactions"]
        if not isinstance(transactions, list) or any(
            not isinstance(tx_id, str) for tx_id in transactions
        ):
            raise _Failure(ERR_INPUT)
        if not _is_int(proof["index"]):
            raise _Failure(ERR_INPUT)
        if not isinstance(proof["state_root"], str):
            raise _Failure(ERR_INPUT)
        if not _is_int(proof["height"]):
            raise _Failure(ERR_INPUT)
        if not isinstance(proof["block_hash"], str):
            raise _Failure(ERR_INPUT)
        if not isinstance(proof["siblings"], list):
            raise _Failure(ERR_INPUT)


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
    coercions such as ``"1"`` or ``1.0`` heights are rejected outright; such
    type/domain defects (non-integer or negative height, non-positive or
    non-integer amount) are reported as ``input``, while recomputation
    mismatches stay ``integrity``.
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
        # A height of the wrong type or sign is a field-type defect (input),
        # not a chain mismatch: strings, floats and booleans must never be
        # coerced into plausible integers before the linkage checks below.
        if not _is_int(height) or height < 0:
            raise _Failure(ERR_INPUT)
        if not isinstance(prev_hash, str):
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
            # Same rule as the block height: the raw amount must already be a
            # non-boolean positive integer — never a coercible string, float
            # or bool — so a domain/type defect is reported as input.
            if not _is_int(amount) or amount <= 0:
                raise _Failure(ERR_INPUT)
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


def _check_state_anchor(bundle: dict, blocks: list[Block]) -> None:
    """Bind the state extension's anchor to the recomputed candidate chain.

    ``state_height`` must name a confirmed candidate block whose hash equals
    ``state_block_hash``; an unknown height, a pending block or a hash
    mismatch is an integrity failure. Every state-proof item and document
    must agree with both anchor heights, the bundle's state root and the
    anchor block hash.
    """
    height = bundle["state_height"]
    state_root = bundle["state_root"]
    block_hash = bundle["state_block_hash"]
    if height >= len(blocks):
        raise _Failure(ERR_INTEGRITY)
    block = blocks[height]
    if block.status != STATUS_CONFIRMED or block.block_hash != block_hash:
        raise _Failure(ERR_INTEGRITY)
    for item in bundle["state_proofs"]:
        proof = item["proof"]
        if item["height"] != height or proof["height"] != height:
            raise _Failure(ERR_INTEGRITY)
        if proof["state_root"] != state_root or proof["block_hash"] != block_hash:
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


def _verify_state_proofs(bundle: dict, blocks: list[Block]) -> list[str]:
    """Verify every account-state proof against the bundle's state anchor.

    The anchor's confirmed transactions determine the ascending account set;
    each proof's ``account`` must belong to it and its ``index`` must be the
    account's position in that ordering. ``height`` + ``account`` pairs must
    be unique. Every proof is then checked with
    :func:`crypto.verify_account_proof` against the bundle's ``state_root``,
    ``state_height`` and ``state_block_hash``; any failure — an illegal
    direction or hash, a forged leaf, an illegal self-pair, a malformed
    sibling path — is a proof failure. Returns the verified accounts sorted
    ascending.
    """
    height = bundle["state_height"]
    # The account set of the anchor height: every account touched by a
    # confirmed transaction up to and including the anchor block, ascending.
    accounts: set[str] = set()
    for block in blocks[: height + 1]:
        if block.status != STATUS_CONFIRMED:
            continue
        for tx in block.transactions:
            accounts.add(tx.sender)
            accounts.add(tx.recipient)
    position = {account: index for index, account in enumerate(sorted(accounts))}

    verified: list[str] = []
    seen: set[tuple] = set()
    for item in bundle["state_proofs"]:
        proof = item["proof"]
        account = proof["account"]
        expected = position.get(account)
        # An account outside the anchor's set, or an index that is not the
        # account's ascending position (including out-of-range), is a proof
        # failure.
        if expected is None or proof["index"] != expected:
            raise _Failure(ERR_PROOF)
        key = (item["height"], account)
        if key in seen:
            raise _Failure(ERR_PROOF)
        seen.add(key)
        if not crypto.verify_account_proof(
            proof,
            bundle["state_root"],
            height,
            bundle["state_block_hash"],
        ):
            raise _Failure(ERR_PROOF)
        verified.append(account)
    return sorted(verified)


# -- range export verification -------------------------------------------------

# The exact top-level key order of one exported incremental range delivery,
# exactly as GET /v1/forks/sync/range/export emits it.
RANGE_EXPORT_KEYS = (
    "source",
    "request_id",
    "mode",
    "expires_at",
    "anchor",
    "blocks",
    "tip",
    "attestation",
)

RANGE_EXPORT_MODES = ("plain", "attested")

# The exact key sets of the export's nested closed documents.
_RANGE_ANCHOR_KEYS = frozenset(("height", "block_hash"))
_RANGE_TIP_KEYS = frozenset(DESCRIPTOR_FIELDS)
_RANGE_ATTESTATION_KEYS = frozenset(("public_key", "version", "signature"))

# The exact key set of one GET /v1/trust source_key_history item, in its
# documented key order version, public_key, activated_event_id.
_HISTORY_ENTRY_KEYS = ("version", "public_key", "activated_event_id")


def verify_range_export(
    document: object,
    expected_anchor: object,
    trust: object,
    now: int | float | None = None,
) -> dict:
    """Verify one exported incremental range delivery offline.

    ``document`` is the decoded ``GET /v1/forks/sync/range/export`` response
    (top-level keys exactly ``source, request_id, mode, expires_at, anchor,
    blocks, tip, attestation`` in that order); ``expected_anchor`` is the
    caller-pinned ``{height, block_hash}`` the document's anchor must strictly
    equal; ``trust`` is the local trust document (``sources`` pins
    ``{public_key, expires_at}`` per attested source, ``allowlist`` maps
    keyless plain sources to their expiry).

    Returns ``{"ok": True, "source", "request_id", "mode", "anchor", "tip",
    "verified_tx_ids"}`` on success (tx_ids ascending) or
    ``{"ok": False, "error": category}`` on failure with category one of
    ``input/auth/expired/integrity``. Never raises for malformed input.
    """
    try:
        anchor, tip, verified_ids = _verify_range_page(
            document, expected_anchor, trust, time.time() if now is None else now
        )
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {
        "ok": True,
        "source": document["source"],
        "request_id": document["request_id"],
        "mode": document["mode"],
        "anchor": anchor,
        "tip": tip,
        "verified_tx_ids": verified_ids,
    }


# Fixed success key order for a verified multi-page range batch.
RANGE_BATCH_RESULT_KEYS = (
    "ok",
    "anchor",
    "tip",
    "pages",
    "verified_tx_ids",
)


def verify_range_exports(
    documents: object,
    expected_anchor: object,
    trust: object,
    now: int | float | None = None,
) -> dict:
    """Verify an ordered batch of exported range deliveries as one chain.

    ``documents`` must be a non-empty list of decoded
    ``GET /v1/forks/sync/range/export`` documents (each with the exact key
    order ``source, request_id, mode, expires_at, anchor, blocks, tip,
    attestation``); ``expected_anchor`` is the caller-pinned
    ``{height, block_hash}`` the first page's anchor must strictly equal;
    ``trust`` is the local trust document applied to every page.

    The pages are re-verified in order: the first page is checked against
    ``expected_anchor``, and every later page's anchor must strictly equal the
    previous page's closed ``tip`` reduced to ``{height, block_hash}`` — which
    also rejects a height jump or a fork at the seam. Transaction ids must be
    unique across the whole batch, not just inside one page, and a pending
    block may only appear on the last page.

    Returns ``{"ok": True, "anchor", "tip", "pages", "verified_tx_ids"}`` on
    success — ``anchor`` the pinned anchor of the first page, ``tip`` the last
    page's closed tip, ``pages`` the number of pages and
    ``verified_tx_ids`` ascending across every page — or
    ``{"ok": False, "error": category}`` on failure with category one of
    ``input/auth/expired/integrity``. Never raises for malformed input.
    """
    current = time.time() if now is None else now
    try:
        if not isinstance(documents, list) or not documents:
            raise _Failure(ERR_INPUT)
        # The pinned anchor is validated once up front so a malformed caller
        # anchor is an input error even before the first page is inspected.
        anchor = _validate_range_anchor(expected_anchor)
        _validate_range_trust(trust)
        pages = len(documents)
        expected = anchor
        first_anchor: dict | None = None
        last_tip: dict | None = None
        seen_tx_ids: set[str] = set()
        verified_ids: list[str] = []
        for position, document in enumerate(documents):
            # _verify_range_page itself rejects a page whose anchor does not
            # strictly equal ``expected`` — the first page's pinned anchor and
            # every later page's previous tip — so a broken seam or a height
            # jump surfaces as integrity here.
            page_anchor, tip, page_tx_ids = _verify_range_page(
                document, expected, trust, current
            )
            if first_anchor is None:
                first_anchor = page_anchor
            # Transaction ids must be unique across pages, not merely within
            # one re-verified tail.
            duplicates = seen_tx_ids.intersection(page_tx_ids)
            if duplicates:
                raise _Failure(ERR_INTEGRITY)
            seen_tx_ids.update(page_tx_ids)
            verified_ids.extend(page_tx_ids)
            # A pending block may only sit on the very last page: any block
            # delivered after a pending tip breaks the continuous confirmed
            # chain and cannot be linked to a committed predecessor.
            if tip["status"] == STATUS_PENDING and position != pages - 1:
                raise _Failure(ERR_INTEGRITY)
            last_tip = tip
            expected = {"height": tip["height"], "block_hash": tip["tip_hash"]}
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {
        "ok": True,
        "anchor": first_anchor,
        "tip": last_tip,
        "pages": pages,
        "verified_tx_ids": sorted(verified_ids),
    }


def _verify_range_page(
    document: object, expected_anchor: object, trust: object, now: float
) -> tuple[dict, dict, list[str]]:
    """Verify one range page, returning ``(anchor, tip, verified_tx_ids)``.

    Shared core of :func:`verify_range_export` (one page) and
    :func:`verify_range_exports` (a batch chaining each page's tip into the
    next page's expected anchor). Raises :class:`_Failure` with the public
    error category on every defect.
    """
    anchor = _validate_range_export_inputs(document, expected_anchor, trust)
    _authenticate_range_export(document, trust, now)
    # The caller-pinned anchor must strictly equal the delivered one.
    if document["anchor"] != expected_anchor:
        raise _Failure(ERR_INTEGRITY)
    tail = _recompute_range_tail(anchor, document["blocks"])
    tip = _range_tip_descriptor(anchor, tail)
    _check_range_tip(document["tip"], tip)
    if document["mode"] == "attested":
        _verify_range_attestation(document, trust)
    verified_ids = sorted(tx.tx_id for block in tail for tx in block.transactions)
    return anchor, tip, verified_ids


def _validate_range_export_inputs(
    document: object, expected_anchor: object, trust: object
) -> dict:
    """Structural validation of the export document, the pinned anchor and
    the trust document. Returns the closed ``{height, block_hash}`` anchor.
    """
    if not isinstance(document, dict):
        raise _Failure(ERR_INPUT)
    if tuple(document.keys()) != RANGE_EXPORT_KEYS:
        raise _Failure(ERR_INPUT)
    source = document["source"]
    if not isinstance(source, str) or not source:
        raise _Failure(ERR_INPUT)
    request_id = document["request_id"]
    if not isinstance(request_id, str) or not request_id:
        raise _Failure(ERR_INPUT)
    if document["mode"] not in RANGE_EXPORT_MODES:
        raise _Failure(ERR_INPUT)
    if not _is_int(document["expires_at"]):
        raise _Failure(ERR_INPUT)
    anchor = _validate_range_anchor(document["anchor"])
    # The expected anchor is validated for shape here; the strict equality
    # binding itself is an integrity check after authorization and expiry.
    _validate_range_anchor(expected_anchor)
    blocks = document["blocks"]
    if not isinstance(blocks, list) or not blocks:
        raise _Failure(ERR_INPUT)
    tip = document["tip"]
    if not isinstance(tip, dict) or set(tip) != _RANGE_TIP_KEYS:
        raise _Failure(ERR_INPUT)
    if document["mode"] == "attested":
        attestation = document["attestation"]
        if not isinstance(attestation, dict) or set(attestation) != (
            _RANGE_ATTESTATION_KEYS
        ):
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(attestation["public_key"]):
            raise _Failure(ERR_INPUT)
        version = attestation["version"]
        if not _is_int(version) or version < 1:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex128(attestation["signature"]):
            raise _Failure(ERR_INPUT)
    _validate_range_trust(trust)
    return anchor


def _validate_range_anchor(raw: object) -> dict:
    """Structural validation of a ``{height, block_hash}`` anchor document."""
    if not isinstance(raw, dict) or set(raw) != _RANGE_ANCHOR_KEYS:
        raise _Failure(ERR_INPUT)
    height = raw["height"]
    if not _is_int(height) or height < 0:
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(raw["block_hash"]):
        raise _Failure(ERR_INPUT)
    return {"height": height, "block_hash": raw["block_hash"]}


def _validate_range_trust(trust: object) -> None:
    """Structural validation of the trust document's ``sources``/``allowlist``.

    Mirrors the bundle verifier's trust rules; a ``genesis_hash`` is not
    required here because the caller pins the range anchor directly. The
    optional GET /v1/trust ``source_key_history`` mapping is validated too:
    each source maps to a non-empty ascending array of
    ``{version, public_key, activated_event_id}`` items whose versions are
    dense from 1 with strictly ascending activation ids, both numeric fields
    non-boolean positive integers and the public key 64 lowercase hex.
    """
    if not isinstance(trust, dict):
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
    history = trust.get("source_key_history")
    if history is not None:
        if not isinstance(history, dict):
            raise _Failure(ERR_INPUT)
        for name, entries in history.items():
            if not isinstance(name, str) or not name:
                raise _Failure(ERR_INPUT)
            if not isinstance(entries, list) or not entries:
                raise _Failure(ERR_INPUT)
            last_activated = None
            for position, entry in enumerate(entries):
                if not isinstance(entry, dict) or set(entry) != set(
                    _HISTORY_ENTRY_KEYS
                ):
                    raise _Failure(ERR_INPUT)
                version = entry.get("version")
                public_key = entry.get("public_key")
                activated = entry.get("activated_event_id")
                # Versions are dense from 1; both numeric fields are plain
                # (non-boolean) positive integers.
                if not _is_int(version) or version != position + 1:
                    raise _Failure(ERR_INPUT)
                if not isinstance(public_key, str) or not _HEX32_RE.fullmatch(public_key):
                    raise _Failure(ERR_INPUT)
                if not _is_int(activated) or activated < 1:
                    raise _Failure(ERR_INPUT)
                if last_activated is not None and activated <= last_activated:
                    raise _Failure(ERR_INPUT)
                last_activated = activated


def _has_key_history(trust: dict) -> bool:
    """Whether the trust document carries a source_key_history mapping."""
    return "source_key_history" in trust


def _authenticate_range_export(document: dict, trust: dict, now: float) -> None:
    """Check mode-specific source authorization and every deadline.

    A ``plain`` export is only acceptable from an allowlisted source and must
    carry ``attestation: null``. An ``attested`` export is authorized one of
    two ways:

    * the trust document carries a ``source_key_history`` mapping (the new
      rule): the source must appear in the mapping — the historical public key
      matching and signature verification happen by attestation version in
      :func:`_verify_range_attestation`; the trust ``sources`` entry and its
      deadline play no role, so a delivery signed under a since-rotated or
      revoked key still authenticates as long as the document itself is
      unexpired;
    * the mapping is absent (the legacy rule): the source must be a
      ``sources`` entry whose unexpired deadline is checked.

    All deadlines are checked before any integrity work: an expired,
    correctly-signed export is still unusable.
    """
    source = document["source"]
    mode = document["mode"]
    sources = trust.get("sources", {})
    allowlist = trust.get("allowlist", {})
    if mode == "plain":
        if source not in allowlist:
            raise _Failure(ERR_AUTH)
        # A plain export carrying an attestation is not a plain delivery.
        if document["attestation"] is not None:
            raise _Failure(ERR_AUTH)
    elif _has_key_history(trust):
        # Historical-key authorization: the source (and later the attestation
        # version) must resolve in the mapping; the current registry entry is
        # deliberately not consulted.
        if source not in trust["source_key_history"]:
            raise _Failure(ERR_AUTH)
    elif source not in sources:
        raise _Failure(ERR_AUTH)

    if document["expires_at"] <= now:
        raise _Failure(ERR_EXPIRED)
    if mode == "plain":
        if allowlist[source] <= now:
            raise _Failure(ERR_EXPIRED)
    elif not _has_key_history(trust) and sources[source]["expires_at"] <= now:
        # Legacy rule only: the pinned registry entry's own deadline applies.
        raise _Failure(ERR_EXPIRED)


def _recompute_range_tail(anchor: dict, blocks_raw: list) -> list[Block]:
    """Recompute and validate the delivered tail standalone from the anchor.

    Mirrors the node's own range-tail rules: heights run consecutively from
    ``anchor.height + 1``, the first ``prev_hash`` is the anchor hash and
    later ones link internally, every transaction's tx_id and Ed25519
    signature verifies, tx_ids are unique across the tail and ascending
    inside each block, Merkle roots and block hashes recompute, and a pending
    block may only sit at the tail tip. Every field is checked on the *raw*
    JSON value; type/domain defects (non-integer or negative height,
    non-positive or non-integer amount) are reported as ``input``, while
    recomputation mismatches stay ``integrity``.
    """
    blocks: list[Block] = []
    seen_tx_ids: set[str] = set()
    for position, block_raw in enumerate(blocks_raw):
        if not isinstance(block_raw, dict):
            raise _Failure(ERR_INTEGRITY)
        height = block_raw.get("height")
        prev_hash = block_raw.get("prev_hash")
        merkle_root = block_raw.get("merkle_root")
        block_hash = block_raw.get("block_hash")
        status = block_raw.get("status")
        txs_raw = block_raw.get("transactions")
        # Same rule as the whole-chain recomputation: a height of the wrong
        # type or sign is a field-type defect (input), never coerced.
        if not _is_int(height) or height < 0:
            raise _Failure(ERR_INPUT)
        if not isinstance(prev_hash, str):
            raise _Failure(ERR_INTEGRITY)
        if not crypto.is_hex64(merkle_root) or not crypto.is_hex64(block_hash):
            raise _Failure(ERR_INTEGRITY)
        if status not in ("pending", "confirmed") or not isinstance(txs_raw, list):
            raise _Failure(ERR_INTEGRITY)
        if height != anchor["height"] + 1 + position:
            raise _Failure(ERR_INTEGRITY)
        expected_prev = (
            anchor["block_hash"] if position == 0 else blocks[position - 1].block_hash
        )
        if prev_hash != expected_prev:
            raise _Failure(ERR_INTEGRITY)
        if position < len(blocks_raw) - 1 and status != STATUS_CONFIRMED:
            # A pending block may only sit at the tail tip.
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
            # The raw amount must already be a non-boolean positive integer —
            # never a coercible string, float or bool.
            if not _is_int(amount) or amount <= 0:
                raise _Failure(ERR_INPUT)
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


def _range_tip_descriptor(anchor: dict, tail: list[Block]) -> dict:
    """Recompute the delivered chain's closed tip summary from anchor + tail."""
    tip = tail[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": anchor["height"] + 1 + len(tail),
        "status": tip.status,
    }


def _check_range_tip(supplied: dict, descriptor: dict) -> None:
    """The export's closed tip summary must equal the recomputed descriptor."""
    for field in DESCRIPTOR_FIELDS:
        if supplied[field] != descriptor[field]:
            raise _Failure(ERR_INTEGRITY)


def _verify_range_attestation(document: dict, trust: dict) -> None:
    """Verify the attested export's Ed25519 signature under the pinned key.

    Two rules, selected by the trust document:

    * with ``source_key_history`` present, the attestation's ``version``
      selects the source's historical public key; the source not appearing in
      the mapping, or the attestation version not being one of its dense
      versions, is an authorization failure (``auth``), as is a mismatch
      between the attestation's ``public_key`` and that historical key. The
      Ed25519 signature is then checked over the SHA-256 digest of the
      canonical ``ledger-sync-range-v1`` message — a wrong signature is an
      integrity failure. The attestation's version is already structurally
      guaranteed to be a positive integer.
    * without the mapping (legacy rule), the attestation's ``public_key``
      must be exactly the key the trust document pins in ``sources`` for the
      source (a mismatched credential is an authorization failure) and the
      same signature check follows.
    """
    source = document["source"]
    attestation = document["attestation"]
    if _has_key_history(trust):
        history = trust["source_key_history"].get(source)
        if history is None:
            raise _Failure(ERR_AUTH)
        version = attestation["version"]
        # Versions are structurally guaranteed dense from 1, so a valid
        # version simply indexes the ascending history.
        if version < 1 or version > len(history):
            raise _Failure(ERR_AUTH)
        pinned = history[version - 1]["public_key"]
        if attestation["public_key"] != pinned:
            raise _Failure(ERR_AUTH)
    else:
        pinned = trust.get("sources", {})[source]["public_key"]
        if attestation["public_key"] != pinned:
            raise _Failure(ERR_AUTH)
    message = attested_range_message(
        source,
        document["request_id"],
        document["expires_at"],
        document["anchor"],
        document["blocks"],
        document["tip"],
    )
    digest = hashlib.sha256(message).digest()
    if not crypto.verify_signature(pinned, digest, attestation["signature"]):
        raise _Failure(ERR_INTEGRITY)


# -- persistent range checkpoints ----------------------------------------------

# Additional error categories only advance() can report: a corrupt or
# conflicting persisted checkpoint (state) and a filesystem failure (io).
ERR_STATE = "state"
ERR_IO = "io"

# The declared key orders of the persisted checkpoint document.
CHECKPOINT_STATE_KEYS = ("generation", "anchor", "tip", "context", "state_hash")
CHECKPOINT_CONTEXT_KEYS = ("verified_at", "trust", "documents", "verified_tx_ids")

# One lock per checkpoint path serializes concurrent advance() calls within
# this process; the guard protects the registry itself.
_CHECKPOINT_LOCKS: dict[str, threading.Lock] = {}
_CHECKPOINT_LOCKS_GUARD = threading.Lock()


def _checkpoint_lock(path: str) -> threading.Lock:
    with _CHECKPOINT_LOCKS_GUARD:
        return _CHECKPOINT_LOCKS.setdefault(path, threading.Lock())


def _canonical_checkpoint_bytes(payload: dict) -> bytes:
    """Canonical JSON bytes the checkpoint ``state_hash`` covers.

    Sorted keys, compact separators, UTF-8 with non-ASCII characters
    unescaped — the same byte convention the checkpoint file itself uses, so
    the digest is stable regardless of incoming key order.
    """
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def advance(
    path: object,
    docs: object,
    trust: object,
    anchor: object,
    now: object,
) -> dict:
    """Verify one range-export batch and persist it as the next checkpoint.

    ``path`` is the checkpoint file; ``docs`` the non-empty ordered batch of
    ``GET /v1/forks/sync/range/export`` documents; ``trust`` the local trust
    document; ``anchor`` the caller-pinned ``{height, block_hash}`` on the
    first call and ``None`` or the stored tip (anchor form or full tip
    descriptor) afterwards; ``now`` a non-boolean non-negative integer of
    Unix seconds. Verification itself is :func:`verify_range_exports`.

    Returns the verifier's success document with ``generation`` appended, or
    exactly ``{"ok": False, "error": category}`` with category one of
    ``input/auth/expired/integrity/state/io``. Never raises for malformed
    input.
    """
    if not isinstance(path, str) or not path:
        return {"ok": False, "error": ERR_INPUT}
    if not _is_int(now) or now < 0:
        return {"ok": False, "error": ERR_INPUT}
    lock = _checkpoint_lock(os.path.abspath(path))
    with lock:
        try:
            return _advance(path, docs, trust, anchor, now)
        except _Failure as failure:
            return {"ok": False, "error": failure.category}
        except Exception:
            # Defensive: structurally unforeseeable inputs must report rather
            # than crash the verifying process.
            return {"ok": False, "error": ERR_INPUT}


def _advance(
    path: str, docs: object, trust: object, anchor: object, now: int
) -> dict:
    """Locked core of :func:`advance`: load, verify, persist, report."""
    state = _load_checkpoint(path)
    if state is None:
        # First use: the caller must pin a legal anchor for the batch.
        if anchor is None:
            raise _Failure(ERR_INPUT)
        expected_anchor = _validate_range_anchor(anchor)
        generation = 1
    else:
        generation = state["generation"] + 1
        expected_anchor = {
            "height": state["tip"]["height"],
            "block_hash": state["tip"]["tip_hash"],
        }
        if anchor is not None:
            _check_checkpoint_anchor(anchor, expected_anchor, state["tip"])
    result = verify_range_exports(docs, expected_anchor, trust, now)
    if not result["ok"]:
        # Already exactly {"ok": False, "error": category}; a failed call
        # touches neither the file nor the generation.
        return result
    record = {
        "generation": generation,
        "anchor": result["anchor"],
        "tip": result["tip"],
        "context": {
            "verified_at": now,
            "trust": trust,
            "documents": docs,
            "verified_tx_ids": result["verified_tx_ids"],
        },
    }
    record["state_hash"] = hashlib.sha256(
        _canonical_checkpoint_bytes(record)
    ).hexdigest()
    _write_checkpoint(path, record)
    return {
        "ok": True,
        "anchor": result["anchor"],
        "tip": result["tip"],
        "pages": result["pages"],
        "verified_tx_ids": result["verified_tx_ids"],
        "generation": generation,
    }


def _check_checkpoint_anchor(
    anchor: object, expected_anchor: dict, stored_tip: dict
) -> None:
    """Bind a later call's ``anchor`` argument to the persisted checkpoint.

    The caller may assert the stored tip either as the ``{height,
    block_hash}`` anchor it chains from or as the full tip descriptor the
    previous success returned; anything else conflicts with the persisted
    state. A malformed anchor document is an input defect, a well-formed but
    disagreeing one a state conflict.
    """
    if isinstance(anchor, dict) and set(anchor) == set(DESCRIPTOR_FIELDS):
        if anchor != stored_tip:
            raise _Failure(ERR_STATE)
        return
    supplied = _validate_range_anchor(anchor)
    if supplied != expected_anchor:
        raise _Failure(ERR_STATE)


def _load_checkpoint(path: str) -> dict | None:
    """Load and strictly validate the persisted checkpoint, if one exists.

    Returns ``None`` when no checkpoint file exists (first use). Every
    content defect — unreadable JSON, a wrong key order, a wrong field type,
    a ``state_hash`` mismatch, or a stored context that no longer re-verifies
    at its recorded ``verified_at`` — is a ``state`` failure; the checkpoint
    is never truncated, rebuilt or silently reset. Filesystem failures are
    ``io``.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return None
    except OSError:
        raise _Failure(ERR_IO) from None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _Failure(ERR_STATE) from None
    if not isinstance(document, dict) or tuple(document) != CHECKPOINT_STATE_KEYS:
        raise _Failure(ERR_STATE)
    generation = document["generation"]
    if not _is_int(generation) or generation < 1:
        raise _Failure(ERR_STATE)
    anchor = document["anchor"]
    if not isinstance(anchor, dict) or tuple(anchor) != ("height", "block_hash"):
        raise _Failure(ERR_STATE)
    if (
        not _is_int(anchor["height"])
        or anchor["height"] < 0
        or not crypto.is_hex64(anchor["block_hash"])
    ):
        raise _Failure(ERR_STATE)
    tip = document["tip"]
    if not isinstance(tip, dict) or tuple(tip) != DESCRIPTOR_FIELDS:
        raise _Failure(ERR_STATE)
    if not crypto.is_hex64(tip["tip_hash"]):
        raise _Failure(ERR_STATE)
    if not _is_int(tip["height"]) or tip["height"] < 0:
        raise _Failure(ERR_STATE)
    if not _is_int(tip["length"]) or tip["length"] < 1:
        raise _Failure(ERR_STATE)
    if tip["status"] not in (STATUS_PENDING, STATUS_CONFIRMED):
        raise _Failure(ERR_STATE)
    context = document["context"]
    if not isinstance(context, dict) or tuple(context) != CHECKPOINT_CONTEXT_KEYS:
        raise _Failure(ERR_STATE)
    verified_at = context["verified_at"]
    if not _is_int(verified_at) or verified_at < 0:
        raise _Failure(ERR_STATE)
    if not isinstance(context["documents"], list) or not context["documents"]:
        raise _Failure(ERR_STATE)
    verified_tx_ids = context["verified_tx_ids"]
    if not isinstance(verified_tx_ids, list) or any(
        not isinstance(tx_id, str) for tx_id in verified_tx_ids
    ):
        raise _Failure(ERR_STATE)
    state_hash = document["state_hash"]
    if not crypto.is_hex64(state_hash):
        raise _Failure(ERR_STATE)
    payload = {key: document[key] for key in CHECKPOINT_STATE_KEYS[:-1]}
    if hashlib.sha256(_canonical_checkpoint_bytes(payload)).hexdigest() != state_hash:
        raise _Failure(ERR_STATE)
    # Replay the stored context at its recorded verification time: the batch
    # must still verify end-to-end and reproduce the persisted boundaries.
    replay = verify_range_exports(
        context["documents"], anchor, context["trust"], verified_at
    )
    if (
        not replay.get("ok")
        or replay["anchor"] != anchor
        or replay["tip"] != tip
        or replay["verified_tx_ids"] != verified_tx_ids
    ):
        raise _Failure(ERR_STATE)
    return {"generation": generation, "tip": tip}


def _write_checkpoint(path: str, record: dict) -> None:
    """Atomically persist the checkpoint document in its declared key order.

    Compact JSON, UTF-8 with non-ASCII characters unescaped, exactly one
    trailing newline; the new file is fsynced in the same directory and then
    promoted with ``os.replace`` so a crash never leaves a torn checkpoint.
    Any filesystem failure is an ``io`` error and leaves the previous
    checkpoint (and its generation) untouched.
    """
    data = (
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp_path = None
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".light-client-", dir=directory)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        tmp_path = None
        # Best-effort directory fsync so the rename itself survives a crash.
        try:
            dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            dir_fd = None
        if dir_fd is not None:
            try:
                os.fsync(dir_fd)
            except OSError:
                pass
            finally:
                os.close(dir_fd)
    except OSError:
        raise _Failure(ERR_IO) from None
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
