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

:func:`advance` durably checkpoints a verified batch to ``path``. The
checkpoint file is one compact UTF-8 JSON document with the exact declared key
order ``generation, anchor, tip, context, state_hash`` and a single trailing
newline (non-ASCII written unescaped); ``generation`` starts at 1 and
increments per successful advance, ``anchor``/``tip`` are the batch's pinned
anchor and closed tip, ``context`` has the exact key order
``verified_at, trust, documents, verified_tx_ids`` (the ``now`` at verification,
the trust document and the re-verifiable batch verbatim) and ``state_hash`` is
the SHA-256 of the canonical (sorted, compact) JSON of the other four fields.
The first advance requires a legal ``anchor``; later advances accept ``None``
(continue from the stored tip) or the stored tip's ``{height, block_hash}``.
Verification itself is :func:`verify_range_exports` unchanged. Same-path
advances share one lock and the new file is atomically replaced into place; a
failed verification never bumps the generation. An existing checkpoint is
strictly reloaded (key order, types, state hash and a context replay at its
``verified_at``); any mismatch is a ``state`` failure and the file is never
truncated or rebuilt. Failures return only ``{"ok": False, "error":
category}`` with category one of
``input/auth/expired/integrity/state/io``; success appends the new
``generation`` as the final result key.

Every successful :func:`advance` also maintains a generation-history sidecar
at ``path + ".history"``: one compact UTF-8 JSON document (same serialization
rules as the checkpoint) with the exact top-level key order
``v, base, records, head``. ``v`` is 1; ``base`` is ``{generation, hash}``
naming the generation *before* the first retained record; each record is
``{checkpoint, prev, hash}`` where ``checkpoint`` is the persisted five-key
checkpoint document, ``prev`` is the previous record's hash (the first
record's is ``base.hash``) and ``hash`` is
``SHA256(ASCII(prev) || canonical_json(checkpoint))``; ``head`` is the last
record's hash. Record generations run consecutively from
``base.generation + 1``. A fresh path starts from ``base = {0, Z}`` (Z = 64
zeros); a pre-existing generation-``g`` checkpoint without a sidecar is
treated as ``base = {g-1, Z}`` with that checkpoint as the first record, and
later advances append. Both files are written under the same per-path lock as
one transaction: an ``io`` failure restores the original bytes best-effort
(a failed compensation surfaces as ``state`` on the next read); crash
atomicity across the two files is not guaranteed.

:func:`history` reads (and prunes) the sidecar. ``history(path)`` returns
``{"ok", "base", "record", "head", "kept"}`` with ``record`` the last
generation's record and ``kept`` null; ``generation=`` selects one retained
generation (an absent one is a ``state`` failure). ``keep=n`` (mutually
exclusive with ``generation``; both must be non-boolean positive integers)
retains only the last ``min(n, count)`` records: when nothing is pruned the
file's bytes are untouched, otherwise ``base`` becomes the last pruned
record's ``{generation, hash}`` and the sidecar is rewritten (the checkpoint
file itself never changes). Loading replays every retained generation —
shape, state hash, context replay and anchor continuity — so any tampering
is a ``state`` failure; a missing or unreadable sidecar is ``io``.

:func:`export_history` exports the retained sidecar pages as signed,
offline-verifiable page documents. ``export_history(path, key, after=None,
limit=50)`` strictly reloads both the checkpoint and its sidecar under the
shared per-path lock and returns one page with the exact key order
``base, records, next, head, checkpoint, auth``: ``base``/``records`` are the
sidecar's own documents (nested key orders unchanged), ``head`` the sidecar
head, ``checkpoint`` the persisted five-key checkpoint (identical to the last
retained record's), ``next`` the page's last record generation when another
page follows or ``null`` on the final page, and ``auth`` is
``{public_key, signature}`` where the Ed25519 signature is made by the 64-hex
seed ``key`` over the SHA-256 of the canonical (sorted, compact,
unescaped-non-ASCII) JSON of the page with ``auth`` removed. ``after`` is
``None`` (start after ``base``) or a non-boolean non-negative integer naming
either ``base.generation`` or a non-last retained generation; ``limit`` is a
non-boolean integer in 1..200. Bad arguments are ``input``, a missing or
unreadable file ``io`` and a corrupt checkpoint/sidecar or unmatched cursor
``state``.

:func:`verify_history` verifies an ordered, non-empty list of such pages
offline against one pinned 64-hex Ed25519 ``public_key``. Every page must have
the exact key order and nested types; ``base``, ``head``, ``checkpoint`` and
the signing public key must be identical on every page; each Ed25519 signature
must verify over the auth-less canonical page digest. Records must run
consecutively from ``base.generation + 1`` and link across page seams through
each page's ``next`` (a non-final page's ``next`` is its last record
generation), every record hash is recomputed and every checkpoint is replayed
(state hash plus the stored batch context) with anchor continuity. The final
page alone carries ``next: null``, its last record's hash must equal ``head``
and its checkpoint must equal the page checkpoint; missing, duplicate or
reordered pages and any tampering are rejected. Success is ``{"ok": True}``;
failure is ``{"ok": False, "error": category}`` with category one of
``input`` (structure/types), ``auth`` (pinned key or signature) and
``integrity`` (chaining, pagination or checkpoint replay); nothing is raised.

:func:`verify_history_trust` verifies the same ordered, non-empty page list
against a signer-rotation trust document instead of one pinned key, so an
export whose pages were signed under rotated (or revoked and reactivated)
keys stays verifiable. The trust document has the exact key order
``root, records, head``: ``root`` is the 64-lowercase-hex Ed25519 public key
the caller pins (it must equal the ``root`` argument); ``records`` is a
non-empty list of rotation certificates with the exact key order
``at, key, status, prev, signature`` — ``at`` a non-boolean positive integer
strictly increasing across the list, ``key`` the 64-hex page signing key,
``status`` exactly ``active`` or ``revoked``, ``prev`` the SHA-256 of the
previous record's canonical JSON (64 zeros for the first) and ``signature``
the root key's Ed25519 signature (128 hex) over the SHA-256 of the record's
canonical JSON with ``signature`` removed; ``head`` is the last record's
hash, computed the same way. An ``active`` record authorizes its key from
``at`` until the key's next record; a ``revoked`` record withdraws it from
``at`` until a later ``active`` record. Every page's ``auth.public_key`` may
differ but must be authorized at the ``verified_at`` of every generation the
page signs, and consecutive generations signed by the same key must not
cross a revocation/reactivation boundary of that key. Signature, hash, cursor,
cross-page linking and checkpoint-replay rules are exactly
:func:`verify_history`'s. Success is ``{"ok": True}``; failure is
``{"ok": False, "error": category}`` with category one of ``input``
(structure/types), ``auth`` (root mismatch, a failing certificate or page
signature, an unknown or revoked key) and ``integrity`` (``at`` order,
``prev``/``head`` chain, a crossed authorization boundary, chaining,
pagination or checkpoint replay); nothing is raised.
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
ERR_STATE = "state"
ERR_IO = "io"

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


# -- durable range checkpoint -------------------------------------------------

# The exact top-level key order of one persisted advance checkpoint.
CHECKPOINT_KEYS = ("generation", "anchor", "tip", "context", "state_hash")

# The exact key order of the checkpoint's re-verifiable context.
CHECKPOINT_CONTEXT_KEYS = (
    "verified_at",
    "trust",
    "documents",
    "verified_tx_ids",
)

# The exact top-level key order of the generation-history sidecar persisted
# at ``path + ".history"`` alongside every advance checkpoint.
HISTORY_KEYS = ("v", "base", "records", "head")

# The exact key order of the sidecar's base cursor and of one record.
HISTORY_BASE_KEYS = ("generation", "hash")
HISTORY_RECORD_KEYS = ("checkpoint", "prev", "hash")

# The sidecar format version.
HISTORY_VERSION = 1

# The sentinel hash of a base that names no real record (64 zeros).
HISTORY_ZERO_HASH = "0" * 64

# One lock per checkpoint path serializes same-path advances (and their
# atomic replace) across threads within one process.
_checkpoint_locks: dict[str, threading.RLock] = {}
_checkpoint_locks_guard = threading.Lock()


def _checkpoint_lock(path: str) -> threading.RLock:
    key = os.path.abspath(path)
    with _checkpoint_locks_guard:
        lock = _checkpoint_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _checkpoint_locks[key] = lock
        return lock


def _canonical_json_bytes(value: object) -> bytes:
    """Sorted-key, compact, unescaped-non-ASCII UTF-8 canonical JSON bytes."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _checkpoint_state_hash(generation: int, anchor: dict, tip: dict, context: dict) -> str:
    """SHA-256 over the canonical JSON bytes of every field but state_hash."""
    body = {
        "generation": generation,
        "anchor": anchor,
        "tip": tip,
        "context": context,
    }
    return hashlib.sha256(_canonical_json_bytes(body)).hexdigest()


def _failed_advance(category: str) -> dict:
    return {"ok": False, "error": category}


def advance(
    path: str,
    docs: object,
    trust: object,
    anchor: object,
    now: object,
) -> dict:
    """Verify a range-export batch and durably checkpoint it at ``path``.

    ``docs`` is an ordered, non-empty batch of range deliveries verified with
    :func:`verify_range_exports` against ``trust`` and ``anchor`` at time
    ``now``: ``now`` must be a plain (non-boolean) non-negative integer; the
    first use of ``path`` requires a legal ``anchor`` (``{height, block_hash}``),
    while a later advance passes ``None`` (continue from the stored tip) or the
    stored tip's ``{height, block_hash}``.

    On success the checkpoint is written atomically (a uniquely named temp file
    in the same directory, fsynced and ``os.replace``d under a per-path lock)
    with key order ``generation, anchor, tip, context, state_hash``; generation
    starts at 1 and increments once per successful advance, so a failed
    verification never bumps it. The return value is the verifier result with
    the new ``generation`` appended as the final key.

    The same transaction appends the new checkpoint to the generation-history
    sidecar at ``path + ".history"`` (see the module docstring for the exact
    format): a missing sidecar is opened at ``base = {0, Z}`` for a first
    advance, or migrated from a pre-existing generation-``g`` checkpoint as
    ``base = {g-1, Z}`` with that checkpoint as the first record; an existing
    sidecar is strictly reloaded and replayed, and its last record must
    reproduce the stored checkpoint. Both files are written under the shared
    per-path lock; an ``io`` failure restores the original bytes of both
    best-effort (crash atomicity across the pair is not guaranteed).

    Every failure is ``{"ok": False, "error": category}`` with category one of
    ``input`` (bad arguments or checkpoint shape), ``auth``/``expired``/
    ``integrity`` (batch verification), ``state`` (an existing checkpoint or
    sidecar fails its key-order/type/hash/replay checks; it is never truncated
    or rebuilt) and ``io`` (the checkpoint cannot be read or written).
    """
    # Argument shape is validated before any file or verification work.
    if not isinstance(path, str) or not path:
        return _failed_advance(ERR_INPUT)
    if not _is_int(now) or now < 0:
        return _failed_advance(ERR_INPUT)

    lock = _checkpoint_lock(path)
    with lock:
        try:
            previous = _load_checkpoint(path)
            sidecar = _load_history(_history_path(path))
        except _CheckpointError as failure:
            return _failed_advance(failure.category)

        if previous is None:
            # A sidecar without its checkpoint is unrecoverable corruption.
            if sidecar is not None:
                return _failed_advance(ERR_STATE)
            # First use: the caller must pin a legal anchor.
            expected_anchor = _validate_advance_anchor(anchor)
            if expected_anchor is None:
                return _failed_advance(ERR_INPUT)
            generation = 0
            base = {"generation": 0, "hash": HISTORY_ZERO_HASH}
            records: list[dict] = []
        else:
            generation = previous["generation"]
            stored_tip = previous["tip"]
            if anchor is None:
                # Continue the continuous chain from the stored closed tip.
                expected_anchor = {
                    "height": stored_tip["height"],
                    "block_hash": stored_tip["tip_hash"],
                }
            else:
                expected_anchor = _validate_advance_anchor(anchor)
                if (
                    expected_anchor is None
                    or expected_anchor
                    != {
                        "height": stored_tip["height"],
                        "block_hash": stored_tip["tip_hash"],
                    }
                ):
                    return _failed_advance(ERR_INPUT)
            if sidecar is None:
                # Migrate a pre-existing checkpoint: it becomes the first
                # record over a zero base one generation below it.
                base = {
                    "generation": generation - 1,
                    "hash": HISTORY_ZERO_HASH,
                }
                records = [_history_record(previous, HISTORY_ZERO_HASH)]
            else:
                # The sidecar's tip record must pin the stored checkpoint.
                if sidecar["records"][-1]["checkpoint"] != previous:
                    return _failed_advance(ERR_STATE)
                base = sidecar["base"]
                records = list(sidecar["records"])

        result = verify_range_exports(docs, expected_anchor, trust, now)
        if not result.get("ok"):
            return {"ok": False, "error": result["error"]}

        context = {
            "verified_at": now,
            "trust": trust,
            "documents": docs,
            "verified_tx_ids": result["verified_tx_ids"],
        }
        next_generation = generation + 1
        checkpoint = {
            "generation": next_generation,
            "anchor": result["anchor"],
            "tip": result["tip"],
            "context": context,
        }
        checkpoint["state_hash"] = _checkpoint_state_hash(
            next_generation,
            checkpoint["anchor"],
            checkpoint["tip"],
            checkpoint["context"],
        )
        head = records[-1]["hash"] if records else base["hash"]
        record = _history_record(checkpoint, head)
        history_document = {
            "v": HISTORY_VERSION,
            "base": base,
            "records": records + [record],
            "head": record["hash"],
        }

        history_path = _history_path(path)
        try:
            original_checkpoint = _read_bytes_or_none(path)
            original_history = _read_bytes_or_none(history_path)
        except OSError:
            return _failed_advance(ERR_IO)
        try:
            _atomic_write_checkpoint(path, checkpoint)
            _atomic_write_history(history_path, history_document)
        except OSError:
            # Compensate: put both files' original bytes back best-effort.
            _restore_bytes(path, original_checkpoint)
            _restore_bytes(history_path, original_history)
            return _failed_advance(ERR_IO)

        advanced = dict(result)
        advanced["generation"] = next_generation
        return advanced


def _validate_advance_anchor(raw: object) -> dict | None:
    """Validate an advance anchor as ``{height: non-negative int, block_hash}``.

    Mirrors the range verifier's raw-value rules (booleans rejected); returns a
    fresh closed document or None on any shape/type defect.
    """
    if not isinstance(raw, dict) or set(raw) != {"height", "block_hash"}:
        return None
    height = raw["height"]
    if not _is_int(height) or height < 0:
        return None
    if not crypto.is_hex64(raw["block_hash"]):
        return None
    return {"height": height, "block_hash": raw["block_hash"]}


class _CheckpointError(Exception):
    """Internal control-flow exception carrying the public error category."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _load_checkpoint(path: str) -> dict | None:
    """Strictly load and re-verify an existing advance checkpoint.

    Returns None when no file exists at ``path``. Otherwise validates the exact
    key order and JSON types, recomputes ``state_hash`` over the other fields,
    and replays the stored batch through :func:`verify_range_exports` at the
    context's ``verified_at`` — the batch must chain from the stored anchor to
    the stored tip and reproduce the stored verified tx ids. Any defect is a
    ``state`` failure (unreadable JSON is ``io``); the file is never truncated
    or rebuilt.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _CheckpointError(ERR_IO) from exc

    try:
        data = json.loads(text)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _CheckpointError(ERR_STATE) from exc
    checkpoint = _validate_checkpoint_shape(data)
    _verify_checkpoint_document(checkpoint)
    return checkpoint


def _verify_checkpoint_document(checkpoint: dict) -> None:
    """Re-verify one shape-validated checkpoint document.

    The recorded state hash pins the document before any replay: a tampered
    generation, anchor, tip or context is state corruption, not re-verified.
    The stored batch is then replayed through :func:`verify_range_exports` at
    the context's ``verified_at`` — it must chain from the stored anchor to
    the stored tip and reproduce the stored verified tx ids.
    """
    recomputed = _checkpoint_state_hash(
        checkpoint["generation"],
        checkpoint["anchor"],
        checkpoint["tip"],
        checkpoint["context"],
    )
    if recomputed != checkpoint["state_hash"]:
        raise _CheckpointError(ERR_STATE)

    context = checkpoint["context"]
    replay = verify_range_exports(
        context["documents"],
        checkpoint["anchor"],
        context["trust"],
        context["verified_at"],
    )
    if not replay.get("ok"):
        raise _CheckpointError(ERR_STATE)
    if replay["anchor"] != checkpoint["anchor"]:
        raise _CheckpointError(ERR_STATE)
    if replay["tip"] != checkpoint["tip"]:
        raise _CheckpointError(ERR_STATE)
    if replay["verified_tx_ids"] != context["verified_tx_ids"]:
        raise _CheckpointError(ERR_STATE)


def _validate_checkpoint_shape(data: object) -> dict:
    """Validate the exact key order and JSON types of one checkpoint document."""
    if not isinstance(data, dict) or tuple(data.keys()) != CHECKPOINT_KEYS:
        raise _CheckpointError(ERR_STATE)
    generation = data["generation"]
    anchor = data["anchor"]
    tip = data["tip"]
    context = data["context"]
    state_hash = data["state_hash"]

    if not _is_int(generation) or generation < 1:
        raise _CheckpointError(ERR_STATE)
    if not isinstance(anchor, dict):
        raise _CheckpointError(ERR_STATE)
    if not isinstance(tip, dict):
        raise _CheckpointError(ERR_STATE)
    if not isinstance(context, dict) or tuple(context.keys()) != CHECKPOINT_CONTEXT_KEYS:
        raise _CheckpointError(ERR_STATE)
    if not crypto.is_hex64(state_hash):
        raise _CheckpointError(ERR_STATE)

    verified_at = context["verified_at"]
    trust = context["trust"]
    documents = context["documents"]
    verified_tx_ids = context["verified_tx_ids"]
    if not _is_int(verified_at) or verified_at < 0:
        raise _CheckpointError(ERR_STATE)
    if not isinstance(trust, dict):
        raise _CheckpointError(ERR_STATE)
    if not isinstance(documents, list) or not documents:
        raise _CheckpointError(ERR_STATE)
    if not isinstance(verified_tx_ids, list) or any(
        not isinstance(tx_id, str) for tx_id in verified_tx_ids
    ):
        raise _CheckpointError(ERR_STATE)

    # The anchor and tip are additionally shape-checked so a corrupt document
    # can never reach the replay (which treats them as trusted call arguments).
    if _validate_advance_anchor(anchor) is None:
        raise _CheckpointError(ERR_STATE)
    if set(tip) != set(DESCRIPTOR_FIELDS):
        raise _CheckpointError(ERR_STATE)
    if not _is_int(tip.get("height")) or tip["height"] < 0:
        raise _CheckpointError(ERR_STATE)
    if not _is_int(tip.get("length")) or tip["length"] < 1:
        raise _CheckpointError(ERR_STATE)
    if not crypto.is_hex64(tip.get("tip_hash")):
        raise _CheckpointError(ERR_STATE)
    if tip.get("status") not in (STATUS_CONFIRMED, STATUS_PENDING):
        raise _CheckpointError(ERR_STATE)

    return {
        "generation": generation,
        "anchor": anchor,
        "tip": tip,
        "context": context,
        "state_hash": state_hash,
    }


def _serialize_document(ordered: dict) -> bytes:
    """Compact UTF-8 JSON (non-ASCII unescaped) with one trailing newline."""
    return (
        json.dumps(ordered, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _atomic_write_checkpoint(path: str, checkpoint: dict) -> None:
    """Write the checkpoint in declared key order and atomically replace ``path``."""
    ordered = {key: checkpoint[key] for key in CHECKPOINT_KEYS}
    _atomic_write_bytes(path, _serialize_document(ordered))


def _atomic_write_bytes(path: str, payload: bytes) -> None:
    """Atomically replace ``path`` with ``payload``.

    The temp file is fsynced before the replace and the directory afterwards,
    mirroring the main store's durability rules.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".light-checkpoint-", dir=directory)
    promoted = False
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
        promoted = True
        _fsync_dir(directory)
    finally:
        if not promoted and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _read_bytes_or_none(path: str) -> bytes | None:
    """Raw bytes of ``path`` (None when absent); other read errors propagate."""
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def _restore_bytes(path: str, original: bytes | None) -> None:
    """Best-effort compensation: put ``original`` back at ``path``.

    A file that did not exist is unlinked again. Any failure is swallowed —
    the caller already reports ``io`` and the next strict load surfaces the
    corruption as ``state``.
    """
    try:
        if original is None:
            os.unlink(path)
        else:
            _atomic_write_bytes(path, original)
    except OSError:
        pass


def _fsync_dir(directory: str) -> None:
    """Best-effort directory fsync so the checkpoint rename survives a crash."""
    try:
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


# -- generation-history sidecar ------------------------------------------------


def _history_path(path: str) -> str:
    """The sidecar path mirroring one advance checkpoint path."""
    return path + ".history"


def _history_record(checkpoint: dict, prev: str) -> dict:
    """One sidecar record: ``{checkpoint, prev, hash}`` in declared key order.

    ``hash`` chains the record: SHA-256 over the ASCII bytes of ``prev``
    concatenated with the canonical (sorted, compact) JSON of the checkpoint.
    """
    ordered = {key: checkpoint[key] for key in CHECKPOINT_KEYS}
    digest = hashlib.sha256(
        prev.encode("ascii") + _canonical_json_bytes(ordered)
    ).hexdigest()
    return {"checkpoint": ordered, "prev": prev, "hash": digest}


def _atomic_write_history(path: str, document: dict) -> None:
    """Write the sidecar in declared key order and atomically replace ``path``."""
    ordered = {key: document[key] for key in HISTORY_KEYS}
    _atomic_write_bytes(path, _serialize_document(ordered))


def _load_history(path: str) -> dict | None:
    """Strictly load and replay the generation-history sidecar.

    Returns None when no file exists at ``path``. Otherwise validates the
    exact key orders and JSON types, then replays every retained generation:
    record generations must run consecutively from ``base.generation + 1``,
    each ``prev`` must name the previous record's hash (the first names
    ``base.hash``), each record hash and the head are recomputed, and every
    checkpoint passes the same state-hash/context-replay checks as
    :func:`_load_checkpoint` plus anchor continuity with its predecessor. Any
    defect is a ``state`` failure (unreadable JSON is ``state`` too, an
    unreadable file ``io``); the file is never truncated or rebuilt.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _CheckpointError(ERR_IO) from exc

    try:
        data = json.loads(text)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _CheckpointError(ERR_STATE) from exc
    return _validate_history_document(data)


def _validate_history_document(data: object) -> dict:
    """Validate and replay one parsed sidecar document."""
    if not isinstance(data, dict) or tuple(data.keys()) != HISTORY_KEYS:
        raise _CheckpointError(ERR_STATE)
    if not _is_int(data["v"]) or data["v"] != HISTORY_VERSION:
        raise _CheckpointError(ERR_STATE)

    base = data["base"]
    if not isinstance(base, dict) or tuple(base.keys()) != HISTORY_BASE_KEYS:
        raise _CheckpointError(ERR_STATE)
    if not _is_int(base["generation"]) or base["generation"] < 0:
        raise _CheckpointError(ERR_STATE)
    if not crypto.is_hex64(base["hash"]):
        raise _CheckpointError(ERR_STATE)

    records = data["records"]
    if not isinstance(records, list) or not records:
        raise _CheckpointError(ERR_STATE)
    head = data["head"]
    if not crypto.is_hex64(head):
        raise _CheckpointError(ERR_STATE)

    validated = []
    prev = base["hash"]
    previous_tip: dict | None = None
    for index, raw in enumerate(records):
        record = _validate_history_record(raw)
        checkpoint = record["checkpoint"]
        if checkpoint["generation"] != base["generation"] + 1 + index:
            raise _CheckpointError(ERR_STATE)
        if record["prev"] != prev:
            raise _CheckpointError(ERR_STATE)
        if record != _history_record(checkpoint, prev):
            raise _CheckpointError(ERR_STATE)
        _verify_checkpoint_document(checkpoint)
        if previous_tip is not None:
            # Consecutive checkpoints chain: each anchor is the previous tip.
            expected_anchor = {
                "height": previous_tip["height"],
                "block_hash": previous_tip["tip_hash"],
            }
            if checkpoint["anchor"] != expected_anchor:
                raise _CheckpointError(ERR_STATE)
        previous_tip = checkpoint["tip"]
        prev = record["hash"]
        validated.append(record)

    if head != validated[-1]["hash"]:
        raise _CheckpointError(ERR_STATE)
    return {
        "v": HISTORY_VERSION,
        "base": {
            "generation": base["generation"],
            "hash": base["hash"],
        },
        "records": validated,
        "head": head,
    }


def _validate_history_record(raw: object) -> dict:
    """Validate the exact key order and JSON types of one sidecar record."""
    if not isinstance(raw, dict) or tuple(raw.keys()) != HISTORY_RECORD_KEYS:
        raise _CheckpointError(ERR_STATE)
    checkpoint = _validate_checkpoint_shape(raw["checkpoint"])
    if not crypto.is_hex64(raw["prev"]):
        raise _CheckpointError(ERR_STATE)
    if not crypto.is_hex64(raw["hash"]):
        raise _CheckpointError(ERR_STATE)
    return {"checkpoint": checkpoint, "prev": raw["prev"], "hash": raw["hash"]}


def history(path: str, generation: object = None, keep: object = None) -> dict:
    """Query or prune the generation-history sidecar of one advance checkpoint.

    ``generation`` and ``keep`` are mutually exclusive and, when given, must
    be non-boolean positive integers. Without either, the last generation's
    record is reported. With ``keep=n`` only the last ``min(n, count)``
    records are retained: when nothing is pruned the sidecar's bytes are left
    untouched, otherwise ``base`` advances to the last pruned record's
    ``{generation, hash}`` and the sidecar is rewritten under the same
    per-path lock as :func:`advance` (the checkpoint file never changes; an
    ``io`` failure restores the original bytes best-effort).

    Success returns ``{"ok", "base", "record", "head", "kept"}`` in that key
    order — ``record`` the queried (default last) or, with ``keep``, the last
    retained record, ``kept`` null for queries and the retained count for
    prunes. Failure returns ``{"ok": False, "error": category}`` with
    category one of ``input`` (bad arguments), ``io`` (the sidecar is missing
    or cannot be read/written) and ``state`` (the sidecar fails validation or
    the requested generation is not retained).
    """
    if not isinstance(path, str) or not path:
        return {"ok": False, "error": ERR_INPUT}
    if generation is not None and keep is not None:
        return {"ok": False, "error": ERR_INPUT}
    for parameter in (generation, keep):
        if parameter is not None and (not _is_int(parameter) or parameter < 1):
            return {"ok": False, "error": ERR_INPUT}

    lock = _checkpoint_lock(path)
    with lock:
        sidecar_path = _history_path(path)
        try:
            sidecar = _load_history(sidecar_path)
        except _CheckpointError as failure:
            return {"ok": False, "error": failure.category}
        if sidecar is None:
            return {"ok": False, "error": ERR_IO}

        records = sidecar["records"]
        if keep is None:
            if generation is None:
                record = records[-1]
            else:
                record = next(
                    (
                        candidate
                        for candidate in records
                        if candidate["checkpoint"]["generation"] == generation
                    ),
                    None,
                )
                if record is None:
                    return {"ok": False, "error": ERR_STATE}
            return {
                "ok": True,
                "base": sidecar["base"],
                "record": record,
                "head": sidecar["head"],
                "kept": None,
            }

        kept = min(keep, len(records))
        record = records[-1]
        if kept == len(records):
            # Nothing pruned: the sidecar's bytes stay exactly as they were.
            return {
                "ok": True,
                "base": sidecar["base"],
                "record": record,
                "head": sidecar["head"],
                "kept": kept,
            }

        last_pruned = records[len(records) - kept - 1]
        base = {
            "generation": last_pruned["checkpoint"]["generation"],
            "hash": last_pruned["hash"],
        }
        rewritten = {
            "v": HISTORY_VERSION,
            "base": base,
            "records": records[len(records) - kept :],
            "head": sidecar["head"],
        }
        try:
            original = _read_bytes_or_none(sidecar_path)
        except OSError:
            return {"ok": False, "error": ERR_IO}
        try:
            _atomic_write_history(sidecar_path, rewritten)
        except OSError:
            # Compensate: put the original bytes back best-effort.
            _restore_bytes(sidecar_path, original)
            return {"ok": False, "error": ERR_IO}
        return {
            "ok": True,
            "base": base,
            "record": record,
            "head": sidecar["head"],
            "kept": kept,
        }


# -- signed history export / offline verification -----------------------------

# The exact top-level key order of one exported history page, and of its auth.
HISTORY_PAGE_KEYS = (
    "base",
    "records",
    "next",
    "head",
    "checkpoint",
    "auth",
)
HISTORY_PAGE_AUTH_KEYS = ("public_key", "signature")

# Page-size bounds for :func:`export_history`.
HISTORY_EXPORT_MIN_LIMIT = 1
HISTORY_EXPORT_MAX_LIMIT = 200
HISTORY_EXPORT_DEFAULT_LIMIT = 50


def export_history(
    path: object,
    key: object,
    after: object = None,
    limit: object = HISTORY_EXPORT_DEFAULT_LIMIT,
) -> dict:
    """Export one signed page of retained checkpoint history for offline use.

    Strictly reloads the checkpoint at ``path`` and its ``path + ".history"``
    sidecar and returns one page with the exact key order
    ``base, records, next, head, checkpoint, auth``:

    * ``base``/``records``/``head`` are the sidecar's own documents (nested
      key orders unchanged), ``checkpoint`` is the persisted five-key
      checkpoint document (identical to the last retained record's);
    * ``next`` is the last record generation of the page when another page
      follows, or ``null`` on the final page;
    * ``auth`` is ``{"public_key", "signature"}``: the Ed25519 public key
      derived from the 64-lowercase-hex seed ``key`` and its signature over the
      SHA-256 digest of the canonical (sorted, compact, non-ASCII-unescaped)
      JSON of the page with ``auth`` removed.

    ``after`` is ``None`` (page starts right after ``base``) or a non-boolean
    non-negative integer naming either ``base.generation`` or a retained
    generation that is not the last one; the page then starts at the following
    record. ``limit`` is a non-boolean integer in 1..200. Bad arguments are
    ``input``; a missing or unreadable file is ``io``; a corrupt checkpoint or
    sidecar, a sidecar/checkpoint mismatch or an unmatched/terminal cursor is
    ``state``.
    """
    if not isinstance(path, str) or not path:
        return {"ok": False, "error": ERR_INPUT}
    if not isinstance(key, str) or not _HEX32_RE.fullmatch(key):
        return {"ok": False, "error": ERR_INPUT}
    if after is not None and (not _is_int(after) or after < 0):
        return {"ok": False, "error": ERR_INPUT}
    if (
        not _is_int(limit)
        or limit < HISTORY_EXPORT_MIN_LIMIT
        or limit > HISTORY_EXPORT_MAX_LIMIT
    ):
        return {"ok": False, "error": ERR_INPUT}
    public_key = crypto.derive_public_key(key)
    if public_key is None:
        return {"ok": False, "error": ERR_INPUT}

    lock = _checkpoint_lock(path)
    with lock:
        try:
            checkpoint = _load_checkpoint(path)
            sidecar = _load_history(_history_path(path))
        except _CheckpointError as failure:
            return {"ok": False, "error": failure.category}
        if sidecar is None:
            # Nothing retained to export: the sidecar missing is an io defect.
            return {"ok": False, "error": ERR_IO}
        if checkpoint is None:
            # A sidecar without its checkpoint is unrecoverable corruption.
            return {"ok": False, "error": ERR_STATE}

        base = sidecar["base"]
        records = sidecar["records"]
        if records[-1]["checkpoint"] != checkpoint:
            # The sidecar tip must pin the persisted checkpoint.
            return {"ok": False, "error": ERR_STATE}

        if after is None or after == base["generation"]:
            start = 0
        else:
            start = next(
                (
                    index + 1
                    for index, record in enumerate(records)
                    if record["checkpoint"]["generation"] == after
                ),
                None,
            )
            # An unknown cursor, or one naming the last retained generation
            # (nothing follows it), is a state defect rather than an input one:
            # the argument has a legal shape but does not name a usable cursor.
            if start is None or start >= len(records):
                return {"ok": False, "error": ERR_STATE}

        page_records = records[start : start + limit]
        has_next = start + limit < len(records)
        next_value = (
            page_records[-1]["checkpoint"]["generation"] if has_next else None
        )
        page = {
            "base": base,
            "records": page_records,
            "next": next_value,
            "head": sidecar["head"],
            "checkpoint": checkpoint,
        }
        digest = hashlib.sha256(_canonical_json_bytes(page)).digest()
        signature = crypto.sign_message(key, digest)
        if signature is None:
            return {"ok": False, "error": ERR_INPUT}
        page["auth"] = {"public_key": public_key, "signature": signature}
        return {name: page[name] for name in HISTORY_PAGE_KEYS}


def verify_history(pages: object, public_key: object) -> dict:
    """Verify an ordered, non-empty batch of signed history pages offline.

    Every page must have the exact key order
    ``base, records, next, head, checkpoint, auth`` (nested documents keep
    their declared orders and types) and carry
    ``auth = {"public_key", "signature"}``. The pinned ``public_key`` (64
    lowercase hex) must match every page's signing key and verify every
    Ed25519 signature over the auth-less canonical page digest; ``base``,
    ``head`` and the page ``checkpoint`` must be identical across all pages.

    Records must run consecutively from ``base.generation + 1`` with each
    ``prev``/``hash`` link recomputed, chaining across page seams in step with
    each non-final page's ``next`` cursor; every checkpoint is replayed (state
    hash plus its stored batch context) with anchor continuity between
    consecutive checkpoints. Only the final page may carry ``next: null``; its
    last record's hash must equal ``head`` and its checkpoint must equal the
    page checkpoint. Missing, duplicate or reordered pages and any tampering
    are rejected.

    Returns ``{"ok": True}`` on success or ``{"ok": False, "error":
    category}`` on failure with category one of ``input`` (structure/types),
    ``auth`` (pinned key or a failing signature) and ``integrity`` (chaining,
    pagination or checkpoint replay). Never raises for malformed input.
    """
    try:
        _verify_history_pages(pages, public_key)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {"ok": True}


def _validate_page_base(raw: object) -> dict:
    """Validate one exported page's ``{generation, hash}`` base document."""
    if not isinstance(raw, dict) or tuple(raw.keys()) != HISTORY_BASE_KEYS:
        raise _Failure(ERR_INPUT)
    if not _is_int(raw["generation"]) or raw["generation"] < 0:
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(raw["hash"]):
        raise _Failure(ERR_INPUT)
    return {"generation": raw["generation"], "hash": raw["hash"]}


def _validate_page_checkpoint(raw: object) -> dict:
    """Shape-validate a checkpoint embedded in an exported history page.

    Shape/type defects are the page's structural defects (``input``); the
    state hash and context replay are judged separately as ``integrity``.
    """
    try:
        return _validate_checkpoint_shape(raw)
    except _CheckpointError:
        raise _Failure(ERR_INPUT) from None


def _validate_page_record(raw: object) -> dict:
    """Validate one ``{checkpoint, prev, hash}`` record embedded in a page."""
    if not isinstance(raw, dict) or tuple(raw.keys()) != HISTORY_RECORD_KEYS:
        raise _Failure(ERR_INPUT)
    checkpoint = _validate_page_checkpoint(raw["checkpoint"])
    if not crypto.is_hex64(raw["prev"]) or not crypto.is_hex64(raw["hash"]):
        raise _Failure(ERR_INPUT)
    return {"checkpoint": checkpoint, "prev": raw["prev"], "hash": raw["hash"]}


def _verify_history_pages(
    pages: object,
    pinned_key: object,
    page_authorizer: object = None,
) -> None:
    """All structural, authentication and chaining checks for :func:`verify_history`.

    With ``page_authorizer`` None the pinned-key rule of
    :func:`verify_history` applies: every page must carry ``pinned_key`` in
    its ``auth``. Otherwise each page is verified under its own
    ``auth.public_key`` and ``page_authorizer(page_key, validated_records)``
    is invoked after the signature check to judge the key's authorization
    (the :func:`verify_history_trust` rotation rules).
    """
    if not isinstance(pages, list) or not pages:
        raise _Failure(ERR_INPUT)
    if page_authorizer is None and (
        not isinstance(pinned_key, str) or not _HEX32_RE.fullmatch(pinned_key)
    ):
        raise _Failure(ERR_INPUT)

    common_base: dict | None = None
    common_head: str | None = None
    common_checkpoint: dict | None = None
    # Linkage state carried across page seams.
    expected_prev: str | None = None
    expected_generation: int | None = None
    previous_tip: dict | None = None

    for position, raw_page in enumerate(pages):
        is_last_page = position == len(pages) - 1
        if not isinstance(raw_page, dict) or tuple(raw_page.keys()) != HISTORY_PAGE_KEYS:
            raise _Failure(ERR_INPUT)
        auth = raw_page["auth"]
        if not isinstance(auth, dict) or tuple(auth.keys()) != HISTORY_PAGE_AUTH_KEYS:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(auth["public_key"]):
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex128(auth["signature"]):
            raise _Failure(ERR_INPUT)
        base = _validate_page_base(raw_page["base"])
        head = raw_page["head"]
        if not crypto.is_hex64(head):
            raise _Failure(ERR_INPUT)
        page_checkpoint = _validate_page_checkpoint(raw_page["checkpoint"])
        records = raw_page["records"]
        if not isinstance(records, list) or not records:
            raise _Failure(ERR_INPUT)
        next_value = raw_page["next"]
        if next_value is not None and (not _is_int(next_value) or next_value < 0):
            raise _Failure(ERR_INPUT)
        # Every embedded record is shape- and type-validated up front, so a
        # structurally malformed page reports ``input`` even if its (now
        # mismatched) signature would fail too — structure precedes trust.
        validated_records = [_validate_page_record(raw) for raw in records]

        # The pinned trust anchor and the signed envelope must be shared by
        # every page of the export. With a page authorizer the pinned-key
        # equality rule is replaced by per-key authorization below.
        if page_authorizer is None and auth["public_key"] != pinned_key:
            raise _Failure(ERR_AUTH)
        if common_base is None:
            common_base = base
            common_head = head
            common_checkpoint = page_checkpoint
        elif base != common_base:
            raise _Failure(ERR_INTEGRITY)
        elif head != common_head or page_checkpoint != common_checkpoint:
            raise _Failure(ERR_INTEGRITY)

        # The signature covers the page verbatim minus auth, canonicalized the
        # same way the exporter canonicalizes it.
        unsigned = {
            key: raw_page[key] for key in HISTORY_PAGE_KEYS if key != "auth"
        }
        digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
        page_key = auth["public_key"]
        if not crypto.verify_signature(page_key, digest, auth["signature"]):
            raise _Failure(ERR_AUTH)
        if page_authorizer is not None:
            # The rotation rules: the page key must be authorized for every
            # generation it signs, without crossing an authorization boundary.
            page_authorizer(page_key, validated_records)

        if expected_prev is None:
            # The first page starts right at the shared base.
            expected_prev = base["hash"]
            expected_generation = base["generation"] + 1

        for record in validated_records:
            checkpoint = record["checkpoint"]
            if checkpoint["generation"] != expected_generation:
                # A gap, duplicate or reordered page breaks generation order.
                raise _Failure(ERR_INTEGRITY)
            if record["prev"] != expected_prev:
                raise _Failure(ERR_INTEGRITY)
            rebuilt = _history_record(checkpoint, expected_prev)
            if record["hash"] != rebuilt["hash"]:
                raise _Failure(ERR_INTEGRITY)
            # The state hash pins the document; the stored batch must replay
            # from its anchor to its tip and reproduce the verified tx ids.
            try:
                _verify_checkpoint_document(checkpoint)
            except _CheckpointError:
                raise _Failure(ERR_INTEGRITY) from None
            if previous_tip is not None:
                expected_anchor = {
                    "height": previous_tip["height"],
                    "block_hash": previous_tip["tip_hash"],
                }
                if checkpoint["anchor"] != expected_anchor:
                    raise _Failure(ERR_INTEGRITY)
            previous_tip = checkpoint["tip"]
            expected_prev = record["hash"]
            expected_generation += 1

        last_generation = records[-1]["checkpoint"]["generation"]
        if is_last_page:
            if next_value is not None:
                raise _Failure(ERR_INTEGRITY)
        else:
            # A non-final page must name its last record as the cursor the next
            # page continues from.
            if next_value != last_generation:
                raise _Failure(ERR_INTEGRITY)

    # The final page closes the export: its last record is the sidecar head and
    # its checkpoint is the page checkpoint shared by every page.
    final_record = _validate_page_record(pages[-1]["records"][-1])
    if final_record["hash"] != common_head:
        raise _Failure(ERR_INTEGRITY)
    if final_record["checkpoint"] != common_checkpoint:
        raise _Failure(ERR_INTEGRITY)


# -- signer-rotation trust verification ----------------------------------------

# The exact top-level key order of the signer-rotation trust document, and of
# one rotation certificate record.
TRUST_KEYS = ("root", "records", "head")
TRUST_RECORD_KEYS = ("at", "key", "status", "prev", "signature")

# The only legal certificate statuses.
TRUST_STATUSES = ("active", "revoked")


def verify_history_trust(pages: object, trust: object, root: object) -> dict:
    """Verify signed history pages against a signer-rotation trust document.

    ``pages`` is an ordered, non-empty list of exported history pages exactly
    as :func:`verify_history` accepts, except each page's ``auth.public_key``
    may differ. ``trust`` is the rotation trust document (exact key order
    ``root, records, head``; see the module docstring) and ``root`` the
    caller-pinned 64-lowercase-hex Ed25519 public key the document's ``root``
    must equal and every certificate signature must verify under.

    Returns ``{"ok": True}`` on success or ``{"ok": False, "error":
    category}`` on failure with category one of ``input`` (structure/types),
    ``auth`` (root mismatch, a failing certificate or page signature, an
    unknown or revoked key) and ``integrity`` (``at`` order, ``prev``/``head``
    chain, a crossed authorization boundary, chaining, pagination or
    checkpoint replay). Never raises for malformed input.
    """
    try:
        records = _validate_trust_document(trust, root)
        _verify_trust_records(records, trust["head"], trust["root"], root)
        intervals = _trust_key_intervals(records)
        # The (page key, authorizing certificate's ``at``) of the previous
        # generation, carried across pages so two consecutive generations
        # signed by one key cannot silently span a revocation/reactivation
        # boundary of that key.
        previous: dict = {}

        def _authorize(page_key: str, validated_records: list) -> None:
            _authorize_history_page(page_key, validated_records, intervals,
                                    previous)

        _verify_history_pages(pages, None, page_authorizer=_authorize)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {"ok": True}


def _validate_trust_document(trust: object, root: object) -> list:
    """Structural validation of the rotation trust document and pinned root.

    Every defect here — a missing/extra/reordered key, a wrong type, a bad hex
    field — is an ``input`` failure; the chain and signature checks run later.
    Returns the record list (its items are not copied: verification never
    mutates them).
    """
    if not isinstance(root, str) or not _HEX32_RE.fullmatch(root):
        raise _Failure(ERR_INPUT)
    if not isinstance(trust, dict) or tuple(trust.keys()) != TRUST_KEYS:
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(trust["root"]):
        raise _Failure(ERR_INPUT)
    records = trust["records"]
    if not isinstance(records, list) or not records:
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(trust["head"]):
        raise _Failure(ERR_INPUT)
    for raw in records:
        if not isinstance(raw, dict) or tuple(raw.keys()) != TRUST_RECORD_KEYS:
            raise _Failure(ERR_INPUT)
        # ``at`` is a plain (non-boolean) positive integer; the strict
        # ascending order across the list is a chain (integrity) check.
        if not _is_int(raw["at"]) or raw["at"] < 1:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(raw["key"]):
            raise _Failure(ERR_INPUT)
        if raw["status"] not in TRUST_STATUSES:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(raw["prev"]):
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex128(raw["signature"]):
            raise _Failure(ERR_INPUT)
    return list(records)


def _verify_trust_records(
    records: list, head: str, trust_root: str, root: str
) -> None:
    """Authenticate the trust document and verify its hash chain.

    The document's ``root`` must equal the caller-pinned root and every
    certificate must carry the root key's Ed25519 signature over the SHA-256
    of the record's canonical JSON without ``signature`` (both ``auth``). The
    chain itself — strictly increasing ``at``, the first ``prev`` being 64
    zeros, every later ``prev`` the SHA-256 of the previous record's canonical
    JSON and ``head`` the last record's hash — is ``integrity``.
    """
    if trust_root != root:
        raise _Failure(ERR_AUTH)
    for record in records:
        unsigned = {
            key: record[key] for key in TRUST_RECORD_KEYS if key != "signature"
        }
        digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
        if not crypto.verify_signature(root, digest, record["signature"]):
            raise _Failure(ERR_AUTH)
    prev = HISTORY_ZERO_HASH
    last_at = 0
    for record in records:
        if record["at"] <= last_at:
            raise _Failure(ERR_INTEGRITY)
        last_at = record["at"]
        if record["prev"] != prev:
            raise _Failure(ERR_INTEGRITY)
        prev = hashlib.sha256(_canonical_json_bytes(record)).hexdigest()
    if head != prev:
        raise _Failure(ERR_INTEGRITY)


def _trust_key_intervals(records: list) -> dict:
    """Map each key to its ascending ``(at, status)`` certificate list.

    The records are globally ``at``-ordered by the chain check, so each key's
    subsequence is ascending too.
    """
    intervals: dict[str, list] = {}
    for record in records:
        intervals.setdefault(record["key"], []).append(
            (record["at"], record["status"])
        )
    return intervals


def _trust_authorizer(intervals: dict, key: str, moment: int) -> tuple | None:
    """The ``(at, status)`` certificate governing ``key`` at ``moment``.

    The governing certificate is the key's latest record with ``at <=
    moment``; None when the key is unknown or not yet mentioned at that time.
    """
    current = None
    for entry in intervals.get(key, ()):
        if entry[0] > moment:
            break
        current = entry
    return current


def _authorize_history_page(
    page_key: str,
    validated_records: list,
    intervals: dict,
    previous: dict,
) -> None:
    """Check the page key's authorization for every generation it signs.

    Each generation is governed by the page key's certificate at the
    checkpoint's ``verified_at``: an unknown or revoked key is an ``auth``
    failure. Consecutive generations signed by the same key must not cross an
    authorization boundary — a revocation followed by a reactivation — so
    when this generation's key equals the previous generation's, both must be
    governed by the very same certificate; a crossed boundary is an
    ``integrity`` failure. ``previous`` carries the last generation's
    ``(page_key, certificate at)`` across page seams.
    """
    for record in validated_records:
        moment = record["checkpoint"]["context"]["verified_at"]
        current = _trust_authorizer(intervals, page_key, moment)
        if current is None or current[1] != "active":
            raise _Failure(ERR_AUTH)
        last = previous.get("last")
        if last is not None and last[0] == page_key and last[1] != current[0]:
            raise _Failure(ERR_INTEGRITY)
        previous["last"] = (page_key, current[0])
