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
``attestation: null``; an ``attested`` export must come from an unexpired
``trust.sources`` entry whose pinned key matches the attestation and verifies
the Ed25519 signature over the SHA-256 digest of the canonical
``ledger-sync-range-v1`` message. Failures map to ``input`` (structure),
``auth`` (authorization), ``expired`` (deadlines) and ``integrity``
(anchor/chain/signature); nothing is raised. Success returns
``{"ok": True, "source", "request_id", "mode", "anchor", "tip",
"verified_tx_ids"}`` with ``verified_tx_ids`` ascending.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

from . import crypto
from .models import STATUS_CONFIRMED, Block, compute_block_hash
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
    current = time.time() if now is None else now
    try:
        anchor = _validate_range_export_inputs(document, expected_anchor, trust)
        _authenticate_range_export(document, trust, current)
        # The caller-pinned anchor must strictly equal the delivered one.
        if document["anchor"] != expected_anchor:
            raise _Failure(ERR_INTEGRITY)
        tail = _recompute_range_tail(anchor, document["blocks"])
        tip = _range_tip_descriptor(anchor, tail)
        _check_range_tip(document["tip"], tip)
        if document["mode"] == "attested":
            _verify_range_attestation(document, trust)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    verified_ids = sorted(
        tx.tx_id for block in tail for tx in block.transactions
    )
    return {
        "ok": True,
        "source": document["source"],
        "request_id": document["request_id"],
        "mode": document["mode"],
        "anchor": anchor,
        "tip": tip,
        "verified_tx_ids": verified_ids,
    }


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
    required here because the caller pins the range anchor directly.
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


def _authenticate_range_export(document: dict, trust: dict, now: float) -> None:
    """Check mode-specific source authorization and every deadline.

    A ``plain`` export is only acceptable from an allowlisted source and must
    carry ``attestation: null``; an ``attested`` export must come from a
    ``sources`` entry. All deadlines are checked before any integrity work:
    an expired, correctly-signed export is still unusable.
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
    elif source not in sources:
        raise _Failure(ERR_AUTH)

    if document["expires_at"] <= now:
        raise _Failure(ERR_EXPIRED)
    if mode == "plain":
        if allowlist[source] <= now:
            raise _Failure(ERR_EXPIRED)
    elif sources[source]["expires_at"] <= now:
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

    The attestation's ``public_key`` must be exactly the key the trust
    document pins for the source (a mismatched credential is an authorization
    failure); the signature covers the SHA-256 digest of the canonical
    ``ledger-sync-range-v1`` message over the document's delivered
    ``source, request_id, expires_at, anchor, blocks, tip``.
    """
    source = document["source"]
    attestation = document["attestation"]
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
