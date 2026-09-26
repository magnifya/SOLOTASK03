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

:func:`verify_header_page` verifies one signed ``GET /v1/chain/headers``
page offline. The document has the exact top-level key order
``anchor, headers, tip, auth``: a closed ``{height, block_hash}`` anchor, an
ascending list of ``{height, prev_hash, merkle_root, block_hash, status}``
headers (no transactions), the chain descriptor S and an
``{key_version, signature}`` envelope. The caller pins both the anchor and
the tip hash; ``trust.audit_signers`` supplies the public key selected by
``key_version``. Key-order/type defects are ``input``; an unknown key
version or a failed Ed25519 verification over
``SHA256(UTF8("ledger-headers-v1") || canonical_json(document without
auth))`` is ``auth``; an anchor/tip mismatch, a recomputed header hash or
prev_hash link mismatch, a non-consecutive height, or a pending header
anywhere but the chain tail is ``integrity``. An empty page is valid only
when its anchor is the pinned tip. Success returns
``{"ok": True, "anchor", "tip", "verified_block_hashes"}``; nothing is
raised for malformed input.

:func:`verify_header_pages` verifies an ordered, non-empty batch of such
signed header pages as one continuous chain. Every page is re-verified
under the exact :func:`verify_header_page` contract (key order, types,
signer history, domain signature, recomputed header hashes); the first
page's anchor must strictly equal the caller-pinned ``anchor`` and every
later page's anchor must equal the previous page's last header's
``{height, block_hash}``, so heights and prev_hash links continue across
the page seams and a missing, duplicated or reordered page breaks the
chain. Every page's ``tip`` descriptor must be field-for-field identical
and name the caller-pinned ``tip_hash``; the last page must reach that
tip. A non-final page's headers may never be empty — an empty page is
only ever valid as the batch's last page with its anchor being the tip —
and a pending header may only be the very last header of the whole batch,
so any page after a pending header is an ``integrity`` failure. Success
returns ``{"ok": True, "anchor", "tip", "pages",
"verified_block_hashes"}`` with ``pages`` the page count and the hashes
in chain order (the anchor itself is not a header and is not included);
failure is ``{"ok": False, "error": category}`` with category one of
``input`` (array/parameter shape, key order, types), ``auth`` (unknown
key version or a failed signature) and ``integrity`` (anchor, tip, hash,
link, pagination or pending-position defects). Nothing is raised.

:func:`verify_header_locator_page` verifies one signed
``POST /v1/chain/headers/locate`` page offline. The document is the same
fixed-order signed page as :func:`verify_header_page`
(``anchor, headers, tip, auth``); instead of one caller-pinned anchor the
caller passes the original ``locators`` list (1-64 ``{height, block_hash}``
items, heights non-boolean non-negative integers, strictly descending and
unique, hashes 64 lowercase hex). The document's own anchor must be one of
those locators — its position in the supplied list is returned as
``matched_index`` (starting at 0) — and every other rule is the
:func:`verify_header_page` rule: the signer version resolves in
``trust.audit_signers`` and verifies the domain-prefixed Ed25519 signature,
the header hashes and prev_hash links recompute from the anchor and the
descriptor names the caller-pinned ``tip_hash``. Bad parameters or list
shape/key order/types are ``input``; an unknown key version or a failed
signature is ``auth``; an anchor absent from the locator list, a broken
header chain or a tip mismatch is ``integrity``. Success returns
``{"ok": True, "anchor", "tip", "matched_index",
"verified_block_hashes"}``; failure returns only ``{"ok": False,
"error": category}`` and nothing is raised.

:func:`verify_header_locator_pages` verifies an ordered, non-empty batch of
such signed locator pages as one continuous chain. The parameters and every
page's key order, raw types and hex are checked first (``input``); then
every page's envelope is verified under the ``ledger-headers-v1`` domain
against ``trust.audit_signers`` (an unknown key version or a failed
signature is ``auth``). The first page's anchor must be one of the
``locators`` — its position (starting at 0) is returned as
``matched_index`` — and every later page's anchor must equal the previous
page's last header's ``{height, block_hash}``, so heights and prev_hash
links continue across the page seams and a missing, duplicated or reordered
page breaks the chain. Every page's ``tip`` descriptor must be
field-for-field identical and name the caller-pinned ``tip_hash``; the last
page must reach it. A non-final page's headers may never be empty — an
empty first page is valid only as the batch's single page with its anchor
being the tip — and a pending header may only be the very last header of
the whole batch. All of those are ``integrity`` failures. Success returns
``{"ok": True, "anchor", "tip", "matched_index", "pages",
"verified_block_hashes"}`` with ``pages`` the page count and the hashes in
chain order (the anchor itself is not included); failure returns only
``{"ok": False, "error": category}`` and nothing is raised.

:func:`advance_headers` durably checkpoints a verified header-page batch to
``path``. The file is one compact UTF-8 JSON document (non-ASCII written
unescaped, one trailing newline) with the exact top-level key order
``v, generation, anchor, tip, steps, hash``: ``v`` is 2, ``generation`` is a
non-boolean positive integer incremented once per successful advance or
reorg, ``anchor`` is the first batch's pinned ``{height, block_hash}``
anchor (key order ``height, block_hash``), ``tip`` is the latest chain
descriptor S, ``steps`` is a non-empty array of ``{kind, tip_hash, trust,
documents, locators}`` items (one per operation, nested key orders
unchanged; an advance appends a ``linear`` step whose ``locators`` is null,
a reorg a ``locator`` step) and ``hash`` is the SHA-256 of the canonical
(sorted, compact) JSON of the document with ``hash`` removed. Version-1
checkpoints (three-key ``{tip_hash, trust, documents}`` steps, all read as
``linear``) are still loaded and replayed; the next successful write
upgrades the file to v2. The first use of ``path`` requires a legal
``anchor``; later advances accept ``None`` (continue from the stored tip) or
the stored tip's ``{height, block_hash}``. Verification itself is
:func:`verify_header_pages` unchanged against the caller-pinned
``tip_hash``. The new tip may never drop in height; at the same height only
the same ``block_hash`` moving from ``pending`` to ``confirmed`` is accepted
— anything else is an ``integrity`` failure. Re-submitting the exact last
batch (same ``tip_hash``, ``trust`` and ``documents``) is idempotent: it
verifies but neither bumps the generation nor touches the file. Loading
strictly replays every stored step (shape, hash, per-batch verification and
tip monotonicity) and checks the stored tip; any mismatch is a ``state``
failure and the file is never truncated or rebuilt. Same-path advances share
one lock and the new file is atomically replaced into place; a failed write
restores the original bytes. Success returns ``{"ok": True, "generation",
"tip"}``; failure returns only ``{"ok": False, "error": category}`` with
category one of ``input/auth/integrity/state/io`` and nothing is raised.

:func:`reorg_headers` durably rewrites such a checkpoint around a verified
locator batch. ``documents`` is verified with
:func:`verify_header_locator_pages` against the caller's ``locators``,
``tip_hash`` and ``trust``; the batch's matched anchor selects the reorg
boundary — the last stored step whose closing tip is that anchor, or the
checkpoint's initial anchor when no step matches (an anchor naming neither
is an ``integrity`` failure). Every step after the boundary is dropped (the
dropped count is returned as ``replaced``) and one ``{kind: "locator",
tip_hash, trust, documents, locators}`` step is appended. The new tip may
never drop below the stored tip's height; at the same height a different
``block_hash`` is accepted in either status while the same ``block_hash``
may only move from ``pending`` to ``confirmed`` — anything else is an
``integrity`` failure. Re-submitting a last step fully identical to the new
locator step is idempotent: it returns the current generation with
``replaced`` 0 and neither bumps the generation nor touches the file; every
other success increments the generation by one and atomically rewrites the
file under the same per-path lock, hash and serialization rules as
:func:`advance_headers`. Success returns ``{"ok": True, "generation",
"tip", "replaced"}`` in that key order; failure returns only ``{"ok":
False, "error": category}`` with category one of ``input`` (argument or
batch structure), ``auth`` (signer lookup or signature), ``integrity``
(boundary, chain, height or same-height conflicts), ``state`` (an existing
checkpoint fails its key-order, type, hash or replay checks; it is never
truncated or rebuilt) and ``io`` (the checkpoint is missing or cannot be
read or written; a failed write restores the original bytes best-effort).
Nothing is raised.

:func:`header_locators` derives a fork-location locator request from a
checkpoint written by :func:`advance_headers`. The file is strictly
reloaded and replayed under the same rules (never rewritten); the replayed
history yields the sequence B — the initial anchor and every step's closing
tip, ascending, with adjacent equal ``(height, block_hash)`` pairs
collapsed — and the request's locators walk B newest-first: up to ten
consecutive tail items, then back-steps of 2, 4, 8, ... pinning B[0] at the
end, at most 64 items (a 64th item that is not B[0] is replaced by it), in
strictly descending height order. ``limit`` must be a plain (non-boolean)
integer in 1..500 (default 100). Success returns ``{"ok": True, "tip",
"request"}`` in that key order with ``tip`` the stored chain descriptor S
and ``request`` the closed ``{"locators", "limit"}`` document (locator key
order ``height, block_hash``); failure returns only ``{"ok": False,
"error": category}`` with category one of ``input`` (bad path or limit),
``io`` (missing or unreadable file) and ``state`` (checkpoint shape, digest
or replay mismatch), and nothing is raised.

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
limit=50, trust_path=None)`` strictly reloads both the checkpoint and its
sidecar under the shared per-path lock and returns one page with the exact key
order ``base, records, next, head, checkpoint, auth``: ``base``/``records``
are the sidecar's own documents (nested key orders unchanged), ``head`` the
sidecar head, ``checkpoint`` the persisted five-key checkpoint (identical to
the last retained record's), ``next`` the page's last record generation when
another page follows or ``null`` on the final page, and ``auth`` is
``{public_key, signature}`` where the Ed25519 signature is made by the 64-hex
seed ``key`` over the SHA-256 of the canonical (sorted, compact,
unescaped-non-ASCII) JSON of the page with ``auth`` removed. ``after`` is
``None`` (start after ``base``) or a non-boolean non-negative integer naming
either ``base.generation`` or a non-last retained generation; ``limit`` is a
non-boolean integer in 1..200. Bad arguments are ``input``, a missing or
unreadable file ``io`` and a corrupt checkpoint/sidecar or unmatched cursor
``state``. With ``trust_path`` set to a signer log (see
:func:`history_trust`), the log is strictly loaded first (a missing log is
``io`` and a corrupt one ``state``) and the page is truncated to the longest
prefix, starting at the cursor, whose checkpoints all carry the same key
active at their ``verified_at``: it stops just before the first record that
would straddle an authorization boundary and sets ``next`` (non-null) so the
following page continues there. The seed ``key`` must derive to the public
key covering that whole span — an unknown or revoked covering key is an
``auth`` failure. A page ending exactly at the retained tail still closes
with ``next: null``.

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

:func:`verify_history_trust` verifies the same pages against a signer
rotation/revocation log instead of one pinned page key, so each page's
``auth.public_key`` may differ. The ``trust`` document has the exact key
order ``root, records, head``: ``root`` is a 64-hex Ed25519 key that must
equal the pinned ``root`` argument; every non-empty record has the exact key
order ``at, key, status, prev, signature`` with ``at`` a plain
(non-boolean) positive strictly-ascending integer, ``key``/``prev`` 64
lowercase hex, ``status`` exactly ``active``/``revoked`` and ``signature``
128 lowercase hex. The first ``prev`` is 64 zeros, every later one is the
previous record's canonical-JSON SHA-256 and ``head`` is the last record's
hash; each certificate is the root key's Ed25519 signature over the
SHA-256 of the record's canonical JSON with ``signature`` removed. An
``active`` record authorizes ``key`` from its ``at`` until the next record;
a ``revoked`` one withdraws it until a later ``active``. A page must name
the single key active at every checkpoint ``verified_at`` it carries — a
page straddling an authorization boundary is rejected — and its signature
must verify over the auth-less canonical page digest. All page structure,
chaining, pagination and checkpoint-replay rules stay identical to
:func:`verify_history`. Failures map to ``input`` (missing/extra/reordered
keys, wrong types or hex), ``auth`` (root mismatch, a bad certificate or
page signature, an unknown or revoked page key) and ``integrity`` (``at``
not ascending, a bad ``prev``/``head``, a boundary crossing, or any
record/pagination/checkpoint-replay defect); nothing is raised and success
is ``{"ok": True}``.

:func:`history_trust` persists such a signer log at its own file path.
``history_trust(path)`` strictly loads and returns the ``{root, records,
head}`` document; a missing file is an ``io`` failure and any damaged log a
``state`` failure. ``history_trust(path, root_seed, at, key, status)``
appends one root-signed certificate — the four update fields are all required
or all absent — with ``root_seed`` a 64-hex Ed25519 seed (its public key is
the log root), ``at`` a non-boolean positive integer, ``key`` a 64-hex public
key and ``status`` ``active``/``revoked``. A fresh log must open with
``active``; ``at`` must strictly ascend; a ``revoked`` entry must name the
currently active key; re-appending the current tail's ``at``/``key``/
``status`` is idempotent. A seed whose root does not match the existing log
is ``auth``; bad argument shapes are ``input``; read-missing and read/write
``io``. The file uses the same compact-UTF-8/unescaped/single-trailing-
newline serialization and atomic per-path-locked replace as the checkpoint
files, and a failed write restores the original bytes best-effort.
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
    trust_path: object = None,
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

    With ``trust_path`` naming a durable signer log (see
    :func:`history_trust`), the log is strictly loaded under its own per-path
    lock first (missing is ``io``; any shape/chain/certificate defect is
    ``state``) and the page is cut at authorization boundaries: it keeps the
    longest prefix, starting at the cursor, whose checkpoints all name one key
    active at their ``verified_at``, stopping just before the first record a
    single envelope key cannot cover and carrying a non-null ``next`` so the
    following export continues there (a page ending exactly at the retained
    tail still closes with ``null``). The seed ``key`` must derive to that one
    covering key; an unknown or revoked covering key — no key is active at the
    page's first record — is an ``auth`` failure. Without ``trust_path`` the
    legacy single-key behavior is unchanged.
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
    if trust_path is not None and (
        not isinstance(trust_path, str) or not trust_path
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

        signer_entries: list[dict] | None = None
        if trust_path is not None:
            # The log has its own per-path lock, shared with history_trust
            # writers; when it names the same path it is the same reentrant
            # lock. A missing log is an io defect, a damaged one state.
            with _checkpoint_lock(trust_path):
                try:
                    signer_log = _load_signer_log(trust_path)
                except _CheckpointError as failure:
                    return {"ok": False, "error": failure.category}
            if signer_log is None:
                return {"ok": False, "error": ERR_IO}
            signer_entries = signer_log["records"]

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

        if signer_entries is None:
            page_records = records[start : start + limit]
            has_next = start + limit < len(records)
        else:
            # Keep only the maximal prefix one envelope key can sign: sample
            # the log at the first record's verified_at and stop at the first
            # record whose active key differs (a rotation or a revocation
            # window opening or closing inside the page).
            covering = _signer_active_key(
                signer_entries,
                records[start]["checkpoint"]["context"]["verified_at"],
            )
            end = start + 1
            while end < len(records) and end < start + limit:
                active = _signer_active_key(
                    signer_entries,
                    records[end]["checkpoint"]["context"]["verified_at"],
                )
                if active != covering:
                    break
                end += 1
            page_records = records[start:end]
            has_next = end < len(records)
            if covering is None or public_key != covering:
                # The page sits (or starts) in a revocation/pre-activation
                # window, or names a key the log does not authorize for it.
                return {"ok": False, "error": ERR_AUTH}

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
        if not isinstance(public_key, str) or not _HEX32_RE.fullmatch(public_key):
            raise _Failure(ERR_INPUT)
        parsed = _parse_all_history_pages(pages)

        def authenticate(page: dict, check_shared: object) -> None:
            # The old verifier judges the pinned-key mismatch before the
            # shared-field comparison and the signature afterwards, so a page
            # failing both reports ``auth`` for the key (and, only once the
            # shared envelope matches, a bad signature).
            if page["auth"]["public_key"] != public_key:
                raise _Failure(ERR_AUTH)
            check_shared()
            _verify_history_page_signature(page, public_key)

        _run_history_checks(parsed, authenticate)
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


def _parse_history_page(raw_page: object) -> dict:
    """Shape-validate one exported history page.

    Returns ``{"raw", "auth", "base", "head", "checkpoint", "records",
    "next"}`` with every nested document's key order and JSON type already
    validated. Raises :class:`_Failure` (``input``) on every structural
    defect; never judges signatures or cross-page chaining.
    """
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
    return {
        "raw": raw_page,
        "auth": auth,
        "base": base,
        "head": head,
        "checkpoint": page_checkpoint,
        "records": validated_records,
        "next": next_value,
    }


def _parse_all_history_pages(pages: object) -> list[dict]:
    """Shape-validate a non-empty ordered batch of exported history pages."""
    if not isinstance(pages, list) or not pages:
        raise _Failure(ERR_INPUT)
    return [_parse_history_page(raw_page) for raw_page in pages]


def _history_page_signing_digest(raw_page: dict) -> bytes:
    """The SHA-256 digest of a page's auth-less canonical JSON document."""
    unsigned = {
        key: raw_page[key] for key in HISTORY_PAGE_KEYS if key != "auth"
    }
    return hashlib.sha256(_canonical_json_bytes(unsigned)).digest()


def _verify_history_page_signature(page: dict, signer_key: str) -> None:
    """Verify one page signature over the auth-less canonical page digest."""
    digest = _history_page_signing_digest(page["raw"])
    if not crypto.verify_signature(signer_key, digest, page["auth"]["signature"]):
        raise _Failure(ERR_AUTH)


def _run_history_checks(parsed: list[dict], authenticate: object) -> None:
    """Shared authentication/chaining core of both history verifiers.

    Pages must already be shape-validated (see
    :func:`_parse_all_history_pages`). They are processed in the exact order
    the single-key verifier always used: ``authenticate(page, check_shared)``
    runs per page (the callback invokes the deferred shared-field comparison
    at its own point relative to key/signature checks), and only then are
    that page's records generation-/prev-/hash-linked and their checkpoints
    replayed; its ``next`` cursor is checked at the page seam. After the loop
    the final page must carry ``next: null`` and close the shared
    ``head``/``checkpoint``.
    """
    common_base: dict | None = None
    common_head: str | None = None
    common_checkpoint: dict | None = None
    # Linkage state carried across page seams.
    expected_prev: str | None = None
    expected_generation: int | None = None
    previous_tip: dict | None = None

    for position, page in enumerate(parsed):
        is_last_page = position == len(parsed) - 1

        def check_shared() -> None:
            # The trust anchor (base) and signed envelope (head, checkpoint)
            # must be shared by every page of the export.
            nonlocal common_base, common_head, common_checkpoint
            if common_base is None:
                common_base = page["base"]
                common_head = page["head"]
                common_checkpoint = page["checkpoint"]
            elif page["base"] != common_base:
                raise _Failure(ERR_INTEGRITY)
            elif page["head"] != common_head or (
                page["checkpoint"] != common_checkpoint
            ):
                raise _Failure(ERR_INTEGRITY)

        authenticate(page, check_shared)

        if expected_prev is None:
            # The first page starts right at the shared base.
            expected_prev = page["base"]["hash"]
            expected_generation = page["base"]["generation"] + 1

        for record in page["records"]:
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

        last_generation = page["records"][-1]["checkpoint"]["generation"]
        if is_last_page:
            if page["next"] is not None:
                raise _Failure(ERR_INTEGRITY)
        else:
            # A non-final page must name its last record as the cursor the
            # next page continues from.
            if page["next"] != last_generation:
                raise _Failure(ERR_INTEGRITY)

    # The final page closes the export: its last record is the sidecar head
    # and its checkpoint is the page checkpoint shared by every page.
    final_record = parsed[-1]["records"][-1]
    if final_record["hash"] != common_head:
        raise _Failure(ERR_INTEGRITY)
    if final_record["checkpoint"] != common_checkpoint:
        raise _Failure(ERR_INTEGRITY)


# -- signed history export verification with signer rotation/revocation --------

# The exact top-level key order of one signer trust/rotation log, and the exact
# key order of one record in it.
HISTORY_TRUST_KEYS = ("root", "records", "head")
SIGNER_RECORD_KEYS = ("at", "key", "status", "prev", "signature")
SIGNER_STATUSES = ("active", "revoked")

# The first signer record's ``prev`` names no predecessor (64 zeros).
SIGNER_ZERO_HASH = "0" * 64


def verify_history_trust(pages: object, trust: object, root: object) -> dict:
    """Verify signed history pages against a rotating/revocable signer log.

    Same page rules as :func:`verify_history`: ``pages`` must be a non-empty
    ordered batch of pages with the exact key order
    ``base, records, next, head, checkpoint, auth`` and valid nested documents,
    shared ``base``/``head``/``checkpoint``, consecutive record generations,
    recomputed ``prev``/``hash`` links, ``next`` cursor seams, replayed
    checkpoints with anchor continuity and final-page closure — but each page's
    ``auth.public_key`` may name a different signer.

    ``trust`` is a signer log with the exact key order ``root, records, head``:

    * ``root`` is a 64-lowercase-hex Ed25519 key and must equal the pinned
      ``root`` argument;
    * ``records`` is a non-empty list of items with the exact key order
      ``at, key, status, prev, signature``: ``at`` a plain (non-boolean)
      positive integer running strictly ascending, ``key``/``prev`` 64
      lowercase hex, ``status`` exactly ``active`` or ``revoked`` and
      ``signature`` 128 lowercase hex;
    * the first item's ``prev`` is 64 zeros and every later one is the
      SHA-256 of the previous item's canonical (sorted, compact) JSON; ``head``
      is the same hash of the final item;
    * every ``signature`` is the root key's Ed25519 signature over the
      SHA-256 of the item's canonical JSON with ``signature`` removed.

    An ``active`` item authorizes ``key`` from its ``at`` until the following
    item; a ``revoked`` item withdraws the key from its ``at`` until a later
    ``active`` item. A page is accepted only when one single key is active for
    every checkpoint ``verified_at`` it carries (a page spanning an
    authorization boundary is rejected), the page names that key and its
    signature verifies over the auth-less canonical page digest.

    Returns ``{"ok": True}`` on success or ``{"ok": False, "error":
    category}`` on failure: ``input`` (missing/extra/reordered keys, wrong
    types or hex), ``auth`` (root mismatch, a bad certificate or page
    signature, an unknown or revoked page key) and ``integrity`` (``at`` not
    ascending, a bad ``prev``/``head``, an authorization-boundary crossing, or
    any record/pagination/checkpoint-replay defect). Never raises.
    """
    try:
        if not isinstance(root, str) or not _HEX32_RE.fullmatch(root):
            raise _Failure(ERR_INPUT)
        parsed = _parse_all_history_pages(pages)
        entries, head, trust_root = _parse_signer_trust(trust)
        # All structural checks precede trust: the well-formed log root is
        # bound to the pinned argument only after every record has a legal
        # shape and a strictly ascending ``at`` sequence.
        if trust_root != root:
            raise _Failure(ERR_AUTH)
        _check_signer_log_chains(entries, head)
        _verify_signer_certificates(entries, root)

        def authenticate(page: dict, check_shared: object) -> None:
            # Resolve the one key the log authorizes for this page's whole
            # span before the shared-envelope comparison and signature check,
            # mirroring the single-key verifier's auth-before-shared order.
            authorized = _page_authorized_key(page, entries)
            check_shared()
            _verify_history_page_signature(page, authorized)

        _run_history_checks(parsed, authenticate)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {"ok": True}


def _parse_signer_trust(trust: object) -> tuple[list[dict], str, str]:
    """Shape-validate the signer rotation log.

    Returns ``(entries, head, root)`` with every item already carrying the
    right keys, types and hex. Key-order/type/hex defects are ``input``; the
    caller binds the well-formed ``root`` to its pinned argument (``auth``)
    before the strictly-ascending ``at`` order, ``prev``/``head`` links
    (``integrity``) and certificate signatures (``auth``) are judged.
    """
    if not isinstance(trust, dict) or tuple(trust.keys()) != HISTORY_TRUST_KEYS:
        raise _Failure(ERR_INPUT)
    trust_root = trust["root"]
    if not crypto.is_hex64(trust_root):
        raise _Failure(ERR_INPUT)
    records = trust["records"]
    if not isinstance(records, list) or not records:
        raise _Failure(ERR_INPUT)
    entries: list[dict] = []
    for raw in records:
        if not isinstance(raw, dict) or tuple(raw.keys()) != SIGNER_RECORD_KEYS:
            raise _Failure(ERR_INPUT)
        at_value = raw["at"]
        key = raw["key"]
        status = raw["status"]
        prev = raw["prev"]
        signature = raw["signature"]
        # Booleans are rejected even though they are integers; every ``at`` is
        # a positive instant.
        if not _is_int(at_value) or at_value < 1:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(key) or not crypto.is_hex64(prev):
            raise _Failure(ERR_INPUT)
        if status not in SIGNER_STATUSES:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex128(signature):
            raise _Failure(ERR_INPUT)
        entries.append(
            {
                "raw": raw,
                "at": at_value,
                "key": key,
                "status": status,
                "prev": prev,
                "signature": signature,
            }
        )
    head = trust["head"]
    if not crypto.is_hex64(head):
        raise _Failure(ERR_INPUT)
    return entries, head, trust_root


def _signer_record_hash(raw: dict) -> str:
    """SHA-256 of one signer record's full canonical (sorted, compact) JSON."""
    return hashlib.sha256(_canonical_json_bytes(raw)).hexdigest()


def _check_signer_log_chains(entries: list[dict], head: str) -> None:
    """Check strictly ascending ``at`` values, ``prev`` links and ``head``."""
    # The strictly ascending ``at`` sequence is a log-ordering rule rather
    # than a shape rule, so a repeat or decrease is an integrity failure.
    for earlier, later in zip(entries, entries[1:]):
        if later["at"] <= earlier["at"]:
            raise _Failure(ERR_INTEGRITY)
    expected_prev = SIGNER_ZERO_HASH
    for entry in entries:
        if entry["prev"] != expected_prev:
            raise _Failure(ERR_INTEGRITY)
        expected_prev = _signer_record_hash(entry["raw"])
    if head != expected_prev:
        raise _Failure(ERR_INTEGRITY)


def _signer_active_key(entries: list[dict], instant: int) -> str | None:
    """The key authorized at ``instant`` per the last item with ``at <= instant``.

    ``active`` authorizes that item's key from its ``at`` until the next item;
    ``revoked`` withdraws it until a later ``active`` item. Returns None when
    no item precedes ``instant`` or the latest one revokes.
    """
    current: str | None = None
    for entry in entries:
        if entry["at"] > instant:
            break
        if entry["status"] == "active":
            current = entry["key"]
        else:
            current = None
    return current


def _page_authorized_key(page: dict, entries: list[dict]) -> str:
    """Resolve the single key the log authorizes for one page's whole span.

    The log's active key is sampled at every checkpoint ``verified_at`` the
    page carries. All samples must agree: a page straddling any
    authorization boundary — a rotation to another key or a transition into
    (or out of) a revocation window — cannot carry one envelope signature
    valid for all its generations and is an integrity failure. When no key
    is active anywhere on the page (before the first activation or inside a
    revocation window), or the page names another key, that is an unknown or
    revoked signer: an auth failure. Returns the key the signature must be
    checked against.
    """
    times = [
        record["checkpoint"]["context"]["verified_at"]
        for record in page["records"]
    ]
    authorized: str | None = _signer_active_key(entries, times[0])
    for instant in times[1:]:
        if _signer_active_key(entries, instant) != authorized:
            # The page straddles a rotation/revocation boundary, so no single
            # envelope key can have signed all its checkpoints.
            raise _Failure(ERR_INTEGRITY)
    if authorized is None:
        # Every checkpoint sits outside an active window: the page's key is
        # unknown or revoked for its whole span.
        raise _Failure(ERR_AUTH)
    if page["auth"]["public_key"] != authorized:
        raise _Failure(ERR_AUTH)
    return authorized


def _verify_signer_certificates(entries: list[dict], root: str) -> None:
    """Verify every signer record's root signature over its unsigned body."""
    for entry in entries:
        unsigned = {
            key: entry["raw"][key]
            for key in SIGNER_RECORD_KEYS
            if key != "signature"
        }
        digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
        if not crypto.verify_signature(root, digest, entry["signature"]):
            raise _Failure(ERR_AUTH)


# -- durable signer trust log --------------------------------------------------


def _load_signer_log(path: str) -> dict | None:
    """Strictly load and verify the durable signer log at ``path``.

    Returns None when no file exists. Otherwise the document is parsed with
    the exact :func:`verify_history_trust` rules — top-level/record key order
    and types (``input`` there), strictly ascending ``at`` and ``prev``/
    ``head`` links (``integrity`` there) and every root certificate signature
    (``auth`` there) — but every defect of a *persisted* log is reported as
    ``state`` corruption, never as a verifier category. An unreadable file is
    an ``io`` failure.
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
    try:
        entries, head, root = _parse_signer_trust(data)
        _check_signer_log_chains(entries, head)
        _verify_signer_certificates(entries, root)
    except _Failure:
        raise _CheckpointError(ERR_STATE) from None
    return {
        "root": root,
        "records": [entry["raw"] for entry in entries],
        "head": head,
    }


def _atomic_write_signer_log(path: str, document: dict) -> None:
    """Write the signer log in declared key order and atomically replace."""
    ordered = {
        "root": document["root"],
        "records": [
            {key: record[key] for key in SIGNER_RECORD_KEYS}
            for record in document["records"]
        ],
        "head": document["head"],
    }
    _atomic_write_bytes(path, _serialize_document(ordered))


def history_trust(
    path: object,
    root_seed: object = None,
    at: object = None,
    key: object = None,
    status: object = None,
) -> dict:
    """Read or append one entry of the durable checkpoint-history signer log.

    The log file follows the exact :func:`verify_history_trust` document
    contract: key order ``root, records, head``, records
    ``at, key, status, prev, signature`` with 64-zero-anchored canonical-hash
    links and root-signed certificates, serialized as compact UTF-8 JSON
    (non-ASCII unescaped) with one trailing newline and atomically replaced
    under the per-path lock shared with every other same-``path`` operation.

    With only ``path`` given, the log is strictly loaded and returned in its
    declared key order. An update requires all four of ``root_seed`` (a
    64-lowercase-hex Ed25519 seed whose public key is the log root), ``at`` (a
    plain non-boolean positive integer), ``key`` (the 64-lowercase-hex public
    key the entry names) and ``status`` (``active``/``revoked``). Append
    rules: a fresh log's first entry must be ``active``; ``at`` must strictly
    exceed the last entry's; a ``revoked`` entry must name the key currently
    active (the last item with a smaller ``at``); an entry byte-identical in
    ``at``/``key``/``status`` to the current last one is an idempotent no-op.

    Success returns the ``{root, records, head}`` document. Failure is
    ``{"ok": False, "error": category}`` with category one of ``input``
    (argument shape), ``auth`` (the seed's root does not match the existing
    log), ``state`` (a corrupt or conflicting log) and ``io`` (the log is
    missing on read or cannot be read/written; a failed write restores the
    original bytes best-effort).
    """
    if not isinstance(path, str) or not path:
        return {"ok": False, "error": ERR_INPUT}
    options = (root_seed, at, key, status)
    given = [value is not None for value in options]
    if any(given) and not all(given):
        # An update needs all four fields; a partial option set never names a
        # well-formed certificate.
        return {"ok": False, "error": ERR_INPUT}
    updating = any(given)

    root_pub: str | None = None
    if updating:
        if not isinstance(root_seed, str) or not _HEX32_RE.fullmatch(root_seed):
            return {"ok": False, "error": ERR_INPUT}
        if not isinstance(key, str) or not crypto.is_hex64(key):
            return {"ok": False, "error": ERR_INPUT}
        if not _is_int(at) or at < 1:
            return {"ok": False, "error": ERR_INPUT}
        if status not in SIGNER_STATUSES:
            return {"ok": False, "error": ERR_INPUT}
        root_pub = crypto.derive_public_key(root_seed)
        if root_pub is None:
            return {"ok": False, "error": ERR_INPUT}

    lock = _checkpoint_lock(path)
    with lock:
        try:
            log = _load_signer_log(path)
        except _CheckpointError as failure:
            return {"ok": False, "error": failure.category}

        if not updating:
            if log is None:
                # Reading a log that does not exist is an io defect.
                return {"ok": False, "error": ERR_IO}
            return log

        assert root_pub is not None
        if log is None:
            # A fresh log starts with its first activation; anything else
            # (including an opening revocation) is a state conflict.
            if status != "active":
                return {"ok": False, "error": ERR_STATE}
            records: list[dict] = []
            prev = SIGNER_ZERO_HASH
        else:
            if log["root"] != root_pub:
                # Entries can only be certified by the log's own root key.
                return {"ok": False, "error": ERR_AUTH}
            records = log["records"]
            last_record = records[-1]
            if (
                last_record["at"] == at
                and last_record["key"] == key
                and last_record["status"] == status
            ):
                # Same certificate replayed against the tail: idempotent, the
                # file bytes stay exactly as they were.
                return log
            if at <= last_record["at"]:
                # The log is append-only with a strictly ascending clock.
                return {"ok": False, "error": ERR_STATE}
            if status == "revoked":
                # Only the key currently authorized may be withdrawn. Every
                # existing item precedes the new strictly-larger ``at``.
                current = _signer_active_key(records, at)
                if current is None or current != key:
                    return {"ok": False, "error": ERR_STATE}
            prev = log["head"]

        unsigned = {"at": at, "key": key, "status": status, "prev": prev}
        digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
        signature = crypto.sign_message(root_seed, digest)
        if signature is None:
            return {"ok": False, "error": ERR_INPUT}
        record = dict(unsigned)
        record["signature"] = signature
        written = {
            "root": root_pub,
            "records": records + [record],
            "head": _signer_record_hash(record),
        }

        try:
            original = _read_bytes_or_none(path)
        except OSError:
            return {"ok": False, "error": ERR_IO}
        try:
            _atomic_write_signer_log(path, written)
        except OSError:
            # Compensate: put the original bytes back best-effort.
            _restore_bytes(path, original)
            return {"ok": False, "error": ERR_IO}
        return written


# -- node-managed file pair inspection -----------------------------------------


def inspect_history_files(path: object, trust_path: object = None) -> dict:
    """Strictly load the checkpoint pair and the optional signer log.

    Shared by the token-gated HTTP endpoints and by startup recovery, so both
    apply the exact :func:`history_trust` / :func:`export_history` file
    contracts (shape, hash chains, replay) and agree on what each file's
    current head is.

    On success returns
    ``{"ok": True, "trust_head", "history_head", "trust_doc"}``: each head is
    the file's current hash head or ``None`` when that file does not exist
    (``trust_doc`` is the parsed ``{root, records, head}`` log or ``None``).
    The checkpoint pair is loaded under its per-path lock (and the signer log
    under its own lock): a sidecar requires its checkpoint and its tip record
    must reproduce it. On failure returns
    ``{"ok": False, "error": category, "path": offending_path}`` with category
    one of ``input`` (bad path arguments), ``io`` (an unreadable file) and
    ``state`` (a corrupt checkpoint/sidecar/log). Never raises.
    """
    if not isinstance(path, str) or not path:
        return {"ok": False, "error": ERR_INPUT, "path": None}
    if trust_path is not None and (
        not isinstance(trust_path, str) or not trust_path
    ):
        return {"ok": False, "error": ERR_INPUT, "path": None}
    try:
        with _checkpoint_lock(path):
            try:
                checkpoint = _load_checkpoint(path)
            except _CheckpointError as failure:
                return {
                    "ok": False,
                    "error": failure.category,
                    "path": path,
                }
            sidecar_path = _history_path(path)
            try:
                sidecar = _load_history(sidecar_path)
            except _CheckpointError as failure:
                return {
                    "ok": False,
                    "error": failure.category,
                    "path": sidecar_path,
                }
            if sidecar is None:
                # Either the pair has never been advanced (no files) or a
                # pre-migration checkpoint exists without a sidecar: either
                # way no sidecar head exists yet.
                history_head = None
            else:
                if checkpoint is None:
                    # A sidecar without its checkpoint is unrecoverable.
                    return {
                        "ok": False,
                        "error": ERR_STATE,
                        "path": path,
                    }
                history_head = sidecar["head"]

            trust_doc = None
            trust_head = None
            if trust_path is not None:
                with _checkpoint_lock(trust_path):
                    try:
                        trust_doc = _load_signer_log(trust_path)
                    except _CheckpointError as failure:
                        return {
                            "ok": False,
                            "error": failure.category,
                            "path": trust_path,
                        }
                    if trust_doc is not None:
                        trust_head = trust_doc["head"]
    except OSError as exc:
        return {"ok": False, "error": ERR_IO, "path": getattr(exc, "filename", path)}
    return {
        "ok": True,
        "trust_head": trust_head,
        "history_head": history_head,
        "trust_doc": trust_doc,
    }


def restore_file_bytes(path: str, original: bytes | None) -> None:
    """Best-effort restore of ``path`` to ``original`` bytes (None = absent).

    Mirrors the in-transaction compensation used by :func:`advance` and
    :func:`history_trust`: any failure is swallowed (the next strict load
    surfaces the damage as ``state``).
    """
    _restore_bytes(path, original)

# -- signed block-header pages (GET /v1/chain/headers) ------------------------

# Domain separator prefixing every signed header page.
HEADER_PAGE_DOMAIN = "ledger-headers-v1"

# The exact contract key order of a signed header page and of its nested
# closed documents.
HEADER_PAGE_KEYS = ("anchor", "headers", "tip", "auth")
HEADER_ANCHOR_KEYS = ("height", "block_hash")
HEADER_ITEM_KEYS = ("height", "prev_hash", "merkle_root", "block_hash", "status")
HEADER_TIP_KEYS = DESCRIPTOR_FIELDS
HEADER_AUTH_KEYS = ("key_version", "signature")

# Fixed success key order returned by :func:`verify_header_page`.
HEADER_PAGE_RESULT_KEYS = ("ok", "anchor", "tip", "verified_block_hashes")


def _header_page_bytes(unsigned: dict) -> bytes:
    """The signed bytes of a header page without its ``auth`` envelope:
    ``UTF8("ledger-headers-v1") || canonical_json(anchor, headers, tip)``.
    """
    return HEADER_PAGE_DOMAIN.encode("utf-8") + _canonical_json_bytes(unsigned)


def sign_header_page(
    private_key_hex: str,
    key_version: int,
    anchor: dict,
    headers: list,
    tip: dict,
) -> dict | None:
    """Build the ``{key_version, signature}`` envelope of a header page.

    The signature is an Ed25519 signature over
    ``SHA256(UTF8("ledger-headers-v1") || canonical_json({anchor, headers,
    tip}))``. Returns None when the private key is malformed.
    """
    unsigned = {"anchor": anchor, "headers": headers, "tip": tip}
    digest = hashlib.sha256(_header_page_bytes(unsigned)).digest()
    signature = crypto.sign_message(private_key_hex, digest)
    if signature is None:
        return None
    return {"key_version": key_version, "signature": signature}


def verify_header_page(
    document: object,
    anchor: object,
    tip_hash: object,
    trust: object,
) -> dict:
    """Offline-verify one signed ``GET /v1/chain/headers`` page.

    ``document`` is the decoded response with the exact top-level key order
    ``anchor, headers, tip, auth``: ``anchor`` is ``{height, block_hash}``
    (key order ``height, block_hash``), ``headers`` is an ascending list of
    ``{height, prev_hash, merkle_root, block_hash, status}`` header items,
    ``tip`` is the chain descriptor S (``tip_hash, height, length, status``)
    and ``auth`` is ``{key_version, signature}``. ``anchor`` is the
    caller-pinned anchor the page's ``anchor`` must strictly equal;
    ``tip_hash`` is the caller-pinned chain tip the page's ``tip`` must
    name. ``trust`` must carry an ``audit_signers`` list; the envelope's
    ``key_version`` selects that version's public key.

    Verification, in order: strict key order and types (``input``), signer
    lookup by ``key_version`` and the Ed25519 signature over
    ``SHA256(UTF8("ledger-headers-v1") || canonical_json(document without
    auth))`` (unknown version/key or a signature that does not verify is
    ``auth``), the pinned anchor, the recomputed header hashes and prev_hash
    links (heights consecutive from the anchor, pending only at the page
    tail), and the tip descriptor (``integrity``). An empty page is valid
    only when its anchor is the pinned tip; a page ending before the tip is
    a valid non-final pagination page. Never raises for malformed input.

    Returns ``{"ok": True, "anchor", "tip", "verified_block_hashes"}`` on
    success (the hashes in ascending page order, empty for an anchor=tip
    page) or ``{"ok": False, "error": "input"|"auth"|"integrity"}``.
    """
    try:
        closed_anchor, closed_tip, verified_hashes = _verify_header_page(
            document, anchor, tip_hash, trust
        )
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {
        "ok": True,
        "anchor": closed_anchor,
        "tip": closed_tip,
        "verified_block_hashes": verified_hashes,
    }


def _validate_header_anchor(raw: object) -> dict:
    """Structural validation of a closed ``{height, block_hash}`` anchor."""
    if not isinstance(raw, dict) or tuple(raw.keys()) != HEADER_ANCHOR_KEYS:
        raise _Failure(ERR_INPUT)
    if not _is_int(raw["height"]) or raw["height"] < 0:
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(raw["block_hash"]):
        raise _Failure(ERR_INPUT)
    return {"height": raw["height"], "block_hash": raw["block_hash"]}


def _validate_header_trust(trust: object) -> dict:
    """Parse ``trust.audit_signers`` into ``{version: public_key}``.

    The list must be non-empty; every entry must carry a positive,
    non-boolean integer ``version`` and a 64-lowercase-hex ``public_key``.
    Versions must be unique. Any other defect is an input error.
    """
    if not isinstance(trust, dict):
        raise _Failure(ERR_INPUT)
    raw_signers = trust.get("audit_signers")
    if not isinstance(raw_signers, list) or not raw_signers:
        raise _Failure(ERR_INPUT)
    signers: dict[int, str] = {}
    for entry in raw_signers:
        if not isinstance(entry, dict):
            raise _Failure(ERR_INPUT)
        version = entry.get("version")
        public_key = entry.get("public_key")
        if not _is_int(version) or version < 1:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(public_key):
            raise _Failure(ERR_INPUT)
        if version in signers:
            raise _Failure(ERR_INPUT)
        signers[version] = public_key
    return signers


def _parse_header_page(document: object) -> tuple[dict, list[dict], dict, int, str]:
    """Stage 1 of the header-page contract: exact key order and raw types.

    Every defect here is an input error. Returns the closed anchor, the
    closed header items, the closed tip descriptor, the envelope's key
    version and its signature.
    """
    if not isinstance(document, dict):
        raise _Failure(ERR_INPUT)
    if tuple(document.keys()) != HEADER_PAGE_KEYS:
        raise _Failure(ERR_INPUT)
    page_anchor = _validate_header_anchor(document["anchor"])
    raw_headers = document["headers"]
    if not isinstance(raw_headers, list):
        raise _Failure(ERR_INPUT)
    headers: list[dict] = []
    for item in raw_headers:
        if not isinstance(item, dict) or tuple(item.keys()) != HEADER_ITEM_KEYS:
            raise _Failure(ERR_INPUT)
        if not _is_int(item["height"]) or item["height"] < 0:
            raise _Failure(ERR_INPUT)
        if (
            not crypto.is_hex64(item["prev_hash"])
            or not crypto.is_hex64(item["merkle_root"])
            or not crypto.is_hex64(item["block_hash"])
        ):
            raise _Failure(ERR_INPUT)
        if item["status"] not in (STATUS_PENDING, STATUS_CONFIRMED):
            raise _Failure(ERR_INPUT)
        headers.append({key: item[key] for key in HEADER_ITEM_KEYS})
    raw_tip = document["tip"]
    if not isinstance(raw_tip, dict) or tuple(raw_tip.keys()) != HEADER_TIP_KEYS:
        raise _Failure(ERR_INPUT)
    if not crypto.is_hex64(raw_tip["tip_hash"]):
        raise _Failure(ERR_INPUT)
    if not _is_int(raw_tip["height"]) or raw_tip["height"] < 0:
        raise _Failure(ERR_INPUT)
    if not _is_int(raw_tip["length"]) or raw_tip["length"] < 1:
        raise _Failure(ERR_INPUT)
    if raw_tip["status"] not in (STATUS_PENDING, STATUS_CONFIRMED):
        raise _Failure(ERR_INPUT)
    tip = {key: raw_tip[key] for key in HEADER_TIP_KEYS}
    raw_auth = document["auth"]
    if not isinstance(raw_auth, dict) or tuple(raw_auth.keys()) != HEADER_AUTH_KEYS:
        raise _Failure(ERR_INPUT)
    key_version = raw_auth["key_version"]
    signature = raw_auth["signature"]
    if not _is_int(key_version) or key_version < 1:
        raise _Failure(ERR_INPUT)
    if not isinstance(signature, str) or not crypto.is_hex128(signature):
        raise _Failure(ERR_INPUT)
    return page_anchor, headers, tip, key_version, signature


def _authenticate_header_page(
    document: dict, key_version: int, signature: str, signers: dict
) -> None:
    """Stage 2 of the header-page contract: signer lookup and signature.

    The envelope's ``key_version`` selects the public key from
    ``trust.audit_signers``; an unknown version or an Ed25519 signature that
    does not verify over the domain-prefixed canonical bytes of the page
    without its ``auth`` is an auth failure.
    """
    public_key = signers.get(key_version)
    if public_key is None:
        raise _Failure(ERR_AUTH)
    unsigned = {key: document[key] for key in HEADER_PAGE_KEYS if key != "auth"}
    digest = hashlib.sha256(_header_page_bytes(unsigned)).digest()
    if not crypto.verify_signature(public_key, digest, signature):
        raise _Failure(ERR_AUTH)


def _check_header_page_chain(
    page_anchor: dict, headers: list[dict], tip: dict, expected_tip_hash: str
) -> list[str]:
    """Stage 3 of the header-page contract: recompute the chain and the tip.

    Every header hash and prev_hash link is recomputed standalone from the
    anchor: heights run consecutively from ``anchor.height + 1``, the first
    prev_hash is the anchor hash and later ones link internally. The
    merkle_root cannot be recomputed from a header-only page, but it is
    bound into the recomputed block hash. A pending header may only sit at
    the page tail. The tip descriptor must name the caller-pinned tip hash
    and stay coherent with the page. Returns the verified header hashes in
    ascending page order. Every defect is an integrity failure.
    """
    previous_hash = page_anchor["block_hash"]
    for position, header in enumerate(headers):
        if header["height"] != page_anchor["height"] + 1 + position:
            raise _Failure(ERR_INTEGRITY)
        if header["prev_hash"] != previous_hash:
            raise _Failure(ERR_INTEGRITY)
        recomputed = compute_block_hash(
            header["height"], header["prev_hash"], header["merkle_root"]
        )
        if recomputed != header["block_hash"]:
            raise _Failure(ERR_INTEGRITY)
        if position < len(headers) - 1 and header["status"] != STATUS_CONFIRMED:
            raise _Failure(ERR_INTEGRITY)
        previous_hash = header["block_hash"]

    # The tip descriptor and the caller-pinned tip hash.
    if tip["tip_hash"] != expected_tip_hash:
        raise _Failure(ERR_INTEGRITY)
    # The canonical chain starts at height 0, so its descriptor length is
    # always the tip height plus one.
    if tip["length"] != tip["height"] + 1:
        raise _Failure(ERR_INTEGRITY)
    if headers:
        last = headers[-1]
        if last["block_hash"] == tip["tip_hash"]:
            # Final page: the page ends exactly at the pinned tip.
            if tip["height"] != last["height"] or tip["status"] != last["status"]:
                raise _Failure(ERR_INTEGRITY)
        else:
            # Non-final pagination page ending strictly before the tip: the
            # chain continues past this page, so a pending last header would
            # put a pending block somewhere other than the chain tail.
            if last["height"] >= tip["height"]:
                # A same-height different hash is a fork past the pin; a page
                # can never extend beyond the tip either.
                raise _Failure(ERR_INTEGRITY)
            if last["status"] != STATUS_CONFIRMED:
                raise _Failure(ERR_INTEGRITY)
    else:
        # An empty page is only coherent when the anchor itself is the tip.
        if (
            page_anchor["block_hash"] != tip["tip_hash"]
            or page_anchor["height"] != tip["height"]
        ):
            raise _Failure(ERR_INTEGRITY)
    return [header["block_hash"] for header in headers]


def _verify_header_page(
    document: object,
    expected_anchor: object,
    expected_tip_hash: object,
    trust: object,
) -> tuple[dict, dict, list[str]]:
    """Strict core of :func:`verify_header_page`; may raise :class:`_Failure`."""
    # 1. Exact key order and types — every defect here is an input error.
    page_anchor, headers, tip, key_version, signature = _parse_header_page(document)

    # The caller-pinned anchor and tip hash are validated for shape too.
    pinned_anchor = _validate_header_anchor(expected_anchor)
    if not isinstance(expected_tip_hash, str) or not crypto.is_hex64(
        expected_tip_hash
    ):
        raise _Failure(ERR_INPUT)

    # 2. Trust signer lookup by key version, then the Ed25519 signature over
    # the domain-prefixed canonical bytes of the page without its auth.
    signers = _validate_header_trust(trust)
    _authenticate_header_page(document, key_version, signature, signers)

    # 3. The delivered anchor must strictly equal the caller-pinned anchor.
    if page_anchor != pinned_anchor:
        raise _Failure(ERR_INTEGRITY)

    # 4./5. Recompute the header chain from the anchor and check the tip
    # descriptor against the caller-pinned tip hash.
    verified_hashes = _check_header_page_chain(
        page_anchor, headers, tip, expected_tip_hash
    )
    return page_anchor, tip, verified_hashes


# Fixed success key order returned by :func:`verify_header_pages`.
HEADER_PAGES_RESULT_KEYS = (
    "ok",
    "anchor",
    "tip",
    "pages",
    "verified_block_hashes",
)


def verify_header_pages(
    documents: object,
    anchor: object,
    tip_hash: object,
    trust: object,
) -> dict:
    """Verify an ordered batch of signed header pages as one chain.

    ``documents`` must be a non-empty list of decoded
    ``GET /v1/chain/headers`` pages, each re-verified under the exact
    :func:`verify_header_page` contract (key order, types, signer history,
    domain signature, recomputed header hashes). ``anchor`` is the
    caller-pinned ``{height, block_hash}`` the first page's anchor must
    strictly equal; every later page's anchor must equal the previous
    page's last header's ``{height, block_hash}``, so heights and
    prev_hash links continue across the page seams and a missing,
    duplicated or reordered page breaks the chain. ``tip_hash`` is the
    caller-pinned chain tip: every page's ``tip`` descriptor must be
    field-for-field identical and name that hash, and the last page must
    reach it. A non-final page's headers may never be empty — an empty
    page is only valid as the batch's last page with its anchor being the
    tip — and a pending header may only be the very last header of the
    whole batch, so any page after a pending header fails.

    Returns ``{"ok": True, "anchor", "tip", "pages",
    "verified_block_hashes"}`` on success — ``anchor`` the pinned anchor
    of the first page, ``tip`` the shared chain descriptor, ``pages`` the
    page count and ``verified_block_hashes`` every verified header hash in
    chain order (the anchor itself is not a header and is not included) —
    or ``{"ok": False, "error": category}`` on failure with category one
    of ``input`` (array/parameter shape, key order, types), ``auth``
    (unknown key version or a failed signature) and ``integrity``
    (anchor, tip, hash, link, pagination or pending-position defects).
    Never raises for malformed input.
    """
    try:
        if not isinstance(documents, list) or not documents:
            raise _Failure(ERR_INPUT)
        pages = len(documents)
        expected_anchor = anchor
        first_anchor: dict | None = None
        shared_tip: dict | None = None
        verified_hashes: list[str] = []
        for position, document in enumerate(documents):
            # _verify_header_page itself rejects a page whose anchor does
            # not strictly equal ``expected_anchor`` — the first page's
            # pinned anchor and every later page's previous last header —
            # so a broken seam, a height jump or a fork surfaces as
            # integrity here.
            page_anchor, tip, page_hashes = _verify_header_page(
                document, expected_anchor, tip_hash, trust
            )
            if first_anchor is None:
                first_anchor = page_anchor
            if shared_tip is None:
                shared_tip = tip
            elif tip != shared_tip:
                # Every page must carry the same chain descriptor, not
                # merely the same tip hash.
                raise _Failure(ERR_INTEGRITY)
            last = position == pages - 1
            if not page_hashes:
                # An empty page (already pinned to the tip by the per-page
                # rules) can only close the batch; a non-final empty page
                # is a pagination defect and leaves no anchor to chain
                # from.
                if not last:
                    raise _Failure(ERR_INTEGRITY)
            else:
                last_header = document["headers"][-1]
                if last:
                    # The final page must reach the pinned tip.
                    if page_hashes[-1] != tip["tip_hash"]:
                        raise _Failure(ERR_INTEGRITY)
                elif last_header["status"] != STATUS_CONFIRMED:
                    # A pending header may only be the batch's very last
                    # header: no page may follow it.
                    raise _Failure(ERR_INTEGRITY)
                expected_anchor = {
                    "height": last_header["height"],
                    "block_hash": page_hashes[-1],
                }
            verified_hashes.extend(page_hashes)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather
        # than crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {
        "ok": True,
        "anchor": first_anchor,
        "tip": shared_tip,
        "pages": pages,
        "verified_block_hashes": verified_hashes,
    }


# Fixed success key order returned by :func:`verify_header_locator_page`.
HEADER_LOCATOR_RESULT_KEYS = (
    "ok",
    "anchor",
    "tip",
    "matched_index",
    "verified_block_hashes",
)


def _validate_header_locators(raw: object) -> list[dict]:
    """Structural validation of a fork-location ``locators`` list.

    The list must hold 1-64 closed ``{height, block_hash}`` items (exact key
    order ``height, block_hash``); heights are non-boolean non-negative
    integers in strictly descending order (which also makes them unique) and
    hashes are 64 lowercase hexadecimal characters. Returns fresh closed item
    documents. Every defect is an input error.
    """
    if not isinstance(raw, list) or not (1 <= len(raw) <= 64):
        raise _Failure(ERR_INPUT)
    locators: list[dict] = []
    previous_height: int | None = None
    for item in raw:
        if not isinstance(item, dict) or tuple(item.keys()) != HEADER_ANCHOR_KEYS:
            raise _Failure(ERR_INPUT)
        height = item["height"]
        block_hash = item["block_hash"]
        if not _is_int(height) or height < 0:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(block_hash):
            raise _Failure(ERR_INPUT)
        if previous_height is not None and height >= previous_height:
            raise _Failure(ERR_INPUT)
        previous_height = height
        locators.append({"height": height, "block_hash": block_hash})
    return locators


def verify_header_locator_page(
    document: object,
    locators: object,
    tip_hash: object,
    trust: object,
) -> dict:
    """Offline-verify one signed ``POST /v1/chain/headers/locate`` page.

    ``document`` is the decoded response — the same fixed-order signed page as
    :func:`verify_header_page` (``anchor, headers, tip, auth``) — and
    ``locators`` is the original request list the client sent (1-64
    ``{height, block_hash}`` items, heights non-boolean non-negative integers
    strictly descending and unique, hashes 64 lowercase hex). ``tip_hash`` is
    the caller-pinned chain tip the descriptor must name; ``trust`` must
    carry ``audit_signers`` exactly as for :func:`verify_header_page`.

    Rather than one caller-pinned anchor, the page's own ``anchor`` must
    appear in ``locators``: its index there (starting at 0) is returned as
    ``matched_index``. Every other rule — envelope key version lookup and the
    Ed25519 domain signature, recomputed header hashes and prev_hash links,
    consecutive heights, pending only at the chain tail, the tip descriptor —
    is the :func:`verify_header_page` rule.

    Returns ``{"ok": True, "anchor", "tip", "matched_index",
    "verified_block_hashes"}`` on success or ``{"ok": False, "error":
    "input"|"auth"|"integrity"}`` on failure: bad parameters or list
    shape/key order/types are ``input``; an unknown key version or a failed
    signature is ``auth``; an anchor absent from the locator list (including
    a duplicate-free mismatch), a broken header chain or a tip mismatch is
    ``integrity``. Never raises for malformed input.
    """
    try:
        # List/parameter shape is input and is settled before the document is
        # authenticated, mirroring verify_header_page's input-before-auth
        # ordering.
        closed_locators = _validate_header_locators(locators)
        # The page pins itself: _verify_header_page still strictly validates
        # the anchor document and every other field, while the real anchor
        # binding is the locator-membership check below.
        if not isinstance(document, dict) or "anchor" not in document:
            raise _Failure(ERR_INPUT)
        page_anchor, closed_tip, verified_hashes = _verify_header_page(
            document, document["anchor"], tip_hash, trust
        )
        matched_index: int | None = None
        for index, locator in enumerate(closed_locators):
            if locator == page_anchor:
                matched_index = index
                break
        if matched_index is None:
            # The signed page anchors at a block the client never offered as
            # a known chain point.
            raise _Failure(ERR_INTEGRITY)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather than
        # crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {
        "ok": True,
        "anchor": page_anchor,
        "tip": closed_tip,
        "matched_index": matched_index,
        "verified_block_hashes": verified_hashes,
    }


# Fixed success key order returned by :func:`verify_header_locator_pages`.
HEADER_LOCATOR_PAGES_RESULT_KEYS = (
    "ok",
    "anchor",
    "tip",
    "matched_index",
    "pages",
    "verified_block_hashes",
)


def verify_header_locator_pages(
    documents: object,
    locators: object,
    tip_hash: object,
    trust: object,
) -> dict:
    """Verify an ordered batch of signed locator pages as one chain.

    ``documents`` must be a non-empty list of decoded
    ``POST /v1/chain/headers/locate`` pages (each with the exact key order
    ``anchor, headers, tip, auth``); ``locators`` is the original request
    list (1-64 ``{height, block_hash}`` items, heights non-boolean
    non-negative integers strictly descending, hashes 64 lowercase hex);
    ``tip_hash`` is the caller-pinned chain tip every page's descriptor must
    name; ``trust`` must carry ``audit_signers`` exactly as for
    :func:`verify_header_page`.

    Verification is staged across the whole batch: the parameters and every
    page's key order, raw types and hex are checked first (``input``); then
    every page's envelope is verified under the ``ledger-headers-v1`` domain
    against ``trust.audit_signers`` (an unknown key version or a failed
    signature is ``auth``); finally the batch is chained (``integrity``) —
    the first page's anchor must be one of the ``locators`` (its position,
    starting at 0, is returned as ``matched_index``), every later page's
    anchor must equal the previous page's last header's
    ``{height, block_hash}`` so heights and prev_hash links continue across
    the seams and a missing, duplicated or reordered page breaks the chain,
    every page's ``tip`` descriptor must be field-for-field identical, and
    the last page must reach the pinned tip. A non-final page's headers may
    never be empty — an empty first page is valid only as the batch's single
    page with its anchor being the tip — and a pending header may only be
    the very last header of the whole batch.

    Returns ``{"ok": True, "anchor", "tip", "matched_index", "pages",
    "verified_block_hashes"}`` on success — ``anchor`` the first page's
    matched anchor, ``tip`` the shared chain descriptor, ``pages`` the page
    count and ``verified_block_hashes`` every verified header hash in chain
    order (the anchor itself is not a header and is not included) — or
    ``{"ok": False, "error": category}`` on failure with category one of
    ``input``, ``auth`` and ``integrity``. Never raises for malformed input.
    """
    try:
        # Stage 1 (input): the parameters and every page's exact key order,
        # raw types and hex are all settled before any signature work.
        if not isinstance(documents, list) or not documents:
            raise _Failure(ERR_INPUT)
        closed_locators = _validate_header_locators(locators)
        if not isinstance(tip_hash, str) or not crypto.is_hex64(tip_hash):
            raise _Failure(ERR_INPUT)
        signers = _validate_header_trust(trust)
        parsed = [_parse_header_page(document) for document in documents]

        # Stage 2 (auth): every page's envelope must resolve a signer version
        # and verify under the ledger-headers-v1 domain signature.
        for document, (_, _, _, key_version, signature) in zip(documents, parsed):
            _authenticate_header_page(document, key_version, signature, signers)

        # Stage 3 (integrity): the first page anchors at one of the locators,
        # every later page anchors at the previous page's last header, every
        # page names the same caller-pinned tip and the batch reaches it.
        pages = len(parsed)
        matched_index: int | None = None
        first_anchor: dict | None = None
        shared_tip: dict | None = None
        verified_hashes: list[str] = []
        expected_anchor: dict | None = None
        for position, (page_anchor, headers, tip, _, _) in enumerate(parsed):
            if position == 0:
                for index, locator in enumerate(closed_locators):
                    if locator == page_anchor:
                        matched_index = index
                        break
                if matched_index is None:
                    # The batch anchors at a block the client never offered
                    # as a known chain point.
                    raise _Failure(ERR_INTEGRITY)
                first_anchor = page_anchor
            elif page_anchor != expected_anchor:
                # A missing, duplicated or reordered page breaks the seam.
                raise _Failure(ERR_INTEGRITY)
            page_hashes = _check_header_page_chain(page_anchor, headers, tip, tip_hash)
            if shared_tip is None:
                shared_tip = tip
            elif tip != shared_tip:
                # Every page must carry the same chain descriptor, not
                # merely the same tip hash.
                raise _Failure(ERR_INTEGRITY)
            last = position == pages - 1
            if not page_hashes:
                # An empty page (already pinned to the tip by the per-page
                # rules) can only close the batch; a non-final empty page is
                # a pagination defect and leaves no anchor to chain from.
                if not last:
                    raise _Failure(ERR_INTEGRITY)
            else:
                if last:
                    # The final page must reach the pinned tip.
                    if page_hashes[-1] != tip["tip_hash"]:
                        raise _Failure(ERR_INTEGRITY)
                elif headers[-1]["status"] != STATUS_CONFIRMED:
                    # A pending header may only be the batch's very last
                    # header: no page may follow it.
                    raise _Failure(ERR_INTEGRITY)
                expected_anchor = {
                    "height": headers[-1]["height"],
                    "block_hash": page_hashes[-1],
                }
            verified_hashes.extend(page_hashes)
    except _Failure as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs must report rather
        # than crash the verifying process.
        return {"ok": False, "error": ERR_INPUT}
    return {
        "ok": True,
        "anchor": first_anchor,
        "tip": shared_tip,
        "matched_index": matched_index,
        "pages": pages,
        "verified_block_hashes": verified_hashes,
    }


# -- durable header-page checkpoint ---------------------------------------------

# The exact top-level key order of one persisted advance_headers checkpoint.
HEADER_CHECKPOINT_KEYS = ("v", "generation", "anchor", "tip", "steps", "hash")

# The exact key order of one stored v2 step, and of a legacy v1 step (a v1
# step carries no kind/locators and is read as a linear step).
HEADER_STEP_KEYS = ("kind", "tip_hash", "trust", "documents", "locators")
HEADER_STEP_KEYS_V1 = ("tip_hash", "trust", "documents")

# The step kinds: a ``linear`` step continues the chain from the stored tip
# (its ``locators`` is null); a ``locator`` step re-anchors the chain at a
# matched locator after a reorg.
HEADER_STEP_KIND_LINEAR = "linear"
HEADER_STEP_KIND_LOCATOR = "locator"
HEADER_STEP_KINDS = (HEADER_STEP_KIND_LINEAR, HEADER_STEP_KIND_LOCATOR)

# The header checkpoint format version written today. Version-1 checkpoints
# (three-key steps, all linear) are still loaded and replayed.
HEADER_CHECKPOINT_VERSION = 2
HEADER_CHECKPOINT_VERSION_V1 = 1
HEADER_CHECKPOINT_VERSIONS = (HEADER_CHECKPOINT_VERSION_V1, HEADER_CHECKPOINT_VERSION)

# Fixed success key order returned by :func:`advance_headers`.
ADVANCE_HEADERS_RESULT_KEYS = ("ok", "generation", "tip")

# Fixed success key order returned by :func:`reorg_headers`.
REORG_HEADERS_RESULT_KEYS = ("ok", "generation", "tip", "replaced")


def _header_checkpoint_hash(
    v: int, generation: int, anchor: dict, tip: dict, steps: list
) -> str:
    """SHA-256 over the canonical JSON bytes of every field but ``hash``.

    ``steps`` are the normalized five-key steps; a v1 document's hash body
    carries their legacy three-key projection (no ``kind``/``locators``), so
    a v1 file's recorded digest still recomputes exactly.
    """
    if v == HEADER_CHECKPOINT_VERSION_V1:
        steps = [
            {
                "tip_hash": step["tip_hash"],
                "trust": step["trust"],
                "documents": step["documents"],
            }
            for step in steps
        ]
    body = {
        "v": v,
        "generation": generation,
        "anchor": anchor,
        "tip": tip,
        "steps": steps,
    }
    return hashlib.sha256(_canonical_json_bytes(body)).hexdigest()


def _header_tip_advances(stored: dict, new: dict) -> bool:
    """Whether ``new`` is a legal successor tip of ``stored``.

    The tip may never drop in height; at the same height only the same
    ``block_hash`` moving from ``pending`` to ``confirmed`` is accepted.
    """
    if new["height"] != stored["height"]:
        return new["height"] > stored["height"]
    return (
        new["tip_hash"] == stored["tip_hash"]
        and stored["status"] == STATUS_PENDING
        and new["status"] == STATUS_CONFIRMED
    )


def _header_tip_reorg_allowed(stored: dict, new: dict) -> bool:
    """Whether ``new`` is a legal reorg successor of the stored tip.

    The tip may never drop in height; at the same height a different
    ``block_hash`` is accepted in either status (that is the reorg), while
    the same ``block_hash`` may only move from ``pending`` to ``confirmed``.
    """
    if new["height"] != stored["height"]:
        return new["height"] > stored["height"]
    if new["tip_hash"] != stored["tip_hash"]:
        return True
    return stored["status"] == STATUS_PENDING and new["status"] == STATUS_CONFIRMED


def _validate_header_checkpoint_shape(data: object) -> dict:
    """Validate the exact key order and JSON types of one checkpoint document.

    Both checkpoint versions are accepted; every step is normalized to the
    five-key v2 form (a v1 three-key step becomes a ``linear`` step with
    ``locators`` null) so every later stage handles one step shape.
    """
    if not isinstance(data, dict) or tuple(data.keys()) != HEADER_CHECKPOINT_KEYS:
        raise _CheckpointError(ERR_STATE)
    v = data["v"]
    generation = data["generation"]
    anchor = data["anchor"]
    tip = data["tip"]
    steps = data["steps"]
    digest = data["hash"]

    if not _is_int(v) or v not in HEADER_CHECKPOINT_VERSIONS:
        raise _CheckpointError(ERR_STATE)
    if not _is_int(generation) or generation < 1:
        raise _CheckpointError(ERR_STATE)
    if not isinstance(anchor, dict) or tuple(anchor.keys()) != HEADER_ANCHOR_KEYS:
        raise _CheckpointError(ERR_STATE)
    if not _is_int(anchor["height"]) or anchor["height"] < 0:
        raise _CheckpointError(ERR_STATE)
    if not crypto.is_hex64(anchor["block_hash"]):
        raise _CheckpointError(ERR_STATE)
    if not isinstance(tip, dict) or tuple(tip.keys()) != HEADER_TIP_KEYS:
        raise _CheckpointError(ERR_STATE)
    if not crypto.is_hex64(tip["tip_hash"]):
        raise _CheckpointError(ERR_STATE)
    if not _is_int(tip["height"]) or tip["height"] < 0:
        raise _CheckpointError(ERR_STATE)
    if not _is_int(tip["length"]) or tip["length"] < 1:
        raise _CheckpointError(ERR_STATE)
    if tip["status"] not in (STATUS_PENDING, STATUS_CONFIRMED):
        raise _CheckpointError(ERR_STATE)
    if not isinstance(steps, list) or not steps:
        raise _CheckpointError(ERR_STATE)
    validated_steps = []
    for raw in steps:
        if v == HEADER_CHECKPOINT_VERSION_V1:
            if not isinstance(raw, dict) or tuple(raw.keys()) != HEADER_STEP_KEYS_V1:
                raise _CheckpointError(ERR_STATE)
            kind = HEADER_STEP_KIND_LINEAR
            locators = None
        else:
            if not isinstance(raw, dict) or tuple(raw.keys()) != HEADER_STEP_KEYS:
                raise _CheckpointError(ERR_STATE)
            kind = raw["kind"]
            if kind not in HEADER_STEP_KINDS:
                raise _CheckpointError(ERR_STATE)
            locators = raw["locators"]
            if kind == HEADER_STEP_KIND_LINEAR:
                if locators is not None:
                    raise _CheckpointError(ERR_STATE)
            elif not isinstance(locators, list):
                raise _CheckpointError(ERR_STATE)
        if not crypto.is_hex64(raw["tip_hash"]):
            raise _CheckpointError(ERR_STATE)
        if not isinstance(raw["trust"], dict):
            raise _CheckpointError(ERR_STATE)
        if not isinstance(raw["documents"], list) or not raw["documents"]:
            raise _CheckpointError(ERR_STATE)
        validated_steps.append(
            {
                "kind": kind,
                "tip_hash": raw["tip_hash"],
                "trust": raw["trust"],
                "documents": raw["documents"],
                "locators": locators,
            }
        )
    if not crypto.is_hex64(digest):
        raise _CheckpointError(ERR_STATE)

    return {
        "v": v,
        "generation": generation,
        "anchor": {key: anchor[key] for key in HEADER_ANCHOR_KEYS},
        "tip": {key: tip[key] for key in HEADER_TIP_KEYS},
        "steps": validated_steps,
        "hash": digest,
    }


def _replay_header_checkpoint(checkpoint: dict) -> list[dict]:
    """Re-verify one shape-validated header checkpoint document.

    The recorded ``hash`` pins the document before any replay: a tampered
    version, generation, anchor, tip or step is state corruption, not
    re-verified. Every stored step is then replayed against its own recorded
    pins — a ``linear`` step through :func:`verify_header_pages` from the
    previous chain point with the same tip-monotonicity rule as a live
    advance, a ``locator`` step through :func:`verify_header_locator_pages`
    with its matched anchor naming exactly the previous chain point (a
    locator step is always appended right at its reorg boundary) — and the
    final replayed tip must equal the stored one. Returns the verified
    per-step tip descriptors in step order.
    """
    recomputed = _header_checkpoint_hash(
        checkpoint["v"],
        checkpoint["generation"],
        checkpoint["anchor"],
        checkpoint["tip"],
        checkpoint["steps"],
    )
    if recomputed != checkpoint["hash"]:
        raise _CheckpointError(ERR_STATE)

    steps = checkpoint["steps"]
    if checkpoint["v"] == HEADER_CHECKPOINT_VERSION_V1:
        # A v1 generation counts exactly the recorded steps: one per advance.
        if checkpoint["generation"] != len(steps):
            raise _CheckpointError(ERR_STATE)
    elif checkpoint["generation"] < len(steps):
        # A v2 generation increments once per successful operation while a
        # reorg may also drop steps, so it never trails the step count.
        raise _CheckpointError(ERR_STATE)

    expected_anchor = checkpoint["anchor"]
    tip: dict | None = None
    step_tips: list[dict] = []
    for step in steps:
        if step["kind"] == HEADER_STEP_KIND_LOCATOR:
            result = verify_header_locator_pages(
                step["documents"],
                step["locators"],
                step["tip_hash"],
                step["trust"],
            )
            if not result.get("ok"):
                raise _CheckpointError(ERR_STATE)
            if result["anchor"] != expected_anchor:
                # A locator step re-anchors exactly at the previous chain
                # point: anything else never was a legal reorg boundary.
                raise _CheckpointError(ERR_STATE)
        else:
            result = verify_header_pages(
                step["documents"], expected_anchor, step["tip_hash"], step["trust"]
            )
            if not result.get("ok"):
                raise _CheckpointError(ERR_STATE)
            if tip is not None and not _header_tip_advances(tip, result["tip"]):
                raise _CheckpointError(ERR_STATE)
        tip = result["tip"]
        step_tips.append(tip)
        expected_anchor = {
            "height": tip["height"],
            "block_hash": tip["tip_hash"],
        }
    assert tip is not None  # steps is shape-guaranteed non-empty
    if tip != checkpoint["tip"]:
        raise _CheckpointError(ERR_STATE)
    return step_tips


def _load_header_checkpoint_document(path: str) -> tuple[dict, list[dict]] | None:
    """Strictly load and re-verify a checkpoint, returning it and its step tips.

    Returns None when no file exists at ``path``. Otherwise validates the
    exact key order and JSON types, recomputes ``hash`` over the other
    fields, and replays every stored step. Any defect is a ``state`` failure
    (unreadable JSON is ``state`` too, an unreadable file ``io``); the file
    is never truncated or rebuilt.
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
    checkpoint = _validate_header_checkpoint_shape(data)
    step_tips = _replay_header_checkpoint(checkpoint)
    return checkpoint, step_tips


def _load_header_checkpoint(path: str) -> dict | None:
    """Strictly load and re-verify an existing advance_headers checkpoint.

    Returns None when no file exists at ``path``; otherwise returns the
    validated checkpoint document under the same rules (and failure
    categories) as :func:`_load_header_checkpoint_document`.
    """
    loaded = _load_header_checkpoint_document(path)
    if loaded is None:
        return None
    checkpoint, _step_tips = loaded
    return checkpoint


def _atomic_write_header_checkpoint(path: str, checkpoint: dict) -> None:
    """Write the checkpoint in declared key order and atomically replace ``path``."""
    ordered = {key: checkpoint[key] for key in HEADER_CHECKPOINT_KEYS}
    _atomic_write_bytes(path, _serialize_document(ordered))


def advance_headers(
    path: object,
    documents: object,
    anchor: object,
    tip_hash: object,
    trust: object,
) -> dict:
    """Verify a signed header-page batch and durably checkpoint it at ``path``.

    ``documents`` is an ordered, non-empty batch of ``GET /v1/chain/headers``
    pages verified with :func:`verify_header_pages` against ``trust`` and the
    caller-pinned ``tip_hash``. The first use of ``path`` requires a legal
    ``anchor`` (``{height, block_hash}``, key order ``height, block_hash``);
    a later advance passes ``None`` (continue from the stored tip) or the
    stored tip's ``{height, block_hash}``.

    The new tip may never drop in height; at the same height only the same
    ``block_hash`` moving from ``pending`` to ``confirmed`` is accepted —
    anything else is an ``integrity`` failure. Re-submitting the exact last
    batch (same ``tip_hash``, ``trust`` and ``documents``) is idempotent: it
    returns success with the current generation and neither bumps the
    generation nor touches the file.

    On success the checkpoint is written atomically (a uniquely named temp
    file in the same directory, fsynced and ``os.replace``d under the
    per-path lock shared with every other same-path operation) with key
    order ``v, generation, anchor, tip, steps, hash`` — ``v`` is 2 and the
    batch is appended as one ``{kind: "linear", tip_hash, trust, documents,
    locators: null}`` step (version-1 checkpoints with three-key steps are
    still read and replayed; the next successful write upgrades the file).
    Generation starts at 1 and increments once per successful advance, so a
    failed verification never bumps it. The return value is ``{"ok": True,
    "generation", "tip"}`` in that key order.

    Every failure is ``{"ok": False, "error": category}`` with category one
    of ``input`` (bad arguments, a malformed first anchor or an illegal
    ``tip_hash``), ``auth``/``integrity`` (batch verification and tip
    conflicts), ``state`` (an existing checkpoint fails its key-order,
    type, hash or replay checks; it is never truncated or rebuilt) and
    ``io`` (the checkpoint cannot be read or written; a failed write
    restores the original bytes best-effort). Nothing is raised.
    """
    # Argument shape is validated before any file or verification work.
    if not isinstance(path, str) or not path:
        return _failed_advance(ERR_INPUT)
    if not isinstance(tip_hash, str) or not crypto.is_hex64(tip_hash):
        return _failed_advance(ERR_INPUT)

    lock = _checkpoint_lock(path)
    with lock:
        try:
            previous = _load_header_checkpoint(path)
        except _CheckpointError as failure:
            return _failed_advance(failure.category)

        if previous is None:
            # First use: the caller must pin a legal anchor.
            expected_anchor = _validate_header_anchor_argument(anchor)
            if expected_anchor is None:
                return _failed_advance(ERR_INPUT)
            generation = 0
            file_anchor = expected_anchor
            steps: list[dict] = []
            stored_tip: dict | None = None
        else:
            generation = previous["generation"]
            file_anchor = previous["anchor"]
            steps = list(previous["steps"])
            stored_tip = previous["tip"]
            if anchor is None:
                # Continue the continuous chain from the stored closed tip.
                expected_anchor = {
                    "height": stored_tip["height"],
                    "block_hash": stored_tip["tip_hash"],
                }
            else:
                expected_anchor = _validate_header_anchor_argument(anchor)
                if (
                    expected_anchor is None
                    or expected_anchor
                    != {
                        "height": stored_tip["height"],
                        "block_hash": stored_tip["tip_hash"],
                    }
                ):
                    return _failed_advance(ERR_INPUT)

        step = {
            "kind": HEADER_STEP_KIND_LINEAR,
            "tip_hash": tip_hash,
            "trust": trust,
            "documents": documents,
            "locators": None,
        }
        if steps and step == steps[-1]:
            # Re-submitting the exact last batch (same tip_hash, trust and
            # documents) is idempotent: it was verified when it was stored
            # and re-verified by the load replay above, so the file bytes
            # stay exactly as they were and the generation holds.
            return {
                "ok": True,
                "generation": generation,
                "tip": stored_tip,
            }

        try:
            result = verify_header_pages(documents, expected_anchor, tip_hash, trust)
            if not result.get("ok"):
                return {"ok": False, "error": result["error"]}

            new_tip = result["tip"]
            if stored_tip is not None and not _header_tip_advances(
                stored_tip, new_tip
            ):
                return _failed_advance(ERR_INTEGRITY)

            next_generation = generation + 1
            steps = steps + [step]
            checkpoint = {
                "v": HEADER_CHECKPOINT_VERSION,
                "generation": next_generation,
                "anchor": file_anchor,
                "tip": new_tip,
                "steps": steps,
            }
            checkpoint["hash"] = _header_checkpoint_hash(
                HEADER_CHECKPOINT_VERSION,
                next_generation,
                file_anchor,
                new_tip,
                steps,
            )

            try:
                original = _read_bytes_or_none(path)
            except OSError:
                return _failed_advance(ERR_IO)
            try:
                _atomic_write_header_checkpoint(path, checkpoint)
            except OSError:
                # Compensate: put the original bytes back best-effort.
                _restore_bytes(path, original)
                return _failed_advance(ERR_IO)
            except (TypeError, ValueError):
                # A trust/document value JSON cannot serialize (verification
                # only judges the fields it pins) is a caller-side defect.
                return _failed_advance(ERR_INPUT)
        except _Failure as failure:  # defensive: verifiers never raise these
            return _failed_advance(failure.category)
        except Exception:
            # Defensive: structurally unforeseeable inputs must report rather
            # than crash the caller.
            return _failed_advance(ERR_INPUT)

        return {
            "ok": True,
            "generation": next_generation,
            "tip": new_tip,
        }


def _validate_header_anchor_argument(raw: object) -> dict | None:
    """Validate an advance_headers anchor as ``{height, block_hash}``.

    Mirrors the header verifier's raw-value rules (exact key order
    ``height, block_hash``, booleans rejected); returns a fresh closed
    document or None on any shape/type defect.
    """
    if not isinstance(raw, dict) or tuple(raw.keys()) != HEADER_ANCHOR_KEYS:
        return None
    height = raw["height"]
    if not _is_int(height) or height < 0:
        return None
    if not crypto.is_hex64(raw["block_hash"]):
        return None
    return {"height": height, "block_hash": raw["block_hash"]}


def reorg_headers(
    path: object,
    documents: object,
    locators: object,
    tip_hash: object,
    trust: object,
) -> dict:
    """Verify a signed locator-page batch and re-anchor the checkpoint.

    ``documents`` is an ordered, non-empty batch of
    ``POST /v1/chain/headers/locate`` pages verified with
    :func:`verify_header_locator_pages` against the caller's ``locators``
    and the pinned ``tip_hash`` under ``trust``. The checkpoint at ``path``
    must already exist (a missing file is an ``io`` failure): the batch's
    matched anchor selects the reorg boundary — the last stored step whose
    closing tip is that anchor, or the checkpoint's initial anchor when no
    step matches; an anchor naming neither is an ``integrity`` failure.
    Every step after the boundary is dropped (the dropped count is returned
    as ``replaced``) and one ``{kind: "locator", tip_hash, trust, documents,
    locators}`` step is appended.

    The new tip may never drop below the stored tip's height; at the same
    height a different ``block_hash`` is accepted in either status, while
    the same ``block_hash`` may only move from ``pending`` to ``confirmed``
    — anything else is an ``integrity`` failure. Re-submitting a last step
    fully identical to the new locator step is idempotent: it returns the
    current generation with ``replaced`` 0 and neither bumps the generation
    nor touches the file. Every other success increments the generation by
    one and atomically rewrites the checkpoint (v2 key orders, same hash and
    serialization rules as :func:`advance_headers`) under the shared
    per-path lock; a failed write restores the original bytes best-effort
    and any failure leaves the file's bytes and the generation untouched.

    Success returns ``{"ok": True, "generation", "tip", "replaced"}`` in
    that key order; failure returns only ``{"ok": False, "error":
    category}`` with category one of ``input`` (bad arguments or batch
    structure), ``auth`` (signer lookup or signature), ``integrity``
    (boundary, chain, height or same-height conflicts), ``state`` (an
    existing checkpoint fails its key-order, type, hash or replay checks)
    and ``io`` (the checkpoint is missing or cannot be read or written).
    Nothing is raised.
    """
    # Argument shape is validated before any file or verification work.
    if not isinstance(path, str) or not path:
        return _failed_advance(ERR_INPUT)
    if not isinstance(tip_hash, str) or not crypto.is_hex64(tip_hash):
        return _failed_advance(ERR_INPUT)

    lock = _checkpoint_lock(path)
    with lock:
        try:
            loaded = _load_header_checkpoint_document(path)
        except _CheckpointError as failure:
            return _failed_advance(failure.category)
        if loaded is None:
            # A reorg rewrites an existing checkpoint; a path that has never
            # been advanced has no anchor to re-anchor at.
            return _failed_advance(ERR_IO)
        previous, step_tips = loaded

        generation = previous["generation"]
        stored_tip = previous["tip"]
        steps = list(previous["steps"])
        step = {
            "kind": HEADER_STEP_KIND_LOCATOR,
            "tip_hash": tip_hash,
            "trust": trust,
            "documents": documents,
            "locators": locators,
        }
        if step == steps[-1]:
            # Re-submitting a last step fully identical to the new locator
            # step is idempotent: it was verified when it was stored and
            # re-verified by the load replay above, so the file bytes stay
            # exactly as they were and the generation holds.
            return {
                "ok": True,
                "generation": generation,
                "tip": stored_tip,
                "replaced": 0,
            }

        try:
            result = verify_header_locator_pages(
                documents, locators, tip_hash, trust
            )
            if not result.get("ok"):
                return {"ok": False, "error": result["error"]}

            anchor = result["anchor"]
            new_tip = result["tip"]

            # The reorg boundary is the last step whose closing tip is the
            # matched anchor; only when no step matches does the initial
            # anchor bound the reorg.
            boundary: int | None = None
            for index, step_tip in enumerate(step_tips):
                if (
                    step_tip["height"] == anchor["height"]
                    and step_tip["tip_hash"] == anchor["block_hash"]
                ):
                    boundary = index
            if boundary is None:
                if anchor != previous["anchor"]:
                    return _failed_advance(ERR_INTEGRITY)
                kept_steps: list[dict] = []
            else:
                kept_steps = steps[: boundary + 1]
            replaced = len(steps) - len(kept_steps)

            # The checkpoint tip never drops in height; at the same height a
            # reorg may switch to a different block hash in either status,
            # while the same hash may only move pending -> confirmed.
            if not _header_tip_reorg_allowed(stored_tip, new_tip):
                return _failed_advance(ERR_INTEGRITY)

            next_generation = generation + 1
            new_steps = kept_steps + [step]
            checkpoint = {
                "v": HEADER_CHECKPOINT_VERSION,
                "generation": next_generation,
                "anchor": previous["anchor"],
                "tip": new_tip,
                "steps": new_steps,
            }
            checkpoint["hash"] = _header_checkpoint_hash(
                HEADER_CHECKPOINT_VERSION,
                next_generation,
                previous["anchor"],
                new_tip,
                new_steps,
            )

            try:
                original = _read_bytes_or_none(path)
            except OSError:
                return _failed_advance(ERR_IO)
            try:
                _atomic_write_header_checkpoint(path, checkpoint)
            except OSError:
                # Compensate: put the original bytes back best-effort.
                _restore_bytes(path, original)
                return _failed_advance(ERR_IO)
            except (TypeError, ValueError):
                # A trust/document value JSON cannot serialize (verification
                # only judges the fields it pins) is a caller-side defect.
                return _failed_advance(ERR_INPUT)
        except _Failure as failure:  # defensive: verifiers never raise these
            return _failed_advance(failure.category)
        except Exception:
            # Defensive: structurally unforeseeable inputs must report rather
            # than crash the caller.
            return _failed_advance(ERR_INPUT)

        return {
            "ok": True,
            "generation": next_generation,
            "tip": new_tip,
            "replaced": replaced,
        }


# -- fork-location locator request --------------------------------------------

# Default and maximum ``limit`` carried by a generated locator request.
HEADER_LOCATORS_DEFAULT_LIMIT = 100
HEADER_LOCATORS_MAX_LIMIT = 500

# A locator request never carries more than this many locators.
HEADER_LOCATORS_MAX_ITEMS = 64

# How many consecutive newest checkpoint points open the locator list before
# the exponentially widening walk-back begins.
HEADER_LOCATORS_TIP_RUN = 10


def _header_locator_indices(count: int) -> list[int]:
    """Pick the checkpoint-sequence indices a locator request probes.

    The walk starts at the newest point and takes up to
    ``HEADER_LOCATORS_TIP_RUN`` consecutive descending indices, then steps
    back from the last taken index by 2, 4, 8, ... (doubling each time);
    running past the start pins index 0 and ends the walk. At most
    ``HEADER_LOCATORS_MAX_ITEMS`` indices are returned and the last one is
    always 0 — when the 64th pick still is not 0, it is replaced by 0.
    """
    indices: list[int] = []
    index = count - 1
    while index >= 0 and len(indices) < HEADER_LOCATORS_TIP_RUN:
        indices.append(index)
        index -= 1
    step = 2
    while (
        indices
        and indices[-1] != 0
        and len(indices) < HEADER_LOCATORS_MAX_ITEMS
    ):
        nxt = indices[-1] - step
        if nxt < 0:
            nxt = 0
        indices.append(nxt)
        step *= 2
    if (
        len(indices) == HEADER_LOCATORS_MAX_ITEMS
        and indices[-1] != 0
    ):
        indices[-1] = 0
    return indices


def header_locators(path: object, limit: object = HEADER_LOCATORS_DEFAULT_LIMIT) -> dict:
    """Build a fork-location locator request from an advance_headers checkpoint.

    The checkpoint at ``path`` is strictly reloaded exactly as
    :func:`advance_headers` reloads it (key order, types, digest, generation
    versus step count and a per-batch replay) — the file is only read, never
    written. The replayed history yields the sequence B: the checkpoint's
    initial anchor followed by every step's closing tip, ascending, with
    adjacent equal ``(height, block_hash)`` pairs collapsed. The request's
    locators walk B newest-first: up to ten consecutive tail items, then
    back-steps of 2, 4, 8, ... pinning B[0] at the end (at most 64 items; a
    64th item that is not B[0] is replaced by it), so the locators come out
    in strictly descending height order.

    ``limit`` must be a plain (non-boolean) integer in 1..500 (default 100);
    it is carried into the request verbatim. Success returns ``{"ok": True,
    "tip", "request"}`` in that key order with ``tip`` the checkpoint's
    stored chain descriptor S and ``request`` the closed ``{"locators",
    "limit"}`` document (locator key order ``height, block_hash``) ready to
    POST to ``/v1/chain/headers/locate``. Failure returns only ``{"ok":
    False, "error": category}`` with category one of ``input`` (an empty or
    non-string path, an illegal limit), ``io`` (a missing or unreadable
    file) and ``state`` (any checkpoint shape, digest or replay mismatch);
    nothing is raised.
    """
    if not isinstance(path, str) or not path:
        return _failed_advance(ERR_INPUT)
    if not _is_int(limit) or limit < 1 or limit > HEADER_LOCATORS_MAX_LIMIT:
        return _failed_advance(ERR_INPUT)

    lock = _checkpoint_lock(path)
    with lock:
        try:
            loaded = _load_header_checkpoint_document(path)
        except _CheckpointError as failure:
            return _failed_advance(failure.category)
        except Exception:
            # Defensive: an unreadable-by-surprise checkpoint must report
            # rather than crash the caller.
            return _failed_advance(ERR_STATE)
        if loaded is None:
            return _failed_advance(ERR_IO)
        checkpoint, step_tips = loaded

        # B: the initial anchor and every step's closing tip, ascending,
        # with adjacent equal (height, block_hash) pairs collapsed.
        points = [checkpoint["anchor"]]
        for tip in step_tips:
            point = {"height": tip["height"], "block_hash": tip["tip_hash"]}
            if point != points[-1]:
                points.append(point)

        locators = [
            {
                "height": points[index]["height"],
                "block_hash": points[index]["block_hash"],
            }
            for index in _header_locator_indices(len(points))
        ]
        return {
            "ok": True,
            "tip": checkpoint["tip"],
            "request": {"locators": locators, "limit": limit},
        }
