"""Append-only audit log hash chaining, checkpoints and offline verification.

Every audit event carries two SHA-256 links:

* ``prev_hash``  — the previous event's ``event_hash``; 64 ASCII zeroes for
  the first event;
* ``event_hash`` — ``sha256(prev_hash ASCII || canonical-event UTF-8)`` where
  the canonical event is the event with both hash fields removed, serialized
  as sorted-key compact JSON (``sort_keys=True, separators=(",", ":")``,
  non-ASCII characters emitted as raw UTF-8).

``audit_checkpoint`` is ``{"event_id", "event_hash"}`` pinning the latest
event: a fresh/empty log checks at ``{0, "0"*64}``. Offline verification walks
one or more exported pages, checking each page anchor, the dense event ids and
every link, and requires every page to pin the identical checkpoint with the
final page's last event (or the empty log) matching it.

A page may additionally carry ``checkpoint_auth`` — an Ed25519 signature over
``SHA256(sorted-compact UTF-8 JSON of {genesis_hash, checkpoint,
key_version})``. ``verify_export(document, trust)`` only checks that envelope
when a trust document (``genesis_hash`` plus a version-ascending
``audit_signers`` list) is supplied; authentication failures then use the
``auth`` error category.
"""
from __future__ import annotations

import hashlib
import json

from . import crypto

# Sentinel previous hash of the first audit event (and checkpoint of an empty
# log): 64 ASCII zeroes.
ZERO_HASH = "0" * 64

# Names of the two link fields excluded from the hashed canonical event.
HASH_FIELDS = ("prev_hash", "event_hash")

# Public offline-verification error categories.
ERR_INPUT = "input"
ERR_INTEGRITY = "integrity"
ERR_AUTH = "auth"


class AuditChainError(ValueError):
    """A persisted audit hash chain or checkpoint failed strict validation.

    Carries a human-readable ``reason``; the persistence layer maps it onto a
    ``StateRecoveryError`` tagged with the offending snapshot path.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class _VerifyError(Exception):
    """Internal control-flow exception carrying the public error category."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _is_plain_int(value: object) -> bool:
    """Plain integer test; booleans are rejected (bool subclasses int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_event(event: dict) -> bytes:
    """Sorted-key compact UTF-8 JSON of the event with both hash fields removed.

    This is the exact byte document chained into ``event_hash``; stripping the
    links makes the hash independent of any re-serialization of the stored
    event object.
    """
    stripped = {key: value for key, value in event.items() if key not in HASH_FIELDS}
    return json.dumps(
        stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def event_hash(prev_hash: str, event: dict) -> str:
    """SHA-256 hex of ``prev_hash`` ASCII bytes followed by the canonical event."""
    return hashlib.sha256(prev_hash.encode("ascii") + canonical_event(event)).hexdigest()


def link_events(events: list[dict]) -> list[dict]:
    """Return copies of ``events`` with dense ids and fresh hash links.

    Event ids are renumbered 1..N; the first event gets the all-zero
    ``prev_hash`` and every later event links to its predecessor. Does not
    mutate the input.
    """
    linked: list[dict] = []
    prev_hash = ZERO_HASH
    for index, event in enumerate(events):
        linked_event = dict(event)
        linked_event["event_id"] = index + 1
        linked_event["prev_hash"] = prev_hash
        linked_event["event_hash"] = event_hash(prev_hash, linked_event)
        linked.append(linked_event)
        prev_hash = linked_event["event_hash"]
    return linked


def make_checkpoint(events: list[dict]) -> dict:
    """``{"event_id", "event_hash"}`` pinning the last event (or the zero root)."""
    if events:
        return {
            "event_id": len(events),
            "event_hash": events[-1]["event_hash"],
        }
    return {"event_id": 0, "event_hash": ZERO_HASH}


# Fields of a page's checkpoint authentication envelope.
AUTH_FIELDS = ("key_version", "signature")


def checkpoint_auth_object(
    genesis_hash: str, checkpoint: dict, key_version: int
) -> dict:
    """The exact JSON object covered by a checkpoint authentication signature.

    ``{"genesis_hash", "checkpoint": {"event_id", "event_hash"},
    "key_version"}`` — the genesis anchor pins the deployment, the checkpoint
    pins the audit log head and the key version selects the verifying public
    key.
    """
    return {
        "genesis_hash": genesis_hash,
        "checkpoint": {
            "event_id": checkpoint["event_id"],
            "event_hash": checkpoint["event_hash"],
        },
        "key_version": key_version,
    }


def checkpoint_auth_bytes(auth_object: dict) -> bytes:
    """Sorted-key compact UTF-8 JSON of a checkpoint authentication object."""
    return json.dumps(
        auth_object, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign_checkpoint_auth(
    private_key_hex: str, genesis_hash: str, checkpoint: dict, key_version: int
) -> str:
    """Ed25519-sign SHA-256 of the canonical checkpoint authentication object.

    Returns the 128-hex signature, or None when the private key is malformed.
    """
    auth_object = checkpoint_auth_object(genesis_hash, checkpoint, key_version)
    digest = hashlib.sha256(checkpoint_auth_bytes(auth_object)).digest()
    return crypto.sign_message(private_key_hex, digest)


def verify_checkpoint_auth(
    public_key_hex: str,
    genesis_hash: str,
    checkpoint: dict,
    key_version: int,
    signature_hex: str,
) -> bool:
    """Verify one checkpoint authentication signature. Never raises."""
    auth_object = checkpoint_auth_object(genesis_hash, checkpoint, key_version)
    digest = hashlib.sha256(checkpoint_auth_bytes(auth_object)).digest()
    return crypto.verify_signature(public_key_hex, digest, signature_hex)


def validate_event_chain(events: object) -> None:
    """Strictly validate a persisted event list's dense ids and hash links.

    ``event_id`` values must be exactly 1..N; each ``prev_hash`` must equal the
    previous event's ``event_hash`` (all zeroes for the first event) and every
    ``event_hash`` must recompute from the event with both hash fields removed.
    Raises AuditChainError on the first defect.
    """
    if not isinstance(events, list):
        raise AuditChainError("'audit_events' must be a list")
    prev_hash = ZERO_HASH
    for index, event in enumerate(events):
        event_id = index + 1
        if not isinstance(event, dict):
            raise AuditChainError(f"audit event {event_id} must be an object")
        if not _is_plain_int(event.get("event_id")) or event["event_id"] != event_id:
            raise AuditChainError(
                f"audit event at position {index} has event_id "
                f"{event.get('event_id')!r}, expected {event_id}"
            )
        stored_prev = event.get("prev_hash")
        if not crypto.is_hex64(stored_prev) or stored_prev != prev_hash:
            raise AuditChainError(
                f"audit event {event_id} has a mismatched prev_hash"
            )
        stored_hash = event.get("event_hash")
        if not crypto.is_hex64(stored_hash):
            raise AuditChainError(
                f"audit event {event_id} has an invalid event_hash"
            )
        if event_hash(prev_hash, event) != stored_hash:
            raise AuditChainError(
                f"audit event {event_id} has a mismatched event_hash"
            )
        prev_hash = stored_hash


def validate_checkpoint(checkpoint: object, events: list[dict]) -> None:
    """Validate an ``audit_checkpoint`` against the recovered event list.

    It must be ``{"event_id": N, "event_hash": H}`` with N the (non-negative)
    number of events and H the last event's hash, or the all-zero root when the
    log is empty. Raises AuditChainError on any defect.
    """
    if not isinstance(checkpoint, dict):
        raise AuditChainError("'audit_checkpoint' must be an object")
    event_id = checkpoint.get("event_id")
    event_hash_value = checkpoint.get("event_hash")
    if not _is_plain_int(event_id) or event_id < 0:
        raise AuditChainError("audit_checkpoint.event_id must be a non-negative integer")
    if not crypto.is_hex64(event_hash_value):
        raise AuditChainError("audit_checkpoint.event_hash must be 64 lowercase hex chars")
    expected = make_checkpoint(events)
    if event_id != expected["event_id"]:
        raise AuditChainError(
            f"audit_checkpoint.event_id is {event_id}, log ends at "
            f"{expected['event_id']}"
        )
    if event_hash_value != expected["event_hash"]:
        raise AuditChainError("audit_checkpoint.event_hash does not match the log head")


def verify_export(document: object, trust: object = None) -> dict:
    """Offline-verify one audit export page or an ordered list of pages.

    A page has the server shape
    ``{items, total, next_cursor, anchor_hash, checkpoint}``. Every page
    must pin the identical checkpoint, each page anchor must equal the
    running predecessor hash, item event ids must be dense and consecutive
    across pages, every ``prev_hash``/``event_hash`` pair must recompute,
    pagination counters must be self-consistent and the last page's tail
    must equal that shared checkpoint.

    When ``trust`` is None (the default) no authentication is attempted and
    the behaviour is unchanged. When a trust document is supplied it must
    carry ``genesis_hash`` and a version-ascending ``audit_signers`` list
    (``{version, public_key, activated_event_id}``); every page must then
    carry the same ``checkpoint_auth`` envelope
    (``{key_version, signature}``) binding the same checkpoint, the key
    version must be known and activated at or before the checkpoint, and the
    Ed25519 signature over
    ``SHA256(sorted-compact UTF-8 JSON of {genesis_hash, checkpoint,
    key_version})`` must verify against that version's public key.

    Returns ``{"ok": True, "checkpoint": {...}}`` or
    ``{"ok": False, "error": "input" | "integrity" | "auth"}``. Never raises
    for malformed input.
    """
    try:
        pages = _coerce_pages(document)
        checkpoint = _verify_pages(pages)
        if trust is not None:
            _verify_checkpoint_auth(pages, checkpoint, trust)
    except _VerifyError as failure:
        return {"ok": False, "error": failure.category}
    except Exception:
        # Defensive: structurally unforeseeable inputs report rather than crash.
        return {"ok": False, "error": ERR_INPUT}
    return {"ok": True, "checkpoint": checkpoint}


def _coerce_pages(document: object) -> list[dict]:
    """Normalize a single page object / list of pages, validating basic shape."""
    if isinstance(document, dict):
        pages = [document]
    elif isinstance(document, list) and (
        not document or all(isinstance(page, dict) for page in document)
    ):
        pages = document
    else:
        raise _VerifyError(ERR_INPUT)
    if not pages:
        raise _VerifyError(ERR_INPUT)
    return pages


def _parse_page_shape(page: object) -> dict:
    """Validate a page's structural fields; returns the dict on success."""
    if not isinstance(page, dict):
        raise _VerifyError(ERR_INPUT)
    for field in ("items", "total", "next_cursor", "anchor_hash", "checkpoint"):
        if field not in page:
            raise _VerifyError(ERR_INPUT)
    items = page["items"]
    total = page["total"]
    next_cursor = page["next_cursor"]
    anchor_hash = page["anchor_hash"]
    checkpoint = page["checkpoint"]
    if not isinstance(items, list):
        raise _VerifyError(ERR_INPUT)
    if not _is_plain_int(total) or total < 0:
        raise _VerifyError(ERR_INPUT)
    if next_cursor is not None and (not _is_plain_int(next_cursor) or next_cursor < 0):
        raise _VerifyError(ERR_INPUT)
    if not crypto.is_hex64(anchor_hash):
        raise _VerifyError(ERR_INPUT)
    if not isinstance(checkpoint, dict):
        raise _VerifyError(ERR_INPUT)
    checkpoint_id = checkpoint.get("event_id")
    checkpoint_hash = checkpoint.get("event_hash")
    if not _is_plain_int(checkpoint_id) or checkpoint_id < 0:
        raise _VerifyError(ERR_INPUT)
    if not crypto.is_hex64(checkpoint_hash):
        raise _VerifyError(ERR_INPUT)
    return page


def _verify_pages(pages: list[dict]) -> dict:
    """Walk every page in order; return the shared checkpoint on success."""
    running_id = 0
    running_hash = ZERO_HASH
    first_checkpoint: dict | None = None
    for page in pages:
        page = _parse_page_shape(page)
        items = page["items"]
        total = page["total"]
        next_cursor = page["next_cursor"]
        checkpoint = page["checkpoint"]

        # Every page of one export pins the identical checkpoint; a replaced
        # or regressed checkpoint on any page breaks the export as a whole.
        if first_checkpoint is None:
            first_checkpoint = checkpoint
        elif checkpoint != first_checkpoint:
            raise _VerifyError(ERR_INTEGRITY)
        # The export is unfiltered, so a page's total is the log length its
        # checkpoint was taken over.
        if checkpoint["event_id"] != total:
            raise _VerifyError(ERR_INTEGRITY)
        # This page begins exactly where verification currently stands: the
        # declared anchor is the predecessor hash of its first item (or of the
        # cursor position for an empty page).
        if page["anchor_hash"] != running_hash:
            raise _VerifyError(ERR_INTEGRITY)

        for item in items:
            if not isinstance(item, dict):
                raise _VerifyError(ERR_INPUT)
            event_id = item.get("event_id")
            prev_hash = item.get("prev_hash")
            stored_hash = item.get("event_hash")
            if not _is_plain_int(event_id):
                raise _VerifyError(ERR_INPUT)
            if not crypto.is_hex64(prev_hash) or not crypto.is_hex64(stored_hash):
                raise _VerifyError(ERR_INPUT)
            if event_id != running_id + 1:
                raise _VerifyError(ERR_INTEGRITY)
            if prev_hash != running_hash:
                raise _VerifyError(ERR_INTEGRITY)
            if event_hash(running_hash, item) != stored_hash:
                raise _VerifyError(ERR_INTEGRITY)
            running_id = event_id
            running_hash = stored_hash

        # Pagination self-consistency: a non-null next_cursor continues exactly
        # after this page and stays below total; a server page with limit >= 1
        # is therefore non-empty whenever it is not the last page. A null
        # next_cursor ends exactly at the total.
        if next_cursor is None:
            if running_id != total:
                raise _VerifyError(ERR_INTEGRITY)
        else:
            if not items or next_cursor != running_id or next_cursor >= total:
                raise _VerifyError(ERR_INTEGRITY)

    # The final page must end exactly on the checkpoint every page pinned.
    assert first_checkpoint is not None
    if (
        running_id != first_checkpoint["event_id"]
        or running_hash != first_checkpoint["event_hash"]
    ):
        raise _VerifyError(ERR_INTEGRITY)
    return dict(first_checkpoint)


def _parse_trust_signers(trust: object) -> tuple[str, dict[int, dict]]:
    """Strictly parse a trust document's genesis anchor and audit signers.

    Returns ``(genesis_hash, {version: {public_key, activated_event_id}})``.
    Versions must be dense and ascending starting at 1, the first
    ``activated_event_id`` must be 0 and later activation ids must be strictly
    ascending. Any defect is an input error.
    """
    if not isinstance(trust, dict):
        raise _VerifyError(ERR_INPUT)
    genesis_hash = trust.get("genesis_hash")
    if not crypto.is_hex64(genesis_hash):
        raise _VerifyError(ERR_INPUT)
    raw_signers = trust.get("audit_signers")
    if not isinstance(raw_signers, list) or not raw_signers:
        raise _VerifyError(ERR_INPUT)
    signers: dict[int, dict] = {}
    previous_activated: int | None = None
    for position, entry in enumerate(raw_signers):
        if not isinstance(entry, dict):
            raise _VerifyError(ERR_INPUT)
        version = entry.get("version")
        public_key = entry.get("public_key")
        activated = entry.get("activated_event_id")
        if not _is_plain_int(version) or version != position + 1:
            raise _VerifyError(ERR_INPUT)
        if not crypto.is_hex64(public_key):
            raise _VerifyError(ERR_INPUT)
        if not _is_plain_int(activated) or activated < 0:
            raise _VerifyError(ERR_INPUT)
        if position == 0:
            if activated != 0:
                raise _VerifyError(ERR_INPUT)
        elif activated <= previous_activated:
            # A gap in versions is already rejected above; an activation id
            # that retreats (or stands still) is likewise a malformed list.
            raise _VerifyError(ERR_INPUT)
        previous_activated = activated
        signers[version] = {
            "public_key": public_key,
            "activated_event_id": activated,
        }
    return genesis_hash, signers


def _verify_checkpoint_auth(
    pages: list[dict], checkpoint: dict, trust: object
) -> None:
    """Verify the Ed25519 checkpoint authentication carried by every page.

    Every page must carry the same ``checkpoint_auth`` envelope
    (``{key_version, signature}``) and pin the same checkpoint; the key
    version must identify a signer already activated at or before the
    checkpoint and the signature must verify over
    ``SHA256(sorted-compact UTF-8 JSON of {genesis_hash, checkpoint,
    key_version})`` under the trust document's anchor. Structural defects are
    input errors; missing, unknown-version, cross-page-inconsistent or
    cryptographically invalid authentication is an auth error; a page whose
    checkpoint differs from the verified head is an integrity error.
    """
    genesis_hash, signers = _parse_trust_signers(trust)
    envelopes: list[object] = []
    for page in pages:
        if page.get("checkpoint") != checkpoint:
            # Two pages of one export must pin the same log head.
            raise _VerifyError(ERR_INTEGRITY)
        envelope = page.get("checkpoint_auth")
        if envelope is None:
            raise _VerifyError(ERR_AUTH)
        if not isinstance(envelope, dict):
            raise _VerifyError(ERR_INPUT)
        key_version = envelope.get("key_version")
        signature = envelope.get("signature")
        if not _is_plain_int(key_version) or key_version < 1:
            raise _VerifyError(ERR_INPUT)
        if not isinstance(signature, str) or not crypto.is_hex128(signature):
            raise _VerifyError(ERR_INPUT)
        envelopes.append({"key_version": key_version, "signature": signature})

    first = envelopes[0]
    for envelope in envelopes[1:]:
        if envelope != first:
            raise _VerifyError(ERR_AUTH)

    signer = signers.get(first["key_version"])
    if signer is None:
        raise _VerifyError(ERR_AUTH)
    # A trust document may not describe signer activations that lie beyond the
    # checkpoint head it is meant to authenticate. The *selected* key's own
    # activation beyond the head is reported as auth (an unactivated key
    # version, matching the signed-envelope failure category); any other
    # history entry beyond the head makes the document itself inconsistent
    # with the verified checkpoint and is an input error.
    for other_version, entry in signers.items():
        if other_version == first["key_version"]:
            continue
        if entry["activated_event_id"] > checkpoint["event_id"]:
            raise _VerifyError(ERR_INPUT)
    # A signer can only authenticate a checkpoint taken at or after the event
    # that activated its key.
    if checkpoint["event_id"] < signer["activated_event_id"]:
        raise _VerifyError(ERR_AUTH)
    if not verify_checkpoint_auth(
        signer["public_key"],
        genesis_hash,
        checkpoint,
        first["key_version"],
        first["signature"],
    ):
        raise _VerifyError(ERR_AUTH)
