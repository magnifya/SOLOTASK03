"""Offline verification of append-only audit-log exports.

An export is one or more pages produced by ``GET /v1/audit/export``::

    {"items": [...], "total": N, "next_cursor": int | null,
     "anchor_hash": "<64 hex>", "checkpoint": {"event_id": N, "event_hash": "..."}}

``verify_export`` accepts either a single page object or an ordered JSON array
of pages covering a complete export from the first event to the checkpoint. It
never touches the network or any ledger state; it checks, purely from the
pages themselves:

* **anchors** — a page's ``anchor_hash`` equals the ``prev_hash`` of its first
  item, and successive pages chain (the next anchor is the previous tail
  hash). A complete export starts at 64 zeros.
* **consecutive numbering** — ``event_id`` runs 1..N with no gaps or
  duplicates across the concatenated pages.
* **hashes** — each ``event_hash`` is recomputed as
  ``sha256(prev_hash ASCII || sorted compact UTF-8 JSON of the event without
  the two hash fields)``.
* **checkpoint** — the final page ends at ``checkpoint`` (same event_id and
  hash); an empty stream's checkpoint is 0 / 64 zeros.

Malformed documents (unparseable JSON, wrong types or missing fields) report
``input``; structurally valid documents whose anchors, numbering, hashes or
checkpoint do not verify report ``integrity``.
"""
from __future__ import annotations

from . import crypto


def _input() -> dict:
    return {"ok": False, "error": "input"}


def _integrity() -> dict:
    return {"ok": False, "error": "integrity"}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_page_shape(page: object) -> dict | None:
    """Validate one page's *structure*; return a normalized dict or None.

    Structural/type defects are ``input``; cryptographic linkage is checked
    separately (``integrity``).
    """
    if not isinstance(page, dict):
        return None
    items = page.get("items")
    total = page.get("total")
    next_cursor = page.get("next_cursor")
    anchor_hash = page.get("anchor_hash")
    checkpoint = page.get("checkpoint")
    if not isinstance(items, list):
        return None
    if not _is_int(total) or total < 0:
        return None
    if next_cursor is not None and (not _is_int(next_cursor) or next_cursor < 0):
        return None
    if not isinstance(anchor_hash, str):
        return None
    if not isinstance(checkpoint, dict):
        return None
    cp_id = checkpoint.get("event_id")
    cp_hash = checkpoint.get("event_hash")
    if not _is_int(cp_id) or cp_id < 0 or not isinstance(cp_hash, str):
        return None
    for event in items:
        if not isinstance(event, dict):
            return None
        if not _is_int(event.get("event_id")) or event.get("event_id") < 1:
            return None
        if not isinstance(event.get("kind"), str) or not event["kind"]:
            return None
        if not isinstance(event.get("at"), (int, float)) or isinstance(event.get("at"), bool):
            return None
        if not isinstance(event.get("prev_hash"), str):
            return None
        if not isinstance(event.get("event_hash"), str):
            return None
    return {
        "items": items,
        "total": total,
        "next_cursor": next_cursor,
        "anchor_hash": anchor_hash,
        "checkpoint": {"event_id": cp_id, "event_hash": cp_hash},
    }


def verify_export(document: object) -> dict:
    """Verify a complete audit export (one page object or an ordered list).

    Returns ``{"ok": True, "checkpoint": {event_id, event_hash}}`` on success
    or ``{"ok": False, "error": "input" | "integrity"}``.
    """
    # A single page object is a one-page export; anything else must be an
    # ordered array of pages.
    if isinstance(document, dict):
        pages_raw = [document]
    elif isinstance(document, list) and document and all(
        isinstance(page, dict) for page in document
    ):
        pages_raw = document
    else:
        return _input()

    pages: list[dict] = []
    for page in pages_raw:
        normalized = _check_page_shape(page)
        if normalized is None:
            return _input()
        pages.append(normalized)

    # Every page carries the same checkpoint; the array is redundant but must
    # agree.
    checkpoint = pages[0]["checkpoint"]
    if any(page["checkpoint"] != checkpoint for page in pages):
        return _integrity()
    if not crypto.is_hex64(checkpoint["event_hash"]):
        return _input()

    # Hash encoding is structural; a wrongly encoded hash cannot even be
    # compared, so it is an input defect rather than an integrity mismatch.
    if not crypto.is_hex64(pages[0]["anchor_hash"]):
        return _input()

    expected_id = 1
    prev_hash = crypto.AUDIT_GENESIS_PREV_HASH
    count = 0
    for index, page in enumerate(pages):
        # Only the terminal page may end the export (next_cursor null); every
        # earlier page must point at a following one.
        is_last = index == len(pages) - 1
        if is_last:
            if page["next_cursor"] is not None:
                return _integrity()
        else:
            if page["next_cursor"] is None or not page["items"]:
                return _integrity()

        # A complete export is anchored at genesis; every later page must be
        # anchored at the previous page's tail hash.
        if page["anchor_hash"] != prev_hash:
            return _integrity()

        for event in page["items"]:
            if event["event_id"] != expected_id:
                return _integrity()
            if not crypto.is_hex64(event["prev_hash"]) or not crypto.is_hex64(
                event["event_hash"]
            ):
                return _input()
            if event["prev_hash"] != prev_hash:
                return _integrity()
            if crypto.audit_event_hash(prev_hash, event) != event["event_hash"]:
                return _integrity()
            prev_hash = event["event_hash"]
            expected_id += 1
            count += 1

    total = pages[0]["total"]
    if any(page["total"] != total for page in pages):
        return _integrity()
    if count != total:
        return _integrity()
    # The final page must reach the checkpoint exactly.
    if checkpoint["event_id"] != expected_id - 1:
        return _integrity()
    if total == 0:
        if checkpoint["event_id"] != 0:
            return _integrity()
        if checkpoint["event_hash"] != crypto.AUDIT_GENESIS_PREV_HASH:
            return _integrity()
        if prev_hash != crypto.AUDIT_GENESIS_PREV_HASH:
            return _integrity()
    elif checkpoint["event_hash"] != prev_hash:
        return _integrity()
    return {"ok": True, "checkpoint": checkpoint}
