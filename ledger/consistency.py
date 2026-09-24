"""Offline whole-snapshot consistency verification.

``verify_snapshot(document)`` re-derives every self-contained invariant of a
persisted ledger snapshot without contacting a server or touching the
filesystem::

    {
      "state":             object (generation, optional state_root, ...),
      "chain":             non-empty block list starting at genesis,
      "pending":           mempool transaction list,
      "index":             {tx_id: confirmed_height},
      "accounts":          {account: {sent, received, transactions}},
      "audit_checkpoint":  {"event_id", "event_hash"},
      "audit_events":      optional append-only hash-chained event list,
      # optional trust extensions, strictly validated when present:
      "trust_sources":     ascending unique registry entries,
      "allowlist":         {source: expires_at} object,
      "source_key_history": per-source key history, cross-checked against
                           the registry and the audit events,
      # extensions, accepted but not re-verified here:
      "forks" / "syncs" / "attested_syncs",
    }

Verification recomputes, from the raw JSON values:

* every transaction's canonical ``tx_id`` and Ed25519 signature;
* every block's ascending tx_id order, Merkle root and block hash, the
  consecutive heights and ``prev_hash`` linkage back to the all-zero anchor,
  the confirmed/empty genesis rules and the pending-only-at-tip rule;
* mempool uniqueness and the mempool/chain de-duplication;
* the confirmed-only transaction ``index`` and ``accounts`` activity;
* the confirmed-account Merkle ``state_root`` (using ``state.initial_balance``
  when recorded, else the default endowment);
* when ``audit_events`` is present, its dense event ids and SHA-256 hash links
  plus the ``audit_checkpoint`` pinning the log head (an absent event list
  still requires the empty-log checkpoint ``{0, "0"*64}``);
* when the trust extensions are present: ``trust_sources`` must be a list of
  exactly ``{source, public_key, expires_at, version, status}`` entries,
  ascending by unique source, with a 64-char lowercase hex public key, a
  plain integer ``expires_at``, a positive integer ``version`` and a status
  of exactly ``active``/``revoked``; ``allowlist`` must map sources to plain
  integer deadlines; and ``source_key_history`` must be a list of exactly
  ``{source, keys}`` items whose keys are exactly
  ``{version, public_key, activated_event_id}`` entries with versions dense
  from 1 and strictly ascending activation ids, agreeing bidirectionally
  with the registry's latest version/public key and with the
  ``source_registered``/``source_rotated``/``source_revoked`` audit events
  (registration activates version 1, each rotation the next version,
  revocation adds none). Absent sections are simply skipped, so a legacy
  snapshot without the extensions still verifies.

Two failure categories are returned, never raised:

* ``input`` — the document is not an object, a required section is missing or
  has the wrong JSON type, an unknown top-level key appears, or a field carries
  a non-integer/non-string value of the wrong kind before any recomputation
  (including every structural defect of the trust extension sections);
* ``integrity`` — the document parses but a recomputed value disagrees with the
  stored one (tx/merkle/block hashes, linkage, index, accounts, state_root,
  pending uniqueness or the audit chain/checkpoint), or the persisted key
  history disagrees with the trust registry or the source lifecycle events.
"""
from __future__ import annotations

from . import audit
from . import crypto
from .models import (
    STATUS_CONFIRMED,
    STATUS_PENDING,
    Block,
    Transaction,
    compute_block_hash,
)
from .store import (
    DEFAULT_INITIAL_BALANCE,
    GENESIS_PREV_HASH,
    TRUST_ACTIVE,
    TRUST_REVOKED,
    LedgerStore,
)

# Public error categories.
ERR_INPUT = "input"
ERR_INTEGRITY = "integrity"

# Required top-level sections; every one must be present with the right type.
REQUIRED_SECTIONS = ("state", "chain", "pending", "index", "accounts", "audit_checkpoint")

# Sections a snapshot may additionally carry. forks/syncs/attested_syncs are
# durable state but their own invariants are not part of this self-contained
# check; audit_events is optional because a pre-audit-chain snapshot omits
# it; the three trust extensions are optional because a snapshot predating
# them omits them, but each present section is strictly validated.
KNOWN_OPTIONAL_SECTIONS = (
    "audit_events",
    "forks",
    "syncs",
    "attested_syncs",
    "trust_sources",
    "allowlist",
    "source_key_history",
)

# Raw keys every stored block document must carry ("status" defaults to
# confirmed for legacy snapshots).
_BLOCK_KEYS = ("height", "prev_hash", "merkle_root", "block_hash", "transactions")

# Raw keys every stored transaction document must carry.
_TX_KEYS = ("from", "to", "amount", "signature", "tx_id")

# The exact key set of one persisted trust-registry entry, listed in the
# canonical order the node writes them.
_TRUST_SOURCE_KEYS = ("source", "public_key", "expires_at", "version", "status")

# The exact key sets of one source_key_history item and of one key entry.
_HISTORY_ITEM_KEYS = ("source", "keys")
_HISTORY_ENTRY_KEYS = ("version", "public_key", "activated_event_id")

# Source-key lifecycle audit event kinds reconstructing the expected history.
_SOURCE_KEY_EVENT_KINDS = ("source_registered", "source_rotated", "source_revoked")


class _Failure(Exception):
    """Internal control-flow exception carrying the public error category."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _is_int(value: object) -> bool:
    """Plain integer test; booleans are rejected (bool subclasses int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _failed(category: str) -> dict:
    return {
        "ok": False,
        "error": category,
        "generation": None,
        "height": None,
        "tip_hash": None,
        "state_root": None,
        "audit_checkpoint": None,
    }


def verify_snapshot(document: object) -> dict:
    """Verify the internal consistency of one decoded snapshot document.

    Returns ``{"ok": True, "error": None, "generation", "height", "tip_hash",
    "state_root", "audit_checkpoint"}`` on success, or the same shape with
    ``ok`` False, ``error`` set to ``"input"``/``"integrity"`` and every other
    field null. Never raises for malformed input.
    """
    try:
        if not isinstance(document, dict):
            raise _Failure(ERR_INPUT)
        result = _verify(document)
    except _Failure as failure:
        return _failed(failure.category)
    except Exception:
        # Defensive: structurally unforeseeable inputs report rather than crash.
        return _failed(ERR_INPUT)
    return {
        "ok": True,
        "error": None,
        "generation": result["generation"],
        "height": result["height"],
        "tip_hash": result["tip_hash"],
        "state_root": result["state_root"],
        "audit_checkpoint": result["audit_checkpoint"],
    }


def _verify(data: dict) -> dict:
    # Unknown top-level keys make the document shape wrong; the five
    # extension sections plus the optional audit log are the only extras.
    allowed = set(REQUIRED_SECTIONS) | set(KNOWN_OPTIONAL_SECTIONS)
    for key in data:
        if key not in allowed:
            raise _Failure(ERR_INPUT)
    for section in REQUIRED_SECTIONS:
        if section not in data:
            raise _Failure(ERR_INPUT)

    state = data["state"]
    chain_raw = data["chain"]
    pending_raw = data["pending"]
    index_raw = data["index"]
    accounts_raw = data["accounts"]
    checkpoint_raw = data["audit_checkpoint"]

    # -- core section types --------------------------------------------------
    if not isinstance(state, dict):
        raise _Failure(ERR_INPUT)
    if not isinstance(chain_raw, list) or not chain_raw:
        raise _Failure(ERR_INPUT)
    if not isinstance(pending_raw, list):
        raise _Failure(ERR_INPUT)
    if not isinstance(index_raw, dict):
        raise _Failure(ERR_INPUT)
    if not isinstance(accounts_raw, dict):
        raise _Failure(ERR_INPUT)

    generation = state.get("generation", 0)
    if not _is_int(generation) or generation < 0:
        raise _Failure(ERR_INPUT)
    endowment = state.get("initial_balance")
    if endowment is not None and (
        not _is_int(endowment) or endowment <= 0
    ):
        raise _Failure(ERR_INPUT)
    if endowment is None:
        endowment = DEFAULT_INITIAL_BALANCE
    recorded_state_root = state.get("state_root")
    if recorded_state_root is not None and not isinstance(recorded_state_root, str):
        raise _Failure(ERR_INPUT)

    # -- chain recomputation -------------------------------------------------
    blocks, seen_tx_ids = _recompute_chain(chain_raw)

    # -- mempool --------------------------------------------------------------
    _verify_pending(pending_raw, seen_tx_ids)

    tip = blocks[-1]
    if state.get("height") is not None and state["height"] != tip.height:
        raise _Failure(ERR_INTEGRITY)
    if state.get("tip_hash") is not None and state["tip_hash"] != tip.block_hash:
        raise _Failure(ERR_INTEGRITY)
    if (
        state.get("tip_status") is not None
        and state["tip_status"] != tip.status
    ):
        raise _Failure(ERR_INTEGRITY)

    # -- derived index / accounts / state root -------------------------------
    expected_index, expected_accounts = _compute_derived(blocks)
    _verify_index(index_raw, expected_index)
    _verify_accounts(accounts_raw, expected_accounts)

    leaves = [
        crypto.account_state_leaf(account, balance, transactions)
        for account, balance, transactions in LedgerStore.account_state_rows(
            blocks, endowment
        )
    ]
    state_root = crypto.account_state_root(leaves)
    if recorded_state_root is not None:
        # A non-string was an input error above; a wrong-length/non-hex string
        # or a digest mismatch is corruption of the stored artifact.
        if not crypto.is_hex64(recorded_state_root) or recorded_state_root != state_root:
            raise _Failure(ERR_INTEGRITY)

    # -- audit hash chain and checkpoint -------------------------------------
    events_raw = data.get("audit_events")
    checkpoint = _verify_audit(events_raw, checkpoint_raw)

    # -- trust registry, allowlist and source key history --------------------
    registry = _verify_trust_sources(data.get("trust_sources"))
    _verify_allowlist(data.get("allowlist"))
    _verify_source_key_history(
        data.get("source_key_history"), registry, events_raw or []
    )

    return {
        "generation": generation,
        "height": tip.height,
        "tip_hash": tip.block_hash,
        "state_root": state_root,
        "audit_checkpoint": checkpoint,
    }


def _recompute_chain(chain_raw: list) -> tuple[list[Block], set[str]]:
    """Parse and re-verify the canonical chain straight from the raw JSON.

    Field presence/type defects are input errors; every recomputed mismatch
    (heights, prev_hash links, tx_ids, signatures, ordering, Merkle roots,
    block hashes, genesis/pending-status rules) is an integrity error.
    """
    blocks: list[Block] = []
    seen_tx_ids: set[str] = set()
    for position, block_raw in enumerate(chain_raw):
        if not isinstance(block_raw, dict):
            raise _Failure(ERR_INPUT)
        for key in _BLOCK_KEYS:
            if key not in block_raw:
                raise _Failure(ERR_INPUT)
        height = block_raw["height"]
        prev_hash = block_raw["prev_hash"]
        merkle_root = block_raw["merkle_root"]
        block_hash = block_raw["block_hash"]
        txs_raw = block_raw["transactions"]
        status = block_raw.get("status", STATUS_CONFIRMED)
        # Raw types are checked before any use: a string/float/bool height or
        # amount is never coerced into the integer it resembles.
        if not _is_int(height) or height < 0:
            raise _Failure(ERR_INPUT)
        if not isinstance(prev_hash, str):
            raise _Failure(ERR_INPUT)
        if not isinstance(merkle_root, str) or not isinstance(block_hash, str):
            raise _Failure(ERR_INPUT)
        if not isinstance(txs_raw, list):
            raise _Failure(ERR_INPUT)
        if not isinstance(status, str):
            raise _Failure(ERR_INPUT)
        if status not in (STATUS_PENDING, STATUS_CONFIRMED):
            raise _Failure(ERR_INTEGRITY)

        if height != position:
            raise _Failure(ERR_INTEGRITY)
        expected_prev = (
            GENESIS_PREV_HASH if position == 0 else blocks[position - 1].block_hash
        )
        if prev_hash != expected_prev:
            raise _Failure(ERR_INTEGRITY)
        if position == 0 and (
            status != STATUS_CONFIRMED or txs_raw
        ):
            # Genesis is born confirmed and carries no transactions.
            raise _Failure(ERR_INTEGRITY)
        if position < len(chain_raw) - 1 and status == STATUS_PENDING:
            # Pending blocks may only sit at the chain tip.
            raise _Failure(ERR_INTEGRITY)

        tx_ids: list[str] = []
        for tx_raw in txs_raw:
            tx = _parse_transaction(tx_raw)
            if tx.tx_id in seen_tx_ids:
                raise _Failure(ERR_INTEGRITY)
            seen_tx_ids.add(tx.tx_id)
            tx_ids.append(tx.tx_id)

        if tx_ids != sorted(tx_ids):
            raise _Failure(ERR_INTEGRITY)
        if crypto.merkle_root(tx_ids) != merkle_root:
            raise _Failure(ERR_INTEGRITY)
        if compute_block_hash(height, prev_hash, merkle_root) != block_hash:
            raise _Failure(ERR_INTEGRITY)
        try:
            blocks.append(Block.from_dict(block_raw))
        except (KeyError, TypeError, ValueError):
            # Every field was validated above; reaching here still means the
            # stored block document cannot represent the recomputed block.
            raise _Failure(ERR_INTEGRITY) from None
    return blocks, seen_tx_ids


def _parse_transaction(tx_raw: object) -> Transaction:
    """Validate one raw transaction document and recompute tx_id/signature.

    Missing keys or non-plain-integer/non-string field types (including a
    non-positive amount) are input errors; a recomputed tx_id or Ed25519
    signature mismatch is an integrity error.
    """
    if not isinstance(tx_raw, dict):
        raise _Failure(ERR_INPUT)
    for key in _TX_KEYS:
        if key not in tx_raw:
            raise _Failure(ERR_INPUT)
    sender = tx_raw["from"]
    recipient = tx_raw["to"]
    amount = tx_raw["amount"]
    signature = tx_raw["signature"]
    stored_tx_id = tx_raw["tx_id"]
    if not isinstance(sender, str) or not isinstance(recipient, str):
        raise _Failure(ERR_INPUT)
    if not _is_int(amount) or amount <= 0:
        raise _Failure(ERR_INPUT)
    if not isinstance(signature, str) or not isinstance(stored_tx_id, str):
        raise _Failure(ERR_INPUT)
    try:
        tx = Transaction.from_dict(tx_raw)
    except (KeyError, TypeError, ValueError):
        raise _Failure(ERR_INPUT) from None
    if stored_tx_id != tx.tx_id or not crypto.is_hex64(stored_tx_id):
        raise _Failure(ERR_INTEGRITY)
    if not crypto.verify_signature(tx.sender, tx.message, tx.signature):
        raise _Failure(ERR_INTEGRITY)
    return tx


def _verify_pending(pending_raw: list, chain_tx_ids: set[str]) -> None:
    """Mempool entries are well-formed, unique, and disjoint from the chain."""
    pending: set[str] = set()
    for tx_raw in pending_raw:
        tx = _parse_transaction(tx_raw)
        if tx.tx_id in pending:
            # Duplicate pending transaction in the mempool.
            raise _Failure(ERR_INTEGRITY)
        if tx.tx_id in chain_tx_ids:
            # A mempool transaction already sealed into a block.
            raise _Failure(ERR_INTEGRITY)
        pending.add(tx.tx_id)


def _compute_derived(
    blocks: list[Block],
) -> tuple[dict[str, int], dict[str, dict]]:
    """Confirmed-only tx_id -> height index and per-account activity.

    Mirrors ``LedgerStore._compute_derived`` exactly (including a self-send
    listing its tx_id once per side) so the comparison can never disagree on
    an artifact the node itself wrote.
    """
    tx_index: dict[str, int] = {}
    accounts: dict[str, dict] = {}
    for block in blocks:
        if block.status != STATUS_CONFIRMED:
            continue
        for tx in block.transactions:
            tx_index[tx.tx_id] = block.height
            for account in (tx.sender, tx.recipient):
                entry = accounts.setdefault(
                    account, {"sent": 0, "received": 0, "transactions": []}
                )
                entry["transactions"].append(tx.tx_id)
            accounts[tx.sender]["sent"] += tx.amount
            accounts[tx.recipient]["received"] += tx.amount
    return tx_index, accounts


def _verify_index(raw: dict, expected: dict[str, int]) -> None:
    for key, value in raw.items():
        if not isinstance(key, str) or not _is_int(value) or value < 0:
            raise _Failure(ERR_INPUT)
    if raw != expected:
        # Any extra, missing or remapped confirmed-transaction entry is a
        # derived-data inconsistency.
        raise _Failure(ERR_INTEGRITY)


def _verify_accounts(raw: dict, expected: dict[str, dict]) -> None:
    for account, entry in raw.items():
        if not isinstance(account, str) or not isinstance(entry, dict):
            raise _Failure(ERR_INPUT)
        sent = entry.get("sent")
        received = entry.get("received")
        transactions = entry.get("transactions")
        if not _is_int(sent) or not _is_int(received) or not isinstance(transactions, list):
            raise _Failure(ERR_INPUT)
        if any(not isinstance(tx_id, str) for tx_id in transactions):
            raise _Failure(ERR_INPUT)
    if raw != expected:
        raise _Failure(ERR_INTEGRITY)


def _verify_audit(events_raw: object, checkpoint_raw: object) -> dict:
    """Validate the optional event hash chain and the mandatory checkpoint.

    A present ``audit_events`` section must be a list of objects whose dense
    1..N ids, prev_hash links and event_hash digests all recompute; the
    checkpoint (required even with no event list) must pin the recomputed log
    head, or the all-zero root for an empty log. Chain/checkpoint defects are
    integrity errors; the section/value types are input errors.
    """
    if events_raw is None:
        events: list[dict] = []
    else:
        if not isinstance(events_raw, list):
            raise _Failure(ERR_INPUT)
        if any(not isinstance(event, dict) for event in events_raw):
            raise _Failure(ERR_INPUT)
        events = events_raw
        try:
            audit.validate_event_chain(events)
        except audit.AuditChainError:
            raise _Failure(ERR_INTEGRITY) from None

    if not isinstance(checkpoint_raw, dict):
        raise _Failure(ERR_INPUT)
    if set(checkpoint_raw) != {"event_id", "event_hash"}:
        # The checkpoint is exactly {event_id, event_hash}; any extra or
        # missing key makes its shape wrong.
        raise _Failure(ERR_INPUT)
    event_id = checkpoint_raw["event_id"]
    event_hash_value = checkpoint_raw["event_hash"]
    if not _is_int(event_id) or event_id < 0:
        raise _Failure(ERR_INPUT)
    if not isinstance(event_hash_value, str):
        raise _Failure(ERR_INPUT)
    try:
        audit.validate_checkpoint(checkpoint_raw, events)
    except audit.AuditChainError:
        raise _Failure(ERR_INTEGRITY) from None
    return {"event_id": event_id, "event_hash": event_hash_value}


def _verify_trust_sources(raw: object) -> dict[str, dict]:
    """Validate the optional persisted source-trust registry.

    A present ``trust_sources`` section must be a list of entries carrying
    exactly ``source, public_key, expires_at, version, status``, ascending by
    unique source; the public key must be 64 lowercase hex, ``expires_at`` a
    plain (non-boolean) integer, ``version`` a positive integer and ``status``
    exactly ``active`` or ``revoked``. Every defect is a structural ``input``
    error. Returns the parsed ``{source: record}`` registry for the
    key-history cross-check.
    """
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise _Failure(ERR_INPUT)
    registry: dict[str, dict] = {}
    previous: str | None = None
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != set(_TRUST_SOURCE_KEYS):
            raise _Failure(ERR_INPUT)
        source = entry["source"]
        if not isinstance(source, str) or not source:
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(entry["public_key"]):
            raise _Failure(ERR_INPUT)
        if not _is_int(entry["expires_at"]):
            raise _Failure(ERR_INPUT)
        version = entry["version"]
        if not _is_int(version) or version < 1:
            raise _Failure(ERR_INPUT)
        if entry["status"] not in (TRUST_ACTIVE, TRUST_REVOKED):
            raise _Failure(ERR_INPUT)
        if previous is not None and source <= previous:
            # The registry is persisted ascending by unique source.
            raise _Failure(ERR_INPUT)
        previous = source
        registry[source] = {
            "public_key": entry["public_key"],
            "expires_at": entry["expires_at"],
            "version": version,
            "status": entry["status"],
        }
    return registry


def _verify_allowlist(raw: object) -> None:
    """Validate the optional keyless ``{source: expires_at}`` allowlist.

    Every key must be a non-empty source string and every value a plain
    (non-boolean) integer deadline; any other shape is an ``input`` error.
    """
    if raw is None:
        return
    if not isinstance(raw, dict):
        raise _Failure(ERR_INPUT)
    for source, expires_at in raw.items():
        if not isinstance(source, str) or not source:
            raise _Failure(ERR_INPUT)
        if not _is_int(expires_at):
            raise _Failure(ERR_INPUT)


def _verify_source_key_history(
    raw: object, registry: dict[str, dict], events: list[dict]
) -> None:
    """Validate the optional persisted per-source public-key history.

    Structurally, a present section must be a list of exactly
    ``{source, keys}`` items, ascending by unique source, whose ``keys`` are
    non-empty lists of exactly ``{version, public_key, activated_event_id}``
    entries: versions dense from 1, activation ids strictly ascending, the
    public key 64 lowercase hex and both numeric fields plain integers.
    Every such defect is an ``input`` error.

    Semantically the persisted history must agree, source for source and
    entry for entry, with the history reconstructed from the trust registry
    and the audit log; any disagreement — including a history source missing
    from the registry or a registry source missing from the section — is an
    ``integrity`` error. A legacy snapshot without the section is accepted
    without any cross-check.
    """
    if raw is None:
        return
    if not isinstance(raw, list):
        raise _Failure(ERR_INPUT)
    persisted: dict[str, list[dict]] = {}
    previous: str | None = None
    for item in raw:
        if not isinstance(item, dict) or set(item) != set(_HISTORY_ITEM_KEYS):
            raise _Failure(ERR_INPUT)
        source = item["source"]
        if not isinstance(source, str) or not source:
            raise _Failure(ERR_INPUT)
        keys = item["keys"]
        if not isinstance(keys, list) or not keys:
            raise _Failure(ERR_INPUT)
        if previous is not None and source <= previous:
            # The section is persisted ascending by unique source.
            raise _Failure(ERR_INPUT)
        previous = source
        entries: list[dict] = []
        for position, entry in enumerate(keys):
            if not isinstance(entry, dict) or set(entry) != set(_HISTORY_ENTRY_KEYS):
                raise _Failure(ERR_INPUT)
            version = entry["version"]
            public_key = entry["public_key"]
            activated = entry["activated_event_id"]
            if not _is_int(version) or version != position + 1:
                raise _Failure(ERR_INPUT)
            if not crypto.is_hex64(public_key):
                raise _Failure(ERR_INPUT)
            if not _is_int(activated) or activated < 0:
                raise _Failure(ERR_INPUT)
            if entries and activated <= entries[-1]["activated_event_id"]:
                raise _Failure(ERR_INPUT)
            entries.append(
                {
                    "version": version,
                    "public_key": public_key,
                    "activated_event_id": activated,
                }
            )
        persisted[source] = entries

    expected = _reconstruct_source_key_histories(registry, events)
    if set(persisted) != set(expected):
        # Bidirectional agreement: no orphan history items and no registry
        # source missing from the section.
        raise _Failure(ERR_INTEGRITY)
    for source, entries in persisted.items():
        if entries != expected[source]:
            raise _Failure(ERR_INTEGRITY)


def _reconstruct_source_key_histories(
    registry: dict[str, dict], events: list[dict]
) -> dict[str, list[dict]]:
    """Rebuild every registry source's expected key history from the audit log.

    Mirrors ``LedgerStore._reconstruct_source_key_history``: version 1 is
    activated by the source's ``source_registered`` event, each
    ``source_rotated`` event activates the next dense version, and
    ``source_revoked`` must reference the current key without adding one.
    Lifecycle events for sources absent from the registry belong to no
    reconstructed history and are ignored. Every malformed lifecycle payload
    or registry/event disagreement is a semantic ``integrity`` failure.
    """
    expected: dict[str, list[dict]] = {}
    for source, record in registry.items():
        entries: list[dict] = []
        revoked = False
        next_version = 1
        for event in events:
            kind = event.get("kind")
            if kind not in _SOURCE_KEY_EVENT_KINDS or event.get("source") != source:
                continue
            event_id = event.get("event_id")
            public_key = event.get("public_key")
            expires_at = event.get("expires_at")
            version = event.get("version")
            if (
                not _is_int(event_id)
                or event_id < 1
                or not crypto.is_hex64(public_key)
                or not _is_int(expires_at)
                or not _is_int(version)
                or version < 1
            ):
                raise _Failure(ERR_INTEGRITY)
            if kind == "source_registered":
                if entries or version != 1:
                    # The history opens with a single version 1 registration.
                    raise _Failure(ERR_INTEGRITY)
                entries.append(
                    {
                        "version": 1,
                        "public_key": public_key,
                        "activated_event_id": event_id,
                    }
                )
                next_version = 2
            elif kind == "source_rotated":
                if revoked or not entries or version != next_version:
                    raise _Failure(ERR_INTEGRITY)
                entries.append(
                    {
                        "version": version,
                        "public_key": public_key,
                        "activated_event_id": event_id,
                    }
                )
                next_version = version + 1
            else:  # source_revoked
                if not entries or version != entries[-1]["version"]:
                    raise _Failure(ERR_INTEGRITY)
                if public_key != entries[-1]["public_key"]:
                    raise _Failure(ERR_INTEGRITY)
                revoked = True
        if not entries:
            # A registry source without its source_registered event.
            raise _Failure(ERR_INTEGRITY)
        if len(entries) != record["version"]:
            raise _Failure(ERR_INTEGRITY)
        if entries[-1]["public_key"] != record["public_key"]:
            raise _Failure(ERR_INTEGRITY)
        expected[source] = entries
    return expected
