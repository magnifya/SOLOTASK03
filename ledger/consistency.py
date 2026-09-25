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
      # trust extensions, verified when present (a pre-feature snapshot
      # omits them and is accepted as legacy):
      "trust_sources" / "allowlist" / "source_key_history",
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
* when the trust extensions are present: ``trust_sources`` as a
  source-ascending unique array of ``{source, public_key, expires_at,
  version, status}`` records (64-char lowercase hex key, non-boolean integer
  expiry, positive integer version, ``active``/``revoked`` status),
  ``allowlist`` as a ``source -> non-boolean integer expires_at`` object, and
  ``source_key_history`` as source-ascending unique ``{source, keys}`` items
  whose ``{version, public_key, activated_event_id}`` keys are dense from
  version 1 with positive, strictly ascending activation ids — bidirectionally
  consistent with the trust registry's latest version/public key/status and
  with the audit log's source-key lifecycle events (``source_registered``
  opens version 1, ``source_rotated`` increments it, ``source_revoked`` adds
  none). The registry/event correspondence is checked even when the persisted
  history section is absent (a pre-feature snapshot omits it and is accepted
  as legacy — the reconstruction is exactly what recovery rebuilds in
  memory): a registry source without its events, a lifecycle event naming no
  registry source, or a registry status that disagrees with the reconstructed
  revocation is an integrity error.

Two failure categories are returned, never raised:

* ``input`` — the document is not an object, a required section is missing or
  has the wrong JSON type, an unknown top-level key appears, or a field carries
  a non-integer/non-string value of the wrong kind before any recomputation;
* ``integrity`` — the document parses but a recomputed value disagrees with
  the stored one (tx/merkle/block hashes, linkage, index, accounts, state_root,
  pending uniqueness or the audit chain/checkpoint), or the trust extensions
  disagree among themselves, the registry or the audit event log.
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
    EVENT_SOURCE_REGISTERED,
    EVENT_SOURCE_REVOKED,
    EVENT_SOURCE_ROTATED,
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
# check; audit_events is optional because a pre-audit-chain snapshot omits it;
# the trust extensions are optional because a pre-feature snapshot omits them
# (each is strictly verified when present).
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

# Exact key sets of the trust extension records.
_TRUST_SOURCE_KEYS = ("source", "public_key", "expires_at", "version", "status")
_TRUST_STATUSES = (TRUST_ACTIVE, TRUST_REVOKED)
_HISTORY_ITEM_KEYS = ("source", "keys")
_HISTORY_KEY_KEYS = ("version", "public_key", "activated_event_id")

# Audit event kinds reconstructing a source's key history.
_SOURCE_KEY_EVENT_KINDS = (
    EVENT_SOURCE_REGISTERED,
    EVENT_SOURCE_ROTATED,
    EVENT_SOURCE_REVOKED,
)


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
    checkpoint, events = _verify_audit(data.get("audit_events"), checkpoint_raw)

    # -- trust extensions (registry, allowlist, key history) ------------------
    _verify_trust(
        data.get("trust_sources"),
        data.get("allowlist"),
        data.get("source_key_history"),
        events,
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


def _verify_audit(events_raw: object, checkpoint_raw: object) -> tuple[dict, list[dict]]:
    """Validate the optional event hash chain and the mandatory checkpoint.

    A present ``audit_events`` section must be a list of objects whose dense
    1..N ids, prev_hash links and event_hash digests all recompute; the
    checkpoint (required even with no event list) must pin the recomputed log
    head, or the all-zero root for an empty log. Chain/checkpoint defects are
    integrity errors; the section/value types are input errors. Returns the
    checkpoint summary and the validated event list (empty when the section
    is absent) for the trust cross-checks.
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
    return {"event_id": event_id, "event_hash": event_hash_value}, events


def _verify_trust(
    trust_raw: object,
    allowlist_raw: object,
    history_raw: object,
    events: list[dict],
) -> None:
    """Validate the trust extension sections against each other and the log.

    Every section is optional (a pre-feature snapshot omits them); a present
    section is strictly validated. Field presence and raw JSON types are input
    errors; value-format, ordering and uniqueness defects, and any
    disagreement between the key history, the trust registry and the audit
    log's source-key lifecycle events, are integrity errors. The registry and
    the lifecycle events must reconstruct a consistent key history even when
    the persisted history section is absent: a legacy snapshot without
    ``source_key_history`` is exactly what recovery rebuilds in memory, so a
    missing event, an orphan lifecycle event or a revoked-status mismatch is
    an integrity error there too.
    """
    registry = _parse_trust_sources(trust_raw)
    _parse_allowlist(allowlist_raw)
    history = (
        None if history_raw is None else _parse_source_key_history(history_raw)
    )
    expected = _reconstruct_key_history(registry, events)
    if history is None:
        # Legacy snapshot without the section: the registry/allowlist checks
        # and the registry/event reconstruction above still apply; there is
        # no persisted history to cross-check entry for entry.
        return
    for source, entries in history.items():
        if source not in registry:
            # A history item whose source is absent from the registry is
            # orphan data; the persisted sections must agree bidirectionally.
            raise _Failure(ERR_INTEGRITY)
        if entries != expected[source]:
            raise _Failure(ERR_INTEGRITY)
    for source in registry:
        if source not in history:
            # Current snapshots write one history item per registered source.
            raise _Failure(ERR_INTEGRITY)


def _parse_trust_sources(raw: object) -> dict[str, dict]:
    """Validate the persisted source-trust registry as a raw JSON array.

    The array must be sorted by source with no duplicates; each record
    carries exactly ``{source, public_key, expires_at, version, status}``.
    """
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise _Failure(ERR_INPUT)
    registry: dict[str, dict] = {}
    previous: str | None = None
    for entry in raw:
        if not isinstance(entry, dict):
            raise _Failure(ERR_INPUT)
        if set(entry) != set(_TRUST_SOURCE_KEYS):
            raise _Failure(ERR_INPUT)
        source = entry["source"]
        public_key = entry["public_key"]
        expires_at = entry["expires_at"]
        version = entry["version"]
        status = entry["status"]
        if not isinstance(source, str) or not source:
            raise _Failure(ERR_INPUT)
        if not isinstance(public_key, str):
            raise _Failure(ERR_INPUT)
        if not _is_int(expires_at):
            raise _Failure(ERR_INPUT)
        if not _is_int(version):
            raise _Failure(ERR_INPUT)
        if not isinstance(status, str):
            raise _Failure(ERR_INPUT)
        if not crypto.is_hex64(public_key):
            raise _Failure(ERR_INTEGRITY)
        if status not in _TRUST_STATUSES:
            raise _Failure(ERR_INTEGRITY)
        if version < 1:
            # A non-positive registry version cannot name a key generation.
            raise _Failure(ERR_INTEGRITY)
        if previous is not None and source <= previous:
            # Sources must be unique and strictly ascending.
            raise _Failure(ERR_INTEGRITY)
        previous = source
        registry[source] = {
            "public_key": public_key,
            "expires_at": expires_at,
            "version": version,
            "status": status,
        }
    return registry


def _parse_allowlist(raw: object) -> None:
    """Validate the keyless ``{source: expires_at}`` allowlist object."""
    if raw is None:
        return
    if not isinstance(raw, dict):
        raise _Failure(ERR_INPUT)
    for source, expires_at in raw.items():
        if not isinstance(source, str) or not source:
            raise _Failure(ERR_INPUT)
        if not _is_int(expires_at):
            raise _Failure(ERR_INPUT)


def _parse_source_key_history(raw: object) -> dict[str, list[dict]]:
    """Validate the persisted per-source key history structurally.

    The array is sorted by source with no duplicates; each item is exactly
    ``{source, keys}`` with a non-empty ``keys`` list of
    ``{version, public_key, activated_event_id}`` entries whose versions are
    dense from 1 and whose activation ids are positive and strictly ascend.
    """
    if not isinstance(raw, list):
        raise _Failure(ERR_INPUT)
    history: dict[str, list[dict]] = {}
    previous: str | None = None
    for item in raw:
        if not isinstance(item, dict):
            raise _Failure(ERR_INPUT)
        if set(item) != set(_HISTORY_ITEM_KEYS):
            raise _Failure(ERR_INPUT)
        source = item["source"]
        keys = item["keys"]
        if not isinstance(source, str) or not source:
            raise _Failure(ERR_INPUT)
        if not isinstance(keys, list) or not keys:
            raise _Failure(ERR_INPUT)
        if previous is not None and source <= previous:
            # Sources must be unique and strictly ascending.
            raise _Failure(ERR_INTEGRITY)
        previous = source
        entries: list[dict] = []
        for position, entry in enumerate(keys):
            if not isinstance(entry, dict) or set(entry) != set(_HISTORY_KEY_KEYS):
                raise _Failure(ERR_INPUT)
            version = entry["version"]
            public_key = entry["public_key"]
            activated = entry["activated_event_id"]
            if not _is_int(version):
                raise _Failure(ERR_INPUT)
            if not isinstance(public_key, str):
                raise _Failure(ERR_INPUT)
            if not _is_int(activated):
                raise _Failure(ERR_INPUT)
            if not crypto.is_hex64(public_key):
                raise _Failure(ERR_INTEGRITY)
            if version != position + 1:
                # Key versions are dense from 1 (hence positive).
                raise _Failure(ERR_INTEGRITY)
            if activated < 1:
                # Activation ids are audit event positions: positive.
                raise _Failure(ERR_INTEGRITY)
            if position > 0 and activated <= entries[-1]["activated_event_id"]:
                # Activation event ids strictly ascend with the version.
                raise _Failure(ERR_INTEGRITY)
            entries.append(
                {
                    "version": version,
                    "public_key": public_key,
                    "activated_event_id": activated,
                }
            )
        history[source] = entries
    return history


def _reconstruct_key_history(
    registry: dict[str, dict], events: list[dict]
) -> dict[str, list[dict]]:
    """Rebuild every registry source's expected key history from the log.

    Mirrors ``LedgerStore._reconstruct_source_key_history``: version 1 is
    activated by the source's ``source_registered`` event, each later version
    by the matching ``source_rotated`` event, and a ``source_revoked`` event
    references the current key without adding one. Any malformed lifecycle
    payload, version gap, rotation after revocation or registry/event
    disagreement is an integrity error. The correspondence is bidirectional:
    a lifecycle event naming no registry source is orphan data, and the
    registry record's status must agree with the reconstructed revocation
    (a revoked source has its ``source_revoked`` event, an active source has
    none).
    """
    for event in events:
        if event.get("kind") not in _SOURCE_KEY_EVENT_KINDS:
            continue
        event_source = event.get("source")
        if not isinstance(event_source, str) or event_source not in registry:
            # A source-key lifecycle event for a source the registry does not
            # know belongs to no reconstructed history: orphan data.
            raise _Failure(ERR_INTEGRITY)
    reconstructed: dict[str, list[dict]] = {}
    for source, record in registry.items():
        entries: list[dict] = []
        revoked = False
        next_version = 1
        for event in events:
            kind = event.get("kind")
            if kind not in _SOURCE_KEY_EVENT_KINDS:
                continue
            if event.get("source") != source:
                continue
            event_id = event.get("event_id")
            public_key = event.get("public_key")
            expires_at = event.get("expires_at")
            version = event.get("version")
            if (
                not crypto.is_hex64(public_key)
                or not _is_int(expires_at)
                or not _is_int(version)
                or version < 1
                or not _is_int(event_id)
                or event_id < 1
            ):
                raise _Failure(ERR_INTEGRITY)
            if kind == EVENT_SOURCE_REGISTERED:
                if entries or version != 1:
                    # The history opens with a single version-1 registration.
                    raise _Failure(ERR_INTEGRITY)
                entries.append(
                    {
                        "version": 1,
                        "public_key": public_key,
                        "activated_event_id": event_id,
                    }
                )
                next_version = 2
            elif kind == EVENT_SOURCE_ROTATED:
                if revoked or not entries or version != next_version:
                    # Rotations increment the version one step at a time and
                    # never happen after revocation.
                    raise _Failure(ERR_INTEGRITY)
                entries.append(
                    {
                        "version": version,
                        "public_key": public_key,
                        "activated_event_id": event_id,
                    }
                )
                next_version = version + 1
            else:  # EVENT_SOURCE_REVOKED
                if (
                    not entries
                    or version != entries[-1]["version"]
                    or public_key != entries[-1]["public_key"]
                ):
                    # Revocation pins the current key without adding one.
                    raise _Failure(ERR_INTEGRITY)
                revoked = True
        if not entries:
            # A registered source has no source_registered event.
            raise _Failure(ERR_INTEGRITY)
        if revoked != (record["status"] == TRUST_REVOKED):
            # The registry status must agree with the reconstructed
            # revocation: a revoked source has its source_revoked event and
            # an active source has none.
            raise _Failure(ERR_INTEGRITY)
        if len(entries) != record["version"]:
            raise _Failure(ERR_INTEGRITY)
        if entries[-1]["public_key"] != record["public_key"]:
            raise _Failure(ERR_INTEGRITY)
        reconstructed[source] = entries
    return reconstructed
