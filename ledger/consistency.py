"""Offline snapshot consistency verification.

``verify_snapshot`` re-derives every committed datum of a ledger snapshot
without trusting any stored value, and reports either the snapshot's verified
tip descriptor or a categorized failure:

* ``input`` — the document is not a snapshot of the documented shape: it is
  not a JSON object, a required top-level section (``state``, ``chain``,
  ``pending``, ``index``, ``accounts``, ``audit_checkpoint``) is missing or has
  the wrong type, an unknown top-level key is present, or a stored field has a
  structurally wrong type (a non-integer height/amount, a non-list block
  transaction array, ...).
* ``integrity`` — the shape is right but recomputation disagrees with what is
  stored: a transaction id or Ed25519 signature, a Merkle root, a block hash,
  the height/prev_hash linkage, the pending-only-at-tip rule, mempool
  uniqueness/de-duplication, the transaction ``index``, the ``accounts``
  activity, ``state.state_root``, or — when present — the ``audit_events``
  hash chain and the ``audit_checkpoint`` it must pin.

``audit_events`` is optional (an empty log carries just its zero checkpoint).
The extension sections ``forks``, ``syncs``, ``attested_syncs``,
``trust_sources`` and ``allowlist`` may be present and are not re-derived
here.

The success document has one contract-fixed key order —
``ok, error, generation, height, tip_hash, state_root, audit_checkpoint`` — so
callers serialize it without key sorting.
"""
from __future__ import annotations

from . import audit
from . import crypto
from .models import STATUS_CONFIRMED, STATUS_PENDING, compute_block_hash

# Required top-level sections of every snapshot.
REQUIRED_KEYS = (
    "state",
    "chain",
    "pending",
    "index",
    "accounts",
    "audit_checkpoint",
)

# Sections that may additionally appear; everything else is an unknown key.
OPTIONAL_KEYS = (
    "audit_events",
    "forks",
    "syncs",
    "attested_syncs",
    "trust_sources",
    "allowlist",
)

# Previous hash of the genesis block.
GENESIS_PREV_HASH = "0" * 64

# Fallback endowment for a snapshot predating state.initial_balance; mirrors
# store.DEFAULT_INITIAL_BALANCE without importing the persistence layer
# (which performs recovery on construction).
DEFAULT_INITIAL_BALANCE = 1_000_000

ERR_INPUT = "input"
ERR_INTEGRITY = "integrity"


class _VerifyError(Exception):
    """Internal control-flow exception carrying the public error category."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _input(condition: bool = True) -> None:
    if condition:
        raise _VerifyError(ERR_INPUT)


def _integrity(condition: bool = True) -> None:
    if condition:
        raise _VerifyError(ERR_INTEGRITY)


def _is_plain_int(value: object) -> bool:
    """Plain integer test; booleans are rejected (bool subclasses int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _failure(category: str) -> dict:
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

    Returns
    ``{"ok": True, "error": None, "generation", "height", "tip_hash",
    "state_root", "audit_checkpoint"}`` on success or the same key order with
    ``ok`` False, ``error`` ``"input"``/``"integrity"`` and every other field
    null. Never raises for malformed input.
    """
    try:
        return _verify(document)
    except _VerifyError as failure:
        return _failure(failure.category)
    except Exception:
        # Defensive: structurally unforeseeable inputs report rather than crash.
        return _failure(ERR_INPUT)


def _verify(document: object) -> dict:
    _input(not isinstance(document, dict))

    # Unknown top-level keys are an input error: a verifier for one schema
    # must never silently pass a document shaped for a different/changed one.
    for key in document:
        _input(key not in REQUIRED_KEYS and key not in OPTIONAL_KEYS)
    for key in REQUIRED_KEYS:
        _input(key not in document)

    state = document["state"]
    chain_raw = document["chain"]
    pending_raw = document["pending"]
    index_raw = document["index"]
    accounts_raw = document["accounts"]
    checkpoint_raw = document["audit_checkpoint"]

    # Core section types.
    _input(not isinstance(state, dict))
    _input(not isinstance(chain_raw, list))
    _input(not isinstance(pending_raw, list))
    _input(not isinstance(index_raw, dict))
    _input(not isinstance(accounts_raw, dict))
    _input(not isinstance(checkpoint_raw, dict))
    events_raw = document.get("audit_events")
    _input(events_raw is not None and not isinstance(events_raw, list))

    # state.generation is reported verbatim (defaulting to 0 for a snapshot
    # predating the field); a present malformed value is a shape error.
    generation = state.get("generation", 0)
    _input(not _is_plain_int(generation) or generation < 0)

    endowment = state.get("initial_balance")
    if endowment is None:
        endowment = DEFAULT_INITIAL_BALANCE
    else:
        _input(not _is_plain_int(endowment))
        _integrity(endowment <= 0)

    recorded_state_root = state.get("state_root")
    if recorded_state_root is not None:
        _input(not crypto.is_hex64(recorded_state_root))

    chain = _verify_chain(chain_raw)
    _verify_pending(pending_raw, chain)
    tip = chain[-1]

    # The state summary, when present, must pin the recomputed chain tip.
    state_height = state.get("height")
    if state_height is not None:
        _input(not _is_plain_int(state_height) or state_height < 0)
        _integrity(state_height != tip["height"])
    state_tip_hash = state.get("tip_hash")
    if state_tip_hash is not None:
        _input(not isinstance(state_tip_hash, str))
        _integrity(state_tip_hash != tip["block_hash"])
    state_tip_status = state.get("tip_status")
    if state_tip_status is not None:
        _input(not isinstance(state_tip_status, str))
        _integrity(state_tip_status != tip["status"])

    # Re-derive the confirmed-only index and account activity and require the
    # stored sections to match byte-for-byte (same keys and same values).
    expected_index = _recompute_index(chain_raw)
    expected_accounts = _recompute_accounts(chain_raw)
    _integrity(index_raw != expected_index)
    _integrity(accounts_raw != expected_accounts)

    state_root = _compute_state_root(chain_raw, endowment)
    if recorded_state_root is not None:
        _integrity(recorded_state_root != state_root)

    audit_checkpoint = _verify_audit(events_raw, checkpoint_raw)

    return {
        "ok": True,
        "error": None,
        "generation": generation,
        "height": tip["height"],
        "tip_hash": tip["block_hash"],
        "state_root": state_root,
        "audit_checkpoint": audit_checkpoint,
    }


def _verify_chain(chain_raw: list) -> list[dict]:
    """Recompute every block of the canonical chain from its raw form.

    Returns a lightweight per-block descriptor
    ``{height, status, tx_ids, block_hash}`` used by the mempool checks. A
    structural defect is an input error; any recomputation mismatch
    (transaction id, Ed25519 signature, Merkle root, block hash,
    height/prev_hash linkage, ordering or the pending-only-at-tip rule) is an
    integrity error.
    """
    _integrity(not chain_raw)
    chain: list[dict] = []
    seen_tx_ids: set[str] = set()
    for position, block_raw in enumerate(chain_raw):
        _input(not isinstance(block_raw, dict))
        for field in ("height", "prev_hash", "merkle_root", "block_hash", "transactions"):
            _input(field not in block_raw)

        height = block_raw["height"]
        prev_hash = block_raw["prev_hash"]
        merkle_root = block_raw["merkle_root"]
        block_hash = block_raw["block_hash"]
        txs_raw = block_raw["transactions"]
        status = block_raw.get("status", STATUS_CONFIRMED)

        _input(not _is_plain_int(height) or height < 0)
        _input(not isinstance(prev_hash, str))
        _input(not isinstance(merkle_root, str))
        _input(not isinstance(block_hash, str))
        _input(not isinstance(txs_raw, list))
        _input(not isinstance(status, str))

        _integrity(height != position)
        _integrity(status not in (STATUS_PENDING, STATUS_CONFIRMED))
        expected_prev = GENESIS_PREV_HASH if position == 0 else chain[-1]["block_hash"]
        _integrity(prev_hash != expected_prev)
        # Genesis must be confirmed and carry no transactions.
        if position == 0:
            _integrity(status != STATUS_CONFIRMED or txs_raw)
        # Pending blocks may only sit at the chain tip.
        if position < len(chain_raw) - 1:
            _integrity(status == STATUS_PENDING)

        tx_ids: list[str] = []
        for tx_raw in txs_raw:
            tx_id = _verify_transaction(tx_raw)
            _integrity(tx_id in seen_tx_ids)
            seen_tx_ids.add(tx_id)
            tx_ids.append(tx_id)

        # Blocks store transactions in ascending tx_id order.
        _integrity(tx_ids != sorted(tx_ids))
        _integrity(crypto.merkle_root(tx_ids) != merkle_root)
        recomputed_hash = compute_block_hash(height, prev_hash, merkle_root)
        _integrity(recomputed_hash != block_hash)

        chain.append(
            {
                "height": height,
                "status": status,
                "tx_ids": tx_ids,
                "block_hash": block_hash,
            }
        )
    return chain


def _verify_transaction(tx_raw: object) -> str:
    """Recompute one transaction's id and verify its Ed25519 signature.

    Returns the recomputed tx_id. Missing/ill-typed payload fields are input
    errors; an empty account, a non-positive amount, a missing/empty signature,
    a stored ``tx_id`` mismatch or a bad signature are integrity errors.
    """
    _input(not isinstance(tx_raw, dict))
    for field in ("from", "to", "amount", "signature"):
        _input(field not in tx_raw)
    sender = tx_raw["from"]
    recipient = tx_raw["to"]
    amount = tx_raw["amount"]
    signature = tx_raw["signature"]

    _input(not isinstance(sender, str) or not isinstance(recipient, str))
    _input(not _is_plain_int(amount))
    _input(not isinstance(signature, str))
    _integrity(not sender or not recipient)
    _integrity(amount <= 0)
    _integrity(not signature)

    message = crypto.canonical_message(sender, recipient, amount)
    tx_id = crypto.compute_tx_id(message)
    _integrity(tx_raw.get("tx_id") != tx_id)
    _integrity(not crypto.verify_signature(sender, message, signature))
    return tx_id


def _verify_pending(pending_raw: list, chain: list[dict]) -> None:
    """Validate the mempool: well-formed entries, unique and disjoint from the
    chain (confirmed blocks and a pending tip block alike)."""
    on_chain: set[str] = set()
    for block in chain:
        on_chain.update(block["tx_ids"])
    pending_ids: set[str] = set()
    for tx_raw in pending_raw:
        tx_id = _verify_transaction(tx_raw)
        _integrity(tx_id in pending_ids)
        _integrity(tx_id in on_chain)
        pending_ids.add(tx_id)


def _recompute_index(chain_raw: list) -> dict:
    """Rebuild the confirmed-only ``index`` section (tx_id -> height).

    Mirrors ``LedgerStore._compute_derived``: a pending tip block contributes
    no index entries.
    """
    tx_index: dict[str, int] = {}
    for block_raw in chain_raw:
        if block_raw.get("status", STATUS_CONFIRMED) != STATUS_CONFIRMED:
            continue
        height = block_raw["height"]
        for tx_raw in block_raw["transactions"]:
            message = crypto.canonical_message(
                tx_raw["from"], tx_raw["to"], tx_raw["amount"]
            )
            tx_index[crypto.compute_tx_id(message)] = height
    return tx_index


def _recompute_accounts(chain_raw: list) -> dict:
    """Rebuild the ``accounts`` section from confirmed block transactions.

    Mirrors ``LedgerStore._compute_derived``: per account
    ``{"sent", "received", "transactions"}`` with transaction ids appended in
    on-chain order; pending blocks are excluded.
    """
    accounts: dict[str, dict] = {}
    for block_raw in chain_raw:
        if block_raw.get("status", STATUS_CONFIRMED) != STATUS_CONFIRMED:
            continue
        for tx_raw in block_raw["transactions"]:
            sender = tx_raw["from"]
            recipient = tx_raw["to"]
            amount = tx_raw["amount"]
            message = crypto.canonical_message(sender, recipient, amount)
            tx_id = crypto.compute_tx_id(message)
            for account in (sender, recipient):
                entry = accounts.setdefault(
                    account, {"sent": 0, "received": 0, "transactions": []}
                )
                entry["transactions"].append(tx_id)
            accounts[sender]["sent"] += amount
            accounts[recipient]["received"] += amount
    return accounts


def _compute_state_root(chain_raw: list, endowment: int) -> str:
    """Recompute the confirmed-account state Merkle root.

    Mirrors ``LedgerStore.state_root_for`` / ``account_state_rows``: rows are
    the confirmed accounts in ascending id order, each balance equal to the
    recorded endowment plus received minus sent, carrying its confirmed
    transaction ids in on-chain order.
    """
    activity = _recompute_accounts(chain_raw)
    leaves = []
    for account in sorted(activity):
        entry = activity[account]
        balance = endowment + entry["received"] - entry["sent"]
        leaves.append(
            crypto.account_state_leaf(account, balance, entry["transactions"])
        )
    return crypto.account_state_root(leaves)


def _verify_audit(events_raw: object, checkpoint_raw: dict) -> dict:
    """Verify the optional audit hash chain and the mandatory checkpoint.

    When ``audit_events`` is absent the log is treated as empty and the
    checkpoint must pin the all-zero root (exactly as a freshly written
    snapshot with no events does). Dense 1..N ids, prev_hash links and
    recomputed event_hashes follow the same rules as
    ``audit.validate_event_chain``; ``event_hash`` is
    ``SHA256(prev_hash ASCII || sorted-compact UTF-8 JSON of the event with
    the two hash fields removed)``. Malformed fields are input errors; every
    link or checkpoint mismatch is an integrity error.
    """
    events = events_raw if isinstance(events_raw, list) else []

    event_id = checkpoint_raw.get("event_id")
    event_hash_value = checkpoint_raw.get("event_hash")
    _input(not _is_plain_int(event_id) or event_id < 0)
    _input(not crypto.is_hex64(event_hash_value))

    prev_hash = audit.ZERO_HASH
    for index, event in enumerate(events):
        expected_id = index + 1
        _input(not isinstance(event, dict))
        _input(
            "event_id" not in event
            or "prev_hash" not in event
            or "event_hash" not in event
        )
        stored_id = event["event_id"]
        stored_prev = event["prev_hash"]
        stored_hash = event["event_hash"]
        _input(not _is_plain_int(stored_id))
        _input(not crypto.is_hex64(stored_prev))
        _input(not crypto.is_hex64(stored_hash))
        _integrity(stored_id != expected_id)
        _integrity(stored_prev != prev_hash)
        _integrity(audit.event_hash(prev_hash, event) != stored_hash)
        prev_hash = stored_hash

    expected_id = len(events)
    _integrity(event_id != expected_id)
    _integrity(event_hash_value != prev_hash)
    return {"event_id": event_id, "event_hash": event_hash_value}
