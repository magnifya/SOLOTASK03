"""Persistent storage: blockchain, pending set and derived indexes (JSON).

The whole state is one JSON document written atomically: a uniquely named
``.ledger-*`` snapshot is fsynced in the same directory and then promoted over
the main file with ``os.replace`` (followed by a directory fsync). Every
successful write advances a monotonic ``generation`` recorded in the
snapshot. A crash can therefore only leave behind (a) the previous main file
or (b) a fully fsynced snapshot that never got renamed — never a torn file.

On startup the main file and every sibling ``.ledger-*`` snapshot are treated
as recovery candidates. When no file exists at all, the unique genesis block
is created; otherwise each candidate is strictly validated (JSON, generation,
consecutive heights, prev_hash linkage, recomputed block hashes and Merkle
roots, per-transaction tx_id and Ed25519 signature, pending-only-at-tip and
mempool/chain de-duplication). The valid snapshot with the highest generation
wins and is promoted if it is still a temp file; same-generation content
conflicts, or a directory with no valid candidate, raise StateRecoveryError
with the offending path and reason — a fresh chain is never silently created.

One atomic write persists everything: the chain (each block carries its
confirm/rollback ``status``), a small ``state`` summary, the mempool
(``pending``), candidate fork chains (``forks``, each a full block list
anchored at the canonical genesis and keyed by its tip hash), the
confirmed-transaction ``index`` and the confirmed ``accounts`` activity.
Derived data (index/accounts) is *rebuilt* from the chain on every load and
every save — pending blocks are excluded, so a restart never resurrects
unconfirmed transactions into balances. Persisted fork candidates are
re-validated on startup and invalid ones are dropped, while canonical-chain
invalidity remains fatal. Persisted sync records are likewise re-checked: a
record whose request deadline elapsed or whose source is unknown, revoked or
registry-expired while the process was down is pruned together with its
candidate fork and earns one back-filled ``sync_expired`` audit event (deduplicated
and persisted atomically), mirroring the lazy runtime sweep; purely structural
or fingerprint/tip-integrity failures are pruned silently without an event. A
re-entrant lock serializes all updates, and a class-wide recovery lock
serializes startup scans against in-flight writes.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time

from .models import (
    STATUS_CONFIRMED,
    STATUS_PENDING,
    Block,
    Transaction,
    compute_block_hash,
)
from . import crypto

# Previous hash of the genesis block.
GENESIS_PREV_HASH = "0" * 64

# On-disk schema version, stored under "state" so future migrations are possible.
STATE_VERSION = 6

# Trust lifecycle states for persisted sources.
TRUST_ACTIVE = "active"
TRUST_REVOKED = "revoked"

# Prefix of durable snapshot temp files ("<state>.ledger-<...>") living next to
# the main state file. They double as crash-recovery candidates on startup.
SNAPSHOT_PREFIX = ".ledger-"

# Fallback per-identity endowment used only for snapshots written before
# state.initial_balance was recorded; mirrors service.DEFAULT_INITIAL_BALANCE
# without importing the service layer (which imports this module).
DEFAULT_INITIAL_BALANCE = 1_000_000


class StateRecoveryError(ValueError):
    """Raised when no usable on-disk state can be recovered on startup.

    Carries the candidate ``path`` that failed and a human-readable ``reason``
    so callers can report (or catch) the failure explicitly. The exception is a
    ``ValueError`` subclass, so older callers expecting ``ValueError`` on a
    corrupt state file keep working.
    """

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"cannot recover ledger state from {path}: {reason}")


class LedgerStore:
    def __init__(self, path: str, initial_balance: int | None = None) -> None:
        self.path = path
        self.chain: list[Block] = []
        self.pending: dict[str, Transaction] = {}
        # Candidate fork chains keyed by tip block hash. Each value is the
        # fork's full block list (including the shared genesis block).
        self.forks: dict[str, list[Block]] = {}
        # Inter-node sync submissions keyed by (source, request_id). Each
        # record stores delivery metadata plus the tip hash of the synced
        # candidate chain (kept in ``forks``) and a content fingerprint used
        # for same-key retry/idempotency checks.
        self.syncs: dict[tuple[str, str], dict] = {}
        # Persistent source-trust registry keyed by source identifier. Each
        # record is {"public_key", "expires_at", "version", "status"}.
        self.trust_sources: dict[str, dict] = {}
        # Keyless trust allowlist {source: expires_at}; preserved verbatim and
        # surfaced by GET /v1/trust for offline light clients.
        self.allowlist: dict[str, int] = {}
        # Append-only audit events, each {"event_id", "kind", "at", ...payload}.
        # event_id is the 1-based position in this list.
        self.audit_events: list[dict] = []
        # Per-identity endowment used for candidate replay checks; recorded in
        # the snapshot so recovery validates against the same convention.
        self.initial_balance: int | None = initial_balance
        # Monotonic counter bumped on every successful atomic write. It is
        # persisted with each snapshot and lets startup pick the newest one.
        self.generation: int = 0
        # Derived, confirmed-only views; rebuilt by rebuild_derived().
        self.tx_index: dict[str, int] = {}
        self.accounts: dict[str, dict] = {}
        self._lock = threading.RLock()
        self.load()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    # Serializes startup scans/promotions between threads (or two store
    # instances on the same path) within one process. All later mutations take
    # the per-store re-entrant lock.
    _recovery_lock = threading.RLock()

    def load(self) -> None:
        """Recover state from disk on startup.

        The main file *and* every sibling ``.ledger-*`` snapshot are treated
        as recovery candidates. When none exist at all, the unique genesis
        block is created (the established first-start convention); otherwise
        every candidate is strictly validated and the valid snapshot with the
        highest generation wins. A winning temp snapshot is atomically
        promoted over the main file and every judged-older or residual
        candidate is removed. Same-generation snapshots with conflicting
        content, or a directory with no valid candidate, raise
        StateRecoveryError — a fresh chain is never silently created.
        """
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        with self._recovery_lock:
            candidates = self._discover_candidates(directory)
            if not candidates:
                os.makedirs(directory, exist_ok=True)
                self.chain = [self.create_genesis()]
                self.pending = {}
                self.forks = {}
                self.syncs = {}
                self.trust_sources = {}
                self.allowlist = {}
                self.audit_events = []
                self.generation = 0
                self.rebuild_derived()
                self.save()
                return

            valid: list[tuple] = []
            errors: list[StateRecoveryError] = []
            for candidate in candidates:
                try:
                    data = self._read_candidate(candidate)
                    parsed = self._parse_snapshot(candidate, data)
                except StateRecoveryError as exc:
                    errors.append(exc)
                    continue
                valid.append(
                    (
                        parsed[2],
                        candidate,
                        parsed[0],
                        parsed[1],
                        parsed[3],
                        parsed[4],
                        parsed[5],
                        parsed[6],
                        parsed[7],
                        parsed[8],
                        parsed[9],
                    )
                )

            if not valid:
                details = "; ".join(f"{exc.path} ({exc.reason})" for exc in errors)
                raise StateRecoveryError(
                    directory, f"no valid snapshot candidate found: {details}"
                )

            max_generation = max(item[0] for item in valid)
            top = [item for item in valid if item[0] == max_generation]
            reference = self._canonical_view(
                top[0][2],
                top[0][3],
                top[0][4],
                top[0][6],
                top[0][7],
                top[0][8],
                top[0][9],
                top[0][5],
            )
            for item in top[1:]:
                if (
                    self._canonical_view(
                        item[2],
                        item[3],
                        item[4],
                        item[6],
                        item[7],
                        item[8],
                        item[9],
                        item[5],
                    )
                    != reference
                ):
                    paths = " vs ".join(item[1] for item in top)
                    raise StateRecoveryError(
                        directory,
                        f"conflicting snapshots at generation {max_generation}: {paths}",
                    )

            # Identical same-generation snapshots: keep the main file when it
            # is one of them, avoiding a pointless promotion cycle.
            main_abs = os.path.abspath(self.path)
            winner = top[0]
            for item in top:
                if os.path.abspath(item[1]) == main_abs:
                    winner = item
                    break
            (
                generation,
                winner_path,
                chain,
                pending,
                forks,
                winner_init_balance,
                syncs,
                trust_sources,
                allowlist,
                audit_events,
                lifecycle_expired,
            ) = winner

            if os.path.abspath(winner_path) != main_abs:
                # The newest durable state only ever made it to a temp
                # snapshot (a crash interrupted the promotion): promote it.
                os.replace(winner_path, self.path)
                self._fsync_dir(directory)

            self.chain = chain
            self.pending = pending
            self.forks = forks
            self.syncs = syncs
            self.trust_sources = trust_sources
            self.allowlist = allowlist
            self.audit_events = audit_events
            self.generation = generation
            # Prefer the endowment recorded by the writer; fall back to the
            # value this instance was constructed with, and finally to the
            # service default, so older snapshots without the field still
            # validate fork replays against the configured endowment.
            if winner_init_balance is not None:
                self.initial_balance = winner_init_balance
            self.rebuild_derived()
            self._cleanup_candidates(directory)
            # Re-authorization/deadline checks above may have classified live
            # records as having lapsed while the process was down. Back-fill
            # the sync_expired audit events the node would itself have written
            # had it been running, and persist the sweep atomically.
            self._backfill_sync_expired(lifecycle_expired)

    def _backfill_sync_expired(
        self,
        lifecycle_expired: list[tuple[tuple[str, str], dict]],
    ) -> None:
        """Back-fill sync_expired events for a downtime lapse and persist.

        Every record whose request deadline elapsed or whose source became
        unauthorized (unknown/revoked/registry-expired) while the process was
        down gets exactly one ``sync_expired`` event, matching the payload the
        lazy runtime sweep writes. A record already carrying such an event
        (e.g. the sweep was persisted but the process crashed before the
        response) is skipped, so an event is never written twice. New events
        continue the dense 1..N sequence and are committed together with the
        pruned records/forks in one atomic write that advances the generation;
        a failed write leaves the on-disk snapshot (and its event log)
        untouched, so a restart retries without losing or duplicating an
        event. The canonical chain is never modified here.
        """
        # Dedupe against the exact record (a (source, request_id) pair may be
        # reused after an earlier record expired and was swept), not just the
        # key: only a surviving sync_expired event naming the same tip and
        # deadline proves this specific persisted record was already swept.
        already = {
            (
                event.get("source"),
                event.get("request_id"),
                event.get("tip_hash"),
                event.get("expires_at"),
            )
            for event in self.audit_events
            if event.get("kind") == "sync_expired"
        }
        appended = 0
        for (source, request_id), rec in lifecycle_expired:
            identity = (source, request_id, rec["tip_hash"], rec["expires_at"])
            if identity in already:
                continue
            already.add(identity)
            self.append_audit_event(
                "sync_expired",
                {
                    "source": source,
                    "request_id": request_id,
                    "tip_hash": rec["tip_hash"],
                    "expires_at": rec["expires_at"],
                },
            )
            appended += 1
        if appended:
            # Atomic promotion; on failure the exception propagates and the
            # caller's process fails to start rather than serving a state whose
            # audit trail was not durably reconciled. Nothing was mutated on
            # disk, so the next attempt re-runs the back-fill cleanly.
            self.save()

    def _discover_candidates(self, directory: str) -> list[str]:
        """List the main file and sibling .ledger-* snapshots (if any)."""
        candidates: list[str] = []
        if os.path.exists(self.path):
            candidates.append(self.path)
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            return candidates
        main_name = os.path.basename(self.path)
        for name in names:
            if name == main_name or not name.startswith(SNAPSHOT_PREFIX):
                continue
            full = os.path.join(directory, name)
            if os.path.isfile(full):
                candidates.append(full)
        return candidates

    @staticmethod
    def _canonical_view(
        chain: list[Block],
        pending: dict[str, Transaction],
        forks: dict[str, list[Block]],
        syncs: dict[tuple[str, str], dict] | None = None,
        trust_sources: dict[str, dict] | None = None,
        allowlist: dict[str, int] | None = None,
        audit_events: list[dict] | None = None,
        initial_balance: int | None = None,
    ) -> str:
        """Order-independent canonical content hash for conflict detection.

        The recorded ``initial_balance`` is part of the authoritative view: two
        same-generation snapshots with identical chains but a different
        endowment describe a different replay judgment and must conflict.
        """
        sync_records = [
            {
                "source": key[0],
                "request_id": key[1],
                "tip_hash": rec["tip_hash"],
                "expires_at": rec["expires_at"],
                "fingerprint": rec["fingerprint"],
            }
            for key, rec in sorted((syncs or {}).items())
        ]
        trust_records = [
            {"source": source, **rec}
            for source, rec in sorted((trust_sources or {}).items())
        ]
        return json.dumps(
            {
                "initial_balance": initial_balance,
                "chain": [block.to_dict() for block in chain],
                "pending": [pending[tx_id].to_dict() for tx_id in sorted(pending)],
                "forks": [
                    [block.to_dict() for block in forks[tip]]
                    for tip in sorted(forks)
                ],
                "syncs": sync_records,
                "trust_sources": trust_records,
                "allowlist": dict(sorted((allowlist or {}).items())),
                "audit_events": audit_events or [],
            },
            sort_keys=True,
            ensure_ascii=False,
        )

    def _cleanup_candidates(self, directory: str) -> None:
        """Remove every residual .ledger-* snapshot next to the main file.

        After recovery these are by definition unusable leftovers: older
        generations, an identical post-promotion residue, or a partially
        written (invalid) file. The promoted/main state is never touched.
        """
        main_name = os.path.basename(self.path)
        for name in list(os.listdir(directory)):
            if not name.startswith(SNAPSHOT_PREFIX) or name == main_name:
                continue
            full = os.path.join(directory, name)
            try:
                if os.path.isfile(full) or os.path.islink(full):
                    os.unlink(full)
            except OSError:
                pass
        self._fsync_dir(directory)

    @staticmethod
    def _read_candidate(path: str) -> dict:
        """Read and JSON-decode one snapshot file.

        Any I/O or JSON failure becomes a StateRecoveryError carrying the
        offending path, never a silent fall-back.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError as exc:
            raise StateRecoveryError(path, f"cannot read file: {exc}") from exc
        except (ValueError, UnicodeDecodeError) as exc:
            raise StateRecoveryError(path, f"invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise StateRecoveryError(path, "snapshot root must be a JSON object")
        return data

    def _parse_snapshot(
        self, path: str, data: dict
    ) -> tuple[
        list[Block],
        dict[str, Transaction],
        int,
        dict[str, list[Block]],
        int | None,
        dict[tuple[str, str], dict],
        dict[str, dict],
        dict[str, int],
        list[dict],
        list[tuple[tuple[str, str], dict]],
    ]:
        """Strictly validate one decoded snapshot.

        Checks the persisted generation, consecutive heights, prev_hash
        linkage, recomputed block hashes, recomputed Merkle roots, every
        transaction's tx_id and Ed25519 signature, the pending-only-at-tip
        rule, and de-duplication between mempool and chain. Returns the parsed
        chain, mempool, generation, candidate forks and the recorded initial
        balance. Raises StateRecoveryError on the first defect, with ``path``
        identifying the candidate.
        """
        def fail(reason: str) -> None:
            raise StateRecoveryError(path, reason)

        chain_raw = data.get("chain")
        if not isinstance(chain_raw, list) or not chain_raw:
            fail("snapshot must contain a non-empty chain")

        state = data.get("state")
        # A pre-state-section snapshot is accepted: the chain itself is fully
        # self-verifying below. A present non-object section is corruption.
        if state is None:
            state = {}
        if not isinstance(state, dict):
            fail("invalid 'state' section: must be a JSON object")
        generation = state.get("generation", 0)
        # bool is an int subclass; reject it explicitly along with negatives.
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            fail("state.generation must be a non-negative integer")
        initial_balance = state.get("initial_balance")
        if initial_balance is not None and (
            isinstance(initial_balance, bool)
            or not isinstance(initial_balance, int)
            or initial_balance <= 0
        ):
            fail("state.initial_balance must be a positive integer")

        chain: list[Block] = []
        seen_tx_ids: set[str] = set()
        for i, block_raw in enumerate(chain_raw):
            if not isinstance(block_raw, dict):
                fail(f"block at position {i} is not a JSON object")
            try:
                block = Block.from_dict(block_raw)
            except (KeyError, TypeError, ValueError) as exc:
                fail(f"block {i} is malformed: {exc}")
            if block.height != i:
                fail(
                    f"block at position {i} has non-consecutive height "
                    f"{block.height}"
                )
            expected_prev = GENESIS_PREV_HASH if i == 0 else chain[i - 1].block_hash
            if block.prev_hash != expected_prev:
                fail(f"block {block.height} has a mismatched prev_hash")
            if block.status not in (STATUS_PENDING, STATUS_CONFIRMED):
                fail(f"block {block.height} has unknown status {block.status!r}")
            if i == 0 and (
                block.status != STATUS_CONFIRMED or block.transactions
            ):
                fail("genesis block must be confirmed and carry no transactions")
            # Pending blocks may only sit at the chain tip.
            if i < len(chain_raw) - 1 and block.status == STATUS_PENDING:
                fail(f"pending block {block.height} is not the chain tip")

            # Validate every transaction: stored tx_id, recomputed tx_id and
            # the Ed25519 signature.
            tx_ids: list[str] = []
            txs_raw = block_raw.get("transactions")
            if not isinstance(txs_raw, list):
                fail(f"block {block.height} transactions must be a list")
            for j, tx in enumerate(block.transactions):
                self._validate_transaction(path, tx)
                stored_tx_id = txs_raw[j].get("tx_id") if isinstance(txs_raw[j], dict) else None
                if stored_tx_id != tx.tx_id:
                    fail(
                        f"transaction in block {block.height} has a mismatched "
                        f"tx_id (stored {stored_tx_id!r}, recomputed {tx.tx_id})"
                    )
                if tx.tx_id in seen_tx_ids:
                    fail(
                        f"duplicate transaction {tx.tx_id} in block "
                        f"{block.height}"
                    )
                seen_tx_ids.add(tx.tx_id)
                tx_ids.append(tx.tx_id)
            # Blocks store transactions in ascending tx_id order.
            if tx_ids != sorted(tx_ids):
                fail(f"block {block.height} transactions are not tx_id sorted")

            recomputed_merkle = crypto.merkle_root(tx_ids)
            if recomputed_merkle != block.merkle_root:
                fail(f"block {block.height} Merkle root mismatch")
            recomputed_hash = compute_block_hash(
                block.height, block.prev_hash, block.merkle_root
            )
            if recomputed_hash != block.block_hash:
                fail(f"block {block.height} block_hash mismatch")
            chain.append(block)

        # Mempool: well-formed, no internal duplicates, never overlapping the
        # chain (neither confirmed nor pending-block transactions).
        pending: dict[str, Transaction] = {}
        pending_raw = data.get("pending", [])
        if not isinstance(pending_raw, list):
            fail("'pending' must be a list")
        for tx_raw in pending_raw:
            if not isinstance(tx_raw, dict):
                fail("pending entry is not a JSON object")
            try:
                tx = Transaction.from_dict(tx_raw)
            except (KeyError, TypeError, ValueError) as exc:
                fail(f"pending transaction is malformed: {exc}")
            self._validate_transaction(path, tx)
            if tx_raw.get("tx_id") != tx.tx_id:
                fail(
                    f"pending transaction has a mismatched tx_id (stored "
                    f"{tx_raw.get('tx_id')!r}, recomputed {tx.tx_id})"
                )
            if tx.tx_id in pending:
                fail(f"duplicate pending transaction {tx.tx_id} in mempool")
            if tx.tx_id in seen_tx_ids:
                fail(
                    f"pending transaction {tx.tx_id} already exists in a block"
                )
            pending[tx.tx_id] = tx

        # Cross-check the persisted tip summary against the chain tail.
        tip = chain[-1]
        if state.get("height") is not None and state["height"] != tip.height:
            fail("state.height does not match the chain tip")
        if state.get("tip_hash") is not None and state["tip_hash"] != tip.block_hash:
            fail("state.tip_hash does not match the chain tip")
        if (
            state.get("tip_status") is not None
            and state["tip_status"] != tip.status
        ):
            fail("state.tip_status does not match the chain tip")

        # The recorded endowment is the *only* balance-replay parameter for the
        # persisted fork candidates: revalidation below must use it rather than
        # this instance's constructor argument, so starting with a different
        # --initial-balance can never change a fork's legality. Only a legacy
        # snapshot that records no endowment falls back to the configured (then
        # the default) value; every snapshot written by current code records it.
        replay_endowment = initial_balance
        if replay_endowment is None:
            replay_endowment = (
                self.initial_balance
                if self.initial_balance is not None
                else DEFAULT_INITIAL_BALANCE
            )

        forks = self._parse_persisted_forks(
            data.get("forks", []), chain, replay_endowment
        )
        # The trust registry is authoritative configuration and must be parsed
        # before the sync records, whose sources are re-authorized against it.
        trust_sources = self._parse_persisted_trust_sources(
            data.get("trust_sources", []), path
        )
        syncs, synced_tips, lifecycle_expired = self._parse_persisted_syncs(
            data.get("syncs", []), forks, chain, trust_sources
        )
        # A fork brought in only by a sync record loses its right to exist once
        # that record is gone (expired/unauthorized/invalid on restart):
        # without this, the independently-persisted fork would resurrect as a
        # never-expiring candidate. Direct submissions carry no sync record and
        # are untouched.
        live_tips = {rec["tip_hash"] for rec in syncs.values()}
        canonical_hashes = {block.block_hash for block in chain}
        for tip in synced_tips - live_tips - canonical_hashes:
            forks.pop(tip, None)
        allowlist = self._parse_persisted_allowlist(data.get("allowlist", {}), path)
        audit_events = self._parse_persisted_audit_events(
            data.get("audit_events", []), path
        )
        return (
            chain,
            pending,
            generation,
            forks,
            initial_balance,
            syncs,
            trust_sources,
            allowlist,
            audit_events,
            lifecycle_expired,
        )

    @staticmethod
    def _parse_persisted_trust_sources(
        raw: object, path: str
    ) -> dict[str, dict]:
        """Strictly parse the persisted source-trust registry.

        Unlike candidate forks (re-validated and silently dropped when stale),
        the trust registry is authoritative configuration: a malformed entry
        is snapshot corruption and fails recovery rather than being dropped.
        Each record needs a non-empty source, a 64-char lowercase hex public
        key, an integer expiry, a positive integer version and a known status.
        """
        if raw is None:
            return {}
        if not isinstance(raw, list):
            raise StateRecoveryError(path, "'trust_sources' must be a list")
        sources: dict[str, dict] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                raise StateRecoveryError(path, "trust source entry must be an object")
            source = entry.get("source")
            public_key = entry.get("public_key")
            expires_at = entry.get("expires_at")
            version = entry.get("version")
            status = entry.get("status")
            if not isinstance(source, str) or not source:
                raise StateRecoveryError(path, "trust source must be a non-empty string")
            if not crypto.is_hex64(public_key):
                raise StateRecoveryError(
                    path, f"trust source {source!r} has an invalid public_key"
                )
            if isinstance(expires_at, bool) or not isinstance(expires_at, int):
                raise StateRecoveryError(
                    path, f"trust source {source!r} expires_at must be an integer"
                )
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version < 1
            ):
                raise StateRecoveryError(
                    path, f"trust source {source!r} version must be a positive integer"
                )
            if status not in (TRUST_ACTIVE, TRUST_REVOKED):
                raise StateRecoveryError(
                    path, f"trust source {source!r} has invalid status {status!r}"
                )
            if source in sources:
                raise StateRecoveryError(
                    path, f"duplicate trust source {source!r} in snapshot"
                )
            sources[source] = {
                "public_key": public_key,
                "expires_at": expires_at,
                "version": version,
                "status": status,
            }
        return sources

    @staticmethod
    def _parse_persisted_allowlist(raw: object, path: str) -> dict[str, int]:
        """Strictly parse the keyless ``{source: expires_at}`` allowlist."""
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise StateRecoveryError(path, "'allowlist' must be a JSON object")
        allowlist: dict[str, int] = {}
        for source, expires_at in raw.items():
            if not isinstance(source, str) or not source:
                raise StateRecoveryError(path, "allowlist source must be a non-empty string")
            if isinstance(expires_at, bool) or not isinstance(expires_at, int):
                raise StateRecoveryError(
                    path, f"allowlist entry {source!r} expires_at must be an integer"
                )
            allowlist[source] = expires_at
        return allowlist

    @staticmethod
    def _parse_persisted_audit_events(raw: object, path: str) -> list[dict]:
        """Strictly parse the append-only audit event log.

        Every event is a JSON object carrying an integer ``at`` timestamp and a
        string ``kind``; ``event_id`` values must be exactly 1..N with no gaps
        or duplicates, since the id is the event's permanent audit position.
        Payload fields beyond those three are retained verbatim.
        """
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise StateRecoveryError(path, "'audit_events' must be a list")
        events: list[dict] = []
        for i, event in enumerate(raw):
            if not isinstance(event, dict):
                raise StateRecoveryError(path, f"audit event {i + 1} must be an object")
            event_id = event.get("event_id")
            kind = event.get("kind")
            at = event.get("at")
            if (
                isinstance(event_id, bool)
                or not isinstance(event_id, int)
                or event_id != i + 1
            ):
                raise StateRecoveryError(
                    path,
                    f"audit event at position {i} has event_id {event_id!r}, "
                    f"expected {i + 1}",
                )
            if not isinstance(kind, str) or not kind:
                raise StateRecoveryError(path, f"audit event {event_id} needs a kind")
            if isinstance(at, bool) or not isinstance(at, (int, float)):
                raise StateRecoveryError(path, f"audit event {event_id} needs a numeric 'at'")
            events.append(dict(event))
        return events

    def _parse_persisted_syncs(
        self,
        syncs_raw: object,
        forks: dict[str, list[Block]],
        canonical_chain: list[Block],
        trust_sources: dict[str, dict] | None = None,
    ) -> tuple[
        dict[tuple[str, str], dict],
        set[str],
        list[tuple[tuple[str, str], dict]],
    ]:
        """Parse persisted sync records, dropping unusable ones on restart.

        A record is kept only when it is structurally valid, has not yet
        expired, its source is still an active, unexpired entry of the
        persistent trust registry, and its tip references either a surviving
        candidate fork or a block on the canonical chain (a synced candidate
        may have been adopted). Records are sorted into two failure classes:

        * *lifecycle* expiry — the request deadline elapsed or the source is
          unknown, revoked or registry-expired. These are exactly the cases the
          running node would itself have swept into a ``sync_expired`` audit
          event, so the caller back-fills one such event per record (never
          duplicating an event already present) when the deadline or the
          authorization lapsed while the process was down.
        * *integrity* failure — a malformed record, a tip resolving to neither
          a surviving fork nor the canonical chain, or a content fingerprint
          that no longer matches the delivered candidate. Such a record could
          never have produced a runtime sweep, so it is pruned silently (its
          historical audit events are left untouched regardless).

        Returns the surviving records, every tip any record claims provenance
        for (including dropped ones, so the caller can drop forks only a pruned
        sync kept alive), and the lifecycle-expired records owed a
        ``sync_expired`` event, sorted by (source, request_id).
        """
        if not isinstance(syncs_raw, list):
            return {}, set(), []
        now = time.time()
        trust_sources = trust_sources or {}
        # Map every canonical block hash to the chain prefix ending there:
        # this is the exact "candidate" document that was delivered for a tip
        # since adopted onto the canonical chain.
        canonical_prefixes: dict[str, list[dict]] = {}
        prefix: list[dict] = []
        for block in canonical_chain:
            prefix = prefix + [block.to_dict()]
            canonical_prefixes[block.block_hash] = prefix
        syncs: dict[tuple[str, str], dict] = {}
        synced_tips: set[str] = set()
        lifecycle_expired: list[tuple[tuple[str, str], dict]] = []
        lifecycle_keys: set[tuple[str, str]] = set()
        for rec_raw in syncs_raw:
            if not isinstance(rec_raw, dict):
                continue
            source = rec_raw.get("source")
            request_id = rec_raw.get("request_id")
            tip_hash = rec_raw.get("tip_hash")
            expires_at = rec_raw.get("expires_at")
            fingerprint = rec_raw.get("fingerprint")
            if not isinstance(source, str) or not source:
                continue
            if not isinstance(request_id, str) or not request_id:
                continue
            if not crypto.is_hex64(tip_hash):
                continue
            # Provenance is recorded even for dropped records: it proves the
            # matching fork must not outlive the sync that delivered it.
            synced_tips.add(tip_hash)
            # Structural/envelope defects are an integrity failure, not a
            # lifecycle one: a record the running node could never have swept
            # earns no back-filled expiry event.
            if (
                isinstance(expires_at, bool)
                or not isinstance(expires_at, int)
            ):
                continue
            if not isinstance(fingerprint, str) or not fingerprint:
                continue
            key = (source, request_id)
            # Lifecycle class first: a request deadline that elapsed while the
            # process was down is indistinguishable from a lazy runtime sweep,
            # so it is owed one sync_expired event. Each record earns at most
            # one event even when it is both expired and de-authorized.
            if expires_at <= now:
                if key not in lifecycle_keys:
                    lifecycle_keys.add(key)
                    lifecycle_expired.append(
                        (
                            key,
                            {
                                "tip_hash": tip_hash,
                                "expires_at": expires_at,
                                "fingerprint": fingerprint,
                            },
                        )
                    )
                continue
            # Re-authorization on restart: the trust decision recorded at
            # delivery is re-checked against the current registry. A source
            # rotated away, revoked or expired since then invalidates its
            # pending records; this is the same lifecycle class as a deadline
            # expiry and is likewise owed one sync_expired event. Historical
            # audit events stay queryable.
            trusted = trust_sources.get(source)
            if (
                trusted is None
                or trusted.get("status") != TRUST_ACTIVE
                or not isinstance(trusted.get("expires_at"), int)
                or isinstance(trusted.get("expires_at"), bool)
                or trusted["expires_at"] <= now
            ):
                if key not in lifecycle_keys:
                    lifecycle_keys.add(key)
                    lifecycle_expired.append(
                        (
                            key,
                            {
                                "tip_hash": tip_hash,
                                "expires_at": expires_at,
                                "fingerprint": fingerprint,
                            },
                        )
                    )
                continue
            # Re-resolve the delivered candidate (a surviving fork, or the
            # canonical prefix for an adopted tip) and recompute its content
            # fingerprint: a tampered tip summary, deadline or request body
            # must not be trusted on the strength of the persisted record. A
            # failure here is an integrity defect, pruned without an event.
            blocks_raw: list[dict] | None = None
            surviving_fork = forks.get(tip_hash)
            if surviving_fork is not None:
                blocks_raw = [block.to_dict() for block in surviving_fork]
            else:
                blocks_raw = canonical_prefixes.get(tip_hash)
            if blocks_raw is None:
                continue
            if self._candidate_fingerprint(blocks_raw) != fingerprint:
                continue
            if key in syncs:
                continue
            syncs[key] = {
                "tip_hash": tip_hash,
                "expires_at": expires_at,
                "fingerprint": fingerprint,
            }
        lifecycle_expired.sort(key=lambda entry: entry[0])
        return syncs, synced_tips, lifecycle_expired

    @staticmethod
    def _candidate_fingerprint(blocks_raw: list) -> str:
        """Stable SHA-256 content fingerprint of a candidate's raw block list.

        Mirrors ``LedgerService._candidate_fingerprint`` so recovery can check
        the persisted record against the re-parsed candidate without importing
        the service layer. Key order and whitespace are normalized.
        """
        return hashlib.sha256(
            json.dumps(blocks_raw, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _validate_transaction(path: str, tx: Transaction) -> None:
        """Recompute a transaction's id and check its Ed25519 signature."""
        if (
            not isinstance(tx.sender, str)
            or not isinstance(tx.recipient, str)
            or not tx.sender
            or not tx.recipient
        ):
            raise StateRecoveryError(path, "transaction has invalid from/to fields")
        if (
            isinstance(tx.amount, bool)
            or not isinstance(tx.amount, int)
            or tx.amount <= 0
        ):
            raise StateRecoveryError(
                path, f"transaction {getattr(tx, 'sender', '?')} has non-positive amount"
            )
        if not isinstance(tx.signature, str) or not tx.signature:
            raise StateRecoveryError(path, "transaction is missing a signature")
        if not crypto.verify_signature(tx.sender, tx.message, tx.signature):
            raise StateRecoveryError(
                path, f"transaction {tx.tx_id} has an invalid signature"
            )

    @staticmethod
    def create_genesis() -> Block:
        # The genesis block is born confirmed.
        return Block.create(
            height=0,
            prev_hash=GENESIS_PREV_HASH,
            transactions=[],
            status=STATUS_CONFIRMED,
        )

    def _compute_derived(self) -> tuple[dict[str, int], dict[str, dict]]:
        """Build the confirmed-only transaction index and account activity.

        Pending blocks are excluded: only confirmed blocks contribute to
        balances and to the tx_id -> height index. Pure: it returns fresh
        dicts and never mutates store state, so callers can compute a
        prospective view and publish it only after a successful write.
        """
        tx_index: dict[str, int] = {}
        accounts: dict[str, dict] = {}
        for block in self.chain:
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

    def rebuild_derived(self) -> None:
        """Rebuild the confirmed-only transaction index and account activity.

        Pending blocks are excluded: only confirmed blocks contribute to
        balances and to the tx_id -> height index.
        """
        self.tx_index, self.accounts = self._compute_derived()

    def save(self) -> None:
        """Atomically persist chain, state, pending set, index and accounts.

        The new state is first written to a uniquely named ``.ledger-*``
        snapshot in the same directory and force-fsynced; only after that does
        an atomic ``os.replace`` promote it to the main file. A crash between
        the fsync and the promotion leaves the snapshot behind, where the
        startup scan finds it as a recovery candidate. The in-memory
        ``generation`` is advanced only after the promotion succeeds, so every
        *successful* atomic write corresponds to exactly one generation.
        """
        # Compute the prospective confirmed-only views WITHOUT publishing them:
        # they describe the *post-write* chain and must not become visible in
        # memory until the promotion succeeds. A failure anywhere below leaves
        # ``self.tx_index``/``self.accounts`` describing the last durably
        # committed chain, which is exactly the state the caller's own rollback
        # restores the rest of the fields to.
        next_index, next_accounts = self._compute_derived()
        next_generation = self.generation + 1
        data = {
            "state": {
                "version": STATE_VERSION,
                "generation": next_generation,
                "height": self.chain[-1].height,
                "tip_hash": self.chain[-1].block_hash,
                "tip_status": self.chain[-1].status,
                "initial_balance": self.initial_balance,
            },
            "chain": [block.to_dict() for block in self.chain],
            "pending": [tx.to_dict() for tx in self.pending.values()],
            "index": dict(next_index),
            "accounts": next_accounts,
        }
        # Only persist a forks section when candidates exist so a chain with
        # no forks keeps the canonical snapshot layout; loads default to [].
        if self.forks:
            data["forks"] = [
                [block.to_dict() for block in fork]
                for fork in sorted(self.forks.values(), key=lambda f: f[-1].block_hash)
            ]
        # Sync metadata is persisted in the same atomic document as the
        # candidate chains it references.
        if self.syncs:
            data["syncs"] = [
                {
                    "source": key[0],
                    "request_id": key[1],
                    "tip_hash": rec["tip_hash"],
                    "expires_at": rec["expires_at"],
                    "fingerprint": rec["fingerprint"],
                }
                for key, rec in sorted(self.syncs.items())
            ]
        # Persistent source-trust registry and the keyless allowlist are part
        # of the same atomic document as every state change they describe.
        if self.trust_sources:
            data["trust_sources"] = [
                {"source": source, **self.trust_sources[source]}
                for source in sorted(self.trust_sources)
            ]
        if self.allowlist:
            data["allowlist"] = dict(sorted(self.allowlist.items()))
        # The audit trail is append-only; every trust change and every sync
        # reception/adoption/expiry is recorded here in write order.
        if self.audit_events:
            data["audit_events"] = list(self.audit_events)
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        # Hold the class-wide recovery lock while a .ledger-* snapshot exists
        # on disk, so a concurrent in-process LedgerStore construction cannot
        # scan a half-written promotion.
        with self._recovery_lock:
            fd, tmp_path = tempfile.mkstemp(
                prefix=SNAPSHOT_PREFIX,
                suffix=f".gen{next_generation}",
                dir=directory,
            )
            promoted = False
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, sort_keys=True)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_path, self.path)
                promoted = True
                self._fsync_dir(directory)
                # Promotion is durable: now publish the prospective derived
                # views and advance the generation, together and last, so a
                # successful write is the only thing that changes memory.
                self.tx_index = next_index
                self.accounts = next_accounts
                self.generation = next_generation
            finally:
                if not promoted and os.path.exists(tmp_path):
                    # Promotion never happened: drop the half-written candidate so
                    # it cannot masquerade as a recoverable snapshot. A candidate
                    # written and fsynced *before* a crash during replace survives
                    # precisely because that crash skips this cleanup.
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

    @staticmethod
    def _fsync_dir(directory: str) -> None:
        """Best-effort directory fsync so a rename survives a power loss."""
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

    # -- chain helpers --------------------------------------------------------

    def tip(self) -> Block:
        return self.chain[-1]

    def tip_hash(self) -> str:
        return self.chain[-1].block_hash

    def next_height(self) -> int:
        return self.chain[-1].height + 1

    def tip_is_pending(self) -> bool:
        return self.chain[-1].status == STATUS_PENDING

    def block_at(self, height: int) -> Block | None:
        if 0 <= height < len(self.chain) and self.chain[height].height == height:
            return self.chain[height]
        return None

    def rollback_tip(self) -> Block:
        """Remove the pending tip block and return its transactions to the mempool.

        Transactions are restored de-duplicated: an id already present in the
        pending set (resubmitted while the block was unconfirmed) is kept as
        is, not overwritten. Caller must hold the lock and must have checked
        that the tip is a pending block. Does not save; callers persist.
        """
        block = self.chain.pop()
        for tx in block.transactions:
            self.pending.setdefault(tx.tx_id, tx)
        return block

    # -- fork candidates ------------------------------------------------------

    @staticmethod
    def _valid_tx_fields(tx: Transaction) -> None:
        """Structural checks shared by candidate submission and recovery."""
        if not isinstance(tx.sender, str) or not tx.sender:
            raise ValueError("transaction has an invalid 'from' field")
        if not isinstance(tx.recipient, str) or not tx.recipient:
            raise ValueError("transaction has an invalid 'to' field")
        if isinstance(tx.amount, bool) or not isinstance(tx.amount, int) or tx.amount <= 0:
            raise ValueError("transaction amount must be a positive integer")
        if not isinstance(tx.signature, str) or not tx.signature:
            raise ValueError("transaction is missing a signature")

    def _parse_verified_chain(
        self, blocks_raw: object, endowment: int, genesis: Block | None = None
    ) -> list[Block]:
        """Strictly validate a block list submitted as (or persisted as) a fork.

        The list must start from the canonical genesis block, connect through
        consecutive heights and prev_hash values, and carry recomputed-correct
        Merkle roots and block hashes. Transactions must have valid Ed25519
        signatures, ascending and globally unique tx_ids, and a replay from the
        per-identity endowment must never overspend. All blocks must be
        confirmed except an optional pending tip. Raises ValueError on any
        defect.
        """
        if not isinstance(blocks_raw, list) or not blocks_raw:
            raise ValueError("'blocks' must be a non-empty list")
        genesis = genesis if genesis is not None else self.chain[0]
        blocks: list[Block] = []
        seen_tx_ids: set[str] = set()
        for i, block_raw in enumerate(blocks_raw):
            if not isinstance(block_raw, dict):
                raise ValueError(f"block at position {i} is not a JSON object")
            try:
                block = Block.from_dict(block_raw)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"block {i} is malformed: {exc}") from exc
            if isinstance(block.height, bool) or block.height != i:
                raise ValueError(
                    f"block at position {i} has non-consecutive height {block.height}"
                )
            expected_prev = GENESIS_PREV_HASH if i == 0 else blocks[i - 1].block_hash
            if block.prev_hash != expected_prev:
                raise ValueError(f"block {i} has a mismatched prev_hash")
            if block.status not in (STATUS_PENDING, STATUS_CONFIRMED):
                raise ValueError(f"block {i} has unknown status {block.status!r}")
            if i == 0:
                # The candidate must connect to *the* canonical genesis.
                if (
                    block.status != STATUS_CONFIRMED
                    or block.transactions
                    or block.block_hash != genesis.block_hash
                    or block.merkle_root != genesis.merkle_root
                ):
                    raise ValueError("first block must be the canonical genesis block")
            elif i < len(blocks_raw) - 1 and block.status == STATUS_PENDING:
                raise ValueError(f"pending block {i} is not the chain tip")

            txs_raw = block_raw.get("transactions")
            if not isinstance(txs_raw, list):
                raise ValueError(f"block {i} transactions must be a list")
            tx_ids: list[str] = []
            for j, tx in enumerate(block.transactions):
                self._valid_tx_fields(tx)
                if not crypto.verify_signature(tx.sender, tx.message, tx.signature):
                    raise ValueError(f"block {i} transaction {j} has an invalid signature")
                stored_id = txs_raw[j].get("tx_id") if isinstance(txs_raw[j], dict) else None
                if stored_id != tx.tx_id:
                    raise ValueError(
                        f"block {i} transaction {j} has a mismatched tx_id"
                    )
                if tx.tx_id in seen_tx_ids:
                    raise ValueError(f"duplicate transaction {tx.tx_id} in candidate")
                seen_tx_ids.add(tx.tx_id)
                tx_ids.append(tx.tx_id)
            if tx_ids != sorted(tx_ids):
                raise ValueError(f"block {i} transactions are not tx_id sorted")
            if crypto.merkle_root(tx_ids) != block.merkle_root:
                raise ValueError(f"block {i} Merkle root mismatch")
            if (
                compute_block_hash(block.height, block.prev_hash, block.merkle_root)
                != block.block_hash
            ):
                raise ValueError(f"block {i} block_hash mismatch")
            blocks.append(block)

        # Replay every transaction from the per-identity endowment; unconfirmed
        # (pending tip) transactions are included so a candidate can never hide
        # an overspend behind a pending final block.
        balances: dict[str, int] = {}
        for block in blocks:
            for tx in block.transactions:
                sender_balance = balances.get(tx.sender, endowment)
                if sender_balance < tx.amount:
                    raise ValueError(
                        f"replay overspend by {tx.sender} in block {block.height}"
                    )
                balances[tx.sender] = sender_balance - tx.amount
                balances[tx.recipient] = balances.get(tx.recipient, endowment) + tx.amount
        return blocks

    def validate_fork_blocks(self, blocks_raw: object) -> list[Block]:
        """Validate and parse a candidate fork submitted by a client.

        The blocks must start from the canonical genesis block, connect via
        consecutive heights and prev_hash, carry correct block hashes and
        Merkle roots, unique ascending tx_ids with valid Ed25519 signatures and
        no replay overspend, and be all confirmed except an optional pending
        tip. Raises ValueError with a descriptive reason on any defect.
        """
        endowment = (
            self.initial_balance if self.initial_balance is not None else 1_000_000
        )
        return self._parse_verified_chain(blocks_raw, endowment)

    def _parse_persisted_forks(
        self,
        forks_raw: object,
        canonical_chain: list[Block],
        endowment: int | None = None,
    ) -> dict[str, list[Block]]:
        """Parse persisted candidate forks, dropping invalid ones on restart.

        Every stored fork is re-validated exactly like a fresh submission
        (genesis connection, hashes, Merkle roots, signatures, uniqueness,
        replay). A fork that no longer validates is silently discarded rather
        than failing recovery of the canonical chain. Recovery of the canonical
        chain itself remains strict and still raises StateRecoveryError. The
        replay uses ``endowment`` — the value recorded in this snapshot — rather
        than the startup argument, so a different launch parameter cannot make
        a persisted fork legal or illegal.
        """
        if not isinstance(forks_raw, list):
            return {}
        if endowment is None:
            endowment = DEFAULT_INITIAL_BALANCE
        genesis = canonical_chain[0]
        forks: dict[str, list[Block]] = {}
        for entry in forks_raw:
            try:
                fork = self._parse_verified_chain(entry, endowment, genesis)
            except (ValueError, KeyError, TypeError):
                continue
            if not fork or fork[0].block_hash != genesis.block_hash:
                continue
            tip_hash = fork[-1].block_hash
            # The canonical chain (or a strict prefix of it, matched by any
            # canonical block hash) is never also stored as a candidate.
            if any(tip_hash == block.block_hash for block in canonical_chain):
                continue
            forks.setdefault(tip_hash, fork)
        return forks

    def replace_chain(self, new_chain: list[Block]) -> None:
        """Atomically adopt a fork: swap the canonical chain, reconcile the
        mempool (old-chain-only confirmed transactions return de-duplicated;
        pending-block transactions never enter the pool) and rebuild indexes.
        Does not save; the caller persists.
        """
        old_confirmed_ids = {
            tx.tx_id
            for block in self.chain
            if block.status == STATUS_CONFIRMED
            for tx in block.transactions
        }
        new_ids = {tx.tx_id for block in new_chain for tx in block.transactions}
        old_tx_by_id = {
            tx.tx_id: tx
            for block in self.chain
            for tx in block.transactions
        }
        # Transactions unique to the superseded chain's confirmed history go
        # back to the mempool, de-duplicated against anything already queued.
        # Transactions from the old pending tip are not in old_confirmed_ids,
        # so they are dropped, never re-enqueued.
        for tx_id in old_confirmed_ids - new_ids:
            self.pending.setdefault(tx_id, old_tx_by_id[tx_id])
        # Transactions now on the adopted chain must leave the mempool.
        for tx_id in new_ids:
            self.pending.pop(tx_id, None)
        self.chain = new_chain
        self.rebuild_derived()

    # -- sync records ---------------------------------------------------------

    def append_audit_event(self, kind: str, payload: dict, at: float | None = None) -> dict:
        """Append an audit event in memory with the next monotonic event_id.

        Does not save; the caller persists the event together with the state
        change it describes in one atomic write. Caller must hold the lock.
        """
        event = {
            "event_id": len(self.audit_events) + 1,
            "kind": kind,
            "at": time.time() if at is None else at,
        }
        event.update(payload)
        self.audit_events.append(event)
        return event

    def prune_syncs(
        self, now: float | None = None
    ) -> tuple[list[str], dict[tuple[str, str], dict]]:
        """Drop expired sync records in memory.

        A record expires once ``expires_at`` has passed. Returns the orphaned
        tip hashes together with every removed record (keyed by
        ``(source, request_id)``) so the caller can persist the sweep
        atomically and restore the pre-cleanup state if that write fails.
        Tips adopted onto the canonical chain are not present in ``forks`` and
        are simply skipped when the caller reconciles them. Does not save; the
        caller persists.
        """
        current = time.time() if now is None else now
        expired_tips: list[str] = []
        removed: dict[tuple[str, str], dict] = {}
        for key in list(self.syncs):
            rec = self.syncs[key]
            if rec["expires_at"] <= current:
                expired_tips.append(rec["tip_hash"])
                removed[key] = rec
                del self.syncs[key]
        return expired_tips, removed

    def restore_syncs(
        self,
        removed: dict[tuple[str, str], dict],
        forks: dict[str, list[Block]],
    ) -> None:
        """Restore sync records and candidate forks removed by a failed sweep.

        Only records still missing are re-inserted, and the matching candidate
        forks are put back only when no other live record still references the
        tip. Caller must hold the lock.
        """
        for key, rec in removed.items():
            self.syncs.setdefault(key, rec)
        for tip, fork in forks.items():
            self.forks.setdefault(tip, fork)
