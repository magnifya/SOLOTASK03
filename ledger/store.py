"""Persistent storage: blockchain, pending set and derived indexes (JSON file).

The whole state lives in one JSON file written atomically (temp file plus
``os.replace``), which is sufficient for a single-process ledger. A
re-entrant lock guards state so the threaded HTTP server serializes updates.

One atomic write persists everything: the chain (each block carries its
confirm/rollback ``status``), a small ``state`` summary (including a
monotonically increasing ``generation``), the mempool (``pending``), the
confirmed-transaction ``index`` and the confirmed ``accounts`` activity.
Derived data (index/accounts) is *rebuilt* from the chain on every load and
every save — pending blocks are excluded, so a restart never resurrects
unconfirmed transactions into balances.

Crash recovery
--------------
Each save writes and fsyncs a ``.ledger-*`` snapshot in the state directory
and only then atomically replaces the main file (fsyncing the directory).
On startup the main file and every leftover ``.ledger-*`` candidate are
fully validated (JSON shape, generation, consecutive heights, prev_hash,
block_hash, Merkle roots, tx ids, signatures, and no overlap between the
mempool and on-chain transactions). The valid candidate with the highest
generation is promoted over the main file and older debris is removed.
A same-generation content conflict, or the absence of any valid candidate,
raises :class:`StateRecoveryError` carrying the path and reason — a fresh
genesis chain is created only when no file exists at all.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading

from . import crypto
from .models import STATUS_CONFIRMED, STATUS_PENDING, Block, Transaction, compute_block_hash

# Previous hash of the genesis block.
GENESIS_PREV_HASH = "0" * 64

# Prefix of snapshot temp files in the state directory; leftovers from an
# interrupted write are scanned as recovery candidates on the next startup.
SNAPSHOT_PREFIX = ".ledger-"

# On-disk schema version, stored under "state" so future migrations are possible.
STATE_VERSION = 2


class StateRecoveryError(ValueError):
    """Raised when on-disk state cannot be safely recovered at startup.

    Every state file candidate (the main file plus stale ``.ledger-*``
    snapshots in the same directory) was missing, unreadable, structurally
    invalid, or the highest-generation snapshots disagreed with each other.
    The error carries the offending ``path`` and a human-readable ``reason``
    so callers can catch and report it instead of silently starting a fresh
    chain. Subclasses :class:`ValueError` for backward compatibility with
    callers that treat a corrupt chain as a value error.
    """

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"cannot recover ledger state from {path}: {reason}")


class LedgerStore:
    def __init__(self, path: str) -> None:
        self.path = path
        self.chain: list[Block] = []
        self.pending: dict[str, Transaction] = {}
        # Monotonic generation counter: every successful atomic write bumps
        # it by one, so startup recovery can rank on-disk snapshots.
        self.generation: int = 0
        # Derived, confirmed-only views; rebuilt by rebuild_derived().
        self.tx_index: dict[str, int] = {}
        self.accounts: dict[str, dict] = {}
        self._lock = threading.RLock()
        self.load()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def load(self) -> None:
        """Recover state from disk on startup, creating genesis only when no
        state file nor snapshot candidate exists at all.

        Every candidate (main file plus stale ``.ledger-*`` snapshots) is
        fully validated; the valid one with the highest generation wins and
        is atomically promoted to the main path. Invalid candidates never
        cause a silent chain reset — :class:`StateRecoveryError` is raised
        instead.
        """
        self._recover()

    def _recover(self) -> None:
        """Validate all snapshot candidates, select and promote the winner.

        The valid candidate with the highest generation wins. A leftover
        snapshot containing a complete newer generation (a crash after the
        data hit disk but before it was promoted over the main file) is thus
        picked automatically; corrupt debris never silently resets the chain.
        """
        candidates = self._candidate_paths()
        if not candidates:
            # No state file and no leftover snapshots: the one and only
            # situation in which a fresh genesis chain may be created.
            self.chain = [self.create_genesis()]
            self.pending = {}
            self.generation = 0
            self.rebuild_derived()
            self.save()
            return

        validated: list[tuple[int, str, list[Block], dict[str, Transaction], bytes]] = []
        failures: list[str] = []
        for candidate in candidates:
            try:
                chain, pending, generation, fingerprint = self._load_validated(candidate)
            except StateRecoveryError as exc:
                failures.append(f"{exc.path}: {exc.reason}")
                continue
            validated.append((generation, candidate, chain, pending, fingerprint))

        if not validated:
            detail = "; ".join(failures) or "no readable state files"
            raise StateRecoveryError(
                self.path, f"no valid recovery candidate found ({detail})"
            )

        max_generation = max(item[0] for item in validated)
        newest = [item for item in validated if item[0] == max_generation]
        reference_fingerprint = newest[0][4]
        for generation, candidate, _chain, _pending, fingerprint in newest[1:]:
            if fingerprint != reference_fingerprint:
                raise StateRecoveryError(
                    candidate,
                    f"conflicting snapshots at generation {max_generation}: "
                    "same generation but different chain content",
                )

        # Identical-content tie: prefer the main file, then the first path.
        def preference(item: tuple[int, str, list[Block], dict[str, Transaction], bytes]) -> tuple[int, str]:
            _generation, candidate, _chain, _pending, _fingerprint = item
            is_main = os.path.abspath(candidate) == os.path.abspath(self.path)
            return (0 if is_main else 1, candidate)

        generation, winner, chain, pending, _fingerprint = min(newest, key=preference)
        self.chain = chain
        self.pending = pending
        self.generation = generation
        self._promote(winner)
        self._cleanup_candidates(set(candidates), winner)
        self.rebuild_derived()

    def _candidate_paths(self) -> list[str]:
        """List recovery candidates: the main file plus ``.ledger-*`` files.

        Only regular files in the same directory as the main state file are
        considered; the result is sorted for deterministic validation order.
        """
        paths: list[str] = []
        if os.path.exists(self.path):
            paths.append(self.path)
        directory = os.path.dirname(os.path.abspath(self.path))
        if os.path.isdir(directory):
            for name in sorted(os.listdir(directory)):
                full = os.path.join(directory, name)
                if name.startswith(SNAPSHOT_PREFIX) and os.path.isfile(full):
                    if os.path.abspath(full) != os.path.abspath(self.path):
                        paths.append(full)
        return paths

    def _load_validated(
        self, path: str
    ) -> tuple[list[Block], dict[str, Transaction], int, bytes]:
        """Read and fully validate one snapshot file.

        Returns ``(chain, pending, generation, fingerprint)`` where the
        fingerprint is a canonical serialization of the chain and mempool
        content, used to detect same-generation conflicts between snapshots.
        Raises :class:`StateRecoveryError` (a ``ValueError`` subclass) with
        the offending path and reason on any structural or cryptographic
        defect.
        """
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except OSError as exc:
            raise StateRecoveryError(path, f"cannot read state file: {exc}") from exc
        except (ValueError, UnicodeDecodeError) as exc:
            raise StateRecoveryError(path, f"state file is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise StateRecoveryError(path, "state file top-level value is not an object")

        raw_chain = data.get("chain", [])
        raw_pending = data.get("pending", [])
        if not isinstance(raw_chain, list) or not isinstance(raw_pending, list):
            raise StateRecoveryError(
                path, "'chain' and 'pending' must both be JSON arrays"
            )
        try:
            chain = [Block.from_dict(b) for b in raw_chain]
            pending_entries = [Transaction.from_dict(t) for t in raw_pending]
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise StateRecoveryError(path, f"malformed chain or pending entry: {exc}") from exc
        if not chain:
            raise StateRecoveryError(path, "chain is empty (missing genesis block)")

        pending: dict[str, Transaction] = {}
        for tx in pending_entries:
            if tx.tx_id in pending:
                raise StateRecoveryError(path, f"duplicate pending transaction {tx.tx_id}")
            pending[tx.tx_id] = tx

        generation = self._generation_of(data)
        self.chain = chain
        self.pending = pending
        self._validate_stored_tx_ids(raw_chain, raw_pending, path)
        self._validate_linkage(path)
        self._validate_blocks(path)
        self._validate_pending(path)
        fingerprint = self._content_fingerprint(chain, pending)
        return chain, pending, generation, fingerprint

    @staticmethod
    def _validate_stored_tx_ids(
        raw_chain: list, raw_pending: list, path: str
    ) -> None:
        """Verify the stored ``tx_id`` fields against the transaction payload.

        :meth:`Transaction.from_dict` recomputes tx ids and ignores the stored
        field, so a tampered ``tx_id`` would otherwise pass silently; check the
        raw on-disk entries explicitly (both in blocks and the mempool).
        """
        groups: list[tuple[str, list]] = [
            ("chain", block.get("transactions", [])) for block in raw_chain
        ]
        groups.append(("pending", raw_pending))
        for location, txs in groups:
            if not isinstance(txs, list):
                raise StateRecoveryError(path, f"{location} transactions are not a list")
            for raw in txs:
                if not isinstance(raw, dict):
                    raise StateRecoveryError(path, f"malformed transaction entry in {location}")
                try:
                    sender = raw["from"]
                    recipient = raw["to"]
                    amount = raw["amount"]
                    stored_id = raw["tx_id"]
                except KeyError as exc:
                    raise StateRecoveryError(
                        path, f"transaction in {location} missing field {exc}"
                    ) from exc
                if not isinstance(sender, str) or not isinstance(recipient, str):
                    raise StateRecoveryError(
                        path, f"non-string party field in a {location} transaction"
                    )
                if isinstance(amount, bool) or not isinstance(amount, int):
                    raise StateRecoveryError(
                        path, f"non-integer amount in a {location} transaction"
                    )
                expected = crypto.compute_tx_id(
                    crypto.canonical_message(sender, recipient, amount)
                )
                if stored_id != expected:
                    raise StateRecoveryError(
                        path,
                        f"stored tx_id {stored_id!r} does not match payload "
                        f"(expected {expected}) in {location}",
                    )

    @staticmethod
    def _content_fingerprint(
        chain: list[Block], pending: dict[str, Transaction]
    ) -> bytes:
        """Canonical digest of the recoverable content (chain + mempool).

        Two snapshots at the same generation are considered conflicting iff
        these bytes differ. Generation and derived indexes are deliberately
        excluded: indexes are rebuilt, and the generation is equal by then.
        """
        payload = {
            "chain": [block.to_dict() for block in chain],
            "pending": [pending[tx_id].to_dict() for tx_id in sorted(pending)],
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(canonical).digest()

    def _validate_blocks(self, path: str) -> None:
        """Cryptographically validate every block of a recovered candidate.

        Checks (per block):
        * at most one pending block and only at the chain tip;
        * recomputed ``merkle_root`` and ``block_hash`` match the stored ones
          (which also rejects a corrupt tx ordering);
        * every transaction id matches the SHA-256 of its canonical message;
        * every transaction signature verifies against its sender;
        * no tx_id repeats inside a block, across blocks, or between
          confirmed blocks and the mempool.
        """
        seen_tx: set[str] = set()
        for i, block in enumerate(self.chain):
            if block.status not in (STATUS_PENDING, STATUS_CONFIRMED):
                raise StateRecoveryError(
                    path, f"block at height {block.height} has invalid status {block.status!r}"
                )
            if block.status == STATUS_PENDING and i != len(self.chain) - 1:
                raise StateRecoveryError(
                    path,
                    f"pending block at height {block.height} is not the chain tip; "
                    "pending blocks may only exist at the tail",
                )

            tx_ids = [tx.tx_id for tx in block.transactions]
            if len(set(tx_ids)) != len(tx_ids):
                raise StateRecoveryError(
                    path, f"duplicate transaction inside block at height {block.height}"
                )
            duplicated = seen_tx.intersection(tx_ids)
            if duplicated:
                raise StateRecoveryError(
                    path,
                    f"transaction {next(iter(duplicated))} appears in multiple blocks",
                )

            expected_merkle = crypto.merkle_root(sorted(tx_ids))
            if block.merkle_root != expected_merkle:
                raise StateRecoveryError(
                    path, f"merkle root mismatch at height {block.height}"
                )
            expected_hash = compute_block_hash(
                block.height, block.prev_hash, block.merkle_root
            )
            if block.block_hash != expected_hash:
                raise StateRecoveryError(
                    path, f"block hash mismatch at height {block.height}"
                )

            for tx in block.transactions:
                message = crypto.canonical_message(tx.sender, tx.recipient, tx.amount)
                if crypto.compute_tx_id(message) != tx.tx_id:
                    raise StateRecoveryError(
                        path,
                        f"tx_id does not match its payload at height {block.height}",
                    )
                if not crypto.verify_signature(tx.sender, message, tx.signature):
                    raise StateRecoveryError(
                        path,
                        f"invalid transaction signature at height {block.height} "
                        f"for tx {tx.tx_id}",
                    )
            seen_tx.update(tx_ids)

    def _validate_pending(self, path: str) -> None:
        """Validate the mempool snapshot: unique ids, good signatures, no
        overlap with transactions already sealed in blocks.
        """
        on_chain = {
            tx.tx_id
            for block in self.chain
            for tx in block.transactions
        }
        for tx_id, tx in self.pending.items():
            if tx_id in on_chain:
                raise StateRecoveryError(
                    path, f"pending transaction {tx_id} already exists in a block"
                )
            message = crypto.canonical_message(tx.sender, tx.recipient, tx.amount)
            if crypto.compute_tx_id(message) != tx_id:
                raise StateRecoveryError(path, f"pending tx_id does not match its payload: {tx_id}")
            if not crypto.verify_signature(tx.sender, message, tx.signature):
                raise StateRecoveryError(
                    path, f"invalid signature on pending transaction {tx_id}"
                )

    @staticmethod
    def _generation_of(data: dict) -> int:
        state = data.get("state")
        if not isinstance(state, dict) or "generation" not in state:
            return 0
        generation = state["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            return 0
        return generation

    def _promote(self, winner: str) -> None:
        """Atomically promote the winning snapshot to the main path.

        Nothing to do when the main file itself won; a leftover snapshot is
        moved over the main file with ``os.replace`` and the directory is
        fsynced so the rename survives a power loss.
        """
        if os.path.abspath(winner) == os.path.abspath(self.path):
            return
        os.replace(winner, self.path)
        self._fsync_directory(os.path.dirname(os.path.abspath(self.path)))

    def _cleanup_candidates(self, scanned: set[str], winner: str) -> None:
        """Delete stale snapshot candidates judged older than the winner.

        Only ``.ledger-*`` files observed during the startup scan are touched;
        anything written by a concurrent process is left alone. A cleanup
        failure must not abort recovery — the promoted main file is already
        authoritative, and the stale file is simply re-evaluated next start.
        """
        directory = os.path.dirname(os.path.abspath(self.path))
        winner_abs = os.path.abspath(winner)
        for candidate in scanned:
            candidate_abs = os.path.abspath(candidate)
            if candidate_abs == winner_abs or candidate_abs == os.path.abspath(self.path):
                continue
            if os.path.dirname(candidate_abs) != directory:
                continue
            try:
                os.unlink(candidate_abs)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        self._fsync_directory(directory)

    @staticmethod
    def _fsync_directory(directory: str) -> None:
        """Best-effort fsync of a directory so renames/unlinks are durable."""
        if not os.path.isdir(directory):
            return
        try:
            fd = os.open(directory, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def _validate_linkage(self, path: str = "") -> None:
        """Ensure heights are consecutive and every prev_hash matches its parent."""
        where = path or self.path
        for i, block in enumerate(self.chain):
            if block.height != i:
                raise StateRecoveryError(
                    where, f"orphan block: height {block.height} at chain position {i}"
                )
            expected_prev = GENESIS_PREV_HASH if i == 0 else self.chain[i - 1].block_hash
            if block.prev_hash != expected_prev:
                raise StateRecoveryError(
                    where,
                    f"orphan block at height {block.height}: prev_hash mismatch",
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

    def rebuild_derived(self) -> None:
        """Rebuild the confirmed-only transaction index and account activity.

        Pending blocks are excluded: only confirmed blocks contribute to
        balances and to the tx_id -> height index.
        """
        self.tx_index = {}
        self.accounts = {}
        for block in self.chain:
            if block.status != STATUS_CONFIRMED:
                continue
            for tx in block.transactions:
                self.tx_index[tx.tx_id] = block.height
                for account in (tx.sender, tx.recipient):
                    entry = self.accounts.setdefault(
                        account, {"sent": 0, "received": 0, "transactions": []}
                    )
                    entry["transactions"].append(tx.tx_id)
                self.accounts[tx.sender]["sent"] += tx.amount
                self.accounts[tx.recipient]["received"] += tx.amount

    def save(self) -> None:
        """Atomically persist chain, state, pending set, index and accounts.

        Every successful write bumps ``generation`` by one and embeds it in
        the snapshot. The new state is serialized and fsynced to a durable
        ``.ledger-*`` temp file first, then moved over the main file with an
        atomic ``os.replace`` and the directory is fsynced. A crash during
        the write therefore leaves either the previous main file intact or a
        complete, recoverable newer snapshot — never a torn main file. The
        caller must hold :attr:`lock` so concurrent mutations serialize.
        """
        self.generation += 1
        self.rebuild_derived()
        data = {
            "state": {
                "version": STATE_VERSION,
                "generation": self.generation,
                "height": self.chain[-1].height,
                "tip_hash": self.chain[-1].block_hash,
                "tip_status": self.chain[-1].status,
            },
            "chain": [block.to_dict() for block in self.chain],
            "pending": [tx.to_dict() for tx in self.pending.values()],
            "index": dict(self.tx_index),
            "accounts": self.accounts,
        }
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=SNAPSHOT_PREFIX, dir=directory)
        replaced = False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.path)
            replaced = True
            self._fsync_directory(directory)
        except BaseException:
            # The temp file only exists pre-replace; once replaced it is the
            # main file and must never be unlinked. A failed write never
            # consumes a generation number.
            if not replaced:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                self.generation -= 1
            raise

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
