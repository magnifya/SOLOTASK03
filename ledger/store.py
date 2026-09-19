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
(``pending``), the confirmed-transaction ``index`` and the confirmed
``accounts`` activity. Derived data (index/accounts) is *rebuilt* from the
chain on every load and every save — pending blocks are excluded, so a
restart never resurrects unconfirmed transactions into balances. A
re-entrant lock serializes all updates, and a class-wide recovery lock
serializes startup scans against in-flight writes.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading

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
STATE_VERSION = 3

# Prefix of durable snapshot temp files ("<state>.ledger-<...>") living next to
# the main state file. They double as crash-recovery candidates on startup.
SNAPSHOT_PREFIX = ".ledger-"


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
    def __init__(self, path: str) -> None:
        self.path = path
        self.chain: list[Block] = []
        self.pending: dict[str, Transaction] = {}
        # Monotonic counter bumped on every successful atomic write. It is
        # persisted with each snapshot and lets startup pick the newest one.
        self.generation: int = 0
        # Derived, confirmed-only views; rebuilt by rebuild_derived().
        self.tx_index: dict[str, int] = {}
        self.accounts: dict[str, dict] = {}
        # Verified fork candidates keyed by their tip block hash. Each value is
        # the candidate chain (a non-empty list[Block] rooted at the canonical
        # genesis); filled in once fork validation lands.
        self.forks: dict[str, list[Block]] = {}
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
                self.generation = 0
                self.rebuild_derived()
                self.save()
                return

            valid: list[tuple[int, str, list[Block], dict[str, Transaction], dict[str, list[Block]]]] = []
            errors: list[StateRecoveryError] = []
            for candidate in candidates:
                try:
                    data = self._read_candidate(candidate)
                    chain, pending, forks, generation = self._parse_snapshot(candidate, data)
                except StateRecoveryError as exc:
                    errors.append(exc)
                    continue
                valid.append((generation, candidate, chain, pending, forks))

            if not valid:
                details = "; ".join(f"{exc.path} ({exc.reason})" for exc in errors)
                raise StateRecoveryError(
                    directory, f"no valid snapshot candidate found: {details}"
                )

            max_generation = max(item[0] for item in valid)
            top = [item for item in valid if item[0] == max_generation]
            reference = self._canonical_view(top[0][2], top[0][3], top[0][4])
            for item in top[1:]:
                if self._canonical_view(item[2], item[3], item[4]) != reference:
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
            generation, winner_path, chain, pending, forks = winner

            if os.path.abspath(winner_path) != main_abs:
                # The newest durable state only ever made it to a temp
                # snapshot (a crash interrupted the promotion): promote it.
                os.replace(winner_path, self.path)
                self._fsync_dir(directory)

            self.chain = chain
            self.pending = pending
            self.forks = forks
            self.generation = generation
            self.rebuild_derived()
            self._cleanup_candidates(directory)

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
        forks: dict[str, list[Block]] | None = None,
    ) -> str:
        """Order-independent canonical content hash for conflict detection."""
        return json.dumps(
            {
                "chain": [block.to_dict() for block in chain],
                "pending": [pending[tx_id].to_dict() for tx_id in sorted(pending)],
                "forks": [
                    [block.to_dict() for block in forks[tip]]
                    for tip in sorted(forks or {})
                ],
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
    ) -> tuple[list[Block], dict[str, Transaction], dict[str, list[Block]], int]:
        """Strictly validate one decoded snapshot.

        Checks the persisted generation, consecutive heights, prev_hash
        linkage, recomputed block hashes, recomputed Merkle roots, every
        transaction's tx_id and Ed25519 signature, the pending-only-at-tip
        rule, and de-duplication between mempool and chain. Fork candidates
        are validated with the same per-block rules. Returns the parsed chain,
        mempool, fork candidates and generation. Raises StateRecoveryError on
        the first defect, with ``path`` identifying the candidate.
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

        chain, seen_tx_ids = self._validate_chain(path, chain_raw, "block")

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

        # Fork candidates: same strict per-chain validation; keyed by tip hash.
        # They must root at exactly the canonical chain's genesis block.
        canonical_genesis_hash = chain[0].block_hash
        forks = self._validate_forks_section(
            path, data.get("forks", []), fail, canonical_genesis_hash
        )

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

        return chain, pending, forks, generation

    def _validate_chain(
        self, path: str, chain_raw: object, noun: str
    ) -> tuple[list[Block], set[str]]:
        """Validate a serialized chain (canonical or one fork candidate).

        Enforces consecutive heights, prev_hash linkage, known status with
        pending only at the tip, a fixed empty confirmed genesis, ascending
        within-block tx_ids unique across the whole chain, stored/recomputed
        tx_ids, Merkle roots, block hashes and Ed25519 signatures.
        """
        def fail(reason: str) -> None:
            raise StateRecoveryError(path, reason)

        if not isinstance(chain_raw, list) or not chain_raw:
            fail(f"{noun} chain must be a non-empty list of blocks")

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
                # tx_id is derivable from the signed message: it may be
                # omitted, but a present value must match the recomputed id.
                if stored_tx_id is not None and stored_tx_id != tx.tx_id:
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
        return chain, seen_tx_ids

    def _validate_forks_section(
        self, path: str, forks_raw: object, fail, canonical_genesis_hash: str
    ) -> dict[str, list[Block]]:
        """Validate and index the persisted ``forks`` candidate section."""
        if forks_raw is None:
            # Snapshots written before forks existed carry no section.
            return {}
        if not isinstance(forks_raw, list):
            fail("'forks' must be a list")
        forks: dict[str, list[Block]] = {}
        for i, entry in enumerate(forks_raw):
            if not isinstance(entry, dict):
                fail(f"fork candidate at position {i} is not a JSON object")
            tip_hash = entry.get("tip_hash")
            if not crypto.is_hex64(tip_hash):
                fail(f"fork candidate at position {i} has an invalid tip_hash")
            blocks_raw = entry.get("blocks")
            chain, _ = self._validate_chain(path, blocks_raw, f"fork {i}")
            if chain[0].block_hash != canonical_genesis_hash:
                fail(
                    f"fork candidate {tip_hash} does not root at the canonical "
                    "genesis block"
                )
            if chain[-1].block_hash != tip_hash:
                fail(f"fork candidate {tip_hash} tip_hash does not match its blocks")
            if tip_hash in forks:
                fail(f"duplicate fork candidate {tip_hash}")
            forks[tip_hash] = chain
        return forks

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

        The new state is first written to a uniquely named ``.ledger-*``
        snapshot in the same directory and force-fsynced; only after that does
        an atomic ``os.replace`` promote it to the main file. A crash between
        the fsync and the promotion leaves the snapshot behind, where the
        startup scan finds it as a recovery candidate. The in-memory
        ``generation`` is advanced only after the promotion succeeds, so every
        *successful* atomic write corresponds to exactly one generation.
        """
        self.rebuild_derived()
        next_generation = self.generation + 1
        data = {
            "state": {
                "version": STATE_VERSION,
                "generation": next_generation,
                "height": self.chain[-1].height,
                "tip_hash": self.chain[-1].block_hash,
                "tip_status": self.chain[-1].status,
            },
            "chain": [block.to_dict() for block in self.chain],
            "pending": [tx.to_dict() for tx in self.pending.values()],
            "index": dict(self.tx_index),
            "accounts": self.accounts,
            "forks": [
                {
                    "tip_hash": tip_hash,
                    "length": len(self.forks[tip_hash]),
                    "status": self.forks[tip_hash][-1].status,
                    "blocks": [block.to_dict() for block in self.forks[tip_hash]],
                }
                for tip_hash in sorted(self.forks)
            ],
        }
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

    def fork_tip_hashes(self) -> list[str]:
        """Tip hashes of every persisted fork candidate, ascending."""
        return sorted(self.forks)

    def fork_chain(self, tip_hash: str) -> list[Block] | None:
        """Return the candidate chain rooted at genesis with the given tip."""
        return self.forks.get(tip_hash)

    @staticmethod
    def chain_summary(blocks: list[Block]) -> dict:
        """The S view: tip_hash, height, length (incl. genesis), tip status."""
        tip = blocks[-1]
        return {
            "tip_hash": tip.block_hash,
            "height": tip.height,
            "length": len(blocks),
            "status": tip.status,
        }

    def put_fork(self, blocks: list[Block]) -> None:
        """Persist a validated fork candidate keyed by its tip hash.

        Caller must hold the lock and must have fully validated the chain.
        Rolls the in-memory registration back if the durable write fails.
        """
        tip_hash = blocks[-1].block_hash
        self.forks[tip_hash] = blocks
        try:
            self.save()
        except BaseException:
            self.forks.pop(tip_hash, None)
            raise

    def adopt_fork(self, tip_hash: str) -> list[Block]:
        """Atomically replace the canonical chain with the candidate fork.

        Transactions confirmed only on the old chain return to the mempool
        de-duplicated; transactions that lived in the old chain's *pending*
        tip are dropped (pending transactions never re-enter the pool here).
        Mempool entries already present on the adopted chain are pruned so
        chain and pool never overlap. Derived indexes are rebuilt and a new
        generation is persisted in one atomic write; any failure restores the
        previous chain, mempool, forks and indexes in memory. Caller must hold
        the lock; raises KeyError for an unknown tip hash.
        """
        new_chain = self.forks[tip_hash]
        old_chain = self.chain
        old_pending = dict(self.pending)
        old_forks = dict(self.forks)

        def confirmed_ids(blocks: list[Block]) -> set[str]:
            return {
                tx.tx_id
                for block in blocks
                if block.status == STATUS_CONFIRMED
                for tx in block.transactions
            }

        new_all_ids = {
            tx.tx_id for block in new_chain for tx in block.transactions
        }
        new_confirmed_ids = confirmed_ids(new_chain)
        # Transactions unique to the OLD chain's confirmed prefix that are
        # absent from the whole adopted chain (including its pending tip)
        # return to the pool. Transactions from the old chain's pending tip
        # never re-enter the pool ("pending 不入池").
        restored = [
            tx
            for block in old_chain
            if block.status == STATUS_CONFIRMED
            for tx in block.transactions
            if tx.tx_id not in new_all_ids
        ]

        # The mempool must never overlap the new canonical chain (including a
        # pending tip): prune every id that is packed on the adopted chain.
        self.chain = list(new_chain)
        self.pending = {
            tx_id: tx
            for tx_id, tx in self.pending.items()
            if tx_id not in new_all_ids
        }
        # Old-chain-only confirmed transactions return to the pool, deduped.
        for tx in restored:
            self.pending.setdefault(tx.tx_id, tx)
        # The adopted fork is the canonical chain now, not merely a candidate.
        self.forks.pop(tip_hash, None)
        # A hash binds the whole ancestry, so any other candidate whose tip
        # now lands on the canonical chain is fully contained in it: no longer
        # a fork, drop it. Candidates that diverge remain valid competitors.
        canonical_hashes = {block.block_hash for block in self.chain}
        for redundant in [tip for tip, blocks in self.forks.items() if blocks[-1].block_hash in canonical_hashes]:
            self.forks.pop(redundant, None)
        try:
            self.save()
        except BaseException:
            self.chain = old_chain
            self.pending = old_pending
            self.forks = old_forks
            self.rebuild_derived()
            raise
        return list(new_chain)
