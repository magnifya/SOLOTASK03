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
invalidity remains fatal. A re-entrant lock serializes all updates, and a
class-wide recovery lock serializes startup scans against in-flight writes.
"""
from __future__ import annotations

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
STATE_VERSION = 5

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
                top[0][2], top[0][3], top[0][4], top[0][6]
            )
            for item in top[1:]:
                if (
                    self._canonical_view(item[2], item[3], item[4], item[6])
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
            self.generation = generation
            # Prefer the endowment recorded by the writer; fall back to the
            # value this instance was constructed with, and finally to the
            # service default, so older snapshots without the field still
            # validate fork replays against the configured endowment.
            if winner_init_balance is not None:
                self.initial_balance = winner_init_balance
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
        forks: dict[str, list[Block]],
        syncs: dict[tuple[str, str], dict] | None = None,
    ) -> str:
        """Order-independent canonical content hash for conflict detection."""
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
        return json.dumps(
            {
                "chain": [block.to_dict() for block in chain],
                "pending": [pending[tx_id].to_dict() for tx_id in sorted(pending)],
                "forks": [
                    [block.to_dict() for block in forks[tip]]
                    for tip in sorted(forks)
                ],
                "syncs": sync_records,
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

        forks = self._parse_persisted_forks(data.get("forks", []), chain)
        syncs, synced_tips = self._parse_persisted_syncs(
            data.get("syncs", []), forks, chain
        )
        # A fork brought in only by a sync record loses its right to exist once
        # that record is gone (expired/invalid on restart): without this, the
        # independently-persisted fork would resurrect as a never-expiring
        # candidate. Direct submissions carry no sync record and are untouched.
        live_tips = {rec["tip_hash"] for rec in syncs.values()}
        canonical_hashes = {block.block_hash for block in chain}
        for tip in synced_tips - live_tips - canonical_hashes:
            forks.pop(tip, None)
        return chain, pending, generation, forks, initial_balance, syncs

    def _parse_persisted_syncs(
        self,
        syncs_raw: object,
        forks: dict[str, list[Block]],
        canonical_chain: list[Block],
    ) -> tuple[dict[tuple[str, str], dict], set[str]]:
        """Parse persisted sync records, dropping unusable ones on restart.

        A record is kept only when it is structurally valid and has not yet
        expired. Its tip must reference either a surviving candidate fork or a
        block on the canonical chain (a synced candidate may have been adopted);
        records pointing at neither are stale orphans and are pruned. Invalid
        or expired records are silently dropped rather than failing recovery of
        the canonical chain. Also returns the set of every tip any sync record
        claims provenance for (including expired ones), so the caller can drop
        forks that only an expired sync kept alive.
        """
        if not isinstance(syncs_raw, list):
            return {}, set()
        now = time.time()
        canonical_hashes = {block.block_hash for block in canonical_chain}
        syncs: dict[tuple[str, str], dict] = {}
        synced_tips: set[str] = set()
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
            # Provenance is recorded even for expired records: it proves the
            # matching fork must not outlive the sync that delivered it.
            synced_tips.add(tip_hash)
            if (
                isinstance(expires_at, bool)
                or not isinstance(expires_at, int)
                or expires_at <= now
            ):
                continue
            if not isinstance(fingerprint, str) or not fingerprint:
                continue
            if tip_hash not in forks and tip_hash not in canonical_hashes:
                continue
            key = (source, request_id)
            if key in syncs:
                continue
            syncs[key] = {
                "tip_hash": tip_hash,
                "expires_at": expires_at,
                "fingerprint": fingerprint,
            }
        return syncs, synced_tips

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
                "initial_balance": self.initial_balance,
            },
            "chain": [block.to_dict() for block in self.chain],
            "pending": [tx.to_dict() for tx in self.pending.values()],
            "index": dict(self.tx_index),
            "accounts": self.accounts,
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
        self, forks_raw: object, canonical_chain: list[Block]
    ) -> dict[str, list[Block]]:
        """Parse persisted candidate forks, dropping invalid ones on restart.

        Every stored fork is re-validated exactly like a fresh submission
        (genesis connection, hashes, Merkle roots, signatures, uniqueness,
        replay). A fork that no longer validates is silently discarded rather
        than failing recovery of the canonical chain. Recovery of the canonical
        chain itself remains strict and still raises StateRecoveryError.
        """
        if not isinstance(forks_raw, list):
            return {}
        endowment = self.initial_balance if self.initial_balance is not None else 1_000_000
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
