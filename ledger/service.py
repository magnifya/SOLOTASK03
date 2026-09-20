"""Ledger business logic: submit transactions, mine blocks, query state,
and drive the confirm/rollback block state machine.

Block lifecycle
---------------
The genesis block is born ``confirmed``. Mining (POST /v1/blocks) is only
allowed when the chain tip is confirmed and the mempool is non-empty; it
produces a ``pending`` block. A pending tip can then be *confirmed* (making
its transactions count toward balances and proofs) or *rolled back* (the
block is deleted and its transactions return to the mempool de-duplicated).
Only the tip can ever be pending, so a confirmed block is final.

Balance convention
------------------
The contract defines no minting endpoint, so every identity starts with a
fixed endowment (``initial_balance``, overridable via LEDGER_INITIAL_BALANCE).
An account's confirmed balance is::

    initial_balance + sum(confirmed amounts received) - sum(confirmed amounts sent)

Only confirmed blocks count. The reported balance additionally subtracts the
account's spends sitting in the pending (unconfirmed) tip block — pending
*credits* are deliberately not counted. An identity only becomes a *queryable
account* once it appears in a confirmed block; GET account before that
returns 404. Balance checks at submission time treat an identity that has
never appeared on chain as holding the initial endowment, otherwise the first
transaction in an empty ledger could never be accepted.
"""
from __future__ import annotations

import hashlib
import json
import time

from . import crypto
from .models import STATUS_CONFIRMED, STATUS_PENDING, Block, Transaction
from .store import LedgerStore

DEFAULT_INITIAL_BALANCE = 1_000_000

REQUIRED_TX_FIELDS = ("from", "to", "amount", "signature")


def _parse_height(height: object) -> int | None:
    """Strict decimal height parse; None when malformed."""
    try:
        height_int = int(height)  # type: ignore[arg-type]
        if str(height_int) != str(height).strip():
            raise ValueError
        return height_int
    except (TypeError, ValueError):
        return None


def _parse_decimal(value: object) -> int | None:
    """Strict non-negative decimal parse; None when malformed.

    Only ``0`` or a digit string whose first digit is non-zero is accepted:
    leading zeros, signs, whitespace and non-string types are all rejected.
    """
    if not isinstance(value, str) or not value:
        return None
    if value != "0" and (not value.isdigit() or value[0] == "0"):
        return None
    return int(value)


class LedgerService:
    def __init__(self, store: LedgerStore, initial_balance: int = DEFAULT_INITIAL_BALANCE) -> None:
        self.store = store
        self.initial_balance = initial_balance
        # Record the endowment convention so persisted fork replay checks and
        # recovery use the same value the service was configured with.
        if self.store.initial_balance is None:
            self.store.initial_balance = initial_balance

    # -- transactions -------------------------------------------------------

    def submit_transaction(self, payload: object) -> tuple[int, dict]:
        """Validate and enqueue a transaction. Returns (status, body)."""
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in REQUIRED_TX_FIELDS:
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}

        sender = payload["from"]
        recipient = payload["to"]
        amount = payload["amount"]
        signature = payload["signature"]

        if not isinstance(sender, str) or not sender:
            return 400, {"error": "field 'from' must be a non-empty string"}
        if not isinstance(recipient, str) or not recipient:
            return 400, {"error": "field 'to' must be a non-empty string"}
        # bool is a subclass of int: reject it and all non-int types explicitly.
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            return 400, {"error": "field 'amount' must be a positive integer"}
        if not isinstance(signature, str) or not signature:
            return 400, {"error": "field 'signature' must be a non-empty string"}

        message = crypto.canonical_message(sender, recipient, amount)
        if not crypto.verify_signature(sender, message, signature):
            return 400, {"error": "invalid signature"}

        tx = Transaction(sender, recipient, amount, signature)
        with self.store.lock:
            if tx.tx_id in self.store.pending:
                return 409, {"error": "transaction already pending", "tx_id": tx.tx_id}
            if any(tx.tx_id == existing.tx_id for block in self.store.chain for existing in block.transactions):
                return 409, {"error": "transaction already confirmed", "tx_id": tx.tx_id}
            if self.available_balance(sender) < amount:
                return 400, {"error": "insufficient balance"}
            self.store.pending[tx.tx_id] = tx
            try:
                self.store.save()
            except BaseException:
                # Persistence failed: drop the in-memory enqueue so memory
                # keeps matching the last durably committed state.
                self.store.pending.pop(tx.tx_id, None)
                raise
        return 202, {"tx_id": tx.tx_id}

    # -- blocks -------------------------------------------------------------

    def mine_block(self) -> tuple[int, dict]:
        """Pack all pending transactions (ascending tx_id) into a pending block.

        Only allowed when the chain tip is confirmed; the new block becomes
        the pending tip until it is confirmed or rolled back.
        """
        with self.store.lock:
            if self.store.tip_is_pending():
                return 409, {"error": "tip block is pending confirmation"}
            if not self.store.pending:
                return 409, {"error": "no pending transactions"}
            ordered = sorted(self.store.pending.values(), key=lambda tx: tx.tx_id)
            block = Block.create(
                height=self.store.next_height(),
                prev_hash=self.store.tip_hash(),
                transactions=ordered,
                status=STATUS_PENDING,
            )
            self.store.chain.append(block)
            removed = [self.store.pending.pop(tx.tx_id) for tx in ordered]
            try:
                self.store.save()
            except BaseException:
                # Undo the in-memory block so nothing un-persisted is visible.
                self.store.chain.pop()
                self.store.pending.update({tx.tx_id: tx for tx in removed})
                raise
        return 201, {
            "height": block.height,
            "block_hash": block.block_hash,
            "merkle_root": block.merkle_root,
            "status": block.status,
        }

    def get_block(self, height: object) -> tuple[int, dict]:
        height_int = _parse_height(height)
        if height_int is None:
            return 404, {"error": "block not found"}
        with self.store.lock:
            block = self.store.block_at(height_int)
            if block is None:
                return 404, {"error": "block not found"}
            return 200, block.to_summary()

    def get_block_status(self, height: object) -> tuple[int, dict]:
        """GET /v1/blocks/{height}/status -> {height, status}; 404 if unknown."""
        height_int = _parse_height(height)
        if height_int is None:
            return 404, {"error": "block not found"}
        with self.store.lock:
            block = self.store.block_at(height_int)
            if block is None:
                return 404, {"error": "block not found"}
            return 200, {"height": block.height, "status": block.status}

    def confirm_block(self, height: object) -> tuple[int, dict]:
        """Confirm a pending tip block.

        Only a pending chain tip whose parent is confirmed can be confirmed.
        Confirming an already-confirmed block is idempotent (200); every
        other case — unknown or malformed height, non-tip pending block —
        returns 409.
        """
        height_int = _parse_height(height)
        with self.store.lock:
            if height_int is None:
                return 409, {"error": "block cannot be confirmed"}
            block = self.store.block_at(height_int)
            if block is None:
                return 409, {"error": "block cannot be confirmed"}
            if block.status == STATUS_CONFIRMED:
                # Idempotent re-confirm.
                return 200, {"height": block.height, "status": STATUS_CONFIRMED}
            if block is not self.store.tip():
                return 409, {"error": "only the chain tip can be confirmed"}
            parent = self.store.chain[-2] if len(self.store.chain) >= 2 else None
            if parent is None or parent.status != STATUS_CONFIRMED:
                return 409, {"error": "previous block is not confirmed"}
            block.status = STATUS_CONFIRMED
            try:
                self.store.save()
            except BaseException:
                block.status = STATUS_PENDING
                raise
            return 200, {"height": block.height, "status": STATUS_CONFIRMED}

    def rollback_block(self, height: object) -> tuple[int, dict]:
        """Roll back a pending tip block: delete it and restore its transactions.

        Unknown or malformed heights (including an already-rolled-back
        height) return 404; a confirmed block or a non-tip block returns 409.
        """
        height_int = _parse_height(height)
        if height_int is None:
            return 404, {"error": "block not found"}
        with self.store.lock:
            block = self.store.block_at(height_int)
            if block is None:
                return 404, {"error": "block not found"}
            if block.status == STATUS_CONFIRMED:
                return 409, {"error": "confirmed block cannot be rolled back"}
            if block is not self.store.tip():
                return 409, {"error": "only the chain tip can be rolled back"}
            pending_before = set(self.store.pending)
            rolled_back = self.store.rollback_tip()
            try:
                self.store.save()
            except BaseException:
                # Restore the block and drop only the mempool entries we added.
                self.store.chain.append(rolled_back)
                for tx_id in list(self.store.pending):
                    if tx_id not in pending_before:
                        del self.store.pending[tx_id]
                raise
            return 200, {"height": rolled_back.height, "status": "rolled_back"}

    def get_proof(self, height: object, tx_id: object) -> tuple[int, dict]:
        """Return a Merkle inclusion proof for tx_id at the given height.

        Returns 404 for an unknown height, a malformed height/tx_id, or a
        transaction absent from that block. Proofs are only issued for
        confirmed blocks; a pending block returns 409.
        """
        height_int = _parse_height(height)
        if height_int is None:
            return 404, {"error": "block not found"}
        if not crypto.is_hex64(tx_id):
            return 404, {"error": "transaction not found"}
        with self.store.lock:
            block = self.store.block_at(height_int)
            if block is None:
                return 404, {"error": "block not found"}
            if block.status != STATUS_CONFIRMED:
                return 409, {"error": "block is pending confirmation"}
            tx_ids = [tx.tx_id for tx in block.transactions]
            try:
                index = tx_ids.index(tx_id)
            except ValueError:
                return 404, {"error": "transaction not found"}
            siblings = crypto.merkle_proof(tx_ids, index)
            return 200, {
                "height": block.height,
                "tx_id": tx_id,
                "index": index,
                "merkle_root": block.merkle_root,
                "block_hash": block.block_hash,
                "siblings": siblings,
            }

    # -- accounts -----------------------------------------------------------

    def get_account(self, account: str) -> tuple[int, dict]:
        with self.store.lock:
            entry = self.store.accounts.get(account)
            if entry is None:
                return 404, {"error": "account not found"}
            return 200, {
                "account": account,
                "balance": self.reported_balance(account),
                "confirmed_transactions": list(entry["transactions"]),
            }

    def confirmed_balance(self, account: str) -> int:
        """Balance from confirmed blocks only."""
        entry = self.store.accounts.get(account)
        if entry is None:
            return self.initial_balance
        return self.initial_balance + entry["received"] - entry["sent"]

    def reported_balance(self, account: str) -> int:
        """Confirmed balance minus spends sitting in the pending tip block.

        Pending-block credits are not counted: unconfirmed income can still
        be rolled back, so it must not inflate the reported balance.
        """
        balance = self.confirmed_balance(account)
        tip = self.store.tip()
        if tip.status == STATUS_PENDING:
            for tx in tip.transactions:
                if tx.sender == account:
                    balance -= tx.amount
        return balance

    def available_balance(self, account: str) -> int:
        """Reported balance minus amounts already committed in the mempool.

        Pending credits (mempool or unconfirmed block) are deliberately not
        counted, so a sequence of submissions cannot spend money that has not
        been confirmed yet.
        """
        balance = self.reported_balance(account)
        for tx in self.store.pending.values():
            if tx.sender == account:
                balance -= tx.amount
        return balance

    # -- fork candidates -----------------------------------------------------

    @staticmethod
    def _fork_summary(blocks: list) -> dict:
        """Public fork descriptor S: tip_hash, height, length, status."""
        tip = blocks[-1]
        return {
            "tip_hash": tip.block_hash,
            "height": tip.height,
            # The length counts every block including the genesis block.
            "length": len(blocks),
            "status": tip.status,
        }

    def _winning_fork(self) -> tuple[str, list]:
        """Pick the winner among the canonical chain and every candidate.

        Longest chain wins; equal lengths are broken by the smallest tip hash
        (lexicographic hex order). Returns (tip_hash, block list).
        """
        contenders: list[tuple[str, list]] = [
            (self.store.tip_hash(), self.store.chain)
        ]
        contenders.extend(self.store.forks.items())
        contenders.sort(key=lambda item: (-len(item[1]), item[0]))
        return contenders[0]

    def submit_fork_candidate(self, payload: object) -> tuple[int, dict]:
        """POST /v1/forks/candidates — validate and store a candidate fork.

        Returns 201 with the fork descriptor S. Malformed or invalid forks
        return 400; a fork already known (identical to the canonical tip or an
        existing candidate tip) returns 409.
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        blocks_raw = payload.get("blocks")
        if not isinstance(blocks_raw, list):
            return 400, {"error": "missing field: blocks (must be a list)"}
        try:
            fork = self.store.validate_fork_blocks(blocks_raw)
        except ValueError as exc:
            return 400, {"error": str(exc)}
        summary = self._fork_summary(fork)
        # An exported fork (the five-field {tip_hash, height, length, status,
        # blocks} document) may be resubmitted verbatim; every supplied summary
        # field is re-verified against the recomputed descriptor.
        for field in ("tip_hash", "height", "length", "status"):
            if field in payload and payload[field] != summary[field]:
                return 400, {"error": f"summary field {field!r} does not match the blocks"}
        tip_hash = fork[-1].block_hash
        with self.store.lock:
            self._prune_expired_syncs()
            # A tip hash equal to any canonical block hash means the candidate
            # is exactly the canonical chain or a prefix of it (the block hash
            # binds height, parent and Merkle root), so it carries nothing new.
            if any(tip_hash == block.block_hash for block in self.store.chain):
                return 409, {"error": "fork is identical to the canonical chain"}
            if tip_hash in self.store.forks:
                return 409, {"error": "candidate fork already exists", "tip_hash": tip_hash}
            self.store.forks[tip_hash] = fork
            try:
                self.store.save()
            except BaseException:
                self.store.forks.pop(tip_hash, None)
                raise
        return 201, self._fork_summary(fork)

    def get_chain(self) -> tuple[int, dict]:
        """GET /v1/chain — canonical chain, candidates sorted by tip hash and
        the adoptable winner (a non-canonical chain that beats canonical).
        """
        with self.store.lock:
            self._prune_expired_syncs()
            canonical = self._fork_summary(self.store.chain)
            candidates = [
                self._fork_summary(self.store.forks[tip])
                for tip in sorted(self.store.forks)
            ]
            winner_tip, winner_chain = self._winning_fork()
            adoptable: list[dict] = []
            if winner_tip != self.store.tip_hash():
                adoptable.append(self._fork_summary(winner_chain))
            return 200, {
                "canonical": canonical,
                "candidates": candidates,
                "adoptable": adoptable,
            }

    def adopt_fork(self, tip_hash: object) -> tuple[int, dict]:
        """POST /v1/forks/{tip_hash}/adopt — atomically switch to the winner.

        Unknown tips return 404; adopting anything other than the current
        winning (longest / smallest-tip-hash) chain returns 409. Adoption
        replaces the canonical chain and mempool in one atomic write that
        advances the generation and rebuilds all indexes; transactions unique
        to the old chain's confirmed history return to the mempool, while
        pending-block transactions never enter it.
        """
        if not crypto.is_hex64(tip_hash):
            return 404, {"error": "unknown fork tip"}
        with self.store.lock:
            self._prune_expired_syncs()
            fork = self.store.forks.get(tip_hash)
            if fork is None:
                return 404, {"error": "unknown fork tip"}
            winner_tip, _ = self._winning_fork()
            if winner_tip != tip_hash:
                return 409, {"error": "only the winning fork can be adopted"}
            old_chain = self.store.chain
            old_pending = dict(self.store.pending)
            self.store.forks.pop(tip_hash)
            self.store.replace_chain(fork)
            try:
                self.store.save()
            except BaseException:
                # Restore the pre-adoption in-memory state on a failed write.
                self.store.chain = old_chain
                self.store.pending = old_pending
                self.store.forks[tip_hash] = fork
                self.store.rebuild_derived()
                raise
            return 200, self._fork_summary(fork)

    def export_fork(self, tip_hash: object) -> tuple[int, dict]:
        """GET /v1/forks/{tip_hash}/export — full export of a candidate fork.

        Only stored candidates are exportable: the canonical tip, an unknown
        tip and a malformed tip hash (not 64 lowercase hex chars) all return
        404. The response carries exactly five fields — the fork descriptor
        (tip_hash, height, length, status, all describing the tip block) plus
        the full block list including the genesis block, every transaction's
        signature and an optional pending tip — and can be resubmitted to
        POST /v1/forks/candidates verbatim.
        """
        if not crypto.is_hex64(tip_hash):
            return 404, {"error": "unknown fork tip"}
        with self.store.lock:
            fork = self.store.forks.get(tip_hash)
            if fork is None:
                return 404, {"error": "unknown fork tip"}
            body = self._fork_summary(fork)
            body["blocks"] = [block.to_dict() for block in fork]
            return 200, body

    # -- inter-node fork sync -------------------------------------------------

    SYNC_DEFAULT_LIMIT = 50
    SYNC_MAX_LIMIT = 200

    @staticmethod
    def _candidate_blocks(candidate: object) -> object:
        """Normalize a sync ``candidate`` to its raw blocks list.

        The candidate follows the existing export format (the five-field
        ``{tip_hash, height, length, status, blocks}`` document); the
        ``{"blocks": [...]}`` wrapper and a bare block list are accepted too.
        """
        if isinstance(candidate, dict):
            return candidate.get("blocks")
        return candidate

    @staticmethod
    def _candidate_fingerprint(blocks_raw: list) -> str:
        """Stable content fingerprint of a candidate's raw block list.

        Used to decide whether a same-key retry carries the same candidate
        content. Key order and whitespace are normalized so two documents that
        serialize the same blocks identically compare equal.
        """
        return hashlib.sha256(
            json.dumps(blocks_raw, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()

    def _prune_expired_syncs(self) -> list[str]:
        """Remove expired sync records and the candidate forks they brought in.

        A candidate received through a sync lives only while its record is
        unexpired; on expiry both the record and its still-stored candidate fork
        are dropped in memory. Candidates submitted directly (no sync record)
        never expire, and an adopted tip is no longer in ``forks`` (it is on the
        canonical chain) so its expiring record leaves the chain untouched.
        Caller must hold the store lock. Returns the pruned tip hashes.
        """
        expired_tips = self.store.prune_syncs()
        for tip in expired_tips:
            self.store.forks.pop(tip, None)
        return expired_tips

    def _tip_descriptor(self, tip_hash: str) -> dict | None:
        """Resolve (height/length/status) for a synced tip.

        Looks the candidate up among stored forks first, then among canonical
        blocks, so audit rows remain available after the candidate is adopted.
        """
        fork = self.store.forks.get(tip_hash)
        if fork is not None:
            return self._fork_summary(fork)
        for block in self.store.chain:
            if block.block_hash == tip_hash:
                return {
                    "tip_hash": block.block_hash,
                    "height": block.height,
                    # Length counts every block including the genesis block.
                    "length": block.height + 1,
                    "status": block.status,
                }
        return None

    def submit_fork_sync(self, payload: object) -> tuple[int, dict]:
        """POST /v1/forks/sync — receive a candidate chain from another node.

        The request carries ``source``, ``request_id``, ``expires_at`` (Unix
        seconds) and ``candidate`` (an export-format fork document). The
        candidate is re-validated exactly like a direct candidate submission
        (canonical genesis, consecutive heights and prev_hash linkage,
        recomputed block hashes and Merkle roots, tx_id and Ed25519 signatures,
        unique ascending tx_ids, endowment replay, pending-only-at-tip).

        Returns 201 with ``{tip_hash, height, length, status, expires_at}``.
        An expired request returns 410; malformed fields or a failing chain
        validation return 400. A retry with the same source + request_id and
        identical content replays the original result as 200; the same key with
        different content, or a duplicate tip already known, returns 409.
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in ("source", "request_id", "expires_at", "candidate"):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}

        source = payload["source"]
        request_id = payload["request_id"]
        expires_at = payload["expires_at"]
        candidate = payload["candidate"]

        if not isinstance(source, str) or not source:
            return 400, {"error": "field 'source' must be a non-empty string"}
        if not isinstance(request_id, str) or not request_id:
            return 400, {"error": "field 'request_id' must be a non-empty string"}
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            return 400, {"error": "field 'expires_at' must be a Unix-seconds integer"}

        blocks_raw = self._candidate_blocks(candidate)
        if not isinstance(blocks_raw, list):
            return 400, {"error": "field 'candidate' must contain a 'blocks' list"}

        with self.store.lock:
            self._prune_expired_syncs()

            key = (source, request_id)
            existing = self.store.syncs.get(key)
            if existing is not None:
                # A retry on a live key is idempotent only when it carries the
                # identical candidate content; a changed body conflicts 409.
                fingerprint = self._candidate_fingerprint(blocks_raw)
                if fingerprint != existing["fingerprint"]:
                    return 409, {
                        "error": "request_id already used with different content"
                    }
                descriptor = self._tip_descriptor(existing["tip_hash"]) or {
                    "tip_hash": existing["tip_hash"],
                    "height": None,
                    "length": None,
                    "status": None,
                }
                return 200, {
                    "tip_hash": descriptor["tip_hash"],
                    "height": descriptor.get("height"),
                    "length": descriptor.get("length"),
                    "status": descriptor.get("status"),
                    "expires_at": existing["expires_at"],
                }

            # Expiry is enforced after the idempotency lookup but before the
            # expensive chain validation: an expired delivery is rejected 410.
            if expires_at <= time.time():
                return 410, {"error": "sync request has expired"}

            try:
                fork = self.store.validate_fork_blocks(blocks_raw)
            except ValueError as exc:
                return 400, {"error": str(exc)}
            summary = self._fork_summary(fork)
            # Re-verify any export-format summary fields carried on the doc.
            if isinstance(candidate, dict):
                for field in ("tip_hash", "height", "length", "status"):
                    if field in candidate and candidate[field] != summary[field]:
                        return 400, {
                            "error": f"candidate field {field!r} does not match the blocks"
                        }
            tip_hash = fork[-1].block_hash
            fingerprint = self._candidate_fingerprint(blocks_raw)

            if any(tip_hash == block.block_hash for block in self.store.chain):
                return 409, {"error": "fork is identical to the canonical chain"}
            if tip_hash in self.store.forks:
                return 409, {
                    "error": "candidate fork already exists",
                    "tip_hash": tip_hash,
                }

            self.store.forks[tip_hash] = fork
            self.store.syncs[key] = {
                "tip_hash": tip_hash,
                "expires_at": expires_at,
                "fingerprint": fingerprint,
            }
            try:
                self.store.save()
            except BaseException:
                # Roll back both the candidate and its metadata together so a
                # failed write never leaves one without the other.
                self.store.syncs.pop(key, None)
                self.store.forks.pop(tip_hash, None)
                raise

            result = dict(summary)
            result["expires_at"] = expires_at
            return 201, result

    def list_fork_syncs(self, params: dict) -> tuple[int, dict]:
        """GET /v1/forks/sync — audit listing of received sync candidates.

        Filters: ``source`` (exact), ``min_height`` and ``max_height``.
        ``limit`` defaults to 50 and must be 1-200; ``cursor`` defaults to 0.
        Every numeric value must be a plain decimal without leading zeros; a
        malformed value returns 400. Rows are ordered by
        ``(height, tip_hash, source)``; ``cursor == total`` returns an empty
        page, ``cursor > total`` returns 400. Each item carries
        ``source, request_id, tip_hash, height, length, status, expires_at``.
        """
        source = params.get("source")
        if source is not None and (not isinstance(source, str) or not source):
            return 400, {"error": "source must be a non-empty string"}

        min_height = None
        if params.get("min_height") is not None:
            min_height = _parse_decimal(params["min_height"])
            if min_height is None:
                return 400, {"error": "min_height must be a non-negative decimal"}
        max_height = None
        if params.get("max_height") is not None:
            max_height = _parse_decimal(params["max_height"])
            if max_height is None:
                return 400, {"error": "max_height must be a non-negative decimal"}
        if min_height is not None and max_height is not None and min_height > max_height:
            return 400, {"error": "min_height must not exceed max_height"}

        limit = self.SYNC_DEFAULT_LIMIT
        if params.get("limit") is not None:
            parsed = _parse_decimal(params["limit"])
            if parsed is None or not 1 <= parsed <= self.SYNC_MAX_LIMIT:
                return 400, {"error": "limit must be a decimal between 1 and 200"}
            limit = parsed
        cursor = 0
        if params.get("cursor") is not None:
            parsed = _parse_decimal(params["cursor"])
            if parsed is None:
                return 400, {"error": "cursor must be a non-negative decimal"}
            cursor = parsed

        with self.store.lock:
            self._prune_expired_syncs()
            rows: list[dict] = []
            for (rec_source, request_id), rec in self.store.syncs.items():
                if source is not None and rec_source != source:
                    continue
                descriptor = self._tip_descriptor(rec["tip_hash"])
                if descriptor is None:
                    continue
                if min_height is not None and descriptor["height"] < min_height:
                    continue
                if max_height is not None and descriptor["height"] > max_height:
                    continue
                rows.append(
                    {
                        "source": rec_source,
                        "request_id": request_id,
                        "tip_hash": descriptor["tip_hash"],
                        "height": descriptor["height"],
                        "length": descriptor["length"],
                        "status": descriptor["status"],
                        "expires_at": rec["expires_at"],
                    }
                )

        rows.sort(key=lambda row: (row["height"], row["tip_hash"], row["source"]))
        total = len(rows)
        if cursor > total:
            return 400, {"error": "cursor is beyond the result set"}
        items = rows[cursor : cursor + limit]
        next_cursor = cursor + limit if cursor + limit < total else None
        return 200, {"items": items, "total": total, "next_cursor": next_cursor}


    # -- transaction index ----------------------------------------------------

    INDEX_DEFAULT_LIMIT = 50
    INDEX_MAX_LIMIT = 200

    def list_transactions(self, params: dict) -> tuple[int, dict]:
        """GET /v1/index/transactions — paginated confirmed-chain tx index.

        Pending-tip transactions are excluded. Filters (AND-combined):
        ``tx_id`` (64 lowercase hex), ``account`` (matches sender or
        recipient) and ``height``; ``limit`` (default 50, range 1-200) and
        ``cursor`` (default 0) paginate. Numeric filters must be plain
        decimals without leading zeros; any malformed value returns 400.
        Rows are ordered by (height, index, tx_id); ``index`` is the
        transaction's 0-based position inside its block, matching the Merkle
        proof index. A cursor beyond the filtered total returns 400, a cursor
        equal to it returns an empty page.
        """
        tx_id = params.get("tx_id")
        if tx_id is not None and not crypto.is_hex64(tx_id):
            return 400, {"error": "tx_id must be 64 lowercase hex characters"}
        account = params.get("account")
        if account is not None and (not isinstance(account, str) or not account):
            return 400, {"error": "account must be a non-empty string"}

        height = None
        if params.get("height") is not None:
            height = _parse_decimal(params["height"])
            if height is None:
                return 400, {"error": "height must be a non-negative decimal"}
        limit = self.INDEX_DEFAULT_LIMIT
        if params.get("limit") is not None:
            parsed = _parse_decimal(params["limit"])
            if parsed is None or not 1 <= parsed <= self.INDEX_MAX_LIMIT:
                return 400, {"error": "limit must be a decimal between 1 and 200"}
            limit = parsed
        cursor = 0
        if params.get("cursor") is not None:
            parsed = _parse_decimal(params["cursor"])
            if parsed is None:
                return 400, {"error": "cursor must be a non-negative decimal"}
            cursor = parsed

        with self.store.lock:
            rows: list[dict] = []
            for block in self.store.chain:
                if block.status != STATUS_CONFIRMED:
                    continue
                if height is not None and block.height != height:
                    continue
                for index, tx in enumerate(block.transactions):
                    if tx_id is not None and tx.tx_id != tx_id:
                        continue
                    if account is not None and account not in (tx.sender, tx.recipient):
                        continue
                    rows.append(
                        {
                            "tx_id": tx.tx_id,
                            "height": block.height,
                            "block_hash": block.block_hash,
                            "index": index,
                            "from": tx.sender,
                            "to": tx.recipient,
                            "amount": tx.amount,
                        }
                    )
        # Chain order is already (height, index) ascending; the tx_id
        # tiebreaker is implied because ids are unique within a block.
        total = len(rows)
        if cursor > total:
            return 400, {"error": "cursor is beyond the result set"}
        items = rows[cursor : cursor + limit]
        next_cursor = cursor + limit if cursor + limit < total else None
        return 200, {"items": items, "total": total, "next_cursor": next_cursor}
