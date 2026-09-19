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

import re

from . import crypto
from .models import STATUS_CONFIRMED, STATUS_PENDING, Block, Transaction
from .store import LedgerStore

DEFAULT_INITIAL_BALANCE = 1_000_000

REQUIRED_TX_FIELDS = ("from", "to", "amount", "signature")

# Strict non-negative decimal with no sign, whitespace or leading zero
# (the single value "0" is allowed). Query parameters for the transaction
# index must look exactly like this.
_DECIMAL_RE = re.compile(r"0|[1-9][0-9]*")

DEFAULT_INDEX_LIMIT = 50
MAX_INDEX_LIMIT = 200


def _strict_decimal(value: object) -> int | None:
    """Parse a non-negative decimal without a leading zero; None if malformed."""
    if not isinstance(value, str) or _DECIMAL_RE.fullmatch(value) is None:
        return None
    return int(value)


def _parse_height(height: object) -> int | None:
    """Strict decimal height parse; None when malformed."""
    try:
        height_int = int(height)  # type: ignore[arg-type]
        if str(height_int) != str(height).strip():
            raise ValueError
        return height_int
    except (TypeError, ValueError):
        return None


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
        tip_hash = fork[-1].block_hash
        with self.store.lock:
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

    # -- fork export ---------------------------------------------------------

    def export_fork(self, tip_hash: object) -> tuple[int, dict]:
        """GET /v1/forks/{tip_hash}/export — export one candidate fork.

        Only a stored *candidate* fork can be exported. The canonical chain
        (its tip is never held as a candidate), an unknown tip hash, and a
        malformed (non-64-lowercase-hex) tip hash all return 404. On success
        the response is the fork descriptor S plus a ``blocks`` array holding
        every block of the fork (canonical genesis first, signed transactions
        inline, and an optional pending tip block) in storage form.
        """
        if not crypto.is_hex64(tip_hash):
            return 404, {"error": "unknown fork tip"}
        with self.store.lock:
            fork = self.store.forks.get(tip_hash)
            if fork is None:
                # Covers both a genuinely unknown tip and the canonical chain,
                # whose tip is never stored as a candidate.
                return 404, {"error": "unknown fork tip"}
            summary = self._fork_summary(fork)
            summary["blocks"] = [block.to_dict() for block in fork]
        return 200, summary

    # -- transaction index ----------------------------------------------------

    def get_transaction_index(self, params: dict) -> tuple[int, dict]:
        """GET /v1/index/transactions — page over confirmed-chain transactions.

        Only confirmed blocks are indexed; a pending tip is excluded. Filters
        are combined with AND:

        - ``tx_id``  exact 64-char lowercase hex transaction id
        - ``account`` matches transactions sent *or* received by the account
        - ``height`` exact block height (strict non-negative decimal)
        - ``limit``  page size, 1..200 (default 50)
        - ``cursor`` offset into the *filtered* sequence (default 0)

        Rows are ordered by (height, index-in-block, tx_id) ascending. Any
        malformed parameter (bad hex/decimal, out-of-range limit) returns 400.
        ``cursor`` may equal the filtered total (an empty trailing page) but a
        cursor past the total returns 400. Returns
        ``{items, total, next_cursor}``; ``next_cursor`` is the next offset or
        null at the end.
        """
        if not isinstance(params, dict):
            return 400, {"error": "query parameters must be a mapping"}

        f_tx_id = params.get("tx_id")
        f_account = params.get("account")
        f_height_raw = params.get("height")
        f_limit_raw = params.get("limit")
        f_cursor_raw = params.get("cursor")

        # tx_id must be 64-char lowercase hex when supplied.
        if f_tx_id is not None:
            if not crypto.is_hex64(f_tx_id):
                return 400, {"error": "query 'tx_id' must be 64 lowercase hex chars"}
        # An account filter is an opaque exact-match string: a value that
        # matches no identity simply yields an empty page rather than an error.
        if f_account is not None and (not isinstance(f_account, str) or not f_account):
            return 400, {"error": "query 'account' must be a non-empty string"}

        f_height = None
        if f_height_raw is not None:
            f_height = _strict_decimal(f_height_raw)
            if f_height is None:
                return 400, {"error": "query 'height' must be a non-negative decimal integer"}

        limit = DEFAULT_INDEX_LIMIT
        if f_limit_raw is not None:
            limit = _strict_decimal(f_limit_raw)
            if limit is None or not (1 <= limit <= MAX_INDEX_LIMIT):
                return 400, {
                    "error": f"query 'limit' must be a decimal integer in 1..{MAX_INDEX_LIMIT}"
                }

        cursor = 0
        if f_cursor_raw is not None:
            cursor = _strict_decimal(f_cursor_raw)
            if cursor is None:
                return 400, {"error": "query 'cursor' must be a non-negative decimal integer"}

        with self.store.lock:
            # Walking the chain in height order and each block in its stored
            # (tx_id ascending) order yields the required (height, index,
            # tx_id) ordering with no further sort. Pending blocks are skipped.
            filtered: list[dict] = []
            for block in self.store.chain:
                if block.status != STATUS_CONFIRMED:
                    continue
                if f_height is not None and block.height != f_height:
                    continue
                block_hash = block.block_hash
                for index, tx in enumerate(block.transactions):
                    if f_tx_id is not None and tx.tx_id != f_tx_id:
                        continue
                    if f_account is not None and (
                        tx.sender != f_account and tx.recipient != f_account
                    ):
                        continue
                    filtered.append(
                        {
                            "tx_id": tx.tx_id,
                            "height": block.height,
                            "block_hash": block_hash,
                            "index": index,
                            "from": tx.sender,
                            "to": tx.recipient,
                            "amount": tx.amount,
                        }
                    )

        total = len(filtered)
        # cursor == total is a valid (empty) trailing page; beyond it is 400.
        if cursor > total:
            return 400, {
                "error": "query 'cursor' is past the last page",
                "total": total,
            }
        page = filtered[cursor : cursor + limit]
        end = cursor + len(page)
        next_cursor = end if end < total else None
        return 200, {"items": page, "total": total, "next_cursor": next_cursor}
