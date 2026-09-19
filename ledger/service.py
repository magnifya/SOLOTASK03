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


class LedgerService:
    def __init__(self, store: LedgerStore, initial_balance: int = DEFAULT_INITIAL_BALANCE) -> None:
        self.store = store
        self.initial_balance = initial_balance

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
            self.store.save()
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
            for tx in ordered:
                self.store.pending.pop(tx.tx_id, None)
            self.store.save()
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
            self.store.save()
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
            rolled_back = self.store.rollback_tip()
            self.store.save()
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
