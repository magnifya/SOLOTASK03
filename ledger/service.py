"""Ledger business logic: submit transactions, mine, confirm, rollback, query.

Block lifecycle
---------------
Mined blocks are created as ``pending`` and only become ``confirmed`` through
``POST /v1/blocks/{height}/confirm``. At most one block may be pending and it
must be the chain tip. A pending tip can be rolled back, which deletes it and
returns its transactions to the pending transaction set (de-duplicated);
re-mining the same set on top of the same parent reproduces the identical
block hash.

Balance convention
------------------
The contract defines no minting endpoint, so every identity starts with a
fixed endowment (``initial_balance``, overridable via LEDGER_INITIAL_BALANCE).
An account's confirmed balance is::

    initial_balance + sum(confirmed amounts received) - sum(confirmed amounts sent)

Only confirmed blocks feed accounts and balances. Funds committed by
not-yet-confirmed transactions -- both queued in the pending set and packed
into the pending block -- reduce the spendable balance, while pending credits
are never counted. An identity only becomes a *queryable account* once it
appears in a confirmed block; GET account before that returns 404. Balance
checks at submission time treat an identity that has never appeared on chain
as holding the initial endowment, otherwise the first transaction in an empty
ledger could never be accepted.
"""
from __future__ import annotations

from . import crypto
from .models import (
    STATUS_CONFIRMED,
    STATUS_PENDING,
    STATUS_ROLLED_BACK,
    Block,
    Transaction,
)
from .store import LedgerStore

DEFAULT_INITIAL_BALANCE = 1_000_000

REQUIRED_TX_FIELDS = ("from", "to", "amount", "signature")


def _parse_height(height: object) -> int | None:
    """Strictly parse a path-segment height; floats and junk yield None."""
    try:
        height_int = int(height)  # type: ignore[arg-type]
        if str(height_int) != str(height).strip():
            return None
    except (TypeError, ValueError):
        return None
    return height_int


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
            if tx.tx_id in self.store.tx_index:
                return 409, {"error": "transaction already confirmed", "tx_id": tx.tx_id}
            if self._in_pending_block(tx.tx_id):
                return 409, {"error": "transaction already pending", "tx_id": tx.tx_id}
            if self.available_balance(sender) < amount:
                return 400, {"error": "insufficient balance"}
            self.store.pending[tx.tx_id] = tx
            self.store.save()
        return 202, {"tx_id": tx.tx_id}

    def _in_pending_block(self, tx_id: str) -> bool:
        """True iff tx_id is packed into the (tip) pending block."""
        tip = self.store.chain[-1]
        if tip.status != STATUS_PENDING:
            return False
        return any(existing.tx_id == tx_id for existing in tip.transactions)

    # -- blocks -------------------------------------------------------------

    def mine_block(self) -> tuple[int, dict]:
        """Pack all pending transactions (ascending tx_id) into a pending block.

        Allowed only when the chain tip is confirmed and the pending set is
        non-empty; anything else yields 409.
        """
        with self.store.lock:
            if self.store.tip().status != STATUS_CONFIRMED:
                return 409, {"error": "chain tip is not confirmed"}
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
            if height_int < 0 or height_int >= len(self.store.chain):
                return 404, {"error": "block not found"}
            return 200, self.store.chain[height_int].to_summary()

    def get_block_status(self, height: object) -> tuple[int, dict]:
        """Return {height, status}; 404 for an unknown height."""
        height_int = _parse_height(height)
        if height_int is None:
            return 404, {"error": "block not found"}
        with self.store.lock:
            if height_int < 0 or height_int >= len(self.store.chain):
                return 404, {"error": "block not found"}
            block = self.store.chain[height_int]
            return 200, {"height": block.height, "status": block.status}

    def confirm_block(self, height: object) -> tuple[int, dict]:
        """Confirm the pending chain tip once its predecessor is confirmed.

        Confirming an already confirmed block is idempotent. Every other case
        (unknown height, pending non-tip, unconfirmed predecessor) is 409.
        """
        height_int = _parse_height(height)
        with self.store.lock:
            if height_int is None or height_int < 0 or height_int >= len(self.store.chain):
                return 409, {"error": "block cannot be confirmed"}
            block = self.store.chain[height_int]
            if block.status == STATUS_CONFIRMED:
                return 200, {"height": block.height, "status": STATUS_CONFIRMED}
            is_tip = height_int == len(self.store.chain) - 1
            prev_confirmed = (
                height_int > 0
                and self.store.chain[height_int - 1].status == STATUS_CONFIRMED
            )
            if not (is_tip and prev_confirmed):
                return 409, {"error": "block cannot be confirmed"}
            block.status = STATUS_CONFIRMED
            for tx in block.transactions:
                self.store.tx_index[tx.tx_id] = block.height
            self.store.save()
            return 200, {"height": block.height, "status": STATUS_CONFIRMED}

    def rollback_block(self, height: object) -> tuple[int, dict]:
        """Roll back the pending chain tip.

        The block is deleted and its transactions are restored to the pending
        set (de-duplicated against anything already queued). Unknown heights,
        including heights already rolled back, yield 404; confirmed blocks and
        non-tip requests yield 409.
        """
        height_int = _parse_height(height)
        if height_int is None or height_int < 0:
            return 404, {"error": "block not found"}
        with self.store.lock:
            if height_int >= len(self.store.chain):
                return 404, {"error": "block not found"}
            block = self.store.chain[height_int]
            if block.status == STATUS_CONFIRMED:
                return 409, {"error": "confirmed block cannot be rolled back"}
            if height_int != len(self.store.chain) - 1:
                return 409, {"error": "only the chain tip can be rolled back"}
            for tx in block.transactions:
                # De-duplicate: never overwrite a transaction already queued.
                if tx.tx_id not in self.store.pending:
                    self.store.pending[tx.tx_id] = tx
            del self.store.chain[height_int]
            self.store.save()
        return 200, {"height": height_int, "status": STATUS_ROLLED_BACK}

    def get_proof(self, height: object, tx_id: object) -> tuple[int, dict]:
        """Return a Merkle inclusion proof for tx_id at the given height.

        Returns 404 for an unknown height, a malformed height/tx_id, or a
        transaction absent from that block; 409 for a block that is still
        pending, since only confirmed transactions carry a verifiable proof.
        """
        height_int = _parse_height(height)
        if height_int is None:
            return 404, {"error": "block not found"}
        if not crypto.is_hex64(tx_id):
            return 404, {"error": "transaction not found"}
        with self.store.lock:
            if height_int < 0 or height_int >= len(self.store.chain):
                return 404, {"error": "block not found"}
            block = self.store.chain[height_int]
            if block.status != STATUS_CONFIRMED:
                return 409, {"error": "block is not confirmed"}
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
            confirmed: list[str] = []
            for block in self._confirmed_blocks():
                for tx in block.transactions:
                    if tx.sender == account or tx.recipient == account:
                        confirmed.append(tx.tx_id)
            if not confirmed:
                return 404, {"error": "account not found"}
            return 200, {
                "account": account,
                # Confirmed result minus every not-yet-confirmed outgoing
                # amount; pending credits are intentionally excluded.
                "balance": self.available_balance(account),
                "confirmed_transactions": confirmed,
            }

    def _confirmed_blocks(self) -> list[Block]:
        confirmed: list[Block] = []
        for block in self.store.chain:
            if block.status != STATUS_CONFIRMED:
                break
            confirmed.append(block)
        return confirmed

    def confirmed_balance(self, account: str) -> int:
        """Initial endowment plus confirmed credits minus confirmed debits."""
        balance = self.initial_balance
        for block in self._confirmed_blocks():
            for tx in block.transactions:
                if tx.sender == account:
                    balance -= tx.amount
                if tx.recipient == account:
                    balance += tx.amount
        return balance

    def available_balance(self, account: str) -> int:
        """Confirmed balance minus all not-yet-confirmed outgoing amounts.

        Pending credits are deliberately not counted, so a sequence of
        submissions cannot spend money that has not been confirmed yet. Both
        queued transactions and transactions packed into the pending block
        commit the sender's balance.
        """
        balance = self.confirmed_balance(account)
        for tx in self.store.pending.values():
            if tx.sender == account:
                balance -= tx.amount
        tip = self.store.chain[-1]
        if tip.status == STATUS_PENDING:
            for tx in tip.transactions:
                if tx.sender == account:
                    balance -= tx.amount
        return balance
