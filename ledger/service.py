"""Ledger business logic: submit transactions, mine blocks, query state.

Balance convention
------------------
The contract defines no minting endpoint, so every identity starts with a
fixed endowment (``initial_balance``, overridable via LEDGER_INITIAL_BALANCE).
An account's confirmed balance is::

    initial_balance + sum(confirmed amounts received) - sum(confirmed amounts sent)

An identity only becomes a *queryable account* once it appears in a confirmed
block; GET account before that returns 404. Balance checks at submission time
treat an identity that has never appeared on chain as holding the initial
endowment, otherwise the first transaction in an empty ledger could never be
accepted.
"""
from __future__ import annotations

from . import crypto
from .models import Block, Transaction
from .store import LedgerStore

DEFAULT_INITIAL_BALANCE = 1_000_000

REQUIRED_TX_FIELDS = ("from", "to", "amount", "signature")


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
        """Pack all pending transactions (ascending tx_id) into one block."""
        with self.store.lock:
            if not self.store.pending:
                return 409, {"error": "no pending transactions"}
            ordered = sorted(self.store.pending.values(), key=lambda tx: tx.tx_id)
            block = Block.create(
                height=self.store.next_height(),
                prev_hash=self.store.tip_hash(),
                transactions=ordered,
            )
            self.store.chain.append(block)
            for tx in ordered:
                self.store.pending.pop(tx.tx_id, None)
            self.store.save()
        return 201, {
            "height": block.height,
            "block_hash": block.block_hash,
            "merkle_root": block.merkle_root,
        }

    def get_block(self, height: object) -> tuple[int, dict]:
        try:
            height_int = int(height)  # type: ignore[arg-type]
            if str(height_int) != str(height).strip():
                raise ValueError
        except (TypeError, ValueError):
            return 404, {"error": "block not found"}
        with self.store.lock:
            if height_int < 0 or height_int >= len(self.store.chain):
                return 404, {"error": "block not found"}
            return 200, self.store.chain[height_int].to_summary()

    def get_proof(self, height: object, tx_id: object) -> tuple[int, dict]:
        """Return a Merkle inclusion proof for tx_id at the given height.

        Returns 404 for an unknown height, a malformed height/tx_id, or a
        transaction absent from that block.
        """
        try:
            height_int = int(height)  # type: ignore[arg-type]
            if str(height_int) != str(height).strip():
                raise ValueError
        except (TypeError, ValueError):
            return 404, {"error": "block not found"}
        if not crypto.is_hex64(tx_id):
            return 404, {"error": "transaction not found"}
        with self.store.lock:
            if height_int < 0 or height_int >= len(self.store.chain):
                return 404, {"error": "block not found"}
            block = self.store.chain[height_int]
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
            for block in self.store.chain:
                for tx in block.transactions:
                    if tx.sender == account or tx.recipient == account:
                        confirmed.append(tx.tx_id)
            if not confirmed:
                return 404, {"error": "account not found"}
            return 200, {
                "account": account,
                "balance": self.confirmed_balance(account),
                "confirmed_transactions": confirmed,
            }

    def confirmed_balance(self, account: str) -> int:
        balance = self.initial_balance
        for block in self.store.chain:
            for tx in block.transactions:
                if tx.sender == account:
                    balance -= tx.amount
                if tx.recipient == account:
                    balance += tx.amount
        return balance

    def available_balance(self, account: str) -> int:
        """Confirmed balance minus amounts already committed in pending txs.

        Pending credits are deliberately not counted, so a sequence of
        submissions cannot spend money that has not been packed yet.
        """
        balance = self.confirmed_balance(account)
        for tx in self.store.pending.values():
            if tx.sender == account:
                balance -= tx.amount
        return balance
