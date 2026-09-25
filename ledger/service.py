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
import hmac
import json
import time

from . import audit
from . import crypto
from .models import STATUS_CONFIRMED, STATUS_PENDING, Block, Transaction
from .store import (
    SYNC_MODE_ATTESTED,
    SYNC_MODE_PLAIN,
    TRUST_ACTIVE,
    TRUST_REVOKED,
    LedgerStore,
    attested_fingerprint,
    attested_message,
    attested_range_fingerprint,
    attested_range_message,
    valid_history_permissions,
)

DEFAULT_INITIAL_BALANCE = 1_000_000

REQUIRED_TX_FIELDS = ("from", "to", "amount", "signature")

# Audit event kinds. The log is append-only: trust lifecycle changes
# (registered/rotated/revoked) and inter-node sync events
# (received/adopted/expired) are all recorded permanently.
EVENT_SOURCE_REGISTERED = "source_registered"
EVENT_SOURCE_ROTATED = "source_rotated"
EVENT_SOURCE_REVOKED = "source_revoked"
EVENT_SYNC_RECEIVED = "sync_received"
EVENT_SYNC_ADOPTED = "sync_adopted"
EVENT_SYNC_EXPIRED = "sync_expired"
EVENT_AUDIT_SIGNER_ROTATED = "audit_signer_rotated"
EVENT_ALLOWLIST_ADDED = "allowlist_added"
EVENT_ALLOWLIST_REMOVED = "allowlist_removed"
EVENT_HISTORY_ACCESS = "history_access"
EVENT_HISTORY_CREDENTIAL_CHANGED = "history_credential_changed"


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
    def __init__(
        self,
        store: LedgerStore,
        initial_balance: int = DEFAULT_INITIAL_BALANCE,
        history_config: tuple[str, str, str] | None = None,
    ) -> None:
        self.store = store
        # Optional token-gated checkpoint-history endpoints. When set, the
        # triple is ``(checkpoint_path, signer_log_path, bearer_token)`` and
        # the store already knows the two paths for startup re-verification.
        if history_config is not None:
            self.history_path, self.history_trust_path, self.history_token = (
                history_config
            )
            self.history_enabled = True
        else:
            self.history_path = None
            self.history_trust_path = None
            self.history_token = None
            self.history_enabled = False
        # The snapshot-recorded endowment is the only balance-replay / balance
        # reporting parameter: a recovered store already knows its endowment, so
        # restarting with a different --initial-balance must not change any
        # legality or reported balance. Only a brand-new store (no recorded
        # value) adopts the constructor argument.
        if store.initial_balance is None:
            store.initial_balance = initial_balance
            self.initial_balance = initial_balance
        else:
            self.initial_balance = store.initial_balance

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

    def get_transaction(self, tx_id: object) -> tuple[int, dict]:
        """GET /v1/transactions/{tx_id} — one transaction receipt.

        The lookup covers the canonical chain and the mempool only; candidate
        forks are never exposed. A ``tx_id`` that is not exactly 64 lowercase
        hex characters, or one nothing holds, returns 404.

        A mempool transaction is reported ``pending`` with ``height``,
        ``block_hash`` and ``index`` all null. A transaction packed into the
        unconfirmed tip block is ``pending`` too, anchored at that block with
        its 0-based in-block index. A transaction in a confirmed block is
        ``confirmed``. Every receipt is built from the stored signed
        transaction: the id is recomputed from its canonical message (never
        taken from an index or a fork-side cache) and the fields are strictly
        re-typed (non-empty strings, a positive non-boolean integer amount),
        so adoption, rollback and restart can only ever surface the current
        canonical/pending state.
        """
        if not crypto.is_hex64(tx_id):
            return 404, {"error": "transaction not found"}
        with self.store.lock:
            # Canonical chain first: confirmed blocks, then at most one
            # pending tip. The stored signed transaction is the sole source
            # for the receipt, and its id is recomputed rather than trusted
            # from any lookup key.
            for block in self.store.chain:
                for index, tx in enumerate(block.transactions):
                    if tx.tx_id != tx_id:
                        continue
                    if not self._is_receipt_tx_well_typed(tx):
                        return 404, {"error": "transaction not found"}
                    status = (
                        STATUS_CONFIRMED
                        if block.status == STATUS_CONFIRMED
                        else STATUS_PENDING
                    )
                    return 200, self._transaction_receipt(
                        tx, status, block.height, block.block_hash, index
                    )
            # Still unpacked in the mempool.
            tx = self.store.pending.get(tx_id)
            if tx is not None:
                if not self._is_receipt_tx_well_typed(tx):
                    return 404, {"error": "transaction not found"}
                return 200, self._transaction_receipt(
                    tx, STATUS_PENDING, None, None, None
                )
            return 404, {"error": "transaction not found"}

    @staticmethod
    def _is_receipt_tx_well_typed(tx: Transaction) -> bool:
        """Strict receipt-time type check of a stored signed transaction.

        Every stored transaction already passed these checks at submission
        (and again during snapshot recovery); the re-check guarantees a
        receipt can never serialize a value that violates the response
        contract, even if an in-memory invariant were broken.
        """
        return (
            isinstance(tx.sender, str)
            and bool(tx.sender)
            and isinstance(tx.recipient, str)
            and bool(tx.recipient)
            and isinstance(tx.amount, int)
            and not isinstance(tx.amount, bool)
            and tx.amount > 0
            and isinstance(tx.signature, str)
            and bool(tx.signature)
        )

    @staticmethod
    def _transaction_receipt(
        tx: Transaction,
        status: str,
        height: int | None,
        block_hash: str | None,
        index: int | None,
    ) -> dict:
        """The fixed nine-field receipt shape."""
        return {
            "tx_id": tx.tx_id,
            "from": tx.sender,
            "to": tx.recipient,
            "amount": tx.amount,
            "signature": tx.signature,
            "status": status,
            "height": height,
            "block_hash": block_hash,
            "index": index,
        }

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

    def get_proofs(self, height: object, payload: object) -> tuple[int, dict]:
        """Return Merkle inclusion proofs for a batch of tx_ids at one height.

        POST /v1/blocks/{height}/proofs with ``{"tx_ids": [...]}``. The body
        must be a JSON object containing exactly the ``tx_ids`` key: a
        non-empty list of distinct 64-lowercase-hex strings. A malformed body
        — parse failure, missing/extra keys, a wrong type, an empty list,
        duplicates or a wrongly formatted id — is 400 and never touches state.
        A malformed/unknown height or any requested transaction absent from
        the block is 404; proofs are only issued for confirmed blocks, so a
        pending block returns 409.

        On success the body carries the block's complete ascending
        ``transaction_ids`` (every leaf) plus one
        ``{tx_id, index, siblings}`` proof per requested id, the proofs sorted
        by tx_id; the sibling paths run leaf-to-root exactly like
        :meth:`get_proof`.
        """
        if not isinstance(payload, dict) or set(payload) != {"tx_ids"}:
            return 400, {"error": "request body must be a JSON object with only 'tx_ids'"}
        tx_ids_raw = payload["tx_ids"]
        if not isinstance(tx_ids_raw, list) or not tx_ids_raw:
            return 400, {"error": "field 'tx_ids' must be a non-empty array"}
        if any(not crypto.is_hex64(tx_id) for tx_id in tx_ids_raw):
            return 400, {
                "error": "every tx_id must be a string of 64 lowercase hex characters"
            }
        if len(set(tx_ids_raw)) != len(tx_ids_raw):
            return 400, {"error": "tx_ids must be distinct"}

        height_int = _parse_height(height)
        if height_int is None:
            return 404, {"error": "block not found"}
        with self.store.lock:
            block = self.store.block_at(height_int)
            if block is None:
                return 404, {"error": "block not found"}
            if block.status != STATUS_CONFIRMED:
                return 409, {"error": "block is pending confirmation"}
            tx_ids = [tx.tx_id for tx in block.transactions]
            present = set(tx_ids)
            if any(tx_id not in present for tx_id in tx_ids_raw):
                return 404, {"error": "transaction not found"}
            requested = sorted(set(tx_ids_raw))
            proofs = []
            for tx_id in requested:
                index = tx_ids.index(tx_id)
                proofs.append({
                    "tx_id": tx_id,
                    "index": index,
                    "siblings": crypto.merkle_proof(tx_ids, index),
                })
            return 200, {
                "height": block.height,
                "block_hash": block.block_hash,
                "merkle_root": block.merkle_root,
                "transaction_ids": tx_ids,
                "proofs": proofs,
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

    # -- account state Merkle tree -------------------------------------------

    def _state_tree(
        self, chain: list | None = None
    ) -> tuple[list[tuple[str, int, list[str]]], list[str], str]:
        """Build the confirmed account rows (ascending account), their leaves
        and the Merkle root, all from the confirmed chain under the current
        endowment. ``chain`` defaults to the whole canonical chain; a confirmed
        prefix replays historical state deterministically. Caller must hold the
        store lock.
        """
        if chain is None:
            chain = self.store.chain
        rows = self.store.account_state_rows(chain, self.initial_balance)
        leaves = [
            crypto.account_state_leaf(account, balance, transactions)
            for account, balance, transactions in rows
        ]
        return rows, leaves, crypto.account_state_root(leaves)

    def get_state_root(self, height: object = None) -> tuple[int, dict]:
        """GET /v1/state/root and GET /v1/state/root/{height}.

        Without a height the tree is anchored to the highest block. A pending
        chain tip anchors nothing yet, so the endpoint returns 404 until the
        tip is confirmed.

        With a path height the state is replayed only from genesis through
        that block: the height must be an unsigned decimal without leading
        zeros (malformed heights are treated like any unknown path), the block
        must exist on the canonical chain and be confirmed — an unknown,
        non-canonical or pending height returns 404. The success body has
        exactly the same four fields as the unanchored endpoint.
        """
        with self.store.lock:
            if height is None:
                anchor = self.store.tip()
            else:
                # Strict unsigned decimal with no leading zeros, signs or
                # whitespace; every malformed value is an unknown path (404).
                height_int = _parse_decimal(height)
                if height_int is None:
                    return 404, {"error": "block not found"}
                anchor = self.store.block_at(height_int)
                if anchor is None:
                    return 404, {"error": "block not found"}
            if anchor.status != STATUS_CONFIRMED:
                return 404, {"error": "chain tip is pending confirmation"}
            prefix = self.store.chain if height is None else self.store.chain[: anchor.height + 1]
            rows, _leaves, root = self._state_tree(prefix)
            return 200, {
                "state_root": root,
                "height": anchor.height,
                "block_hash": anchor.block_hash,
                "account_count": len(rows),
            }

    def get_account_proof(
        self, account: str, params: dict | None = None
    ) -> tuple[int, dict]:
        """GET /v1/accounts/{account}/proof — an inclusion proof in the
        account-state tree.

        Without ``height`` the proof is anchored to the highest (confirmed)
        block. With ``height=H`` the state is deterministically replayed from
        the canonical confirmed prefix through that block only: the value must
        be a plain non-negative decimal without leading zeros (a malformed or
        repeated query parameter is 400), and an unknown/non-canonical/pending
        anchor height is 404. ``height`` is the only accepted query parameter;
        any unknown parameter is 400. Returns 404 while a pending tip anchors
        the default view, or for an account absent from the (historical)
        confirmed account set.
        """
        height_raw: object = None
        if params is not None:
            if any(key != "height" for key in params):
                return 400, {"error": "unknown query parameter"}
            height_raw = params.get("height")
        anchor_height: int | None = None
        if height_raw is not None:
            anchor_height = _parse_decimal(height_raw)
            if anchor_height is None:
                return 400, {"error": "height must be a non-negative decimal"}
        with self.store.lock:
            if anchor_height is None:
                anchor = self.store.tip()
            else:
                anchor = self.store.block_at(anchor_height)
                if anchor is None:
                    return 404, {"error": "anchor block not found"}
            if anchor.status != STATUS_CONFIRMED:
                return 404, {"error": "chain tip is pending confirmation"}
            prefix = (
                self.store.chain
                if anchor_height is None
                else self.store.chain[: anchor.height + 1]
            )
            rows, leaves, root = self._state_tree(prefix)
            index = next(
                (i for i, (name, _b, _t) in enumerate(rows) if name == account),
                None,
            )
            if index is None:
                return 404, {"error": "account not found"}
            account_name, balance, transactions = rows[index]
            siblings = crypto.merkle_proof(leaves, index)
            return 200, {
                "account": account_name,
                "balance": balance,
                "confirmed_transactions": transactions,
                "index": index,
                "state_root": root,
                "height": anchor.height,
                "block_hash": anchor.block_hash,
                "siblings": siblings,
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
            # An adopted synced tip keeps its sync records (queryable until
            # expiry); record the adoption once per provenance entry. The
            # adopted tip summary is frozen from the adopted fork itself and
            # is never rewritten by later expiry.
            adopted_summary = self._fork_summary(fork)
            # The adopted tip may have provenance entries in the plain table,
            # the attested table, or both; each gets one adoption event.
            adopted: list[tuple[str | None, tuple[str, str]]] = []
            for skey in sorted(self.store.syncs):
                if self.store.syncs[skey]["tip_hash"] == tip_hash:
                    adopted.append((None, skey))
            for skey in sorted(self.store.attested_syncs):
                if self.store.attested_syncs[skey]["tip_hash"] == tip_hash:
                    adopted.append((SYNC_MODE_ATTESTED, skey))
            adopted_count = len(adopted)
            for rec_mode, (rec_source, request_id) in adopted:
                table = (
                    self.store.attested_syncs
                    if rec_mode is not None
                    else self.store.syncs
                )
                payload = {
                    "source": rec_source,
                    "request_id": request_id,
                    "tip_hash": tip_hash,
                    "expires_at": table[(rec_source, request_id)]["expires_at"],
                    "height": adopted_summary["height"],
                    "length": adopted_summary["length"],
                    "status": adopted_summary["status"],
                }
                if rec_mode is not None:
                    payload["mode"] = rec_mode
                self.store.append_audit_event(EVENT_SYNC_ADOPTED, payload)
            try:
                self.store.save()
            except BaseException:
                # Restore the pre-adoption in-memory state on a failed write.
                self.store.chain = old_chain
                self.store.pending = old_pending
                self.store.forks[tip_hash] = fork
                self.store.rebuild_derived()
                self.store.truncate_audit_events(adopted_count)
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

    # -- incremental chain ranges --------------------------------------------

    RANGE_DEFAULT_LIMIT = 100
    RANGE_MAX_LIMIT = 500

    @staticmethod
    def _anchor_descriptor(block: Block) -> dict:
        """Public range anchor shape: {height, block_hash}."""
        return {"height": block.height, "block_hash": block.block_hash}

    def get_chain_range(self, params: dict) -> tuple[int, dict]:
        """GET /v1/chain/range — the canonical blocks strictly after an anchor.

        Query parameters: ``after_height`` (a non-negative decimal anchor
        height) and ``after_hash`` (the anchor block's hash, 64 lowercase hex
        characters), both required, plus ``limit`` (default 100, range 1-500).
        Every value must follow the strict decimal/hex format used by the
        other query endpoints; a repeated parameter is rejected by the HTTP
        layer.

        Returns, under the store lock,
        ``{anchor, blocks, canonical, next_height}``: ``anchor`` is
        ``{height, block_hash}`` naming the block the page starts *after*;
        ``blocks`` are the complete blocks following it (full documents
        including transactions; a pending tip block is exported too), up to
        ``limit``; ``canonical`` is the current chain descriptor S;
        ``next_height`` is the height immediately after the returned page, or
        ``null`` when the page already ends at the chain tip. A well-formed
        but unknown anchor height returns 404; a malformed anchor hash returns
        400; an anchor hash that does not match the block at that height
        returns 409.
        """
        after_height_raw = params.get("after_height")
        after_hash = params.get("after_hash")
        if after_height_raw is None:
            return 400, {"error": "missing parameter: after_height"}
        if after_hash is None:
            return 400, {"error": "missing parameter: after_hash"}
        after_height = _parse_decimal(after_height_raw)
        if after_height is None:
            return 400, {"error": "after_height must be a non-negative decimal"}
        if not crypto.is_hex64(after_hash):
            return 400, {"error": "after_hash must be 64 lowercase hex characters"}
        limit = self.RANGE_DEFAULT_LIMIT
        if params.get("limit") is not None:
            parsed = _parse_decimal(params["limit"])
            if parsed is None or not 1 <= parsed <= self.RANGE_MAX_LIMIT:
                return 400, {"error": "limit must be a decimal between 1 and 500"}
            limit = parsed

        with self.store.lock:
            anchor_block = self.store.block_at(after_height)
            if anchor_block is None:
                return 404, {"error": "anchor block not found"}
            if after_hash is not None and after_hash != anchor_block.block_hash:
                return 409, {
                    "error": "after_hash does not match the block at after_height"
                }
            page = self.store.chain[
                after_height + 1 : after_height + 1 + limit
            ]
            page_end_height = page[-1].height if page else anchor_block.height
            if page_end_height < self.store.chain[-1].height:
                next_height = page_end_height + 1
            else:
                next_height = None
            return 200, {
                "anchor": self._anchor_descriptor(anchor_block),
                "blocks": [block.to_dict() for block in page],
                "canonical": self._fork_summary(self.store.chain),
                "next_height": next_height,
            }

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
        """Sweep expired sync records and persist the sweep atomically.

        Both the plain and the attested record tables are swept together in a
        single atomic save that advances the generation. A candidate received
        through a sync lives only while a referencing record is unexpired; on
        expiry the record and its still-stored candidate fork are dropped
        together. Candidates submitted directly (no sync record) never expire,
        and an adopted tip is no longer in ``forks`` (it is on the canonical
        chain), so its expiring audit record leaves the chain untouched. A
        fork is dropped only when neither table still references it. If the
        write fails the pre-cleanup records and forks are restored so no
        success is ever reported for an un-persisted sweep. Caller must hold
        the store lock. Returns the pruned tip hashes.
        """
        plain_tips, plain_removed = self.store.prune_syncs()
        attested_tips, attested_removed = self.store.prune_attested_syncs()
        if not plain_removed and not attested_removed:
            return plain_tips + attested_tips
        expired_tips = plain_tips + attested_tips
        removed_forks: dict[str, list] = {}
        canonical_hashes = {block.block_hash for block in self.store.chain}
        # The same tip could be referenced by another live record in either
        # table; only drop a fork nothing still points at.
        live_tips = {rec["tip_hash"] for rec in self.store.syncs.values()}
        live_tips.update(
            rec["tip_hash"] for rec in self.store.attested_syncs.values()
        )
        for tip in expired_tips:
            if tip in canonical_hashes or tip in live_tips:
                continue
            fork = self.store.forks.pop(tip, None)
            if fork is not None:
                removed_forks[tip] = fork

        def append_expiry_events(
            removed: dict[tuple[str, str], dict], mode: str | None
        ) -> None:
            # Record one permanent expiry event per removed sync record. A tip
            # already adopted onto the canonical chain still gets its event:
            # the record's expiry is auditable even though the chain is
            # untouched. The event freezes the originally delivered summary.
            # Attested records' events carry mode="attested"; plain records
            # keep the historical shape with no mode.
            for (rec_source, request_id), rec in sorted(removed.items()):
                payload = {
                    "source": rec_source,
                    "request_id": request_id,
                    "tip_hash": rec["tip_hash"],
                    "expires_at": rec["expires_at"],
                    "height": rec.get("height"),
                    "length": rec.get("length"),
                    "status": rec.get("status"),
                }
                if mode is not None:
                    payload["mode"] = mode
                self.store.append_audit_event(EVENT_SYNC_EXPIRED, payload)

        append_expiry_events(plain_removed, None)
        append_expiry_events(attested_removed, SYNC_MODE_ATTESTED)
        removed_count = len(plain_removed) + len(attested_removed)
        try:
            self.store.save()
        except BaseException:
            # Restore the pre-cleanup state: a failed write must neither leave
            # the records gone nor their candidates orphaned, nor the events
            # durably visible.
            self.store.truncate_audit_events(removed_count)
            self.store.restore_syncs(plain_removed, removed_forks)
            self.store.restore_syncs(
                attested_removed, {}, table=self.store.attested_syncs
            )
            raise
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
        seconds) and ``candidate`` (an export-format fork document).

        Authorization. A *new* source+request_id pair is accepted only when the
        source is registered in the persistent trust registry with status
        ``active`` and an ``expires_at`` still in the future. An unknown,
        revoked or registry-expired source is rejected 403 before the candidate
        is examined. A retry on a still-live recorded key bypasses the registry
        check entirely: the recorded result must keep replaying even after the
        source has since been rotated, revoked or expired.

        After authorization (and only then) the candidate is re-validated
        exactly like a direct candidate submission (canonical genesis,
        consecutive heights and prev_hash linkage, recomputed block hashes and
        Merkle roots, tx_id and Ed25519 signatures, unique ascending tx_ids,
        endowment replay, pending-only-at-tip).

        Status precedence: malformed envelope fields are 400; an unauthorized
        source is 403; a well-formed new request whose ``expires_at`` is not
        later than now is 410; a well-formed but failing candidate chain (or a
        tampered candidate summary) is 400. Returns 201 on first acceptance
        with ``{tip_hash, height, length, status, expires_at}``. A retry with
        the same source + request_id and identical content replays the original
        result as 200; the same key with different content returns 409, as does
        a duplicate tip already known.
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

            if existing is None:
                # Authorization gate for new deliveries only: the source must
                # be an active, unexpired entry of the persistent trust
                # registry. Unknown, revoked or registry-expired sources are
                # refused 403 before the candidate is examined. A retry on a
                # still-live key skips this, so a recorded result keeps
                # replaying even after the source has since been rotated,
                # revoked or expired.
                now = time.time()
                trusted = self.store.trust_sources.get(source)
                if (
                    trusted is None
                    or trusted["status"] != TRUST_ACTIVE
                    or trusted["expires_at"] <= now
                ):
                    return 403, {"error": "source is not an active trusted source"}
                # The request's own deadline is checked next, still before the
                # candidate chain is examined: a well-formed request whose
                # expiry is not later than now is gone (410).
                if expires_at <= now:
                    return 410, {"error": "sync request has expired"}

            # Re-validate the whole candidate chain and recompute the tip
            # summary BEFORE any idempotency decision: a request whose supplied
            # tip_hash/height/length/status were tampered with must fail 400,
            # never be answered with the cached 200 for its source+request_id.
            try:
                fork = self.store.validate_fork_blocks(blocks_raw)
            except ValueError as exc:
                return 400, {"error": str(exc)}
            summary = self._fork_summary(fork)
            if isinstance(candidate, dict):
                for field in ("tip_hash", "height", "length", "status"):
                    if field in candidate and candidate[field] != summary[field]:
                        return 400, {
                            "error": f"candidate field {field!r} does not match the blocks"
                        }
            tip_hash = fork[-1].block_hash
            # Fingerprint the *canonicalized* parsed blocks, not the raw
            # request list, so recovery (which re-parses the stored fork)
            # recomputes an identical fingerprint regardless of insignificant
            # serialization differences in the original submission.
            canonical_blocks = [block.to_dict() for block in fork]
            fingerprint = self._candidate_fingerprint(canonical_blocks)

            if existing is not None:
                # A retry on a live key is idempotent only when it carries the
                # identical candidate content; a changed body conflicts 409.
                if fingerprint != existing["fingerprint"]:
                    return 409, {
                        "error": "request_id already used with different content"
                    }
                # Replay the ORIGINAL result frozen at first reception; only
                # legacy records without a frozen summary resolve live.
                descriptor: dict | None = None
                if existing.get("height") is not None:
                    descriptor = {
                        "tip_hash": existing["tip_hash"],
                        "height": existing["height"],
                        "length": existing["length"],
                        "status": existing["status"],
                    }
                if descriptor is None:
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
                # The tip summary is frozen at reception: later adoption or
                # expiry never rewrites it, so the history always reports what
                # was originally delivered.
                "height": summary["height"],
                "length": summary["length"],
                "status": summary["status"],
            }
            self.store.append_audit_event(
                EVENT_SYNC_RECEIVED,
                {
                    "source": source,
                    "request_id": request_id,
                    "tip_hash": tip_hash,
                    "expires_at": expires_at,
                    "height": summary["height"],
                    "length": summary["length"],
                    "status": summary["status"],
                },
            )
            try:
                self.store.save()
            except BaseException:
                # Roll back the candidate, its metadata and the audit event
                # together so a failed write never leaves one without the others.
                self.store.syncs.pop(key, None)
                self.store.forks.pop(tip_hash, None)
                self.store.truncate_audit_events(1)
                raise

            result = dict(summary)
            result["expires_at"] = expires_at
            return 201, result

    # -- signature-attested inter-node sync ----------------------------------

    def submit_fork_sync_attested(self, payload: object) -> tuple[int, dict]:
        """POST /v1/forks/sync/attested — receive a signed candidate chain.

        The request carries ``source``, ``request_id``, ``expires_at`` (Unix
        seconds), ``candidate`` (an export object, a ``{"blocks": [...]}``
        wrapper or a bare block array, kept in its delivered original form)
        and ``signature`` — exactly 128 lowercase hex characters. The signed
        message is the README canonical JSON of
        ``{domain:"ledger-sync-v1", source, request_id, expires_at,
        candidate}``; the signature is an Ed25519 signature over the raw
        32-byte SHA-256 digest of those bytes, made with the source's current
        registered public key.

        Status precedence for a NEW key: malformed envelope fields (including
        a signature that is not 128 lowercase hex characters) are 400; an
        unauthorized source (unknown, revoked or registry-expired) is 403; a
        well-formed request whose ``expires_at`` is not later than now is 410;
        a signature that does not verify under the source's CURRENT registered
        key/version is 403; then the candidate chain (and any supplied export
        summary) is fully re-validated exactly like a plain sync, failure 400;
        a tip already known as canonical or a stored candidate is 409.

        On success the frozen signing public key, its registry version, the
        signature and the signed-message fingerprint (covering the candidate
        in its signed original form plus the signature) are persisted
        atomically with the candidate, the sync record and a
        ``sync_received`` event carrying ``mode:"attested"``. A failed
        signature verification performs no writes and leaves no candidate.

        The attested idempotency key ``(source, request_id)`` is a separate
        namespace from the plain sync endpoints. A same-key retry on a live
        record first re-verifies the signature (against the frozen key, so a
        later rotation/revocation does not change the answer) and re-validates
        the candidate chain; a wrong signature is 403, the identical signed
        content replays the original frozen result as 200 (with its original
        ``expires_at``), and any other well-formed content conflicts 409. The
        frozen-key replay is unaffected by later trust changes.

        On a record's own expiry, or when the source loses authorization
        before a restart, the record and its not-adopted candidate are removed
        and a ``mode:"attested"`` ``sync_expired`` event is appended; the same
        key can then start a new lifecycle. Restart re-verifies the message,
        signature, frozen key/version and fingerprint: a mismatch only drops
        the cached record (the canonical chain is untouched, audit history
        stays continuous); expiry/authorization loss is reconciled exactly
        like plain sync.
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in ("source", "request_id", "expires_at", "candidate", "signature"):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}

        source = payload["source"]
        request_id = payload["request_id"]
        expires_at = payload["expires_at"]
        candidate = payload["candidate"]
        signature = payload["signature"]

        if not isinstance(source, str) or not source:
            return 400, {"error": "field 'source' must be a non-empty string"}
        if not isinstance(request_id, str) or not request_id:
            return 400, {"error": "field 'request_id' must be a non-empty string"}
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            return 400, {"error": "field 'expires_at' must be a Unix-seconds integer"}
        if not crypto.is_hex128(signature):
            return 400, {
                "error": "field 'signature' must be 128 lowercase hex characters"
            }
        if isinstance(candidate, dict):
            if not isinstance(candidate.get("blocks"), list):
                return 400, {"error": "field 'candidate' must contain a 'blocks' list"}
        elif not isinstance(candidate, list):
            return 400, {"error": "field 'candidate' must contain a 'blocks' list"}

        mode = SYNC_MODE_ATTESTED
        with self.store.lock:
            self._prune_expired_syncs()

            key = (source, request_id)
            existing = self.store.attested_syncs.get(key)

            if existing is None:
                # New delivery: the source must be an active, unexpired entry
                # of the persistent trust registry before anything else is
                # examined; unknown/revoked/registry-expired is 403.
                now = time.time()
                trusted = self.store.trust_sources.get(source)
                if (
                    trusted is None
                    or trusted["status"] != TRUST_ACTIVE
                    or trusted["expires_at"] <= now
                ):
                    return 403, {"error": "source is not an active trusted source"}
                if expires_at <= now:
                    return 410, {"error": "sync request has expired"}
                signer_public_key = trusted["public_key"]
                signer_version = trusted["version"]
            else:
                # A live-key replay verifies against the FROZEN key/version,
                # never the current registry: the recorded answer must not
                # change when the source is rotated, revoked or expired after
                # first reception. The frozen attestation is always present
                # for attested records.
                signer_public_key = existing["attested"]["public_key"]
                signer_version = existing["attested"]["version"]

            # Verify the Ed25519 signature over the raw SHA-256 digest of the
            # canonical signed message. This is before any candidate
            # validation or write; a failed verification changes nothing.
            message = attested_message(source, request_id, expires_at, candidate)
            digest = hashlib.sha256(message).digest()
            if not crypto.verify_signature(signer_public_key, digest, signature):
                return 403, {"error": "attestation signature is invalid"}

            # Full whole-chain re-validation of the signed candidate, exactly
            # like a plain sync; the export summary fields of a five-field
            # document are recomputed and checked too.
            blocks_raw = self._candidate_blocks(candidate)
            try:
                fork = self.store.validate_fork_blocks(blocks_raw)
            except ValueError as exc:
                return 400, {"error": str(exc)}
            summary = self._fork_summary(fork)
            if isinstance(candidate, dict):
                for field in ("tip_hash", "height", "length", "status"):
                    if field in candidate and candidate[field] != summary[field]:
                        return 400, {
                            "error": f"candidate field {field!r} does not match the blocks"
                        }
            tip_hash = fork[-1].block_hash
            fingerprint = attested_fingerprint(
                source, request_id, expires_at, candidate, signature
            )

            if existing is not None:
                # Same-key retry: the signature just verified over this exact
                # message, so any difference in envelope/candidate/signature is
                # different signed content → 409. Identical content replays the
                # original frozen result as 200, with the original deadline.
                if fingerprint != existing["fingerprint"]:
                    return 409, {
                        "error": "request_id already used with different content"
                    }
                descriptor = None
                if existing.get("height") is not None:
                    descriptor = {
                        "tip_hash": existing["tip_hash"],
                        "height": existing["height"],
                        "length": existing["length"],
                        "status": existing["status"],
                    }
                if descriptor is None:
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

            if any(tip_hash == block.block_hash for block in self.store.chain):
                return 409, {"error": "fork is identical to the canonical chain"}
            if tip_hash in self.store.forks:
                return 409, {
                    "error": "candidate fork already exists",
                    "tip_hash": tip_hash,
                }

            self.store.forks[tip_hash] = fork
            self.store.attested_syncs[key] = {
                "tip_hash": tip_hash,
                "expires_at": expires_at,
                "fingerprint": fingerprint,
                "height": summary["height"],
                "length": summary["length"],
                "status": summary["status"],
                # Freeze the attestation: the signing public key and its
                # registry version at delivery, the signature and the
                # candidate in the exact form that was signed. Same-key
                # replays verify against the frozen key, independent of later
                # trust changes; restart re-verifies message/signature/
                # version/fingerprint and only drops the cache on mismatch.
                "attested": {
                    "public_key": signer_public_key,
                    "version": signer_version,
                    "signature": signature,
                    "candidate": candidate,
                },
            }
            self.store.append_audit_event(
                EVENT_SYNC_RECEIVED,
                {
                    "mode": mode,
                    "source": source,
                    "request_id": request_id,
                    "tip_hash": tip_hash,
                    "expires_at": expires_at,
                    "height": summary["height"],
                    "length": summary["length"],
                    "status": summary["status"],
                },
            )
            try:
                self.store.save()
            except BaseException:
                # Roll back the candidate, its attested metadata and the audit
                # event together: a failed write leaves nothing behind.
                self.store.attested_syncs.pop(key, None)
                self.store.forks.pop(tip_hash, None)
                self.store.truncate_audit_events(1)
                raise

            result = dict(summary)
            result["expires_at"] = expires_at
            return 201, result

    # -- incremental inter-node range sync -----------------------------------

    @staticmethod
    def _range_tip_summary(anchor: dict, tail: list) -> dict:
        """Recompute the delivered chain's tip descriptor from anchor + tail."""
        tip = tail[-1]
        return {
            "tip_hash": tip.block_hash,
            "height": tip.height,
            # The assembled length counts the canonical prefix (anchor height
            # + 1 blocks) plus every delivered tail block.
            "length": anchor["height"] + 1 + len(tail),
            "status": tip.status,
        }

    def submit_fork_sync_range(self, payload: object) -> tuple[int, dict]:
        """POST /v1/forks/sync/range — receive an incremental chain range.

        The request carries ``source``, ``request_id``, ``expires_at`` (Unix
        seconds), ``anchor`` (``{height, block_hash}`` naming the canonical
        block the range starts *after*), ``blocks`` (a non-empty list of
        complete blocks starting at the next height) and ``tip`` (the
        mandatory closed summary ``{tip_hash, height, length, status}`` of the
        delivered chain: exactly those four fields, a 64-hex tip_hash, a
        non-boolean non-negative height, a non-boolean positive length and a
        pending/confirmed status). Any structural, type or summary violation
        is 400, decided BEFORE the source is authorized and before any
        candidate, fork, sync record, audit event or generation is touched.

        A new request follows the full-sync order: envelope format validation
        (400), then the source authorization gate (403), then the request
        deadline (410). The anchor must then match the *current* canonical
        chain: an unknown anchor height or a hash mismatch is a stale anchor
        (409). The tail is prepended with the canonical prefix and put through
        the existing whole-chain re-validation (genesis connection,
        consecutive heights/prev_hash, recomputed block hashes and Merkle
        roots, tx_id/Ed25519 verification, global uniqueness and ordering,
        endowment replay, pending-only-at-tip); failure is 400, as is a
        ``tip`` summary that does not recompute (height must equal the last
        block's height, length the assembled chain length including genesis,
        status the last block's status). A tip already known as the
        canonical chain or a stored candidate is 409, mirroring full sync.

        Success stores the ASSEMBLED complete candidate (keyed by its tip hash)
        together with the sync record, the range content fingerprint
        (anchor + delivered tail only) and a ``sync_received`` event in one
        atomic write; 201 returns the same five fields as a full sync. A
        same-key retry on a live record first re-validates anchor, blocks and
        the full tip STANDALONE (never re-spliced against the current
        canonical chain): a malformed or tampered body fails 400 rather than
        replaying the cached 200, identical content replays the original
        frozen result as 200 with its original ``expires_at``, and any other
        well-formed content conflicts 409. The replay is unaffected by the
        source having rotated/revoked/expired, by the request deadline having
        passed, or by the receiver's canonical chain having advanced.
        Longest-chain adoption, expiry, mempool return-to-pool and restart
        reconciliation then all operate on the stored assembled candidate
        exactly as for a full sync.
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in ("source", "request_id", "expires_at", "anchor", "blocks", "tip"):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}

        source = payload["source"]
        request_id = payload["request_id"]
        expires_at = payload["expires_at"]
        anchor_raw = payload["anchor"]
        blocks_raw = payload["blocks"]
        tip = payload["tip"]

        if not isinstance(source, str) or not source:
            return 400, {"error": "field 'source' must be a non-empty string"}
        if not isinstance(request_id, str) or not request_id:
            return 400, {"error": "field 'request_id' must be a non-empty string"}
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            return 400, {"error": "field 'expires_at' must be a Unix-seconds integer"}
        if not isinstance(anchor_raw, dict):
            return 400, {"error": "field 'anchor' must be a JSON object"}
        anchor_height = anchor_raw.get("height")
        anchor_hash = anchor_raw.get("block_hash")
        if (
            isinstance(anchor_height, bool)
            or not isinstance(anchor_height, int)
            or anchor_height < 0
        ):
            return 400, {"error": "anchor.height must be a non-negative integer"}
        if not crypto.is_hex64(anchor_hash):
            return 400, {
                "error": "anchor.block_hash must be 64 lowercase hex characters"
            }
        anchor = {"height": anchor_height, "block_hash": anchor_hash}
        if not isinstance(blocks_raw, list):
            return 400, {"error": "field 'blocks' must be a list"}
        if not blocks_raw:
            return 400, {"error": "field 'blocks' must be non-empty"}
        # The tip summary is mandatory and closed: exactly the four fields
        # tip_hash/height/length/status, each strictly typed. Any structural
        # or type violation is 400 here, before the source is authorized and
        # before any candidate, fork, sync record, audit event or generation
        # is touched.
        if not isinstance(tip, dict):
            return 400, {"error": "field 'tip' must be a JSON object"}
        if set(tip) != {"tip_hash", "height", "length", "status"}:
            return 400, {
                "error": "tip must contain exactly tip_hash, height, length and status"
            }
        if not crypto.is_hex64(tip["tip_hash"]):
            return 400, {"error": "tip.tip_hash must be 64 lowercase hex characters"}
        if (
            isinstance(tip["height"], bool)
            or not isinstance(tip["height"], int)
            or tip["height"] < 0
        ):
            return 400, {"error": "tip.height must be a non-negative integer"}
        if (
            isinstance(tip["length"], bool)
            or not isinstance(tip["length"], int)
            or tip["length"] < 1
        ):
            return 400, {"error": "tip.length must be a positive integer"}
        if tip["status"] not in (STATUS_PENDING, STATUS_CONFIRMED):
            return 400, {"error": "tip.status must be 'pending' or 'confirmed'"}

        with self.store.lock:
            self._prune_expired_syncs()
            key = (source, request_id)
            existing = self.store.syncs.get(key)

            if existing is not None:
                # Idempotent replay on a live key. The tail is re-verified
                # STANDALONE (never re-spliced against the current canonical
                # chain) and its supplied tip summary recomputed BEFORE the
                # idempotency decision — exactly like a full-sync retry, where
                # a malformed/tampered body fails 400 rather than replaying the
                # cached 200. Identical range content then replays the original
                # frozen result as 200 even after the source has rotated,
                # revoked or expired OR the receiver's canonical chain has
                # advanced; changed content conflicts 409. The authorization
                # gate is bypassed for retries.
                try:
                    tail = self.store.validate_range_tail(anchor, blocks_raw)
                except ValueError as exc:
                    return 400, {"error": str(exc)}
                recomputed_tip = self._range_tip_summary(anchor, tail)
                if tip != recomputed_tip:
                    return 400, {"error": "tip summary does not match the blocks"}
                fingerprint = self.store.range_fingerprint(anchor, tail)
                if fingerprint != existing["fingerprint"]:
                    return 409, {
                        "error": "request_id already used with different content"
                    }
                descriptor = None
                if existing.get("height") is not None:
                    descriptor = {
                        "tip_hash": existing["tip_hash"],
                        "height": existing["height"],
                        "length": existing["length"],
                        "status": existing["status"],
                    }
                if descriptor is None:
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

            # New delivery follows the full-sync order: authorization (403),
            # then the request deadline (410), before the anchor or chain is
            # examined.
            now = time.time()
            trusted = self.store.trust_sources.get(source)
            if (
                trusted is None
                or trusted["status"] != TRUST_ACTIVE
                or trusted["expires_at"] <= now
            ):
                return 403, {"error": "source is not an active trusted source"}
            if expires_at <= now:
                return 410, {"error": "sync request has expired"}

            # The anchor must match the current canonical chain; an unknown
            # height or a mismatched hash is a stale anchor (409).
            anchor_block = self.store.block_at(anchor_height)
            if anchor_block is None or anchor_block.block_hash != anchor_hash:
                return 409, {"error": "anchor does not match the current canonical chain"}

            # Splice the canonical prefix and run the existing whole-chain
            # revalidation: blocks start at the next height and stay
            # consecutive, prev_hash links onto the anchor, recomputed block
            # hashes/Merkle roots, tx_id/Ed25519 verification, global
            # uniqueness and block ordering, endowment replay, and
            # pending-only-at-tip. Failure is 400.
            assembled_raw = [
                block.to_dict() for block in self.store.chain[: anchor_height + 1]
            ]
            assembled_raw.extend(
                block_raw for block_raw in blocks_raw
            )
            try:
                fork = self.store.validate_fork_blocks(assembled_raw)
            except ValueError as exc:
                return 400, {"error": str(exc)}
            summary = self._fork_summary(fork)
            tail = fork[anchor_height + 1 :]
            recomputed_tip = self._range_tip_summary(anchor, tail)
            if summary != recomputed_tip:
                return 400, {"error": "range does not assemble onto the canonical chain"}
            if tip != recomputed_tip:
                return 400, {"error": "tip summary does not match the blocks"}
            fingerprint = self.store.range_fingerprint(anchor, tail)
            tip_hash = fork[-1].block_hash

            if any(tip_hash == block.block_hash for block in self.store.chain):
                return 409, {"error": "fork is identical to the canonical chain"}
            if tip_hash in self.store.forks:
                return 409, {
                    "error": "candidate fork already exists",
                    "tip_hash": tip_hash,
                }

            # Persist the ASSEMBLED candidate so adoption, expiry cleanup and
            # restart never need to re-splice it against a later canonical,
            # alongside the range payload and its range-content fingerprint.
            self.store.forks[tip_hash] = fork
            self.store.syncs[key] = {
                "tip_hash": tip_hash,
                "expires_at": expires_at,
                "fingerprint": fingerprint,
                "height": summary["height"],
                "length": summary["length"],
                "status": summary["status"],
                "range": {
                    "anchor": dict(anchor),
                    "blocks": [block.to_dict() for block in tail],
                },
            }
            self.store.append_audit_event(
                EVENT_SYNC_RECEIVED,
                {
                    "source": source,
                    "request_id": request_id,
                    "tip_hash": tip_hash,
                    "expires_at": expires_at,
                    "height": summary["height"],
                    "length": summary["length"],
                    "status": summary["status"],
                },
            )
            try:
                self.store.save()
            except BaseException:
                # Roll back the assembled candidate, its range record and the
                # audit event together: a failed write changes nothing.
                self.store.syncs.pop(key, None)
                self.store.forks.pop(tip_hash, None)
                self.store.truncate_audit_events(1)
                raise

            result = dict(summary)
            result["expires_at"] = expires_at
            return 201, result

    # -- signature-attested incremental range sync ---------------------------

    def submit_fork_sync_range_attested(self, payload: object) -> tuple[int, dict]:
        """POST /v1/forks/sync/range/attested — receive a signed chain range.

        Combines the incremental range envelope with an Ed25519 attestation.
        The request carries ``source``, ``request_id``, ``expires_at`` (Unix
        seconds), ``anchor`` (``{height, block_hash}``), ``blocks`` (a
        non-empty tail starting at the next height), ``tip`` (the closed
        four-field summary ``{tip_hash, height, length, status}`` of the
        delivered chain) and ``signature`` — exactly 128 lowercase hex
        characters. The signed message is the README canonical JSON of
        ``{domain:"ledger-sync-range-v1", source, request_id, expires_at,
        anchor, blocks, tip}`` (key-sorted, compact separators,
        ``ensure_ascii=False``, UTF-8); the signature is an Ed25519 signature
        over the raw 32-byte SHA-256 digest of those bytes, made with the
        source's current registered public key.

        Status precedence for a NEW key: malformed envelope fields (structure,
        types, the closed tip summary or a non-128-lowercase-hex signature)
        are 400; an unauthorized source (unknown, revoked or registry-expired)
        is 403; a request whose ``expires_at`` is not later than now is 410; a
        signature that fails under the source's CURRENT key is 403; an anchor
        not matching the current canonical chain is 409; then the tail is
        spliced onto the canonical prefix and fully re-validated like a plain
        range (failure 400, as is a non-recomputing ``tip``); a tip already
        canonical or stored is 409.

        On success the signing public key, its registry version, the signature
        and the signed range payload are frozen atomically with the ASSEMBLED
        candidate, the attested sync record (the attested idempotency
        namespace, independent of the plain endpoints) and a
        ``mode:"attested"`` ``sync_received`` event; 201 returns the five
        fields S plus ``expires_at``.

        A same-key retry on a live record bypasses authorization and the
        deadline and re-verifies the signature against the FROZEN key: a wrong
        signature is 403, a malformed/tampered body (re-validated standalone,
        never re-spliced) is 400, a valid signature over different content is
        409 and identical content replays the frozen result as 200 with its
        original ``expires_at``. Lifecycle (adoption, expiry, restart
        reconciliation) follows the existing attested rules; an un-adopted
        candidate removed on expiry also gets one ``mode:"attested"``
        sync_expired event. A fingerprint or signed tip that no longer parses
        on restart is silently dropped with no event.
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in (
            "source", "request_id", "expires_at", "anchor", "blocks", "tip",
            "signature",
        ):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}

        source = payload["source"]
        request_id = payload["request_id"]
        expires_at = payload["expires_at"]
        anchor_raw = payload["anchor"]
        blocks_raw = payload["blocks"]
        tip = payload["tip"]
        signature = payload["signature"]

        if not isinstance(source, str) or not source:
            return 400, {"error": "field 'source' must be a non-empty string"}
        if not isinstance(request_id, str) or not request_id:
            return 400, {"error": "field 'request_id' must be a non-empty string"}
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            return 400, {"error": "field 'expires_at' must be a Unix-seconds integer"}
        if not isinstance(anchor_raw, dict):
            return 400, {"error": "field 'anchor' must be a JSON object"}
        anchor_height = anchor_raw.get("height")
        anchor_hash = anchor_raw.get("block_hash")
        if (
            isinstance(anchor_height, bool)
            or not isinstance(anchor_height, int)
            or anchor_height < 0
        ):
            return 400, {"error": "anchor.height must be a non-negative integer"}
        if not crypto.is_hex64(anchor_hash):
            return 400, {
                "error": "anchor.block_hash must be 64 lowercase hex characters"
            }
        anchor = {"height": anchor_height, "block_hash": anchor_hash}
        if not isinstance(blocks_raw, list):
            return 400, {"error": "field 'blocks' must be a list"}
        if not blocks_raw:
            return 400, {"error": "field 'blocks' must be non-empty"}
        # The tip summary is mandatory and closed, exactly like the plain range
        # endpoint: any structural/type violation is 400 before authorization.
        if not isinstance(tip, dict):
            return 400, {"error": "field 'tip' must be a JSON object"}
        if set(tip) != {"tip_hash", "height", "length", "status"}:
            return 400, {
                "error": "tip must contain exactly tip_hash, height, length and status"
            }
        if not crypto.is_hex64(tip["tip_hash"]):
            return 400, {"error": "tip.tip_hash must be 64 lowercase hex characters"}
        if (
            isinstance(tip["height"], bool)
            or not isinstance(tip["height"], int)
            or tip["height"] < 0
        ):
            return 400, {"error": "tip.height must be a non-negative integer"}
        if (
            isinstance(tip["length"], bool)
            or not isinstance(tip["length"], int)
            or tip["length"] < 1
        ):
            return 400, {"error": "tip.length must be a positive integer"}
        if tip["status"] not in (STATUS_PENDING, STATUS_CONFIRMED):
            return 400, {"error": "tip.status must be 'pending' or 'confirmed'"}
        if not crypto.is_hex128(signature):
            return 400, {
                "error": "field 'signature' must be 128 lowercase hex characters"
            }

        mode = SYNC_MODE_ATTESTED
        with self.store.lock:
            self._prune_expired_syncs()
            key = (source, request_id)
            existing = self.store.attested_syncs.get(key)

            if existing is None:
                # New delivery: active, unexpired registry entry (403), then
                # the request deadline (410), before the signature or anything
                # else is examined.
                now = time.time()
                trusted = self.store.trust_sources.get(source)
                if (
                    trusted is None
                    or trusted["status"] != TRUST_ACTIVE
                    or trusted["expires_at"] <= now
                ):
                    return 403, {"error": "source is not an active trusted source"}
                if expires_at <= now:
                    return 410, {"error": "sync request has expired"}
                signer_public_key = trusted["public_key"]
                signer_version = trusted["version"]
                is_new = True
            else:
                # Live-key replay verifies against the FROZEN key/version, never
                # the current registry; authorization and the deadline are
                # bypassed entirely.
                signer_public_key = existing["attested"]["public_key"]
                signer_version = existing["attested"]["version"]
                is_new = False

            # Verify the Ed25519 signature over the SHA-256 digest of the
            # canonical signed range message. Failure changes nothing.
            message = attested_range_message(
                source, request_id, expires_at, anchor, blocks_raw, tip
            )
            digest = hashlib.sha256(message).digest()
            if not crypto.verify_signature(signer_public_key, digest, signature):
                return 403, {"error": "attestation signature is invalid"}

            fingerprint = attested_range_fingerprint(
                source, request_id, expires_at, anchor, blocks_raw, tip, signature
            )

            if is_new:
                # New delivery: the anchor must match the current canonical
                # chain (409) before the assembled whole chain is re-validated
                # (400). Splice the canonical prefix exactly like a plain
                # range, so endowment replay and global uniqueness run on the
                # full chain.
                anchor_block = self.store.block_at(anchor_height)
                if anchor_block is None or anchor_block.block_hash != anchor_hash:
                    return 409, {"error": "anchor does not match the current canonical chain"}
                assembled_raw = [
                    block.to_dict() for block in self.store.chain[: anchor_height + 1]
                ]
                assembled_raw.extend(blocks_raw)
                try:
                    fork = self.store.validate_fork_blocks(assembled_raw)
                except ValueError as exc:
                    return 400, {"error": str(exc)}
                summary = self._fork_summary(fork)
                tail = fork[anchor_height + 1 :]
                recomputed_tip = self._range_tip_summary(anchor, tail)
                if summary != recomputed_tip:
                    return 400, {"error": "range does not assemble onto the canonical chain"}
            else:
                # Retry: re-validate anchor + tail STANDALONE, never re-spliced
                # against the current canonical chain; a tampered body is 400,
                # not the cached 200.
                try:
                    tail = self.store.validate_range_tail(anchor, blocks_raw)
                except ValueError as exc:
                    return 400, {"error": str(exc)}
                recomputed_tip = self._range_tip_summary(anchor, tail)
                summary = recomputed_tip

            if tip != recomputed_tip:
                return 400, {"error": "tip summary does not match the blocks"}
            tip_hash = recomputed_tip["tip_hash"]

            if existing is not None:
                # The signature just verified over this exact signed message,
                # so a fingerprint difference is different signed content →
                # 409; identical content replays the frozen result as 200 with
                # the original deadline.
                if fingerprint != existing["fingerprint"]:
                    return 409, {
                        "error": "request_id already used with different content"
                    }
                descriptor = None
                if existing.get("height") is not None:
                    descriptor = {
                        "tip_hash": existing["tip_hash"],
                        "height": existing["height"],
                        "length": existing["length"],
                        "status": existing["status"],
                    }
                if descriptor is None:
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

            if any(tip_hash == block.block_hash for block in self.store.chain):
                return 409, {"error": "fork is identical to the canonical chain"}
            if tip_hash in self.store.forks:
                return 409, {
                    "error": "candidate fork already exists",
                    "tip_hash": tip_hash,
                }

            # Persist the ASSEMBLED candidate (so adoption/expiry/restart act
            # on it exactly like a full sync) and the attested record, whose
            # frozen attestation retains the signed range in its delivered
            # original form.
            self.store.forks[tip_hash] = fork
            self.store.attested_syncs[key] = {
                "tip_hash": tip_hash,
                "expires_at": expires_at,
                "fingerprint": fingerprint,
                "height": summary["height"],
                "length": summary["length"],
                "status": summary["status"],
                "attested": {
                    "public_key": signer_public_key,
                    "version": signer_version,
                    "signature": signature,
                    "range": {
                        "anchor": dict(anchor),
                        "blocks": blocks_raw,
                        "tip": dict(tip),
                    },
                },
            }
            self.store.append_audit_event(
                EVENT_SYNC_RECEIVED,
                {
                    "mode": mode,
                    "source": source,
                    "request_id": request_id,
                    "tip_hash": tip_hash,
                    "expires_at": expires_at,
                    "height": summary["height"],
                    "length": summary["length"],
                    "status": summary["status"],
                },
            )
            try:
                self.store.save()
            except BaseException:
                # Roll back the assembled candidate, its attested range record
                # and the audit event together: a failed write changes nothing.
                self.store.attested_syncs.pop(key, None)
                self.store.forks.pop(tip_hash, None)
                self.store.truncate_audit_events(1)
                raise

            result = dict(summary)
            result["expires_at"] = expires_at
            return 201, result

    SYNC_QUERY_MODES = (SYNC_MODE_PLAIN, SYNC_MODE_ATTESTED, "all")

    def list_fork_syncs(self, params: dict) -> tuple[int, dict]:
        """GET /v1/forks/sync — audit listing of received sync candidates.

        Filters: ``source`` (exact), ``min_height`` and ``max_height``, plus
        the optional ``mode``: absent or ``plain`` lists only ordinary (plain
        and range) sync records, ``attested`` lists only signature-attested
        records and ``all`` merges both tables. Any other value is 400.
        ``limit`` defaults to 50 and must be 1-200; ``cursor`` defaults to 0.
        Every numeric value must be a plain decimal without leading zeros; a
        malformed value returns 400. Rows are ordered by
        ``(height, tip_hash, source, mode, request_id)``; ``cursor == total``
        returns an empty page, ``cursor > total`` returns 400. Each item keeps
        the historical seven fields
        ``source, request_id, tip_hash, height, length, status, expires_at`` —
        ``mode`` participates only in ordering/selection, never in the item.
        """
        source = params.get("source")
        if source is not None and (not isinstance(source, str) or not source):
            return 400, {"error": "source must be a non-empty string"}

        mode = params.get("mode")
        if mode is None:
            mode = SYNC_MODE_PLAIN
        if mode not in self.SYNC_QUERY_MODES:
            return 400, {"error": "mode must be one of plain, attested, all"}

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
            # The plain table (ordinary full/range syncs) and the attested
            # table are separate idempotency namespaces; ``mode`` selects
            # which participate in this listing.
            tables: list[tuple[str, dict]] = []
            if mode in (SYNC_MODE_PLAIN, "all"):
                tables.append((SYNC_MODE_PLAIN, self.store.syncs))
            if mode == SYNC_MODE_ATTESTED or mode == "all":
                tables.append((SYNC_MODE_ATTESTED, self.store.attested_syncs))
            rows: list[tuple[tuple, dict]] = []
            for rec_mode, table in tables:
                for (rec_source, request_id), rec in table.items():
                    if source is not None and rec_source != source:
                        continue
                    descriptor = self._tip_descriptor(rec["tip_hash"])
                    if descriptor is None:
                        continue
                    if min_height is not None and descriptor["height"] < min_height:
                        continue
                    if max_height is not None and descriptor["height"] > max_height:
                        continue
                    item = {
                        "source": rec_source,
                        "request_id": request_id,
                        "tip_hash": descriptor["tip_hash"],
                        "height": descriptor["height"],
                        "length": descriptor["length"],
                        "status": descriptor["status"],
                        "expires_at": rec["expires_at"],
                    }
                    rows.append(
                        (
                            (
                                descriptor["height"],
                                descriptor["tip_hash"],
                                rec_source,
                                rec_mode,
                                request_id,
                            ),
                            item,
                        )
                    )

        rows.sort(key=lambda entry: entry[0])
        ordered = [item for _key, item in rows]
        total = len(ordered)
        if cursor > total:
            return 400, {"error": "cursor is beyond the result set"}
        items = ordered[cursor : cursor + limit]
        next_cursor = cursor + limit if cursor + limit < total else None
        return 200, {"items": items, "total": total, "next_cursor": next_cursor}

    # -- sync candidate export ------------------------------------------------

    SYNC_EXPORT_PARAMS = ("source", "request_id", "mode")
    SYNC_EXPORT_MODES = (SYNC_MODE_PLAIN, SYNC_MODE_ATTESTED)

    def _resolve_sync_blocks(self, tip_hash: str) -> list[dict] | None:
        """Rebuild a synced tip's full block list without new authoritative
        copies: the stored candidate fork, or the canonical chain prefix when
        the tip has since been adopted. Caller must hold the store lock."""
        fork = self.store.forks.get(tip_hash)
        if fork is not None:
            return [block.to_dict() for block in fork]
        prefix: list[dict] = []
        for block in self.store.chain:
            prefix.append(block.to_dict())
            if block.block_hash == tip_hash:
                return prefix
        return None

    def _drop_sync_record(
        self, table: dict[tuple[str, str], dict], key: tuple[str, str]
    ) -> None:
        """Silently drop a stale sync record and persist the cleanup.

        Mirrors the recovery-time cache rules: the record (and its candidate
        fork, when no other live record references the tip and the tip is not
        on the canonical chain) is removed in one atomic write; the audit
        history is never touched and no lifecycle event is emitted. If the
        write fails the pre-cleanup records and forks are restored and the
        error (an OSError from the failed save) propagates. Caller must hold
        the store lock.
        """
        rec = table.pop(key, None)
        if rec is None:
            return
        tip = rec["tip_hash"]
        canonical_hashes = {block.block_hash for block in self.store.chain}
        live_tips = {r["tip_hash"] for r in self.store.syncs.values()}
        live_tips.update(r["tip_hash"] for r in self.store.attested_syncs.values())
        removed_fork: list | None = None
        if tip not in canonical_hashes and tip not in live_tips:
            removed_fork = self.store.forks.pop(tip, None)
        try:
            self.store.save()
        except BaseException:
            # Restore the pre-cleanup state: a failed write must neither
            # leave the record gone nor its candidate orphaned.
            table[key] = rec
            if removed_fork is not None:
                self.store.forks.setdefault(tip, removed_fork)
            raise

    def export_fork_sync(self, params: dict) -> tuple[int, dict]:
        """GET /v1/forks/sync/export — export one received sync candidate.

        Exactly three query parameters are required, each a single value:
        ``source`` and ``request_id`` (non-empty) and ``mode``
        (``plain``/``attested``). Unknown or repeated parameters are 400.
        The plain table and the attested table remain separate idempotency
        namespaces, so ``mode`` selects which table the key is looked up in.

        A hit returns 200 with the fixed key order ``source, request_id,
        mode, expires_at, tip_hash, height, length, status, candidate,
        attestation``. For ``plain`` the candidate is the five-field export
        document ``{tip_hash, height, length, status, blocks}`` and
        ``attestation`` is null; for ``attested`` the candidate is the
        signed candidate preserved verbatim and ``attestation`` carries the
        frozen ``{public_key, version, signature}``. The block list is
        rebuilt under the store lock from the stored fork or — for an
        adopted tip — the canonical prefix; no new authoritative copy is
        created. Incremental range records are not exportable and answer
        409. Unknown, expired or already-cleaned keys answer 404.

        Before exporting, the record is re-verified exactly like on
        restart: the plain content fingerprint is recomputed over the
        rebuilt blocks, the attested signature is re-verified against the
        domain message with the frozen public key and its fingerprint
        recomputed, and the frozen tip summary is checked against the
        rebuilt candidate. A signature/digest mismatch drops the cached
        record (persisted atomically, audit history untouched) and answers
        404; if that cleanup save fails the state is restored and the
        OSError propagates.
        """
        unknown = [key for key in params if key not in self.SYNC_EXPORT_PARAMS]
        if unknown:
            return 400, {"error": f"unknown query parameter: {sorted(unknown)[0]}"}
        for name in self.SYNC_EXPORT_PARAMS:
            if name not in params:
                return 400, {"error": f"missing query parameter: {name}"}
        source = params["source"]
        request_id = params["request_id"]
        mode = params["mode"]
        if not isinstance(source, str) or not source:
            return 400, {"error": "source must be a non-empty string"}
        if not isinstance(request_id, str) or not request_id:
            return 400, {"error": "request_id must be a non-empty string"}
        if mode not in self.SYNC_EXPORT_MODES:
            return 400, {"error": "mode must be one of plain, attested"}

        table = (
            self.store.attested_syncs
            if mode == SYNC_MODE_ATTESTED
            else self.store.syncs
        )
        with self.store.lock:
            # Sweep due expiries first (persisted atomically, exactly like
            # the other sync queries): an expired record exports as 404.
            self._prune_expired_syncs()
            key = (source, request_id)
            rec = table.get(key)
            if rec is None:
                return 404, {"error": "sync record not found"}
            # Incremental range deliveries (a plain record carrying a
            # "range" payload, or an attested record whose frozen
            # attestation holds the signed range) are not exportable here.
            attested = rec.get("attested")
            if "range" in rec or (
                isinstance(attested, dict) and "range" in attested
            ):
                return 409, {
                    "error": "incremental range sync records are not exportable"
                }

            tip_hash = rec["tip_hash"]
            blocks_raw = self._resolve_sync_blocks(tip_hash)
            if blocks_raw is None:
                # The tip resolves nowhere: a stale cache entry, dropped
                # under the same rules as a fingerprint mismatch.
                self._drop_sync_record(table, key)
                return 404, {"error": "sync record not found"}
            descriptor = {
                "tip_hash": tip_hash,
                "height": blocks_raw[-1]["height"],
                "length": len(blocks_raw),
                "status": blocks_raw[-1]["status"],
            }

            # Re-verify the record against the rebuilt candidate, exactly
            # like restart reconciliation: any signature/digest mismatch
            # drops the cache (audit history untouched) and answers 404.
            stale = False
            if mode == SYNC_MODE_PLAIN:
                if self._candidate_fingerprint(blocks_raw) != rec.get("fingerprint"):
                    stale = True
            else:
                if not isinstance(attested, dict):
                    stale = True
                else:
                    public_key = attested.get("public_key")
                    signature = attested.get("signature")
                    signed_candidate = attested.get("candidate")
                    if not crypto.is_hex64(public_key) or not crypto.is_hex128(
                        signature
                    ):
                        stale = True
                    else:
                        message = attested_message(
                            source, request_id, rec["expires_at"], signed_candidate
                        )
                        digest = hashlib.sha256(message).digest()
                        if not crypto.verify_signature(public_key, digest, signature):
                            stale = True
                        elif attested_fingerprint(
                            source,
                            request_id,
                            rec["expires_at"],
                            signed_candidate,
                            signature,
                        ) != rec.get("fingerprint"):
                            stale = True
                        else:
                            # Bind the signed chain to the rebuilt blocks.
                            signed_blocks = self._candidate_blocks(signed_candidate)
                            try:
                                signed_fork = self.store.validate_fork_blocks(
                                    signed_blocks
                                )
                            except ValueError:
                                stale = True
                            else:
                                stale = [
                                    block.to_dict() for block in signed_fork
                                ] != blocks_raw
            if not stale and rec.get("height") is not None:
                # The frozen tip summary must match the rebuilt candidate,
                # exactly like the restart-time summary check.
                stale = (
                    rec["height"] != descriptor["height"]
                    or rec["length"] != descriptor["length"]
                    or rec["status"] != descriptor["status"]
                )
            if stale:
                self._drop_sync_record(table, key)
                return 404, {"error": "sync record not found"}

            # The frozen summary wins when present (legacy records without
            # it fall back to the rebuilt descriptor); a valid record's
            # frozen values always equal the descriptor.
            height = rec["height"] if rec.get("height") is not None else descriptor["height"]
            length = rec["length"] if rec.get("length") is not None else descriptor["length"]
            status = rec["status"] if rec.get("status") is not None else descriptor["status"]
            if mode == SYNC_MODE_PLAIN:
                candidate_doc: object = {
                    "tip_hash": tip_hash,
                    "height": height,
                    "length": length,
                    "status": status,
                    "blocks": blocks_raw,
                }
                attestation: object = None
            else:
                candidate_doc = attested["candidate"]
                attestation = {
                    "public_key": attested["public_key"],
                    "version": attested["version"],
                    "signature": attested["signature"],
                }
            return 200, {
                "source": source,
                "request_id": request_id,
                "mode": mode,
                "expires_at": rec["expires_at"],
                "tip_hash": tip_hash,
                "height": height,
                "length": length,
                "status": status,
                "candidate": candidate_doc,
                "attestation": attestation,
            }

    SYNC_RANGE_EXPORT_PARAMS = ("source", "request_id", "mode")

    @staticmethod
    def _range_export_anchor(raw: object) -> dict | None:
        """Structurally validate a range export anchor ``{height, block_hash}``.

        Mirrors the range endpoints: ``height`` is a non-boolean non-negative
        integer and ``block_hash`` is 64 lowercase hex characters. Returns the
        closed ``{height, block_hash}`` anchor or None.
        """
        if not isinstance(raw, dict):
            return None
        height = raw.get("height")
        block_hash = raw.get("block_hash")
        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            return None
        if not crypto.is_hex64(block_hash):
            return None
        return {"height": height, "block_hash": block_hash}

    def export_fork_sync_range(self, params: dict) -> tuple[int, dict]:
        """GET /v1/forks/sync/range/export — export one received range delivery.

        The query contract mirrors ``GET /v1/forks/sync/export``: exactly the
        three single-valued parameters ``source`` and ``request_id``
        (non-empty) and ``mode`` (``plain``/``attested``); missing, repeated,
        unknown or illegal parameters are 400. The plain and attested tables
        stay separate idempotency namespaces, so ``mode`` selects the table.

        Only incremental RANGE records are exportable here: a whole-chain sync
        record (a plain record without a range payload, or an attested record
        whose frozen attestation carries a signed candidate rather than a
        signed range) answers 409. Unknown, expired or already-cleaned keys
        answer 404.

        A hit returns 200 with the fixed key order ``source, request_id, mode,
        expires_at, anchor, blocks, tip, attestation``. ``anchor`` is
        ``{height, block_hash}``; ``blocks`` is the non-empty delivered tail
        (normalized block documents in README key order); ``tip`` is the
        closed ``{tip_hash, height, length, status}`` summary recomputed from
        anchor + tail. A plain record carries ``attestation: null``; an
        attested record carries the frozen ``{public_key, version,
        signature}`` (64/positive-int/128 lowercase hex).

        Before exporting, the record is re-verified exactly like on restart:
        the tail standalone re-validates (consecutive heights, prev_hash
        links, recomputed block hashes and Merkle roots, tx_id/Ed25519,
        uniqueness/ordering, pending-only-at-tip), the assembled chain (the
        stored fork or, after adoption, the canonical prefix) is fully
        re-validated and confirmed to be exactly the canonical anchor prefix
        plus that tail, and the range content fingerprint is recomputed. An
        attested record additionally re-verifies its Ed25519 signature over
        the SHA-256 digest of the canonical
        ``{domain:"ledger-sync-range-v1", ...}`` message under the FROZEN
        public key, recomputes its fingerprint and checks the frozen signed
        tip recomputes. Any mismatch silently drops the cached record (and its
        candidate fork under the existing cache rules; the audit history is
        untouched, no event is emitted) and answers 404; if that cleanup save
        fails the record and fork are restored and the OSError propagates.
        """
        unknown = [
            key for key in params if key not in self.SYNC_RANGE_EXPORT_PARAMS
        ]
        if unknown:
            return 400, {"error": f"unknown query parameter: {sorted(unknown)[0]}"}
        for name in self.SYNC_RANGE_EXPORT_PARAMS:
            if name not in params:
                return 400, {"error": f"missing query parameter: {name}"}
        source = params["source"]
        request_id = params["request_id"]
        mode = params["mode"]
        if not isinstance(source, str) or not source:
            return 400, {"error": "source must be a non-empty string"}
        if not isinstance(request_id, str) or not request_id:
            return 400, {"error": "request_id must be a non-empty string"}
        if mode not in self.SYNC_EXPORT_MODES:
            return 400, {"error": "mode must be one of plain, attested"}

        table = (
            self.store.attested_syncs
            if mode == SYNC_MODE_ATTESTED
            else self.store.syncs
        )
        with self.store.lock:
            # Sweep due expiries first (persisted atomically, exactly like
            # the other sync queries): an expired record exports as 404.
            self._prune_expired_syncs()
            key = (source, request_id)
            rec = table.get(key)
            if rec is None:
                return 404, {"error": "sync record not found"}
            # Only incremental range records are exportable here; a
            # whole-chain delivery in either namespace answers 409.
            attested = rec.get("attested")
            if mode == SYNC_MODE_PLAIN:
                range_payload = rec.get("range")
                if not isinstance(range_payload, dict):
                    return 409, {
                        "error": "only incremental range sync records are exportable"
                    }
            else:
                if not isinstance(attested, dict) or not isinstance(
                    attested.get("range"), dict
                ):
                    return 409, {
                        "error": "only incremental range sync records are exportable"
                    }
                range_payload = attested["range"]

            anchor = self._range_export_anchor(range_payload.get("anchor"))
            if anchor is None:
                stale = True
                tail = None
                blocks_tail_raw: list[dict] = []
            else:
                stale = False
                tail = []
                blocks_tail_raw = []
                try:
                    tail = self.store.validate_range_tail(
                        anchor, range_payload.get("blocks")
                    )
                except ValueError:
                    stale = True
                else:
                    blocks_tail_raw = [block.to_dict() for block in tail]
                    if tail[-1].block_hash != rec["tip_hash"]:
                        stale = True

            # Attested records additionally re-verify the frozen signature
            # over the canonical ledger-sync-range-v1 message, recompute the
            # fingerprint and check the signed closed tip recomputes.
            signed_tip: dict | None = None
            attestation: object = None
            if not stale and mode == SYNC_MODE_ATTESTED:
                public_key = attested.get("public_key")
                version = attested.get("version")
                signature = attested.get("signature")
                signed_tip = range_payload.get("tip")
                if (
                    not crypto.is_hex64(public_key)
                    or isinstance(version, bool)
                    or not isinstance(version, int)
                    or version < 1
                    or not crypto.is_hex128(signature)
                    or not isinstance(signed_tip, dict)
                ):
                    stale = True
                else:
                    message = attested_range_message(
                        source,
                        request_id,
                        rec["expires_at"],
                        anchor,
                        range_payload.get("blocks"),
                        signed_tip,
                    )
                    digest = hashlib.sha256(message).digest()
                    if not crypto.verify_signature(public_key, digest, signature):
                        stale = True
                    elif (
                        attested_range_fingerprint(
                            source,
                            request_id,
                            rec["expires_at"],
                            anchor,
                            range_payload.get("blocks"),
                            signed_tip,
                            signature,
                        )
                        != rec.get("fingerprint")
                    ):
                        stale = True
                    attestation = {
                        "public_key": public_key,
                        "version": version,
                        "signature": signature,
                    }
            elif not stale:
                # Plain range: recompute the anchor + tail fingerprint.
                if self.store.range_fingerprint(anchor, tail) != rec.get(
                    "fingerprint"
                ):
                    stale = True

            # Resolve the stored assembled chain (the surviving fork, or the
            # canonical prefix once adopted) and confirm it is exactly the
            # anchor prefix plus the delivered tail; then run the full
            # whole-chain re-validation (genesis connection, endowment
            # replay and pending-only-at-tip included).
            recomputed_tip = None
            if not stale:
                recomputed_tip = self._range_tip_summary(anchor, tail)
                if mode == SYNC_MODE_ATTESTED and signed_tip != recomputed_tip:
                    stale = True
                elif rec.get("height") is not None and (
                    rec["height"] != recomputed_tip["height"]
                    or rec["length"] != recomputed_tip["length"]
                    or rec["status"] != recomputed_tip["status"]
                ):
                    # The frozen summary must match the recomputed delivered
                    # chain, exactly like the restart-time summary check.
                    stale = True
            blocks_full = None
            if not stale:
                blocks_full = self._resolve_sync_blocks(rec["tip_hash"])
                if blocks_full is None:
                    stale = True
                else:
                    anchor_height = anchor["height"]
                    if len(blocks_full) <= anchor_height + 1:
                        stale = True
                    else:
                        stored_anchor = blocks_full[anchor_height]
                        stored_tail = blocks_full[anchor_height + 1 :]
                        if (
                            stored_anchor.get("height") != anchor_height
                            or stored_anchor.get("block_hash")
                            != anchor["block_hash"]
                            or stored_tail != blocks_tail_raw
                        ):
                            stale = True
                        else:
                            try:
                                assembled = self.store.validate_fork_blocks(
                                    blocks_full
                                )
                            except ValueError:
                                stale = True
                            else:
                                if assembled[-1].block_hash != rec["tip_hash"]:
                                    stale = True
            if stale:
                # Signature/digest/chain mismatch: silently drop the cache
                # (audit history untouched, no event) and answer 404. A
                # failed cleanup save restores record and fork and propagates.
                self._drop_sync_record(table, key)
                return 404, {"error": "sync record not found"}

            return 200, {
                "source": source,
                "request_id": request_id,
                "mode": mode,
                "expires_at": rec["expires_at"],
                "anchor": {"height": anchor["height"], "block_hash": anchor["block_hash"]},
                "blocks": blocks_tail_raw,
                "tip": recomputed_tip,
                "attestation": attestation,
            }


    SYNC_HISTORY_KINDS = (
        EVENT_SYNC_RECEIVED,
        EVENT_SYNC_ADOPTED,
        EVENT_SYNC_EXPIRED,
    )
    SYNC_HISTORY_DEFAULT_LIMIT = 50
    SYNC_HISTORY_MAX_LIMIT = 200

    def list_fork_sync_history(self, params: dict) -> tuple[int, dict]:
        """GET /v1/forks/sync/history — paginated sync lifecycle history.

        Backed by the append-only audit log: one row per durable
        ``sync_received`` / ``sync_adopted`` / ``sync_expired`` event. Every
        row freezes the tip summary (height/length/status) captured when the
        event was recorded, so adoption and expiry never rewrite past rows and
        an adopted-then-expired record stays auditable after the sync metadata
        is gone.

        Filters (AND-combined): ``source`` (exact), ``tip_hash`` (exact, must
        be 64 lowercase hex characters — a malformed value is 400 while an
        unknown one simply yields an empty page), ``kind`` (one of the three
        sync kinds; unknown 400), ``mode`` (absent or ``all`` returns every
        event; ``plain`` matches ordinary events including legacy rows with no
        mode field; ``attested`` matches only ``mode:"attested"`` events; any
        other value is 400), ``min_height`` / ``max_height``. ``limit``
        defaults to 50 and must be 1-200; ``cursor`` defaults to 0. Every
        numeric value must be a plain non-negative decimal with no leading
        zeros (except ``0`` itself); signs, whitespace, decimals and repeated
        parameters are rejected before anything else. Rows are ordered by
        ``(height, tip_hash, source, request_id, event_id)``;
        ``cursor == total`` returns an empty page, ``cursor > total`` is 400.
        """
        source = params.get("source")
        if source is not None and (not isinstance(source, str) or not source):
            return 400, {"error": "source must be a non-empty string"}

        tip_hash = params.get("tip_hash")
        if tip_hash is not None and not crypto.is_hex64(tip_hash):
            return 400, {"error": "tip_hash must be 64 lowercase hex characters"}

        kind = params.get("kind")
        if kind is not None and kind not in self.SYNC_HISTORY_KINDS:
            return 400, {
                "error": "kind must be one of sync_received, sync_adopted, "
                "sync_expired"
            }

        # Optional transport-mode filter: absent or "all" returns every
        # lifecycle event; "plain" matches ordinary events including legacy
        # rows that carry no mode field at all; "attested" matches only events
        # explicitly recorded with mode="attested". Any other value is 400.
        mode = params.get("mode")
        if mode is None:
            mode = "all"
        if mode not in self.SYNC_QUERY_MODES:
            return 400, {"error": "mode must be one of plain, attested, all"}

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

        limit = self.SYNC_HISTORY_DEFAULT_LIMIT
        if params.get("limit") is not None:
            parsed = _parse_decimal(params["limit"])
            if parsed is None or not 1 <= parsed <= self.SYNC_HISTORY_MAX_LIMIT:
                return 400, {"error": "limit must be a decimal between 1 and 200"}
            limit = parsed
        cursor = 0
        if params.get("cursor") is not None:
            parsed = _parse_decimal(params["cursor"])
            if parsed is None:
                return 400, {"error": "cursor must be a non-negative decimal"}
            cursor = parsed

        with self.store.lock:
            # Make any due expiry durable first, exactly like the other sync
            # queries, so its sync_expired row appears on this page too.
            self._prune_expired_syncs()
            rows: list[dict] = []
            for event in self.store.audit_events:
                event_kind = event.get("kind")
                if event_kind not in self.SYNC_HISTORY_KINDS:
                    continue
                if source is not None and event.get("source") != source:
                    continue
                if tip_hash is not None and event.get("tip_hash") != tip_hash:
                    continue
                if kind is not None and event_kind != kind:
                    continue
                # Transport-mode filtering. Legacy events written before the
                # attested mode existed have no mode field and therefore count
                # as plain; mode="all" skips the check entirely.
                event_is_attested = event.get("mode") == SYNC_MODE_ATTESTED
                if mode == SYNC_MODE_PLAIN and event_is_attested:
                    continue
                if mode == SYNC_MODE_ATTESTED and not event_is_attested:
                    continue
                # Prefer the summary frozen into the event when it was
                # recorded. Events written before summaries were frozen fall
                # back to resolving the tip live; a tip that no longer
                # resolves anywhere is omitted rather than misordered.
                height = event.get("height")
                length = event.get("length")
                status = event.get("status")
                if (
                    not isinstance(height, int)
                    or isinstance(height, bool)
                    or length is None
                    or status is None
                ):
                    descriptor = self._tip_descriptor(event.get("tip_hash"))
                    if descriptor is None:
                        continue
                    height = descriptor["height"]
                    length = descriptor["length"]
                    status = descriptor["status"]
                if min_height is not None and height < min_height:
                    continue
                if max_height is not None and height > max_height:
                    continue
                # New events always carry the deadline; a legacy adopted
                # event predating the field inherits it from its still-live
                # sync record when possible.
                expires_at = event.get("expires_at")
                if expires_at is None:
                    is_attested = event.get("mode") == SYNC_MODE_ATTESTED
                    table = (
                        self.store.attested_syncs
                        if is_attested
                        else self.store.syncs
                    )
                    live_rec = table.get(
                        (event.get("source"), event.get("request_id"))
                    )
                    if (
                        live_rec is not None
                        and live_rec.get("tip_hash") == event.get("tip_hash")
                    ):
                        expires_at = live_rec.get("expires_at")
                rows.append(
                    {
                        "event_id": event["event_id"],
                        "kind": event_kind,
                        "at": event["at"],
                        "source": event.get("source"),
                        "request_id": event.get("request_id"),
                        "tip_hash": event.get("tip_hash"),
                        "height": height,
                        "length": length,
                        "status": status,
                        "expires_at": expires_at,
                    }
                )

        rows.sort(
            key=lambda row: (
                row["height"],
                row["tip_hash"],
                row["source"],
                row["request_id"],
                row["event_id"],
            )
        )
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

    # -- source trust registry ------------------------------------------------

    @staticmethod
    def _trust_record(source: str, rec: dict) -> dict:
        """Public shape of one trust-source record."""
        return {
            "source": source,
            "public_key": rec["public_key"],
            "expires_at": rec["expires_at"],
            "version": rec["version"],
            "status": rec["status"],
        }

    def _validate_trust_input(self, payload: object, require_version: bool) -> tuple | None:
        """Validate a trust registration/rotation body.

        ``source`` must be a non-empty string, ``public_key`` 64 lowercase
        hex characters and ``expires_at`` a plain (non-boolean) integer.
        Rotation/revocation additionally require a positive integer
        ``expected_version``. Returns (source, public_key, expires_at[,
        expected_version]) or None after sending a 400.
        """
        if not isinstance(payload, dict):
            return None
        for field in ("source", "public_key", "expires_at"):
            if field not in payload:
                return None
        source = payload["source"]
        public_key = payload["public_key"]
        expires_at = payload["expires_at"]
        if not isinstance(source, str) or not source:
            return None
        if not crypto.is_hex64(public_key):
            return None
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            return None
        if not require_version:
            return source, public_key, expires_at
        expected_version = payload.get("expected_version")
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 1
        ):
            return None
        return source, public_key, expires_at, expected_version

    def register_trust_source(self, payload: object) -> tuple[int, dict]:
        """POST /v1/trust/sources — register a trusted source.

        A new source is created at version 1 with status ``active`` and the
        change is persisted together with its audit event in one atomic write
        (201). Re-posting the exact same (public_key, expires_at) content is
        idempotent (200, the stored record unchanged); the same source with
        different content conflicts (409).
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in ("source", "public_key", "expires_at"):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}
        parsed = self._validate_trust_input(payload, require_version=False)
        if parsed is None:
            return 400, {
                "error": "source must be a non-empty string, public_key 64 "
                "lowercase hex characters and expires_at an integer"
            }
        source, public_key, expires_at = parsed
        with self.store.lock:
            existing = self.store.trust_sources.get(source)
            if existing is not None:
                if (
                    existing["public_key"] == public_key
                    and existing["expires_at"] == expires_at
                ):
                    # Idempotent re-registration: the stored record is reported
                    # unchanged, with no new version and no new audit event.
                    return 200, self._trust_record(source, existing)
                return 409, {"error": "trust source already exists with different content"}
            record = {
                "public_key": public_key,
                "expires_at": expires_at,
                "version": 1,
                "status": TRUST_ACTIVE,
            }
            self.store.trust_sources[source] = record
            event = self.store.append_audit_event(
                EVENT_SOURCE_REGISTERED,
                {
                    "source": source,
                    "public_key": public_key,
                    "expires_at": expires_at,
                    "version": 1,
                },
            )
            # Open the source's key history at version 1, activated by the
            # registration event; retained forever (rotation appends, revoke
            # keeps) so an old attested delivery stays verifiable offline.
            self.store.source_key_history[source] = [
                {
                    "version": 1,
                    "public_key": public_key,
                    "activated_event_id": event["event_id"],
                }
            ]
            try:
                self.store.save()
            except BaseException:
                # Undo the registry change, its event and its history together.
                self.store.trust_sources.pop(source, None)
                self.store.source_key_history.pop(source, None)
                self.store.truncate_audit_events(1)
                raise
            return 201, self._trust_record(source, record)

    def rotate_trust_source(self, source: object, payload: object) -> tuple[int, dict]:
        """POST /v1/trust/sources/{source}/rotate — install a new public key.

        Requires ``public_key``, ``expires_at`` and ``expected_version``. An
        unknown or already-revoked source returns 404; a stale
        ``expected_version`` returns 409. A successful rotation increments the
        version, keeps the source active and persists the change with an audit
        event atomically.
        """
        if not isinstance(source, str) or not source:
            return 404, {"error": "unknown trust source"}
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in ("public_key", "expires_at", "expected_version"):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}
        body = dict(payload)
        body["source"] = source
        parsed = self._validate_trust_input(body, require_version=True)
        if parsed is None:
            return 400, {
                "error": "public_key must be 64 lowercase hex characters and "
                "expires_at/expected_version integers"
            }
        _, public_key, expires_at, expected_version = parsed
        with self.store.lock:
            existing = self.store.trust_sources.get(source)
            if existing is None or existing["status"] == TRUST_REVOKED:
                return 404, {"error": "unknown trust source"}
            if existing["version"] != expected_version:
                return 409, {"error": "expected_version does not match the current version"}
            old_record = dict(existing)
            old_history = list(self.store.source_key_history.get(source, ()))
            existing["public_key"] = public_key
            existing["expires_at"] = expires_at
            existing["version"] = old_record["version"] + 1
            event = self.store.append_audit_event(
                EVENT_SOURCE_ROTATED,
                {
                    "source": source,
                    "public_key": public_key,
                    "expires_at": expires_at,
                    "version": existing["version"],
                },
            )
            # Append the new key to the source's ascending history, activated
            # by this rotation event; previous versions are retained forever.
            history = self.store.source_key_history.setdefault(source, [])
            history.append(
                {
                    "version": existing["version"],
                    "public_key": public_key,
                    "activated_event_id": event["event_id"],
                }
            )
            try:
                self.store.save()
            except BaseException:
                self.store.trust_sources[source] = old_record
                if old_history:
                    self.store.source_key_history[source] = old_history
                else:
                    self.store.source_key_history.pop(source, None)
                self.store.truncate_audit_events(1)
                raise
            return 200, self._trust_record(source, existing)

    def revoke_trust_source(self, source: object, payload: object) -> tuple[int, dict]:
        """POST /v1/trust/sources/{source}/revoke — revoke a trusted source.

        Requires ``expected_version``. An unknown source returns 404 and a
        version mismatch returns 409; revoking an already-revoked source at the
        recorded version is idempotent (200). A new revocation marks the source
        revoked and is persisted with its audit event atomically.
        """
        if not isinstance(source, str) or not source:
            return 404, {"error": "unknown trust source"}
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        if "expected_version" not in payload:
            return 400, {"error": "missing field: expected_version"}
        expected_version = payload["expected_version"]
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 1
        ):
            return 400, {"error": "expected_version must be a positive integer"}
        with self.store.lock:
            existing = self.store.trust_sources.get(source)
            if existing is None:
                return 404, {"error": "unknown trust source"}
            if existing["version"] != expected_version:
                return 409, {"error": "expected_version does not match the current version"}
            if existing["status"] == TRUST_REVOKED:
                # Idempotent repeat revocation: no second event, no new write.
                return 200, self._trust_record(source, existing)
            old_status = existing["status"]
            existing["status"] = TRUST_REVOKED
            self.store.append_audit_event(
                EVENT_SOURCE_REVOKED,
                {
                    "source": source,
                    "public_key": existing["public_key"],
                    "expires_at": existing["expires_at"],
                    "version": existing["version"],
                },
            )
            try:
                self.store.save()
            except BaseException:
                existing["status"] = old_status
                self.store.truncate_audit_events(1)
                raise
            return 200, self._trust_record(source, existing)

    def get_trust_document(self) -> tuple[int, dict]:
        """GET /v1/trust — the offline light-client verify document.

        ``genesis_hash`` always pins the fixed canonical genesis block;
        ``sources`` contains only active, unexpired entries in the light
        client's shape ``{public_key, expires_at}``; the keyless
        ``allowlist`` is preserved verbatim; ``audit_signers`` lists every
        checkpoint key ever held in ascending version order as
        ``{version, public_key, activated_event_id}`` (version 1 is activated
        at event 0), so offline audit export verification can pick the key
        that signed each checkpoint; ``source_key_history`` maps every
        registered source to every source key it ever held, in ascending
        version order as ``{version, public_key, activated_event_id}``
        (version 1 is activated at the ``source_registered`` event, each
        rotation at its ``source_rotated`` event; revocation retains the full
        history), so offline attested-range verification can pick the key that
        signed an older attestation.
        """
        with self.store.lock:
            now = time.time()
            sources = {}
            for source, rec in self.store.trust_sources.items():
                if rec["status"] != TRUST_ACTIVE or rec["expires_at"] <= now:
                    continue
                sources[source] = {
                    "public_key": rec["public_key"],
                    "expires_at": rec["expires_at"],
                }
            audit_signers = [dict(entry) for entry in self.store.audit_signer_history]
            source_key_history = {
                source: [dict(entry) for entry in history]
                for source, history in self.store.source_key_history.items()
            }
            return 200, {
                "genesis_hash": self.store.chain[0].block_hash,
                "sources": sources,
                "allowlist": dict(self.store.allowlist),
                "audit_signers": audit_signers,
                "source_key_history": source_key_history,
            }

    # -- keyless allowlist management -----------------------------------------

    @staticmethod
    def _allowlist_entry(source: str, expires_at: int) -> dict:
        """Public shape of one keyless allowlist entry."""
        return {"source": source, "expires_at": expires_at}

    def add_allowlist_entry(self, payload: object) -> tuple[int, dict]:
        """POST /v1/trust/allowlist — add a keyless source for offline verify.

        The body carries ``source`` (a non-empty string) and ``expires_at`` (a
        plain, non-boolean Unix-seconds integer); anything malformed is 400. A
        new entry is persisted together with its ``allowlist_added`` audit
        event in one atomic write and returns 201 with
        ``{source, expires_at}``. Re-posting the exact same content is
        idempotent (200, no new event, no write); the same source with a
        different expiry conflicts 409 (remove it first).

        The allowlist is keyless and offline-only: it never creates a trust
        source and never authorizes POST /v1/forks/sync, and expired entries
        are retained verbatim (an expired entry is still an entry, so a
        same-content retry stays 200 and a changed-content retry stays 409).
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in ("source", "expires_at"):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}
        source = payload["source"]
        expires_at = payload["expires_at"]
        if not isinstance(source, str) or not source:
            return 400, {"error": "field 'source' must be a non-empty string"}
        # bool is a subclass of int: reject it and every other non-int type.
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            return 400, {"error": "field 'expires_at' must be a Unix-seconds integer"}
        with self.store.lock:
            existing = self.store.allowlist.get(source)
            if existing is not None:
                if existing == expires_at:
                    # Idempotent re-add: the stored entry is reported
                    # unchanged, with no new audit event and no new write.
                    return 200, self._allowlist_entry(source, existing)
                return 409, {"error": "allowlist entry already exists with different content"}
            self.store.allowlist[source] = expires_at
            self.store.append_audit_event(
                EVENT_ALLOWLIST_ADDED,
                {"source": source, "expires_at": expires_at},
            )
            try:
                self.store.save()
            except BaseException:
                # Undo the entry and its event together so a failed write
                # never leaves one without the other.
                self.store.allowlist.pop(source, None)
                self.store.truncate_audit_events(1)
                raise
            return 201, self._allowlist_entry(source, expires_at)

    def remove_allowlist_entry(self, source: object) -> tuple[int, dict]:
        """DELETE /v1/trust/allowlist/{source} — remove a keyless entry.

        An unknown source (including the empty path segment) returns 404. A
        known entry is deleted and its ``allowlist_removed`` event (carrying
        the source and the removed entry's ``expires_at``) is persisted in the
        same atomic write; a failed write restores both. Returns
        ``{source, removed: true}`` on success. Removing an allowlist entry
        never touches a same-named entry of the persistent trust registry.
        """
        if not isinstance(source, str) or not source:
            return 404, {"error": "unknown allowlist entry"}
        with self.store.lock:
            existing = self.store.allowlist.get(source)
            if existing is None:
                return 404, {"error": "unknown allowlist entry"}
            del self.store.allowlist[source]
            self.store.append_audit_event(
                EVENT_ALLOWLIST_REMOVED,
                {"source": source, "expires_at": existing},
            )
            try:
                self.store.save()
            except BaseException:
                # Restore the entry and drop its event together.
                self.store.allowlist[source] = existing
                self.store.truncate_audit_events(1)
                raise
            return 200, {"source": source, "removed": True}

    # -- audit log ------------------------------------------------------------

    AUDIT_DEFAULT_LIMIT = 50
    AUDIT_MAX_LIMIT = 200

    def rotate_audit_signer(self, payload: object) -> tuple[int, dict]:
        """POST /v1/audit/signer/rotate — install a new Ed25519 checkpoint key.

        The body carries ``private_key`` (64 lowercase hex characters — the
        Ed25519 seed) and ``expected_version`` (the current key version).
        Malformed input returns 400 and a stale ``expected_version`` returns
        409. On success the new key version is derived from the seed, an
        ``audit_signer_rotated`` event records the new version and public key,
        and the key, the event and the refreshed checkpoint are persisted in
        one atomic write (200), returning ``{"version", "public_key"}``. Old
        public keys are retained in the signer history so historical
        checkpoints stay verifiable.
        """
        if not isinstance(payload, dict):
            return 400, {"error": "request body must be a JSON object"}
        for field in ("private_key", "expected_version"):
            if field not in payload:
                return 400, {"error": f"missing field: {field}"}
        private_key = payload["private_key"]
        expected_version = payload["expected_version"]
        if not crypto.is_hex64(private_key):
            return 400, {
                "error": "field 'private_key' must be 64 lowercase hex characters"
            }
        public_key = crypto.derive_public_key(private_key)
        if public_key is None:
            return 400, {
                "error": "field 'private_key' must be 64 lowercase hex characters"
            }
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 1
        ):
            return 400, {"error": "field 'expected_version' must be a positive integer"}
        with self.store.lock:
            current = self.store.audit_signer
            if current is None:
                # load() mints/migrates a key for every node, so a live store
                # always has a current signer.
                return 409, {"error": "audit signer is not initialized"}
            if current["version"] != expected_version:
                return 409, {
                    "error": "expected_version does not match the current signer version"
                }
            new_version = current["version"] + 1
            old_signer = dict(current)
            history_length = len(self.store.audit_signer_history)
            event = self.store.append_audit_event(
                EVENT_AUDIT_SIGNER_ROTATED,
                {"version": new_version, "public_key": public_key},
            )
            new_signer = {
                "version": new_version,
                "private_key": private_key,
                "public_key": public_key,
                "activated_event_id": event["event_id"],
            }
            self.store.audit_signer = new_signer
            self.store.audit_signer_history.append(
                {
                    "version": new_version,
                    "public_key": public_key,
                    "activated_event_id": event["event_id"],
                }
            )
            try:
                self.store.save()
            except BaseException:
                # Roll the key, the history entry and its audit event back
                # together so a failed write never leaves a rotated key
                # without its event.
                self.store.audit_signer = old_signer
                del self.store.audit_signer_history[history_length:]
                self.store.truncate_audit_events(1)
                raise
            return 200, {"version": new_version, "public_key": public_key}

    def list_audit_events(self, params: dict) -> tuple[int, dict]:
        """GET /v1/audit/events — paginated append-only audit log.

        Filters ``source`` and ``kind`` are AND-combined; ``limit`` defaults
        to 50 and must be 1-200, ``cursor`` defaults to 0. Numeric values
        must be plain decimals without leading zeros. Events are ordered by
        their ascending ``event_id``; ``cursor == total`` returns an empty
        page, ``cursor > total`` returns 400.
        """
        source = params.get("source")
        if source is not None and (not isinstance(source, str) or not source):
            return 400, {"error": "source must be a non-empty string"}
        kind = params.get("kind")
        if kind is not None and (not isinstance(kind, str) or not kind):
            return 400, {"error": "kind must be a non-empty string"}
        limit = self.AUDIT_DEFAULT_LIMIT
        if params.get("limit") is not None:
            parsed = _parse_decimal(params["limit"])
            if parsed is None or not 1 <= parsed <= self.AUDIT_MAX_LIMIT:
                return 400, {"error": "limit must be a decimal between 1 and 200"}
            limit = parsed
        cursor = 0
        if params.get("cursor") is not None:
            parsed = _parse_decimal(params["cursor"])
            if parsed is None:
                return 400, {"error": "cursor must be a non-negative decimal"}
            cursor = parsed

        with self.store.lock:
            # Sweep expired syncs first so their expiry events are visible on
            # the same page that observes the removal.
            self._prune_expired_syncs()
            items = [
                dict(event)
                for event in self.store.audit_events
                if (source is None or event.get("source") == source)
                and (kind is None or event.get("kind") == kind)
            ]
        # Events are stored in ascending event_id order; filtering preserves it.
        total = len(items)
        if cursor > total:
            return 400, {"error": "cursor is beyond the result set"}
        page = items[cursor : cursor + limit]
        next_cursor = cursor + limit if cursor + limit < total else None
        return 200, {"items": page, "total": total, "next_cursor": next_cursor}

    def export_audit_events(self, params: dict) -> tuple[int, dict]:
        """GET /v1/audit/export — hash-anchored export page for offline checks.

        Pagination is identical to ``GET /v1/audit/events`` for the *whole*
        log (no source/kind filters — an offline verifier replays every
        event): ``limit`` defaults to 50 and must be 1-200, ``cursor``
        defaults to 0; both must be plain decimals without leading zeros.
        Items are the events in ascending ``event_id``, each carrying its
        ``prev_hash``/``event_hash`` links. The response additionally
        contains:

        * ``anchor_hash`` — the hash immediately preceding the page's first
          event (64 zeroes at cursor 0; the head at cursor == total);
        * ``checkpoint`` — the current ``{event_id, event_hash}`` log head
          (``{0, "0"*64}`` for an empty log), included on every page;
        * ``checkpoint_auth`` — ``{key_version, signature}`` binding that
          checkpoint (and the genesis anchor) under the current audit signer;
          the same envelope is returned on every page of one export.

        ``cursor == total`` returns an empty last page (its anchor is the log
        head so the final page matches the checkpoint); ``cursor > total`` is
        400.
        """
        limit = self.AUDIT_DEFAULT_LIMIT
        if params.get("limit") is not None:
            parsed = _parse_decimal(params["limit"])
            if parsed is None or not 1 <= parsed <= self.AUDIT_MAX_LIMIT:
                return 400, {"error": "limit must be a decimal between 1 and 200"}
            limit = parsed
        cursor = 0
        if params.get("cursor") is not None:
            parsed = _parse_decimal(params["cursor"])
            if parsed is None:
                return 400, {"error": "cursor must be a non-negative decimal"}
            cursor = parsed

        with self.store.lock:
            # Sweep due expiries first, exactly like /v1/audit/events, so the
            # exported checkpoint and log never lag a durable expiry.
            self._prune_expired_syncs()
            events = self.store.audit_events
            total = len(events)
            if cursor > total:
                return 400, {"error": "cursor is beyond the result set"}
            page = [dict(event) for event in events[cursor : cursor + limit]]
            # The anchor is the predecessor hash of the page's first event;
            # for an empty terminal page it is the current log head, which the
            # offline verifier requires the last page to meet.
            if cursor == 0:
                anchor_hash = audit.ZERO_HASH
            else:
                anchor_hash = events[cursor - 1]["event_hash"]
            next_cursor = cursor + limit if cursor + limit < total else None
            body = {
                "items": page,
                "total": total,
                "next_cursor": next_cursor,
                "anchor_hash": anchor_hash,
                "checkpoint": dict(self.store.audit_checkpoint),
                # One fresh signature over the current head on every request;
                # every page fetched in the same export binds the identical
                # checkpoint and therefore the same verifiable envelope.
                "checkpoint_auth": self.store.sign_checkpoint(),
            }
        return 200, body

    # -- node-managed checkpoint history -------------------------------------

    HISTORY_TRUST_UPDATE_FIELDS = ("root_seed", "at", "key", "status")
    HISTORY_EXPORT_FIELDS = ("key", "after", "limit")

    # The light_client failure categories of these two operations are exactly
    # input/auth/state/io; map them onto the HTTP status contract.
    _HISTORY_STATUS = {
        "input": 400,
        "auth": 403,
        "state": 409,
        "io": 500,
    }

    @classmethod
    def _history_failure(cls, result: dict) -> tuple[int, dict]:
        category = result.get("error", "io")
        return (
            cls._HISTORY_STATUS.get(category, 500),
            {"ok": False, "error": category},
        )

    def _history_heads(self) -> tuple[str | None, str | None]:
        """Current (trust_head, history_head); null for a not-yet-created file.

        Caller must already hold the store lock and both file-path locks.
        Raises OSError for an ``io``-class read failure or
        ``_HistoryFileError`` for a strict-verification (``state``) defect, so
        callers can map the outcome onto the 500/409 contract.
        """
        from . import light_client

        inspection = light_client.inspect_history_files(
            self.history_path, self.history_trust_path
        )
        if not inspection.get("ok"):
            category = inspection.get("error")
            if category == "io":
                raise OSError(
                    inspection.get("path"),
                    "managed history file unreadable",
                )
            raise LedgerService._HistoryFileError(
                category or "state", inspection.get("path")
            )
        return inspection["trust_head"], inspection["history_head"]

    class _HistoryFileError(Exception):
        """A managed history file failed strict verification mid-request."""

        def __init__(self, category: str, path: str | None) -> None:
            self.category = category
            self.path = path
            super().__init__(f"{category}: {path}")

    def _append_history_access_and_save(
        self,
        action: str,
        trust_head: str | None,
        history_head: str | None,
        restore: list[tuple[str, bytes | None]] | None = None,
    ) -> None:
        """Append the history_access event and persist the snapshot atomically.

        The event payload has the fixed key order
        ``action, trust_head, history_head`` (a missing file contributes
        ``null``). On a snapshot failure the in-memory event is dropped and,
        when given, each ``(path, original_bytes)`` pair is restored
        best-effort; the original exception is re-raised so the caller answers
        500/io.
        """
        self.store.append_audit_event(
            EVENT_HISTORY_ACCESS,
            {
                "action": action,
                "trust_head": trust_head,
                "history_head": history_head,
            },
        )
        try:
            self.store.save()
        except BaseException:
            self.store.truncate_audit_events(1)
            if restore is not None:
                from . import light_client

                for path, original in restore:
                    light_client.restore_file_bytes(path, original)
            raise

    # -- scoped history-access credential ------------------------------------

    # The permission each token-gated history route requires; "manage" names
    # the credential-management route, which only the static token may use.
    HISTORY_PERMISSION_MANAGE = "manage"

    def history_authorization(
        self, authorization: str | None, permission: str
    ) -> str:
        """Authorize one /v1/history/* request against the configured tokens.

        Returns ``"ok"``, ``"unauthorized"`` or ``"forbidden"``. The static
        ``--history-token`` is full-power and is the ONLY credential allowed
        to manage the scoped credential (permission ``manage``). A scoped
        bearer token authenticates only while its credential is ``active``
        (the hash of the presented token is compared in constant time) and
        then only for its recorded permissions; a valid active token lacking
        the required permission is ``forbidden``, everything else —
        missing/malformed header, unknown or revoked token — is
        ``unauthorized``. No state is read or written beyond the persisted
        credential record.
        """
        expected = (
            f"Bearer {self.history_token}"
            if self.history_token is not None
            else None
        )
        # Compare bytes: a header containing non-ASCII (decoded latin-1 by
        # the HTTP layer) must simply mismatch, never raise out of
        # compare_digest (which rejects non-ASCII str inputs).
        if (
            expected is not None
            and authorization is not None
            and hmac.compare_digest(
                authorization.encode("utf-8", errors="replace"),
                expected.encode("utf-8"),
            )
        ):
            return "ok"
        with self.store.lock:
            credential = self.store.history_credential
        if (
            authorization is not None
            and credential is not None
            and credential["status"] == "active"
            and authorization.startswith("Bearer ")
        ):
            digest = hashlib.sha256(
                authorization[len("Bearer ") :].encode("utf-8", errors="replace")
            ).hexdigest()
            if hmac.compare_digest(digest, credential["token_hash"]):
                if (
                    permission == self.HISTORY_PERMISSION_MANAGE
                    or permission not in credential["permissions"]
                ):
                    return "forbidden"
                return "ok"
        return "unauthorized"

    HISTORY_ACCESS_FIELDS = ("action", "token", "permissions", "expected_version")

    def update_history_credential(self, payload: object) -> tuple[int, dict]:
        """POST /v1/history/access — rotate or revoke the scoped credential.

        The body must be a JSON object containing exactly ``action, token,
        permissions, expected_version``. For ``rotate`` the token must be a
        non-empty string and permissions a non-empty duplicate-free
        subsequence of read/update/export; for ``revoke`` both must be null.
        ``expected_version`` is a non-boolean non-negative integer that must
        equal the current version (0 before the first rotation) — a mismatch
        is 409/state. Every shape defect is 400/input.

        The first rotation returns 201; every later change returns 200 with
        the version advanced by one. Revocation keeps the recorded hash and
        permissions, flipping only the status to ``revoked``. The success
        document has the contract key order
        ``version, token_hash, permissions, status`` where ``token_hash`` is
        the SHA-256 of the token's UTF-8 bytes; the plaintext token is never
        stored. The new credential, its ``history_credential_changed`` audit
        event (payload: the action followed by the response document) and the
        generation land in one atomic snapshot; a write failure rolls all
        three back and answers 500/io.
        """
        if not self.history_enabled:
            return 404, {"ok": False, "error": "not found"}
        if not isinstance(payload, dict) or set(payload) != set(
            self.HISTORY_ACCESS_FIELDS
        ):
            return 400, {"ok": False, "error": "input"}
        action = payload["action"]
        if action not in ("rotate", "revoke"):
            return 400, {"ok": False, "error": "input"}
        expected_version = payload["expected_version"]
        if (
            isinstance(expected_version, bool)
            or not isinstance(expected_version, int)
            or expected_version < 0
        ):
            return 400, {"ok": False, "error": "input"}
        token = payload["token"]
        permissions = payload["permissions"]
        if action == "rotate":
            if not isinstance(token, str) or not token:
                return 400, {"ok": False, "error": "input"}
            if not valid_history_permissions(permissions):
                return 400, {"ok": False, "error": "input"}
        elif token is not None or permissions is not None:
            return 400, {"ok": False, "error": "input"}

        try:
            with self.store.lock:
                current = self.store.history_credential
                current_version = (
                    current["version"] if current is not None else 0
                )
                if expected_version != current_version:
                    return 409, {"ok": False, "error": "state"}
                if action == "revoke" and (
                    current is None or current["status"] != TRUST_ACTIVE
                ):
                    # Nothing active to revoke.
                    return 409, {"ok": False, "error": "state"}
                if action == "rotate":
                    credential = {
                        "version": current_version + 1,
                        "token_hash": hashlib.sha256(
                            token.encode("utf-8")
                        ).hexdigest(),
                        "permissions": list(permissions),
                        "status": TRUST_ACTIVE,
                    }
                else:
                    # Revocation retains the hash and the permissions.
                    credential = {
                        "version": current_version + 1,
                        "token_hash": current["token_hash"],
                        "permissions": list(current["permissions"]),
                        "status": TRUST_REVOKED,
                    }
                created = current is None
                self.store.history_credential = credential
                self.store.append_audit_event(
                    EVENT_HISTORY_CREDENTIAL_CHANGED,
                    {"action": action, **credential},
                )
                try:
                    self.store.save()
                except BaseException:
                    # Roll the credential, its event and the generation back
                    # together so a failed write leaves nothing behind.
                    self.store.history_credential = current
                    self.store.truncate_audit_events(1)
                    raise
        except OSError:
            return 500, {"ok": False, "error": "io"}
        except Exception:
            # Defensive HTTP boundary, mirroring the other history endpoints.
            return 500, {"ok": False, "error": "io"}
        return (201 if created else 200), dict(credential)

    def read_history_trust(self) -> tuple[int, dict]:
        """GET /v1/history/trust — strictly read the durable signer log.

        Returns the ``{root, records, head}`` document in its contract key
        order. Every read is audited with a ``read`` history_access event; the
        event, checkpoint and generation land in one snapshot before the
        response. A missing log is ``io`` (500), a corrupt log ``state`` (409).
        """
        if not self.history_enabled:
            return 404, {"ok": False, "error": "not found"}
        from . import light_client

        with self.store.lock:
            with light_client._checkpoint_lock(
                self.history_path
            ), light_client._checkpoint_lock(self.history_trust_path):
                try:
                    result = light_client.history_trust(self.history_trust_path)
                    if result.get("ok") is False:
                        return self._history_failure(result)
                    trust_head, history_head = self._history_heads()
                    self._append_history_access_and_save(
                        "read", trust_head, history_head
                    )
                except self._HistoryFileError as failure:
                    return self._history_failure(
                        {"error": failure.category}
                    )
                except OSError:
                    return 500, {"ok": False, "error": "io"}
                except Exception:
                    # Defensive HTTP boundary: any unforeseen failure is an
                    # internal error; any external-file compensation already
                    # ran inside _append_history_access_and_save.
                    return 500, {"ok": False, "error": "io"}
                return 200, result

    def update_history_trust(self, payload: object) -> tuple[int, dict]:
        """POST /v1/history/trust — append one signer-log certificate.

        The body must be a JSON object containing exactly
        ``root_seed, at, key, status``; every shape defect is 400 (input). The
        append reuses ``light_client.history_trust`` unchanged: a fresh log
        opens with ``active``, ``at`` strictly ascends, a revocation must name
        the currently active key and an identical tail is an idempotent
        no-op. A new record returns 201; the idempotent replay returns 200. The
        log write, the ``update`` history_access event and the snapshot land
        together under one shared lock; a snapshot failure restores the log's
        original bytes and drops the in-memory event, answering 500/io.
        """
        if not self.history_enabled:
            return 404, {"ok": False, "error": "not found"}
        from . import light_client

        if not isinstance(payload, dict) or set(payload) != set(
            self.HISTORY_TRUST_UPDATE_FIELDS
        ):
            return 400, {"ok": False, "error": "input"}
        at_value = payload["at"]
        if (
            isinstance(at_value, bool)
            or not isinstance(at_value, int)
            or at_value < 1
        ):
            return 400, {"ok": False, "error": "input"}

        with self.store.lock:
            with light_client._checkpoint_lock(
                self.history_path
            ), light_client._checkpoint_lock(self.history_trust_path):
                try:
                    # Pre-flight: the checkpoint pair (and the trust log)
                    # must strictly load before the trust log is touched, so
                    # a corrupt file pair is reported (409/state or 500/io)
                    # without mutating anything.
                    self._history_heads()
                    # Record the durable tail size before the append so a
                    # byte-level change distinguishes 201 (fresh log /
                    # appended record) from the 200 idempotent no-op.
                    before = light_client.history_trust(self.history_trust_path)
                    if before.get("ok") is False:
                        # A missing log starts a fresh one below; a corrupt or
                        # otherwise unreadable log is a state conflict and must
                        # never be touched.
                        if before.get("error") != "io":
                            return self._history_failure(before)
                        before_count = None
                    else:
                        before_count = len(before["records"])
                    # Snapshot the log bytes: a later snapshot failure must put
                    # the already-committed external write back byte-for-byte.
                    original_trust = light_client._read_bytes_or_none(
                        self.history_trust_path
                    )
                    result = light_client.history_trust(
                        self.history_trust_path,
                        payload["root_seed"],
                        at_value,
                        payload["key"],
                        payload["status"],
                    )
                    if result.get("ok") is False:
                        return self._history_failure(result)
                    created = (
                        before_count is None
                        or len(result["records"]) > before_count
                    )
                    trust_head, history_head = self._history_heads()
                    self._append_history_access_and_save(
                        "update",
                        trust_head,
                        history_head,
                        restore=[(self.history_trust_path, original_trust)],
                    )
                except self._HistoryFileError as failure:
                    return self._history_failure(
                        {"error": failure.category}
                    )
                except OSError:
                    return 500, {"ok": False, "error": "io"}
                except Exception:
                    # Defensive HTTP boundary: any unforeseen failure is an
                    # internal error; any external-file compensation already
                    # ran inside _append_history_access_and_save.
                    return 500, {"ok": False, "error": "io"}
                return (201 if created else 200), result

    def export_history_page(self, payload: object) -> tuple[int, dict]:
        """POST /v1/history/export — export one signed checkpoint-history page.

        The body must be a JSON object whose keys are a subset of exactly
        ``key, after, limit`` (``key`` required; ``after``/``limit`` optional
        with the library defaults). The export reuses
        ``light_client.export_history`` unchanged — page key order,
        cursor/pagination, strict reload and the Ed25519 signature — and is
        audited with an ``export`` history_access event before responding.
        Failures map input 400 / auth 403 / state 409 / io 500.
        """
        if not self.history_enabled:
            return 404, {"ok": False, "error": "not found"}
        from . import light_client

        if not isinstance(payload, dict):
            return 400, {"ok": False, "error": "input"}
        if set(payload) - set(self.HISTORY_EXPORT_FIELDS):
            return 400, {"ok": False, "error": "input"}
        if "key" not in payload:
            return 400, {"ok": False, "error": "input"}
        after = payload.get("after")
        if after is not None and (
            isinstance(after, bool) or not isinstance(after, int) or after < 0
        ):
            return 400, {"ok": False, "error": "input"}
        limit = payload.get("limit")
        if limit is not None and (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not (
                light_client.HISTORY_EXPORT_MIN_LIMIT
                <= limit
                <= light_client.HISTORY_EXPORT_MAX_LIMIT
            )
        ):
            return 400, {"ok": False, "error": "input"}

        with self.store.lock:
            with light_client._checkpoint_lock(
                self.history_path
            ), light_client._checkpoint_lock(self.history_trust_path):
                try:
                    result = light_client.export_history(
                        self.history_path,
                        payload["key"],
                        after=after,
                        limit=(
                            limit
                            if limit is not None
                            else light_client.HISTORY_EXPORT_DEFAULT_LIMIT
                        ),
                    )
                    if result.get("ok") is False:
                        return self._history_failure(result)
                    trust_head, history_head = self._history_heads()
                    self._append_history_access_and_save(
                        "export", trust_head, history_head
                    )
                except self._HistoryFileError as failure:
                    return self._history_failure(
                        {"error": failure.category}
                    )
                except OSError:
                    return 500, {"ok": False, "error": "io"}
                except Exception:
                    # Defensive HTTP boundary: any unforeseen failure is an
                    # internal error; any external-file compensation already
                    # ran inside _append_history_access_and_save.
                    return 500, {"ok": False, "error": "io"}
                return 200, result
