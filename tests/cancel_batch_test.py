"""Tests for atomic batch cancellation of mempool transactions.

Covers POST /v1/transactions/cancel/batch end to end at the service layer
and over HTTP:

* the strict envelope (exactly {"cancellations": [...]} with 1-200 items)
  and per-item shape (exactly {"tx_id", "signature"}, 64/128 lowercase
  hex), with envelope defects answering 400 {"error": "input"} without an
  index and item/duplicate defects carrying the first offending zero-based
  index (a duplicate names its later occurrence);
* the phased business checks: per-item lookup (canonical chain and mempool
  only), sender signature and packing state in input order, then the
  per-sender contiguous-suffix nonce rule over all reserved nonces
  (mempool plus pending tip) — 404 not_found, 403 unauthorized, 409
  not_cancellable and 409 sequence_conflict, each naming the first
  offending item and each leaving the whole batch untouched;
* 200 {"items", "total"} with the items in input order, releasing spend
  and nonce reservations (next_sequence steps back per sender by its
  cancelled sequenced count), leaving other mempool transactions (and
  their order) and confirmed balances untouched;
* one transaction_cancelled event per item appended in input order and
  persisted in the same single atomic write (generation advances once),
  with persistence-failure rollback of the mempool, the events and the
  generation and a 500 {"error": "persistence failed"} answer;
* uniform Idempotency-Key behavior (replay, conflict, no key occupied on
  failure), keyless retries judged against the current state, and restart
  recovery of the batch and its idempotency records;
* cancelled transactions reading as not found, immediate resubmission and
  nonce reuse, and the single-cancel endpoint keeping its behavior.

Run: python3 tests/cancel_batch_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import audit, crypto
from ledger.server import build_handler
from ledger.service import (
    EVENT_TRANSACTION_CANCELLED,
    EVENT_TRANSACTION_SUBMITTED,
    LedgerService,
)
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def legacy_payload(key, sender, to, amount) -> dict:
    message = crypto.canonical_message(sender, to, amount)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(message).hex(),
    }


def sequenced_payload(key, sender, to, amount, nonce) -> dict:
    message = crypto.sequenced_message(sender, to, amount, nonce)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(message).hex(),
    }


def cancel_item(key, tx_id) -> dict:
    return {
        "tx_id": tx_id,
        "signature": key.sign(crypto.cancel_message(tx_id)).hex(),
    }


class CancelBatchServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        self.store = self.svc.store

    def reopen(self) -> LedgerService:
        return LedgerService(LedgerStore(self.state_path), initial_balance=1000)

    def submit_legacy(self, amount: int = 10, key=None, sender=None, to=None) -> str:
        key = key or self.ka
        sender = sender or self.A
        status, body = self.svc.submit_transaction(
            legacy_payload(key, sender, to or self.B, amount)
        )
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def submit_sequenced(self, nonce: int, amount: int = 10, key=None, sender=None) -> str:
        key = key or self.ka
        sender = sender or self.A
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(key, sender, self.B, amount, nonce)
        )
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def batch(self, items):
        return self.svc.cancel_transactions_batch({"cancellations": items})

    def batch_of(self, *tx_ids, keys=None) -> tuple[int, dict]:
        keys = keys or [self.ka] * len(tx_ids)
        return self.batch([cancel_item(k, t) for k, t in zip(keys, tx_ids)])

    # -- envelope validation --------------------------------------------------

    def test_envelope_defects_are_400_without_index(self) -> None:
        tx_id = self.submit_legacy()
        good = cancel_item(self.ka, tx_id)
        too_many = [
            {"tx_id": f"{i:064x}", "signature": good["signature"]}
            for i in range(201)
        ]
        for bad in (
            None,
            [],
            "cancellations",
            {},
            {"cancellations": None},
            {"cancellations": {}},
            {"cancellations": "x"},
            {"cancellations": []},
            {"cancellations": [good], "extra": 1},
            {"items": [good]},
            {"cancellations": too_many},
        ):
            status, result = self.svc.cancel_transactions_batch(bad)
            self.assertEqual((status, result), (400, {"error": "input"}), bad)
        self.assertIn(tx_id, self.store.pending)
        self.assertEqual(len(self.store.audit_events), 1)  # only the submit

    def test_exactly_200_items_accepted(self) -> None:
        ids = [
            self.submit_legacy(amount=1, to=f"rcp{i}") for i in range(200)
        ]
        status, result = self.batch_of(*ids)
        self.assertEqual(status, 200)
        self.assertEqual(result["total"], 200)
        self.assertEqual(self.store.pending, {})

    # -- item format / duplicates ----------------------------------------------

    def test_item_format_defects_carry_index(self) -> None:
        first = self.submit_legacy()
        second = self.submit_legacy(amount=11)
        good0 = cancel_item(self.ka, first)
        good1 = cancel_item(self.ka, second)
        bad_items = (
            None,
            [],
            "x",
            {},
            {"tx_id": second},
            {"signature": good1["signature"]},
            {"tx_id": second, "signature": good1["signature"], "x": 1},
            {"tx_id": None, "signature": good1["signature"]},
            {"tx_id": "zz" * 32, "signature": good1["signature"]},
            {"tx_id": "AB" * 32, "signature": good1["signature"]},
            {"tx_id": "a" * 63, "signature": good1["signature"]},
            {"tx_id": second, "signature": None},
            {"tx_id": second, "signature": "zz" * 64},
            {"tx_id": second, "signature": "AB" * 64},
            {"tx_id": second, "signature": "a" * 127},
        )
        for bad in bad_items:
            status, result = self.batch([good0, bad])
            self.assertEqual(
                (status, result), (400, {"error": "input", "index": 1}), bad
            )
        # The first item is checked first: a defect at index 0 wins.
        status, result = self.batch([bad_items[0], good0])
        self.assertEqual((status, result), (400, {"error": "input", "index": 0}))
        self.assertIn(first, self.store.pending)
        self.assertIn(second, self.store.pending)
        self.assertEqual(len(self.store.audit_events), 2)  # only the submits

    def test_duplicate_tx_id_names_later_occurrence(self) -> None:
        first = self.submit_legacy()
        second = self.submit_legacy(amount=11)
        item0 = cancel_item(self.ka, first)
        item1 = cancel_item(self.ka, second)
        # Adjacent duplicate.
        status, result = self.batch([item0, item1, dict(item1)])
        self.assertEqual((status, result), (400, {"error": "input", "index": 2}))
        # Non-adjacent duplicate of the first item.
        status, result = self.batch([item0, item1, dict(item0)])
        self.assertEqual((status, result), (400, {"error": "input", "index": 2}))
        # A duplicate pair earlier in the batch beats a later format defect.
        status, result = self.batch(
            [item0, dict(item0), {"tx_id": "zz" * 32, "signature": "ab" * 64}]
        )
        self.assertEqual((status, result), (400, {"error": "input", "index": 1}))
        self.assertIn(first, self.store.pending)
        self.assertIn(second, self.store.pending)

    # -- per-item business checks ----------------------------------------------

    def test_unknown_id_is_404_with_index(self) -> None:
        known = self.submit_legacy()
        unknown = "cd" * 32
        status, result = self.batch_of(unknown)
        self.assertEqual((status, result), (404, {"error": "not_found", "index": 0}))
        # The first unknown item in input order names the index.
        status, result = self.batch_of(known, unknown, "ef" * 32)
        self.assertEqual((status, result), (404, {"error": "not_found", "index": 1}))
        self.assertIn(known, self.store.pending)
        self.assertEqual(len(self.store.audit_events), 1)

    def test_bad_signature_is_403_with_index(self) -> None:
        first = self.submit_legacy()
        second = self.submit_legacy(amount=11)
        items = [
            cancel_item(self.ka, first),
            cancel_item(self.kb, second),  # not the sender
        ]
        status, result = self.batch(items)
        self.assertEqual((status, result), (403, {"error": "unauthorized", "index": 1}))
        # Signed by the sender but over a different tx_id.
        items = [
            cancel_item(self.ka, first),
            {"tx_id": second, "signature": cancel_item(self.ka, "cd" * 32)["signature"]},
        ]
        status, result = self.batch(items)
        self.assertEqual((status, result), (403, {"error": "unauthorized", "index": 1}))
        self.assertIn(first, self.store.pending)
        self.assertIn(second, self.store.pending)
        self.assertEqual(len(self.store.audit_events), 2)

    def test_packed_and_confirmed_are_409_with_index(self) -> None:
        packed = self.submit_legacy()
        block = self.svc.mine_block()[1]
        # Submitted after the mine, this one stays queued in the mempool.
        queued = self.submit_legacy(amount=11)
        items = [cancel_item(self.ka, queued), cancel_item(self.ka, packed)]
        status, result = self.batch(items)
        self.assertEqual(
            (status, result), (409, {"error": "not_cancellable", "index": 1})
        )
        self.svc.confirm_block(block["height"])
        status, result = self.batch(items)
        self.assertEqual(
            (status, result), (409, {"error": "not_cancellable", "index": 1})
        )
        self.assertIn(queued, self.store.pending)
        kinds = [event["kind"] for event in self.store.audit_events]
        self.assertEqual(
            kinds,
            [
                EVENT_TRANSACTION_SUBMITTED,
                "block_mined",
                EVENT_TRANSACTION_SUBMITTED,
                "block_confirmed",
            ],
        )

    def test_lookup_never_searches_candidate_forks(self) -> None:
        from ledger.models import Block, Transaction

        fork_tx = legacy_payload(self.ka, self.A, self.B, 10)
        tx_id = crypto.compute_tx_id(crypto.canonical_message(self.A, self.B, 10))
        genesis = self.store.chain[0]
        block = Block.create(
            1, genesis.block_hash, [Transaction.from_dict(fork_tx)]
        )
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), block.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        status, result = self.batch_of(tx_id)
        self.assertEqual((status, result), (404, {"error": "not_found", "index": 0}))

    # -- suffix rule -------------------------------------------------------------

    def test_suffix_rule_full_and_partial(self) -> None:
        ids = [self.submit_sequenced(nonce) for nonce in range(3)]
        # Cancelling the top two (in reverse order) is a valid suffix.
        status, result = self.batch_of(ids[2], ids[1])
        self.assertEqual(status, 200)
        self.assertEqual(
            result,
            {
                "items": [
                    {"tx_id": ids[2], "status": "cancelled"},
                    {"tx_id": ids[1], "status": "cancelled"},
                ],
                "total": 2,
            },
        )
        view = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(view["next_sequence"], 1)
        self.assertEqual(
            view["pending_sequences"], [{"nonce": 0, "tx_id": ids[0]}]
        )

    def test_suffix_violation_names_earliest_account_item(self) -> None:
        ids = [self.submit_sequenced(nonce) for nonce in range(3)]
        legacy = self.submit_legacy()
        # {0, 2} is not a contiguous suffix of reserved {0, 1, 2}; the
        # sender's earliest sequenced batch item (index 1) is named.
        items = [
            cancel_item(self.ka, legacy),
            cancel_item(self.ka, ids[0]),
            cancel_item(self.ka, ids[2]),
        ]
        status, result = self.batch(items)
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 1})
        )
        # {2} alone is a valid suffix but {1} alone is not.
        status, result = self.batch_of(ids[1])
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 0})
        )
        # Nothing moved: every transaction is still queued and no cancel
        # event was appended.
        for tx_id in (*ids, legacy):
            self.assertIn(tx_id, self.store.pending)
        self.assertEqual(
            [event["kind"] for event in self.store.audit_events],
            [EVENT_TRANSACTION_SUBMITTED] * 4,
        )
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 3
        )

    def test_suffix_rule_is_per_sender(self) -> None:
        a_ids = [self.submit_sequenced(nonce) for nonce in range(2)]
        b_ids = [
            self.submit_sequenced(nonce, key=self.kb, sender=self.B)
            for nonce in range(2)
        ]
        # A cancels its top nonce, B its bottom one: B violates.
        items = [
            cancel_item(self.ka, a_ids[1]),
            cancel_item(self.kb, b_ids[0]),
        ]
        status, result = self.batch(items)
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 1})
        )
        # Both tops together are fine, in any order.
        status, result = self.batch(
            [cancel_item(self.kb, b_ids[1]), cancel_item(self.ka, a_ids[1])]
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 1
        )
        self.assertEqual(
            self.svc.get_account_sequence(self.B)[1]["next_sequence"], 1
        )

    def test_suffix_reservations_include_pending_tip(self) -> None:
        ids = [self.submit_sequenced(nonce) for nonce in range(2)]
        block = self.svc.mine_block()[1]  # packs nonces 0 and 1
        top = self.submit_sequenced(2)
        # The mempool top nonce alone is still a suffix of the reserved
        # set {0, 1, 2} even though 0 and 1 sit in the pending tip.
        status, _ = self.batch_of(top)
        self.assertEqual(status, 200)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 2
        )
        # nonce 1 is now the highest reserved nonce but lives in the
        # pending block, so it is not cancellable.
        status, result = self.batch_of(ids[1])
        self.assertEqual(
            (status, result), (409, {"error": "not_cancellable", "index": 0})
        )
        # After rollback nonce 1 is the highest reserved nonce again and
        # the batch can take it.
        self.svc.rollback_block(block["height"])
        status, _ = self.batch_of(ids[1])
        self.assertEqual(status, 200)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 1
        )

    # -- success semantics -------------------------------------------------------

    def test_success_mixed_batch_releases_everything(self) -> None:
        legacy_a = self.submit_legacy(amount=40)
        seq_a = [self.submit_sequenced(nonce, amount=10) for nonce in range(2)]
        legacy_b = self.submit_legacy(amount=5, key=self.kb, sender=self.B)
        seq_b = self.submit_sequenced(0, amount=7, key=self.kb, sender=self.B)
        other = self.submit_legacy(amount=3, key=self.kb, sender=self.B)
        self.assertEqual(self.svc.available_balance(self.A), 1000 - 40 - 20)
        self.assertEqual(self.svc.available_balance(self.B), 1000 - 5 - 7 - 3)
        events_before = len(self.store.audit_events)
        generation_before = self.store.generation

        items = [
            cancel_item(self.ka, seq_a[1]),
            cancel_item(self.kb, legacy_b),
            cancel_item(self.ka, legacy_a),
            cancel_item(self.kb, seq_b),
            cancel_item(self.ka, seq_a[0]),
        ]
        status, result = self.batch(items)
        self.assertEqual(status, 200)
        self.assertEqual(
            result,
            {
                "items": [
                    {"tx_id": seq_a[1], "status": "cancelled"},
                    {"tx_id": legacy_b, "status": "cancelled"},
                    {"tx_id": legacy_a, "status": "cancelled"},
                    {"tx_id": seq_b, "status": "cancelled"},
                    {"tx_id": seq_a[0], "status": "cancelled"},
                ],
                "total": 5,
            },
        )
        # Every cancelled id is gone; the untouched transaction keeps its
        # mempool slot (and is the only one left).
        self.assertEqual(list(self.store.pending), [other])
        # Spend reservations are released; confirmed balances never moved.
        self.assertEqual(self.svc.available_balance(self.A), 1000 - 0)
        self.assertEqual(self.svc.available_balance(self.B), 1000 - 3)
        # Nonce reservations rolled back per sender.
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 0
        )
        self.assertEqual(
            self.svc.get_account_sequence(self.B)[1]["next_sequence"], 0
        )
        # One transaction_cancelled event per item, appended in input
        # order, and the generation advanced exactly once.
        events = self.store.audit_events[events_before:]
        self.assertEqual(
            [event["kind"] for event in events],
            [EVENT_TRANSACTION_CANCELLED] * 5,
        )
        self.assertEqual(
            [event["tx_id"] for event in events],
            [seq_a[1], legacy_b, legacy_a, seq_b, seq_a[0]],
        )
        self.assertEqual(events[0]["nonce"], 1)
        self.assertNotIn("nonce", events[1])
        self.assertEqual(events[3]["nonce"], 0)
        self.assertEqual(events[4]["nonce"], 0)
        self.assertEqual(
            [event["signature"] for event in events],
            [item["signature"] for item in items],
        )
        self.assertEqual(self.store.generation, generation_before + 1)
        audit.validate_event_chain(self.store.audit_events)
        audit.validate_checkpoint(
            self.store.audit_checkpoint, self.store.audit_events
        )

    def test_receipts_read_not_found_after_batch_cancel(self) -> None:
        first = self.submit_legacy()
        second = self.submit_legacy(amount=11)
        status, _ = self.batch_of(first, second)
        self.assertEqual(status, 200)
        for tx_id in (first, second):
            status, _ = self.svc.get_transaction(tx_id)
            self.assertEqual(status, 404)
        status, batch = self.svc.get_transaction_receipts(
            {"tx_ids": [first, second]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            batch["items"],
            [
                {"tx_id": first, "receipt": None, "error": "not_found"},
                {"tx_id": second, "receipt": None, "error": "not_found"},
            ],
        )

    def test_resubmission_and_nonce_reuse_after_batch_cancel(self) -> None:
        payload = legacy_payload(self.ka, self.A, self.B, 10)
        status, body = self.svc.submit_transaction(payload)
        self.assertEqual(status, 202)
        legacy_id = body["tx_id"]
        seq_id = self.submit_sequenced(0)
        status, _ = self.batch_of(legacy_id, seq_id)
        self.assertEqual(status, 200)
        # The same legacy transaction can be resubmitted and the freed
        # nonce reused immediately.
        status, body = self.svc.submit_transaction(payload)
        self.assertEqual((status, body), (202, {"tx_id": legacy_id}))
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 5, 0)
        )
        self.assertEqual((status, body), (202, {"tx_id": body["tx_id"], "nonce": 0}))
        kinds = [event["kind"] for event in self.store.audit_events]
        self.assertEqual(
            kinds,
            [
                EVENT_TRANSACTION_SUBMITTED,
                EVENT_TRANSACTION_SUBMITTED,
                EVENT_TRANSACTION_CANCELLED,
                EVENT_TRANSACTION_CANCELLED,
                EVENT_TRANSACTION_SUBMITTED,
                EVENT_TRANSACTION_SUBMITTED,
            ],
        )

    def test_keyless_retry_is_judged_against_current_state(self) -> None:
        first = self.submit_legacy()
        second = self.submit_legacy(amount=11)
        items = [cancel_item(self.ka, first), cancel_item(self.ka, second)]
        status, _ = self.batch(items)
        self.assertEqual(status, 200)
        # A keyless retry of the same batch finds the first item gone.
        status, result = self.batch(items)
        self.assertEqual((status, result), (404, {"error": "not_found", "index": 0}))

    # -- atomicity / idempotency ----------------------------------------------

    def test_save_failure_rolls_everything_back(self) -> None:
        first = self.submit_legacy()
        second = self.submit_sequenced(0)
        events_before = len(self.store.audit_events)
        pending_before = dict(self.store.pending)
        generation_before = self.store.generation

        original = self.store.save
        state = {"failed": False}

        def failing_save() -> None:
            if not state["failed"]:
                state["failed"] = True
                raise OSError("simulated disk failure")
            return original()

        self.store.save = failing_save
        try:
            status, result = self.batch_of(first, second)
        finally:
            self.store.save = original
        self.assertEqual((status, result), (500, {"error": "persistence failed"}))
        # Mempool content and order, the audit chain and the generation
        # are exactly as before the request.
        self.assertEqual(dict(self.store.pending), pending_before)
        self.assertEqual(list(self.store.pending), list(pending_before))
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)
        audit.validate_event_chain(self.store.audit_events)
        # The durable file is still recoverable and both txs are queued.
        reopened = self.reopen()
        self.assertIn(first, reopened.store.pending)
        self.assertIn(second, reopened.store.pending)

    def test_idempotent_replay_and_conflict(self) -> None:
        first = self.submit_legacy()
        second = self.submit_legacy(amount=11)
        body = {
            "cancellations": [
                cancel_item(self.ka, first),
                cancel_item(self.ka, second),
            ]
        }
        target = "/v1/transactions/cancel/batch"

        def action():
            return self.svc.cancel_transactions_batch(body)

        status, result, replayed, _text = self.svc.execute_idempotent(
            "POST", target, "batch-key", body, action, sort_keys=False
        )
        self.assertEqual((status, replayed), (200, False))
        self.assertEqual(result["total"], 2)
        events = len(self.store.audit_events)
        # Replay: same key, same request -> cached response, no new event.
        status, result2, replayed, _text = self.svc.execute_idempotent(
            "POST", target, "batch-key", body, action, sort_keys=False
        )
        self.assertEqual((status, replayed), (200, True))
        self.assertEqual(result2, result)
        self.assertEqual(len(self.store.audit_events), events)
        # Same key, different body -> conflict, no state change.
        other = {"cancellations": [cancel_item(self.ka, first)]}
        status, _r, replayed, _t = self.svc.execute_idempotent(
            "POST", target, "batch-key", other, action, sort_keys=False
        )
        self.assertEqual((status, replayed), (409, False))
        self.assertEqual(len(self.store.audit_events), events)
        # The replay survives a restart.
        reopened = self.reopen()
        status, result3, replayed, _text = reopened.execute_idempotent(
            "POST", target, "batch-key", body, action, sort_keys=False
        )
        self.assertEqual((status, replayed), (200, True))
        self.assertEqual(result3, result)

    def test_idempotent_failure_occupies_no_key(self) -> None:
        tx_id = self.submit_legacy()
        body = {"cancellations": [cancel_item(self.kb, tx_id)]}  # wrong signer
        target = "/v1/transactions/cancel/batch"
        status, _r, _p, _t = self.svc.execute_idempotent(
            "POST",
            target,
            "batch-fail",
            body,
            lambda: self.svc.cancel_transactions_batch(body),
            sort_keys=False,
        )
        self.assertEqual(status, 403)
        self.assertNotIn("batch-fail", self.store.idempotency)
        self.assertEqual(len(self.store.audit_events), 1)

    def test_idempotent_persistence_failure_is_500(self) -> None:
        first = self.submit_legacy()
        second = self.submit_legacy(amount=11)
        body = {
            "cancellations": [
                cancel_item(self.ka, first),
                cancel_item(self.ka, second),
            ]
        }
        target = "/v1/transactions/cancel/batch"
        pending_before = dict(self.store.pending)
        events_before = len(self.store.audit_events)
        generation_before = self.store.generation

        original = self.store.save
        state = {"failed": False}

        def failing_save() -> None:
            if not state["failed"]:
                state["failed"] = True
                raise OSError("simulated disk failure")
            return original()

        self.store.save = failing_save
        try:
            status, result, replayed, _t = self.svc.execute_idempotent(
                "POST",
                target,
                "batch-500",
                body,
                lambda: self.svc.cancel_transactions_batch(body),
                sort_keys=False,
            )
        finally:
            self.store.save = original
        self.assertEqual((status, replayed), (500, False))
        self.assertEqual(result, {"error": "persistence failed"})
        self.assertNotIn("batch-500", self.store.idempotency)
        self.assertEqual(dict(self.store.pending), pending_before)
        self.assertEqual(list(self.store.pending), list(pending_before))
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)

    # -- restart / recovery -----------------------------------------------------

    def test_restart_preserves_batch_cancel(self) -> None:
        first = self.submit_legacy()
        second = self.submit_sequenced(0)
        third = self.submit_legacy(amount=11)
        status, _ = self.batch_of(first, second)
        self.assertEqual(status, 200)
        events_before = [dict(event) for event in self.store.audit_events]
        reopened = self.reopen()
        self.assertEqual(list(reopened.store.pending), [third])
        self.assertEqual(
            [dict(event) for event in reopened.store.audit_events],
            events_before,
        )
        self.assertEqual(
            reopened.get_account_sequence(self.A)[1]["next_sequence"], 0
        )
        for tx_id in (first, second):
            status, _ = reopened.get_transaction(tx_id)
            self.assertEqual(status, 404)

    def test_single_cancel_unaffected_by_batch_feature(self) -> None:
        tx_id = self.submit_legacy()
        status, result = self.svc.cancel_transaction(
            tx_id, {"signature": cancel_item(self.ka, tx_id)["signature"]}
        )
        self.assertEqual((status, result), (200, {"tx_id": tx_id, "status": "cancelled"}))


class CancelBatchHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path), initial_balance=1000
        )
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.svc)
        )
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None, raw=None):
        data = raw if raw is not None else (
            json.dumps(body).encode("utf-8") if body is not None else None
        )
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                payload = resp.read()
                return resp.status, json.loads(payload), dict(resp.headers), payload
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            return exc.code, json.loads(payload), dict(exc.headers), payload

    def test_http_batch_cancel_flow_and_idempotency(self) -> None:
        key, pub = keypair()
        ids = []
        for amount in (10, 20):
            payload = legacy_payload(key, pub, self.__class__.__name__, amount)
            status, body, _h, _raw = self.request("POST", "/v1/transactions", payload)
            self.assertEqual(status, 202)
            ids.append(body["tx_id"])
        signed = {"cancellations": [cancel_item(key, tx_id) for tx_id in ids]}
        target = "/v1/transactions/cancel/batch"

        # Query parameters are rejected before anything else.
        status, body, _h, _raw = self.request("POST", target + "?x=1", signed)
        self.assertEqual((status, body), (400, {"error": "input"}))
        # Unparseable JSON and non-UTF-8 bodies are 400 input.
        status, body, _h, _raw = self.request("POST", target, raw=b"{not json")
        self.assertEqual((status, body), (400, {"error": "input"}))
        status, body, _h, _raw = self.request("POST", target, raw=b"\xff\xfe")
        self.assertEqual((status, body), (400, {"error": "input"}))
        # A top-level shape defect is 400 input without an index.
        status, body, _h, _raw = self.request("POST", target, {"cancellations": []})
        self.assertEqual((status, body), (400, {"error": "input"}))
        # First success echoes the idempotency headers and keeps the
        # contract key order items,total.
        status, body, headers, raw_first = self.request(
            "POST", target, signed, {"Idempotency-Key": "batch-http-1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "items": [
                    {"tx_id": ids[0], "status": "cancelled"},
                    {"tx_id": ids[1], "status": "cancelled"},
                ],
                "total": 2,
            },
        )
        self.assertLess(raw_first.index(b'"items"'), raw_first.index(b'"total"'))
        self.assertEqual(headers.get("Idempotency-Key"), "batch-http-1")
        self.assertEqual(headers.get("Idempotency-Replayed"), "false")
        # Replay is byte-identical and flagged.
        status, body2, headers, raw_replay = self.request(
            "POST", target, signed, {"Idempotency-Key": "batch-http-1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Idempotency-Replayed"), "true")
        self.assertEqual(raw_replay, raw_first)
        self.assertEqual(body2, body)
        # Same key, different body -> 409.
        status, body, _h, _raw = self.request(
            "POST",
            target,
            {"cancellations": [cancel_item(key, ids[0])]},
            {"Idempotency-Key": "batch-http-1"},
        )
        self.assertEqual(
            (status, body), (409, {"error": "idempotency key conflict"})
        )
        # Without the key the cancelled transactions are simply gone; a
        # bare trailing "?" carries no parameter and is accepted.
        status, body, _h, _raw = self.request("POST", target + "?", signed)
        self.assertEqual((status, body), (404, {"error": "not_found", "index": 0}))
        # The single receipts read not found as well.
        for tx_id in ids:
            status, _body, _h, _raw = self.request(
                "GET", f"/v1/transactions/{tx_id}"
            )
            self.assertEqual(status, 404)

    def test_http_per_item_errors_carry_index(self) -> None:
        key, pub = keypair()
        payload = legacy_payload(key, pub, "http-index", 10)
        status, body, _h, _raw = self.request("POST", "/v1/transactions", payload)
        self.assertEqual(status, 202)
        tx_id = body["tx_id"]
        # Unknown second item -> 404 with index.
        status, body, _h, _raw = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            {
                "cancellations": [
                    cancel_item(key, tx_id),
                    cancel_item(key, "cd" * 32),
                ]
            },
        )
        self.assertEqual(
            (status, body), (404, {"error": "not_found", "index": 1})
        )
        # The failed batch changed nothing: the transaction is still
        # queued and a corrected batch succeeds.
        status, body, _h, _raw = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            {"cancellations": [cancel_item(key, tx_id)]},
        )
        self.assertEqual(
            (status, body),
            (200, {"items": [{"status": "cancelled", "tx_id": tx_id}], "total": 1}),
        )


if __name__ == "__main__":
    unittest.main()
