"""Tests for atomic sequenced-batch transfers.

Covers POST /v1/transactions/sequenced/batch at the service layer and over
HTTP and the ``send-sequenced-batch`` CLI command:

* strict {"transactions": [...]} envelope and per-item field/type/signature
  validation with {"error": "input", "index": I};
* 202 first success with ordered items,total and one transaction_submitted
  event per new tx, all in one atomic write; failure of any check changes no
  state;
* per-sender consecutive nonces interleaved across senders: in-batch
  duplicates/gaps are 400, start misalignment and occupied-slot conflicts
  are 409 {"error": "sequence_conflict", "index": I, "next_sequence": N};
* per-sender batch-total balance checks that never count unconfirmed income;
* whole-batch replay returns 200 with each item's location; partial overlap
  is 409 transaction_exists;
* batches participate in packing, confirmation, rollback, restart recovery;
* Idempotency-Key serialization and keyless persistence-failure semantics;
* the CLI reads --file / stdin and never calls the server on local errors.

Run: python3 tests/sequenced_batch_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
import concurrent.futures
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import build_parser as build_cli_parser
from ledger.server import build_handler
from ledger.service import EVENT_TRANSACTION_SUBMITTED, LedgerService
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def item(key, sender, to, amount, nonce) -> dict:
    message = crypto.sequenced_message(sender, to, amount, nonce)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(message).hex(),
    }


def tx_id_of(payload: dict) -> str:
    message = crypto.sequenced_message(
        payload["from"], payload["to"], payload["amount"], payload["nonce"]
    )
    return crypto.compute_tx_id(message)


class BatchServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(self.state_path), initial_balance=100
        )

    def batch(self, items, key=None):
        if key is None:
            return self.svc.submit_sequenced_batch({"transactions": items})
        return self.svc.execute_idempotent(
            "POST",
            "/v1/transactions/sequenced/batch",
            key,
            {"transactions": items},
            lambda: self.svc.submit_sequenced_batch({"transactions": items}),
            sort_keys=False,
        )[:2]

    # -- envelope and item validation -------------------------------------

    def test_envelope_defects_are_input_without_index(self) -> None:
        cases = [
            None,
            [],
            "x",
            {},
            {"transactions": []},
            {"transactions": [item(self.ka, self.A, self.B, 1, 0)], "x": 1},
            {"items": []},
        ]
        for payload in cases:
            status, body = self.svc.submit_sequenced_batch(payload)
            self.assertEqual((status, body), (400, {"error": "input"}), payload)

    def test_non_list_transactions_is_input(self) -> None:
        for value in (None, {}, "x", 5, True, item(self.ka, self.A, self.B, 1, 0)):
            status, body = self.svc.submit_sequenced_batch({"transactions": value})
            self.assertEqual((status, body), (400, {"error": "input"}), value)

    def test_item_field_defects_carry_index(self) -> None:
        good = item(self.ka, self.A, self.B, 1, 0)
        bad_items = [
            {},
            {**good, "x": 1},
            {"to": "z", "amount": 1, "nonce": 0, "signature": "s"},
            {**good, "from": ""},
            {**good, "from": 7},
            {**good, "to": ""},
            {**good, "amount": 0},
            {**good, "amount": -1},
            {**good, "amount": 1.5},
            {**good, "amount": True},
            {**good, "nonce": -1},
            {**good, "nonce": 1.0},
            {**good, "nonce": False},
            {**good, "signature": ""},
        ]
        for index in (0, 2):
            for bad in bad_items:
                payload = [
                    item(self.ka, self.A, self.B, 1, 0),
                    item(self.ka, self.A, self.B, 1, 1),
                    item(self.ka, self.A, self.B, 1, 2),
                ]
                payload[index] = bad
                status, body = self.svc.submit_sequenced_batch(
                    {"transactions": payload}
                )
                self.assertEqual(status, 400, (bad, body))
                self.assertEqual(body["error"], "input")
                self.assertEqual(body["index"], index)

    def test_bad_signature_carries_index(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.ka, self.A, self.B, 1, 1),
        ]
        payload[1]["signature"] = "00" * 64
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))

    def test_signed_with_other_key_is_input(self) -> None:
        forged = item(self.kb, self.A, self.B, 1, 0)
        status, body = self.svc.submit_sequenced_batch({"transactions": [forged]})
        self.assertEqual(status, 400)
        self.assertEqual(body["index"], 0)

    # -- first success -----------------------------------------------------

    def test_first_success_202_ordered_items_and_events(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.kb, self.B, self.A, 5, 0),
            item(self.ka, self.A, self.C, 7, 1),
        ]
        expected_ids = [tx_id_of(t) for t in payload]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 202)
        self.assertEqual(list(body), ["items", "total"])
        self.assertEqual(body["total"], 3)
        self.assertEqual(
            body["items"],
            [
                {"tx_id": expected_ids[0], "nonce": 0},
                {"tx_id": expected_ids[1], "nonce": 0},
                {"tx_id": expected_ids[2], "nonce": 1},
            ],
        )
        for entry in body["items"]:
            self.assertEqual(list(entry), ["tx_id", "nonce"])
        for txid in expected_ids:
            self.assertIn(txid, self.svc.store.pending)
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual([event["tx_id"] for event in events], expected_ids)
        seq = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(seq["next_sequence"], 2)
        self.assertEqual([p["nonce"] for p in seq["pending_sequences"]], [0, 1])
        seq_b = self.svc.get_account_sequence(self.B)[1]
        self.assertEqual(seq_b["next_sequence"], 1)

    # -- nonce ordering: gaps, duplicates, start misalignment -------------

    def test_in_batch_gap_is_input_400(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.ka, self.A, self.B, 1, 2),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))
        self.assertEqual(self.svc.get_account_sequence(self.A)[1]["next_sequence"], 0)

    def test_in_batch_duplicate_slot_is_input_400(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.ka, self.A, self.C, 2, 0),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))

    def test_identical_duplicate_item_is_input_400(self) -> None:
        first = item(self.ka, self.A, self.B, 1, 0)
        payload = [dict(first), dict(first)]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))

    def test_gap_reported_at_skipping_item_across_interleave(self) -> None:
        # A0 starts A's stream, B0 interleaves, then A2 skips nonce 1: the
        # in-batch gap is reported at index 2 even though another sender sits
        # between A's items.
        payload = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.kb, self.B, self.A, 1, 0),
            item(self.ka, self.A, self.B, 1, 2),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (400, {"error": "input", "index": 2}))

    def test_backwards_nonce_after_start_is_in_batch_gap(self) -> None:
        # A starts with nonce 1 at index 1 and names nonce 0 only at index 2:
        # the later backwards item is an in-batch gap, so the 400 category
        # wins over the earlier misalignment.
        payload = [
            item(self.kb, self.B, self.A, 1, 0),
            item(self.ka, self.A, self.B, 1, 1),
            item(self.ka, self.A, self.B, 1, 0),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (400, {"error": "input", "index": 2}))

    def test_start_misalignment_is_sequence_conflict_409(self) -> None:
        payload = [item(self.ka, self.A, self.B, 1, 5)]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(
            body,
            {"error": "sequence_conflict", "index": 0, "next_sequence": 0},
        )

    def test_start_misalignment_second_batch(self) -> None:
        first = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.ka, self.A, self.B, 1, 1),
        ]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        payload = [
            item(self.ka, self.A, self.B, 1, 3),
            item(self.kb, self.B, self.A, 1, 0),
            item(self.ka, self.A, self.B, 1, 4),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 409)
        self.assertEqual(
            body,
            {"error": "sequence_conflict", "index": 0, "next_sequence": 2},
        )

    def test_different_tx_on_reserved_slot_is_conflict(self) -> None:
        first = [item(self.ka, self.A, self.B, 1, 0)]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        payload = [
            item(self.kb, self.B, self.A, 1, 0),
            item(self.ka, self.A, self.C, 9, 0),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "sequence_conflict")
        self.assertEqual(body["index"], 1)
        self.assertEqual(body["next_sequence"], 1)
        # Nothing from the rejected batch entered the pool.
        self.assertNotIn(tx_id_of(payload[0]), self.svc.store.pending)

    def test_conflict_prefers_400_category_regardless_of_index(self) -> None:
        # A's nonces appear out of order (index 2: internal batch gap, 400);
        # B starts at nonce 9 (index 1: start misalignment, 409). The 400
        # category must win even though the 409 sits at a smaller index.
        payload = [
            item(self.ka, self.A, self.B, 1, 9),
            item(self.kb, self.B, self.A, 1, 0),
            item(self.kb, self.B, self.A, 1, 2),
            item(self.ka, self.A, self.B, 1, 0),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (400, {"error": "input", "index": 2}))

    def test_start_conflict_reports_next_sequence(self) -> None:
        self.assertEqual(
            self.svc.submit_sequenced_transaction(
                item(self.ka, self.A, self.B, 1, 0)
            )[0],
            202,
        )
        payload = [
            item(self.kb, self.B, self.A, 1, 0),
            item(self.ka, self.A, self.B, 1, 4),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(
            body,
            {"error": "sequence_conflict", "index": 1, "next_sequence": 1},
        )

    # -- balance -----------------------------------------------------------

    def test_batch_total_spend_balance_check(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 60, 0),
            item(self.ka, self.A, self.B, 41, 1),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(
            (status, body), (409, {"error": "insufficient_balance", "index": 1})
        )
        self.assertEqual(len(self.svc.store.pending), 0)

    def test_unconfirmed_income_is_not_spendable_in_same_batch(self) -> None:
        # B (endowment 100) receives 80 from A and spends 150 in the same
        # batch: the unconfirmed credit must not count.
        payload = [
            item(self.ka, self.A, self.B, 80, 0),
            item(self.kb, self.B, self.A, 150, 0),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(
            (status, body), (409, {"error": "insufficient_balance", "index": 1})
        )

    def test_unconfirmed_income_not_spendable_from_earlier_unconfirmed_batch(self) -> None:
        first = [item(self.ka, self.A, self.B, 80, 0)]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        payload = [item(self.kb, self.B, self.A, 150, 0)]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "insufficient_balance")

    def test_self_transfer_balance_counts_spend_only(self) -> None:
        payload = [
            item(self.ka, self.A, self.A, 60, 0),
            item(self.ka, self.A, self.B, 50, 1),
        ]
        status, _ = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 409)

    def test_balance_index_counts_only_fresh_spend_on_retry(self) -> None:
        first = [
            item(self.ka, self.A, self.B, 60, 0),
        ]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        # Whole-batch replay of the existing spend plus one more 60: only the
        # fresh 60 counts against the 40 still available.
        payload = [
            item(self.ka, self.A, self.B, 60, 0),
            item(self.ka, self.A, self.B, 60, 1),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "insufficient_balance")
        self.assertEqual(body["index"], 1)

    # -- replay and partial overlap ---------------------------------------

    def test_whole_batch_replay_returns_200_with_locations(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.ka, self.A, self.B, 10, 1),
            item(self.kb, self.B, self.A, 3, 0),
        ]
        ids = [tx_id_of(t) for t in payload]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": payload})[0], 202
        )
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 200)
        self.assertEqual(list(body), ["items", "total"])
        self.assertEqual(body["total"], 3)
        self.assertEqual(
            body["items"],
            [
                {"tx_id": ids[0], "nonce": 0, "location": "pending"},
                {"tx_id": ids[1], "nonce": 1, "location": "pending"},
                {"tx_id": ids[2], "nonce": 0, "location": "pending"},
            ],
        )
        # Replay adds no events and no pool entries.
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(events), 3)

    def test_replay_order_is_request_order(self) -> None:
        first = [
            item(self.kb, self.B, self.A, 2, 0),
            item(self.ka, self.A, self.B, 2, 0),
        ]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        reordered = [first[1], first[0]]
        status, body = self.svc.submit_sequenced_batch(
            {"transactions": reordered}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [entry["tx_id"] for entry in body["items"]],
            [tx_id_of(reordered[0]), tx_id_of(reordered[1])],
        )

    def test_partial_overlap_is_transaction_exists(self) -> None:
        first = [item(self.ka, self.A, self.B, 10, 0)]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.ka, self.A, self.B, 10, 1),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(
            (status, body), (409, {"error": "transaction_exists", "index": 0})
        )
        self.assertEqual(len(self.svc.store.pending), 1)

    def test_partial_overlap_with_fresh_gap_is_sequence_conflict(self) -> None:
        first = [item(self.ka, self.A, self.B, 10, 0)]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        # Existing nonce 0 plus a fresh nonce 2 (skipping live nonce 1):
        # the misalignment beats the partial-overlap check.
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.ka, self.A, self.B, 10, 2),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "sequence_conflict")
        self.assertEqual(body["index"], 1)
        self.assertEqual(body["next_sequence"], 1)
        self.assertEqual(len(self.svc.store.pending), 1)

    def test_partial_overlap_other_sender_rejected(self) -> None:
        first = [item(self.ka, self.A, self.B, 10, 0)]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": first})[0], 202
        )
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.kb, self.B, self.A, 10, 0),
        ]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "transaction_exists")
        self.assertEqual(body["index"], 0)

    def test_replay_locations_after_packing_and_confirmation(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.kb, self.B, self.A, 2, 0),
        ]
        ids = [tx_id_of(t) for t in payload]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": payload})[0], 202
        )
        self.assertEqual(self.svc.mine_block()[0], 201)
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 200)
        self.assertEqual([entry["location"] for entry in body["items"]], ["pending", "pending"])
        self.assertEqual(self.svc.confirm_block(1)[0], 200)
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 200)
        self.assertEqual(
            [entry["location"] for entry in body["items"]], ["confirmed", "confirmed"]
        )
        # Sequence advanced after confirmation; the replayed ids stay valid.
        seq = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(seq["next_sequence"], 1)
        self.assertEqual(seq["confirmed_sequences"][0]["tx_id"], ids[0])

    # -- packing, rollback, recovery ---------------------------------------

    def test_batch_txs_pack_confirm_and_roll_back(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.ka, self.A, self.B, 5, 1),
            item(self.kb, self.B, self.A, 2, 0),
        ]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": payload})[0], 202
        )
        self.assertEqual(self.svc.mine_block()[0], 201)
        self.assertEqual(len(self.svc.store.pending), 0)
        seq = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(seq["next_sequence"], 2)
        self.assertEqual(
            sorted(p["nonce"] for p in seq["pending_sequences"]), [0, 1]
        )
        # Rollback restores dense reservations.
        self.assertEqual(self.svc.rollback_block(1)[0], 200)
        self.assertEqual(len(self.svc.store.pending), 3)
        seq = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(seq["next_sequence"], 2)
        # Re-mine then confirm.
        self.assertEqual(self.svc.mine_block()[0], 201)
        self.assertEqual(self.svc.confirm_block(1)[0], 200)
        seq = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(seq["next_sequence"], 2)
        self.assertEqual(len(seq["confirmed_sequences"]), 2)
        self.assertEqual(seq["pending_sequences"], [])
        # The next batch continues at nonce 2.
        followup = [item(self.ka, self.A, self.B, 1, 2)]
        status, body = self.svc.submit_sequenced_batch({"transactions": followup})
        self.assertEqual(status, 202)
        self.assertEqual(body["items"][0]["nonce"], 2)

    def test_restart_recovers_batch_reservations(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.ka, self.A, self.B, 5, 1),
        ]
        ids = [tx_id_of(t) for t in payload]
        self.assertEqual(
            self.svc.submit_sequenced_batch({"transactions": payload})[0], 202
        )
        reopened = LedgerService(
            LedgerStore(self.state_path), initial_balance=100
        )
        for txid in ids:
            self.assertIn(txid, reopened.store.pending)
        seq = reopened.get_account_sequence(self.A)[1]
        self.assertEqual(seq["next_sequence"], 2)
        # A replay after restart still returns 200 and no new events.
        status, body = reopened.submit_sequenced_batch({"transactions": payload})
        self.assertEqual(status, 200)
        events = [
            event
            for event in reopened.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(events), 2)

    def test_rejected_batch_changes_nothing_on_disk(self) -> None:
        good = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.ka, self.A, self.B, 10, 2),
        ]
        status, _ = self.svc.submit_sequenced_batch({"transactions": good})
        self.assertEqual(status, 400)
        reopened = LedgerService(
            LedgerStore(self.state_path), initial_balance=100
        )
        self.assertEqual(len(reopened.store.pending), 0)
        self.assertEqual(reopened.get_account_sequence(self.A)[1]["next_sequence"], 0)

    # -- idempotency key and persistence failure ---------------------------

    def test_idempotency_key_replays_cached_batch(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.ka, self.A, self.B, 1, 1),
        ]
        body_obj = {"transactions": payload}
        first = self.batch(payload, key="batch-key-1")
        self.assertEqual(first[0], 202)
        again = self.batch(payload, key="batch-key-1")
        self.assertEqual(again, first)
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(events), 2)

    def test_idempotency_key_rejected_batch_occupies_no_key(self) -> None:
        bad = [item(self.ka, self.A, self.B, 1, 0), item(self.ka, self.A, self.B, 1, 2)]
        status, _ = self.batch(bad, key="batch-key-2")
        self.assertEqual(status, 400)
        good = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.ka, self.A, self.B, 1, 1),
        ]
        status, body = self.batch(good, key="batch-key-2")
        self.assertEqual(status, 202)
        self.assertEqual(body["total"], 2)

    def test_keyless_persistence_failure_is_500_and_restores(self) -> None:
        payload = [item(self.ka, self.A, self.B, 1, 0)]

        def fail():
            raise OSError("disk full")

        self.svc.store.save = fail  # type: ignore[method-assign]
        status, body = self.svc.submit_sequenced_batch({"transactions": payload})
        self.assertEqual((status, body), (500, {"error": "persistence failed"}))
        self.assertEqual(len(self.svc.store.pending), 0)
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(events, [])

class BatchConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")), initial_balance=1000
        )

    def test_concurrent_same_batch_only_one_changes_state(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 1, 0),
            item(self.ka, self.A, self.B, 1, 1),
        ]

        def submit():
            return self.svc.submit_sequenced_batch({"transactions": payload})

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: submit(), range(8)))
        statuses = [status for status, _ in results]
        self.assertEqual(statuses.count(202), 1)
        self.assertEqual(statuses.count(200), 7)
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(events), 2)
        self.assertEqual(len(self.svc.store.pending), 2)

    def test_concurrent_disjoint_senders_all_succeed(self) -> None:
        batches = [
            [item(self.ka, self.A, self.B, 1, 0)],
            [item(self.kb, self.B, self.A, 1, 0)],
        ]

        def submit(payload):
            return self.svc.submit_sequenced_batch({"transactions": payload})

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(submit, batches * 4))
        self.assertEqual(self.svc.get_account_sequence(self.A)[1]["next_sequence"], 1)
        self.assertEqual(self.svc.get_account_sequence(self.B)[1]["next_sequence"], 1)
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(events), 2)

    def test_concurrent_same_idempotency_key_serialized(self) -> None:
        payload = [item(self.ka, self.A, self.B, 1, 0)]

        def submit():
            return self.svc.execute_idempotent(
                "POST",
                "/v1/transactions/sequenced/batch",
                "concurrent-key",
                {"transactions": payload},
                lambda: self.svc.submit_sequenced_batch({"transactions": payload}),
                sort_keys=False,
            )[:2]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: submit(), range(8)))
        statuses = sorted(status for status, _ in results)
        self.assertEqual(set(statuses), {202})
        events = [
            event
            for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(events), 1)


class BatchHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, path: str, payload, key: str | None = None):
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if key is not None:
            headers["Idempotency-Key"] = key
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, dict(resp.headers), json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), json.loads(exc.read().decode())

    def test_batch_lifecycle_over_http(self) -> None:
        payload = [
            item(self.ka, self.A, self.B, 10, 0),
            item(self.kb, self.B, self.A, 4, 0),
            item(self.ka, self.A, self.B, 10, 1),
        ]
        body = {"transactions": payload}
        status, headers, first = self.request(
            "/v1/transactions/sequenced/batch", body
        )
        self.assertEqual(status, 202)
        self.assertEqual(list(first), ["items", "total"])
        self.assertEqual(first["total"], 3)

        status, _, replay = self.request(
            "/v1/transactions/sequenced/batch", body
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [entry["location"] for entry in replay["items"]],
            ["pending", "pending", "pending"],
        )
        self.assertEqual(
            [entry["tx_id"] for entry in replay["items"]],
            [entry["tx_id"] for entry in first["items"]],
        )

        status, _, bad = self.request(
            "/v1/transactions/sequenced/batch",
            {"transactions": [item(self.ka, self.A, self.B, 1, 5)]},
        )
        self.assertEqual(
            bad, {"error": "sequence_conflict", "index": 0, "next_sequence": 2}
        )

    def test_malformed_json_is_input(self) -> None:
        req = urllib.request.Request(
            f"{self.base}/v1/transactions/sequenced/batch",
            data=b"{not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            self.assertEqual(json.loads(exc.read().decode()), {"error": "input"})

    def test_idempotency_headers_over_http(self) -> None:
        payload = {"transactions": [item(self.ka, self.A, self.B, 2, 2)]}
        status, headers, _ = self.request(
            "/v1/transactions/sequenced/batch", payload, key="http-batch-1"
        )
        self.assertEqual(status, 202)
        self.assertEqual(headers.get("Idempotency-Key"), "http-batch-1")
        self.assertEqual(headers.get("Idempotency-Replayed"), "false")
        status, headers, _ = self.request(
            "/v1/transactions/sequenced/batch", payload, key="http-batch-1"
        )
        self.assertEqual(status, 202)
        self.assertEqual(headers.get("Idempotency-Replayed"), "true")

    def test_single_endpoint_unchanged(self) -> None:
        payload = item(self.kb, self.B, self.A, 1, 1)
        req = urllib.request.Request(
            f"{self.base}/v1/transactions/sequenced",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 202)


class BatchCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "cli.json")), initial_balance=100
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def run_cli(self, argv: list[str], stdin: str | None = None) -> tuple[int, str]:
        parser = build_cli_parser()
        args = parser.parse_args(argv)
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            if stdin is not None:
                old_stdin = sys.stdin
                sys.stdin = io.StringIO(stdin)
                try:
                    code = args.func(args)
                finally:
                    sys.stdin = old_stdin
            else:
                code = args.func(args)
        return code, out.getvalue().strip()

    def test_cli_submits_from_file_and_stdin(self) -> None:
        payload = {
            "transactions": [
                item(self.ka, self.A, self.B, 10, 0),
                item(self.ka, self.A, self.B, 5, 1),
            ]
        }
        path = os.path.join(self.tmp, "batch.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        code, out = self.run_cli(
            ["--base-url", self.base, "send-sequenced-batch", "--file", path]
        )
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertEqual(list(body), ["items", "total"])
        self.assertEqual(body["total"], 2)

        # Same file again -> whole-batch replay 200, still exit 0.
        code, out = self.run_cli(
            ["--base-url", self.base, "send-sequenced-batch", "--file", path]
        )
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertEqual(body["items"][0]["location"], "pending")

        # stdin via "-" with the B sender's next batch.
        stdin_payload = {"transactions": [item(self.kb, self.B, self.A, 1, 0)]}
        code, out = self.run_cli(
            ["--base-url", self.base, "send-sequenced-batch", "--file", "-"],
            stdin=json.dumps(stdin_payload),
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["total"], 1)

    def test_cli_local_errors_do_not_hit_server(self) -> None:
        missing = os.path.join(self.tmp, "nope.json")
        code, out = self.run_cli(
            ["--base-url", self.base, "send-sequenced-batch", "--file", missing]
        )
        self.assertEqual((code, out), (1, json.dumps({"error": "input"})))

        bad_path = os.path.join(self.tmp, "bad.json")
        with open(bad_path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        code, out = self.run_cli(
            ["--base-url", self.base, "send-sequenced-batch", "--file", bad_path]
        )
        self.assertEqual((code, out), (1, json.dumps({"error": "input"})))

        code, out = self.run_cli(
            ["--base-url", self.base, "send-sequenced-batch", "--file", "-"],
            stdin="[1, 2",
        )
        self.assertEqual((code, out), (1, json.dumps({"error": "input"})))

    def test_cli_server_rejection_exit_1(self) -> None:
        payload = {"transactions": [item(self.ka, self.A, self.B, 1, 9)]}
        path = os.path.join(self.tmp, "conflict.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        code, out = self.run_cli(
            ["--base-url", self.base, "send-sequenced-batch", "--file", path]
        )
        self.assertEqual(code, 1)
        body = json.loads(out)
        self.assertEqual(body["error"], "sequence_conflict")
        self.assertEqual(body["index"], 0)


if __name__ == "__main__":
    unittest.main()
