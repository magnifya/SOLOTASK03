"""Tests for atomic batch cancellation of mempool transactions.

Covers POST /v1/transactions/cancel/batch end to end at the service layer
and over HTTP:

* envelope validation (body is exactly {"cancellations": [...]}, 1-200
  items) answers 400 {"error": "input"} without an index for bad JSON,
  non-UTF-8, query parameters, top-level shape or count defects;
* per-item shape/format defects and duplicate tx_ids answer the same 400
  body with the first offending zero-based index (a duplicate naming the
  position of its second occurrence);
* per-item lookup, signature and block checks answer 404 not_found,
  403 unauthorized and 409 not_cancellable with that item's index, each
  phase reporting only its first error;
* per-sender selected sequenced nonces must form a contiguous suffix of
  the full reserved range (mempool plus pending tip), order independent and
  legacy/sequenced/different-account items may interleave; a violation is
  409 sequence_conflict naming the earliest violating sequence entry;
* 200 {"items": [{"tx_id", "status": "cancelled"}, ...], "total": N}
  preserves input order, removes every transaction in one atomic write,
  releases spend reservations and backs next_sequence off by the per-sender
  cancelled sequenced count while leaving other mempool transactions and
  confirmed balances untouched; generation advances once and exactly one
  transaction_cancelled event lands per transaction in input order;
* persistence failure answers 500 {"error": "persistence failed"} and
  restores mempool order, sequences, the audit chain, generation and
  idempotency records;
* uniform Idempotency-Key replay semantics, keyless retries judged by
  current state, receipts reading not found, resubmission / nonce reuse,
  candidate-fork invisibility and restart preservation.

Run: python3 tests/cancel_transaction_batch_test.py
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
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(crypto.canonical_message(sender, to, amount)).hex(),
    }


def sequenced_payload(key, sender, to, amount, nonce) -> dict:
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(
            crypto.sequenced_message(sender, to, amount, nonce)
        ).hex(),
    }


def cancel_item(key, tx_id) -> dict:
    return {
        "tx_id": tx_id,
        "signature": key.sign(crypto.cancel_message(tx_id)).hex(),
    }


def batch(*items) -> dict:
    return {"cancellations": list(items)}


class BatchCancelServiceTests(unittest.TestCase):
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
        to = to or self.B
        status, body = self.svc.submit_transaction(
            legacy_payload(key, sender, to, amount)
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

    def cancel_batch(self, payload):
        return self.svc.cancel_transactions_batch(payload)

    # -- envelope validation -------------------------------------------------

    def test_bad_envelope_is_400_without_index(self) -> None:
        tx_id = self.submit_legacy()
        good = cancel_item(self.ka, tx_id)
        bad_payloads = [
            None,
            [],
            "cancellations",
            {},
            {"cancellations": []},  # empty
            {"cancellations": [good, good]},  # shape valid but dup-free? no -> index
            {"cancellations": None},
            {"cancellations": "x"},
            {"cancellations": {}},
            {"cancellations": [good], "extra": 1},
        ]
        bad_no_index = [p for p in bad_payloads if p != {"cancellations": [good, good]}]
        for bad in bad_no_index:
            status, result = self.cancel_batch(bad)
            self.assertEqual((status, result), (400, {"error": "input"}), bad)
        # 201 items: over the count limit, no index.
        oversized = {"cancellations": [good] * 201}
        # duplicates surface at index 1 first; craft distinct-looking items
        # instead by giving each a syntactically valid unique id.
        oversized = {
            "cancellations": [
                {"tx_id": f"{i:064x}"[:64], "signature": "00" * 64}
                for i in range(1, 202)
            ]
        }
        status, result = self.cancel_batch(oversized)
        self.assertEqual((status, result), (400, {"error": "input"}))
        # No state changed.
        self.assertIn(tx_id, self.store.pending)
        self.assertEqual(len(self.store.audit_events), 1)

    def test_bad_item_shape_is_400_with_first_index(self) -> None:
        ids = [self.submit_legacy(amount=1 + i) for i in range(3)]
        good0 = cancel_item(self.ka, ids[0])
        good2 = cancel_item(self.ka, ids[2])
        cases = [
            # first item malformed
            ([None, good2], 0),
            (["x", good2], 0),
            ([{}, good2], 0),
            ([{"tx_id": ids[0]}, good2], 0),
            ([{"signature": good0["signature"]}, good2], 0),
            ([{"tx_id": ids[0], "signature": good0["signature"], "x": 1}], 0),
            # a later item is the first malformed one
            ([good0, None, good2], 1),
            ([good0, {"tx_id": ids[1], "signature": 1}, good2], 1),
            ([good0, {"tx_id": 1, "signature": good0["signature"]}, good2], 1),
            ([good0, {"tx_id": ids[1][:-1] + "g",
                      "signature": good0["signature"]}, good2], 1),
            ([good0, {"tx_id": ids[1].upper(),
                      "signature": good0["signature"]}, good2], 1),
            ([good0, {"tx_id": ids[1],
                      "signature": "Z" * 128}, good2], 1),
            ([good0, {"tx_id": ids[1],
                      "signature": "a" * 127}, good2], 1),
        ]
        for items, expected_index in cases:
            status, result = self.cancel_batch(batch(*items))
            self.assertEqual(
                (status, result),
                (400, {"error": "input", "index": expected_index}),
                items,
            )
        self.assertEqual(
            sorted(self.store.pending), sorted(ids)
        )

    def test_duplicate_tx_id_names_second_occurrence(self) -> None:
        ids = [self.submit_legacy(amount=10 + i) for i in range(3)]
        i0 = cancel_item(self.ka, ids[0])
        i1 = cancel_item(self.ka, ids[1])
        # First duplicate at index 1 (ids[0] repeated).
        status, result = self.cancel_batch(batch(i0, dict(i0), i1))
        self.assertEqual(
            (status, result), (400, {"error": "input", "index": 1})
        )
        # The third occurrence also reports the second position, not the third.
        status, result = self.cancel_batch(batch(i0, dict(i0), dict(i0)))
        self.assertEqual(
            (status, result), (400, {"error": "input", "index": 1})
        )
        # A later duplicate is reported at its own second position.
        status, result = self.cancel_batch(batch(i0, i1, dict(i1)))
        self.assertEqual(
            (status, result), (400, {"error": "input", "index": 2})
        )
        # Identical bodies (same tx_id, same signature) are duplicates too.
        status, result = self.cancel_batch(batch(i1, i1))
        self.assertEqual(
            (status, result), (400, {"error": "input", "index": 1})
        )
        self.assertEqual(len(self.store.pending), 3)

    def test_format_phase_precedes_lookup_phase(self) -> None:
        unknown = "cd" * 32
        # A malformed item at index 1 beats an unknown id at index 0: the
        # whole-batch format phase runs before any lookup.
        payload = batch(
            {"tx_id": unknown, "signature": "00" * 64},
            {"tx_id": "not-hex", "signature": "00" * 64},
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (400, {"error": "input", "index": 1})
        )

    # -- per-item lookup / signature / block phase ----------------------------

    def test_unknown_id_is_404_with_index(self) -> None:
        queued = self.submit_legacy()
        payload = batch(
            cancel_item(self.ka, queued),
            {"tx_id": "cd" * 32, "signature": "00" * 64},
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (404, {"error": "not_found", "index": 1})
        )
        # First item unknown is reported at 0 even if a later signature fails.
        other_queued = self.submit_legacy(amount=20)
        payload = batch(
            {"tx_id": "ef" * 32, "signature": "00" * 64},
            cancel_item(self.kb, other_queued),  # wrong signer
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (404, {"error": "not_found", "index": 0})
        )
        self.assertEqual(len(self.store.pending), 2)

    def test_bad_signature_is_403_with_index(self) -> None:
        first = self.submit_legacy(amount=10)
        second = self.submit_legacy(amount=20)
        # Index 1 signed by the wrong key; index 0 is sound.
        payload = batch(
            cancel_item(self.ka, first),
            cancel_item(self.kb, second),
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (403, {"error": "unauthorized", "index": 1})
        )
        # A signature over a different id fails too.
        payload = batch(
            cancel_item(self.ka, first),
            {
                "tx_id": second,
                "signature": cancel_item(self.ka, first)["signature"],
            },
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (403, {"error": "unauthorized", "index": 1})
        )
        self.assertEqual(sorted(self.store.pending), sorted([first, second]))
        self.assertEqual(len(self.store.audit_events), 2)

    def test_candidate_fork_is_not_searched(self) -> None:
        from ledger.models import Block, Transaction

        fork_tx = legacy_payload(self.ka, self.A, self.B, 10)
        tx_id = crypto.compute_tx_id(
            crypto.canonical_message(self.A, self.B, 10)
        )
        genesis = self.store.chain[0]
        block = Block.create(
            1, genesis.block_hash, [Transaction.from_dict(fork_tx)]
        )
        status, _ = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), block.to_dict()]}
        )
        self.assertEqual(status, 201)
        status, result = self.cancel_batch(batch(cancel_item(self.ka, tx_id)))
        self.assertEqual(
            (status, result), (404, {"error": "not_found", "index": 0})
        )

    def test_packed_and_confirmed_are_409_with_index(self) -> None:
        packed = self.submit_legacy(amount=10)
        # Mining packs the whole mempool; submit the queued tx afterwards so
        # it survives alongside the pending tip.
        block = self.svc.mine_block()[1]
        queued = self.submit_legacy(amount=20)
        # The packed item (index 0) is reported before the later items.
        payload = batch(
            cancel_item(self.ka, packed),
            cancel_item(self.ka, queued),
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (409, {"error": "not_cancellable", "index": 0})
        )
        self.assertIn(queued, self.store.pending)
        self.svc.confirm_block(block["height"])
        status, result = self.cancel_batch(
            batch(cancel_item(self.ka, packed))
        )
        self.assertEqual(
            (status, result), (409, {"error": "not_cancellable", "index": 0})
        )
        self.assertIn(queued, self.store.pending)

    def test_item_phase_precedence_input_order(self) -> None:
        # index 0: unknown; index 1: bad signature; index 2: packed.
        packed = self.submit_sequenced(0)
        self.svc.mine_block()
        queued = self.submit_sequenced(1)
        payload = batch(
            {"tx_id": "11" * 32, "signature": "00" * 64},
            cancel_item(self.kb, queued),
            cancel_item(self.ka, packed),
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (404, {"error": "not_found", "index": 0})
        )

    # -- suffix phase ----------------------------------------------------------

    def test_sequenced_suffix_required(self) -> None:
        ids = [self.submit_sequenced(nonce) for nonce in range(3)]
        # Selecting only nonce 2 (the top) is fine; a non-top selection is a
        # sequence_conflict naming the selected entry.
        status, result = self.cancel_batch(batch(cancel_item(self.ka, ids[0])))
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 0})
        )
        status, result = self.cancel_batch(batch(cancel_item(self.ka, ids[1])))
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 0})
        )
        # Non-contiguous selection {0, 2} fails at the earliest selected entry.
        payload = batch(
            cancel_item(self.ka, ids[2]),
            cancel_item(self.ka, ids[0]),
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 0})
        )
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 3
        )
        # The contiguous suffix {1, 2} in any order succeeds.
        payload = batch(
            cancel_item(self.ka, ids[2]),
            cancel_item(self.ka, ids[1]),
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(status, 200, result)
        self.assertEqual(
            [item["tx_id"] for item in result["items"]], [ids[2], ids[1]]
        )
        self.assertEqual(result["total"], 2)
        view = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(view["next_sequence"], 1)
        self.assertEqual(
            view["pending_sequences"], [{"nonce": 0, "tx_id": ids[0]}]
        )
        # The freed top nonce can be reused immediately.
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 5, 1)
        )
        self.assertEqual(status, 202)
        self.assertEqual(body["nonce"], 1)

    def test_suffix_includes_pending_tip(self) -> None:
        # Pack nonces 0 and 1 into the pending tip (mining packs the whole
        # mempool), then reserve 2 and 3 in the mempool afterwards.
        ids = [self.submit_sequenced(nonce, amount=4) for nonce in range(2)]
        block = self.svc.mine_block()[1]
        ids += [self.submit_sequenced(nonce, amount=4) for nonce in (2, 3)]
        # Selecting only queued nonce 2 fails: it is not a suffix while the
        # higher reserved nonce 3 stays selected by nothing.
        status, result = self.cancel_batch(
            batch(cancel_item(self.ka, ids[2]))
        )
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 0})
        )
        # Selecting only nonce 3 is the length-1 suffix of the full reserved
        # range {0,1,2,3}: valid, next_sequence steps back to 3.
        status, result = self.cancel_batch(
            batch(cancel_item(self.ka, ids[3]))
        )
        self.assertEqual(status, 200, result)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 3
        )
        # Nonce 2 is now the top queued reservation and cancels on its own.
        status, result = self.cancel_batch(
            batch(cancel_item(self.ka, ids[2]))
        )
        self.assertEqual(status, 200, result)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 2
        )
        # nonce 1 sits in the pending tip: not cancellable (block check comes
        # before the suffix check).
        status, result = self.cancel_batch(
            batch(cancel_item(self.ka, ids[1]))
        )
        self.assertEqual(
            (status, result), (409, {"error": "not_cancellable", "index": 0})
        )
        self.svc.rollback_block(block["height"])
        status, result = self.cancel_batch(
            batch(
                cancel_item(self.ka, ids[1]),
                cancel_item(self.ka, ids[0]),
            )
        )
        self.assertEqual(status, 200, result)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 0
        )

    def test_suffix_error_names_earliest_violating_entry(self) -> None:
        # Sender A reserves 0..3, B reserves 0..1.
        a_ids = [self.submit_sequenced(i, amount=5) for i in range(4)]
        b_ids = [
            self.submit_sequenced(i, amount=5, key=self.kb, sender=self.B)
            for i in range(2)
        ]
        # First trim A's reservations back to {0, 1}; this batch succeeds.
        status, _ = self.cancel_batch(
            batch(
                cancel_item(self.ka, a_ids[3]),
                cancel_item(self.ka, a_ids[2]),
            )
        )
        self.assertEqual(status, 200)
        pending_before = dict(self.store.pending)
        # In the next batch A (first appearing) selects its full suffix
        # {1, 0} — valid; B (appearing second at index 1) selects only its
        # lower nonce 0, so B is the earliest violating sender and its
        # earliest selected sequence entry (index 1) names the error.
        payload = batch(
            cancel_item(self.ka, a_ids[1]),   # index 0: A valid
            cancel_item(self.kb, b_ids[0]),   # index 1: B violates
            cancel_item(self.ka, a_ids[0]),   # index 2: A valid
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(
            (status, result), (409, {"error": "sequence_conflict", "index": 1})
        )
        # Nothing changed.
        self.assertEqual(dict(self.store.pending), pending_before)

    def test_legacy_and_sequenced_and_accounts_interleave(self) -> None:
        legacy_a = self.submit_legacy(amount=11)
        legacy_b = self.submit_legacy(amount=7, key=self.kb, sender=self.B)
        seq = [self.submit_sequenced(nonce, amount=3) for nonce in range(2)]
        payload = batch(
            cancel_item(self.ka, seq[1]),       # top nonce for A
            cancel_item(self.kb, legacy_b),     # legacy for B
            cancel_item(self.ka, legacy_a),     # legacy for A
            cancel_item(self.ka, seq[0]),       # new top for A
        )
        status, result = self.cancel_batch(payload)
        self.assertEqual(status, 200, result)
        self.assertEqual(
            [item["tx_id"] for item in result["items"]],
            [seq[1], legacy_b, legacy_a, seq[0]],
        )
        self.assertEqual(result["total"], 4)
        self.assertEqual(self.store.pending, {})
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 0
        )
        # Spend reservations released for both senders.
        self.assertEqual(self.svc.available_balance(self.A), 1000)
        self.assertEqual(self.svc.available_balance(self.B), 1000)

    # -- success / atomicity ---------------------------------------------------

    def test_success_is_one_write_with_ordered_events(self) -> None:
        first = self.submit_legacy(amount=40)
        second = self.submit_legacy(amount=20, key=self.kb, sender=self.B)
        third = self.submit_legacy(amount=5)
        generation_before = self.store.generation
        saves = []
        original = self.store.save

        def counting_save():
            saves.append(1)
            return original()

        self.store.save = counting_save
        try:
            status, result = self.cancel_batch(
                batch(
                    cancel_item(self.ka, third),
                    cancel_item(self.kb, second),
                    cancel_item(self.ka, first),
                )
            )
        finally:
            self.store.save = original
        self.assertEqual(status, 200)
        self.assertEqual(saves, [1])  # exactly one write, one generation
        self.assertEqual(
            result,
            {
                "items": [
                    {"tx_id": third, "status": "cancelled"},
                    {"tx_id": second, "status": "cancelled"},
                    {"tx_id": first, "status": "cancelled"},
                ],
                "total": 3,
            },
        )
        self.assertEqual(self.store.generation, generation_before + 1)
        self.assertEqual(self.store.pending, {})
        # Reservations released; confirmed balances untouched.
        self.assertEqual(self.svc.available_balance(self.A), 1000)
        self.assertEqual(self.svc.available_balance(self.B), 1000)
        # Three cancel events appended in input order.
        kinds = [event["kind"] for event in self.store.audit_events]
        self.assertEqual(
            kinds,
            [
                EVENT_TRANSACTION_SUBMITTED,
                EVENT_TRANSACTION_SUBMITTED,
                EVENT_TRANSACTION_SUBMITTED,
                EVENT_TRANSACTION_CANCELLED,
                EVENT_TRANSACTION_CANCELLED,
                EVENT_TRANSACTION_CANCELLED,
            ],
        )
        self.assertEqual(
            [event["tx_id"] for event in self.store.audit_events[-3:]],
            [third, second, first],
        )
        audit.validate_event_chain(self.store.audit_events)
        audit.validate_checkpoint(
            self.store.audit_checkpoint, self.store.audit_events
        )

    def test_other_mempool_transactions_keep_order(self) -> None:
        keep1 = self.submit_legacy(amount=1)
        gone = self.submit_legacy(amount=2)
        keep2 = self.submit_legacy(amount=3)
        before = list(self.store.pending)
        status, _ = self.cancel_batch(batch(cancel_item(self.ka, gone)))
        self.assertEqual(status, 200)
        self.assertEqual(list(self.store.pending), [keep1, keep2])
        self.assertEqual(before, [keep1, gone, keep2])

    def test_sequenced_event_carries_nonce(self) -> None:
        ids = [self.submit_sequenced(nonce, amount=4) for nonce in range(2)]
        status, _ = self.cancel_batch(
            batch(
                cancel_item(self.ka, ids[1]),
                cancel_item(self.ka, ids[0]),
            )
        )
        self.assertEqual(status, 200)
        events = self.store.audit_events[-2:]
        self.assertEqual(
            [event["nonce"] for event in events], [1, 0]
        )
        for event in events:
            self.assertEqual(
                set(event),
                {
                    "event_id", "kind", "at", "prev_hash", "event_hash",
                    "tx_id", "from", "to", "amount", "signature", "nonce",
                },
            )

    def test_receipts_resubmit_and_nonce_reuse(self) -> None:
        ids = [self.submit_sequenced(nonce, amount=6) for nonce in range(2)]
        payloads = [
            sequenced_payload(self.ka, self.A, self.B, 6, nonce)
            for nonce in range(2)
        ]
        status, _ = self.cancel_batch(
            batch(
                cancel_item(self.ka, ids[1]),
                cancel_item(self.ka, ids[0]),
            )
        )
        self.assertEqual(status, 200)
        for tx_id in ids:
            status, _ = self.svc.get_transaction(tx_id)
            self.assertEqual(status, 404)
        status, body = self.svc.get_transaction_receipts(
            {"tx_ids": ids}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            body["items"],
            [
                {"tx_id": tx_id, "receipt": None, "error": "not_found"}
                for tx_id in ids
            ],
        )
        # Same transactions can be resubmitted under the original rules.
        for nonce, payload in enumerate(payloads):
            status, body = self.svc.submit_sequenced_transaction(payload)
            self.assertEqual(status, 202, body)
            self.assertEqual(body["tx_id"], ids[nonce])
        kinds = [event["kind"] for event in self.store.audit_events]
        self.assertEqual(kinds.count(EVENT_TRANSACTION_CANCELLED), 2)
        self.assertEqual(kinds.count(EVENT_TRANSACTION_SUBMITTED), 4)

    def test_save_failure_rolls_everything_back(self) -> None:
        ids = [self.submit_legacy(amount=10 + i) for i in range(3)]
        events_before = len(self.store.audit_events)
        pending_before = dict(self.store.pending)
        order_before = list(self.store.pending)
        generation_before = self.store.generation
        sequences_before = self.svc.get_account_sequence(self.A)[1]

        original = self.store.save
        state = {"failed": False}

        def failing_save():
            if not state["failed"]:
                state["failed"] = True
                raise OSError("simulated disk failure")
            return original()

        self.store.save = failing_save
        try:
            status, result = self.cancel_batch(
                batch(*(cancel_item(self.ka, tx_id) for tx_id in ids))
            )
        finally:
            self.store.save = original
        self.assertEqual((status, result), (500, {"error": "persistence failed"}))
        self.assertEqual(dict(self.store.pending), pending_before)
        self.assertEqual(list(self.store.pending), order_before)
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1], sequences_before
        )
        audit.validate_event_chain(self.store.audit_events)
        reopened = self.reopen()
        self.assertEqual(sorted(reopened.store.pending), sorted(ids))

    def test_failed_validation_changes_nothing(self) -> None:
        ids = [self.submit_sequenced(nonce, amount=8) for nonce in range(3)]
        pending_before = dict(self.store.pending)
        events_before = len(self.store.audit_events)
        generation_before = self.store.generation
        # suffix violation, bad signature and unknown id requests in turn
        for payload in (
            batch(cancel_item(self.ka, ids[0])),
            batch(cancel_item(self.kb, ids[2])),
            batch({"tx_id": "77" * 32, "signature": "00" * 64}),
        ):
            status, _ = self.cancel_batch(payload)
            self.assertIn(status, (403, 404, 409))
        self.assertEqual(dict(self.store.pending), pending_before)
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)

    # -- idempotency -----------------------------------------------------------

    def test_idempotent_replay_conflict_and_keyless_retry(self) -> None:
        ids = [self.submit_legacy(amount=10 + i) for i in range(2)]
        body = batch(
            cancel_item(self.ka, ids[1]),
            cancel_item(self.ka, ids[0]),
        )
        target = "/v1/transactions/cancel/batch"

        def action():
            return self.svc.cancel_transactions_batch(body)

        status, result, replayed, text = self.svc.execute_idempotent(
            "POST", target, "batch-cancel-1", body, action, sort_keys=False
        )
        self.assertEqual((status, replayed), (200, False))
        self.assertEqual(result["total"], 2)
        first_result = result
        # Exact key order on the wire: items before total.
        self.assertEqual(text, json.dumps(result, sort_keys=False))
        self.assertTrue(text.startswith('{"items":'))
        events = len(self.store.audit_events)
        # Replay returns the cached response verbatim, no new events.
        status, result2, replayed, text2 = self.svc.execute_idempotent(
            "POST", target, "batch-cancel-1", body, action, sort_keys=False
        )
        self.assertEqual((status, replayed), (200, True))
        self.assertEqual(text2, text)
        self.assertEqual(result2, first_result)
        self.assertEqual(len(self.store.audit_events), events)
        # Same key, different body -> conflict.
        other = batch(cancel_item(self.ka, "ab" * 32))
        status, _r, replayed, _t = self.svc.execute_idempotent(
            "POST", target, "batch-cancel-1", other,
            lambda: self.svc.cancel_transactions_batch(other),
            sort_keys=False,
        )
        self.assertEqual((status, replayed), (409, False))
        # Keyless retry judges by current state: the first id is gone.
        status, retry_body = self.cancel_batch(body)
        self.assertEqual(
            (status, retry_body), (404, {"error": "not_found", "index": 0})
        )
        # The replay survives a restart.
        reopened = self.reopen()
        status, result3, replayed, _t = reopened.execute_idempotent(
            "POST", target, "batch-cancel-1", body,
            lambda: reopened.cancel_transactions_batch(body),
            sort_keys=False,
        )
        self.assertEqual((status, replayed), (200, True))
        self.assertEqual(result3, first_result)

    def test_idempotent_failure_occupies_no_key(self) -> None:
        tx_id = self.submit_legacy()
        bad = batch(cancel_item(self.kb, tx_id))
        target = "/v1/transactions/cancel/batch"
        status, _r, replayed, _t = self.svc.execute_idempotent(
            "POST", target, "batch-cancel-fail", bad,
            lambda: self.svc.cancel_transactions_batch(bad),
            sort_keys=False,
        )
        self.assertEqual(status, 403)
        self.assertNotIn("batch-cancel-fail", self.store.idempotency)
        self.assertEqual(len(self.store.audit_events), 1)

    # -- restart ---------------------------------------------------------------

    def test_restart_preserves_batch_cancel(self) -> None:
        seq = [self.submit_sequenced(nonce, amount=9) for nonce in range(2)]
        legacy = self.submit_legacy(amount=12)
        status, _ = self.cancel_batch(
            batch(
                cancel_item(self.ka, seq[1]),
                cancel_item(self.ka, legacy),
                cancel_item(self.ka, seq[0]),
            )
        )
        self.assertEqual(status, 200)
        events_before = [dict(event) for event in self.store.audit_events]
        reopened = self.reopen()
        self.assertEqual(reopened.store.pending, {})
        self.assertEqual(
            [dict(event) for event in reopened.store.audit_events],
            events_before,
        )
        self.assertEqual(
            reopened.get_account_sequence(self.A)[1]["next_sequence"], 0
        )
        for tx_id in seq + [legacy]:
            status, _ = reopened.get_transaction(tx_id)
            self.assertEqual(status, 404)


class BatchCancelHttpTests(unittest.TestCase):
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

    def _submit(self, key, pub, amount: int) -> str:
        payload = legacy_payload(key, pub, f"to-{pub[:8]}", amount)
        status, body, _h, _raw = self.request(
            "POST", "/v1/transactions", payload
        )
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def test_http_batch_flow(self) -> None:
        key, pub = keypair()
        tx1 = self._submit(key, pub, 10)
        tx2 = self._submit(key, pub, 20)
        request_body = batch(
            cancel_item(key, tx2),
            cancel_item(key, tx1),
        )

        # Query parameters rejected, body unread.
        status, body, _h, _raw = self.request(
            "POST", "/v1/transactions/cancel/batch?x=1", request_body
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # Malformed JSON and non-UTF-8 bytes are both 400 input.
        status, body, _h, _raw = self.request(
            "POST", "/v1/transactions/cancel/batch", raw=b"{not json"
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        status, body, _h, _raw = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            raw=b'{"cancellations": []}\xff',
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # Envelope/key order defect (empty list).
        status, body, _h, _raw = self.request(
            "POST", "/v1/transactions/cancel/batch", {"cancellations": []}
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # First success with an Idempotency-Key, fixed wire key order.
        status, body, headers, raw_first = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            request_body,
            {"Idempotency-Key": "batch-http-1"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            body,
            {
                "items": [
                    {"tx_id": tx2, "status": "cancelled"},
                    {"tx_id": tx1, "status": "cancelled"},
                ],
                "total": 2,
            },
        )
        self.assertEqual(
            raw_first,
            json.dumps(body, sort_keys=False).encode("utf-8"),
        )
        self.assertEqual(headers.get("Idempotency-Key"), "batch-http-1")
        self.assertEqual(headers.get("Idempotency-Replayed"), "false")
        # Replay is byte-identical.
        status, body2, headers, raw_replay = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            request_body,
            {"Idempotency-Key": "batch-http-1"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Idempotency-Replayed"), "true")
        self.assertEqual(raw_replay, raw_first)
        self.assertEqual(body2, body)
        # Same key, different body -> conflict.
        status, body, _h, _raw = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            batch(cancel_item(key, "ab" * 32)),
            {"Idempotency-Key": "batch-http-1"},
        )
        self.assertEqual(
            (status, body), (409, {"error": "idempotency key conflict"})
        )
        # Keyless retry judges by current state: first id is gone.
        status, body, _h, _raw = self.request(
            "POST", "/v1/transactions/cancel/batch", request_body
        )
        self.assertEqual(
            (status, body), (404, {"error": "not_found", "index": 0})
        )

    def test_http_suffix_and_mixed_batch(self) -> None:
        key, pub = keypair()
        # Two sequenced and one legacy transaction.
        seq_ids = []
        for nonce in range(2):
            payload = sequenced_payload(key, pub, f"to-{pub[:6]}", 3, nonce)
            status, body, _h, _raw = self.request(
                "POST", "/v1/transactions/sequenced", payload
            )
            self.assertEqual(status, 202, body)
            seq_ids.append(body["tx_id"])
        legacy_id = self._submit(key, pub, 5)
        # Non-suffix selection is 409 with index.
        status, body, _h, _raw = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            batch(cancel_item(key, seq_ids[0])),
        )
        self.assertEqual(
            (status, body), (409, {"error": "sequence_conflict", "index": 0})
        )
        # Full suffix plus the legacy tx, shuffled.
        status, body, _h, _raw = self.request(
            "POST",
            "/v1/transactions/cancel/batch",
            batch(
                cancel_item(key, legacy_id),
                cancel_item(key, seq_ids[1]),
                cancel_item(key, seq_ids[0]),
            ),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            [item["tx_id"] for item in body["items"]],
            [legacy_id, seq_ids[1], seq_ids[0]],
        )


if __name__ == "__main__":
    unittest.main()
