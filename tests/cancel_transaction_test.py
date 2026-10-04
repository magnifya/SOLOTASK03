"""Tests for sender-signed cancellation of mempool transactions.

Covers POST /v1/transactions/{tx_id}/cancel end to end at the service layer
and over HTTP:

* the fixed signed-message format ``ledger-cancel-v1\\n<tx_id>``;
* 400 {"error": "input"} for every tx_id/body format or JSON defect and for
  any query parameter;
* 404 {"error": "not_found"} when only candidate forks (or nothing) hold the
  transaction, 403 {"error": "unauthorized"} for a bad sender signature;
* 409 {"error": "not_cancellable"} for packed/confirmed transactions and
  409 {"error": "sequence_conflict"} when a sequenced nonce is not the
  sender's highest reserved nonce (mempool plus pending tip);
* 200 {"tx_id", "status": "cancelled"} removing the transaction, releasing
  the spend reservation and (for sequenced transfers) the nonce so
  next_sequence steps back by one, leaving other transactions and confirmed
  balances untouched;
* exactly one transaction_cancelled audit event per successful cancel,
  atomically persisted (generation advances once; failures and idempotent
  replays append nothing), with persistence-failure rollback of the mempool
  (and its order), sequences, idempotency records and the audit chain;
* restart recovery of the cancellation and idempotent replays, strict
  rejection of snapshots whose cancel event has illegal fields, a
  non-recomputing tx_id or an unverifiable signature, and recovery of old
  snapshots without cancel events;
* cancelled transactions reading as not found in single and batch receipts,
  immediate resubmission / nonce reuse, and candidate forks still being
  allowed to contain the cancelled transaction.

Run: python3 tests/cancel_transaction_test.py
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
from ledger.models import Block
from ledger.server import build_handler
from ledger.service import (
    EVENT_TRANSACTION_CANCELLED,
    EVENT_TRANSACTION_SUBMITTED,
    LedgerService,
)
from ledger.store import LedgerStore, StateRecoveryError


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


def cancel_body(key, tx_id) -> dict:
    return {"signature": key.sign(crypto.cancel_message(tx_id)).hex()}


class CancelMessageTests(unittest.TestCase):
    def test_message_format_is_fixed(self) -> None:
        tx_id = "ab" * 32
        self.assertEqual(
            crypto.cancel_message(tx_id),
            b"ledger-cancel-v1\n" + tx_id.encode("utf-8"),
        )

    def test_message_domain_is_distinct(self) -> None:
        tx_id = "ab" * 32
        self.assertNotEqual(
            crypto.cancel_message(tx_id),
            crypto.canonical_message("alice", "bob", 1),
        )
        self.assertTrue(
            crypto.cancel_message(tx_id).startswith(b"ledger-cancel-v1\n")
        )


class CancelServiceTests(unittest.TestCase):
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

    def submit_legacy(self, amount: int = 10, key=None, sender=None) -> str:
        key = key or self.ka
        sender = sender or self.A
        status, body = self.svc.submit_transaction(
            legacy_payload(key, sender, self.B, amount)
        )
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def submit_sequenced(self, nonce: int, amount: int = 10) -> str:
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, amount, nonce)
        )
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def cancel(self, tx_id, key=None):
        key = key or self.ka
        return self.svc.cancel_transaction(tx_id, cancel_body(key, tx_id))

    # -- input validation ---------------------------------------------------

    def test_bad_tx_id_is_400_input(self) -> None:
        tx_id = self.submit_legacy()
        body = cancel_body(self.ka, tx_id)
        for bad in (
            None,
            123,
            "",
            "zz" * 32,
            "AB" * 32,  # uppercase
            "a" * 63,
            "a" * 65,
            tx_id + "ff",
        ):
            status, result = self.svc.cancel_transaction(bad, body)
            self.assertEqual((status, result), (400, {"error": "input"}), bad)
        self.assertEqual(self.store.audit_events, [self.store.audit_events[0]])
        self.assertEqual(len(self.store.audit_events), 1)  # only the submit

    def test_bad_body_is_400_input(self) -> None:
        tx_id = self.submit_legacy()
        good = cancel_body(self.ka, tx_id)
        for bad in (
            None,
            [],
            "signature",
            {},
            {"signature": None},
            {"signature": 12},
            {"signature": "zz" * 64},
            {"signature": "AB" * 64},
            {"signature": "a" * 127},
            {"signature": "a" * 129},
            {"signature": good["signature"], "extra": 1},
            {"sig": good["signature"]},
        ):
            status, result = self.svc.cancel_transaction(tx_id, bad)
            self.assertEqual((status, result), (400, {"error": "input"}), bad)
        self.assertEqual(len(self.store.audit_events), 1)  # only the submit
        self.assertIn(tx_id, self.store.pending)

    # -- lookup / authorization ----------------------------------------------

    def test_unknown_id_is_404_not_found(self) -> None:
        status, result = self.cancel("cd" * 32)
        self.assertEqual((status, result), (404, {"error": "not_found"}))

    def test_bad_signature_is_403_unauthorized(self) -> None:
        tx_id = self.submit_legacy()
        # Signed by someone other than the sender.
        status, result = self.cancel(tx_id, key=self.kb)
        self.assertEqual((status, result), (403, {"error": "unauthorized"}))
        # Signed by the sender but over a different tx_id.
        other = cancel_body(self.ka, "cd" * 32)
        status, result = self.svc.cancel_transaction(tx_id, other)
        self.assertEqual((status, result), (403, {"error": "unauthorized"}))
        self.assertIn(tx_id, self.store.pending)
        self.assertEqual(len(self.store.audit_events), 1)

    def test_candidate_fork_is_not_searched(self) -> None:
        # A transaction that exists only inside a candidate fork is invisible
        # to cancellation: the lookup covers canonical chain and mempool only.
        fork_tx = legacy_payload(self.ka, self.A, self.B, 10)
        tx_id = crypto.compute_tx_id(
            crypto.canonical_message(self.A, self.B, 10)
        )
        genesis = self.store.chain[0]
        from ledger.models import Transaction

        block = Block.create(
            1, genesis.block_hash, [Transaction.from_dict(fork_tx)]
        )
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), block.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        status, result = self.cancel(tx_id)
        self.assertEqual((status, result), (404, {"error": "not_found"}))

    # -- state-machine results ------------------------------------------------

    def test_packed_and_confirmed_are_not_cancellable(self) -> None:
        tx_id = self.submit_legacy()
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201)
        status, result = self.cancel(tx_id)
        self.assertEqual((status, result), (409, {"error": "not_cancellable"}))
        status, _ = self.svc.confirm_block(block["height"])
        self.assertEqual(status, 200)
        status, result = self.cancel(tx_id)
        self.assertEqual((status, result), (409, {"error": "not_cancellable"}))
        self.assertEqual(
            [event["kind"] for event in self.store.audit_events],
            ["transaction_submitted", "block_mined", "block_confirmed"],
        )

    def test_rollback_returns_cancellability(self) -> None:
        tx_id = self.submit_legacy()
        block = self.svc.mine_block()[1]
        self.svc.rollback_block(block["height"])
        status, result = self.cancel(tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(result, {"tx_id": tx_id, "status": "cancelled"})

    def test_success_releases_spend_and_appends_one_event(self) -> None:
        tx_id = self.submit_legacy(amount=40)
        self.assertEqual(self.svc.available_balance(self.A), 960)
        status, result = self.cancel(tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(result, {"tx_id": tx_id, "status": "cancelled"})
        self.assertNotIn(tx_id, self.store.pending)
        # The spend reservation is released.
        self.assertEqual(self.svc.available_balance(self.A), 1000)
        # Exactly one transaction_cancelled event, chained after the submit.
        kinds = [event["kind"] for event in self.store.audit_events]
        self.assertEqual(
            kinds, [EVENT_TRANSACTION_SUBMITTED, EVENT_TRANSACTION_CANCELLED]
        )
        event = self.store.audit_events[-1]
        self.assertEqual(
            set(event),
            {
                "event_id", "kind", "at", "prev_hash", "event_hash",
                "tx_id", "from", "to", "amount", "signature",
            },
        )
        self.assertEqual(
            (event["tx_id"], event["from"], event["to"], event["amount"]),
            (tx_id, self.A, self.B, 40),
        )
        self.assertEqual(
            event["signature"], cancel_body(self.ka, tx_id)["signature"]
        )
        audit.validate_event_chain(self.store.audit_events)
        audit.validate_checkpoint(
            self.store.audit_checkpoint, self.store.audit_events
        )

    def test_receipts_read_not_found_after_cancel(self) -> None:
        tx_id = self.submit_legacy()
        self.cancel(tx_id)
        status, result = self.svc.get_transaction(tx_id)
        self.assertEqual(status, 404)
        status, batch = self.svc.get_transaction_receipts({"tx_ids": [tx_id]})
        self.assertEqual(status, 200)
        self.assertEqual(
            batch["items"],
            [{"tx_id": tx_id, "receipt": None, "error": "not_found"}],
        )

    def test_resubmission_after_cancel(self) -> None:
        payload = legacy_payload(self.ka, self.A, self.B, 10)
        status, body = self.svc.submit_transaction(payload)
        self.assertEqual(status, 202)
        tx_id = body["tx_id"]
        self.cancel(tx_id)
        # The same transaction can be resubmitted under the original rules
        # and records a fresh transaction_submitted event.
        status, body = self.svc.submit_transaction(payload)
        self.assertEqual((status, body), (202, {"tx_id": tx_id}))
        kinds = [event["kind"] for event in self.store.audit_events]
        self.assertEqual(
            kinds,
            [
                EVENT_TRANSACTION_SUBMITTED,
                EVENT_TRANSACTION_CANCELLED,
                EVENT_TRANSACTION_SUBMITTED,
            ],
        )

    def test_other_transactions_and_balances_untouched(self) -> None:
        first = self.submit_legacy(amount=10)
        second = self.submit_legacy(amount=20, key=self.kb, sender=self.B)
        self.cancel(first)
        self.assertNotIn(first, self.store.pending)
        self.assertIn(second, self.store.pending)
        self.assertEqual(self.svc.available_balance(self.A), 1000)
        self.assertEqual(self.svc.available_balance(self.B), 980)

    # -- sequenced transfers ---------------------------------------------------

    def test_sequenced_requires_highest_reserved_nonce(self) -> None:
        ids = [self.submit_sequenced(nonce) for nonce in range(3)]
        # nonce 1 is not the highest reserved nonce.
        status, result = self.cancel(ids[1])
        self.assertEqual((status, result), (409, {"error": "sequence_conflict"}))
        # nonce 0 likewise (and the conflict does not move next_sequence).
        status, result = self.cancel(ids[0])
        self.assertEqual((status, result), (409, {"error": "sequence_conflict"}))
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 3
        )
        # Highest first: nonce 2 then nonce 1, each stepping next_sequence
        # back by one.
        status, _ = self.cancel(ids[2])
        self.assertEqual(status, 200)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 2
        )
        status, _ = self.cancel(ids[1])
        self.assertEqual(status, 200)
        view = self.svc.get_account_sequence(self.A)[1]
        self.assertEqual(view["next_sequence"], 1)
        self.assertEqual(
            view["pending_sequences"], [{"nonce": 0, "tx_id": ids[0]}]
        )
        # The freed nonce can be reused immediately.
        status, body = self.svc.submit_sequenced_transaction(
            sequenced_payload(self.ka, self.A, self.B, 5, 1)
        )
        self.assertEqual(status, 202)
        self.assertEqual(body["nonce"], 1)

    def test_sequenced_event_carries_nonce(self) -> None:
        tx_id = self.submit_sequenced(0)
        status, _ = self.cancel(tx_id)
        self.assertEqual(status, 200)
        event = self.store.audit_events[-1]
        self.assertEqual(event["kind"], EVENT_TRANSACTION_CANCELLED)
        self.assertEqual(event["nonce"], 0)
        self.assertEqual(
            set(event),
            {
                "event_id", "kind", "at", "prev_hash", "event_hash",
                "tx_id", "from", "to", "amount", "signature", "nonce",
            },
        )

    def test_reservation_range_includes_pending_tip(self) -> None:
        ids = [self.submit_sequenced(nonce) for nonce in range(2)]
        # Pack nonces 0 and 1 into the pending tip; nonce 2 stays queued.
        block = self.svc.mine_block()[1]
        top = self.submit_sequenced(2)
        # The highest reserved nonce (2, in the mempool) can be cancelled
        # even though lower nonces sit in the pending tip.
        status, _ = self.cancel(top)
        self.assertEqual(status, 200)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 2
        )
        # nonce 1 is now the highest reserved nonce but lives in the pending
        # block, so it is not cancellable.
        status, result = self.cancel(ids[1])
        self.assertEqual((status, result), (409, {"error": "not_cancellable"}))
        # After rollback nonce 1 is the highest reserved nonce again and can
        # be cancelled.
        self.svc.rollback_block(block["height"])
        status, _ = self.cancel(ids[1])
        self.assertEqual(status, 200)
        self.assertEqual(
            self.svc.get_account_sequence(self.A)[1]["next_sequence"], 1
        )

    # -- atomicity / idempotency ----------------------------------------------

    def test_save_failure_rolls_everything_back(self) -> None:
        tx_id = self.submit_legacy()
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
            with self.assertRaises(OSError):
                self.svc.cancel_transaction(tx_id, cancel_body(self.ka, tx_id))
        finally:
            self.store.save = original
        # Mempool content and order, the audit chain and the generation are
        # exactly as before the request.
        self.assertEqual(dict(self.store.pending), pending_before)
        self.assertEqual(list(self.store.pending), list(pending_before))
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)
        audit.validate_event_chain(self.store.audit_events)
        # The durable file is still recoverable and the tx is still queued.
        reopened = self.reopen()
        self.assertIn(tx_id, reopened.store.pending)

    def test_idempotent_replay_and_conflict(self) -> None:
        tx_id = self.submit_legacy()
        body = cancel_body(self.ka, tx_id)
        target = f"/v1/transactions/{tx_id}/cancel"

        def action():
            return self.svc.cancel_transaction(tx_id, body)

        status, result, replayed, _text = self.svc.execute_idempotent(
            "POST", target, "cancel-key", body, action
        )
        self.assertEqual((status, replayed), (200, False))
        self.assertEqual(result, {"tx_id": tx_id, "status": "cancelled"})
        events = len(self.store.audit_events)
        # Replay: same key, same request -> cached response, no new event.
        status, result2, replayed, _text = self.svc.execute_idempotent(
            "POST", target, "cancel-key", body, action
        )
        self.assertEqual((status, replayed), (200, True))
        self.assertEqual(result2, result)
        self.assertEqual(len(self.store.audit_events), events)
        # Same key, different body -> conflict, no state change.
        other = cancel_body(self.ka, "cd" * 32)
        status, _r, replayed, _t = self.svc.execute_idempotent(
            "POST", target, "cancel-key", other, action
        )
        self.assertEqual((status, replayed), (409, False))
        self.assertEqual(len(self.store.audit_events), events)
        # The replay survives a restart.
        reopened = self.reopen()
        status, result3, replayed, _text = reopened.execute_idempotent(
            "POST", target, "cancel-key", body, action
        )
        self.assertEqual((status, replayed), (200, True))
        self.assertEqual(result3, result)

    def test_idempotent_failure_occupies_no_key(self) -> None:
        tx_id = self.submit_legacy()
        bad = cancel_body(self.kb, tx_id)  # wrong signer
        target = f"/v1/transactions/{tx_id}/cancel"
        status, _r, _p, _t = self.svc.execute_idempotent(
            "POST",
            target,
            "cancel-fail",
            bad,
            lambda: self.svc.cancel_transaction(tx_id, bad),
        )
        self.assertEqual(status, 403)
        self.assertNotIn("cancel-fail", self.store.idempotency)
        self.assertEqual(len(self.store.audit_events), 1)

    def test_idempotent_persistence_failure_is_500(self) -> None:
        tx_id = self.submit_legacy()
        body = cancel_body(self.ka, tx_id)
        target = f"/v1/transactions/{tx_id}/cancel"
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
                "cancel-500",
                body,
                lambda: self.svc.cancel_transaction(tx_id, body),
            )
        finally:
            self.store.save = original
        self.assertEqual((status, replayed), (500, False))
        self.assertEqual(result, {"error": "persistence failed"})
        self.assertNotIn("cancel-500", self.store.idempotency)
        self.assertEqual(dict(self.store.pending), pending_before)
        self.assertEqual(list(self.store.pending), list(pending_before))
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)

    # -- restart / recovery -----------------------------------------------------

    def test_restart_preserves_cancel(self) -> None:
        tx_id = self.submit_legacy()
        self.cancel(tx_id)
        events_before = [dict(event) for event in self.store.audit_events]
        reopened = self.reopen()
        self.assertNotIn(tx_id, reopened.store.pending)
        self.assertEqual(
            [dict(event) for event in reopened.store.audit_events],
            events_before,
        )
        status, _ = reopened.get_transaction(tx_id)
        self.assertEqual(status, 404)

    def _pristine_copy(self) -> str:
        backup = os.path.join(self.tmp, "pristine.json")
        with open(self.state_path, "rb") as src, open(backup, "wb") as dst:
            dst.write(src.read())
        return backup

    def _corrupt(self, backup: str, mutate) -> None:
        with open(backup, encoding="utf-8") as fh:
            doc = json.load(fh)
        mutate(doc)
        # Re-link the hash chain and checkpoint around the tampered payload
        # so the failure is attributed to the cancel-event fact check.
        doc["audit_events"] = audit.link_events(doc["audit_events"])
        doc["audit_checkpoint"] = audit.make_checkpoint(doc["audit_events"])
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)

    def _cancel_event_index(self) -> int:
        for index, event in enumerate(self.store.audit_events):
            if event["kind"] == EVENT_TRANSACTION_CANCELLED:
                return index
        raise AssertionError("no transaction_cancelled event recorded")

    def test_recovery_rejects_bad_cancel_event_fields(self) -> None:
        tx_id = self.submit_legacy()
        self.cancel(tx_id)
        backup = self._pristine_copy()
        index = self._cancel_event_index()
        for mutate in (
            lambda doc: doc["audit_events"][index].__setitem__("amount", 11),
            lambda doc: doc["audit_events"][index].__setitem__("amount", "10"),
            lambda doc: doc["audit_events"][index].__setitem__("from", ""),
            lambda doc: doc["audit_events"][index].__setitem__("tx_id", "g" * 64),
            lambda doc: doc["audit_events"][index].__setitem__("signature", "zz"),
            lambda doc: doc["audit_events"][index].__setitem__("signature", "AB" * 64),
            lambda doc: doc["audit_events"][index].__setitem__("extra", 1),
            lambda doc: doc["audit_events"][index].__delitem__("signature"),
        ):
            self._corrupt(backup, mutate)
            with self.assertRaises(StateRecoveryError, msg=mutate):
                LedgerStore(self.state_path)

    def test_recovery_rejects_tx_id_mismatch_and_bad_signature(self) -> None:
        tx_id = self.submit_legacy()
        self.cancel(tx_id)
        backup = self._pristine_copy()
        index = self._cancel_event_index()
        # tx_id no longer recomputes from the payload.
        self._corrupt(
            backup,
            lambda doc: doc["audit_events"][index].__setitem__("amount", 11),
        )
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)
        # A well-formed but wrong cancellation signature (signed by someone
        # else over this tx_id) fails verification.
        forged = self.kb.sign(crypto.cancel_message(tx_id)).hex()

        def forge(doc):
            doc["audit_events"][index]["signature"] = forged

        self._corrupt(backup, forge)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_recovery_rejects_bad_sequenced_cancel_event(self) -> None:
        tx_id = self.submit_sequenced(0)
        self.cancel(tx_id)
        backup = self._pristine_copy()
        index = self._cancel_event_index()
        for mutate in (
            lambda doc: doc["audit_events"][index].__setitem__("nonce", 1),
            lambda doc: doc["audit_events"][index].__setitem__("nonce", -1),
            lambda doc: doc["audit_events"][index].__delitem__("nonce"),
        ):
            self._corrupt(backup, mutate)
            with self.assertRaises(StateRecoveryError, msg=mutate):
                LedgerStore(self.state_path)

    def test_old_snapshot_without_cancel_events_recovers(self) -> None:
        # A snapshot written before the cancel feature (no
        # transaction_cancelled events) still loads and keeps working.
        tx_id = self.submit_legacy()
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        reopened = self.reopen()
        self.assertEqual(
            [event["kind"] for event in reopened.store.audit_events],
            ["transaction_submitted", "block_mined", "block_confirmed"],
        )
        status, receipt = reopened.get_transaction(tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")

    def test_cancel_does_not_forbid_fork_containing_tx(self) -> None:
        payload = legacy_payload(self.ka, self.A, self.B, 10)
        status, body = self.svc.submit_transaction(payload)
        self.assertEqual(status, 202)
        tx_id = body["tx_id"]
        self.cancel(tx_id)
        # A candidate fork may still legally contain the cancelled
        # transaction: cancellation blacklists nothing.
        from ledger.models import Transaction

        genesis = self.store.chain[0]
        block = Block.create(
            1, genesis.block_hash, [Transaction.from_dict(payload)]
        )
        status, result = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), block.to_dict()]}
        )
        self.assertEqual(status, 201, result)


class CancelHttpTests(unittest.TestCase):
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

    def test_http_cancel_flow_and_idempotency(self) -> None:
        key, pub = keypair()
        payload = legacy_payload(key, pub, self.__class__.__name__, 10)
        status, body, _h, _raw = self.request("POST", "/v1/transactions", payload)
        self.assertEqual(status, 202)
        tx_id = body["tx_id"]
        signed = cancel_body(key, tx_id)
        target = f"/v1/transactions/{tx_id}/cancel"

        # Query parameters are rejected before anything else.
        status, body, _h, _raw = self.request(
            "POST", target + "?x=1", signed
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # Unparseable JSON is 400 input too.
        status, body, _h, _raw = self.request(
            "POST", target, raw=b"{not json"
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # A malformed tx_id is 400 input.
        status, body, _h, _raw = self.request(
            "POST", "/v1/transactions/zz/cancel", signed
        )
        self.assertEqual((status, body), (400, {"error": "input"}))
        # First success echoes the idempotency headers.
        status, body, headers, raw_first = self.request(
            "POST", target, signed, {"Idempotency-Key": "cancel-http-1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, {"status": "cancelled", "tx_id": tx_id})
        self.assertEqual(headers.get("Idempotency-Key"), "cancel-http-1")
        self.assertEqual(headers.get("Idempotency-Replayed"), "false")
        # Replay is byte-identical and flagged.
        status, body2, headers, raw_replay = self.request(
            "POST", target, signed, {"Idempotency-Key": "cancel-http-1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Idempotency-Replayed"), "true")
        self.assertEqual(raw_replay, raw_first)
        self.assertEqual(body2, body)
        # Same key, different body -> 409.
        status, body, _h, _raw = self.request(
            "POST",
            target,
            {"signature": "00" * 64},
            {"Idempotency-Key": "cancel-http-1"},
        )
        self.assertEqual(
            (status, body), (409, {"error": "idempotency key conflict"})
        )
        # Without the key the cancelled transaction is simply gone.
        status, body, _h, _raw = self.request("POST", target, signed)
        self.assertEqual((status, body), (404, {"error": "not_found"}))
        # The single receipt reads not found as well.
        status, _body, _h, _raw = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
