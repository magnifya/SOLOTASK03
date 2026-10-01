"""Tests for the four core ledger lifecycle audit events.

Every successful submit / mine / confirm / rollback appends exactly one
``transaction_submitted`` / ``block_mined`` / ``block_confirmed`` /
``block_rolled_back`` event into the existing hash-chained audit log, in the
same atomic persistence as the business change (and, when present, the
Idempotency-Key record). These tests cover event payloads and ordering,
replay without duplication, persistence-failure rollback, strict recovery
validation (types, hex formats, transaction order, referenced facts) and
restart continuity.

Run: python3 tests/lifecycle_audit_events_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import audit, crypto
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


class LifecycleEventServiceTests(unittest.TestCase):
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

    def test_full_lifecycle_event_shapes_and_chain(self) -> None:
        status, body = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        self.assertEqual(status, 202)
        tx_id = body["tx_id"]
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201)
        height = block["height"]
        status, _ = self.svc.confirm_block(height)
        self.assertEqual(status, 200)

        events = self.store.audit_events
        self.assertEqual(
            [event["kind"] for event in events],
            ["transaction_submitted", "block_mined", "block_confirmed"],
        )
        submitted, mined, confirmed = events
        self.assertEqual(
            set(submitted),
            {
                "event_id", "kind", "at", "prev_hash", "event_hash",
                "tx_id", "from", "to", "amount",
            },
        )
        self.assertEqual(
            (submitted["tx_id"], submitted["from"], submitted["to"], submitted["amount"]),
            (tx_id, self.A, self.B, 10),
        )
        self.assertEqual(crypto.compute_tx_id(crypto.canonical_message(self.A, self.B, 10)), tx_id)
        self.assertEqual(
            set(mined),
            {
                "event_id", "kind", "at", "prev_hash", "event_hash",
                "height", "block_hash", "merkle_root", "transaction_ids",
            },
        )
        self.assertEqual(
            (mined["height"], mined["block_hash"], mined["merkle_root"], mined["transaction_ids"]),
            (height, block["block_hash"], block["merkle_root"], [tx_id]),
        )
        self.assertEqual(
            set(confirmed),
            {"event_id", "kind", "at", "prev_hash", "event_hash", "height", "block_hash"},
        )
        self.assertEqual((confirmed["height"], confirmed["block_hash"]), (height, block["block_hash"]))
        # Dense ids and hash links.
        audit.validate_event_chain(events)
        audit.validate_checkpoint(self.store.audit_checkpoint, events)
        self.assertEqual(submitted["prev_hash"], "0" * 64)
        self.assertEqual(mined["prev_hash"], submitted["event_hash"])
        self.assertEqual(confirmed["prev_hash"], mined["event_hash"])

    def test_idempotent_reconfirm_appends_nothing(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        after_first = len(self.store.audit_events)
        self.assertEqual(self.svc.confirm_block(block["height"])[0], 200)
        self.assertEqual(len(self.store.audit_events), after_first)

    def test_failed_requests_append_no_events(self) -> None:
        before = len(self.store.audit_events)
        bad_sig = make_tx(self.ka, self.A, self.B, 10)
        bad_sig["signature"] = "0" * 128
        self.assertEqual(self.svc.submit_transaction(bad_sig)[0], 400)
        self.assertEqual(
            self.svc.submit_transaction(
                {"from": self.A, "to": self.B, "amount": -1, "signature": "0" * 128}
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10 ** 9))[0], 400
        )
        self.assertEqual(self.svc.mine_block()[0], 409)  # empty mempool
        self.assertEqual(self.svc.confirm_block(99)[0], 409)
        self.assertEqual(self.svc.rollback_block(99)[0], 404)
        self.assertEqual(self.svc.rollback_block(0)[0], 409)
        self.assertEqual(len(self.store.audit_events), before)

    def test_duplicate_submission_appends_no_event(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 10)
        self.assertEqual(self.svc.submit_transaction(payload)[0], 202)
        self.assertEqual(self.svc.submit_transaction(payload)[0], 409)
        self.assertEqual(
            [event["kind"] for event in self.store.audit_events],
            ["transaction_submitted"],
        )

    def test_rollback_event_records_restored_ids_in_block_order(self) -> None:
        one = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))[1]["tx_id"]
        two = self.svc.submit_transaction(make_tx(self.kb, self.B, self.A, 4))[1]["tx_id"]
        block = self.svc.mine_block()[1]
        ordered = sorted([one, two])
        status, body = self.svc.rollback_block(block["height"])
        self.assertEqual(status, 200)
        event = self.store.audit_events[-1]
        self.assertEqual(event["kind"], "block_rolled_back")
        self.assertEqual(event["height"], block["height"])
        self.assertEqual(event["block_hash"], block["block_hash"])
        # Both transactions actually returned, in ascending block order.
        self.assertEqual(event["transaction_ids"], ordered)

    def test_rollback_event_excludes_already_present_ids(self) -> None:
        from ledger.models import Transaction

        payload = make_tx(self.ka, self.A, self.B, 10)
        self.svc.submit_transaction(payload)
        block = self.svc.mine_block()[1]
        tx_id = self.store.chain[block["height"]].transactions[0].tx_id
        # Pre-seed the mempool with the same id, as rollback_tip
        # de-duplicates it: the restored event list is then empty.
        self.store.pending[tx_id] = Transaction(
            payload["from"], payload["to"], payload["amount"], payload["signature"]
        )
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 200)
        event = self.store.audit_events[-1]
        self.assertEqual(event["kind"], "block_rolled_back")
        self.assertEqual(event["transaction_ids"], [])

    def test_events_survive_restart(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        expected = [dict(event) for event in self.store.audit_events]
        reopened = self.reopen()
        self.assertEqual(
            [dict(event) for event in reopened.store.audit_events], expected
        )
        self.assertEqual(reopened.store.audit_checkpoint, self.store.audit_checkpoint)

    def test_save_failure_trims_event_and_restores_state(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        block = self.svc.mine_block()[1]
        for operation in ("confirm", "rollback"):
            if operation == "rollback":
                self.svc.rollback_block(block["height"])
                block = self.svc.mine_block()[1]
            events_before = len(self.store.audit_events)
            chain_before = len(self.svc.store.chain)
            pending_before = set(self.svc.store.pending)
            generation_before = self.svc.store.generation

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
                    if operation == "confirm":
                        self.svc.confirm_block(block["height"])
                    else:
                        self.svc.rollback_block(block["height"])
            finally:
                self.store.save = original
            self.assertEqual(len(self.store.audit_events), events_before)
            self.assertEqual(len(self.store.chain), chain_before)
            self.assertEqual(set(self.store.pending), pending_before)
            self.assertEqual(self.store.generation, generation_before)
            audit.validate_event_chain(self.store.audit_events)
            # The durable file is still recoverable.
            self.reopen()

    def test_idempotent_first_success_appends_one_replay_none(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 3)

        def action():
            return self.svc.submit_transaction(payload)

        status, _result, replayed, _text = self.svc.execute_idempotent(
            "POST", "/v1/transactions", "key-1", payload, action
        )
        self.assertEqual((status, replayed), (202, False))
        self.assertEqual(
            [event["kind"] for event in self.store.audit_events],
            ["transaction_submitted"],
        )
        status, _result, replayed, _text = self.svc.execute_idempotent(
            "POST", "/v1/transactions", "key-1", payload, action
        )
        self.assertEqual((status, replayed), (202, True))
        self.assertEqual(len(self.store.audit_events), 1)
        # Same key, different body: conflict, no event.
        other = make_tx(self.ka, self.A, self.B, 4)
        status, _result, replayed, _text = self.svc.execute_idempotent(
            "POST", "/v1/transactions", "key-1", other,
            lambda: self.svc.submit_transaction(other),
        )
        self.assertEqual((status, replayed), (409, False))
        self.assertEqual(len(self.store.audit_events), 1)

    def test_idempotent_non_success_occupies_no_key_and_appends_none(self) -> None:
        bad = make_tx(self.ka, self.A, self.B, 10 ** 9)

        def action():
            return self.svc.submit_transaction(bad)

        status, _result, _replayed, _text = self.svc.execute_idempotent(
            "POST", "/v1/transactions", "key-bad", bad, action
        )
        self.assertEqual(status, 400)
        self.assertNotIn("key-bad", self.store.idempotency)
        self.assertEqual(self.store.audit_events, [])

    # -- strict recovery validation ----------------------------------------

    def _pristine_copy(self) -> str:
        """Copy the current (valid) state file to a pristine backup path."""
        backup = os.path.join(self.tmp, "pristine.json")
        with open(self.state_path, "rb") as src, open(backup, "wb") as dst:
            dst.write(src.read())
        return backup

    def _corrupt(self, backup: str, mutate) -> None:
        """Write a tampered, re-linked copy of the pristine snapshot."""
        with open(backup, encoding="utf-8") as fh:
            doc = json.load(fh)
        mutate(doc)
        # Re-link the hash chain and checkpoint around the tampered payload so
        # the failure is attributed to the lifecycle fact check, not the link.
        doc["audit_events"] = audit.link_events(doc["audit_events"])
        doc["audit_checkpoint"] = audit.make_checkpoint(doc["audit_events"])
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)

    def _seed_pending_mined(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        self.svc.mine_block()

    def test_recovery_rejects_bad_transaction_payload(self) -> None:
        self._seed_pending_mined()
        backup = self._pristine_copy()
        for mutate in (
            lambda doc: doc["audit_events"][0].__setitem__("amount", 11),
            lambda doc: doc["audit_events"][0].__setitem__("amount", "10"),
            lambda doc: doc["audit_events"][0].__setitem__("from", ""),
            lambda doc: doc["audit_events"][0].__setitem__("tx_id", "g" * 64),
            lambda doc: doc["audit_events"][0].__setitem__("extra", 1),
        ):
            self._corrupt(backup, mutate)
            with self.assertRaises(StateRecoveryError):
                LedgerStore(self.state_path)

    def test_recovery_rejects_tx_id_mismatch(self) -> None:
        self._seed_pending_mined()
        backup = self._pristine_copy()
        self._corrupt(backup, lambda doc: doc["audit_events"][0].__setitem__("amount", 11))
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_recovery_rejects_bad_block_mined_payload(self) -> None:
        self._seed_pending_mined()
        backup = self._pristine_copy()
        for mutate in (
            lambda doc: doc["audit_events"][1].__setitem__("merkle_root", "0" * 64),
            lambda doc: doc["audit_events"][1].__setitem__("height", 0),
            lambda doc: doc["audit_events"][1].__setitem__("block_hash", "x"),
            lambda doc: doc["audit_events"][1]["transaction_ids"].append(
                doc["audit_events"][1]["transaction_ids"][0]
            ),
        ):
            self._corrupt(backup, mutate)
            with self.assertRaises(StateRecoveryError):
                LedgerStore(self.state_path)

    def test_recovery_rejects_forged_confirmation(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        backup = self._pristine_copy()
        self._corrupt(
            backup,
            lambda doc: next(
                event
                for event in doc["audit_events"]
                if event["kind"] == "block_confirmed"
            ).__setitem__("block_hash", "a" * 64),
        )
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)

    def test_recovery_rejects_rollback_id_outside_block(self) -> None:
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        block = self.svc.mine_block()[1]
        self.svc.rollback_block(block["height"])
        backup = self._pristine_copy()
        self._corrupt(
            backup,
            lambda doc: next(
                event
                for event in doc["audit_events"]
                if event["kind"] == "block_rolled_back"
            ).__setitem__("transaction_ids", ["f" * 64]),
        )
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path)


class LifecycleEventHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method: str, path: str, payload=None, headers=None):
        import urllib.error
        import urllib.request

        url = f"{self.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode()), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode()), dict(exc.headers)

    def test_events_visible_per_kind_and_export_verifies(self) -> None:
        status, body, _ = self.request("POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 7))
        self.assertEqual(status, 202)
        status, block, _ = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        height = block["height"]
        status, _, _ = self.request("POST", f"/v1/blocks/{height}/confirm", {})
        self.assertEqual(status, 200)
        for kind in ("transaction_submitted", "block_mined", "block_confirmed"):
            status, page, _ = self.request("GET", f"/v1/audit/events?kind={quote(kind)}")
            self.assertEqual(status, 200)
            self.assertGreaterEqual(page["total"], 1)
            self.assertTrue(all(item["kind"] == kind for item in page["items"]))
        status, export_page, _ = self.request("GET", "/v1/audit/export?limit=200")
        self.assertEqual(status, 200)
        self.assertTrue(audit.verify_export(export_page)["ok"])

    def test_idempotency_key_appends_exactly_one_submission_event(self) -> None:
        payload = make_tx(self.kb, self.B, self.A, 2)
        status, _, headers = self.request(
            "POST", "/v1/transactions", payload, {"Idempotency-Key": "lc-http-key"}
        )
        self.assertEqual(status, 202)
        self.assertEqual(headers.get("Idempotency-Replayed"), "false")
        status, _, headers = self.request(
            "POST", "/v1/transactions", payload, {"Idempotency-Key": "lc-http-key"}
        )
        self.assertEqual(status, 202)
        self.assertEqual(headers.get("Idempotency-Replayed"), "true")
        _, before, _ = self.request("GET", "/v1/audit/events?kind=transaction_submitted")
        self.request(
            "POST", "/v1/transactions", payload, {"Idempotency-Key": "lc-http-key"}
        )
        _, after, _ = self.request("GET", "/v1/audit/events?kind=transaction_submitted")
        self.assertEqual(after["total"], before["total"])


if __name__ == "__main__":
    unittest.main()
