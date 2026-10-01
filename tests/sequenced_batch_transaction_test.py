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

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import EVENT_TRANSACTION_SUBMITTED, LedgerService
from ledger.store import LedgerStore


def keypair():
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, public


def sequenced(key, sender, recipient, amount, nonce):
    message = crypto.sequenced_message(sender, recipient, amount, nonce)
    return {
        "from": sender,
        "to": recipient,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(message).hex(),
    }


class SequencedBatchServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )

    def batch(self, items):
        return self.svc.submit_sequenced_transaction_batch(
            {"transactions": items}
        )

    def tx_id(self, item):
        return crypto.compute_tx_id(
            crypto.sequenced_message(
                item["from"], item["to"], item["amount"], item["nonce"]
            )
        )

    def test_valid_interleaved_batch_is_atomic_and_ordered(self):
        items = [
            sequenced(self.ka, self.A, self.B, 10, 0),
            sequenced(self.kb, self.B, self.A, 20, 0),
            sequenced(self.ka, self.A, self.B, 5, 1),
        ]
        status, body = self.batch(items)
        self.assertEqual(status, 202)
        self.assertEqual(list(body), ["items", "total"])
        self.assertEqual(body["total"], 3)
        self.assertEqual(
            body["items"],
            [
                {"tx_id": self.tx_id(items[0]), "nonce": 0},
                {"tx_id": self.tx_id(items[1]), "nonce": 0},
                {"tx_id": self.tx_id(items[2]), "nonce": 1},
            ],
        )
        self.assertEqual(len(self.svc.store.pending), 3)
        self.assertEqual(self.svc.get_account_sequence(self.A)[1]["next_sequence"], 2)
        self.assertEqual(self.svc.get_account_sequence(self.B)[1]["next_sequence"], 1)
        submitted = [
            event for event in self.svc.store.audit_events
            if event["kind"] == EVENT_TRANSACTION_SUBMITTED
        ]
        self.assertEqual(len(submitted), 3)

    def test_whole_existing_batch_replays_with_locations(self):
        items = [
            sequenced(self.ka, self.A, self.B, 10, 0),
            sequenced(self.ka, self.A, self.B, 5, 1),
        ]
        self.assertEqual(self.batch(items)[0], 202)
        status, retry = self.batch(list(reversed(items)))
        self.assertEqual(status, 200)
        self.assertEqual(
            retry["items"],
            [
                {"tx_id": self.tx_id(items[1]), "nonce": 1, "location": "pending"},
                {"tx_id": self.tx_id(items[0]), "nonce": 0, "location": "pending"},
            ],
        )

        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])
        status, confirmed_retry = self.batch(items)
        self.assertEqual(status, 200)
        self.assertEqual(
            {item["location"] for item in confirmed_retry["items"]},
            {"confirmed"},
        )

    def test_partial_existing_batch_is_rejected_without_new_state(self):
        existing = sequenced(self.ka, self.A, self.B, 10, 0)
        self.batch([existing])
        fresh = sequenced(self.ka, self.A, self.B, 5, 1)

        status, body = self.batch([fresh, existing])
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "transaction_exists", "index": 1})
        self.assertNotIn(self.tx_id(fresh), self.svc.store.pending)
        self.assertEqual(self.svc.get_account_sequence(self.A)[1]["next_sequence"], 1)

    def test_partial_existing_batch_still_checks_new_sequence_and_balance(self):
        existing = sequenced(self.ka, self.A, self.B, 10, 0)
        self.batch([existing])

        continuation = sequenced(self.ka, self.A, self.B, 5, 1)
        status, body = self.batch([existing, continuation])
        self.assertEqual(
            (status, body),
            (409, {"error": "transaction_exists", "index": 0}),
        )
        self.assertNotIn(self.tx_id(continuation), self.svc.store.pending)

        stale = sequenced(self.ka, self.A, self.B, 5, 0)
        status, body = self.batch([existing, stale])
        self.assertEqual(
            (status, body),
            (409, {"error": "sequence_conflict", "index": 1, "next_sequence": 1}),
        )

        overspend = sequenced(self.ka, self.A, self.B, 1000, 1)
        status, body = self.batch([existing, overspend])
        self.assertEqual(
            (status, body),
            (409, {"error": "insufficient_balance", "index": 1}),
        )

    def test_self_transfer_credit_does_not_offset_batch_spend(self):
        status, body = self.batch([
            sequenced(self.ka, self.A, self.A, 600, 0),
            sequenced(self.ka, self.A, self.B, 600, 1),
        ])
        self.assertEqual(
            (status, body),
            (409, {"error": "insufficient_balance", "index": 0}),
        )

    def test_field_signature_and_duplicate_indexes(self):
        cases = [
            ({"transactions": []}, {"error": "input"}),
            ([], {"error": "input"}),
            ({"transactions": [{}]}, {"error": "input", "index": 0}),
        ]
        for payload, expected in cases:
            self.assertEqual(
                self.svc.submit_sequenced_transaction_batch(payload),
                (400, expected),
            )

        good = sequenced(self.ka, self.A, self.B, 10, 0)
        bad_field = dict(good)
        bad_field["extra"] = True
        status, body = self.batch([good, bad_field])
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))

        bad_signature = sequenced(self.ka, self.A, self.B, 10, 1)
        bad_signature["signature"] = "00" * 64
        status, body = self.batch([good, bad_signature])
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))

        status, body = self.batch([good, dict(good)])
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))

    def test_sequence_errors_use_batch_semantics(self):
        status, body = self.batch([
            sequenced(self.ka, self.A, self.B, 1, 1),
            sequenced(self.ka, self.A, self.B, 1, 2),
        ])
        self.assertEqual(
            (status, body),
            (409, {"error": "sequence_conflict", "index": 0, "next_sequence": 0}),
        )

        status, body = self.batch([
            sequenced(self.ka, self.A, self.B, 1, 0),
            sequenced(self.kb, self.B, self.A, 1, 1),
        ])
        self.assertEqual(
            (status, body),
            (409, {"error": "sequence_conflict", "index": 1, "next_sequence": 0}),
        )

        status, body = self.batch([
            sequenced(self.ka, self.A, self.B, 1, 0),
            sequenced(self.ka, self.A, self.B, 2, 0),
        ])
        self.assertEqual(
            (status, body),
            (409, {"error": "sequence_conflict", "index": 1, "next_sequence": 0}),
        )

        status, body = self.batch([
            sequenced(self.ka, self.A, self.B, 1, 0),
            sequenced(self.ka, self.A, self.B, 1, 2),
            sequenced(self.ka, self.A, self.B, 1, 1),
        ])
        self.assertEqual((status, body), (400, {"error": "input", "index": 1}))

        self.batch([sequenced(self.ka, self.A, self.B, 1, 0)])
        status, body = self.batch([sequenced(self.ka, self.A, self.B, 2, 0)])
        self.assertEqual(
            (status, body),
            (409, {"error": "sequence_conflict", "index": 0, "next_sequence": 1}),
        )

    def test_balance_is_checked_against_total_batch_spend(self):
        status, body = self.batch([
            sequenced(self.ka, self.A, self.B, 600, 0),
            sequenced(self.ka, self.A, self.B, 600, 1),
        ])
        self.assertEqual(
            (status, body),
            (409, {"error": "insufficient_balance", "index": 0}),
        )
        self.assertEqual(self.svc.store.pending, {})

    def test_persistence_failure_rolls_back_entire_batch(self):
        original_save = self.svc.store.save
        self.svc.store.save = lambda: (_ for _ in ()).throw(RuntimeError("disk"))
        try:
            status, body = self.batch([
                sequenced(self.ka, self.A, self.B, 1, 0),
                sequenced(self.kb, self.B, self.A, 1, 0),
            ])
        finally:
            self.svc.store.save = original_save
        self.assertEqual((status, body), (500, {"error": "persistence failed"}))
        self.assertEqual(self.svc.store.pending, {})
        self.assertEqual(self.svc.store.audit_events, [])

    def test_batch_survives_restart_and_packs_confirms(self):
        items = [
            sequenced(self.ka, self.A, self.B, 11, 0),
            sequenced(self.ka, self.A, self.B, 7, 1),
            sequenced(self.kb, self.B, self.A, 3, 0),
        ]
        _, body = self.batch(items)
        tx_ids = [item["tx_id"] for item in body["items"]]

        restarted = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        self.assertEqual(set(restarted.store.pending), set(tx_ids))
        self.assertEqual(restarted.get_account_sequence(self.A)[1]["next_sequence"], 2)
        self.assertEqual(restarted.get_account_sequence(self.B)[1]["next_sequence"], 1)

        block = restarted.mine_block()[1]
        restarted.confirm_block(block["height"])
        confirmed = LedgerService(
            LedgerStore(self.state_path), initial_balance=1000
        )
        self.assertEqual(confirmed.get_account_sequence(self.A)[1]["next_sequence"], 2)
        self.assertEqual(confirmed.get_account_sequence(self.B)[1]["next_sequence"], 1)
        self.assertEqual(
            [p["nonce"] for p in confirmed.get_account_sequence(self.A)[1]["confirmed_sequences"]],
            [0, 1],
        )
        self.assertEqual(confirmed.store.pending, {})

    def test_batch_participates_in_tip_rollback(self):
        items = [
            sequenced(self.ka, self.A, self.B, 11, 0),
            sequenced(self.ka, self.A, self.B, 7, 1),
        ]
        _, body = self.batch(items)
        tx_ids = [item["tx_id"] for item in body["items"]]

        block = self.svc.mine_block()[1]
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 200)
        self.assertEqual(set(self.svc.store.pending), set(tx_ids))
        self.assertEqual(
            [p["nonce"] for p in self.svc.get_account_sequence(self.A)[1]["pending_sequences"]],
            [0, 1],
        )


class SequencedBatchHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
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
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, payload, key=None):
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if key is not None:
            headers["Idempotency-Key"] = key
        req = urllib.request.Request(
            f"{self.base}/v1/transactions/sequenced/batch",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as response:
                return (
                    response.status,
                    json.loads(response.read().decode()),
                    response.headers.get("Idempotency-Replayed"),
                )
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode()), None

    def test_http_batch_and_idempotency_replay(self):
        payload = {
            "transactions": [
                sequenced(self.ka, self.A, self.B, 10, 0),
                sequenced(self.kb, self.B, self.A, 2, 0),
            ]
        }
        status, first, replayed = self.request(payload, key="batch-1")
        self.assertEqual(status, 202)
        self.assertEqual(replayed, "false")
        status, replay, replayed = self.request(payload, key="batch-1")
        self.assertEqual(status, 202)
        self.assertEqual(replay, first)
        self.assertEqual(replayed, "true")

    def test_same_key_concurrency_executes_batch_once(self):
        payload = {"transactions": [sequenced(self.ka, self.A, self.B, 3, 1)]}
        barrier = threading.Barrier(4)
        results = []

        def worker():
            barrier.wait()
            results.append(self.request(payload, key="concurrent-batch"))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(result[0] for result in results), [202] * 4)
        self.assertEqual(sum(result[2] == "false" for result in results), 1)
        self.assertEqual(sum(result[2] == "true" for result in results), 3)


class SequencedBatchCliTests(unittest.TestCase):
    def run_cli(self, *argv):
        from io import StringIO

        original_stdout = sys.stdout
        captured = StringIO()
        sys.stdout = captured
        try:
            code = cli_main(list(argv))
        finally:
            sys.stdout = original_stdout
        return code, captured.getvalue().strip()

    def test_missing_file_is_input_without_server(self):
        code, output = self.run_cli(
            "--base-url", "http://127.0.0.1:1",
            "send-sequenced-batch", "--file",
            os.path.join(tempfile.gettempdir(), "definitely-absent-ledger-batch.json"),
        )
        self.assertEqual(code, 1)
        self.assertEqual(output, json.dumps({"error": "input"}))

    def test_invalid_stdin_json_is_input_without_server(self):
        from io import StringIO

        original_stdin = sys.stdin
        sys.stdin = StringIO("{not-json")
        try:
            code, output = self.run_cli(
                "--base-url", "http://127.0.0.1:1",
                "send-sequenced-batch", "--file", "-",
            )
        finally:
            sys.stdin = original_stdin
        self.assertEqual(code, 1)
        self.assertEqual(output, json.dumps({"error": "input"}))


if __name__ == "__main__":
    unittest.main()
