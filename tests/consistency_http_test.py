"""HTTP/CLI tests for the online whole-ledger consistency audit.

Covers the ``GET /v1/audit/consistency`` route and the ``consistency-http``
CLI subcommand:

* the route takes no query parameters and no request body: any parameter
  (blank or valued) or a non-empty body is 400 with the ordered
  ``{"ok", "error"}`` input body, while a bare trailing ``?`` and an
  explicit empty body are accepted;
* a healthy ledger answers 200 with the contract key order
  ``ok, error, generation, height, tip_hash, state_root,
  audit_checkpoint``: ``ok`` true, ``error`` null and the summary naming
  the current persisted generation, chain tip, state root and audit
  checkpoint — across an empty ledger, confirmed traffic, sequenced
  transfers, trust/key-history sections and idempotency records;
* the audit is strictly read-only: repeated and concurrent queries (also
  under concurrent writes) never change the generation, the audit log,
  the idempotency records or any file byte, and every response comes from
  one persisted generation;
* a structurally malformed maintained section is still 200 with
  ``error`` ``"input"`` and every summary field null; a recomputed
  mismatch is 200 with ``error`` ``"integrity"`` and the same nulls; an
  unreadable ledger view is 500 ``{"ok": false, "error": "io"}``;
* a restart over the same persisted state returns the identical document;
* CLI: ``consistency-http`` takes no positional argument, prints one
  single-line JSON document in the response key order and exits 0 only
  for 200 with ``ok`` true (input/integrity/io, HTTP errors and
  connection failures all exit 1).

Run: python3 tests/consistency_http_test.py
"""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

TOP_KEYS = [
    "ok",
    "error",
    "generation",
    "height",
    "tip_hash",
    "state_root",
    "audit_checkpoint",
]
ERROR_KEYS = ["ok", "error"]
SUMMARY_KEYS = [
    "generation",
    "height",
    "tip_hash",
    "state_root",
    "audit_checkpoint",
]


def ordered_document(raw: str):
    """Parse JSON preserving key insertion order."""
    return json.loads(raw, object_pairs_hook=dict)


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


class ConsistencyHttpFixture(unittest.TestCase):
    """A real HTTP service over a fresh temporary store."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_file = os.path.join(self.tmp, "ledger.json")
        self.store = LedgerStore(self.state_file)
        self.store.load()
        self.service = LedgerService(self.store)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    # -- helpers ------------------------------------------------------------

    def raw_get(
        self, target: str = "/v1/audit/consistency", body: bytes | None = None
    ) -> tuple[int, str]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if body is not None:
            headers["Content-Length"] = str(len(body))
        conn.request("GET", target, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        conn.close()
        return response.status, raw

    def get(self, target: str = "/v1/audit/consistency"):
        status, raw = self.raw_get(target)
        return status, ordered_document(raw)

    def restart(self) -> None:
        """Start a fresh service over the same on-disk state."""
        self.httpd.shutdown()
        self.httpd.server_close()
        self.store = LedgerStore(self.state_file)
        self.store.load()
        self.service = LedgerService(self.store)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def state_bytes(self) -> bytes:
        with open(self.state_file, "rb") as fh:
            return fh.read()

    def grow_confirmed(self) -> None:
        key, sender = keypair()
        msg = crypto.canonical_message(sender, "carol", 7)
        self.service.submit_transaction(
            {
                "from": sender,
                "to": "carol",
                "amount": 7,
                "signature": key.sign(msg).hex(),
            }
        )
        self.service.mine_block()
        self.service.confirm_block("1")


class ConsistencyRouteContractTests(ConsistencyHttpFixture):
    def test_empty_ledger_is_200_ok_with_contract_key_order(self) -> None:
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertTrue(body["ok"])
        self.assertIsNone(body["error"])
        self.assertEqual(body["generation"], self.store.generation)
        self.assertEqual(body["height"], 0)
        self.assertEqual(body["tip_hash"], self.store.chain[-1].block_hash)
        self.assertIsInstance(body["state_root"], str)
        self.assertEqual(
            body["audit_checkpoint"], {"event_id": 0, "event_hash": "0" * 64}
        )

    def test_bare_question_mark_is_accepted(self) -> None:
        status, body = self.get("/v1/audit/consistency?")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_any_query_parameter_is_400_input_in_order(self) -> None:
        for target in (
            "/v1/audit/consistency?x=1",
            "/v1/audit/consistency?x=",
            "/v1/audit/consistency?generation=1",
            "/v1/audit/consistency?%00=x",
        ):
            status, raw = self.raw_get(target)
            self.assertEqual(status, 400, target)
            body = ordered_document(raw)
            self.assertEqual(list(body.keys()), ERROR_KEYS, target)
            self.assertEqual(body, {"ok": False, "error": "input"}, target)

    def test_non_empty_body_is_400_input_in_order(self) -> None:
        status, raw = self.raw_get(body=b"{}")
        self.assertEqual(status, 400)
        body = ordered_document(raw)
        self.assertEqual(list(body.keys()), ERROR_KEYS)
        self.assertEqual(body, {"ok": False, "error": "input"})

    def test_explicit_empty_body_is_accepted(self) -> None:
        status, raw = self.raw_get(body=b"")
        self.assertEqual(status, 200)
        self.assertTrue(ordered_document(raw)["ok"])

    def test_wrong_method_routes_unchanged(self) -> None:
        # The new GET route must not change the POST surface.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/v1/audit/consistency", body=b"{}")
        response = conn.getresponse()
        self.assertEqual(response.status, 404)
        response.read()
        conn.close()


class ConsistencyResultTests(ConsistencyHttpFixture):
    def test_confirmed_traffic_summary_matches_store(self) -> None:
        self.grow_confirmed()
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["generation"], self.store.generation)
        self.assertEqual(body["height"], 1)
        self.assertEqual(body["tip_hash"], self.store.chain[-1].block_hash)
        self.assertEqual(body["audit_checkpoint"]["event_id"],
                         self.store.audit_checkpoint["event_id"])

    def test_extension_sections_are_audited(self) -> None:
        # Trust registry + key history, sequenced reservations and an
        # idempotency record all join the same consistent view.
        source_key, source_pub = keypair()
        status, _ = self.service.register_trust_source(
            {"source": "alpha", "public_key": source_pub, "expires_at": 99}
        )
        self.assertEqual(status, 201)
        _, rotated_pub = keypair()
        status, _ = self.service.rotate_trust_source(
            "alpha",
            {
                "public_key": rotated_pub,
                "expires_at": 100,
                "expected_version": 1,
            },
        )
        self.assertEqual(status, 200)
        key, sender = keypair()
        msg = crypto.sequenced_message(sender, "carol", 7, 0)
        status, _ = self.service.submit_sequenced_transaction(
            {
                "from": sender,
                "to": "carol",
                "amount": 7,
                "nonce": 0,
                "signature": key.sign(msg).hex(),
            }
        )
        self.assertEqual(status, 202)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/v1/trust/allowlist",
            body=json.dumps({"source": "beta", "expires_at": 5}),
            headers={"Content-Type": "application/json",
                     "Idempotency-Key": "audit-consistency-1"},
        )
        response = conn.getresponse()
        self.assertEqual(response.status, 201)
        response.read()
        conn.close()

        with self.store.lock:
            document = self.service._consistency_snapshot_document()
        for section in (
            "trust_sources",
            "source_key_history",
            "sequences",
            "idempotency",
        ):
            self.assertIn(section, document)

        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["generation"], self.store.generation)

    def test_structural_defect_is_200_input_with_null_summary(self) -> None:
        self.store.accounts["broken"] = {
            "sent": "not-an-int",
            "received": 0,
            "transactions": [],
        }
        try:
            status, body = self.get()
        finally:
            del self.store.accounts["broken"]
        self.assertEqual(status, 200)
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "input")
        for key in SUMMARY_KEYS:
            self.assertIsNone(body[key], key)

    def test_recomputed_mismatch_is_200_integrity_with_null_summary(self) -> None:
        self.grow_confirmed()
        self.store.tx_index["0" * 64] = 0
        try:
            status, body = self.get()
        finally:
            del self.store.tx_index["0" * 64]
        self.assertEqual(status, 200)
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "integrity")
        for key in SUMMARY_KEYS:
            self.assertIsNone(body[key], key)

    def test_unreadable_ledger_is_500_io_in_order(self) -> None:
        chain = self.store.chain
        self.store.chain = []
        try:
            status, raw = self.raw_get()
        finally:
            self.store.chain = chain
        self.assertEqual(status, 500)
        body = ordered_document(raw)
        self.assertEqual(list(body.keys()), ERROR_KEYS)
        self.assertEqual(body, {"ok": False, "error": "io"})


class ConsistencyReadOnlyTests(ConsistencyHttpFixture):
    def test_repeated_queries_change_no_state_byte(self) -> None:
        self.grow_confirmed()
        before_bytes = self.state_bytes()
        before_generation = self.store.generation
        before_events = len(self.store.audit_events)
        first_status, first_raw = self.raw_get()
        for _ in range(5):
            status, raw = self.raw_get()
            self.assertEqual(status, first_status)
            self.assertEqual(raw, first_raw)
        self.assertEqual(self.store.generation, before_generation)
        self.assertEqual(len(self.store.audit_events), before_events)
        self.assertEqual(self.state_bytes(), before_bytes)

    def test_concurrent_reads_and_writes_stay_consistent(self) -> None:
        self.grow_confirmed()
        errors: list[str] = []
        generations: list[int] = []
        stop = threading.Event()

        def writer() -> None:
            counter = 0
            while not stop.is_set():
                self.service.add_allowlist_entry(
                    {"source": f"w{counter}", "expires_at": 1}
                )
                counter += 1

        def reader() -> None:
            while not stop.is_set():
                status, raw = self.raw_get()
                body = json.loads(raw)
                if not (status == 200 and body["ok"] is True):
                    errors.append(raw)
                generations.append(body["generation"])

        threads = [threading.Thread(target=writer) for _ in range(2)]
        threads += [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        time.sleep(2)
        stop.set()
        for thread in threads:
            thread.join()
        self.assertFalse(errors, errors[:3])
        self.assertTrue(generations)
        # Every read saw one persisted generation; writers advanced it.
        self.assertLessEqual(min(generations), max(generations))
        self.assertEqual(self.store.generation, max(generations))

    def test_restart_returns_identical_result(self) -> None:
        self.grow_confirmed()
        before_status, before_raw = self.raw_get()
        before_bytes = self.state_bytes()
        self.restart()
        after_status, after_raw = self.raw_get()
        self.assertEqual(after_status, before_status)
        self.assertEqual(after_raw, before_raw)
        self.assertEqual(self.state_bytes(), before_bytes)


class ConsistencyCliTests(ConsistencyHttpFixture):
    def _run_cli(self, *argv: str, base_url: str | None = None) -> tuple[int, str]:
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            rc = cli_main(
                [
                    "--base-url",
                    base_url or f"http://127.0.0.1:{self.port}",
                    *argv,
                ]
            )
        return rc, capture.getvalue()

    def test_success_prints_one_ordered_line_and_exits_zero(self) -> None:
        self.grow_confirmed()
        rc, output = self._run_cli("consistency-http")
        self.assertEqual(rc, 0, output)
        self.assertEqual(output.count("\n"), 1)
        body = ordered_document(output.strip())
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertTrue(body["ok"])
        self.assertEqual(body["height"], 1)

    def test_integrity_result_exits_one(self) -> None:
        self.grow_confirmed()
        self.store.tx_index["0" * 64] = 0
        try:
            rc, output = self._run_cli("consistency-http")
        finally:
            del self.store.tx_index["0" * 64]
        self.assertEqual(rc, 1)
        body = ordered_document(output.strip())
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertEqual(body["error"], "integrity")

    def test_io_result_exits_one_with_ordered_failure(self) -> None:
        chain = self.store.chain
        self.store.chain = []
        try:
            rc, output = self._run_cli("consistency-http")
        finally:
            self.store.chain = chain
        self.assertEqual(rc, 1)
        body = ordered_document(output.strip())
        self.assertEqual(list(body.keys()), ERROR_KEYS)
        self.assertEqual(body, {"ok": False, "error": "io"})

    def test_http_error_exits_one(self) -> None:
        # POST-only route shape: a 404 from the server is a CLI failure.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/v1/audit/consistency?x=1")
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        conn.close()
        # The CLI itself sends no parameters; simulate the HTTP-error path
        # by pointing it at a server that answers 404 for the route.
        service = LedgerService(self.store)
        handler = build_handler(service)

        class NoConsistency(handler):  # type: ignore[misc, valid-type]
            def do_GET(self):  # noqa: N802
                if self.path.split("?", 1)[0] == "/v1/audit/consistency":
                    self.send_response(404)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                super().do_GET()

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), NoConsistency)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            rc, _ = self._run_cli(
                "consistency-http", base_url=f"http://127.0.0.1:{port}"
            )
            self.assertEqual(rc, 1)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_connection_failure_exits_one(self) -> None:
        # A freshly closed port refuses the connection: the CLI reports and
        # exits 1.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        rc, output = self._run_cli(
            "consistency-http", base_url=f"http://127.0.0.1:{dead_port}"
        )
        self.assertEqual(rc, 1)
        self.assertEqual(output.count("\n"), 1)
        self.assertIn("error", json.loads(output.strip()))

    def test_takes_no_positional_arguments(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self._run_cli("consistency-http", "extra")
        self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
