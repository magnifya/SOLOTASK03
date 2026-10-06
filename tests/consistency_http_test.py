"""Tests for the online consistency audit endpoint and its CLI wrapper.

Covers ``GET /v1/audit/consistency`` and
``python -m ledger.cli consistency-http``:

* a healthy ledger answers 200 with the fixed key order
  ``ok,error,generation,height,tip_hash,state_root,audit_checkpoint`` and
  the same-generation summary; the result is identical to the offline
  ``verify_snapshot`` of the persisted snapshot and is stable across a
  restart on the same persisted state;
* the endpoint takes no query parameters and no request body: any
  parameter (including a blank one) or a non-empty body is 400
  ``{"ok": false, "error": "input"}``; a bare trailing ``?`` is accepted;
* the audit is read-only: no generation advance, no audit event, no
  idempotency record and no snapshot file rewrite;
* a structurally corrupt in-memory snapshot section is 200
  ``error="input"`` and a recomputed-value mismatch is 200
  ``error="integrity"`` — both with every summary field null; a ledger
  that cannot be read answers 500 ``{"ok": false, "error": "io"}``;
* the CLI prints the response as one JSON line in its original key order
  and exits 0 only on HTTP 200 with ``ok`` true; ``input``/``integrity``/
  ``io``, HTTP errors and connection failures all exit 1.

Run: python3 tests/consistency_http_test.py
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.consistency import verify_snapshot
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

RESULT_KEYS = (
    "ok",
    "error",
    "generation",
    "height",
    "tip_hash",
    "state_root",
    "audit_checkpoint",
)
SUMMARY_KEYS = ("generation", "height", "tip_hash", "state_root", "audit_checkpoint")
FUTURE = 1_900_000_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(msg).hex(),
    }


class HttpFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.start_service(LedgerStore(self.state_path, initial_balance=1000))

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def start_service(self, store: LedgerStore) -> None:
        self.store = store
        self.service = LedgerService(store, initial_balance=1000)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def restart_service(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.start_service(LedgerStore(self.state_path, initial_balance=1000))

    def request(self, target: str, body: object = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request("GET", target, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        conn.close()
        return response.status, json.loads(raw.decode("utf-8")), raw

    def get(self, target: str = "/v1/audit/consistency"):
        status, payload, _ = self.request(target)
        return status, payload

    def _confirm_tx(self, amount: int = 10) -> None:
        self.service.submit_transaction(signed_tx(self.ka, self.A, self.B, amount))
        block = self.service.mine_block()[1]
        self.service.confirm_block(block["height"])

    def load_snapshot(self) -> dict:
        with open(self.state_path, encoding="utf-8") as fh:
            return json.load(fh)


class HealthyAuditTests(HttpFixture):
    def test_genesis_ledger_verifies(self) -> None:
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertEqual(tuple(body.keys()), RESULT_KEYS)
        self.assertTrue(body["ok"])
        self.assertIsNone(body["error"])
        self.assertEqual(body["generation"], self.store.generation)
        self.assertEqual(body["height"], 0)
        self.assertEqual(body["tip_hash"], self.store.tip_hash())
        self.assertTrue(crypto.is_hex64(body["state_root"]))
        self.assertEqual(
            body["audit_checkpoint"], {"event_id": 0, "event_hash": "0" * 64}
        )

    def test_busy_ledger_verifies_and_matches_offline(self) -> None:
        self._confirm_tx(10)
        self.service.submit_transaction(signed_tx(self.kb, self.B, self.A, 3))
        self.assertEqual(
            self.service.register_trust_source(
                {"source": "node-1", "public_key": "ab" * 32, "expires_at": FUTURE}
            )[0],
            201,
        )
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"], body)
        self.assertEqual(tuple(body.keys()), RESULT_KEYS)
        self.assertEqual(body["height"], 1)
        self.assertEqual(body["generation"], self.store.generation)
        self.assertEqual(body["tip_hash"], self.store.tip_hash())
        self.assertEqual(body["audit_checkpoint"], self.store.audit_checkpoint)
        # The online audit of the current state is exactly the offline
        # verification of the persisted snapshot.
        self.assertEqual(body, verify_snapshot(self.load_snapshot()))

    def test_pending_tip_verifies(self) -> None:
        self.service.submit_transaction(signed_tx(self.ka, self.A, self.B, 5))
        self.service.mine_block()  # pending tip, never confirmed
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["height"], 1)

    def test_restart_keeps_same_result(self) -> None:
        self._confirm_tx(7)
        first = self.get()
        self.restart_service()
        second = self.get()
        self.assertEqual(first, second)
        self.assertTrue(second[1]["ok"])

    def test_bare_trailing_question_mark_is_accepted(self) -> None:
        status, body = self.get("/v1/audit/consistency?")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_audit_is_read_only(self) -> None:
        self._confirm_tx(10)
        generation = self.store.generation
        events = len(self.store.audit_events)
        idempotency = dict(self.store.idempotency)
        with open(self.state_path, "rb") as fh:
            snapshot_bytes = fh.read()
        self.get()
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(len(self.store.audit_events), events)
        self.assertEqual(self.store.idempotency, idempotency)
        with open(self.state_path, "rb") as fh:
            self.assertEqual(fh.read(), snapshot_bytes)


class RequestShapeTests(HttpFixture):
    def assert_input_400(self, target: str, body: object = None) -> None:
        status, payload = self.request(target, body)[:2]
        self.assertEqual(status, 400, target)
        self.assertEqual(payload, {"ok": False, "error": "input"}, target)

    def test_query_parameters_are_rejected(self) -> None:
        for target in (
            "/v1/audit/consistency?x=1",
            "/v1/audit/consistency?x",
            "/v1/audit/consistency?x=",
            "/v1/audit/consistency?generation=1",
            "/v1/audit/consistency?x=1&y=2",
        ):
            self.assert_input_400(target)

    def test_non_empty_body_is_rejected(self) -> None:
        self.assert_input_400("/v1/audit/consistency", {"a": 1})
        self.assert_input_400("/v1/audit/consistency", [])

    def test_rejection_has_no_side_effects(self) -> None:
        generation = self.store.generation
        events = len(self.store.audit_events)
        self.assert_input_400("/v1/audit/consistency?x=1")
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(len(self.store.audit_events), events)


class FailureCategoryTests(HttpFixture):
    def assert_failure(self, error: str) -> None:
        status, body = self.get()
        self.assertEqual(status, 200, body)
        self.assertEqual(tuple(body.keys()), RESULT_KEYS)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], error)
        for key in SUMMARY_KEYS:
            self.assertIsNone(body[key], key)

    def test_structural_type_defect_is_input(self) -> None:
        saved = self.store.audit_checkpoint
        self.store.audit_checkpoint = ["not-a-dict"]
        try:
            self.assert_failure("input")
        finally:
            self.store.audit_checkpoint = saved

    def test_wrong_generation_type_is_input(self) -> None:
        saved = self.store.generation
        self.store.generation = str(saved)
        try:
            self.assert_failure("input")
        finally:
            self.store.generation = saved

    def test_derived_index_mismatch_is_integrity(self) -> None:
        self._confirm_tx(10)
        self.store.tx_index["f" * 64] = 0
        try:
            self.assert_failure("integrity")
        finally:
            del self.store.tx_index["f" * 64]

    def test_checkpoint_mismatch_is_integrity(self) -> None:
        saved = self.store.audit_checkpoint
        self.store.audit_checkpoint = {"event_id": 99, "event_hash": "1" * 64}
        try:
            self.assert_failure("integrity")
        finally:
            self.store.audit_checkpoint = saved

    def test_unreadable_ledger_is_io(self) -> None:
        def boom():
            raise RuntimeError("cannot read ledger")

        saved = self.store.current_snapshot_document
        self.store.current_snapshot_document = boom
        try:
            status, body = self.get()
            self.assertEqual(status, 500)
            self.assertEqual(body, {"ok": False, "error": "io"})
        finally:
            self.store.current_snapshot_document = saved


class ConsistencyHttpCliTests(HttpFixture):
    def run_cli(self, *args: str) -> tuple[int, str]:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ledger.cli",
                "--base-url",
                f"http://127.0.0.1:{self.port}",
                "consistency-http",
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.stderr, "")
        lines = proc.stdout.strip().splitlines()
        self.assertEqual(len(lines), 1)
        return proc.returncode, lines[0]

    def test_healthy_exit_0_ordered_keys(self) -> None:
        self._confirm_tx(10)
        code, line = self.run_cli()
        self.assertEqual(code, 0, line)
        body = json.loads(line)
        self.assertTrue(body["ok"])
        # The line preserves the contract key order.
        self.assertEqual(list(body.keys()), list(RESULT_KEYS))

    def test_integrity_exit_1(self) -> None:
        self._confirm_tx(10)
        self.store.tx_index["f" * 64] = 0
        try:
            code, line = self.run_cli()
        finally:
            del self.store.tx_index["f" * 64]
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(line)["error"], "integrity")

    def test_io_exit_1(self) -> None:
        saved = self.store.current_snapshot_document
        self.store.current_snapshot_document = lambda: 1 / 0
        try:
            code, line = self.run_cli()
        finally:
            self.store.current_snapshot_document = saved
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "io"})

    def test_http_error_exit_1(self) -> None:
        # A server answering 500 for every request: the CLI prints the
        # error body and exits 1.
        from http.server import BaseHTTPRequestHandler

        class Always500(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
                data = b'{"ok": false, "error": "io"}'
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args) -> None:
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Always500)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ledger.cli",
                    "--base-url",
                    f"http://127.0.0.1:{httpd.server_address[1]}",
                    "consistency-http",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(
                json.loads(proc.stdout.strip()), {"ok": False, "error": "io"}
            )
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_connection_failure_exit_1(self) -> None:
        # An unreachable server yields the (0, {"error": ...}) sentinel from
        # _request; the command prints it and exits 1. Patched at the Python
        # level so the test does not depend on how the platform reports a
        # refused connection.
        import contextlib
        import io
        import types

        from ledger import cli

        args = types.SimpleNamespace(base_url="http://127.0.0.1:1")
        original = cli._request
        cli._request = lambda *a, **k: (
            0,
            {"error": "cannot reach ledger server: refused"},
        )
        try:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = cli.cmd_consistency_http(args)
        finally:
            cli._request = original
        self.assertEqual(code, 1)
        lines = stdout.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn("error", json.loads(lines[0]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
