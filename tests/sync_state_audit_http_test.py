"""HTTP/CLI tests for the read-only sync-state audit surface.

Covers:

* GET /v1/light-client/sync-state takes no parameters: any query string
  (including a blank value) answers 400 with the ordered
  ``{"ok", "error"}`` input body; a bare trailing ``?`` carries none;
* unconfigured node (no ``--sync-state``): 404 and the ordered
  ``{"ok": false, "error": "not_found"}`` body;
* configured node: the ``light_client.audit_sync_state`` result is passed
  through verbatim with its contract key order (200 for ok=true, 500 for
  io, including the ``corrupt`` status) and queries never change a byte,
  never roll a leftover ``.txn`` journal forward and never clean it up;
* the query shares the per-path lock with ``advance_sync_state``, so
  concurrent audits/advances all answer deterministically;
* ``--sync-state ""`` exits 2 before any state loads; omission is the
  unchanged startup;
* the ``sync-state-audit`` CLI subcommand takes no positional argument,
  prints one JSON line in the server's key order and exits 0 only on a
  200 ok=true response.

Run: python3 tests/sync_state_audit_http_test.py
"""
from __future__ import annotations

import http.client
import io
import json
import os
import subprocess
import sys
import threading
import unittest
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ledger.light_client as light_client  # noqa: E402
from ledger.cli import main as cli_main  # noqa: E402
from ledger.server import build_handler  # noqa: E402
from ledger.service import LedgerService  # noqa: E402
from ledger.store import LedgerStore  # noqa: E402
from light_client_advance_sync_state_test import SyncStateFixture  # noqa: E402


class SyncStateHttpFixture(SyncStateFixture):
    def start_http(self, sync_state_path: str | None) -> None:
        self.sync_path_configured = sync_state_path
        self.service = LedgerService(
            self.store, sync_state_path=sync_state_path
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.port}"

    def stop_http(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def raw_request(self, target: str) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", target)
        response = conn.getresponse()
        raw = response.read()
        status = response.status
        conn.close()
        return status, raw

    def request(self, target: str) -> tuple[int, object]:
        status, raw = self.raw_request(target)
        return status, json.loads(raw.decode("utf-8"))


class SyncStateRouteInputTests(SyncStateHttpFixture):
    def setUp(self) -> None:
        super().setUp()
        self.start_http(self.path)

    def tearDown(self) -> None:
        self.stop_http()
        super().tearDown()

    def test_any_query_parameter_is_400_input(self) -> None:
        for target in (
            "/v1/light-client/sync-state?x",
            "/v1/light-client/sync-state?x=",
            "/v1/light-client/sync-state?x=1",
            "/v1/light-client/sync-state?foo=bar&baz=qux",
        ):
            status, raw = self.raw_request(target)
            self.assertEqual(status, 400, target)
            self.assertEqual(raw, b'{"ok": false, "error": "input"}', target)

    def test_bare_question_mark_carries_no_parameters(self) -> None:
        status, body = self.request("/v1/light-client/sync-state?")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "empty")


class SyncStateRouteUnconfiguredTests(SyncStateHttpFixture):
    def setUp(self) -> None:
        super().setUp()
        self.start_http(None)

    def tearDown(self) -> None:
        self.stop_http()
        super().tearDown()

    def test_unconfigured_is_404_not_found(self) -> None:
        status, raw = self.raw_request("/v1/light-client/sync-state")
        self.assertEqual(status, 404)
        self.assertEqual(raw, b'{"ok": false, "error": "not_found"}')
        body = json.loads(raw)
        self.assertEqual(list(body.keys()), ["ok", "error"])


class SyncStateRoutePassthroughTests(SyncStateHttpFixture):
    def setUp(self) -> None:
        super().setUp()
        self.start_http(self.path)

    def tearDown(self) -> None:
        self.stop_http()
        super().tearDown()

    def snapshot(self) -> dict:
        return {
            target: open(target, "rb").read()
            for target in (self.path, self.state_path(), self.txn_path())
            if os.path.exists(target)
        }

    def test_empty_pair_passes_through_with_key_order(self) -> None:
        status, raw = self.raw_request("/v1/light-client/sync-state")
        self.assertEqual(status, 200)
        # The success document keeps the library insertion order.
        self.assertTrue(
            raw.startswith(b'{"ok": true, "status": "empty", "header":'),
            raw,
        )
        _status, body = self.request("/v1/light-client/sync-state")
        self.assertEqual(
            list(body.keys()),
            ["ok", "status", "header", "state", "transaction"],
        )
        self.assertEqual(
            list(body["header"].keys()),
            ["status", "generation", "tip", "finalized"],
        )
        self.assertEqual(
            list(body["state"].keys()),
            ["status", "generation", "account", "anchor"],
        )
        self.assertEqual(
            list(body["transaction"].keys()),
            ["status", "header_generation", "state_generation"],
        )

    def test_committed_pair_is_consistent_and_queries_change_nothing(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(
                self.path, self.first_bundle()
            )["ok"]
        )
        before = self.snapshot()
        status, body = self.request("/v1/light-client/sync-state")
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["status"], "consistent")
        self.assertEqual(body["header"]["status"], "valid")
        self.assertEqual(body["header"]["generation"], 1)
        self.assertEqual(body["state"]["status"], "valid")
        self.assertEqual(body["state"]["account"], self.sender)
        self.assertEqual(body["transaction"]["status"], "absent")
        for _ in range(3):
            again_status, again = self.request(
                "/v1/light-client/sync-state"
            )
            self.assertEqual(again_status, 200)
            self.assertEqual(again, body)
        self.assertEqual(self.snapshot(), before)

    def test_corrupt_pair_passes_through_as_200_corrupt(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(
                self.path, self.first_bundle()
            )["ok"]
        )
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("garbage")
        status, body = self.request("/v1/light-client/sync-state")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "corrupt")
        self.assertEqual(body["header"]["status"], "invalid")
        # The defective file is left exactly where it was.
        self.assertEqual(
            open(self.path, "r", encoding="utf-8").read(), "garbage"
        )

    def test_io_failure_is_500_ordered_body(self) -> None:
        os.mkdir(os.path.join(self.tmp, "a-directory"))
        self.stop_http()
        self.start_http(os.path.join(self.tmp, "a-directory"))
        try:
            status, raw = self.raw_request("/v1/light-client/sync-state")
            self.assertEqual(status, 500)
            self.assertEqual(raw, b'{"ok": false, "error": "io"}')
        finally:
            self.stop_http()
            self.start_http(self.path)

    def test_leftover_journal_is_recoverable_and_never_rolled_forward(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(
                self.path, self.first_bundle()
            )["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        original = light_client._atomic_write_bytes
        counter = {"calls": 0}

        def flaky(target, payload):
            counter["calls"] += 1
            if counter["calls"] == 3:
                raise OSError("injected crash")
            return original(target, payload)

        light_client._atomic_write_bytes = flaky
        try:
            self.assertEqual(
                light_client.advance_sync_state(self.path, bundle),
                {"ok": False, "error": "io"},
            )
        finally:
            light_client._atomic_write_bytes = original
        self.assertTrue(os.path.exists(self.txn_path()))
        journal_before = self.read_raw(self.txn_path())
        pair_before = self.snapshot()

        status, body = self.request("/v1/light-client/sync-state")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "recoverable", body)
        self.assertEqual(body["transaction"]["status"], "valid")
        self.assertEqual(
            body["transaction"]["header_generation"], 2
        )
        # The HTTP query must not recover, clean or rewrite anything.
        self.assertTrue(os.path.exists(self.txn_path()))
        self.assertEqual(self.read_raw(self.txn_path()), journal_before)
        self.assertEqual(self.snapshot(), pair_before)

    def test_concurrent_audits_and_advances_are_deterministic(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(
                self.path, self.first_bundle()
            )["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)

        results: list = []
        results_lock = threading.Lock()

        def audit_worker() -> None:
            for _ in range(10):
                status, body = self.request("/v1/light-client/sync-state")
                with results_lock:
                    results.append(("audit", status, body))

        def advance_worker() -> None:
            result = light_client.advance_sync_state(self.path, bundle)
            with results_lock:
                results.append(("advance", result))

        threads = [
            threading.Thread(target=audit_worker) for _ in range(4)
        ] + [threading.Thread(target=advance_worker)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        advances = [entry for entry in results if entry[0] == "advance"]
        self.assertEqual(len(advances), 1)
        self.assertTrue(advances[0][1]["ok"], advances[0])
        for _kind, status, body in (
            entry for entry in results if entry[0] == "audit"
        ):
            self.assertEqual(status, 200)
            self.assertTrue(body["ok"], body)
            self.assertIn(
                body["status"], ("consistent", "recoverable")
            )
            self.assertNotEqual(body["status"], "corrupt")
        # The advance left no journal behind and the final state is stable
        # across a "restart": a fresh service over the same files returns
        # byte-identical audit results.
        self.assertFalse(os.path.exists(self.txn_path()))
        _status, final_body = self.request("/v1/light-client/sync-state")
        self.stop_http()
        self.start_http(self.path)
        _status, restarted = self.request(
            "/v1/light-client/sync-state"
        )
        self.assertEqual(restarted, final_body)
        self.assertEqual(restarted["status"], "consistent")


class SyncStateCliTests(SyncStateHttpFixture):
    def cli(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_main(["--base-url", self.base_url, *argv])
        return rc, out.getvalue().strip()

    def test_cli_success_single_line_ordered_json_exit_0(self) -> None:
        self.start_http(self.path)
        try:
            rc, line = self.cli("sync-state-audit")
            self.assertEqual(rc, 0, line)
            self.assertEqual(len(line.splitlines()), 1)
            self.assertTrue(
                line.startswith('{"ok": true, "status": "empty"'), line
            )
            body = json.loads(line)
            self.assertEqual(
                list(body.keys()),
                ["ok", "status", "header", "state", "transaction"],
            )
        finally:
            self.stop_http()

    def test_cli_not_configured_exit_1(self) -> None:
        self.start_http(None)
        try:
            rc, line = self.cli("sync-state-audit")
            self.assertEqual(rc, 1)
            self.assertEqual(line, '{"ok": false, "error": "not_found"}')
        finally:
            self.stop_http()

    def test_cli_io_exit_1(self) -> None:
        os.mkdir(os.path.join(self.tmp, "a-directory"))
        self.start_http(os.path.join(self.tmp, "a-directory"))
        try:
            rc, line = self.cli("sync-state-audit")
            self.assertEqual(rc, 1)
            self.assertEqual(line, '{"ok": false, "error": "io"}')
        finally:
            self.stop_http()

    def test_cli_rejects_positional_arguments(self) -> None:
        self.start_http(self.path)
        try:
            with self.assertRaises(SystemExit) as raised:
                self.cli("sync-state-audit", "unexpected")
            self.assertEqual(raised.exception.code, 2)
        finally:
            self.stop_http()


class SyncStateServerFlagTests(SyncStateFixture):
    def test_empty_sync_state_value_exits_2(self) -> None:
        env = dict(os.environ)
        repo_root = os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
        env["PYTHONPATH"] = repo_root + os.pathsep + env.get(
            "PYTHONPATH", ""
        )
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ledger",
                "--state",
                os.path.join(self.tmp, "fresh-state.json"),
                "--sync-state",
                "",
                "--port",
                "0",
            ],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--sync-state", proc.stderr)
        # Validation fails before any state file is created.
        self.assertFalse(
            os.path.exists(os.path.join(self.tmp, "fresh-state.json"))
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
