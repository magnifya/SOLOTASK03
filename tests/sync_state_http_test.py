"""HTTP/CLI tests for the read-only sync-state audit surface.

Covers the ``GET /v1/light-client/sync-state`` route and the
``sync-state-audit`` CLI subcommand on top of the real
``SyncStateFixture`` (a committed synced header/state pair and a crashed
pair-commit journal):

* server flag: ``--sync-state PATH`` is optional (omitted leaves startup
  unchanged and the route answers 404 with the ordered
  ``{"ok", "error"}`` not_found body) and an empty value exits 2 before
  any state loads;
* the route takes no query parameters: any parameter (blank or valued)
  is 400 with the ordered ``{"ok", "error"}`` input body, while a bare
  trailing ``?`` is accepted;
* configured: the ``audit_sync_state`` result is passed through with its
  contract key order (``ok, status, header, state, transaction``): an
  empty trio is 200/empty, a committed pair is 200/consistent, a tampered
  file is still 200 with status corrupt and an invalid component, a
  leftover sealed journal is 200/recoverable and never rolled forward,
  and an unreadable path is 500/io;
* read-only guarantees under concurrency and restart: repeated and
  parallel queries change no byte and return byte-identical ordered JSON,
  including with a leftover journal;
* CLI: ``sync-state-audit`` takes no positional argument, prints one
  single-line JSON document in the response key order and exits 0 only
  for 200 with ``ok`` true (400/404/500 all exit 1).

Run: python3 tests/sync_state_http_test.py
"""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ledger.light_client as light_client  # noqa: E402
from ledger import __main__ as server_main  # noqa: E402
from ledger.cli import main as cli_main  # noqa: E402
from ledger.server import build_handler  # noqa: E402
from ledger.service import LedgerService  # noqa: E402
from light_client_advance_sync_state_test import SyncStateFixture  # noqa: E402

TOP_KEYS = ["ok", "status", "header", "state", "transaction"]
ERROR_KEYS = ["ok", "error"]
HEADER_KEYS = ["status", "generation", "tip", "finalized"]
STATE_KEYS = ["status", "generation", "account", "anchor"]
TXN_KEYS = ["status", "header_generation", "state_generation"]


def ordered_document(raw: str):
    """Parse JSON preserving key insertion order."""
    return json.loads(raw, object_pairs_hook=dict)


class SyncStateHttpFixture(SyncStateFixture):
    """A real HTTP service configured with the fixture's sync-state path."""

    sync_state_configured = True

    def setUp(self) -> None:
        super().setUp()
        self.http_service = LedgerService(
            self.store, sync_state_path=(self.path if self.sync_state_configured else None)
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.http_service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def raw_get(self, target: str) -> tuple[int, str]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", target)
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        conn.close()
        return response.status, body

    def get(self, target: str = "/v1/light-client/sync-state"):
        status, raw = self.raw_get(target)
        return status, ordered_document(raw)

    def restart(self) -> None:
        """Start a fresh service over the same on-disk pair and store."""
        self.httpd.shutdown()
        self.httpd.server_close()
        self.http_service = LedgerService(
            self.store, sync_state_path=self.path
        )
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.http_service)
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )
        self.thread.start()

    def trio_snapshot(self) -> dict:
        return {
            target: self.read_raw(target)
            for target in (self.path, self.state_path(), self.txn_path())
            if os.path.exists(target)
        }

    def crash_pair_commit(self, bundle: dict) -> None:
        """Leave a sealed journal by failing the second target write."""
        original = light_client._atomic_write_bytes
        counter = {"calls": 0}

        def flaky(target, payload):
            counter["calls"] += 1
            if counter["calls"] == 3:
                raise OSError("injected crash")
            return original(target, payload)

        light_client._atomic_write_bytes = flaky
        try:
            result = light_client.advance_sync_state(self.path, bundle)
        finally:
            light_client._atomic_write_bytes = original
        self.assertEqual(result, {"ok": False, "error": "io"})
        self.assertTrue(os.path.exists(self.txn_path()))


class UnconfiguredSyncStateHttpFixture(SyncStateHttpFixture):
    sync_state_configured = False


class SyncStateRouteQueryTests(SyncStateHttpFixture):
    def test_empty_trio_is_200_empty_with_contract_key_order(self) -> None:
        status, body = self.get()
        self.assertEqual(status, 200)
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertTrue(body["ok"])
        self.assertEqual(body["status"], "empty")
        self.assertEqual(list(body["header"].keys()), HEADER_KEYS)
        self.assertEqual(body["header"]["status"], "missing")
        self.assertEqual(list(body["state"].keys()), STATE_KEYS)
        self.assertEqual(body["state"]["status"], "missing")
        self.assertEqual(list(body["transaction"].keys()), TXN_KEYS)
        self.assertEqual(body["transaction"]["status"], "absent")

    def test_any_query_parameter_is_400_input_in_order(self) -> None:
        for target in (
            "/v1/light-client/sync-state?x=1",
            "/v1/light-client/sync-state?x=",
            "/v1/light-client/sync-state?height=3",
            "/v1/light-client/sync-state?%00=x",
        ):
            status, raw = self.raw_get(target)
            self.assertEqual(status, 400, target)
            body = ordered_document(raw)
            self.assertEqual(list(body.keys()), ERROR_KEYS, target)
            self.assertEqual(body, {"ok": False, "error": "input"}, target)

    def test_bare_question_mark_is_accepted(self) -> None:
        status, body = self.get("/v1/light-client/sync-state?")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "empty")

    def test_wrong_method_routes_unchanged(self) -> None:
        # The new GET route must not change the POST surface.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/v1/light-client/sync-state", body=b"{}")
        response = conn.getresponse()
        self.assertEqual(response.status, 404)
        response.read()
        conn.close()


class SyncStateRouteConfiguredTests(SyncStateHttpFixture):
    def test_committed_pair_is_consistent_200(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        status, body = self.get()
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertEqual(body["status"], "consistent")
        self.assertEqual(body["header"]["status"], "valid")
        self.assertEqual(body["header"]["generation"], 1)
        self.assertEqual(
            body["header"]["finalized"],
            {"height": 3, "block_hash": self.h(3)},
        )
        self.assertEqual(body["state"]["status"], "valid")
        self.assertEqual(body["state"]["generation"], 1)
        self.assertEqual(body["state"]["account"], self.sender)
        self.assertEqual(body["state"]["anchor"]["height"], 3)
        self.assertEqual(body["transaction"]["status"], "absent")

    def test_corrupt_target_is_still_200_but_corrupt(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.state_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        status, body = self.get()
        # A successful read of a corrupt pair: the query itself succeeds.
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "corrupt")
        self.assertEqual(body["state"]["status"], "invalid")
        self.assertIsNone(body["state"]["generation"])
        self.assertEqual(body["header"]["status"], "valid")
        self.assertEqual(body["transaction"]["status"], "absent")

    def test_leftover_journal_is_recoverable_and_not_rolled_forward(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        self.crash_pair_commit(self.advance_bundle_to(3, height))
        before = self.trio_snapshot()

        status, body = self.get()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "recoverable")
        self.assertEqual(body["transaction"]["status"], "valid")
        self.assertEqual(body["transaction"]["header_generation"], 2)
        self.assertEqual(body["transaction"]["state_generation"], 2)
        # The query never materializes or unlinks the journal.
        self.assertEqual(self.trio_snapshot(), before)
        self.assertTrue(os.path.exists(self.txn_path()))

    def test_unreadable_path_is_500_io_in_order(self) -> None:
        os.mkdir(self.path)
        status, raw = self.raw_get("/v1/light-client/sync-state")
        self.assertEqual(status, 500)
        body = ordered_document(raw)
        self.assertEqual(list(body.keys()), ERROR_KEYS)
        self.assertEqual(body, {"ok": False, "error": "io"})


class SyncStateRouteUnconfiguredTests(UnconfiguredSyncStateHttpFixture):
    def test_unconfigured_is_404_not_found_in_order(self) -> None:
        status, raw = self.raw_get("/v1/light-client/sync-state")
        self.assertEqual(status, 404)
        body = ordered_document(raw)
        self.assertEqual(list(body.keys()), ERROR_KEYS)
        self.assertEqual(body, {"ok": False, "error": "not_found"})

    def test_query_param_still_400_when_unconfigured(self) -> None:
        # The parameter contract is settled before the configuration check.
        status, body = self.get("/v1/light-client/sync-state?x=1")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"ok": False, "error": "input"})


class SyncStateReadOnlyDeterminismTests(SyncStateHttpFixture):
    def _raw_query(self) -> tuple[int, str]:
        return self.raw_get("/v1/light-client/sync-state")

    def test_repeated_queries_change_no_byte(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        before = self.trio_snapshot()
        first_status, first_raw = self._raw_query()
        for _ in range(5):
            status, raw = self._raw_query()
            self.assertEqual(status, first_status)
            self.assertEqual(raw, first_raw)
        self.assertEqual(self.trio_snapshot(), before)

    def test_concurrent_queries_are_identical_and_read_only(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        self.crash_pair_commit(self.advance_bundle_to(3, height))
        before = self.trio_snapshot()

        results: list[tuple[int, str]] = []
        errors: list[BaseException] = []
        start = threading.Barrier(8)

        def worker() -> None:
            try:
                start.wait()
                for _ in range(5):
                    results.append(self._raw_query())
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(errors, errors)
        self.assertEqual(len(results), 40)
        self.assertEqual(len(set(results)), 1, results)
        status, raw = results[0]
        self.assertEqual(status, 200)
        self.assertEqual(ordered_document(raw)["status"], "recoverable")
        # The shared per-path lock serialized the reads; no recovery ran.
        self.assertEqual(self.trio_snapshot(), before)
        self.assertTrue(os.path.exists(self.txn_path()))

    def test_restart_returns_identical_result(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        self.crash_pair_commit(self.advance_bundle_to(3, height))
        before_status, before_raw = self._raw_query()
        before_files = self.trio_snapshot()

        self.restart()
        after_status, after_raw = self._raw_query()
        self.assertEqual(after_status, before_status)
        self.assertEqual(after_raw, before_raw)
        self.assertEqual(self.trio_snapshot(), before_files)
        self.assertTrue(os.path.exists(self.txn_path()))


class SyncStateCliTests(SyncStateHttpFixture):
    def _run_cli(self, *argv: str) -> tuple[int, str]:
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            rc = cli_main(
                ["--base-url", f"http://127.0.0.1:{self.port}", *argv]
            )
        output = capture.getvalue()
        return rc, output

    def test_success_prints_one_ordered_line_and_exits_zero(self) -> None:
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        rc, output = self._run_cli("sync-state-audit")
        self.assertEqual(rc, 0, output)
        self.assertEqual(output.count("\n"), 1)
        line = output.rstrip("\n")
        body = ordered_document(line)
        self.assertEqual(list(body.keys()), TOP_KEYS)
        self.assertEqual(body["status"], "consistent")
        self.assertEqual(list(body["header"].keys()), HEADER_KEYS)
        self.assertEqual(list(body["state"].keys()), STATE_KEYS)
        self.assertEqual(list(body["transaction"].keys()), TXN_KEYS)

    def test_empty_trio_exits_zero(self) -> None:
        rc, output = self._run_cli("sync-state-audit")
        self.assertEqual(rc, 0)
        self.assertEqual(
            ordered_document(output.strip())["status"], "empty"
        )

    def test_corrupt_pair_exits_zero_for_successful_query(self) -> None:
        # corrupt is an ok=true pass-through document, hence exit 0.
        self.assertTrue(
            light_client.advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("garbage")
        rc, output = self._run_cli("sync-state-audit")
        self.assertEqual(rc, 0, output)
        self.assertEqual(ordered_document(output.strip())["status"], "corrupt")

    def test_unconfigured_is_exit_one_with_ordered_failure(self) -> None:
        # Re-point a CLI invocation at a second, unconfigured server.
        service = LedgerService(self.store)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(service))
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                rc = cli_main(
                    [
                        "--base-url",
                        f"http://127.0.0.1:{port}",
                        "sync-state-audit",
                    ]
                )
            output = capture.getvalue()
            self.assertEqual(rc, 1)
            self.assertEqual(output.count("\n"), 1)
            body = ordered_document(output.strip())
            self.assertEqual(list(body.keys()), ERROR_KEYS)
            self.assertEqual(body, {"ok": False, "error": "not_found"})
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_io_failure_is_exit_one_with_ordered_failure(self) -> None:
        os.mkdir(self.path)
        rc, output = self._run_cli("sync-state-audit")
        self.assertEqual(rc, 1)
        body = ordered_document(output.strip())
        self.assertEqual(list(body.keys()), ERROR_KEYS)
        self.assertEqual(body, {"ok": False, "error": "io"})

    def test_takes_no_positional_arguments(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self._run_cli("sync-state-audit", "extra")
        self.assertEqual(caught.exception.code, 2)


class SyncStateServerFlagTests(SyncStateFixture):
    def test_parser_default_is_none(self) -> None:
        args = server_main.build_parser().parse_args([])
        self.assertIsNone(args.sync_state)

    def test_empty_value_exits_2_before_state_loads(self) -> None:
        state_file = os.path.join(self.tmp, "never-created.json")
        rc = server_main.main(
            [
                "--state",
                state_file,
                "--sync-state",
                "",
                "--port",
                "0",
            ]
        )
        self.assertEqual(rc, 2)
        # The empty-flag failure is settled before any store is opened.
        self.assertFalse(os.path.exists(state_file))


if __name__ == "__main__":
    unittest.main(verbosity=2)
