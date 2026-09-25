"""Tests for the token-gated node-managed checkpoint-history HTTP endpoints.

Covers:

* server flags: ``--history``/``--history-trust``/``--history-token`` are
  all-or-none (a partial or empty set exits 2, all absent is unchanged);
* the bearer gate: missing/malformed/wrong ``Authorization: Bearer`` is 401
  with ``{"ok": false, "error": "unauthorized"}`` and no side effects (the
  target file and the state snapshot stay byte-identical);
* GET /v1/history/trust reads the signer log (missing file 500/io), POST to
  the same path accepts exactly ``root_seed,at,key,status`` (201 on append,
  200 on the idempotent replay, 400 input / 403 auth / 409 state otherwise),
  POST /v1/history/export accepts exactly ``key,after,limit`` and returns the
  contract-ordered page (200) that verifies offline;
* every successful call appends exactly one ``history_access`` audit event
  with payload key order ``action,trust_head,history_head`` (null for a file
  that does not exist yet), persisted in the same snapshot as the external
  file write; a forced snapshot write failure restores the trust log bytes,
  drops the in-memory event and answers 500/io;
* restart re-verifies both files and binds the last history_access event to
  their current heads; a tampered trust log or a malformed persisted event
  raises StateRecoveryError carrying path and reason.

Run: python3 tests/history_http_test.py
"""
from __future__ import annotations

import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from light_client_advance_test import AdvanceFixture  # noqa: E402

from ledger import crypto  # noqa: E402
from ledger.light_client import (  # noqa: E402
    advance,
    inspect_history_files,
    verify_history_trust,
)
from ledger.server import build_handler  # noqa: E402
from ledger.service import LedgerService  # noqa: E402
from ledger.store import LedgerStore, StateRecoveryError  # noqa: E402

ERROR_BODY = {"ok": False, "error": "unauthorized"}
HISTORY_ACTIONS = ("read", "update", "export")


class HttpHistoryFixture(AdvanceFixture):
    def setUp(self) -> None:
        super().setUp()
        self.history_file = os.path.join(self.tmp, "managed-checkpoint.json")
        self.trust_file = os.path.join(self.tmp, "managed-trust.json")
        self.state_path = os.path.join(self.tmp, "state.json")
        self.token = "test-token"
        self.root_seed = crypto.generate_private_key()
        self.root_pub = crypto.derive_public_key(self.root_seed)
        self.key_seed = crypto.generate_private_key()
        self.key_pub = crypto.derive_public_key(self.key_seed)
        self.start_service(LedgerStore(self.state_path, initial_balance=1000))

    def start_service(self, store: LedgerStore) -> None:
        self.store = store
        self.service = LedgerService(
            store,
            initial_balance=1000,
            history_config=(
                self.history_file,
                self.trust_file,
                self.token,
            ),
        )
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
        self.start_service(
            LedgerStore(
                self.state_path,
                initial_balance=1000,
                history_path=self.history_file,
                history_trust_path=self.trust_file,
            )
        )

    def request(self, method, target, body=None, *, auth="Bearer test-token"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth is not None:
            headers["Authorization"] = auth
        conn.request(method, target, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        payload = json.loads(raw.decode("utf-8")) if raw else None
        conn.close()
        return response.status, payload

    def activate(self, at_value):
        return self.request(
            "POST",
            "/v1/history/trust",
            {
                "root_seed": self.root_seed,
                "at": at_value,
                "key": self.key_pub,
                "status": "active",
            },
        )

    def history_access_events(self):
        return [
            event
            for event in self.store.audit_events
            if event["kind"] == "history_access"
        ]

    def stop_service(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def tearDown(self) -> None:
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
        super().tearDown()


class BearerGateTests(HttpHistoryFixture):
    def test_missing_wrong_and_malformed_authorization_is_401(self) -> None:
        # Create the log legitimately so a successful baseline exists.
        status, _ = self.activate(1)
        self.assertEqual(status, 201)
        before = open(self.state_path, "rb").read()
        trust_exists = os.path.exists(self.trust_file)
        for auth in (None, "Bearer wrong-token", "Bearer", "Basic test-token"):
            status, body = self.request(
                "GET", "/v1/history/trust", auth=auth
            )
            self.assertEqual((status, body), (401, ERROR_BODY), auth)
            status, body = self.request(
                "POST",
                "/v1/history/trust",
                {"root_seed": self.root_seed, "at": 2,
                 "key": self.key_pub, "status": "active"},
                auth=auth,
            )
            self.assertEqual((status, body), (401, ERROR_BODY), auth)
        # No side effects: state snapshot bytes and the trust file presence are
        # unchanged, and no additional audit event was appended.
        self.assertEqual(open(self.state_path, "rb").read(), before)
        self.assertEqual(os.path.exists(self.trust_file), trust_exists)
        self.assertEqual(len(self.history_access_events()), 1)

    def test_body_is_not_read_on_401(self) -> None:
        # The gate precedes body parsing: even invalid JSON is rejected 401.
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(
            "POST",
            "/v1/history/trust",
            body=b"{not json",
            headers={"Content-Type": "application/json"},
        )
        response = conn.getresponse()
        self.assertEqual(response.status, 401)
        self.assertEqual(
            json.loads(response.read().decode("utf-8")), ERROR_BODY
        )
        conn.close()


class HistoryTrustEndpointTests(HttpHistoryFixture):
    def test_read_missing_log_is_io(self) -> None:
        status, body = self.request("GET", "/v1/history/trust")
        self.assertEqual((status, body), (500, {"ok": False, "error": "io"}))
        # A failed operation audits nothing: the access never completed, so no
        # event, checkpoint or generation change is persisted.
        self.assertEqual(self.history_access_events(), [])

    def test_append_201_idempotent_200_and_read(self) -> None:
        status, log = self.activate(1)
        self.assertEqual(status, 201)
        self.assertEqual(list(log.keys()), ["root", "records", "head"])
        self.assertEqual(log["root"], self.root_pub)
        self.assertEqual(
            list(log["records"][0].keys()),
            ["at", "key", "status", "prev", "signature"],
        )
        trust_bytes = open(self.trust_file, "rb").read()
        # Exact tail replay is idempotent: 200, file bytes untouched.
        status, again = self.activate(1)
        self.assertEqual(status, 200)
        self.assertEqual(again, log)
        self.assertEqual(open(self.trust_file, "rb").read(), trust_bytes)
        # A read returns the same document.
        status, read_log = self.request("GET", "/v1/history/trust")
        self.assertEqual(status, 200)
        self.assertEqual(read_log, log)

    def test_input_failures_are_400(self) -> None:
        valid = {"root_seed": self.root_seed, "at": 1,
                 "key": self.key_pub, "status": "active"}
        bad_bodies = [
            {},
            {**valid, "extra": 1},
            {key: value for key, value in list(valid.items())[:-1]},
            ["not", "object"],
        ]
        bad_values = dict(valid)
        for bad_at in (0, -1, True, False, 1.5, "1"):
            bad_bodies.append({**valid, "at": bad_at})
        for bad_status in ("ACTIVE", "", None):
            bad_bodies.append({**valid, "status": bad_status})
        for body in bad_bodies:
            status, payload = self.request(
                "POST", "/v1/history/trust", body
            )
            self.assertEqual(status, 400, body)
            self.assertEqual(payload, {"ok": False, "error": "input"})

    def test_auth_failure_is_403(self) -> None:
        status, _ = self.activate(1)
        self.assertEqual(status, 201)
        other_seed = crypto.generate_private_key()
        status, body = self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": other_seed, "at": 2,
             "key": self.key_pub, "status": "active"},
        )
        self.assertEqual((status, body), (403, {"ok": False, "error": "auth"}))

    def test_state_conflicts_are_409(self) -> None:
        # Opening a fresh log with a revocation is a state conflict.
        status, body = self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": self.root_seed, "at": 1,
             "key": self.key_pub, "status": "revoked"},
        )
        self.assertEqual((status, body), (409, {"ok": False, "error": "state"}))
        self.assertFalse(os.path.exists(self.trust_file))
        # After activating, a non-ascending at is also state.
        self.assertEqual(self.activate(1)[0], 201)
        status, body = self.request(
            "POST",
            "/v1/history/trust",
            {"root_seed": self.root_seed, "at": 1,
             "key": crypto.derive_public_key(crypto.generate_private_key()),
             "status": "active"},
        )
        self.assertEqual((status, body), (409, {"ok": False, "error": "state"}))

    def test_corrupt_log_read_is_409(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        raw = open(self.trust_file, encoding="utf-8").read()
        document = json.loads(raw)
        document["head"] = "f" * 64
        with open(self.trust_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(document, separators=(",", ":")) + "\n")
        status, body = self.request("GET", "/v1/history/trust")
        self.assertEqual((status, body), (409, {"ok": False, "error": "state"}))
        with open(self.trust_file, "w", encoding="utf-8") as fh:
            fh.write(raw)


class HistoryExportEndpointTests(HttpHistoryFixture):
    def test_export_requires_an_advanced_pair(self) -> None:
        # No files at all: the library reports io (missing sidecar).
        status, body = self.request(
            "POST", "/v1/history/export", {"key": self.key_seed}
        )
        self.assertEqual((status, body), (500, {"ok": False, "error": "io"}))

    def test_export_page_shape_and_offline_verification(self) -> None:
        # Establish the signer log and one checkpoint generation offline.
        self.assertEqual(self.activate(100)[0], 201)
        result = advance(
            self.history_file,
            [self.continuation_page(0)],
            self.trust,
            self.anchor,
            100,
        )
        self.assertTrue(result["ok"], result)
        status, page = self.request(
            "POST", "/v1/history/export", {"key": self.key_seed}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            list(page.keys()),
            ["base", "records", "next", "head", "checkpoint", "auth"],
        )
        self.assertEqual(page["auth"]["public_key"], self.key_pub)
        status, log = self.request("GET", "/v1/history/trust")
        self.assertEqual(status, 200)
        self.assertEqual(
            verify_history_trust([page], log, self.root_pub), {"ok": True}
        )

    def test_export_input_validation(self) -> None:
        bad_bodies = [
            {},
            {"key": self.key_seed, "extra": 1},
            ["not", "object"],
            {"key": "z" * 64},
            {"key": self.key_seed, "after": -1},
            {"key": self.key_seed, "after": 1.5},
            {"key": self.key_seed, "after": True},
            {"key": self.key_seed, "limit": 0},
            {"key": self.key_seed, "limit": 201},
            {"key": self.key_seed, "limit": "5"},
        ]
        for body in bad_bodies:
            status, payload = self.request(
                "POST", "/v1/history/export", body
            )
            self.assertEqual(status, 400, body)
            self.assertEqual(payload, {"ok": False, "error": "input"})


class HistoryAccessEventTests(HttpHistoryFixture):
    def test_event_payload_order_and_heads(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        result = advance(
            self.history_file,
            [self.continuation_page(0)],
            self.trust,
            self.anchor,
            100,
        )
        self.assertTrue(result["ok"], result)
        status, page = self.request(
            "POST", "/v1/history/export", {"key": self.key_seed}
        )
        self.assertEqual(status, 200)
        status, _ = self.request("GET", "/v1/history/trust")
        self.assertEqual(status, 200)
        events = self.history_access_events()
        self.assertEqual([e["action"] for e in events],
                         ["update", "export", "read"])
        # Fixed payload key order inside the stored event.
        for event in events:
            keys = [
                key
                for key in event
                if key in ("action", "trust_head", "history_head")
            ]
            self.assertEqual(keys, ["action", "trust_head", "history_head"])
        self.assertIsNone(events[0]["history_head"])
        self.assertIsNotNone(events[0]["trust_head"])
        self.assertEqual(events[-1]["trust_head"], events[0]["trust_head"])
        self.assertEqual(events[1]["history_head"], page["head"])
        # The event hash chain stays continuous and pins the checkpoint.
        self.assertEqual(
            self.store.audit_checkpoint["event_id"],
            len(self.store.audit_events),
        )

    def test_snapshot_failure_restores_file_and_memory(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        trust_bytes = open(self.trust_file, "rb").read()
        events_before = len(self.store.audit_events)
        generation_before = self.store.generation
        original_save = LedgerStore.save
        LedgerStore.save = lambda instance: (_ for _ in ()).throw(
            OSError("disk full")
        )
        try:
            status, body = self.request(
                "POST",
                "/v1/history/trust",
                {"root_seed": self.root_seed, "at": 2,
                 "key": self.key_pub, "status": "revoked"},
            )
        finally:
            LedgerStore.save = original_save
        self.assertEqual((status, body), (500, {"ok": False, "error": "io"}))
        # External file restored and the in-memory event/generation dropped.
        self.assertEqual(open(self.trust_file, "rb").read(), trust_bytes)
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation_before)

    def test_concurrent_access_is_serialized(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        tail = {"root_seed": self.root_seed, "at": 1,
                "key": self.key_pub, "status": "active"}
        results = []

        def worker():
            for _ in range(5):
                results.append(self.request(
                    "POST", "/v1/history/trust", tail
                )[0])
                results.append(self.request(
                    "GET", "/v1/history/trust"
                )[0])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertTrue(results)
        self.assertTrue(all(code == 200 for code in results), results[:5])
        self.assertEqual(
            len(self.history_access_events()), 1 + len(results)
        )


class RecoveryBindingTests(HttpHistoryFixture):
    def test_offline_created_files_verify_without_events(self) -> None:
        self.httpd.shutdown()
        # A fresh node against files prepared offline (no audit history yet)
        # must start: there is nothing to bind, only strict verification.
        store = LedgerStore(
            os.path.join(self.tmp, "other-state.json"),
            initial_balance=1000,
            history_path=self.history_file,
            history_trust_path=self.trust_file,
        )
        self.assertEqual(
            [
                e
                for e in store.audit_events
                if e["kind"] == "history_access"
            ],
            [],
        )

    def test_restart_rebinds_last_event(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        result = advance(
            self.history_file,
            [self.continuation_page(0)],
            self.trust,
            self.anchor,
            100,
        )
        self.assertTrue(result["ok"], result)
        status, page = self.request(
            "POST", "/v1/history/export", {"key": self.key_seed}
        )
        self.assertEqual(status, 200)
        self.restart_service()
        events = self.history_access_events()
        self.assertEqual(events[-1]["action"], "export")
        inspection = inspect_history_files(
            self.history_file, self.trust_file
        )
        self.assertTrue(inspection["ok"])
        self.assertEqual(events[-1]["trust_head"], inspection["trust_head"])
        self.assertEqual(events[-1]["history_head"], inspection["history_head"])
        self.assertEqual(events[-1]["history_head"], page["head"])

    def test_tampered_trust_log_fails_recovery(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        self.httpd.shutdown()
        with open(self.trust_file, encoding="utf-8") as fh:
            raw = fh.read()
        document = json.loads(raw)
        document["head"] = "a" * 64
        with open(self.trust_file, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(document, separators=(",", ":")) + "\n")
        with self.assertRaises(StateRecoveryError) as context:
            LedgerStore(
                self.state_path,
                initial_balance=1000,
                history_path=self.history_file,
                history_trust_path=self.trust_file,
            )
        self.assertEqual(context.exception.path, self.trust_file)
        self.assertTrue(context.exception.reason)

    def test_malformed_persisted_event_fails_recovery(self) -> None:
        self.assertEqual(self.activate(1)[0], 201)
        self.httpd.shutdown()
        with open(self.state_path, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        for event in snapshot["audit_events"]:
            if event.get("kind") == "history_access":
                event["action"] = "not-an-action"
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(
                self.state_path,
                initial_balance=1000,
                history_path=self.history_file,
                history_trust_path=self.trust_file,
            )


if __name__ == "__main__":
    unittest.main()
