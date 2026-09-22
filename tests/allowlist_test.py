"""Tests for persistent keyless allowlist management.

Covers POST /v1/trust/allowlist (201 with {source, expires_at}, 200
idempotent re-post with no new event, 409 on changed content, 400 on
malformed source/expires_at), DELETE /v1/trust/allowlist/{source}
(200 {source, removed: true}, 404 unknown), the allowlist_added /
allowlist_removed audit events carrying source and expires_at, atomic
rollback when the durable write fails (entry and event move together,
generation unchanged on the idempotent path), strict isolation from the
same-named persistent trust registry and from /v1/forks/sync
authorization, expired entries retained by GET /v1/trust and reported
``expired`` by offline verify, restart durability, StateRecoveryError on
corrupt allowlist sections/events and same-generation snapshot conflicts,
serialized concurrency, plus the HTTP and CLI surfaces.

Run: python3 tests/allowlist_test.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ledger import audit as audit_mod
from ledger.cli import main as cli_main
from ledger.light_client import verify_bundle
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

KEY_A = "a" * 64
FUTURE = 1_900_000_000


class AllowlistServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0].block_hash

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add(self, source="node-a", expires_at=FUTURE):
        return self.svc.add_allowlist_entry(
            {"source": source, "expires_at": expires_at}
        )

    # -- add -----------------------------------------------------------------

    def test_add_returns_201_with_entry_shape(self) -> None:
        status, body = self.add()
        self.assertEqual(status, 201, body)
        self.assertEqual(body, {"source": "node-a", "expires_at": FUTURE})
        self.assertEqual(self.store.allowlist, {"node-a": FUTURE})

    def test_add_emits_event_with_source_and_expires_at(self) -> None:
        self.assertEqual(self.add("node-a", 12345)[0], 201)
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 1)
        event = page["items"][0]
        self.assertEqual(event["kind"], "allowlist_added")
        self.assertEqual(event["source"], "node-a")
        self.assertEqual(event["expires_at"], 12345)
        # The event participates in the append-only hash chain and the
        # checkpoint pins the new head.
        audit_mod.validate_event_chain(self.store.audit_events)
        audit_mod.validate_checkpoint(
            self.store.audit_checkpoint, self.store.audit_events
        )

    def test_add_same_content_is_idempotent_200_without_event(self) -> None:
        self.assertEqual(self.add()[0], 201)
        generation = self.store.generation
        status, body = self.add()
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"source": "node-a", "expires_at": FUTURE})
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 1)
        # An idempotent retry performs no write and advances no generation.
        self.assertEqual(self.store.generation, generation)

    def test_add_different_content_conflicts_409(self) -> None:
        self.assertEqual(self.add(expires_at=100)[0], 201)
        status, body = self.add(expires_at=101)
        self.assertEqual(status, 409, body)
        self.assertEqual(self.store.allowlist, {"node-a": 100})
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 1)

    def test_add_validation_errors_400(self) -> None:
        for bad in (
            {"source": "", "expires_at": FUTURE},
            {"source": 1, "expires_at": FUTURE},
            {"source": None, "expires_at": FUTURE},
            {"source": "node-a", "expires_at": "soon"},
            {"source": "node-a", "expires_at": True},
            {"source": "node-a", "expires_at": False},
            {"source": "node-a", "expires_at": 1.0},
            {"source": "node-a"},
            {"expires_at": FUTURE},
            ["not", "an", "object"],
            None,
        ):
            status, body = self.svc.add_allowlist_entry(bad)
            self.assertEqual(status, 400, bad)
        self.assertEqual(self.store.allowlist, {})

    def test_add_accepts_negative_and_zero_expiry_as_plain_integers(self) -> None:
        # The contract requires a non-boolean integer only; a past/zero
        # deadline is a valid (already-expired) entry, never auto-removed.
        self.assertEqual(self.add("old", -5)[0], 201)
        self.assertEqual(self.add("zero", 0)[0], 201)
        self.assertEqual(self.store.allowlist, {"old": -5, "zero": 0})

    # -- remove --------------------------------------------------------------

    def test_remove_unknown_is_404(self) -> None:
        status, body = self.svc.remove_allowlist_entry("ghost")
        self.assertEqual(status, 404, body)
        # The empty path segment is an unknown entry too, not a 400.
        self.assertEqual(self.svc.remove_allowlist_entry("")[0], 404)
        self.assertEqual(self.svc.remove_allowlist_entry(None)[0], 404)
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 0)

    def test_remove_returns_200_and_emits_event_with_removed_expiry(self) -> None:
        self.add("node-a", 777)
        status, body = self.svc.remove_allowlist_entry("node-a")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"source": "node-a", "removed": True})
        self.assertNotIn("node-a", self.store.allowlist)
        _, page = self.svc.list_audit_events({})
        kinds = [(e["kind"], e["source"], e["expires_at"]) for e in page["items"]]
        self.assertEqual(
            kinds,
            [("allowlist_added", "node-a", 777),
             ("allowlist_removed", "node-a", 777)],
        )
        # Removing again is now an unknown entry -> 404, no second event.
        self.assertEqual(self.svc.remove_allowlist_entry("node-a")[0], 404)
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 2)

    # -- atomicity -----------------------------------------------------------

    def _failing_save(self) -> None:
        def boom() -> None:
            raise RuntimeError("disk full")

        self.store.save = boom  # type: ignore[method-assign]

    def test_failed_add_write_rolls_back_entry_and_event(self) -> None:
        self._failing_save()
        generation = self.store.generation
        with self.assertRaises(RuntimeError):
            self.add()
        self.assertEqual(self.store.allowlist, {})
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 0)
        self.assertEqual(self.store.audit_checkpoint, audit_mod.make_checkpoint([]))
        self.assertEqual(self.store.generation, generation)

    def test_failed_remove_write_restores_entry_and_drops_event(self) -> None:
        self.add()
        self._failing_save()
        generation = self.store.generation
        with self.assertRaises(RuntimeError):
            self.svc.remove_allowlist_entry("node-a")
        self.assertEqual(self.store.allowlist, {"node-a": FUTURE})
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["kind"], "allowlist_added")
        self.assertEqual(self.store.generation, generation)

    # -- isolation from trust registry and sync authorization ----------------

    def test_allowlist_does_not_touch_same_named_trust_source(self) -> None:
        status, reg = self.svc.register_trust_source(
            {"source": "dup", "public_key": KEY_A, "expires_at": FUTURE}
        )
        self.assertEqual(status, 201)
        self.assertEqual(self.add("dup", 42)[0], 201)
        # Both surfaces coexist: the keyed registry source and the keyless
        # offline-only allowlist entry are independent records.
        self.assertEqual(self.store.trust_sources["dup"]["status"], "active")
        self.assertEqual(self.store.allowlist["dup"], 42)
        _, doc = self.svc.get_trust_document()
        self.assertEqual(doc["sources"]["dup"], {"public_key": KEY_A, "expires_at": FUTURE})
        self.assertEqual(doc["allowlist"]["dup"], 42)
        # Removing the allowlist entry leaves the trust source exactly as was.
        self.assertEqual(self.svc.remove_allowlist_entry("dup")[0], 200)
        self.assertIn("dup", self.store.trust_sources)
        self.assertEqual(self.store.trust_sources["dup"]["version"], 1)
        self.assertNotIn("dup", self.store.allowlist)
        kinds = [e["kind"] for e in self.store.audit_events]
        self.assertNotIn("source_revoked", kinds)
        self.assertEqual(kinds, ["source_registered", "allowlist_added", "allowlist_removed"])

    def test_allowlist_entry_does_not_authorize_fork_sync(self) -> None:
        # An allowlist-only source must still be refused at the sync
        # authorization gate (403): the allowlist serves offline verify only.
        self.add("offline-only", FUTURE)
        status, body = self.svc.submit_fork_sync(
            {
                "source": "offline-only",
                "request_id": "req-1",
                "expires_at": FUTURE,
                "candidate": {"blocks": []},
            }
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(self.store.syncs, {})

    # -- expired entries are retained ----------------------------------------

    def test_trust_document_keeps_expired_allowlist_entries(self) -> None:
        past = int(time.time()) - 10
        self.add("fresh", FUTURE)
        self.add("stale", past)
        _, doc = self.svc.get_trust_document()
        # Unlike keyed sources, expired allowlist entries are never filtered
        # out or deleted.
        self.assertEqual(doc["allowlist"], {"fresh": FUTURE, "stale": past})
        self.assertEqual(self.store.allowlist["stale"], past)
        # Triggering other locked operations never sweeps them either.
        self.svc.list_audit_events({})
        self.assertIn("stale", self.store.allowlist)

    def test_offline_verify_reports_expired_for_expired_allowlist_entry(self) -> None:
        past = int(time.time()) - 1
        bundle = {
            "source": "node-a",
            "expires_at": FUTURE,
            "response": {
                "tip_hash": self.genesis,
                "height": 0,
                "length": 1,
                "status": "confirmed",
            },
            "candidate": [],
            "proofs": [],
        }
        genesis_block = self.store.chain[0].to_dict()
        bundle["candidate"] = [genesis_block]
        trust = {
            "genesis_hash": self.genesis,
            "sources": {},
            "allowlist": {"node-a": FUTURE},
        }
        self.assertEqual(verify_bundle(bundle, trust)["ok"], True)
        # Same bundle once the allowlist entry has expired: expired, and the
        # entry remains in the document rather than disappearing.
        trust["allowlist"]["node-a"] = past
        result = verify_bundle(bundle, trust)
        self.assertEqual(result, {"ok": False, "error": "expired"})

    # -- serialized concurrency ----------------------------------------------

    def test_concurrent_adds_are_serialized(self) -> None:
        errors = []

        def worker(i: int) -> None:
            try:
                status, _ = self.add(f"node-{i}", FUTURE + i)
                if status != 201:
                    errors.append((i, status))
            except BaseException as exc:  # noqa: BLE001
                errors.append((i, repr(exc)))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(self.store.allowlist), 20)
        _, page = self.svc.list_audit_events({})
        self.assertEqual(page["total"], 20)
        self.assertEqual(
            sorted(e["source"] for e in page["items"]),
            sorted(f"node-{i}" for i in range(20)),
        )

    # -- durability & recovery -----------------------------------------------

    def test_restart_preserves_entries_and_events(self) -> None:
        self.add("keep", FUTURE)
        self.add("expired-keep", int(time.time()) - 5)
        self.add("gone", 1)
        self.svc.remove_allowlist_entry("gone")
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(
            reopened.allowlist,
            {"keep": FUTURE, "expired-keep": self.store.allowlist["expired-keep"]},
        )
        kinds = [e["kind"] for e in reopened.audit_events]
        self.assertEqual(
            kinds,
            ["allowlist_added", "allowlist_added", "allowlist_added", "allowlist_removed"],
        )
        self.assertEqual([e["event_id"] for e in reopened.audit_events], [1, 2, 3, 4])
        audit_mod.validate_event_chain(reopened.audit_events)
        audit_mod.validate_checkpoint(
            reopened.audit_checkpoint, reopened.audit_events
        )

    def test_corrupt_allowlist_section_fails_recovery(self) -> None:
        self.add()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["allowlist"] = ["not", "an", "object"]
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("allowlist", ctx.exception.reason)

    def test_corrupt_allowlist_entry_type_fails_recovery(self) -> None:
        self.add()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["allowlist"] = {"node-a": "soon"}
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_corrupt_allowlist_event_payload_fails_recovery(self) -> None:
        self.add()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["audit_events"][0]["expires_at"] = True
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("allowlist_added", ctx.exception.reason)

    def test_same_generation_conflicting_allowlist_snapshots_fail(self) -> None:
        self.add("node-a", 1)
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        generation = data["state"]["generation"]
        # A same-generation candidate disagreeing about the allowlist is a
        # split-brain conflict, never a silent choice.
        data["allowlist"] = {"node-a": 2}
        snapshot = os.path.join(self.tmp, f".ledger-conflict.gen{generation}")
        with open(snapshot, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("conflicting snapshots", ctx.exception.reason)


class AllowlistHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_surface(self) -> None:
        import urllib.error

        status, body = self._request(
            "POST", "/v1/trust/allowlist",
            {"source": "n1", "expires_at": FUTURE},
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(body, {"source": "n1", "expires_at": FUTURE})
        status, body = self._request(
            "POST", "/v1/trust/allowlist", {"source": "n1", "expires_at": FUTURE}
        )
        self.assertEqual(status, 200, body)
        status, _ = self._request(
            "POST", "/v1/trust/allowlist", {"source": "n1", "expires_at": 1}
        )
        self.assertEqual(status, 409)
        status, _ = self._request(
            "POST", "/v1/trust/allowlist", {"source": "n2", "expires_at": True}
        )
        self.assertEqual(status, 400)
        status, _ = self._request(
            "POST", "/v1/trust/allowlist", {"source": "", "expires_at": 1}
        )
        self.assertEqual(status, 400)

        # Expired entries are kept and exported.
        status, _ = self._request(
            "POST", "/v1/trust/allowlist", {"source": "old", "expires_at": 0}
        )
        self.assertEqual(status, 201)
        status, doc = self._request("GET", "/v1/trust")
        self.assertEqual(status, 200)
        self.assertEqual(doc["allowlist"], {"n1": FUTURE, "old": 0})

        status, body = self._request("DELETE", "/v1/trust/allowlist/n1")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"source": "n1", "removed": True})
        status, _ = self._request("DELETE", "/v1/trust/allowlist/n1")
        self.assertEqual(status, 404)
        status, _ = self._request("DELETE", "/v1/trust/allowlist/ghost")
        self.assertEqual(status, 404)

        # Events are on the same append-only audit log.
        status, page = self._request("GET", "/v1/audit/events")
        self.assertEqual(status, 200)
        kinds = [e["kind"] for e in page["items"]]
        self.assertIn("allowlist_added", kinds)
        self.assertIn("allowlist_removed", kinds)


class AllowlistCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cli(self, *argv) -> tuple[int, str]:
        out = StringIO()
        with redirect_stdout(out):
            rc = cli_main(["--base-url", self.base, *argv])
        return rc, out.getvalue().strip()

    def test_cli_commands_single_line_json(self) -> None:
        rc, line = self._cli(
            "trust", "allowlist-add", "--source", "n1", "--expires-at", str(FUTURE)
        )
        self.assertEqual(rc, 0, line)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertEqual(json.loads(line), {"source": "n1", "expires_at": FUTURE})

        # Idempotent retry stays success.
        rc, line = self._cli(
            "trust", "allowlist-add", "--source", "n1", "--expires-at", str(FUTURE)
        )
        self.assertEqual(rc, 0)

        # Changed content: single JSON line, exit 1.
        rc, line = self._cli(
            "trust", "allowlist-add", "--source", "n1", "--expires-at", "1"
        )
        self.assertEqual(rc, 1)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertIn("error", json.loads(line))

        # Malformed type via the API contract surface: exit 1.
        rc, _ = self._cli(
            "trust", "allowlist-add", "--source", "", "--expires-at", "1"
        )
        self.assertEqual(rc, 1)

        rc, line = self._cli("trust", "allowlist-remove", "--source", "n1")
        self.assertEqual(rc, 0, line)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertEqual(json.loads(line), {"source": "n1", "removed": True})

        rc, line = self._cli("trust", "allowlist-remove", "--source", "n1")
        self.assertEqual(rc, 1)
        self.assertIn("error", json.loads(line))


if __name__ == "__main__":
    unittest.main(verbosity=2)
