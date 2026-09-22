"""Tests for persistent keyless allowlist management.

Covers POST /v1/trust/allowlist (201 on add, 200 idempotent re-post with no
new event, 409 on changed expiry, 400 on a non-string/empty source or a
boolean/non-integer expires_at), DELETE /v1/trust/allowlist/{source}
(404 unknown, 200 {source, removed: true}), the allowlist_added /
allowlist_removed audit events (source + expires_at), atomic persistence
together with the hash chain, checkpoint and generation (full rollback when
the write fails), independence from same-named keyed trust sources and from
/v1/forks/sync authorization (allowlist-only sources stay 403), expired
entries being retained verbatim (never auto-deleted; offline verify returns
"expired"), restart durability with strict recovery validation
(StateRecoveryError on a malformed allowlist entry or event), plus the HTTP
routing and the `trust allowlist-add` / `trust allowlist-remove` CLI
(single-line JSON, non-2xx exits 1).

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
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
        self.svc = LedgerService(LedgerStore(self.state_path, initial_balance=1000))
        self.store = self.svc.store

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add(self, source="n1", expires_at=FUTURE):
        return self.svc.add_allowlist_entry(
            {"source": source, "expires_at": expires_at}
        )

    # -- validation ----------------------------------------------------------

    def test_validation_errors_400(self) -> None:
        for bad in (
            {"source": "", "expires_at": FUTURE},
            {"source": 1, "expires_at": FUTURE},
            {"source": "n", "expires_at": True},
            {"source": "n", "expires_at": False},
            {"source": "n", "expires_at": "soon"},
            {"source": "n", "expires_at": 1.5},
            {"source": "n"},
            {"expires_at": FUTURE},
            ["not", "an", "object"],
        ):
            status, body = self.svc.add_allowlist_entry(bad)
            self.assertEqual(status, 400, bad)

    # -- add / idempotency / conflict ---------------------------------------

    def test_add_returns_201_with_event(self) -> None:
        status, body = self.add()
        self.assertEqual(status, 201, body)
        self.assertEqual(body, {"source": "n1", "expires_at": FUTURE})
        _, audit = self.svc.list_audit_events({})
        self.assertEqual(audit["total"], 1)
        event = audit["items"][0]
        self.assertEqual(event["kind"], "allowlist_added")
        self.assertEqual(event["source"], "n1")
        self.assertEqual(event["expires_at"], FUTURE)
        self.assertEqual(event["event_id"], 1)

    def test_same_content_retry_is_200_with_no_event(self) -> None:
        self.assertEqual(self.add()[0], 201)
        generation = self.store.generation
        status, body = self.add()
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"source": "n1", "expires_at": FUTURE})
        # No write and no second event.
        self.assertEqual(self.store.generation, generation)
        _, audit = self.svc.list_audit_events({})
        self.assertEqual(
            [e["kind"] for e in audit["items"]], ["allowlist_added"]
        )

    def test_different_expiry_conflicts_409(self) -> None:
        self.assertEqual(self.add()[0], 201)
        generation = self.store.generation
        status, body = self.add(expires_at=FUTURE + 1)
        self.assertEqual(status, 409, body)
        # The stored entry and generation are unchanged.
        self.assertEqual(self.store.allowlist["n1"], FUTURE)
        self.assertEqual(self.store.generation, generation)

    # -- removal -------------------------------------------------------------

    def test_remove_lifecycle_and_404(self) -> None:
        status, body = self.svc.remove_allowlist_entry("ghost")
        self.assertEqual(status, 404, body)
        self.assertEqual(self.add()[0], 201)
        status, body = self.svc.remove_allowlist_entry("n1")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"source": "n1", "removed": True})
        self.assertNotIn("n1", self.store.allowlist)
        self.assertEqual(self.svc.remove_allowlist_entry("n1")[0], 404)
        self.assertEqual(self.svc.remove_allowlist_entry("")[0], 404)
        kinds = [e["kind"] for e in self.svc.list_audit_events({})[1]["items"]]
        self.assertEqual(kinds, ["allowlist_added", "allowlist_removed"])
        removed = self.svc.list_audit_events({"kind": "allowlist_removed"})[1][
            "items"
        ][0]
        self.assertEqual(removed["source"], "n1")
        self.assertEqual(removed["expires_at"], FUTURE)

    # -- independence --------------------------------------------------------

    def test_independent_of_trust_registry_and_sync_authorization(self) -> None:
        # A same-named keyed trust source is unaffected by allowlist removal.
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "dup", "public_key": KEY_A, "expires_at": FUTURE}
            )[0],
            201,
        )
        self.assertEqual(self.add("dup")[0], 201)
        self.assertEqual(self.svc.remove_allowlist_entry("dup")[0], 200)
        self.assertIn("dup", self.store.trust_sources)
        self.assertEqual(self.store.trust_sources["dup"]["status"], "active")
        self.assertNotIn("dup", self.store.allowlist)

        # An allowlist-only source must never authorize /v1/forks/sync:
        # the delivery is rejected 403 before the candidate is examined.
        self.assertEqual(self.add("keyless")[0], 201)
        genesis = self.store.chain[0]
        candidate = {
            "tip_hash": genesis.block_hash,
            "height": 0,
            "length": 1,
            "status": "confirmed",
            "blocks": [genesis.to_dict()],
        }
        status, body = self.svc.submit_fork_sync(
            {
                "source": "keyless",
                "request_id": "r1",
                "expires_at": int(time.time()) + 3600,
                "candidate": candidate,
            }
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(self.store.syncs, {})

    # -- expiry is preserved, never auto-swept -------------------------------

    def test_expired_entries_are_retained(self) -> None:
        past = int(time.time()) - 10
        self.assertEqual(self.add("old", past)[0], 201)
        _, doc = self.svc.get_trust_document()
        self.assertEqual(doc["allowlist"], {"old": past})
        # Operations that sweep expired sync records must not touch the
        # allowlist; the expired entry survives verbatim.
        self.svc.list_audit_events({})
        self.assertEqual(self.store.allowlist, {"old": past})
        _, doc = self.svc.get_trust_document()
        self.assertEqual(doc["allowlist"], {"old": past})

    def test_offline_verify_reports_expired_allowlist(self) -> None:
        genesis = self.store.chain[0]
        now = time.time()
        trust = {
            "genesis_hash": genesis.block_hash,
            "sources": {},
            "allowlist": {"keyless": int(now) + 3600},
        }
        bundle = {
            "source": "keyless",
            "expires_at": int(now) + 3600,
            "response": {
                "height": 0,
                "tip_hash": genesis.block_hash,
                "length": 1,
                "status": "confirmed",
            },
            "candidate": [genesis.to_dict()],
            "proofs": [],
        }
        result = verify_bundle(json.loads(json.dumps(bundle)), trust, now=now)
        self.assertTrue(result["ok"], result)
        # An expired allowlist deadline yields the "expired" category.
        trust["allowlist"]["keyless"] = int(now) - 1
        result = verify_bundle(json.loads(json.dumps(bundle)), trust, now=now)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "expired")

    # -- atomicity -----------------------------------------------------------

    def test_failed_add_save_rolls_back_everything(self) -> None:
        original_save = self.store.save

        def failing_save() -> None:
            raise OSError("simulated persistence failure")

        self.store.save = failing_save
        try:
            with self.assertRaises(OSError):
                self.add()
        finally:
            self.store.save = original_save
        self.assertNotIn("n1", self.store.allowlist)
        self.assertEqual(self.store.audit_events, [])
        self.assertEqual(self.store.audit_checkpoint["event_id"], 0)

    def test_failed_remove_save_restores_entry_and_event(self) -> None:
        self.assertEqual(self.add()[0], 201)
        original_save = self.store.save

        def failing_save() -> None:
            raise OSError("simulated persistence failure")

        self.store.save = failing_save
        try:
            with self.assertRaises(OSError):
                self.svc.remove_allowlist_entry("n1")
        finally:
            self.store.save = original_save
        self.assertEqual(self.store.allowlist, {"n1": FUTURE})
        self.assertEqual(len(self.store.audit_events), 1)
        self.assertEqual(
            self.store.audit_checkpoint["event_id"], 1
        )

    # -- restart durability and strict recovery ------------------------------

    def test_restart_preserves_allowlist_lifecycle(self) -> None:
        self.add("n1")
        self.svc.remove_allowlist_entry("n1")
        self.add("n2", FUTURE - 5)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        # The removed entry is gone and the surviving (already-expired) entry
        # is retained with its recorded deadline.
        self.assertEqual(reopened.allowlist, {"n2": FUTURE - 5})
        kinds = [e["kind"] for e in reopened.audit_events]
        self.assertEqual(
            kinds,
            ["allowlist_added", "allowlist_removed", "allowlist_added"],
        )
        self.assertEqual(reopened.audit_checkpoint["event_id"], 3)
        # Hash links and checkpoint survive the restart unchanged.
        self.assertEqual(
            reopened.audit_checkpoint["event_hash"],
            reopened.audit_events[-1]["event_hash"],
        )

    def test_corrupt_allowlist_section_fails_recovery(self) -> None:
        self.add("n1")
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["allowlist"]["n1"] = "soon"
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_corrupt_allowlist_event_fails_recovery(self) -> None:
        self.add("n1")
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["audit_events"][0]["expires_at"] = True
        # The hash chain guards the event too: recompute it consistently so the
        # failure is attributable to the allowlist payload type check.
        from ledger import audit as audit_mod

        data["audit_events"] = audit_mod.link_events(data["audit_events"])
        data["audit_checkpoint"] = audit_mod.make_checkpoint(data["audit_events"])
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_missing_allowlist_event_field_fails_recovery(self) -> None:
        self.add("n1")
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        del data["audit_events"][0]["source"]
        from ledger import audit as audit_mod

        data["audit_events"] = audit_mod.link_events(data["audit_events"])
        data["audit_checkpoint"] = audit_mod.make_checkpoint(data["audit_events"])
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)


class AllowlistHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(LedgerStore(self.state_path, initial_balance=1000))
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
            self.base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_lifecycle(self) -> None:
        status, body = self._request(
            "POST", "/v1/trust/allowlist", {"source": "n1", "expires_at": FUTURE}
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(body, {"source": "n1", "expires_at": FUTURE})
        # Idempotent retry.
        self.assertEqual(
            self._request(
                "POST", "/v1/trust/allowlist", {"source": "n1", "expires_at": FUTURE}
            )[0],
            200,
        )
        # Changed content conflicts.
        self.assertEqual(
            self._request(
                "POST", "/v1/trust/allowlist", {"source": "n1", "expires_at": 123}
            )[0],
            409,
        )
        # Malformed body.
        self.assertEqual(
            self._request(
                "POST", "/v1/trust/allowlist", {"source": "", "expires_at": 1}
            )[0],
            400,
        )
        self.assertEqual(
            self._request(
                "POST", "/v1/trust/allowlist", {"source": "n", "expires_at": True}
            )[0],
            400,
        )
        # Delete unknown then known; the trust document reflects the removal.
        self.assertEqual(
            self._request("DELETE", "/v1/trust/allowlist/ghost")[0], 404
        )
        status, body = self._request("DELETE", "/v1/trust/allowlist/n1")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"source": "n1", "removed": True})
        _, doc = self._request("GET", "/v1/trust")
        self.assertNotIn("n1", doc["allowlist"])

    def test_http_routes_do_not_shadow_existing_trust_endpoints(self) -> None:
        # Existing keyed-registry routes keep working alongside the new ones.
        status, _ = self._request(
            "POST",
            "/v1/trust/sources",
            {"source": "k1", "public_key": KEY_A, "expires_at": FUTURE},
        )
        self.assertEqual(status, 201)
        status, _ = self._request(
            "POST", "/v1/trust/allowlist", {"source": "k1", "expires_at": FUTURE}
        )
        self.assertEqual(status, 201)
        # Removing the allowlist entry leaves the keyed source active.
        self.assertEqual(self._request("DELETE", "/v1/trust/allowlist/k1")[0], 200)
        _, doc = self._request("GET", "/v1/trust")
        self.assertIn("k1", doc["sources"])
        self.assertNotIn("k1", doc["allowlist"])
        # Unknown DELETE routes still 404.
        self.assertEqual(self._request("DELETE", "/v1/trust/nope")[0], 404)

    def _cli(self, *argv) -> tuple[int, str]:
        out = StringIO()
        with redirect_stdout(out):
            try:
                rc = cli_main(["--base-url", self.base, *argv])
            except SystemExit as exc:
                # argparse rejects a malformed argument before any request.
                rc = int(exc.code) if isinstance(exc.code, int) else 1
        return rc, out.getvalue().strip()

    def test_cli_allowlist_commands(self) -> None:
        rc, line = self._cli(
            "trust", "allowlist-add", "--source", "c1", "--expires-at", str(FUTURE)
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertEqual(json.loads(line), {"source": "c1", "expires_at": FUTURE})
        # Idempotent repeat stays successful single-line JSON.
        rc, _ = self._cli(
            "trust", "allowlist-add", "--source", "c1", "--expires-at", str(FUTURE)
        )
        self.assertEqual(rc, 0)
        rc, line = self._cli("trust", "allowlist-remove", "--source", "c1")
        self.assertEqual(rc, 0)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertEqual(json.loads(line), {"source": "c1", "removed": True})
        # Non-2xx responses print JSON and exit 1.
        rc, line = self._cli("trust", "allowlist-remove", "--source", "c1")
        self.assertEqual(rc, 1)
        self.assertTrue(json.loads(line).get("error"))
        # A server-side validation failure (empty source) prints JSON exit 1.
        rc, line = self._cli(
            "trust", "allowlist-add", "--source", "", "--expires-at", "1"
        )
        self.assertEqual(rc, 1)
        self.assertTrue(json.loads(line).get("error"))
        # argparse itself rejects a non-integer expiry before any request.
        rc, _ = self._cli(
            "trust", "allowlist-add", "--source", "c1", "--expires-at", "not-an-int"
        )
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
