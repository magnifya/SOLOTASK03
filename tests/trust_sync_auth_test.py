"""Tests for source authorization and the audit lifecycle around fork sync.

Covers the POST /v1/forks/sync authorization gate: a new request's source
must be a persistently registered, still-active trust source whose
registration has not expired — unknown/revoked/trust-expired sources get 403
before the request's own expiry (410) and before candidate-chain validation;
malformed envelope fields still get 400 first. A same source+request_id retry
on a still-live record replays the original 200 (same content) or 409
(different content) even after the source is rotated or revoked. Also covers
restart re-authorization (invalid records dropped, their exclusive forks
dropped, historical audit events retained verbatim, adopted tips leaving the
canonical chain intact), failed-save rollback (chain/candidate/sync metadata/
generation restored, existing audit events byte-identical with no event_id
gap), and the HTTP + CLI surfaces for 403/410/idempotency.

Run: python3 tests/trust_sync_auth_test.py
"""
from __future__ import annotations

import copy
import io
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

KEY_A = "a" * 64
KEY_B = "b" * 64
FUTURE = 1_900_000_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key, sender, to, amount) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def make_candidate(genesis: Block, key, sender, to, amount=10) -> dict:
    block = Block.create(
        1,
        genesis.block_hash,
        [Transaction.from_dict(signed_tx(key, sender, to, amount))],
    )
    tip = block
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": 2,
        "status": tip.status,
        "blocks": [genesis.to_dict(), block.to_dict()],
    }


class SyncAuthorizationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.key, self.pub = keypair()
        _, self.pub2 = keypair()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def register(self, source="node-1", key_hex=KEY_A, expires_at=FUTURE):
        return self.svc.register_trust_source(
            {"source": source, "public_key": key_hex, "expires_at": expires_at}
        )

    def sync_body(self, candidate, *, source="node-1", request_id="req-1",
                  expires_at=None) -> dict:
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        return {
            "source": source,
            "request_id": request_id,
            "expires_at": expires_at,
            "candidate": candidate,
        }

    def sync(self, *args, **kwargs):
        return self.svc.submit_fork_sync(self.sync_body(*args, **kwargs))

    # -- 403 gate ------------------------------------------------------------

    def test_unknown_source_is_403(self) -> None:
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        status, body = self.sync(cand)
        self.assertEqual(status, 403, body)
        # A rejected delivery persists nothing and records no event.
        self.assertEqual(self.store.syncs, {})
        self.assertEqual(self.store.forks, {})
        self.assertEqual(self.store.audit_events, [])

    def test_revoked_source_is_403(self) -> None:
        self.register()
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        self.assertEqual(self.sync(cand)[0], 403)

    def test_trust_expired_source_is_403(self) -> None:
        self.register(expires_at=int(time.time()) + 3600)
        # The trust registration lapses (simulated directly and persisted); a
        # request with a future expiry of its own is still unauthorized.
        self.store.trust_sources["node-1"]["expires_at"] = int(time.time()) - 1
        self.store.save()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        status, body = self.sync(cand, expires_at=int(time.time()) + 3600)
        self.assertEqual(status, 403, body)

    def test_403_takes_precedence_over_410(self) -> None:
        # Unknown source AND an already-passed request expiry: the source is
        # rejected (403) before the request's own expiry is evaluated.
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        status, _ = self.sync(cand, expires_at=int(time.time()) - 1)
        self.assertEqual(status, 403)

    def test_403_takes_precedence_over_chain_validation(self) -> None:
        # An unknown source presenting a structurally well-formed but invalid
        # candidate is forbidden (403), not rejected for the chain defect.
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        cand["blocks"][1]["block_hash"] = "f" * 64
        self.assertEqual(self.sync(cand)[0], 403)

    def test_malformed_envelope_is_400_before_authorization(self) -> None:
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        for bad_source in ("", 1, None, []):
            body = self.sync_body(cand, source=bad_source)  # type: ignore[arg-type]
            self.assertEqual(self.svc.submit_fork_sync(body)[0], 400, bad_source)
        # A missing field is a format error too.
        body = self.sync_body(cand)
        del body["request_id"]
        self.assertEqual(self.svc.submit_fork_sync(body)[0], 400)

    def test_authorized_expired_request_is_410(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        self.assertEqual(self.sync(cand, expires_at=int(time.time()))[0], 410)
        self.assertEqual(self.sync(cand, expires_at=int(time.time()) - 5)[0], 410)

    def test_authorized_fresh_request_is_201(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        status, body = self.sync(cand)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], cand["tip_hash"])

    def test_duplicate_tip_after_authorization_is_409(self) -> None:
        self.register("node-1")
        self.register("node-2", key_hex=KEY_B)
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        self.assertEqual(self.sync(cand, source="node-1", request_id="a")[0], 201)
        # An equally authorized second source pushing the identical tip: the
        # tip de-duplication runs after the gate and conflicts 409.
        self.assertEqual(
            self.sync(cand, source="node-2", request_id="b")[0], 409
        )

    # -- idempotency survives trust changes ----------------------------------

    def test_retry_after_revoke_still_replays_200(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        first_status, first_body = self.sync(cand)
        self.assertEqual(first_status, 201)
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        # Same source+request_id, identical content: the recorded 200 is
        # replayed despite the revocation, with the original expires_at.
        retry_status, retry_body = self.sync(cand)
        self.assertEqual(retry_status, 200, retry_body)
        self.assertEqual(retry_body, first_body)

    def test_retry_after_rotation_still_replays_200(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        self.assertEqual(self.sync(cand)[0], 201)
        self.assertEqual(
            self.svc.rotate_trust_source(
                "node-1",
                {"public_key": KEY_B, "expires_at": FUTURE + 10,
                 "expected_version": 1},
            )[0],
            200,
        )
        self.assertEqual(self.sync(cand)[0], 200)

    def test_retry_different_content_after_revoke_is_409(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2, amount=10)
        self.assertEqual(self.sync(cand)[0], 201)
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        other = make_candidate(self.genesis, self.key, self.pub, self.pub2, amount=11)
        # Content conflict is detected on the retry even though the source is
        # now revoked (the gate is skipped for a live key).
        self.assertEqual(self.sync(other)[0], 409)
        self.assertNotIn(other["tip_hash"], self.store.forks)

    def test_revoked_source_retry_after_record_expired_is_403(self) -> None:
        # Once the recorded delivery itself expires and is swept, the key no
        # longer exists and a revoked source can never re-deliver: 403.
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        self.assertEqual(
            self.sync(cand, expires_at=int(time.time()) + 1)[0], 201
        )
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        time.sleep(1.1)
        # Trigger the expiry sweep.
        self.svc.list_audit_events({})
        self.assertEqual(self.sync(cand)[0], 403)

    # -- restart re-authorization --------------------------------------------

    def _reopen(self) -> LedgerStore:
        return LedgerStore(self.state_path, initial_balance=1000)

    def test_restart_drops_revoked_source_record_but_keeps_events(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        _, body = self.sync(cand)
        tip = body["tip_hash"]
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        reopened = self._reopen()
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        # The source registry and the historical events are retained.
        self.assertEqual(reopened.trust_sources["node-1"]["status"], "revoked")
        kinds = [e["kind"] for e in reopened.audit_events]
        self.assertIn("source_registered", kinds)
        self.assertIn("sync_received", kinds)
        self.assertIn("source_revoked", kinds)
        received = [e for e in reopened.audit_events if e["kind"] == "sync_received"]
        self.assertEqual(received[0]["tip_hash"], tip)
        # event_ids stay dense 1..N with no gap.
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(reopened.audit_events) + 1)),
        )

    def test_restart_drops_trust_expired_record_and_fork(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        _, body = self.sync(cand)
        tip = body["tip_hash"]
        # Lapse the registration while keeping the delivery nominally live.
        self.store.trust_sources["node-1"]["expires_at"] = int(time.time()) - 1
        self.store.save()
        reopened = self._reopen()
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        self.assertTrue(
            any(e["kind"] == "sync_received" for e in reopened.audit_events)
        )

    def test_restart_keeps_authorized_live_record(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        _, body = self.sync(cand)
        tip = body["tip_hash"]
        reopened = self._reopen()
        self.assertIn(("node-1", "req-1"), reopened.syncs)
        self.assertIn(tip, reopened.forks)

    def test_restart_adopted_tip_survives_revocation_chain_intact(self) -> None:
        # Canonical starts at height 0; deliver a height-1 fork, adopt it, then
        # revoke and restart: the record disappears but the canonical chain is
        # untouched and its adoption/reception history remains queryable.
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        _, body = self.sync(cand)
        tip = body["tip_hash"]
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        reopened = self._reopen()
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertEqual(reopened.tip_hash(), tip)
        kinds = [e["kind"] for e in reopened.audit_events]
        self.assertEqual(
            [k for k in kinds if k.startswith("sync_")],
            ["sync_received", "sync_adopted"],
        )

    def test_expired_records_absent_from_sync_listing(self) -> None:
        self.register()
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        self.assertEqual(
            self.sync(cand, request_id="q", expires_at=int(time.time()) + 1)[0],
            201,
        )
        time.sleep(1.1)
        status, listing = self.svc.list_fork_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(listing["items"], [])
        self.assertEqual(listing["total"], 0)
        # The historical reception event is still in the audit log.
        _, audit = self.svc.list_audit_events({"kind": "sync_received"})
        self.assertEqual(audit["total"], 1)

    # -- failed-save rollback -------------------------------------------------

    def test_failed_receive_save_restores_everything_and_keeps_events(self) -> None:
        self.register("node-a", key_hex=KEY_A)
        # Pre-existing events/state that must survive byte-for-byte.
        events_before = copy.deepcopy(self.store.audit_events)
        generation_before = self.store.generation
        syncs_before = copy.deepcopy(self.store.syncs)
        forks_before = copy.deepcopy(list(self.store.forks))
        chain_len_before = len(self.store.chain)

        original_save = self.store.save

        def failing_save() -> None:
            raise OSError("simulated persistence failure")

        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        self.store.save = failing_save
        try:
            with self.assertRaises(OSError):
                self.sync(cand, source="node-a")
        finally:
            self.store.save = original_save

        self.assertEqual(self.store.syncs, syncs_before)
        self.assertEqual(list(self.store.forks), forks_before)
        self.assertEqual(len(self.store.chain), chain_len_before)
        self.assertEqual(self.store.generation, generation_before)
        # Existing audit events are unchanged verbatim; no event was appended.
        self.assertEqual(self.store.audit_events, events_before)

        # A subsequent successful delivery continues the event-id sequence with
        # no gap (the failed append consumed no id).
        status, _ = self.sync(cand, source="node-a")
        self.assertEqual(status, 201)
        self.assertEqual(
            [e["event_id"] for e in self.store.audit_events],
            list(range(1, len(self.store.audit_events) + 1)),
        )
        self.assertEqual(
            self.store.audit_events[-1]["event_id"], len(events_before) + 1
        )


class SyncAuthorizationHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "http.json"), initial_balance=1000),
            initial_balance=1000,
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"
        self.genesis = self.svc.store.chain[0]
        self.key, self.pub = keypair()
        _, self.pub2 = keypair()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_403_410_idempotency(self) -> None:
        cand = make_candidate(self.genesis, self.key, self.pub, self.pub2)
        now = int(time.time())

        def body(source="n1", request_id="r1", expires_at=now + 3600):
            return {
                "source": source, "request_id": request_id,
                "expires_at": expires_at, "candidate": cand,
            }

        # Unknown source -> 403.
        self.assertEqual(self._request("POST", "/v1/forks/sync", body())[0], 403)
        # Register; an expired request -> 410; a fresh one -> 201.
        self.assertEqual(
            self._request(
                "POST", "/v1/trust/sources",
                {"source": "n1", "public_key": KEY_A, "expires_at": FUTURE},
            )[0],
            201,
        )
        self.assertEqual(
            self._request("POST", "/v1/forks/sync", body(expires_at=now - 1))[0],
            410,
        )
        status, first = self._request("POST", "/v1/forks/sync", body())
        self.assertEqual(status, 201, first)
        # Revoke, then an identical retry still replays 200.
        self.assertEqual(
            self._request(
                "POST", "/v1/trust/sources/n1/revoke", {"expected_version": 1}
            )[0],
            200,
        )
        status, retry = self._request("POST", "/v1/forks/sync", body())
        self.assertEqual(status, 200)
        self.assertEqual(retry, first)
        # A new request_id from the now-revoked source is 403.
        self.assertEqual(
            self._request("POST", "/v1/forks/sync", body(request_id="r2"))[0],
            403,
        )


class SyncAuthorizationCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "cli.json"), initial_balance=1000),
            initial_balance=1000,
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.genesis = self.svc.store.chain[0]
        self.key, self.pub = keypair()
        _, self.pub2 = keypair()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cli(self, *argv) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *argv])
        raw = buf.getvalue().strip()
        self.assertEqual(len(raw.splitlines()), 1)
        return rc, json.loads(raw)

    def test_cli_403_410_and_idempotency(self) -> None:
        cand = json.dumps(
            make_candidate(self.genesis, self.key, self.pub, self.pub2)
        )
        exp = str(int(time.time()) + 3600)

        def sync_args(source, request_id, expires_at):
            return (
                "sync", "--source", source, "--request-id", request_id,
                "--expires-at", str(expires_at), cand,
            )

        # Unknown source: non-zero exit and a JSON error envelope.
        rc, body = self._cli(*sync_args("ghost", "g1", exp))
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        # Register and authorize the source.
        self.svc.register_trust_source(
            {"source": "live", "public_key": KEY_A, "expires_at": FUTURE}
        )
        # Expired request exits 1 (410).
        rc, _ = self._cli(*sync_args("live", "e1", "1"))
        self.assertEqual(rc, 1)
        # Fresh delivery succeeds.
        rc, first = self._cli(*sync_args("live", "c1", exp))
        self.assertEqual(rc, 0, first)
        # Idempotent retry prints the same body and succeeds.
        rc, retry = self._cli(*sync_args("live", "c1", exp))
        self.assertEqual(rc, 0)
        self.assertEqual(retry, first)
        # Revoke; identical retry is still the recorded 200, a fresh key is 403.
        self.assertEqual(
            self.svc.revoke_trust_source("live", {"expected_version": 1})[0], 200
        )
        rc, again = self._cli(*sync_args("live", "c1", exp))
        self.assertEqual(rc, 0)
        self.assertEqual(again, first)
        rc, _ = self._cli(*sync_args("live", "c2", exp))
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
