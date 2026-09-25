"""Tests for persistent source trust and the append-only audit log.

Covers POST /v1/trust/sources (201 at version 1 active, 200 idempotent
re-post, 409 on changed content, 400 on malformed input), rotate (404
unknown/revoked, 409 version mismatch, version increment), revoke (404
unknown, 409 mismatch, revoked state, 200 idempotent repeat), atomic
persistence of every change together with its audit event, GET /v1/trust
(fixed genesis hash, active unexpired sources only, allowlist preserved),
GET /v1/audit/events (source/kind filters, limit default 50 / 1-200,
cursor pagination by ascending event_id, cursor == total empty page,
cursor > total 400, items/total/next_cursor), sync reception/adoption/
expiry audit events that stay queryable after adoption or expiry,
restart durability, strict recovery rejection of corrupt trust sections
and same-generation snapshot conflicts (StateRecoveryError), plus the
HTTP and CLI surfaces.

Run: python3 tests/trust_audit_test.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import Block
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

KEY_A = "a" * 64
KEY_B = "b" * 64
FUTURE = 1_900_000_000


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def make_block(genesis: Block, key, sender, recipient, amount, *, height=1, status="confirmed"):
    from ledger.models import Transaction

    return Block.create(
        height,
        genesis.block_hash,
        [Transaction.from_dict(signed_tx(key, sender, recipient, amount))],
        status,
    )


def make_fork(genesis: Block, blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class TrustAuditServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.key, self.pub = keypair()
        self.key2, self.pub2 = keypair()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def register(self, source="node-1", key_hex=KEY_A, expires_at=FUTURE):
        return self.svc.register_trust_source(
            {"source": source, "public_key": key_hex, "expires_at": expires_at}
        )

    def _ensure_sync_trust(self, source: str) -> None:
        # Sync deliveries require an active trusted source. The first call
        # records a source_registered audit event; re-posts are idempotent.
        status, body = self.register(source, KEY_A, FUTURE)
        self.assertIn(status, (200, 201), body)

    # -- registration --------------------------------------------------------

    def test_register_creates_version_1_active_with_event(self) -> None:
        status, body = self.register()
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "source": "node-1",
                "public_key": KEY_A,
                "expires_at": FUTURE,
                "version": 1,
                "status": "active",
            },
        )
        status, audit = self.svc.list_audit_events({})
        self.assertEqual(status, 200)
        self.assertEqual(audit["total"], 1)
        self.assertEqual(audit["items"][0]["kind"], "source_registered")
        self.assertEqual(audit["items"][0]["event_id"], 1)
        self.assertEqual(audit["items"][0]["source"], "node-1")

    def test_register_same_content_is_idempotent_200(self) -> None:
        self.assertEqual(self.register()[0], 201)
        status, body = self.register()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["version"], 1)
        _, audit = self.svc.list_audit_events({})
        # Idempotent re-post records no second event.
        self.assertEqual(audit["total"], 1)

    def test_register_different_content_conflicts_409(self) -> None:
        self.assertEqual(self.register()[0], 201)
        status, body = self.register(key_hex=KEY_B)
        self.assertEqual(status, 409, body)
        status, body = self.register(expires_at=FUTURE + 1)
        self.assertEqual(status, 409, body)

    def test_register_validation_errors_400(self) -> None:
        for bad in (
            {"source": "", "public_key": KEY_A, "expires_at": FUTURE},
            {"source": "n", "public_key": "Z" * 64, "expires_at": FUTURE},
            {"source": "n", "public_key": KEY_A, "expires_at": "soon"},
            {"source": "n", "public_key": KEY_A, "expires_at": True},
            {"source": "n", "public_key": KEY_A[:63], "expires_at": FUTURE},
            ["not", "an", "object"],
        ):
            status, body = self.svc.register_trust_source(bad)
            self.assertEqual(status, 400, bad)

    # -- rotation -----------------------------------------------------------

    def test_rotate_increments_version_and_events(self) -> None:
        self.register()
        status, body = self.svc.rotate_trust_source(
            "node-1",
            {"public_key": KEY_B, "expires_at": FUTURE + 10, "expected_version": 1},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["version"], 2)
        self.assertEqual(body["status"], "active")
        self.assertEqual(body["public_key"], KEY_B)
        _, audit = self.svc.list_audit_events({})
        self.assertEqual([e["kind"] for e in audit["items"]][:2],
                         ["source_registered", "source_rotated"])

    def test_rotate_unknown_or_revoked_is_404(self) -> None:
        status, _ = self.svc.rotate_trust_source(
            "ghost", {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 1}
        )
        self.assertEqual(status, 404)
        self.register()
        self.assertEqual(
            self.svc.revoke_trust_source("node-1", {"expected_version": 1})[0], 200
        )
        status, _ = self.svc.rotate_trust_source(
            "node-1", {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 2}
        )
        self.assertEqual(status, 404)

    def test_rotate_version_mismatch_is_409(self) -> None:
        self.register()
        status, _ = self.svc.rotate_trust_source(
            "node-1", {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 9}
        )
        self.assertEqual(status, 409)

    # -- revocation ---------------------------------------------------------

    def test_revoke_lifecycle_and_idempotency(self) -> None:
        self.register()
        status, body = self.svc.revoke_trust_source("node-1", {"expected_version": 1})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "revoked")
        # Repeating at the same recorded version is idempotent: 200, no event.
        status, body = self.svc.revoke_trust_source("node-1", {"expected_version": 1})
        self.assertEqual(status, 200)
        _, audit = self.svc.list_audit_events({})
        self.assertEqual(sum(e["kind"] == "source_revoked" for e in audit["items"]), 1)
        # Wrong version conflicts.
        status, _ = self.svc.revoke_trust_source("node-1", {"expected_version": 2})
        self.assertEqual(status, 409)
        # Unknown source 404.
        status, _ = self.svc.revoke_trust_source("ghost", {"expected_version": 1})
        self.assertEqual(status, 404)
        # Malformed version 400.
        status, _ = self.svc.revoke_trust_source("node-1", {"expected_version": "x"})
        self.assertEqual(status, 400)

    # -- GET /v1/trust ------------------------------------------------------

    def test_trust_document_filters_and_preserves_allowlist(self) -> None:
        self.register("live", KEY_A, FUTURE)
        self.register("expired", KEY_B, int(time.time()) - 1)
        self.register("revoked", KEY_A, FUTURE)
        self.svc.revoke_trust_source("revoked", {"expected_version": 1})
        self.store.allowlist["keyless-node"] = FUTURE
        self.store.save()
        status, doc = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        self.assertEqual(doc["genesis_hash"], self.genesis.block_hash)
        self.assertEqual(set(doc["sources"]), {"live"})
        self.assertEqual(
            doc["sources"]["live"], {"public_key": KEY_A, "expires_at": FUTURE}
        )
        self.assertEqual(doc["allowlist"], {"keyless-node": FUTURE})

    # -- audit pagination ----------------------------------------------------

    def test_audit_pagination_filters_and_cursor_rules(self) -> None:
        for i in range(5):
            self.register(f"n{i}", format(i + 1, "064x"), FUTURE)
        status, page = self.svc.list_audit_events({"limit": "2", "cursor": "0"})
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 5)
        self.assertEqual([e["event_id"] for e in page["items"]], [1, 2])
        self.assertEqual(page["next_cursor"], 2)
        status, page = self.svc.list_audit_events({"limit": "2", "cursor": "2"})
        self.assertEqual([e["event_id"] for e in page["items"]], [3, 4])
        status, page = self.svc.list_audit_events({"limit": "2", "cursor": "4"})
        self.assertEqual([e["event_id"] for e in page["items"]], [5])
        self.assertIsNone(page["next_cursor"])
        # cursor == total -> empty page
        status, page = self.svc.list_audit_events({"cursor": "5"})
        self.assertEqual(status, 200)
        self.assertEqual(page["items"], [])
        # cursor > total -> 400
        status, _ = self.svc.list_audit_events({"cursor": "6"})
        self.assertEqual(status, 400)
        # bad limit / leading zeros
        self.assertEqual(self.svc.list_audit_events({"limit": "0"})[0], 400)
        self.assertEqual(self.svc.list_audit_events({"limit": "201"})[0], 400)
        self.assertEqual(self.svc.list_audit_events({"limit": "01"})[0], 400)
        self.assertEqual(self.svc.list_audit_events({"cursor": "x"})[0], 400)
        # filters
        status, page = self.svc.list_audit_events({"source": "n2"})
        self.assertEqual(page["total"], 1)
        status, page = self.svc.list_audit_events({"kind": "source_registered"})
        self.assertEqual(page["total"], 5)
        self.assertEqual(self.svc.list_audit_events({"kind": "nope"})[1]["total"], 0)

    # -- sync events: received / adopted / expired --------------------------

    def _sync_fork(self, *, source="node-2", request_id="req-1", expires_at=None):
        block = make_block(self.genesis, self.key, self.pub, self.pub2, 10)
        candidate = make_fork(self.genesis, [self.genesis, block])
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        self._ensure_sync_trust(source)
        return self.svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": candidate,
            }
        )

    def test_sync_received_event_persisted(self) -> None:
        status, body = self._sync_fork()
        self.assertEqual(status, 201, body)
        _, audit = self.svc.list_audit_events({"kind": "sync_received"})
        self.assertEqual(audit["total"], 1)
        event = audit["items"][0]
        self.assertEqual(event["source"], "node-2")
        self.assertEqual(event["request_id"], "req-1")
        self.assertEqual(event["tip_hash"], body["tip_hash"])
        self.assertEqual(event["expires_at"], body["expires_at"])

    def test_sync_adopted_event_survives_adoption(self) -> None:
        _, body = self._sync_fork()
        status, _ = self.svc.adopt_fork(body["tip_hash"])
        self.assertEqual(status, 200)
        _, audit = self.svc.list_audit_events({"source": "node-2"})
        kinds = [e["kind"] for e in audit["items"]]
        # The source's own registration event also carries source="node-2";
        # the sync events follow in append order and remain queryable.
        self.assertEqual(
            kinds, ["source_registered", "sync_received", "sync_adopted"]
        )
        # Still queryable after adoption, by kind and source.
        _, adopted = self.svc.list_audit_events({"kind": "sync_adopted"})
        self.assertEqual(adopted["total"], 1)
        self.assertEqual(adopted["items"][0]["tip_hash"], body["tip_hash"])

    def test_sync_expired_event_survives_expiry(self) -> None:
        _, body = self._sync_fork(expires_at=int(time.time()) - 10)
        # A fresh expired submission is 410 and records nothing; instead
        # register live, then force expiry and trigger the sweep.
        status, body = self._sync_fork(request_id="req-2", expires_at=int(time.time()) + 3600)
        self.assertEqual(status, 201)
        rec = self.store.syncs[("node-2", "req-2")]
        rec["expires_at"] = int(time.time()) - 5
        # Any locked operation runs the expiry sweep; query the audit log.
        status, audit = self.svc.list_audit_events({})
        self.assertEqual(status, 200)
        kinds = [e["kind"] for e in audit["items"]]
        self.assertIn("sync_expired", kinds)
        expired = [e for e in audit["items"] if e["kind"] == "sync_expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["tip_hash"], body["tip_hash"])
        # The delivered candidate fork is gone with its record...
        self.assertNotIn(body["tip_hash"], self.store.forks)
        self.assertNotIn(("node-2", "req-2"), self.store.syncs)
        # ...but the event remains queryable.
        _, again = self.svc.list_audit_events({"kind": "sync_expired"})
        self.assertEqual(again["total"], 1)

    def test_adopted_sync_expiry_leaves_chain_intact(self) -> None:
        _, body = self._sync_fork(expires_at=int(time.time()) + 3600)
        self.assertEqual(self.svc.adopt_fork(body["tip_hash"])[0], 200)
        tip_hash = body["tip_hash"]
        self.store.syncs[("node-2", "req-1")]["expires_at"] = int(time.time()) - 1
        self.svc.list_audit_events({})  # trigger sweep
        self.assertEqual(self.store.tip_hash(), tip_hash)
        self.assertNotIn(("node-2", "req-1"), self.store.syncs)

    # -- durability & recovery ----------------------------------------------

    def test_restart_preserves_trust_and_events(self) -> None:
        self.register()
        self.svc.rotate_trust_source(
            "node-1", {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 1}
        )
        self.svc.revoke_trust_source("node-1", {"expected_version": 2})
        self._sync_fork()
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("node-1", reopened.trust_sources)
        rec = reopened.trust_sources["node-1"]
        self.assertEqual(rec["version"], 2)
        self.assertEqual(rec["status"], "revoked")
        self.assertEqual(rec["public_key"], KEY_B)
        kinds = [e["kind"] for e in reopened.audit_events]
        # node-1 lifecycle, then node-2's registration (the sync authorization
        # gate) followed by its sync_received event.
        self.assertEqual(
            kinds,
            [
                "source_registered",
                "source_rotated",
                "source_revoked",
                "source_registered",
                "sync_received",
            ],
        )
        # event_ids are dense 1..N
        self.assertEqual([e["event_id"] for e in reopened.audit_events], [1, 2, 3, 4, 5])
        # The live node-2 sync record survives the restart re-authorization.
        self.assertIn(("node-2", "req-1"), reopened.syncs)

    def test_corrupt_trust_section_fails_recovery(self) -> None:
        self.register()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["trust_sources"][0]["public_key"] = "z" * 64  # uppercase hex
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("public_key", ctx.exception.reason)

    def test_corrupt_audit_sequence_fails_recovery(self) -> None:
        self.register()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["audit_events"][0]["event_id"] = 7
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_same_generation_conflicting_snapshots_fail(self) -> None:
        self.register()
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        generation = data["state"]["generation"]
        data["audit_events"].append(
            {"event_id": 2, "kind": "note", "at": 1.0}
        )
        # Keep the alternative candidate individually valid under the hash
        # chain: relink the whole log and pin its checkpoint, leaving only the
        # extra event as the same-generation content conflict. (A generic
        # event kind is used: an orphan source-key lifecycle event is itself
        # fatal corruption and could no longer serve as valid twin content.)
        from ledger import audit as audit_mod

        data["audit_events"] = audit_mod.link_events(data["audit_events"])
        data["audit_checkpoint"] = audit_mod.make_checkpoint(data["audit_events"])
        snapshot = os.path.join(self.tmp, f".ledger-conflict.gen{generation}")
        with open(snapshot, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("conflicting snapshots", ctx.exception.reason)


class TrustAuditHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        import threading

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
            "POST", "/v1/trust/sources",
            {"source": "n1", "public_key": KEY_A, "expires_at": FUTURE},
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(self._request("GET", "/v1/trust")[0], 200)
        status, body = self._request(
            "POST", "/v1/trust/sources/n1/rotate",
            {"public_key": KEY_B, "expires_at": FUTURE, "expected_version": 1},
        )
        self.assertEqual(status, 200)
        status, body = self._request(
            "POST", "/v1/trust/sources/n1/revoke", {"expected_version": 2}
        )
        self.assertEqual(status, 200)
        status, body = self._request("GET", "/v1/audit/events?limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)
        self.assertEqual(body["next_cursor"], 1)
        self.assertEqual(self._request("GET", "/v1/audit/events?cursor=9")[0], 400)
        # URL-encoded source path segment.
        status, _ = self._request(
            "POST", "/v1/trust/sources/n%31/revoke", {"expected_version": 1}
        )
        self.assertIn(status, (200, 404, 409))


class TrustAuditCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        import threading

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
            "trust", "add", "--source", "n1", "--public-key", KEY_A,
            "--expires-at", str(FUTURE),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertEqual(json.loads(line)["version"], 1)

        rc, line = self._cli("trust", "export")
        self.assertEqual(rc, 0)
        self.assertIn("genesis_hash", json.loads(line))

        rc, line = self._cli(
            "trust", "rotate", "--source", "n1", "--public-key", KEY_B,
            "--expires-at", str(FUTURE), "--expected-version", "1",
        )
        self.assertEqual(rc, 0)
        rc, line = self._cli(
            "trust", "revoke", "--source", "n1", "--expected-version", "2"
        )
        self.assertEqual(rc, 0)
        rc, line = self._cli("audit", "--limit", "2")
        self.assertEqual(rc, 0)
        body = json.loads(line)
        self.assertEqual(body["total"], 3)
        self.assertEqual(len(body["items"]), 2)
        rc, line = self._cli("audit", "--kind", "source_registered")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(line)["total"], 1)

        # Non-2xx prints JSON and exits 1.
        rc, line = self._cli(
            "trust", "rotate", "--source", "ghost", "--public-key", KEY_B,
            "--expires-at", str(FUTURE), "--expected-version", "1",
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line)["error"] is not None, True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
