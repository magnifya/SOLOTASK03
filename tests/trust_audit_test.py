"""Tests for persisted source trust management and the audit event log.

Covers POST /v1/trust/sources (201 version=1/active, identical content 200,
conflicting content 409, field validation 400), rotate (200 version bump,
unknown/revoked 404, stale expected_version 409), revoke (200 revoked,
unknown 404, conflict 409, idempotent repeat 200 without a second event),
atomic persistence of the registry change together with its audit event and
rollback on a failed save, GET /v1/trust (fixed genesis_hash, active and
unexpired sources only, allowlist retained verbatim), GET /v1/audit/events
(source/kind filters, limit default 50 / range 1-200, event_id ascending,
items/total/next_cursor pagination with cursor == total -> empty page and
cursor > total -> 400), sync_received/sync_adopted/sync_expired coverage
(received only on the first delivery, adopted per live record, rows remaining
queryable after adoption or expiry), StateRecoveryError on a tampered trust
registry or audit log and on same-generation content conflicts, plus the HTTP
and CLI surfaces.

Run: python3 tests/trust_audit_test.py
"""
from __future__ import annotations

import io
import json
import os
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
from ledger.models import Block, Transaction, compute_block_hash
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import (
    SNAPSHOT_PREFIX,
    GENESIS_PREV_HASH,
    LedgerStore,
    StateRecoveryError,
)

KEY1 = "a" * 64
KEY2 = "b" * 64
FUTURE = 2_000_000_000
FUTURE2 = 2_000_000_100


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


class TrustRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )

    def test_new_source_is_201_version_one_active_with_event(self) -> None:
        status, body = self.svc.register_trust_source(
            {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
        )
        self.assertEqual(status, 201)
        self.assertEqual(
            body,
            {
                "source": "node-a",
                "public_key": KEY1,
                "expires_at": FUTURE,
                "version": 1,
                "status": "active",
                "event_id": 1,
            },
        )
        events = self.svc.store.audit_events
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "trust_source_registered")
        self.assertEqual(events[0]["source"], "node-a")
        self.assertEqual(events[0]["event_id"], 1)

    def test_identical_registration_is_idempotent_200(self) -> None:
        payload = {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
        self.assertEqual(self.svc.register_trust_source(payload)[0], 201)
        status, body = self.svc.register_trust_source(payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], 1)
        self.assertEqual(body["status"], "active")
        # The original registration result (including its event id) is replayed.
        self.assertEqual(body["event_id"], 1)
        # No second event is recorded.
        self.assertEqual(len(self.svc.store.audit_events), 1)

    def test_conflicting_registration_is_409(self) -> None:
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
            )[0],
            201,
        )
        for payload in (
            {"source": "node-a", "public_key": KEY2, "expires_at": FUTURE},
            {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE2},
        ):
            self.assertEqual(self.svc.register_trust_source(payload)[0], 409, payload)
        # The conflicted writes left neither a second version nor an event.
        self.assertEqual(
            self.svc.store.trust_sources["node-a"]["public_key"], KEY1
        )
        self.assertEqual(len(self.svc.store.audit_events), 1)

    def test_registration_validation_errors_are_400(self) -> None:
        bad_payloads = [
            [],
            {},
            {"public_key": KEY1, "expires_at": FUTURE},
            {"source": "node-a", "expires_at": FUTURE},
            {"source": "node-a", "public_key": KEY1},
            {"source": "", "public_key": KEY1, "expires_at": FUTURE},
            {"source": 5, "public_key": KEY1, "expires_at": FUTURE},
            {"source": "node-a", "public_key": "A" * 64, "expires_at": FUTURE},
            {"source": "node-a", "public_key": "x" * 63, "expires_at": FUTURE},
            {"source": "node-a", "public_key": KEY1, "expires_at": "100"},
            {"source": "node-a", "public_key": KEY1, "expires_at": True},
            {"source": "node-a", "public_key": KEY1, "expires_at": 1.5},
        ]
        for payload in bad_payloads:
            self.assertEqual(
                self.svc.register_trust_source(payload)[0], 400, payload
            )
        self.assertEqual(self.svc.store.trust_sources, {})
        self.assertEqual(self.svc.store.audit_events, [])

    def test_registration_persists_atomically(self) -> None:
        status, body = self.svc.register_trust_source(
            {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
        )
        self.assertEqual(status, 201)
        doc = read_json(self.path)
        self.assertEqual(
            doc["trust_sources"],
            [
                {
                    "source": "node-a",
                    "public_key": KEY1,
                    "expires_at": FUTURE,
                    "version": 1,
                    "status": "active",
                }
            ],
        )
        self.assertEqual(doc["audit_events"][0]["event_id"], body["event_id"])
        # One atomic write persists both the registry and the event.
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=1000
        )
        self.assertEqual(reopened.store.trust_sources["node-a"]["version"], 1)
        self.assertEqual(len(reopened.store.audit_events), 1)

    def test_failed_save_rolls_back_registration_and_event(self) -> None:
        original = self.svc.store.save
        self.svc.store.save = lambda: (_ for _ in ()).throw(OSError("disk full"))
        with self.assertRaises(OSError):
            self.svc.register_trust_source(
                {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
            )
        self.svc.store.save = original
        self.assertNotIn("node-a", self.svc.store.trust_sources)
        self.assertEqual(self.svc.store.audit_events, [])
        # After recovery the same registration succeeds.
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
            )[0],
            201,
        )


class TrustRotateRevokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.svc.register_trust_source(
            {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
        )

    def test_rotate_advances_version(self) -> None:
        status, body = self.svc.rotate_trust_source(
            "node-a",
            {"public_key": KEY2, "expires_at": FUTURE2, "expected_version": 1},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], 2)
        self.assertEqual(body["status"], "active")
        self.assertEqual(body["public_key"], KEY2)
        self.assertEqual(body["expires_at"], FUTURE2)
        self.assertEqual(body["event_id"], 2)
        event = self.svc.store.audit_events[-1]
        self.assertEqual(event["kind"], "trust_source_rotated")
        self.assertEqual(event["details"]["previous_public_key"], KEY1)
        self.assertEqual(event["details"]["public_key"], KEY2)

    def test_rotate_unknown_or_revoked_is_404(self) -> None:
        body = {"public_key": KEY2, "expires_at": FUTURE, "expected_version": 1}
        self.assertEqual(self.svc.rotate_trust_source("ghost", body)[0], 404)
        self.assertEqual(
            self.svc.revoke_trust_source("node-a", {"expected_version": 1})[0], 200
        )
        self.assertEqual(self.svc.rotate_trust_source("node-a", body)[0], 404)

    def test_rotate_version_conflict_is_409_with_current_version(self) -> None:
        status, body = self.svc.rotate_trust_source(
            "node-a",
            {"public_key": KEY2, "expires_at": FUTURE2, "expected_version": 9},
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["current_version"], 1)
        self.assertEqual(
            self.svc.store.trust_sources["node-a"]["public_key"], KEY1
        )

    def test_rotate_validation_errors_are_400(self) -> None:
        bad = [
            [],
            {},
            {"expires_at": FUTURE, "expected_version": 1},
            {"public_key": KEY2, "expected_version": 1},
            {"public_key": KEY2, "expires_at": FUTURE},
            {"public_key": "Z" * 64, "expires_at": FUTURE, "expected_version": 1},
            {"public_key": KEY2, "expires_at": False, "expected_version": 1},
            {"public_key": KEY2, "expires_at": FUTURE, "expected_version": 0},
            {"public_key": KEY2, "expires_at": FUTURE, "expected_version": "1"},
            {"public_key": KEY2, "expires_at": FUTURE, "expected_version": True},
        ]
        for payload in bad:
            self.assertEqual(
                self.svc.rotate_trust_source("node-a", payload)[0], 400, payload
            )

    def test_rotate_failed_save_rolls_back(self) -> None:
        self.svc.store.save = lambda: (_ for _ in ()).throw(OSError("x"))
        with self.assertRaises(OSError):
            self.svc.rotate_trust_source(
                "node-a",
                {"public_key": KEY2, "expires_at": FUTURE2, "expected_version": 1},
            )
        rec = self.svc.store.trust_sources["node-a"]
        self.assertEqual(rec["version"], 1)
        self.assertEqual(rec["public_key"], KEY1)
        self.assertEqual(len(self.svc.store.audit_events), 1)

    def test_revoke_flow_and_idempotency(self) -> None:
        status, body = self.svc.revoke_trust_source(
            "node-a", {"expected_version": 1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "revoked")
        self.assertEqual(body["event_id"], 2)
        self.assertEqual(
            self.svc.store.audit_events[-1]["kind"], "trust_source_revoked"
        )
        # Repeating the revocation at the same version is idempotent 200 and
        # records no second event.
        status, again = self.svc.revoke_trust_source(
            "node-a", {"expected_version": 1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(again, body)
        self.assertEqual(len(self.svc.store.audit_events), 2)
        # Persisted status survives restart.
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=1000
        )
        self.assertEqual(
            reopened.store.trust_sources["node-a"]["status"], "revoked"
        )

    def test_revoke_unknown_is_404(self) -> None:
        self.assertEqual(
            self.svc.revoke_trust_source("ghost", {"expected_version": 1})[0], 404
        )

    def test_revoke_version_conflict_is_409(self) -> None:
        status, body = self.svc.revoke_trust_source(
            "node-a", {"expected_version": 7}
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["current_version"], 1)
        # Bad payloads are 400.
        for payload in ([], {}, {"expected_version": 0}, {"expected_version": "1"}):
            self.assertEqual(
                self.svc.revoke_trust_source("node-a", payload)[0], 400, payload
            )


class TrustDocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )

    def test_document_has_fixed_genesis_hash_and_allowlist(self) -> None:
        # The genesis hash is a function of the fixed, timestamp-free genesis
        # block, so it is identical for every fresh ledger.
        expected_genesis = compute_block_hash(
            0, GENESIS_PREV_HASH, crypto.merkle_root([])
        )
        status, doc = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        self.assertEqual(doc["genesis_hash"], expected_genesis)
        self.assertEqual(doc["genesis_hash"], self.svc.store.chain[0].block_hash)
        self.assertEqual(doc["sources"], {})
        self.assertEqual(doc["allowlist"], {})
        # The keyless allowlist is retained verbatim.
        with self.svc.store.lock:
            self.svc.store.allowlist["unsigned-node"] = FUTURE
            self.svc.store.save()
        _, doc = self.svc.get_trust_document()
        self.assertEqual(doc["allowlist"], {"unsigned-node": FUTURE})

    def test_sources_only_active_and_unexpired(self) -> None:
        self.svc.register_trust_source(
            {"source": "live", "public_key": KEY1, "expires_at": FUTURE}
        )
        self.svc.register_trust_source(
            {"source": "already-expired", "public_key": KEY2, "expires_at": 1}
        )
        self.svc.register_trust_source(
            {"source": "soon-revoked", "public_key": KEY2, "expires_at": FUTURE}
        )
        self.svc.revoke_trust_source("soon-revoked", {"expected_version": 1})

        _, doc = self.svc.get_trust_document()
        self.assertEqual(set(doc["sources"]), {"live"})
        self.assertEqual(
            doc["sources"]["live"], {"public_key": KEY1, "expires_at": FUTURE}
        )
        # Expired and revoked entries remain in the registry itself; they are
        # only hidden from the verification document.
        self.assertIn("already-expired", self.svc.store.trust_sources)
        self.assertIn("soon-revoked", self.svc.store.trust_sources)


class AuditQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.svc.register_trust_source(
            {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
        )
        self.svc.register_trust_source(
            {"source": "node-b", "public_key": KEY2, "expires_at": FUTURE}
        )
        self.svc.rotate_trust_source(
            "node-a",
            {"public_key": KEY2, "expires_at": FUTURE2, "expected_version": 1},
        )

    def test_events_ordered_by_event_id_with_shape(self) -> None:
        status, body = self.svc.list_audit_events({})
        self.assertEqual(status, 200)
        ids = [item["event_id"] for item in body["items"]]
        self.assertEqual(ids, [1, 2, 3])
        for item in body["items"]:
            self.assertEqual(
                set(item), {"event_id", "kind", "source", "at", "details"}
            )
        self.assertEqual(
            [item["kind"] for item in body["items"]],
            [
                "trust_source_registered",
                "trust_source_registered",
                "trust_source_rotated",
            ],
        )
        self.assertIsNone(body["next_cursor"])
        self.assertEqual(body["total"], 3)

    def test_filters(self) -> None:
        _, by_source = self.svc.list_audit_events({"source": "node-a"})
        self.assertEqual([i["event_id"] for i in by_source["items"]], [1, 3])
        _, by_kind = self.svc.list_audit_events({"kind": "trust_source_registered"})
        self.assertEqual(by_kind["total"], 2)
        _, both = self.svc.list_audit_events(
            {"source": "node-a", "kind": "trust_source_rotated"}
        )
        self.assertEqual([i["event_id"] for i in both["items"]], [3])
        self.assertEqual(
            self.svc.list_audit_events({"source": ""})[0], 400
        )
        self.assertEqual(self.svc.list_audit_events({"kind": ""})[0], 400)

    def test_pagination_default_limit_and_bounds(self) -> None:
        # Add enough events to cross the default page size of 50.
        with self.svc.store.lock:
            for _ in range(55):
                self.svc.store.append_event("trust_source_registered", "x", 1, {})
            self.svc.store.save()
        first = self.svc.list_audit_events({})[1]
        self.assertEqual(len(first["items"]), 50)
        self.assertEqual(first["total"], 58)
        self.assertEqual(first["next_cursor"], 50)
        second = self.svc.list_audit_events({"cursor": "50"})[1]
        self.assertEqual(len(second["items"]), 8)
        self.assertEqual(second["items"][0]["event_id"], 51)
        self.assertIsNone(second["next_cursor"])
        # limit bounds.
        self.assertEqual(self.svc.list_audit_events({"limit": "1"})[0], 200)
        self.assertEqual(self.svc.list_audit_events({"limit": "200"})[0], 200)
        for bad in ("0", "201", "-1", "01", "x"):
            self.assertEqual(
                self.svc.list_audit_events({"limit": bad})[0], 400, bad
            )
        for bad in ("-1", "01", "x"):
            self.assertEqual(
                self.svc.list_audit_events({"cursor": bad})[0], 400, bad
            )
        # cursor == total -> empty page; cursor > total -> 400.
        empty = self.svc.list_audit_events({"cursor": "58"})[1]
        self.assertEqual(empty["items"], [])
        self.assertIsNone(empty["next_cursor"])
        self.assertEqual(self.svc.list_audit_events({"cursor": "59"})[0], 400)


class SyncAuditEventTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.genesis = self.svc.store.chain[0]
        self.block = Block.create(
            1,
            self.genesis.block_hash,
            [Transaction.from_dict(signed_tx(self.ka, self.A, self.B, 10))],
        )
        self.doc = {
            "tip_hash": self.block.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
            "blocks": [self.genesis.to_dict(), self.block.to_dict()],
        }

    def _sync(self, source: str, request_id: str, expires_at: int) -> tuple[int, dict]:
        return self.svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": self.doc,
            }
        )

    def test_received_then_adopted_then_expired_events(self) -> None:
        self.assertEqual(self._sync("node-1", "r1", FUTURE)[0], 201)
        # The same-key retry returns 200 and does not append another event.
        self.assertEqual(self._sync("node-1", "r1", FUTURE)[0], 200)
        self.assertEqual(
            [e["kind"] for e in self.svc.store.audit_events], ["sync_received"]
        )

        # A second live sync record referencing the same delivered tip produces
        # one adopted event per record on adoption. A duplicate tip is rejected
        # through the API by the existing de-duplication rule, so the second
        # record is set up directly (it models a record already on disk).
        with self.svc.store.lock:
            self.svc.store.syncs[("node-2", "r9")] = {
                "tip_hash": self.block.block_hash,
                "expires_at": FUTURE,
                "fingerprint": "x",
            }
            self.svc.store.save()

        self.assertEqual(self.svc.adopt_fork(self.block.block_hash)[0], 200)
        kinds = [e["kind"] for e in self.svc.store.audit_events]
        self.assertEqual(
            kinds,
            [
                "sync_received",
                "sync_adopted",
                "sync_adopted",
            ],
        )
        adopted_sources = {
            e["source"]
            for e in self.svc.store.audit_events
            if e["kind"] == "sync_adopted"
        }
        self.assertEqual(adopted_sources, {"node-1", "node-2"})
        for event in self.svc.store.audit_events:
            if event["kind"] == "sync_adopted":
                self.assertEqual(event["details"]["tip_hash"], self.block.block_hash)
                self.assertEqual(event["details"]["height"], 1)

        # Expiring the records keeps every historical event queryable.
        with self.svc.store.lock:
            for rec in self.svc.store.syncs.values():
                rec["expires_at"] = 0
            self.svc._prune_expired_syncs()
        kinds = [e["kind"] for e in self.svc.store.audit_events]
        self.assertEqual(
            kinds,
            [
                "sync_received",
                "sync_adopted",
                "sync_adopted",
                "sync_expired",
                "sync_expired",
            ],
        )
        # Adopted and expired rows survive: the audit log is append-only.
        self.assertEqual(
            self.svc.list_audit_events({"kind": "sync_received"})[1]["total"], 1
        )
        self.assertEqual(
            self.svc.list_audit_events({"kind": "sync_adopted"})[1]["total"], 2
        )
        self.assertEqual(
            self.svc.list_audit_events({"kind": "sync_expired"})[1]["total"], 2
        )

    def test_direct_candidate_adoption_records_no_sync_event(self) -> None:
        # A directly submitted candidate (no sync record) adopts without any
        # sync_adopted event.
        self.assertEqual(
            self.svc.submit_fork_candidate({"blocks": self.doc["blocks"]})[0], 201
        )
        self.assertEqual(self.svc.adopt_fork(self.block.block_hash)[0], 200)
        self.assertEqual(self.svc.store.audit_events, [])

    def test_events_durable_after_restart(self) -> None:
        self._sync("node-1", "r1", FUTURE)
        self.svc.adopt_fork(self.block.block_hash)
        with self.svc.store.lock:
            for rec in self.svc.store.syncs.values():
                rec["expires_at"] = 0
            self.svc._prune_expired_syncs()
        kinds_before = [e["kind"] for e in self.svc.store.audit_events]
        reopened = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.assertEqual(
            [e["kind"] for e in reopened.store.audit_events], kinds_before
        )


class TrustRecoveryTests(unittest.TestCase):
    def _built_state(self, path: str) -> LedgerService:
        svc = LedgerService(LedgerStore(path), initial_balance=1000)
        svc.register_trust_source(
            {"source": "node-a", "public_key": KEY1, "expires_at": FUTURE}
        )
        svc.rotate_trust_source(
            "node-a",
            {"public_key": KEY2, "expires_at": FUTURE2, "expected_version": 1},
        )
        return svc

    def _reload_tampered(self, mutate) -> None:
        src_dir = tempfile.mkdtemp()
        src_path = os.path.join(src_dir, "s.json")
        self._built_state(src_path)
        data = read_json(src_path)
        mutate(data)
        out_dir = tempfile.mkdtemp()
        path = os.path.join(out_dir, "state.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(path)

    def test_tampered_trust_registry_rejected(self) -> None:
        self._reload_tampered(
            lambda d: d["trust_sources"][0].__setitem__("expires_at", "soon")
        )
        self._reload_tampered(
            lambda d: d["trust_sources"][0].__setitem__("status", "bogus")
        )
        self._reload_tampered(
            lambda d: d["trust_sources"][0].__setitem__("public_key", "z" * 64)
        )

    def test_tampered_audit_log_rejected(self) -> None:
        self._reload_tampered(lambda d: d["audit_events"][0].__setitem__("event_id", 5))
        self._reload_tampered(lambda d: d["audit_events"][-1].__setitem__("kind", ""))

    def test_same_generation_trust_conflict_rejected(self) -> None:
        one_dir = tempfile.mkdtemp()
        one_path = os.path.join(one_dir, "s.json")
        self._built_state(one_path)
        other_dir = tempfile.mkdtemp()
        other_path = os.path.join(other_dir, "s.json")
        svc2 = self._built_state(other_path)
        svc2.register_trust_source(
            {"source": "node-c", "public_key": KEY1, "expires_at": FUTURE}
        )
        first = read_json(one_path)
        second = read_json(other_path)
        gen = 777
        first["state"]["generation"] = gen
        second["state"]["generation"] = gen
        conflict_dir = tempfile.mkdtemp()
        main_path = os.path.join(conflict_dir, "state.json")
        with open(main_path, "w", encoding="utf-8") as fh:
            json.dump(first, fh)
        with open(
            os.path.join(conflict_dir, f"{SNAPSHOT_PREFIX}twin.gen{gen}"), "w"
        ) as fh:
            json.dump(second, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(main_path)
        self.assertIn("conflicting snapshots", ctx.exception.reason)


class TrustAuditHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, method: str, path: str, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{cls.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_trust_lifecycle_and_audit_over_http(self) -> None:
        status, body = self.request(
            "POST",
            "/v1/trust/sources",
            {"source": "http-a", "public_key": KEY1, "expires_at": FUTURE},
        )
        self.assertEqual(status, 201, body)
        self.assertEqual((body["version"], body["status"]), (1, "active"))
        # Identical retry -> 200; conflicting -> 409.
        self.assertEqual(
            self.request(
                "POST",
                "/v1/trust/sources",
                {"source": "http-a", "public_key": KEY1, "expires_at": FUTURE},
            )[0],
            200,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/trust/sources",
                {"source": "http-a", "public_key": KEY2, "expires_at": FUTURE},
            )[0],
            409,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/trust/sources/http-a/rotate",
                {"public_key": KEY2, "expires_at": FUTURE2, "expected_version": 1},
            )[0],
            200,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/trust/sources/http-a/rotate",
                {"public_key": KEY1, "expires_at": FUTURE, "expected_version": 1},
            )[0],
            409,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/trust/sources/missing/rotate",
                {"public_key": KEY1, "expires_at": FUTURE, "expected_version": 1},
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST",
                "/v1/trust/sources/http-a/revoke",
                {"expected_version": 2},
            )[0],
            200,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/trust/sources/nope/revoke", {"expected_version": 1}
            )[0],
            404,
        )
        # Verification document hides the now-revoked source.
        _, doc = self.request("GET", "/v1/trust")
        self.assertNotIn("http-a", doc["sources"])
        self.assertIn("genesis_hash", doc)
        # Audit listing.
        status, listing = self.request(
            "GET", "/v1/audit/events?source=http-a&limit=2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["items"]), 2)
        self.assertEqual(listing["items"][0]["kind"], "trust_source_registered")
        self.assertEqual(listing["next_cursor"], 2)
        self.assertEqual(self.request("GET", "/v1/audit/events?limit=0")[0], 400)
        self.assertEqual(self.request("GET", "/v1/audit/events?cursor=9999")[0], 400)

    def test_non_json_body_400(self) -> None:
        req = urllib.request.Request(
            f"{self.base}/v1/trust/sources",
            data=b"not-json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)


class TrustAuditCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw)

    def test_trust_and_audit_cli(self) -> None:
        rc, body = self.run_cli(
            "trust", "register", "--source", "cli-a",
            "--public-key", KEY1, "--expires-at", str(FUTURE),
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual((body["version"], body["status"]), (1, "active"))
        rc, body = self.run_cli(
            "trust", "rotate", "--source", "cli-a",
            "--public-key", KEY2, "--expires-at", str(FUTURE2),
            "--expected-version", "1",
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["version"], 2)
        rc, doc = self.run_cli("trust", "export")
        self.assertEqual(rc, 0)
        self.assertEqual(
            doc["sources"]["cli-a"],
            {"public_key": KEY2, "expires_at": FUTURE2},
        )
        rc, listing = self.run_cli("audit", "--source", "cli-a")
        self.assertEqual(rc, 0)
        self.assertEqual(
            [i["kind"] for i in listing["items"]],
            ["trust_source_registered", "trust_source_rotated"],
        )
        rc, listing = self.run_cli("audit", "--kind", "trust_source_rotated")
        self.assertEqual(rc, 0)
        self.assertEqual(listing["total"], 1)
        # Revoke and repeat (idempotent 200).
        self.assertEqual(
            self.run_cli(
                "trust", "revoke", "--source", "cli-a",
                "--expected-version", "2",
            )[0],
            0,
        )
        self.assertEqual(
            self.run_cli(
                "trust", "revoke", "--source", "cli-a",
                "--expected-version", "2",
            )[0],
            0,
        )
        # A conflict and an unknown source exit 1.
        self.assertEqual(
            self.run_cli(
                "trust", "revoke", "--source", "cli-a",
                "--expected-version", "1",
            )[0],
            1,
        )
        self.assertEqual(
            self.run_cli(
                "trust", "rotate", "--source", "ghost",
                "--public-key", KEY1, "--expires-at", str(FUTURE),
                "--expected-version", "1",
            )[0],
            1,
        )
        self.assertEqual(self.run_cli("audit", "--limit", "0")[0], 1)
        self.assertEqual(self.run_cli("audit", "--cursor", "xx")[0], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
