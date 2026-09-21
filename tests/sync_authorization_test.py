"""Tests for the source-authorization and audit lifecycle of fork sync.

Covers the authorization gate on POST /v1/forks/sync (a new source+request_id
pair is accepted only when its source is active and unexpired in the
persistent trust registry — unknown/revoked/registry-expired sources get 403;
malformed fields get 400; an authorized but past request deadline gets 410;
candidate validation and tip de-duplication happen only after authorization),
idempotent replay of a recorded request that survives later rotation,
revocation and registry expiry (same content 200, different content 409,
tampered summary 400), restart re-authorization that drops invalidated sync
records and their candidate forks while keeping the canonical adopted tip and
the verbatim historical sync_received/sync_adopted/sync_expired audit events,
save-failure rollback that restores chain, candidate, sync metadata and
generation and leaves existing audit events byte-for-byte unchanged with a
dense event_id sequence, and the HTTP/CLI surfaces of 403/410/idempotency.

Run: python3 tests/sync_authorization_test.py
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


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(signed_tx(key, sender, to, amount))


def make_fork(genesis: Block, blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class _ServiceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def register(self, source="node-1", key_hex=KEY_A, expires_at=FUTURE):
        return self.svc.register_trust_source(
            {"source": source, "public_key": key_hex, "expires_at": expires_at}
        )

    def revoke(self, source="node-1", version=1):
        return self.svc.revoke_trust_source(source, {"expected_version": version})

    def rotate(self, source, key_hex=KEY_B, expires_at=FUTURE, expected_version=1):
        return self.svc.rotate_trust_source(
            source,
            {
                "public_key": key_hex,
                "expires_at": expires_at,
                "expected_version": expected_version,
            },
        )

    def block(self, amount=10, *, sender_key=None, sender=None, recipient=None,
              height=1, prev=None, status="confirmed"):
        sender_key = sender_key or self.ka
        sender = sender or self.A
        recipient = recipient or self.B
        return Block.create(
            height,
            prev if prev is not None else self.genesis.block_hash,
            [tx_obj(sender_key, sender, recipient, amount)],
            status,
        )

    def candidate(self, *blocks):
        chain = [self.genesis, *blocks]
        return make_fork(self.genesis, chain)

    def sync(self, cand, *, source="node-1", request_id="req-1", expires_at=None):
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        return self.svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": cand,
            }
        )


class AuthorizationGateTests(_ServiceCase):
    # -- 403: unknown / revoked / registry-expired ---------------------------

    def test_unknown_source_is_403(self) -> None:
        status, body = self.sync(self.candidate(self.block()), source="ghost")
        self.assertEqual(status, 403, body)
        self.assertIn("trusted", body["error"])

    def test_revoked_source_is_403(self) -> None:
        self.assertEqual(self.register()[0], 201)
        self.assertEqual(self.revoke()[0], 200)
        status, body = self.sync(self.candidate(self.block()))
        self.assertEqual(status, 403, body)

    def test_registry_expired_source_is_403(self) -> None:
        # Active state but a registry expires_at already in the past.
        self.register(expires_at=int(time.time()) - 1)
        status, body = self.sync(self.candidate(self.block()))
        self.assertEqual(status, 403, body)

    def test_active_authorized_source_is_201(self) -> None:
        self.register()
        status, body = self.sync(self.candidate(self.block()))
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], self.block().block_hash)

    # -- status precedence ----------------------------------------------------

    def test_403_takes_precedence_over_410_and_bad_candidate(self) -> None:
        # Unknown source, a past request deadline and a tampered candidate all
        # at once: authorization fails first, so the answer is 403 — neither
        # 410 nor a candidate 400 leaks out.
        doc = self.candidate(self.block())
        doc["blocks"][1]["block_hash"] = "f" * 64
        status, body = self.sync(
            doc, source="ghost", expires_at=int(time.time()) - 10
        )
        self.assertEqual(status, 403, body)

    def test_410_after_authorization_precedes_bad_candidate(self) -> None:
        self.register()
        doc = self.candidate(self.block())
        doc["blocks"][1]["block_hash"] = "f" * 64
        status, body = self.sync(doc, expires_at=int(time.time()) - 1)
        self.assertEqual(status, 410, body)

    def test_candidate_validated_only_after_authorization(self) -> None:
        self.register()
        doc = self.candidate(self.block())
        doc["blocks"][1]["block_hash"] = "f" * 64
        status, body = self.sync(doc)
        self.assertEqual(status, 400, body)

    def test_malformed_field_is_400_even_for_unregistered_source(self) -> None:
        cand = self.candidate(self.block())
        full = {
            "source": "ghost",
            "request_id": "r",
            "expires_at": int(time.time()) + 10,
            "candidate": cand,
        }
        # Missing field.
        for field in ("source", "request_id", "expires_at", "candidate"):
            partial = dict(full)
            del partial[field]
            self.assertEqual(self.svc.submit_fork_sync(partial)[0], 400, field)
        # Non-string / empty source, non-string request_id, boolean expiry.
        for bad_source in ("", 1, None, []):
            self.assertEqual(
                self.svc.submit_fork_sync(dict(full, source=bad_source))[0], 400
            )
        for bad_rid in ("", 1, None):
            self.assertEqual(
                self.svc.submit_fork_sync(dict(full, request_id=bad_rid))[0], 400
            )
        for bad_exp in ("100", 1.5, True, None):
            self.assertEqual(
                self.svc.submit_fork_sync(dict(full, expires_at=bad_exp))[0], 400
            )
        # A non-object body is a format error regardless of registry state.
        self.assertEqual(self.svc.submit_fork_sync(["x"])[0], 400)

    # -- side-effect-free refusal --------------------------------------------

    def test_403_records_nothing(self) -> None:
        # An unregistered refusal persists nothing: no candidate, no sync
        # record, no audit event at all.
        status, _ = self.sync(self.candidate(self.block()), source="ghost")
        self.assertEqual(status, 403)
        self.assertEqual(self.store.syncs, {})
        self.assertEqual(self.store.forks, {})
        self.assertEqual(self.store.audit_events, [])

    def test_403_precedes_tip_dedup_for_unknown_source(self) -> None:
        # An authorized source delivers a candidate; an unregistered source
        # pushing the identical tip must get 403 (authorization), never the
        # 409 duplicate-tip that de-duplication would produce later.
        self.assertEqual(self.register("node-1")[0], 201)
        doc = self.candidate(self.block())
        self.assertEqual(self.sync(doc, source="node-1")[0], 201)
        status, body = self.sync(doc, source="intruder", request_id="x")
        self.assertEqual(status, 403, body)

    def test_410_records_nothing(self) -> None:
        self.register()
        status, _ = self.sync(
            self.candidate(self.block()), expires_at=int(time.time()) - 1
        )
        self.assertEqual(status, 410)
        self.assertEqual(self.store.syncs, {})
        self.assertEqual(self.store.forks, {})
        # Only the source registration event exists; no sync event.
        self.assertEqual(
            [e["kind"] for e in self.store.audit_events], ["source_registered"]
        )


class ReplaySurvivesTrustChangesTests(_ServiceCase):
    def _delivered(self, source="node-1", request_id="req-1"):
        self.assertEqual(self.register(source)[0], 201)
        doc = self.candidate(self.block())
        status, body = self.sync(doc, source=source, request_id=request_id)
        self.assertEqual(status, 201, body)
        return doc, body

    def test_replay_stays_200_after_rotation(self) -> None:
        doc, first = self._delivered()
        self.assertEqual(self.rotate("node-1", KEY_B, FUTURE, 1)[0], 200)
        status, retry = self.sync(doc)
        self.assertEqual(status, 200, retry)
        self.assertEqual(retry, first)

    def test_replay_stays_200_after_revocation(self) -> None:
        doc, first = self._delivered()
        self.assertEqual(self.rotate("node-1", KEY_B, FUTURE, 1)[0], 200)
        self.assertEqual(self.revoke(version=2)[0], 200)
        # Same recorded content replays the first 200 result even though the
        # source is now revoked.
        status, retry = self.sync(doc)
        self.assertEqual(status, 200, retry)
        self.assertEqual(retry, first)
        # A *new* request id from the revoked source is refused.
        status, body = self.sync(doc, request_id="req-new")
        self.assertEqual(status, 403, body)

    def test_replay_stays_200_after_registry_expiry(self) -> None:
        source = "ephemeral"
        self.assertEqual(
            self.register(source, KEY_A, int(time.time()) + 2)[0], 201
        )
        doc = self.candidate(self.block(amount=4))
        status, first = self.sync(doc, source=source)
        self.assertEqual(status, 201, first)
        time.sleep(2.1)  # the registry entry has now expired
        # The recorded request still replays its first result.
        status, retry = self.sync(doc, source=source)
        self.assertEqual(status, 200, retry)
        self.assertEqual(retry, first)
        # A fresh request id is no longer authorized.
        status, body = self.sync(doc, source=source, request_id="req-2")
        self.assertEqual(status, 403, body)

    def test_replay_ignores_elapsed_request_deadline(self) -> None:
        # Even an expires_at echoed past its deadline replays while the record
        # itself is still live; here combined with a revoked source.
        doc, first = self._delivered()
        self.assertEqual(self.revoke()[0], 200)
        status, retry = self.sync(doc, expires_at=int(time.time()) - 5)
        self.assertEqual(status, 200, retry)
        self.assertEqual(retry, first)

    def test_replay_different_content_is_409_after_revocation(self) -> None:
        self._delivered()
        self.assertEqual(self.revoke()[0], 200)
        other = self.candidate(self.block(amount=11))
        status, body = self.sync(other)
        self.assertEqual(status, 409, body)
        # The conflicting candidate was not stored.
        self.assertNotIn(other["tip_hash"], self.store.forks)

    def test_replay_tampered_summary_is_400_after_revocation(self) -> None:
        doc, _ = self._delivered()
        self.assertEqual(self.revoke()[0], 200)
        for field, forged in (
            ("tip_hash", "a" * 64),
            ("height", 9),
            ("length", 3),
            ("status", "pending"),
        ):
            forged_doc = dict(doc)
            forged_doc[field] = forged
            status, body = self.sync(forged_doc)
            self.assertEqual(status, 400, (field, body))

    def test_replay_writes_no_audit_event(self) -> None:
        doc, _ = self._delivered()
        kinds_after_delivery = [e["kind"] for e in self.store.audit_events]
        self.assertEqual(self.revoke()[0], 200)
        status, _ = self.sync(doc)
        self.assertEqual(status, 200)
        # Replays (even post-revocation) append no events; the log only gained
        # the single revocation event.
        kinds = [e["kind"] for e in self.store.audit_events]
        self.assertEqual(
            kinds, kinds_after_delivery + ["source_revoked"]
        )
        self.assertEqual([e["event_id"] for e in self.store.audit_events],
                         list(range(1, len(kinds) + 1)))


class RestartReauthorizationTests(_ServiceCase):
    def _events_snapshot(self):
        return [dict(e) for e in self.store.audit_events]

    def _assert_events_verbatim(self, before) -> None:
        reopened_events = [dict(e) for e in self.reopened.audit_events]
        self.assertEqual(reopened_events, before)
        self.assertEqual(
            [e["event_id"] for e in reopened_events],
            list(range(1, len(reopened_events) + 1)),
        )

    def _assert_prefix_plus_expiry(
        self, before, *, tip, source="node-1", request_id="req-1"
    ) -> dict:
        """The durable history survives verbatim, followed by exactly one
        backfilled sync_expired event with a dense, continuing event_id and
        the full lifecycle payload. Returns the backfilled event."""
        events = [dict(e) for e in self.reopened.audit_events]
        self.assertEqual(events[: len(before)], before)
        self.assertEqual(len(events), len(before) + 1)
        event = events[-1]
        self.assertEqual(event["kind"], "sync_expired")
        self.assertEqual(event["event_id"], len(before) + 1)
        self.assertEqual(event["source"], source)
        self.assertEqual(event["request_id"], request_id)
        self.assertEqual(event["tip_hash"], tip)
        self.assertIn("expires_at", event)
        self.assertEqual(
            [e["event_id"] for e in events], list(range(1, len(events) + 1))
        )
        return event

    def _reopen(self) -> LedgerStore:
        self.reopened = LedgerStore(self.state_path, initial_balance=1000)
        return self.reopened

    def test_restart_drops_revoked_source_record_and_candidate(self) -> None:
        self.assertEqual(self.register("node-1")[0], 201)
        doc = self.candidate(self.block())
        status, body = self.sync(doc)
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        self.assertEqual(self.revoke("node-1", 1)[0], 200)
        before = self._events_snapshot()

        reopened = self._reopen()
        # The pending sync record and its delivered candidate are gone...
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        # ...the registration/reception/revocation history survives verbatim,
        # followed by exactly one backfilled sync_expired for the record whose
        # authorization lapsed while the process was down.
        self._assert_prefix_plus_expiry(before, tip=tip)
        self.assertEqual(
            [e["kind"] for e in reopened.audit_events],
            ["source_registered", "sync_received", "source_revoked", "sync_expired"],
        )
        svc2 = LedgerService(reopened, initial_balance=1000)
        self.assertEqual(svc2.list_fork_syncs({})[1]["total"], 0)
        # The reception event remains queryable through the audit log.
        _, page = svc2.list_audit_events({"kind": "sync_received"})
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["tip_hash"], tip)
        # The backfilled expiry is queryable too...
        _, expired_page = svc2.list_audit_events({"kind": "sync_expired"})
        self.assertEqual(expired_page["total"], 1)
        self.assertEqual(expired_page["items"][0]["tip_hash"], tip)
        # ...and a second restart neither duplicates the event nor advances the
        # generation (nothing left to reconcile).
        generation_after = reopened.generation
        reopened_again = self._reopen()
        self.assertEqual(
            [e["kind"] for e in reopened_again.audit_events].count("sync_expired"), 1
        )
        self.assertEqual(reopened_again.generation, generation_after)

    def test_restart_keeps_record_when_source_still_active(self) -> None:
        # Rotation advances the version but keeps the same source active: the
        # recorded sync stays valid across a restart.
        self.assertEqual(self.register("node-1")[0], 201)
        doc = self.candidate(self.block())
        status, body = self.sync(doc)
        self.assertEqual(status, 201)
        self.assertEqual(
            self.rotate("node-1", KEY_B, FUTURE, expected_version=1)[0], 200
        )
        reopened = self._reopen()
        self.assertIn(("node-1", "req-1"), reopened.syncs)
        self.assertIn(body["tip_hash"], reopened.forks)

    def test_restart_drops_registry_expired_source_record(self) -> None:
        source = "ephemeral"
        self.assertEqual(
            self.register(source, KEY_A, int(time.time()) + 2)[0], 201
        )
        doc = self.candidate(self.block(amount=4))
        status, body = self.sync(doc, source=source)
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        time.sleep(2.1)  # registry entry expires while the process is "down"
        before = self._events_snapshot()

        reopened = self._reopen()
        self.assertNotIn((source, "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        # The registry entry expiring while down backfills one sync_expired
        # event; the durable history before it survives verbatim and the
        # event_id sequence stays dense.
        self._assert_prefix_plus_expiry(before, tip=tip, source=source)

    def test_restart_drops_record_when_registry_entry_missing(self) -> None:
        # Simulate a snapshot whose trust entry vanished while the sync record
        # and its reception event remain: the record is pruned, the event log
        # (dense event_ids) is preserved exactly.
        self.assertEqual(self.register("node-1")[0], 201)
        doc = self.candidate(self.block())
        status, body = self.sync(doc)
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        before = self._events_snapshot()

        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["trust_sources"] = []
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        reopened = self._reopen()
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        # A source that vanished from the registry invalidates the record while
        # down: the record is pruned and one sync_expired is backfilled, while
        # the prior event log is retained verbatim with dense event_ids.
        self._assert_prefix_plus_expiry(before, tip=tip)

    def test_restart_adopted_tip_keeps_chain_and_history_after_revoke(self) -> None:
        # Canonical confirmed block 1 (A->B 10).
        canon = self.block(amount=10)
        self.store.chain.append(canon)
        self.store.rebuild_derived()
        self.store.save()
        # Synced fork strictly longer: height1 A->C 20, height2 C->A 5 pending.
        f1 = self.block(
            amount=20, recipient=self.C, height=1
        )
        f2 = self.block(
            amount=5, sender_key=self.kc, sender=self.C, recipient=self.A,
            height=2, prev=f1.block_hash,
        )
        self.assertEqual(self.register("node-1")[0], 201)
        doc = make_fork(self.genesis, [self.genesis, f1, f2])
        status, body = self.sync(doc)
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)
        self.assertEqual(self.store.tip_hash(), tip)
        self.assertEqual(self.revoke("node-1", 1)[0], 200)
        before = self._events_snapshot()

        reopened = self._reopen()
        # The adopted canonical chain is untouched...
        self.assertEqual(reopened.tip_hash(), tip)
        # ...the invalidated sync record is gone...
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        # ...the full received+adopted history survives verbatim, followed by
        # the backfilled expiry event (canonical chain still unchanged).
        self._assert_prefix_plus_expiry(before, tip=tip)
        self.assertEqual(
            [e["kind"] for e in reopened.audit_events],
            [
                "source_registered",
                "sync_received",
                "sync_adopted",
                "source_revoked",
                "sync_expired",
            ],
        )
        svc2 = LedgerService(reopened, initial_balance=1000)
        # The sync list returns no expired/invalidated record...
        self.assertEqual(svc2.list_fork_syncs({})[1]["total"], 0)
        # ...but all sync lifecycle events stay queryable by kind.
        for kind, expect in (
            ("sync_received", 1),
            ("sync_adopted", 1),
            ("sync_expired", 1),
        ):
            _, page = svc2.list_audit_events({"kind": kind})
            self.assertEqual(page["total"], expect, kind)
            self.assertEqual(page["items"][0]["tip_hash"], tip, kind)

    def test_restart_does_not_duplicate_expiry_events(self) -> None:
        self.assertEqual(self.register("node-1")[0], 201)
        doc = self.candidate(self.block())
        status, body = self.sync(doc, expires_at=int(time.time()) + 1)
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        time.sleep(1.1)
        # The lazy sweep expires record + candidate and records sync_expired.
        self.assertEqual(self.svc.list_fork_syncs({})[1]["total"], 0)
        before = self._events_snapshot()
        self.assertEqual(
            [e["kind"] for e in before],
            ["source_registered", "sync_received", "sync_expired"],
        )

        reopened = self._reopen()
        self.assertEqual(reopened.syncs, {})
        self.assertNotIn(tip, reopened.forks)
        # No second sync_expired event: history is byte-for-byte identical.
        self._assert_events_verbatim(before)
        svc2 = LedgerService(reopened, initial_balance=1000)
        _, page = svc2.list_audit_events({"kind": "sync_expired"})
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["tip_hash"], tip)

    def test_restart_request_deadline_backfills_expiry_while_source_active(self) -> None:
        # The source stays fully authorized; only the *request's* deadline
        # elapsed while the process was down. That still reconciles the record
        # and backfills exactly one sync_expired event.
        self.assertEqual(self.register("node-1")[0], 201)
        doc = self.candidate(self.block(amount=9))
        status, body = self.sync(doc, expires_at=int(time.time()) + 3600)
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        generation_before = self.store.generation
        before = self._events_snapshot()

        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        past = int(time.time()) - 5
        data["syncs"][0]["expires_at"] = past
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        reopened = self._reopen()
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        event = self._assert_prefix_plus_expiry(before, tip=tip)
        self.assertEqual(event["expires_at"], past)
        # The reconciliation is persisted atomically and advances generation.
        self.assertEqual(reopened.generation, generation_before + 1)

    def test_restart_backfills_multiple_expiries_dense_and_sorted(self) -> None:
        # Two independent sources deliver two different candidates; both lose
        # authorization (revoked) while down. Each record gets one event,
        # appended in (source, request_id) order with a dense id run.
        self.assertEqual(self.register("node-1")[0], 201)
        self.assertEqual(self.register("node-2", KEY_B)[0], 201)
        doc1 = self.candidate(self.block(amount=1))
        st, body1 = self.sync(doc1, source="node-1", request_id="r1")
        self.assertEqual(st, 201, body1)
        doc2 = self.candidate(self.block(amount=2, recipient=self.C))
        st, body2 = self.sync(doc2, source="node-2", request_id="r2")
        self.assertEqual(st, 201, body2)
        self.assertEqual(self.revoke("node-1", 1)[0], 200)
        self.assertEqual(
            self.svc.revoke_trust_source("node-2", {"expected_version": 1})[0], 200
        )
        before = self._events_snapshot()

        reopened = self._reopen()
        self.assertEqual(reopened.syncs, {})
        self.assertNotIn(body1["tip_hash"], reopened.forks)
        self.assertNotIn(body2["tip_hash"], reopened.forks)
        events = [dict(e) for e in reopened.audit_events]
        self.assertEqual(events[: len(before)], before)
        backfilled = events[len(before):]
        self.assertEqual([e["kind"] for e in backfilled], ["sync_expired"] * 2)
        self.assertEqual(
            [(e["source"], e["request_id"]) for e in backfilled],
            [("node-1", "r1"), ("node-2", "r2")],
        )
        self.assertEqual(
            [e["tip_hash"] for e in backfilled],
            [body1["tip_hash"], body2["tip_hash"]],
        )
        self.assertEqual(
            [e["event_id"] for e in events], list(range(1, len(events) + 1))
        )
        for e in backfilled:
            self.assertIn("expires_at", e)

    def test_restart_with_durable_expiry_event_backfills_nothing(self) -> None:
        # A sync_expired event for the identity is already durable while the
        # expired record is still in the snapshot (a crash interrupted the
        # cleanup). Recovery must not add a second event and must not rewrite.
        self.assertEqual(self.register("node-1")[0], 201)
        doc = self.candidate(self.block(amount=3))
        status, body = self.sync(doc, expires_at=int(time.time()) + 3600)
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        past = int(time.time()) - 5

        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["syncs"][0]["expires_at"] = past
        data["audit_events"].append(
            {
                "event_id": 3,
                "kind": "sync_expired",
                "at": 1.0,
                "source": "node-1",
                "request_id": "req-1",
                "tip_hash": tip,
                "expires_at": past,
            }
        )
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        generation_before = self.store.generation
        reopened = self._reopen()
        kinds = [e["kind"] for e in reopened.audit_events]
        self.assertEqual(kinds, ["source_registered", "sync_received", "sync_expired"])
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events], [1, 2, 3]
        )
        # Record and fork are still reconciled away, but no new write happened.
        self.assertNotIn(("node-1", "req-1"), reopened.syncs)
        self.assertNotIn(tip, reopened.forks)
        self.assertEqual(reopened.generation, generation_before)


class SaveFailureRollbackTests(_ServiceCase):
    def _fail_save_once(self) -> None:
        original = self.store.save
        state = {"failed": False}

        def failing():
            if not state["failed"]:
                state["failed"] = True
                raise OSError("simulated persistence failure")
            return original()

        self.store.save = failing
        self.addCleanup(lambda: setattr(self.store, "save", original))

    def test_receive_failure_restores_candidate_metadata_events_generation(self) -> None:
        self.assertEqual(self.register("node-1")[0], 201)
        self.assertEqual(self.register("node-other", KEY_B)[0], 201)
        # Pre-existing events and generation captured verbatim.
        before_events = [dict(e) for e in self.store.audit_events]
        before_gen = self.store.generation
        doc = self.candidate(self.block())
        tip = doc["tip_hash"]

        self._fail_save_once()
        with self.assertRaises(OSError):
            self.svc.submit_fork_sync(
                {
                    "source": "node-1",
                    "request_id": "req-1",
                    "expires_at": int(time.time()) + 3600,
                    "candidate": doc,
                }
            )

        # No candidate, no sync metadata, no generation advance.
        self.assertNotIn(tip, self.store.forks)
        self.assertNotIn(("node-1", "req-1"), self.store.syncs)
        self.assertEqual(self.store.generation, before_gen)
        # Existing audit events are byte-for-byte intact with a dense sequence.
        self.assertEqual(
            [dict(e) for e in self.store.audit_events], before_events
        )
        self.assertEqual(
            [e["event_id"] for e in self.store.audit_events],
            list(range(1, len(before_events) + 1)),
        )

        # A retry after recovery succeeds normally and persists exactly once.
        status, body = self.sync(doc)
        self.assertEqual(status, 201, body)
        self.assertEqual(self.store.generation, before_gen + 1)
        kinds = [e["kind"] for e in self.store.audit_events]
        self.assertEqual(kinds.count("sync_received"), 1)
        self.assertEqual(
            [e["event_id"] for e in self.store.audit_events],
            list(range(1, len(kinds) + 1)),
        )

    def test_adopt_failure_restores_chain_and_trims_adopted_events(self) -> None:
        # Canonical confirmed block 1.
        canon = self.block(amount=10)
        self.store.chain.append(canon)
        self.store.rebuild_derived()
        self.store.save()
        original_tip = self.store.tip_hash()
        # A longer synced fork that wins adoption.
        f1 = self.block(amount=20, recipient=self.C, height=1)
        f2 = self.block(
            amount=5, sender_key=self.kc, sender=self.C, recipient=self.A,
            height=2, prev=f1.block_hash,
        )
        self.assertEqual(self.register("node-1")[0], 201)
        doc = make_fork(self.genesis, [self.genesis, f1, f2])
        status, body = self.sync(doc)
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        before_events = [dict(e) for e in self.store.audit_events]
        before_gen = self.store.generation

        self._fail_save_once()
        with self.assertRaises(OSError):
            self.svc.adopt_fork(tip)

        # Chain back on the old tip; candidate restored for a retry.
        self.assertEqual(self.store.tip_hash(), original_tip)
        self.assertIn(tip, self.store.forks)
        self.assertEqual(self.store.generation, before_gen)
        # The would-be sync_adopted event was trimmed; existing events intact.
        self.assertEqual(
            [dict(e) for e in self.store.audit_events], before_events
        )
        self.assertEqual(
            [e["kind"] for e in self.store.audit_events].count("sync_adopted"), 0
        )
        self.assertEqual(
            [e["event_id"] for e in self.store.audit_events],
            list(range(1, len(before_events) + 1)),
        )

        # The recovered candidate can then be adopted successfully.
        status, _ = self.svc.adopt_fork(tip)
        self.assertEqual(status, 200)
        self.assertEqual(self.store.tip_hash(), tip)
        kinds = [e["kind"] for e in self.store.audit_events]
        self.assertEqual(kinds.count("sync_adopted"), 1)
        self.assertEqual(
            [e["event_id"] for e in self.store.audit_events],
            list(range(1, len(kinds) + 1)),
        )

    def test_revoke_failure_restores_registry_and_events(self) -> None:
        self.assertEqual(self.register("node-1")[0], 201)
        before_events = [dict(e) for e in self.store.audit_events]
        before_gen = self.store.generation

        self._fail_save_once()
        with self.assertRaises(OSError):
            self.revoke("node-1", 1)

        # The source stays active and no revocation event survived the rollback.
        self.assertEqual(self.store.trust_sources["node-1"]["status"], "active")
        self.assertEqual(self.store.generation, before_gen)
        self.assertEqual(
            [dict(e) for e in self.store.audit_events], before_events
        )
        # It is still authorized for new syncs after the failed revocation.
        status, _ = self.sync(self.candidate(self.block()))
        self.assertEqual(status, 201)


class AuthorizationHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.genesis = cls.service.store.chain[0]
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def request(cls, method, path, payload=None):
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

    def _block(self, amount=6):
        return Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, amount)]
        )

    def _body(self, source, request_id, block, expires_at):
        return {
            "source": source,
            "request_id": request_id,
            "expires_at": expires_at,
            "candidate": make_fork(self.genesis, [self.genesis, block]),
        }

    def test_http_403_410_400_and_idempotent_replay(self) -> None:
        block = self._block()
        future = int(time.time()) + 3600

        # Unknown source -> 403 over the wire.
        status, body = self.request(
            "POST", "/v1/forks/sync", self._body("http-x", "r1", block, future)
        )
        self.assertEqual(status, 403, body)

        # Register http-x, then an authorized but past request -> 410.
        status, _ = self.request(
            "POST", "/v1/trust/sources",
            {"source": "http-x", "public_key": KEY_A, "expires_at": FUTURE},
        )
        self.assertEqual(status, 201)
        status, body = self.request(
            "POST", "/v1/forks/sync",
            self._body("http-x", "r2", block, int(time.time()) - 1),
        )
        self.assertEqual(status, 410, body)

        # Malformed envelope -> 400 even with an unregistered source.
        bad = {"source": 1, "request_id": "r", "expires_at": future,
               "candidate": make_fork(self.genesis, [self.genesis, block])}
        self.assertEqual(
            self.request("POST", "/v1/forks/sync", bad)[0], 400
        )

        # Authorized delivery -> 201.
        status, first = self.request(
            "POST", "/v1/forks/sync", self._body("http-x", "r1", block, future)
        )
        self.assertEqual(status, 201, first)

        # Revoke, then replay the recorded request: still the first 200 result.
        status, _ = self.request(
            "POST", "/v1/trust/sources/http-x/revoke", {"expected_version": 1}
        )
        self.assertEqual(status, 200)
        status, replay = self.request(
            "POST", "/v1/forks/sync", self._body("http-x", "r1", block, future)
        )
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay, first)

        # A new request id after revocation -> 403.
        status, body = self.request(
            "POST", "/v1/forks/sync", self._body("http-x", "r9", block, future)
        )
        self.assertEqual(status, 403, body)

    def test_http_sync_listing_and_audit_query(self) -> None:
        # A delivered, still-live record is returned by the sync list and its
        # reception is independently queryable from the audit log.
        block = self._block(amount=3)
        source = "http-list"
        status, _ = self.request(
            "POST", "/v1/trust/sources",
            {"source": source, "public_key": KEY_B, "expires_at": FUTURE},
        )
        self.assertEqual(status, 201)
        status, body = self.request(
            "POST", "/v1/forks/sync",
            self._body(source, "q1", block, int(time.time()) + 3600),
        )
        self.assertEqual(status, 201)
        tip = body["tip_hash"]
        status, listing = self.request("GET", f"/v1/forks/sync?source={source}")
        self.assertEqual(status, 200)
        self.assertTrue(any(it["tip_hash"] == tip for it in listing["items"]))
        # The reception event is independently queryable.
        status, events = self.request(
            "GET", f"/v1/audit/events?kind=sync_received&source={source}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(events["total"], 1)

    def test_http_403_for_registry_expired_source(self) -> None:
        # Register an entry that immediately expires; a subsequent new sync is
        # refused 403 even though the source was once trusted.
        block = self._block(amount=2)
        source = "http-soon"
        status, _ = self.request(
            "POST", "/v1/trust/sources",
            {"source": source, "public_key": KEY_A,
             "expires_at": int(time.time()) + 1},
        )
        self.assertEqual(status, 201)
        time.sleep(1.1)
        status, body = self.request(
            "POST", "/v1/forks/sync",
            self._body(source, "q", block, int(time.time()) + 3600),
        )
        self.assertEqual(status, 403, body)


class AuthorizationCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.genesis = cls.service.store.chain[0]
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        import shutil

        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *argv])
        raw = buf.getvalue().strip()
        return rc, json.loads(raw) if raw else {}

    def test_cli_403_and_410_exit_1_with_json_and_idempotent_rc_0(self) -> None:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 4)]
        )
        candidate = json.dumps(
            [self.genesis.to_dict(), block.to_dict()]
        )
        future = str(int(time.time()) + 3600)

        # Unregistered source: 403 -> exit 1 with an error document.
        rc, body = self._cli(
            "sync", "--source", "cli-x", "--request-id", "z1",
            "--expires-at", future, candidate,
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", body)

        # Register the source.
        rc, body = self._cli(
            "trust", "add", "--source", "cli-x", "--public-key", KEY_A,
            "--expires-at", str(FUTURE),
        )
        self.assertEqual(rc, 0, body)

        # Past expiry: 410 -> exit 1.
        rc, _ = self._cli(
            "sync", "--source", "cli-x", "--request-id", "z2",
            "--expires-at", "1", candidate,
        )
        self.assertEqual(rc, 1)

        # Authorized delivery -> exit 0.
        rc, first = self._cli(
            "sync", "--source", "cli-x", "--request-id", "z1",
            "--expires-at", future, candidate,
        )
        self.assertEqual(rc, 0, first)

        # Idempotent replay -> same body, exit 0.
        rc, replay = self._cli(
            "sync", "--source", "cli-x", "--request-id", "z1",
            "--expires-at", future, candidate,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(replay, first)


if __name__ == "__main__":
    unittest.main(verbosity=2)
