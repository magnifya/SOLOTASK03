"""Tests for inter-node candidate-chain sync and the audit query.

Covers POST /v1/forks/sync (envelope validation, full candidate re-validation
reusing the fork rules, 201 success with the five result fields, 410 on an
expired request, 400 on malformed/input or a failing chain check, 200
same-source+request_id identical-content retry returning the original result,
409 on same-key different content and on a duplicate tip), GET /v1/forks/sync
(source/min_height/max_height/limit/cursor filters, strict decimal parsing,
(height, tip_hash, source) ordering, items/total/next_cursor pagination with
cursor == total -> empty page and cursor > total -> 400), expiry-driven
removal of the delivered candidate, serialization against adoption, adoption
of a winning synced fork (longest chain / smallest tip hash, atomic swap,
old-chain confirmed txs returning to the mempool while pending txs stay out),
restart re-validation/expiry handling (records expiring while down are pruned
and each gets one deduplicated, densely-id'd sync_expired backfilled and
persisted atomically; a second restart does not repeat it), and the HTTP +
CLI surfaces.

Run: python3 tests/fork_sync_test.py
"""
from __future__ import annotations

import copy
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
    """Build an export-format candidate document for the given block list."""
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class ForkSyncServiceTests(unittest.TestCase):
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
        # Sources used through the sync() helper are registered as active,
        # far-future trusted sources. Tests for the authorization gate register
        # (or deliberately leave unregistered) sources by hand.
        self._trusted: set[str] = set()
        self._trust_seq = 0

    def _trust(self, source: str, *, expires_at: int | None = None) -> None:
        if source in self._trusted and expires_at is None:
            return
        self._trust_seq += 1
        key_hex = format(0x1000 + self._trust_seq, "064x")
        status, body = self.svc.register_trust_source(
            {
                "source": source,
                "public_key": key_hex,
                "expires_at": int(time.time()) + 10_000_000
                if expires_at is None
                else expires_at,
            }
        )
        self.assertIn(status, (200, 201), body)
        self._trusted.add(source)

    def block1(self, to=None, amount=10, *, status="confirmed") -> Block:
        return Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, to or self.B, amount)],
            status,
        )

    def sync(self, candidate, *, source="node-1", request_id="req-1",
             expires_at=None, blocks_key="candidate"):
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        self._trust(source)
        body = {
            "source": source,
            "request_id": request_id,
            "expires_at": expires_at,
            blocks_key: candidate,
        }
        return self.svc.submit_fork_sync(body)

    # -- success / envelope -------------------------------------------------

    def test_valid_sync_returns_201_with_fields(self) -> None:
        block = self.block1()
        status, body = self.sync(make_fork(self.genesis, [self.genesis, block]))
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "tip_hash": block.block_hash,
                "height": 1,
                "length": 2,
                "status": "confirmed",
                "expires_at": body["expires_at"],
            },
        )
        self.assertIn(block.block_hash, self.store.forks)

    def test_accepts_blocks_wrapper_and_bare_list(self) -> None:
        block = self.block1(self.C)
        raw = [self.genesis.to_dict(), block.to_dict()]
        # {"blocks": [...]} candidate.
        status, body = self.sync({"blocks": raw}, request_id="r-a")
        self.assertEqual(status, 201, body)
        # A second source pushing the same tip conflicts, so use a distinct tip
        # for the bare-list variant.
        block2 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 5)]
        )
        status2, body2 = self.sync(
            [self.genesis.to_dict(), block2.to_dict()], request_id="r-b"
        )
        self.assertEqual(status2, 201, body2)

    def test_persisted_atomically_with_metadata(self) -> None:
        block = self.block1()
        exp = int(time.time()) + 3600
        status, body = self.sync(
            make_fork(self.genesis, [self.genesis, block]), expires_at=exp
        )
        self.assertEqual(status, 201)
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(len(doc.get("forks", [])), 1)
        records = doc.get("syncs")
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["source"], "node-1")
        self.assertEqual(rec["request_id"], "req-1")
        self.assertEqual(rec["tip_hash"], block.block_hash)
        self.assertEqual(rec["expires_at"], exp)
        self.assertTrue(crypto.is_hex64(rec["fingerprint"]))

    # -- malformed input -----------------------------------------------------

    def test_non_object_body_is_400(self) -> None:
        for bad in ([], "x", 1, None):
            self.assertEqual(self.svc.submit_fork_sync(bad)[0], 400, bad)

    def test_missing_fields_400(self) -> None:
        block = self.block1()
        full = {
            "source": "n",
            "request_id": "r",
            "expires_at": int(time.time()) + 10,
            "candidate": make_fork(self.genesis, [self.genesis, block]),
        }
        for field in ("source", "request_id", "expires_at", "candidate"):
            partial = dict(full)
            del partial[field]
            self.assertEqual(self.svc.submit_fork_sync(partial)[0], 400, field)

    def test_envelope_field_types_400(self) -> None:
        block = self.block1()
        cand = make_fork(self.genesis, [self.genesis, block])
        # Register "n" so that the past-expiry and malformed-candidate cases
        # reach their own checks past the authorization gate.
        self._trust("n")
        base = {"request_id": "r", "expires_at": int(time.time()) + 10,
                "candidate": cand}
        for bad_source in ("", 1, None, []):
            body = dict(base, source=bad_source)
            self.assertEqual(self.svc.submit_fork_sync(body)[0], 400, bad_source)
        for bad_rid in ("", 1, None):
            body = dict(base, source="n", request_id=bad_rid)
            self.assertEqual(self.svc.submit_fork_sync(body)[0], 400, bad_rid)
        for bad_exp in ("100", 1.5, True, None):
            body = dict(base, source="n", expires_at=bad_exp)
            self.assertEqual(self.svc.submit_fork_sync(body)[0], 400, bad_exp)
        # A negative integer is a well-typed Unix timestamp but in the past, so
        # it is an expiry rejection (410), not a format error.
        body = dict(base, source="n", expires_at=-1)
        self.assertEqual(self.svc.submit_fork_sync(body)[0], 410)
        for bad_cand in ("x", 1, {}, {"blocks": "x"}, [1]):
            body = dict(base, source="n", candidate=bad_cand)
            self.assertEqual(self.svc.submit_fork_sync(body)[0], 400, bad_cand)

    def test_candidate_chain_revalidated(self) -> None:
        # A negative (far-future) expiry passes the envelope, so a 400 here is
        # attributable to the candidate, not to expiry.
        future = int(time.time()) + 100000
        # Missing canonical genesis.
        block = self.block1()
        self.assertEqual(self.sync([block.to_dict()], expires_at=future)[0], 400)
        # Tampered block hash.
        tampered = make_fork(self.genesis, [self.genesis, block])
        tampered["blocks"][1]["block_hash"] = "f" * 64
        self.assertEqual(self.sync(tampered, expires_at=future)[0], 400)
        # Bad signature.
        bad_tx = Transaction(self.A, self.B, 10, "00" * 64)
        bad_block = Block.create(1, self.genesis.block_hash, [bad_tx])
        self.assertEqual(
            self.sync({"blocks": [self.genesis.to_dict(), bad_block.to_dict()]},
                      expires_at=future)[0],
            400,
        )
        # Replay overspend.
        t1 = tx_obj(self.ka, self.A, self.B, 600)
        t2 = tx_obj(self.ka, self.A, self.C, 600)
        b1 = Block.create(1, self.genesis.block_hash, [t1])
        b2 = Block.create(2, b1.block_hash, [t2])
        self.assertEqual(
            self.sync(make_fork(self.genesis, [self.genesis, b1, b2]),
                      expires_at=future)[0],
            400,
        )
        # Pending block not at tip.
        p1 = Block.create(1, self.genesis.block_hash, [t1], status="pending")
        p2 = Block.create(2, p1.block_hash,
                          [tx_obj(self.kb, self.B, self.A, 1)], status="confirmed")
        self.assertEqual(
            self.sync(make_fork(self.genesis, [self.genesis, p1, p2]),
                      expires_at=future)[0],
            400,
        )

    def test_export_summary_fields_reverified(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        doc["height"] = 9
        self.assertEqual(self.sync(doc)[0], 400)
        doc = make_fork(self.genesis, [self.genesis, block])
        doc["tip_hash"] = "a" * 64
        self.assertEqual(self.sync(doc)[0], 400)

    def test_tampered_summary_retry_is_400_not_200(self) -> None:
        # The tip summary must be recomputed from the blocks and checked
        # BEFORE the source+request_id idempotency decision, so a retry that
        # reuses a live key but forges any summary field is rejected 400 and
        # can never be answered with the cached 200.
        block = self.block1()
        exp = int(time.time()) + 3600
        doc = make_fork(self.genesis, [self.genesis, block])
        self.assertEqual(self.sync(doc, expires_at=exp)[0], 201)
        for field, forged in (
            ("tip_hash", "a" * 64),
            ("height", 9),
            ("length", 3),
            ("status", "pending"),
        ):
            forged_doc = dict(doc)
            forged_doc[field] = forged
            status, body = self.sync(forged_doc, expires_at=exp)
            self.assertEqual(status, 400, (field, body))
        # The untouched document still replays the original result as 200.
        status, retry = self.sync(doc, expires_at=exp + 999)
        self.assertEqual(status, 200)
        self.assertEqual(retry["tip_hash"], block.block_hash)

    def test_disguised_candidate_types_are_400_without_any_write(self) -> None:
        # A string/float/boolean height or amount inside the candidate is a 400
        # reached only after the authorization gate, and must not write a fork,
        # a sync record or an audit event nor advance the generation.
        block = self.block1()
        good = make_fork(self.genesis, [self.genesis, block])
        self._trust("node-1")
        base = {
            "source": "node-1",
            "expires_at": int(time.time()) + 3600,
        }
        mutations = (
            lambda bl: bl[1].update(height="1"),
            lambda bl: bl[1].update(height=1.0),
            lambda bl: bl[1].update(height=True),
            lambda bl: bl[1]["transactions"][0].update(amount="10"),
            lambda bl: bl[1]["transactions"][0].update(amount=10.0),
            lambda bl: bl[1]["transactions"][0].update(amount=True),
        )
        for index, mutate in enumerate(mutations):
            doc = copy.deepcopy(good)
            mutate(doc["blocks"])
            body = dict(base, request_id=f"bad-{index}", candidate=doc)
            forks_before = len(self.store.forks)
            syncs_before = len(self.store.syncs)
            events_before = len(self.store.audit_events)
            generation_before = self.store.generation
            status, resp = self.svc.submit_fork_sync(body)
            self.assertEqual(status, 400, resp)
            self.assertEqual(len(self.store.forks), forks_before)
            self.assertEqual(len(self.store.syncs), syncs_before)
            self.assertEqual(len(self.store.audit_events), events_before)
            self.assertEqual(self.store.generation, generation_before)

    def test_disguised_candidate_replay_same_key_is_400_not_200(self) -> None:
        # Reusing a live source+request_id with a type-disguised document must
        # not replay the cached 200: full re-validation runs first and returns
        # 400. The identical document still replays 200 afterwards.
        block = self.block1()
        exp = int(time.time()) + 3600
        doc = make_fork(self.genesis, [self.genesis, block])
        self.assertEqual(self.sync(doc, request_id="idem", expires_at=exp)[0], 201)
        for mutate in (
            lambda bl: bl[1].update(height="1"),
            lambda bl: bl[1]["transactions"][0].update(amount=True),
        ):
            forged = copy.deepcopy(doc)
            mutate(forged["blocks"])
            status, resp = self.sync(forged, request_id="idem", expires_at=exp)
            self.assertEqual(status, 400, resp)
        self.assertEqual(self.sync(doc, request_id="idem", expires_at=exp)[0], 200)

    def test_restart_prunes_sync_record_with_disguised_candidate(self) -> None:
        # A persisted sync record whose candidate gained a disguised numeric
        # type is cache, not authority: on restart the record and its fork are
        # silently pruned (no synthetic sync_expired), canonical is untouched.
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        self.assertEqual(
            self.sync(doc, source="node-9", request_id="rx")[0], 201
        )
        with open(self.state_path, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        snapshot["forks"][0][1]["transactions"][0]["amount"] = True
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(reopened.forks, {})
        self.assertEqual(reopened.syncs, {})
        self.assertEqual(reopened.tip_hash(), self.genesis.block_hash)
        self.assertFalse(
            any(e["kind"] == "sync_expired" for e in reopened.audit_events)
        )

    def test_expiry_sweep_is_persisted_before_response(self) -> None:
        # A read (audit query) that triggers the lazy expiry sweep must remove
        # the record and its candidate in one atomic save before responding.
        block = self.block1(self.C, amount=3)
        tip = block.block_hash
        self.assertEqual(
            self.sync(
                make_fork(self.genesis, [self.genesis, block]),
                source="node-x", request_id="qx", expires_at=int(time.time()) + 1,
            )[0],
            201,
        )
        generation_before = self.store.generation
        time.sleep(1.1)
        status, listing = self.svc.list_fork_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 0)
        # The sweep advanced the generation ...
        self.assertEqual(self.store.generation, generation_before + 1)
        # ... and was durably persisted before the response was produced.
        with open(self.state_path, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        self.assertEqual(on_disk["state"]["generation"], self.store.generation)
        self.assertNotIn(
            "qx", [rec.get("request_id") for rec in on_disk.get("syncs", [])]
        )
        on_disk_tips = [fork[-1]["block_hash"] for fork in on_disk.get("forks", [])]
        self.assertNotIn(tip, on_disk_tips)
        self.assertNotIn(tip, self.store.forks)

    def test_failed_sweep_save_restores_pre_cleanup_state(self) -> None:
        # If persisting an expiry sweep fails, the swept records and their
        # candidate forks must be restored in memory and no success reported.
        block = self.block1(self.C, amount=2)
        tip = block.block_hash
        key = ("node-y", "qy")
        self.assertEqual(
            self.sync(
                make_fork(self.genesis, [self.genesis, block]),
                source=key[0], request_id=key[1], expires_at=int(time.time()) + 1,
            )[0],
            201,
        )
        time.sleep(1.1)

        original_save = self.store.save

        def failing_save() -> None:
            raise OSError("simulated persistence failure")

        self.store.save = failing_save
        try:
            with self.assertRaises(OSError):
                self.svc.list_fork_syncs({})
        finally:
            self.store.save = original_save

        # The expired record and its candidate were restored, not dropped.
        self.assertIn(key, self.store.syncs)
        self.assertIn(tip, self.store.forks)
        # The next successful sweep completes normally.
        status, listing = self.svc.list_fork_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 0)
        self.assertNotIn(key, self.store.syncs)
        self.assertNotIn(tip, self.store.forks)

    # -- expiry --------------------------------------------------------------

    def test_expired_request_is_410(self) -> None:
        block = self.block1()
        self._trust("node-1")
        past = int(time.time()) - 1
        status, body = self.sync(
            make_fork(self.genesis, [self.genesis, block]), expires_at=past
        )
        self.assertEqual(status, 410, body)
        self.assertNotIn(block.block_hash, self.store.forks)
        self.assertEqual(self.store.syncs, {})
        # An expiry exactly at "now" counts as expired.
        status, _ = self.sync(
            make_fork(self.genesis, [self.genesis, self.block1(self.C)]),
            request_id="r2",
            expires_at=int(time.time()),
        )
        self.assertEqual(status, 410)

    def test_expiry_removes_record_and_candidate(self) -> None:
        block = self.block1()
        tip = block.block_hash
        status, _ = self.sync(
            make_fork(self.genesis, [self.genesis, block]), expires_at=int(time.time())
        )
        self.assertEqual(status, 410)
        self.assertNotIn(tip, self.store.forks)
        # A record accepted, then expiring, drops both on the next locked op.
        block2 = self.block1(self.C, amount=3)
        tip2 = block2.block_hash
        self.assertEqual(
            self.sync(
                make_fork(self.genesis, [self.genesis, block2]),
                source="node-2", request_id="q", expires_at=int(time.time()) + 1,
            )[0],
            201,
        )
        time.sleep(1.1)
        # Any serialized operation performs the lazy expiry sweep.
        status, listing = self.svc.list_fork_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(listing["total"], 0)
        self.assertNotIn(tip2, self.store.forks)
        # The expired fork can no longer win / be adopted.
        self.assertEqual(self.svc.get_chain()[1]["candidates"], [])

    def test_restart_prunes_expired_but_keeps_live(self) -> None:
        live = self.block1()
        live_tip = live.block_hash
        self.assertEqual(
            self.sync(
                make_fork(self.genesis, [self.genesis, live]),
                source="s1", request_id="live", expires_at=int(time.time()) + 3600,
            )[0],
            201,
        )
        dead = self.block1(self.C, amount=4)
        dead_tip = dead.block_hash
        self.assertEqual(
            self.sync(
                make_fork(self.genesis, [self.genesis, dead]),
                source="s2", request_id="dead", expires_at=int(time.time()) - 10,
            )[0],
            410,
        )
        # Manually install an already-expired durable record + fork to simulate
        # a snapshot whose expiry elapsed while the process was down.
        dead_exp = int(time.time()) - 10
        self.store.forks[dead_tip] = [self.genesis, dead]
        self.store.syncs[("s2", "dead")] = {
            "tip_hash": dead_tip,
            "expires_at": dead_exp,
            "fingerprint": "x",
        }
        self.store.save()
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn(live_tip, reopened.forks)
        self.assertNotIn(dead_tip, reopened.forks)  # fork dropped with the sync
        self.assertNotIn(("s2", "dead"), reopened.syncs)
        self.assertIn(("s1", "live"), reopened.syncs)
        # The record whose request deadline elapsed while down gets exactly one
        # backfilled sync_expired (the placeholder fingerprint is irrelevant:
        # expiry reconciliation precedes content verification), with the full
        # lifecycle payload and a dense event_id; the live record gets none.
        expired = [
            e for e in reopened.audit_events if e["kind"] == "sync_expired"
        ]
        self.assertEqual(len(expired), 1, [e["kind"] for e in reopened.audit_events])
        event = expired[0]
        self.assertEqual(event["source"], "s2")
        self.assertEqual(event["request_id"], "dead")
        self.assertEqual(event["tip_hash"], dead_tip)
        self.assertEqual(event["expires_at"], dead_exp)
        self.assertEqual(
            [e["event_id"] for e in reopened.audit_events],
            list(range(1, len(reopened.audit_events) + 1)),
        )
        # A second restart neither duplicates the event nor rewrites.
        generation_after = reopened.generation
        reopened_again = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(
            [e["kind"] for e in reopened_again.audit_events].count("sync_expired"), 1
        )
        self.assertEqual(reopened_again.generation, generation_after)
        self.assertIn(live_tip, reopened_again.forks)
        self.assertIn(("s1", "live"), reopened_again.syncs)

    # -- idempotency / conflict ---------------------------------------------

    def test_same_key_same_content_retry_returns_200_original(self) -> None:
        block = self.block1()
        exp = int(time.time()) + 3600
        doc = make_fork(self.genesis, [self.genesis, block])
        first = self.sync(doc, expires_at=exp)
        self.assertEqual(first[0], 201)
        # A retry even carrying a different expires_at returns the stored one.
        retry = self.sync(doc, expires_at=exp + 999)
        self.assertEqual(retry[0], 200)
        self.assertEqual(retry[1], first[1])
        self.assertEqual(retry[1]["expires_at"], exp)
        # Whitespace/key-order differences in the JSON source are irrelevant:
        # the candidate content is the same.
        reshuffled = {"blocks": doc["blocks"]}
        self.assertEqual(self.sync(reshuffled, expires_at=exp)[0], 200)

    def test_same_key_different_content_is_409(self) -> None:
        block = self.block1(amount=10)
        doc = make_fork(self.genesis, [self.genesis, block])
        self.assertEqual(self.sync(doc)[0], 201)
        other = self.block1(amount=11)
        other_doc = make_fork(self.genesis, [self.genesis, other])
        status, body = self.sync(other_doc)
        self.assertEqual(status, 409, body)
        # The conflicting submission stored nothing new.
        self.assertNotIn(other.block_hash, self.store.forks)

    def test_duplicate_tip_is_409(self) -> None:
        block = self.block1()
        doc = make_fork(self.genesis, [self.genesis, block])
        self.assertEqual(self.sync(doc, source="s1", request_id="a")[0], 201)
        # A different source/request id pushing the identical tip.
        self.assertEqual(self.sync(doc, source="s2", request_id="b")[0], 409)

    def test_canonical_tip_sync_is_409(self) -> None:
        # Extend the canonical chain, then sync an exact copy of it.
        block = self.block1()
        self.store.chain.append(block)
        self.store.rebuild_derived()
        self.store.save()
        status, _ = self.sync(make_fork(self.genesis, [self.genesis, block]))
        self.assertEqual(status, 409)

    # -- audit query ---------------------------------------------------------

    def seed_three(self) -> None:
        # height-1 tip from node-a, height-2 tip from node-b, another height-1
        # tip from node-c (ordering tiebreak by tip_hash then source).
        h1a = self.block1(self.B, amount=10)
        b2 = Block.create(2, h1a.block_hash, [tx_obj(self.kb, self.B, self.A, 1)])
        h1c = Block.create(1, self.genesis.block_hash,
                           [tx_obj(self.ka, self.A, self.C, 7)])
        self.assertEqual(
            self.sync(make_fork(self.genesis, [self.genesis, h1a]),
                      source="node-a", request_id="1")[0],
            201,
        )
        self.assertEqual(
            self.sync(make_fork(self.genesis, [self.genesis, h1a, b2]),
                      source="node-b", request_id="2")[0],
            201,
        )
        self.assertEqual(
            self.sync(make_fork(self.genesis, [self.genesis, h1c]),
                      source="node-c", request_id="3")[0],
            201,
        )

    def test_list_shape_and_ordering(self) -> None:
        self.seed_three()
        status, body = self.svc.list_fork_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)
        self.assertIsNone(body["next_cursor"])
        keys = [(it["height"], it["tip_hash"], it["source"]) for it in body["items"]]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([it["height"] for it in body["items"]][:2], [1, 1])
        for item in body["items"]:
            self.assertEqual(
                set(item),
                {"source", "request_id", "tip_hash", "height", "length",
                 "status", "expires_at"},
            )

    def test_list_filters(self) -> None:
        self.seed_three()
        _, body = self.svc.list_fork_syncs({"source": "node-b"})
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["source"], "node-b")
        _, body = self.svc.list_fork_syncs({"min_height": "2"})
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["height"], 2)
        _, body = self.svc.list_fork_syncs({"max_height": "1"})
        self.assertEqual(body["total"], 2)
        _, body = self.svc.list_fork_syncs({"min_height": "1", "max_height": "1"})
        self.assertEqual(body["total"], 2)
        _, body = self.svc.list_fork_syncs({"min_height": "5"})
        self.assertEqual(body["total"], 0)
        # Inverted range and malformed values -> 400.
        self.assertEqual(
            self.svc.list_fork_syncs({"min_height": "3", "max_height": "1"})[0], 400
        )

    def test_list_invalid_params_400(self) -> None:
        for bad in ("01", "-1", "1.0", "abc", ""):
            self.assertEqual(
                self.svc.list_fork_syncs({"min_height": bad})[0], 400, bad
            )
            self.assertEqual(
                self.svc.list_fork_syncs({"max_height": bad})[0], 400, bad
            )
        for bad in ("0", "201", "00", "-1", "abc", ""):
            self.assertEqual(self.svc.list_fork_syncs({"limit": bad})[0], 400, bad)
        for bad in ("01", "-1", "abc", ""):
            self.assertEqual(self.svc.list_fork_syncs({"cursor": bad})[0], 400, bad)
        self.assertEqual(self.svc.list_fork_syncs({"source": ""})[0], 400)

    def test_list_pagination(self) -> None:
        self.seed_three()
        status, page1 = self.svc.list_fork_syncs({"limit": "2", "cursor": "0"})
        self.assertEqual(status, 200)
        self.assertEqual(len(page1["items"]), 2)
        self.assertEqual(page1["total"], 3)
        self.assertEqual(page1["next_cursor"], 2)
        _, page2 = self.svc.list_fork_syncs({"limit": "2", "cursor": "2"})
        self.assertEqual(len(page2["items"]), 1)
        self.assertIsNone(page2["next_cursor"])
        full = self.svc.list_fork_syncs({})[1]["items"]
        self.assertEqual(
            [it["tip_hash"] for it in page1["items"] + page2["items"]],
            [it["tip_hash"] for it in full],
        )
        # cursor == total -> empty page; cursor > total -> 400.
        status, empty = self.svc.list_fork_syncs({"cursor": "3"})
        self.assertEqual(status, 200)
        self.assertEqual(empty["items"], [])
        self.assertEqual(self.svc.list_fork_syncs({"cursor": "4"})[0], 400)

    # -- adoption ------------------------------------------------------------

    def test_synced_winner_adopted_atomically(self) -> None:
        # Canonical: confirmed block 1 A->B 10.
        canon_tx = tx_obj(self.ka, self.A, self.B, 10)
        c1 = Block.create(1, self.genesis.block_hash, [canon_tx])
        self.store.chain.append(c1)
        self.store.rebuild_derived()
        self.store.save()
        gen = self.store.chain[0]
        # Synced fork: two blocks so it strictly outgrows canonical.
        f1 = Block.create(1, gen.block_hash, [tx_obj(self.ka, self.A, self.C, 20)])
        f2tx = tx_obj(self.kc, self.C, self.A, 5)
        f2 = Block.create(2, f1.block_hash, [f2tx], status="pending")
        doc = make_fork(gen, [gen, f1, f2])
        status, body = self.sync(doc, source="node-z", request_id="sync-1")
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        generation_before = self.store.generation
        # It is the adoptable winner.
        chain = self.svc.get_chain()[1]
        self.assertEqual(chain["adoptable"][0]["tip_hash"], tip)
        status, adopted = self.svc.adopt_fork(tip)
        self.assertEqual(status, 200, adopted)
        self.assertEqual(self.store.tip_hash(), tip)
        self.assertEqual(self.store.generation, generation_before + 1)
        # Old confirmed tx back in pool; new pending-tip tx stays out.
        self.assertIn(canon_tx.tx_id, self.store.pending)
        self.assertNotIn(f2tx.tx_id, self.store.pending)
        # Audit row remains queryable after adoption, resolved from canonical.
        _, listing = self.svc.list_fork_syncs({})
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["tip_hash"], tip)
        self.assertEqual(listing["items"][0]["height"], 2)

    def test_same_length_smallest_tip_hash_governs_adoption(self) -> None:
        h1 = self.block1(self.B, amount=10)
        h2 = Block.create(1, self.genesis.block_hash,
                          [tx_obj(self.ka, self.A, self.C, 10)])
        t1 = self.sync(make_fork(self.genesis, [self.genesis, h1]),
                       source="s1", request_id="1")[1]["tip_hash"]
        t2 = self.sync(make_fork(self.genesis, [self.genesis, h2]),
                       source="s2", request_id="2")[1]["tip_hash"]
        winner, loser = sorted((t1, t2))
        self.assertEqual(self.svc.adopt_fork(loser)[0], 409)
        self.assertEqual(self.svc.adopt_fork(winner)[0], 200)
        self.assertEqual(self.store.tip_hash(), winner)

    def test_expired_synced_candidate_cannot_be_adopted(self) -> None:
        block = self.block1()
        tip = block.block_hash
        self.assertEqual(
            self.sync(
                make_fork(self.genesis, [self.genesis, block]),
                expires_at=int(time.time()) + 1,
            )[0],
            201,
        )
        time.sleep(1.1)
        # Expiry sweep on adoption turns the tip into an unknown fork (404).
        self.assertEqual(self.svc.adopt_fork(tip)[0], 404)
        self.assertNotIn(tip, self.store.forks)


class ForkSyncHttpTests(unittest.TestCase):
    """Both endpoints over the real HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.genesis = cls.service.store.chain[0]
        # Sync submissions require an active trusted source.
        status, _ = cls.service.register_trust_source(
            {
                "source": "http-node",
                "public_key": "a" * 64,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        assert status in (200, 201), status

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, method: str, path: str, payload=None):
        url = f"{cls.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_sync_and_query_over_http(self) -> None:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 8)]
        )
        doc = make_fork(self.genesis, [self.genesis, block])
        payload = {
            "source": "http-node",
            "request_id": "h1",
            "expires_at": int(time.time()) + 3600,
            "candidate": doc,
        }
        status, body = self.request("POST", "/v1/forks/sync", payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], block.block_hash)
        # Identical retry -> 200 with the original body.
        status, retry = self.request("POST", "/v1/forks/sync", payload)
        self.assertEqual(status, 200)
        self.assertEqual(retry, body)
        # Altered content under the same key -> 409.
        conflict = dict(payload)
        conflict["candidate"] = {
            "blocks": [
                self.genesis.to_dict(),
                Block.create(
                    1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 9)]
                ).to_dict(),
            ]
        }
        self.assertEqual(self.request("POST", "/v1/forks/sync", conflict)[0], 409)
        # Expired -> 410.
        expired = dict(payload, request_id="h2", expires_at=int(time.time()) - 1)
        self.assertEqual(self.request("POST", "/v1/forks/sync", expired)[0], 410)
        # Malformed JSON-independent envelope error -> 400.
        bad = dict(payload, request_id="h3")
        del bad["source"]
        self.assertEqual(self.request("POST", "/v1/forks/sync", bad)[0], 400)
        # Audit query.
        status, listing = self.request("GET", "/v1/forks/sync?source=http-node")
        self.assertEqual(status, 200)
        self.assertTrue(any(it["request_id"] == "h1" for it in listing["items"]))
        self.assertEqual(
            self.request("GET", "/v1/forks/sync?limit=0")[0], 400
        )
        self.assertEqual(
            self.request("GET", "/v1/forks/sync?cursor=99999")[0], 400
        )

    def test_non_json_body_400(self) -> None:
        url = f"{self.base}/v1/forks/sync"
        req = urllib.request.Request(
            url, data=b"not-json", headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)


class ForkSyncCliTests(unittest.TestCase):
    """The sync / syncs CLI subcommands against a live server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.genesis = cls.service.store.chain[0]
        # Sync submissions require an active trusted source.
        status, _ = cls.service.register_trust_source(
            {
                "source": "cli-node",
                "public_key": "b" * 64,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        assert status in (200, 201), status

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

    def test_sync_and_syncs_cli(self) -> None:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 6)]
        )
        candidate = json.dumps([self.genesis.to_dict(), block.to_dict()])
        exp = str(int(time.time()) + 3600)
        rc, body = self.run_cli(
            "sync", "--source", "cli-node", "--request-id", "c1",
            "--expires-at", exp, candidate,
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["tip_hash"], block.block_hash)
        self.assertEqual(body["expires_at"], int(exp))
        # Idempotent retry prints the same body and still succeeds.
        rc, retry = self.run_cli(
            "sync", "--source", "cli-node", "--request-id", "c1",
            "--expires-at", exp, candidate,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(retry, body)
        # Expired submission exits 1.
        rc, _ = self.run_cli(
            "sync", "--source", "cli-node", "--request-id", "c2",
            "--expires-at", "1", candidate,
        )
        self.assertEqual(rc, 1)
        # Audit listing.
        rc, body = self.run_cli("syncs", "--source", "cli-node")
        self.assertEqual(rc, 0, body)
        self.assertTrue(any(it["request_id"] == "c1" for it in body["items"]))
        rc, _ = self.run_cli("syncs", "--limit", "0")
        self.assertEqual(rc, 1)
        rc, _ = self.run_cli("syncs", "--min-height", "xx")
        self.assertEqual(rc, 1)

    def test_sync_cli_invalid_json_exits_1(self) -> None:
        rc, body = self.run_cli(
            "sync", "--source", "n", "--request-id", "r",
            "--expires-at", str(int(time.time()) + 10), "{not json",
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
