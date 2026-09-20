"""Tests for inter-node candidate-chain sync and the audit query.

Covers POST /v1/forks/sync (field and candidate validation, 201 success with
the seven-field descriptor, 410 on expiry, 400 on malformed JSON/failed
re-validation, 200 idempotent retry returning the original result for the
same source+request_id, 409 for the same key with different content or a
duplicate tip hash against the canonical chain, a manual candidate or
another sync record), full candidate re-validation (canonical genesis,
height/prev_hash linkage, block hash, Merkle root, signatures, unique
ascending tx_ids, balance replay, pending-only-at-tip, export-summary
mismatch), atomic metadata+candidate persistence with rollback on a failed
write, GET /v1/forks/sync auditing ((height, tip_hash, source) ordering,
source/min_height/max_height filters, limit/cursor pagination with
cursor == total empty page and cursor > total / malformed numbers -> 400),
restart behaviour (re-validation, expiry eviction durable, pool
withdrawal), serialized adoption of synced candidates (longest chain,
smallest-tip-hash tie-break, atomic swap, old confirmed txs back in the
mempool de-duplicated, pending tip txs never enqueued, record removed
after adoption), plus HTTP and CLI coverage.

Run: python3 tests/fork_sync_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
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
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    msg = crypto.canonical_message(sender, to, amount)
    return Transaction(sender, to, amount, key.sign(msg).hex())


class FakeClock:
    """Mutable Unix-seconds clock injected into the store."""

    def __init__(self, value: int = 1000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class SyncServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.clock = FakeClock(1000)
        self.store = LedgerStore(
            self.state_path, initial_balance=1000, clock=self.clock
        )
        self.svc = LedgerService(self.store, initial_balance=1000)
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()

    # -- builders ----------------------------------------------------------

    def block(self, height, prev, txs, status="confirmed"):
        return Block.create(height, prev, txs, status)

    def tx(self, key, sender, to, amount):
        return tx_obj(key, sender, to, amount)

    def fork_blocks(self, *blocks):
        return [self.genesis.to_dict()] + [b.to_dict() for b in blocks]

    def export_doc(self, *blocks):
        return {"blocks": self.fork_blocks(*blocks)}

    def sync_payload(self, *blocks, source="node-1", request_id="req-1",
                     expires_at=5000, as_export=True):
        candidate = self.export_doc(*blocks) if as_export else self.fork_blocks(*blocks)
        return {
            "source": source,
            "request_id": request_id,
            "expires_at": expires_at,
            "candidate": candidate,
        }

    def submit(self, *blocks, **kw):
        return self.svc.sync_candidate(self.sync_payload(*blocks, **kw))

    # -- 201 / descriptor ---------------------------------------------------

    def test_valid_sync_returns_201_descriptor(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        status, body = self.submit(b)
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "source": "node-1",
                "request_id": "req-1",
                "tip_hash": b.block_hash,
                "height": 1,
                "length": 2,
                "status": "confirmed",
                "expires_at": 5000,
            },
        )
        # The synced candidate immediately joins the adoption pool.
        self.assertIn(b.block_hash, self.store.forks)

    def test_bare_blocks_array_candidate_accepted(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        status, body = self.submit(b, as_export=False)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], b.block_hash)

    def test_pending_tip_candidate_accepted(self):
        b = self.block(
            1, self.genesis.block_hash,
            [self.tx(self.ka, self.A, self.B, 10)], status="pending",
        )
        status, body = self.submit(b)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], "pending")

    # -- malformed requests -> 400 -----------------------------------------

    def test_missing_fields_400(self):
        status, _ = self.svc.sync_candidate({"source": "x"})
        self.assertEqual(status, 400)
        self.assertEqual(self.svc.sync_candidate("nope")[0], 400)

    def test_bad_metadata_types_400(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        base = self.sync_payload(b)
        for field, value in (
            ("source", ""), ("source", 7),
            ("request_id", ""), ("request_id", 9),
            ("expires_at", "5000"), ("expires_at", True), ("expires_at", -1),
        ):
            broken = dict(base)
            broken[field] = value
            self.assertEqual(self.svc.sync_candidate(broken)[0], 400, (field, value))

    def test_candidate_not_object_400(self):
        payload = self.sync_payload(self.block(
            1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)]))
        payload["candidate"] = [1, 2]
        self.assertEqual(self.svc.sync_candidate(payload)[0], 400)
        payload["candidate"] = {"blocks": "x"}
        self.assertEqual(self.svc.sync_candidate(payload)[0], 400)

    def test_candidate_chain_revalidation_failures_400(self):
        good = self.block(1, self.genesis.block_hash,
                          [self.tx(self.ka, self.A, self.B, 10)])
        # Tampered block hash.
        bad_hash = good.to_dict()
        bad_hash["block_hash"] = "f" * 64
        payload = {"source": "n", "request_id": "r", "expires_at": 5000,
                   "candidate": {"blocks": [self.genesis.to_dict(), bad_hash]}}
        self.assertEqual(self.svc.sync_candidate(payload)[0], 400)
        # Invalid signature.
        bad_sig = self.block(1, self.genesis.block_hash,
                             [Transaction(self.A, self.B, 10, "00" * 64)])
        self.assertEqual(self.submit(bad_sig)[0], 400)
        # Missing canonical genesis.
        self.assertEqual(self.svc.sync_candidate({
            "source": "n", "request_id": "r1", "expires_at": 5000,
            "candidate": {"blocks": [good.to_dict()]}})[0], 400)
        # Height gap: a height-3 block at position 2.
        gap = self.block(3, good.block_hash, [self.tx(self.kb, self.B, self.A, 1)])
        self.assertEqual(self.svc.sync_candidate({
            "source": "n", "request_id": "r2", "expires_at": 5000,
            "candidate": {"blocks": [self.genesis.to_dict(), good.to_dict(), gap.to_dict()]}})[0], 400)
        # Replay overspend.
        o1 = self.block(1, self.genesis.block_hash,
                        [self.tx(self.ka, self.A, self.B, 600)])
        o2 = self.block(2, o1.block_hash,
                        [self.tx(self.ka, self.A, self.C, 600)])
        self.assertEqual(self.svc.sync_candidate({
            "source": "n", "request_id": "r3", "expires_at": 5000,
            "candidate": {"blocks": self.fork_blocks(o1, o2)}})[0], 400)
        # Pending block not at tip.
        p1 = self.block(1, self.genesis.block_hash,
                        [self.tx(self.ka, self.A, self.B, 10)], status="pending")
        p2 = self.block(2, p1.block_hash,
                        [self.tx(self.kb, self.B, self.A, 1)], status="confirmed")
        self.assertEqual(self.svc.sync_candidate({
            "source": "n", "request_id": "r4", "expires_at": 5000,
            "candidate": {"blocks": self.fork_blocks(p1, p2)}})[0], 400)
        # Duplicate tx_id across the chain.
        dup = self.block(2, good.block_hash, [good.transactions[0]])
        self.assertEqual(self.svc.sync_candidate({
            "source": "n", "request_id": "r5", "expires_at": 5000,
            "candidate": {"blocks": self.fork_blocks(good, dup)}})[0], 400)

    def test_export_summary_mismatch_400(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        payload = self.sync_payload(b)
        payload["candidate"]["tip_hash"] = "f" * 64
        self.assertEqual(self.svc.sync_candidate(payload)[0], 400)
        payload = self.sync_payload(b)
        payload["candidate"]["length"] = 9
        self.assertEqual(self.svc.sync_candidate(payload)[0], 400)

    # -- expiry -------------------------------------------------------------

    def test_expired_request_410(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        # expires_at == now is already expired.
        self.assertEqual(self.submit(b, expires_at=1000)[0], 410)
        self.assertEqual(self.submit(b, expires_at=999)[0], 410)
        # Nothing was stored.
        self.assertEqual(self.store.syncs, {})

    # -- idempotency / conflicts -------------------------------------------

    def test_idempotent_retry_returns_200_original(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        status, first = self.submit(b, expires_at=5000)
        self.assertEqual(status, 201)
        # Retry with a different expires_at still replays the ORIGINAL result.
        status, retry = self.submit(b, expires_at=9999)
        self.assertEqual(status, 200, retry)
        self.assertEqual(retry, first)
        self.assertEqual(retry["expires_at"], 5000)
        # Only one record exists and generation advanced once for the pair.
        self.assertEqual(len(self.store.syncs), 1)

    def test_same_key_different_content_409(self):
        b1 = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        b2 = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.C, 10)])
        self.assertEqual(self.submit(b1)[0], 201)
        self.assertEqual(self.submit(b2)[0], 409)
        # The original record is untouched.
        self.assertEqual(len(self.store.syncs), 1)
        self.assertEqual(next(iter(self.store.syncs.values())).tip_hash, b1.block_hash)

    def test_same_content_different_request_id_is_new_record(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        self.assertEqual(self.submit(b, request_id="r1")[0], 201)
        # Same tip under a different request id is a duplicate tip -> 409.
        self.assertEqual(self.submit(b, request_id="r2")[0], 409)
        # The same request id from a different source is an independent record
        # with the same tip -> still a duplicate tip -> 409.
        self.assertEqual(self.submit(b, source="node-2", request_id="r1")[0], 409)

    def test_duplicate_of_canonical_tip_409(self):
        # Extend the canonical chain with one confirmed block.
        c1 = self.block(1, self.genesis.block_hash,
                        [self.tx(self.ka, self.A, self.B, 10)])
        self.store.chain.append(c1)
        self.store.rebuild_derived()
        self.store.save()
        self.assertEqual(self.submit(c1)[0], 409)

    def test_duplicate_of_manual_candidate_409(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        status, manual = self.svc.submit_fork_candidate(
            {"blocks": self.fork_blocks(b)})
        self.assertEqual(status, 201, manual)
        self.assertEqual(self.submit(b)[0], 409)

    def test_two_distinct_tips_coexist(self):
        b1 = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        b2 = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.C, 10)])
        self.assertEqual(self.submit(b1, source="n1", request_id="a")[0], 201)
        self.assertEqual(self.submit(b2, source="n2", request_id="b")[0], 201)
        self.assertEqual(len(self.store.syncs), 2)

    # -- persistence --------------------------------------------------------

    def test_metadata_and_candidate_persisted_atomically(self):
        b = self.block(1, self.genesis.block_hash,
                       [self.tx(self.ka, self.A, self.B, 10)], status="pending")
        generation_before = self.store.generation
        self.assertEqual(self.submit(b)[0], 201)
        # Exactly one atomic write for the receive.
        self.assertEqual(self.store.generation, generation_before + 1)
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(len(doc["syncs"]), 1)
        record = doc["syncs"][0]
        self.assertEqual(record["source"], "node-1")
        self.assertEqual(record["request_id"], "req-1")
        self.assertEqual(record["expires_at"], 5000)
        # The full candidate (including genesis and signatures) is in the same
        # snapshot as the metadata.
        self.assertEqual(len(record["blocks"]), 2)
        self.assertEqual(record["blocks"][-1]["status"], "pending")
        self.assertTrue(record["blocks"][-1]["transactions"][0]["signature"])

    def test_failed_write_rolls_back_memory(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])

        def boom():
            raise OSError("disk full")

        self.store.save = boom  # type: ignore[assignment]
        with self.assertRaises(OSError):
            self.submit(b)
        self.assertEqual(self.store.syncs, {})
        self.assertEqual(self.store.forks, {})
        self.assertEqual(self.store.sync_tips, set())

    # -- audit query --------------------------------------------------------

    def _seed_three(self):
        b1a = self.block(1, self.genesis.block_hash,
                         [self.tx(self.ka, self.A, self.B, 10)])
        b1b = self.block(1, self.genesis.block_hash,
                         [self.tx(self.ka, self.A, self.C, 10)])
        b2 = self.block(2, b1a.block_hash,
                        [self.tx(self.kb, self.B, self.C, 1)])
        self.submit(b1a, source="z", request_id="1")
        self.submit(b1b, source="a", request_id="2")
        self.submit(b1a, b2, source="m", request_id="3")
        return b1a, b1b, b2

    def test_list_ordering(self):
        b1a, b1b, b2 = self._seed_three()
        status, body = self.svc.list_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)
        keys = [(i["height"], i["tip_hash"], i["source"]) for i in body["items"]]
        self.assertEqual(keys, sorted(keys))
        # Height-1 rows come first ordered by tip hash; height-2 row is last.
        self.assertEqual([i["height"] for i in body["items"]], [1, 1, 2])
        self.assertEqual(body["items"][-1]["tip_hash"], b2.block_hash)
        for item in body["items"]:
            self.assertEqual(
                set(item),
                {"source", "request_id", "tip_hash", "height", "length",
                 "status", "expires_at"},
            )

    def test_list_filters(self):
        self._seed_three()
        self.assertEqual(
            [i["request_id"] for i in self.svc.list_syncs({"source": "a"})[1]["items"]],
            ["2"],
        )
        self.assertEqual(self.svc.list_syncs({"min_height": "2"})[1]["total"], 1)
        self.assertEqual(self.svc.list_syncs({"max_height": "1"})[1]["total"], 2)
        self.assertEqual(
            self.svc.list_syncs({"min_height": "1", "max_height": "1",
                                 "source": "z"})[1]["total"],
            1,
        )

    def test_list_pagination(self):
        self._seed_three()
        # Page size 2: first page then second page via next_cursor.
        status, page1 = self.svc.list_syncs({"limit": "2"})
        self.assertEqual(status, 200)
        self.assertEqual(page1["total"], 3)
        self.assertEqual(len(page1["items"]), 2)
        self.assertEqual(page1["next_cursor"], 2)
        status, page2 = self.svc.list_syncs({"limit": "2", "cursor": str(page1["next_cursor"])})
        self.assertEqual(len(page2["items"]), 1)
        self.assertIsNone(page2["next_cursor"])
        # cursor == total -> empty page.
        status, empty = self.svc.list_syncs({"cursor": "3"})
        self.assertEqual(status, 200)
        self.assertEqual(empty["items"], [])
        self.assertIsNone(empty["next_cursor"])
        # cursor > total -> 400.
        self.assertEqual(self.svc.list_syncs({"cursor": "4"})[0], 400)

    def test_list_invalid_params_400(self):
        self._seed_three()
        for params in (
            {"limit": "0"}, {"limit": "201"}, {"limit": "x"}, {"limit": "01"},
            {"cursor": "-1"}, {"cursor": "ab"}, {"cursor": "00"},
            {"min_height": "x"}, {"max_height": "01"},
            {"min_height": "5", "max_height": "2"},
            {"source": ""},
        ):
            self.assertEqual(self.svc.list_syncs(params)[0], 400, params)

    def test_list_excludes_expired(self):
        self._seed_three()
        self.clock.value = 6000
        status, body = self.svc.list_syncs({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        self.assertEqual(self.store.forks, {})

    # -- restart ------------------------------------------------------------

    def test_restart_keeps_live_records_and_pool_entry(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        self.submit(b)
        reopened = LedgerStore(self.state_path, initial_balance=1000, clock=self.clock)
        self.assertEqual(len(reopened.syncs), 1)
        record = next(iter(reopened.syncs.values()))
        self.assertEqual(record.tip_hash, b.block_hash)
        self.assertIn(b.block_hash, reopened.forks)
        self.assertIn(b.block_hash, reopened.sync_tips)

    def test_restart_drops_invalid_records(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        self.submit(b)
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["syncs"].append({"source": "ghost", "request_id": "g",
                             "expires_at": 5000, "blocks": [{"bogus": True}]})
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        reopened = LedgerStore(self.state_path, initial_balance=1000, clock=self.clock)
        self.assertEqual(len(reopened.syncs), 1)
        self.assertEqual(next(iter(reopened.syncs.values())).source, "node-1")
        # Canonical recovery stays intact.
        self.assertEqual(reopened.tip_hash(), self.genesis.block_hash)

    def test_restart_evicts_expired_records_durably(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        self.submit(b)
        self.clock.value = 6000
        reopened = LedgerStore(self.state_path, initial_balance=1000, clock=self.clock)
        self.assertEqual(reopened.syncs, {})
        self.assertEqual(reopened.forks, {})
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertNotIn("syncs", doc)

    def test_restart_tip_canonical_after_independent_adoption_is_dropped(self):
        # A synced record whose tip became canonical out-of-band (simulated by
        # tampering the snapshot to a matching chain) is dropped on restart
        # rather than duplicated into the candidate pool.
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        self.submit(b)
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["chain"].append(doc["syncs"][0]["blocks"][1])
        doc["state"]["height"] = 1
        doc["state"]["tip_hash"] = b.block_hash
        doc["state"]["tip_status"] = "confirmed"
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        reopened = LedgerStore(self.state_path, initial_balance=1000, clock=self.clock)
        self.assertEqual(reopened.syncs, {})
        self.assertEqual(reopened.forks, {})
        self.assertEqual(reopened.tip_hash(), b.block_hash)

    # -- adoption -----------------------------------------------------------

    def test_synced_candidate_competes_and_adopts(self):
        # Canonical: confirmed block 1 A->B 10.
        canon_tx = self.tx(self.ka, self.A, self.B, 10)
        c1 = self.block(1, self.genesis.block_hash, [canon_tx])
        self.store.chain.append(c1)
        self.store.rebuild_derived()
        self.store.save()
        # A longer synced fork: block 1 A->C 20 then block 2 C->A 1.
        f1 = self.block(1, self.genesis.block_hash,
                        [self.tx(self.ka, self.A, self.C, 20)])
        f2 = self.block(2, f1.block_hash, [self.tx(self.kc, self.C, self.A, 1)])
        status, body = self.submit(f1, f2, source="peer", request_id="long")
        self.assertEqual(status, 201, body)
        tip = f2.block_hash
        # It is the adoptable winner.
        chain = self.svc.get_chain()[1]
        self.assertEqual(chain["adoptable"][0]["tip_hash"], tip)
        generation_before = self.store.generation
        status, adopted = self.svc.adopt_fork(tip)
        self.assertEqual(status, 200, adopted)
        self.assertEqual(self.store.tip_hash(), tip)
        self.assertEqual(self.store.generation, generation_before + 1)
        # Old confirmed tx back in the mempool; adopted record removed; the
        # adopted tip left the pool.
        self.assertIn(canon_tx.tx_id, self.store.pending)
        self.assertNotIn(tip, self.store.forks)
        self.assertEqual(self.store.syncs, {})
        # The audit log no longer lists the adopted offer.
        self.assertEqual(self.svc.list_syncs({})[1]["total"], 0)

    def test_synced_pending_tip_adoption_keeps_pending_tx_out_of_pool(self):
        # Canonical confirmed block 1.
        canon_tx = self.tx(self.ka, self.A, self.B, 10)
        c1 = self.block(1, self.genesis.block_hash, [canon_tx])
        self.store.chain.append(c1)
        self.store.rebuild_derived()
        self.store.save()
        # Strictly longer synced fork ending in a pending tip.
        f1 = self.block(1, self.genesis.block_hash,
                        [self.tx(self.ka, self.A, self.C, 20)])
        f2 = self.block(2, f1.block_hash,
                        [self.tx(self.kc, self.C, self.A, 5)], status="pending")
        status, body = self.submit(f1, f2, source="peer", request_id="p")
        self.assertEqual(status, 201, body)
        status, _ = self.svc.adopt_fork(f2.block_hash)
        self.assertEqual(status, 200)
        self.assertEqual(self.store.tip().status, "pending")
        # Old-chain confirmed tx returns; the pending-tip tx never enters pool.
        self.assertIn(canon_tx.tx_id, self.store.pending)
        pending_tip_tx = f2.transactions[0].tx_id
        self.assertNotIn(pending_tip_tx, self.store.pending)

    def test_tie_broken_by_smallest_tip_hash_across_sources(self):
        b1 = self.block(1, self.genesis.block_hash,
                        [self.tx(self.ka, self.A, self.B, 10)])
        b2 = self.block(1, self.genesis.block_hash,
                        [self.tx(self.ka, self.A, self.C, 10)])
        manual_status, manual = self.svc.submit_fork_candidate(
            {"blocks": self.fork_blocks(b1)})
        self.assertEqual(manual_status, 201)
        sync_status, synced = self.submit(b2, source="peer", request_id="x")
        self.assertEqual(sync_status, 201)
        winner = min(manual["tip_hash"], synced["tip_hash"])
        chain = self.svc.get_chain()[1]
        self.assertEqual(chain["adoptable"][0]["tip_hash"], winner)
        self.assertEqual(self.svc.adopt_fork(
            max(manual["tip_hash"], synced["tip_hash"]))[0], 409)
        self.assertEqual(self.svc.adopt_fork(winner)[0], 200)

    def test_expired_offer_cannot_be_adopted(self):
        b = self.block(1, self.genesis.block_hash, [self.tx(self.ka, self.A, self.B, 10)])
        status, body = self.submit(b)
        self.assertEqual(status, 201)
        self.clock.value = 6000
        # Reconciliation happens inside the winner computation.
        self.assertEqual(self.svc.get_chain()[1]["adoptable"], [])
        self.assertEqual(self.svc.adopt_fork(b.block_hash)[0], 404)

    # -- serialization ------------------------------------------------------

    def test_concurrent_syncs_are_serialized(self):
        # Each worker offers a distinct, valid height-1 candidate; they all
        # contend for the same store lock and must never corrupt state.
        results = []
        barrier = threading.Barrier(9)

        def worker(index, recipient):
            block = self.block(
                1, self.genesis.block_hash,
                [self.tx(self.ka, self.A, recipient, index + 1)])
            barrier.wait()
            status, body = self.svc.sync_candidate({
                "source": f"peer-{index}",
                "request_id": f"req-{index}",
                "expires_at": 5000,
                "candidate": {"blocks": self.fork_blocks(block)},
            })
            results.append((status, body))

        threads = [threading.Thread(target=worker, args=(i, pub))
                   for i, (_, pub) in enumerate(
                       [keypair() for _ in range(8)])]
        for t in threads:
            t.start()
        barrier.wait()
        for t in threads:
            t.join()
        statuses = [status for status, _ in results]
        self.assertTrue(all(s in (200, 201, 409, 400) for s in statuses), statuses)
        self.assertEqual(sum(1 for s in statuses if s == 201), 8)
        # In-memory indexes stay consistent and the snapshot re-recovers.
        self.assertEqual(self.store.sync_tips, set(self.store.forks))
        LedgerStore(self.state_path, initial_balance=1000, clock=self.clock)


class SyncHttpTests(unittest.TestCase):
    """The sync endpoints over the real HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.clock = FakeClock(1000)
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"),
                        initial_balance=1000, clock=cls.clock),
            initial_balance=1000,
        )
        cls.genesis = cls.service.store.chain[0]
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
        url = f"{cls.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def _candidate_doc(self, recipient, amount):
        b = Block.create(
            1, self.genesis.block_hash,
            [tx_obj(self.ka, self.A, recipient, amount)],
        )
        return b, {"blocks": [self.genesis.to_dict(), b.to_dict()]}

    def test_sync_lifecycle_over_http(self):
        b, doc = self._candidate_doc(self.B, 11)
        payload = {"source": "node-x", "request_id": "http-1",
                   "expires_at": 5000, "candidate": doc}
        status, body = self.request("POST", "/v1/forks/sync", payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], b.block_hash)
        # Idempotent retry.
        status, retry = self.request("POST", "/v1/forks/sync", payload)
        self.assertEqual(status, 200)
        self.assertEqual(retry, body)
        # Audit query.
        status, listing = self.request(
            "GET", "/v1/forks/sync?source=node-x&limit=10")
        self.assertEqual(status, 200, listing)
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["request_id"], "http-1")
        # Bad params -> 400, expired (expires_at=0) -> 410, malformed -> 400.
        self.assertEqual(self.request("GET", "/v1/forks/sync?limit=0")[0], 400)
        b2, doc2 = self._candidate_doc(self.B, 22)
        expired = {"source": "node-y", "request_id": "old",
                   "expires_at": 0, "candidate": doc2}
        self.assertEqual(
            self.request("POST", "/v1/forks/sync", expired)[0], 410)
        self.assertEqual(
            self.request("POST", "/v1/forks/sync", {"nope": True})[0], 400)
        # Duplicate tip -> 409.
        dup = {"source": "node-z", "request_id": "dup",
               "expires_at": 5000, "candidate": doc}
        self.assertEqual(
            self.request("POST", "/v1/forks/sync", dup)[0], 409)
        # Same key, different content -> 409.
        conflict = dict(payload)
        conflict["candidate"] = doc2
        self.assertEqual(
            self.request("POST", "/v1/forks/sync", conflict)[0], 409)


class SyncCliTests(unittest.TestCase):
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
        genesis = cls.service.store.chain[0]
        cls.block = Block.create(
            1, genesis.block_hash, [tx_obj(cls.ka, cls.A, cls.B, 8)])
        cls.candidate_json = json.dumps(
            {"blocks": [genesis.to_dict(), cls.block.to_dict()]})
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
        self.assertEqual(raw.count("\n"), 1)
        return rc, json.loads(raw)

    def test_sync_and_syncs_cli(self):
        rc, body = self.run_cli(
            "sync", "--source", "cli-peer", "--request-id", "c1",
            "--expires-at", "2000000000", self.candidate_json)
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["tip_hash"], self.block.block_hash)
        # Idempotent retry over the CLI returns 200 (still a success exit).
        rc, body = self.run_cli(
            "sync", "--source", "cli-peer", "--request-id", "c1",
            "--expires-at", "2000000000", self.candidate_json)
        self.assertEqual(rc, 0)
        # Audit query with filters.
        rc, body = self.run_cli("syncs", "--source", "cli-peer", "--limit", "5")
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["total"], 1)
        # An expired offer is a non-2xx response -> exit code 1.
        rc, body = self.run_cli(
            "sync", "--source", "cli-peer", "--request-id", "c2",
            "--expires-at", "1", self.candidate_json)
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
