"""Tests for the incremental range sync protocol.

Covers GET /v1/chain/range (anchor/default-tip semantics, limit 1-500 with
default 100, strict decimal/hex validation 400, missing anchor height 404,
hash mismatch 409, full blocks including an exportable pending tip,
next_height paging) and POST /v1/forks/sync/range (400/403/410 precedence,
anchor-must-match-canonical 409, canonical-prefix splice followed by the
existing whole-chain re-validation, tip cross-check, 201 with the five
familiar fields, 200 same-key identical retry replaying the frozen result
even after the source was revoked or the canonical chain moved, 409 on
changed content / cross-endpoint key reuse / duplicate tip, atomic
candidate+record+fingerprint+event persistence with full rollback on a
failed write, adoption/longest-chain rules, expiry and restart
reconciliation) plus the HTTP and CLI surfaces.

Run: python3 tests/range_sync_test.py
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


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    msg = crypto.canonical_message(sender, to, amount)
    return Transaction(sender, to, amount, key.sign(msg).hex())


def make_block(height: int, prev: str, key, sender, to, amount, status="confirmed"):
    return Block.create(height, prev, [tx_obj(key, sender, to, amount)], status)


class RangeBase(unittest.TestCase):
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
        self._trust_seq = 0

    def trust(self, source="node-2", expires_at=None) -> None:
        self._trust_seq += 1
        key_hex = format(0x2000 + self._trust_seq, "064x")
        status, _ = self.svc.register_trust_source(
            {
                "source": source,
                "public_key": key_hex,
                "expires_at": int(time.time()) + 10_000_000
                if expires_at is None
                else expires_at,
            }
        )
        self.assertIn(status, (200, 201), status)

    def build_chain(self, amounts) -> list[Block]:
        """Append confirmed blocks A->B with distinct amounts; return them."""
        blocks = []
        prev = self.genesis.block_hash
        for i, amount in enumerate(amounts, start=1):
            block = make_block(i, prev, self.ka, self.A, self.B, amount)
            self.store.chain.append(block)
            self.store.save()
            blocks.append(block)
            prev = block.block_hash
        return blocks

    def range_payload(self, anchor, blocks, tip, *, source="node-2",
                      request_id="r-1", expires_at=None):
        return {
            "source": source,
            "request_id": request_id,
            "expires_at": int(time.time()) + 3600 if expires_at is None else expires_at,
            "anchor": anchor,
            "blocks": [
                b.to_dict() if hasattr(b, "to_dict") else b for b in blocks
            ],
            "tip": tip,
        }

    def winning_range(self, anchor_block, amounts=(5, 6)):
        """Build a longer forking range (C->B) anchored at anchor_block."""
        blocks = []
        prev = anchor_block.block_hash
        for i, amount in enumerate(amounts):
            block = make_block(
                anchor_block.height + 1 + i, prev, self.kc, self.C, self.B, amount
            )
            blocks.append(block)
            prev = block.block_hash
        tip_block = blocks[-1]
        anchor = {"height": anchor_block.height, "block_hash": anchor_block.block_hash}
        tip = {"height": tip_block.height, "block_hash": tip_block.block_hash}
        return blocks, anchor, tip


class ChainRangeServiceTests(RangeBase):
    def test_default_anchor_is_tip_with_empty_range(self) -> None:
        b1 = self.build_chain([10])[0]
        status, body = self.svc.get_chain_range({})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], {"height": 1, "block_hash": b1.block_hash})
        self.assertEqual(body["blocks"], [])
        self.assertIsNone(body["next_height"])
        self.assertEqual(body["canonical"]["tip_hash"], b1.block_hash)
        self.assertEqual(body["canonical"]["height"], 1)

    def test_paging_and_next_height(self) -> None:
        blocks = self.build_chain([10, 20, 30])
        # First page after genesis capped at 1 block.
        status, p0 = self.svc.get_chain_range(
            {"after_height": "0", "after_hash": self.genesis.block_hash, "limit": "1"}
        )
        self.assertEqual(status, 200)
        self.assertEqual([b["height"] for b in p0["blocks"]], [1])
        self.assertEqual(p0["next_height"], 2)
        self.assertEqual(
            p0["anchor"], {"height": 0, "block_hash": self.genesis.block_hash}
        )
        # Continue from the returned cursor.
        status, p1 = self.svc.get_chain_range(
            {"after_height": "1", "after_hash": blocks[0].block_hash, "limit": "1"}
        )
        self.assertEqual([b["height"] for b in p1["blocks"]], [2])
        self.assertEqual(p1["next_height"], 3)
        # Last page reaches the tip -> next_height is null.
        status, p2 = self.svc.get_chain_range(
            {"after_height": "2", "after_hash": blocks[1].block_hash}
        )
        self.assertEqual([b["height"] for b in p2["blocks"]], [3])
        self.assertIsNone(p2["next_height"])

    def test_blocks_are_full_documents(self) -> None:
        self.build_chain([10])
        status, body = self.svc.get_chain_range(
            {"after_height": "0", "after_hash": self.genesis.block_hash}
        )
        block = body["blocks"][0]
        self.assertEqual(
            set(block),
            {"height", "prev_hash", "merkle_root", "block_hash", "status",
             "transactions"},
        )
        self.assertEqual(block["transactions"][0]["to"], self.B)
        self.assertEqual(block["transactions"][0]["amount"], 10)

    def test_pending_tip_is_exportable(self) -> None:
        b1 = self.build_chain([10])[0]
        pending = make_block(
            2, b1.block_hash, self.ka, self.A, self.B, 20, status="pending"
        )
        self.store.chain.append(pending)
        self.store.save()
        status, body = self.svc.get_chain_range(
            {"after_height": "0", "after_hash": self.genesis.block_hash}
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [(b["height"], b["status"]) for b in body["blocks"]],
            [(1, "confirmed"), (2, "pending")],
        )

    def test_default_limit_100_and_max_500(self) -> None:
        blocks = self.build_chain(range(1, 6))  # five blocks, tiny amounts
        status, body = self.svc.get_chain_range(
            {"after_height": "0", "after_hash": self.genesis.block_hash}
        )
        self.assertEqual(len(body["blocks"]), 5)
        self.assertEqual(
            self.svc.get_chain_range({"limit": "500"})[0], 200
        )
        for bad in ("0", "501", "-1", "x", "01", "1.0", " 1", ""):
            self.assertEqual(
                self.svc.get_chain_range({"limit": bad})[0], 400, bad
            )

    def test_strict_height_and_hash_format(self) -> None:
        self.build_chain([10])
        for bad in ("01", "-1", "x", "1.0", ""):
            self.assertEqual(
                self.svc.get_chain_range({"after_height": bad})[0], 400, bad
            )
        # Malformed hash is 400 even with a valid height.
        self.assertEqual(
            self.svc.get_chain_range(
                {"after_height": "0", "after_hash": "not-hex"}
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.get_chain_range({"after_hash": "A" * 64})[0], 400
        )

    def test_missing_height_404_and_mismatch_409(self) -> None:
        b1 = self.build_chain([10])[0]
        self.assertEqual(self.svc.get_chain_range({"after_height": "99"})[0], 404)
        # Well-formed hash at an existing height that does not match -> 409.
        self.assertEqual(
            self.svc.get_chain_range(
                {"after_height": "0", "after_hash": b1.block_hash}
            )[0],
            409,
        )
        # Hash-only lookup: unknown hash is 404.
        self.assertEqual(
            self.svc.get_chain_range({"after_hash": "a" * 64})[0], 404
        )
        # Hash-only lookup of a real block succeeds.
        self.assertEqual(
            self.svc.get_chain_range({"after_hash": self.genesis.block_hash})[0],
            200,
        )


class SyncRangeServiceTests(RangeBase):
    def test_success_returns_five_fields_and_stores_full_chain(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        payload = self.range_payload(anchor, blocks, tip)
        status, body = self.svc.submit_fork_sync_range(payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(
            body,
            {
                "tip_hash": tip["block_hash"],
                "height": 3,
                "length": 4,
                "status": "confirmed",
                "expires_at": payload["expires_at"],
            },
        )
        # The assembled *full* chain (prefix + range) is stored as a candidate.
        fork = self.store.forks[tip["block_hash"]]
        self.assertEqual([b.height for b in fork], [0, 1, 2, 3])
        self.assertEqual(fork[1].block_hash, b1.block_hash)
        record = self.store.syncs[("node-2", "r-1")]
        self.assertEqual(record["mode"], "range")
        self.assertTrue(record["request_fingerprint"])
        # A sync_received audit event was recorded.
        self.assertEqual(
            self.store.audit_events[-1]["kind"], "sync_received"
        )

    def test_identical_retry_replays_200(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        payload = self.range_payload(anchor, blocks, tip)
        status, first = self.svc.submit_fork_sync_range(payload)
        self.assertEqual(status, 201)
        status, retry = self.svc.submit_fork_sync_range(payload)
        self.assertEqual(status, 200)
        self.assertEqual(retry, first)
        # Only one received event exists.
        self.assertEqual(
            [e["kind"] for e in self.store.audit_events].count("sync_received"), 1
        )

    def test_retry_survives_revocation_and_anchor_becoming_stale(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        payload = self.range_payload(anchor, blocks, tip)
        self.assertEqual(self.svc.submit_fork_sync_range(payload)[0], 201)
        # Revoke the source: a retry on the live key is exempt from authz.
        self.assertEqual(
            self.svc.revoke_trust_source("node-2", {"expected_version": 1})[0], 200
        )
        self.assertEqual(self.svc.submit_fork_sync_range(payload)[0], 200)
        # A brand-new key from the revoked source is now refused 403.
        other = dict(payload, request_id="r-other")
        self.assertEqual(self.svc.submit_fork_sync_range(other)[0], 403)
        # Replace canonical with a chain not containing the anchor block: the
        # retry still replays (it never re-checks today's anchor).
        alt = make_block(1, self.genesis.block_hash, self.kc, self.C, self.B, 2)
        alt2 = make_block(2, alt.block_hash, self.kc, self.C, self.B, 3)
        alt3 = make_block(3, alt2.block_hash, self.kc, self.C, self.B, 4)
        alt4 = make_block(4, alt3.block_hash, self.kc, self.C, self.B, 5)
        self.store.forks[alt4.block_hash] = [
            self.genesis, alt, alt2, alt3, alt4
        ]
        self.store.save()
        self.assertEqual(self.svc.adopt_fork(alt4.block_hash)[0], 200)
        self.assertEqual(self.svc.submit_fork_sync_range(payload)[0], 200)

    def test_changed_content_conflicts_409(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        self.assertEqual(
            self.svc.submit_fork_sync_range(self.range_payload(anchor, blocks, tip))[0],
            201,
        )
        # Tamper the tip descriptor only.
        bad_tip = dict(tip)
        bad_tip["block_hash"] = "b" * 64
        changed = self.range_payload(anchor, blocks, bad_tip)
        self.assertEqual(self.svc.submit_fork_sync_range(changed)[0], 409)
        # Tamper the anchor (same key, different body).
        changed_anchor = self.range_payload(
            {"height": 0, "block_hash": self.genesis.block_hash}, blocks, tip
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(changed_anchor)[0], 409
        )

    def test_envelope_format_errors_are_400(self) -> None:
        self.trust()
        b1 = self.build_chain([10])[0]
        blocks, anchor, tip = self.winning_range(b1)
        base = self.range_payload(anchor, blocks, tip, request_id="fmt")

        def body(**over):
            p = dict(base)
            p.update(over)
            return p

        self.assertEqual(self.svc.submit_fork_sync_range("notobj")[0], 400)
        for field in ("source", "request_id", "expires_at", "anchor", "blocks", "tip"):
            p = dict(base)
            del p[field]
            self.assertEqual(self.svc.submit_fork_sync_range(p)[0], 400, field)
        self.assertEqual(
            self.svc.submit_fork_sync_range(body(source=""))[0], 400
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(body(request_id=""))[0], 400
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(body(expires_at=True))[0], 400
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(body(anchor={"height": 0}))[0], 400
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(
                body(anchor={"height": "0", "block_hash": "a" * 64})
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(
                body(anchor={"height": -1, "block_hash": "a" * 64})
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(
                body(anchor={"height": 0, "block_hash": "ZZ"})
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(body(tip={"x": 1}))[0], 400
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(body(blocks=[]))[0], 400
        )
        self.assertEqual(
            self.svc.submit_fork_sync_range(body(blocks={}))[0], 400
        )

    def test_authorization_403_and_expiry_410_precedence(self) -> None:
        b1 = self.build_chain([10])[0]
        blocks, anchor, tip = self.winning_range(b1)
        # No trust registered -> 403, before anchor/chain examination.
        unauth = self.range_payload(anchor, blocks, tip, source="stranger")
        self.assertEqual(self.svc.submit_fork_sync_range(unauth)[0], 403)
        self.trust("node-2")
        # An expired request is 410, still before chain examination.
        expired = self.range_payload(
            anchor, blocks, tip, expires_at=int(time.time()) - 1
        )
        self.assertEqual(self.svc.submit_fork_sync_range(expired)[0], 410)

    def test_stale_anchor_409(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, _, tip = self.winning_range(b1)
        # Anchor height that does not exist.
        missing = self.range_payload(
            {"height": 99, "block_hash": "a" * 64}, blocks, tip, request_id="a1"
        )
        self.assertEqual(self.svc.submit_fork_sync_range(missing)[0], 409)
        # Anchor hash that does not match the block at that height.
        mismatch = self.range_payload(
            {"height": 1, "block_hash": self.genesis.block_hash},
            blocks, tip, request_id="a2",
        )
        self.assertEqual(self.svc.submit_fork_sync_range(mismatch)[0], 409)

    def test_spliced_chain_is_fully_revalidated(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        # Delivered blocks do not start at the next height -> 400.
        gap = self.range_payload(anchor, [blocks[1]], tip, request_id="g1")
        self.assertEqual(self.svc.submit_fork_sync_range(gap)[0], 400)
        # A tampered block hash fails the recomputed block-hash check -> 400.
        broken = dict(blocks[0].to_dict())
        broken["block_hash"] = "d" * 64
        bad = self.range_payload(anchor, [broken], tip, request_id="g2")
        self.assertEqual(self.svc.submit_fork_sync_range(bad)[0], 400)
        # Tip descriptor disagrees with the delivered tail -> 400.
        wrong_tip = {"height": 2, "block_hash": blocks[0].block_hash}
        bad = self.range_payload(anchor, blocks, wrong_tip, request_id="g3")
        self.assertEqual(self.svc.submit_fork_sync_range(bad)[0], 400)

    def test_duplicate_tip_409(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        self.assertEqual(
            self.svc.submit_fork_sync_range(
                self.range_payload(anchor, blocks, tip, request_id="d1")
            )[0],
            201,
        )
        # Same assembled tip under a different idempotency key -> 409.
        self.assertEqual(
            self.svc.submit_fork_sync_range(
                self.range_payload(anchor, blocks, tip, request_id="d2")
            )[0],
            409,
        )

    def test_cross_endpoint_key_reuse_conflicts(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        # A whole-chain sync occupying (node-2, shared).
        block = make_block(1, self.genesis.block_hash, self.ka, self.A, self.B, 99)
        full_doc = {
            "tip_hash": block.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
            "blocks": [self.genesis.to_dict(), block.to_dict()],
        }
        whole = {
            "source": "node-2",
            "request_id": "shared",
            "expires_at": int(time.time()) + 3600,
            "candidate": full_doc,
        }
        self.assertEqual(self.svc.submit_fork_sync(whole)[0], 201)
        # A range delivery reusing the same key is a conflict, regardless of
        # content.
        blocks, anchor, tip = self.winning_range(b1)
        rng = self.range_payload(anchor, blocks, tip, request_id="shared")
        self.assertEqual(self.svc.submit_fork_sync_range(rng)[0], 409)
        # And vice versa on a fresh store ordering (range first, then whole).
        blocks2, anchor2, tip2 = self.winning_range(b1)
        rng_first = self.range_payload(
            anchor2, blocks2, tip2, source="node-2", request_id="shared2"
        )
        self.assertEqual(self.svc.submit_fork_sync_range(rng_first)[0], 201)
        whole2 = dict(whole, request_id="shared2")
        self.assertEqual(self.svc.submit_fork_sync(whole2)[0], 409)

    def test_pending_tip_range(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        pending = make_block(
            2, b1.block_hash, self.kc, self.C, self.B, 5, status="pending"
        )
        anchor = {"height": 1, "block_hash": b1.block_hash}
        tip = {"height": 2, "block_hash": pending.block_hash}
        payload = self.range_payload(anchor, [pending], tip, request_id="pend")
        status, body = self.svc.submit_fork_sync_range(payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], "pending")
        self.assertEqual(self.store.forks[pending.block_hash][-1].status, "pending")

    def test_failed_write_rolls_back_everything(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        payload = self.range_payload(anchor, blocks, tip, request_id="rollback")
        generation = self.store.generation
        forks_before = set(self.store.forks)
        events_before = len(self.store.audit_events)

        def boom():
            raise OSError("simulated disk failure")

        self.store.save = boom  # type: ignore[assignment]
        with self.assertRaises(OSError):
            self.svc.submit_fork_sync_range(payload)
        # Nothing survived: no candidate, no record, no event, no generation.
        self.assertEqual(set(self.store.forks), forks_before)
        self.assertNotIn(("node-2", "rollback"), self.store.syncs)
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.generation, generation)


class SyncRangeLifecycleTests(RangeBase):
    def test_range_candidate_adopts_longest_chain(self) -> None:
        b1 = self.build_chain([10])[0]  # canonical length 2
        self.trust()
        # A longer fork (length 4) delivered as a range anchored at b1.
        blocks = []
        prev = b1.block_hash
        for i, amount in enumerate((5, 6)):
            block = make_block(2 + i, prev, self.kc, self.C, self.B, amount)
            blocks.append(block)
            prev = block.block_hash
        anchor = {"height": 1, "block_hash": b1.block_hash}
        tip = {"height": 3, "block_hash": blocks[-1].block_hash}
        self.assertEqual(
            self.svc.submit_fork_sync_range(
                self.range_payload(anchor, blocks, tip, request_id="life")
            )[0],
            201,
        )
        # It is the adoptable winner (longest).
        status, view = self.svc.get_chain()
        self.assertEqual(
            [c["tip_hash"] for c in view["adoptable"]], [blocks[-1].block_hash]
        )
        status, adopted = self.svc.adopt_fork(blocks[-1].block_hash)
        self.assertEqual(status, 200, adopted)
        self.assertEqual(self.store.tip_hash(), blocks[-1].block_hash)
        # One sync_adopted event was recorded for the range record.
        kinds = [e["kind"] for e in self.store.audit_events]
        self.assertEqual(kinds.count("sync_adopted"), 1)
        adopted_event = [e for e in self.store.audit_events
                         if e["kind"] == "sync_adopted"][0]
        self.assertEqual(adopted_event["source"], "node-2")
        self.assertEqual(adopted_event["request_id"], "life")
        # The record stays queryable until it expires.
        status, listing = self.svc.list_fork_syncs({})
        self.assertEqual(listing["total"], 1)
        # Expire it: adopted tip leaves canonical untouched, event appended.
        self.store.syncs[("node-2", "life")]["expires_at"] = int(time.time()) - 1
        self.svc._prune_expired_syncs()
        self.assertEqual(self.store.tip_hash(), blocks[-1].block_hash)
        self.assertEqual(
            [e["kind"] for e in self.store.audit_events].count("sync_expired"), 1
        )
        self.assertEqual(self.svc.list_fork_syncs({})[1]["total"], 0)

    def test_restart_persists_range_record_and_allows_replay(self) -> None:
        b1 = self.build_chain([10])[0]
        self.trust()
        blocks, anchor, tip = self.winning_range(b1)
        payload = self.range_payload(anchor, blocks, tip)
        self.assertEqual(self.svc.submit_fork_sync_range(payload)[0], 201)
        # Restart: record and assembled candidate survive.
        reopened = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        rec = reopened.store.syncs.get(("node-2", "r-1"))
        self.assertIsNotNone(rec)
        self.assertEqual(rec["mode"], "range")
        self.assertTrue(rec["request_fingerprint"])
        self.assertEqual(rec["tip_hash"], tip["block_hash"])
        self.assertIn(tip["block_hash"], reopened.store.forks)
        # Same-content retry after restart replays 200.
        self.assertEqual(reopened.submit_fork_sync_range(payload)[0], 200)

    def test_restart_prunes_unauthorized_range_record_with_event(self) -> None:
        b1 = self.build_chain([10])[0]
        # A source already registry-expired at delivery time is impossible
        # (403); simulate a record whose authorization lapses while down by
        # delivering, then expiring the *registry* entry on disk directly.
        self.trust("node-2", expires_at=int(time.time()) + 10_000_000)
        blocks, anchor, tip = self.winning_range(b1)
        payload = self.range_payload(anchor, blocks, tip)
        self.assertEqual(self.svc.submit_fork_sync_range(payload)[0], 201)
        self.store.trust_sources["node-2"]["expires_at"] = int(time.time()) - 1
        self.store.save()
        # Reopen: the record is re-authorized against the registry, pruned,
        # its candidate removed and one sync_expired backfilled.
        reopened = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.assertNotIn(("node-2", "r-1"), reopened.store.syncs)
        self.assertNotIn(tip["block_hash"], reopened.store.forks)
        expired = [e for e in reopened.store.audit_events
                   if e["kind"] == "sync_expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["request_id"], "r-1")
        # A second restart does not duplicate the event.
        reopened2 = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.assertEqual(
            [e["kind"] for e in reopened2.store.audit_events].count("sync_expired"), 1
        )


class RangeHttpTests(unittest.TestCase):
    """Both endpoints over the real HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.genesis = cls.service.store.chain[0]
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

    def _canonical_block(self, amount) -> Block:
        prev = cls_block_tip(self.service)
        height = self.service.store.next_height()
        block = make_block(height, prev, self.ka, self.A, self.B, amount)
        self.service.store.chain.append(block)
        self.service.store.save()
        return block

    def test_chain_range_over_http(self) -> None:
        status, body = self.request("GET", "/v1/chain/range")
        self.assertEqual(status, 200, body)
        self.assertIn("anchor", body)
        # Repeated query parameter -> 400.
        status, _ = self.request("GET", "/v1/chain/range?limit=1&limit=2")
        self.assertEqual(status, 400)
        # Malformed limit -> 400.
        self.assertEqual(self.request("GET", "/v1/chain/range?limit=501")[0], 400)
        # Missing anchor height -> 404; hash mismatch -> 409.
        self.assertEqual(
            self.request("GET", "/v1/chain/range?after_height=9999")[0], 404
        )
        self.assertEqual(
            self.request(
                "GET",
                f"/v1/chain/range?after_height=0&after_hash={'b' * 64}",
            )[0],
            409,
        )

    def test_sync_range_over_http(self) -> None:
        anchor_block = self._canonical_block(10)
        r2 = make_block(
            anchor_block.height + 1, anchor_block.block_hash,
            self.kc, self.C, self.B, 5,
        )
        r3 = make_block(
            anchor_block.height + 2, r2.block_hash, self.kc, self.C, self.B, 6
        )
        payload = {
            "source": "http-node",
            "request_id": f"h-{anchor_block.height}",
            "expires_at": int(time.time()) + 3600,
            "anchor": {"height": anchor_block.height,
                       "block_hash": anchor_block.block_hash},
            "blocks": [r2.to_dict(), r3.to_dict()],
            "tip": {"height": r3.height, "block_hash": r3.block_hash},
        }
        status, body = self.request("POST", "/v1/forks/sync/range", payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], r3.block_hash)
        # Identical retry -> 200.
        status, retry = self.request("POST", "/v1/forks/sync/range", payload)
        self.assertEqual(status, 200)
        self.assertEqual(retry, body)
        # Malformed body -> 400.
        status, _ = self.request("POST", "/v1/forks/sync/range", {"source": "x"})
        self.assertEqual(status, 400)

    def test_sync_range_non_json_body_400(self) -> None:
        req = urllib.request.Request(
            f"{self.base}/v1/forks/sync/range",
            data=b"not-json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)


def cls_block_tip(service) -> str:
    return service.store.tip_hash()


class RangeCliTests(unittest.TestCase):
    """The chain-range / sync-range CLI subcommands against a live server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.genesis = cls.service.store.chain[0]
        status, _ = cls.service.register_trust_source(
            {
                "source": "cli-node",
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
    def run_cli(cls, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", cls.base_url, *argv])
        line = buf.getvalue().strip()
        return rc, json.loads(line)

    def test_chain_range_cli(self) -> None:
        prev = self.service.store.tip_hash()
        block = make_block(
            self.service.store.next_height(), prev, self.ka, self.A, self.B, 11
        )
        self.service.store.chain.append(block)
        self.service.store.save()
        rc, body = self.run_cli(
            "chain-range", "--after-height", "0",
            "--after-hash", self.genesis.block_hash,
        )
        self.assertEqual(rc, 0)
        self.assertTrue(any(b["block_hash"] == block.block_hash for b in body["blocks"]))
        # A bad request exits non-zero but still prints one JSON line.
        rc, body = self.run_cli("chain-range", "--limit", "0")
        self.assertEqual(rc, 1)
        self.assertIn("error", body)

    def test_sync_range_cli(self) -> None:
        prev = self.service.store.tip_hash()
        anchor_block = make_block(
            self.service.store.next_height(), prev, self.ka, self.A, self.B, 12
        )
        self.service.store.chain.append(anchor_block)
        self.service.store.save()
        r2 = make_block(
            anchor_block.height + 1, anchor_block.block_hash,
            self.kc, self.C, self.B, 7,
        )
        doc = {
            "anchor": {"height": anchor_block.height,
                       "block_hash": anchor_block.block_hash},
            "blocks": [r2.to_dict()],
            "tip": {"height": r2.height, "block_hash": r2.block_hash},
        }
        rc, body = self.run_cli(
            "sync-range", "--source", "cli-node", "--request-id", "c-1",
            "--expires-at", str(int(time.time()) + 3600), json.dumps(doc),
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["tip_hash"], r2.block_hash)
        # Retry exits 0 with 200.
        rc, body = self.run_cli(
            "sync-range", "--source", "cli-node", "--request-id", "c-1",
            "--expires-at", str(int(time.time()) + 3600), json.dumps(doc),
        )
        self.assertEqual(rc, 0)
        # Unauthorized source exits 1.
        rc, body = self.run_cli(
            "sync-range", "--source", "nobody", "--request-id", "c-2",
            "--expires-at", str(int(time.time()) + 3600), json.dumps(doc),
        )
        self.assertEqual(rc, 1)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main()
