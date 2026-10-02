"""Tests for the block-anchor prefix of GET /v1/index/transactions.

The optional ``at_height``/``at_hash`` pair fixes the query prefix to the
confirmed main-chain blocks from genesis through the anchor inclusive.
Covers the all-or-nothing strict validation (400 input, including repeats),
anchor resolution (404 anchor_not_found for unknown/pending heights, 409
anchor_conflict on hash mismatch, candidate forks never satisfying an
anchor), fixed-prefix filtering and pagination, prefix stability as the
tail grows or is rolled back, fork adoption semantics, persistence across
a restart, read-only behaviour, and the HTTP/CLI surface.

Run: python3 tests/index_anchor_test.py
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


class AnchorServiceTests(unittest.TestCase):
    """Anchor prefix semantics at service level."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(LedgerStore(cls.path), initial_balance=1000)
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        # Block 1 (confirmed): A->B 10, A->C 20. Block 2 (confirmed): B->C 5.
        for key, sender, to, amount in (
            (cls.ka, cls.A, cls.B, 10),
            (cls.ka, cls.A, cls.C, 20),
        ):
            rc, _ = cls.svc.submit_transaction(signed_tx(key, sender, to, amount))
            assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kb, cls.B, cls.C, 5))
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(2)[0] == 200
        cls.hashes = {
            block.height: block.block_hash for block in cls.svc.store.chain
        }

    def query(self, **params) -> tuple[int, dict]:
        return self.svc.list_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def anchor(self, anchor_height: int, block_hash: str | None = None, **params):
        params.setdefault("at_height", str(anchor_height))
        params.setdefault("at_hash", block_hash or self.hashes[anchor_height])
        return self.query(**params)

    def test_anchor_prefix_contents_and_order(self) -> None:
        status, body = self.anchor(2)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 3)
        self.assertIsNone(body["next_cursor"])
        self.assertEqual([it["height"] for it in body["items"]], [1, 1, 2])
        status, body = self.anchor(1)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 2)
        self.assertTrue(all(it["height"] == 1 for it in body["items"]))
        # The genesis anchor is valid and yields an empty set.
        status, body = self.anchor(0)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])
        self.assertIsNone(body["next_cursor"])

    def test_anchor_prefix_pagination(self) -> None:
        status, first = self.anchor(2, limit="2")
        self.assertEqual(status, 200, first)
        self.assertEqual(first["total"], 3)
        self.assertEqual(len(first["items"]), 2)
        self.assertEqual(first["next_cursor"], 2)
        status, second = self.anchor(2, cursor="2", limit="2")
        self.assertEqual(status, 200, second)
        self.assertEqual(second["total"], 3)
        self.assertEqual(len(second["items"]), 1)
        self.assertIsNone(second["next_cursor"])
        self.assertNotEqual(first["items"][0], second["items"][0])
        # cursor == total -> empty page; beyond -> the legacy 400.
        status, body = self.anchor(1, cursor="2")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["items"], [])
        self.assertEqual(self.anchor(1, cursor="3")[0], 400)

    def test_filters_intersect_prefix(self) -> None:
        # A filter height above the anchor is a normal empty page.
        status, body = self.anchor(1, height="2")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])
        self.assertIsNone(body["next_cursor"])
        status, body = self.anchor(1, min_height="2")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        # Bounds inside the prefix intersect normally.
        status, body = self.anchor(2, min_height="2")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        status, body = self.anchor(2, account=self.A, direction="out")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        status, body = self.anchor(1, account=self.A, direction="out")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        # tx_id intersects the prefix too.
        status, all_items = self.anchor(2)
        tx_in_two = all_items["items"][-1]["tx_id"]
        status, body = self.anchor(1, tx_id=tx_in_two)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        status, body = self.anchor(2, tx_id=tx_in_two)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)

    def test_input_errors(self) -> None:
        good_hash = self.hashes[1]
        cases = (
            {"at_height": "1"},
            {"at_hash": good_hash},
            {"at_height": "", "at_hash": good_hash},
            {"at_height": "1", "at_hash": ""},
            {"at_height": "01", "at_hash": good_hash},
            {"at_height": "00", "at_hash": good_hash},
            {"at_height": "-1", "at_hash": good_hash},
            {"at_height": "1.0", "at_hash": good_hash},
            {"at_height": "+1", "at_hash": good_hash},
            {"at_height": " 1", "at_hash": good_hash},
            {"at_height": "1 ", "at_hash": good_hash},
            {"at_height": "abc", "at_hash": good_hash},
            # Non-ASCII digits are not ASCII decimal strings.
            {"at_height": "\u0663", "at_hash": good_hash},
            {"at_height": "\uff11\uff12", "at_hash": good_hash},
            {"at_height": "1", "at_hash": "abc"},
            {"at_height": "1", "at_hash": "B" * 64},
            {"at_height": "1", "at_hash": "g" * 64},
            {"at_height": "1", "at_hash": good_hash[:63]},
            {"at_height": "1", "at_hash": good_hash + "0"},
        )
        for params in cases:
            status, body = self.query(**params)
            self.assertEqual(status, 400, params)
            self.assertEqual(body, {"error": "input"}, params)

    def test_anchor_resolution_errors(self) -> None:
        # Unknown height beyond the chain.
        status, body = self.query(at_height="99", at_hash="a" * 64)
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "anchor_not_found"})
        # Confirmed height, wrong hash.
        status, body = self.query(at_height="1", at_hash="a" * 64)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "anchor_conflict"})
        # Another confirmed block hash at a different height also conflicts.
        status, body = self.query(
            at_height="1", at_hash=self.hashes[2]
        )
        self.assertEqual(status, 409)

    def test_anchor_errors_precede_cursor_error(self) -> None:
        # A bad anchor is reported even though the cursor is beyond total.
        status, _ = self.query(
            at_height="99", at_hash="a" * 64, cursor="5"
        )
        self.assertEqual(status, 404)
        status, _ = self.query(
            at_height="1", at_hash="a" * 64, cursor="5"
        )
        self.assertEqual(status, 409)
        # Sanity: with a valid anchor the out-of-range cursor stays 400.
        self.assertEqual(self.anchor(1, cursor="99")[0], 400)

    def test_omitted_pair_preserves_legacy_behaviour(self) -> None:
        status, body = self.query()
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)

    def test_query_is_read_only(self) -> None:
        store = self.svc.store
        with store.lock:
            before = {
                "generation": store.generation,
                "audit": len(store.audit_events),
                "chain": [(b.height, b.block_hash, b.status) for b in store.chain],
                "pending": sorted(store.pending),
                "forks": sorted(store.forks),
            }
        for params in (
            {"at_height": "1", "at_hash": self.hashes[1]},
            {"at_height": "99", "at_hash": "a" * 64},
            {"at_height": "1", "at_hash": "a" * 64},
            {"at_height": "1"},
        ):
            self.svc.list_transactions(params)
        with store.lock:
            after = {
                "generation": store.generation,
                "audit": len(store.audit_events),
                "chain": [(b.height, b.block_hash, b.status) for b in store.chain],
                "pending": sorted(store.pending),
                "forks": sorted(store.forks),
            }
        self.assertEqual(before, after)


class AnchorLifecycleTests(unittest.TestCase):
    """The fixed prefix survives growth, rollback and a restart."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.kd, self.D = keypair()
        rc, _ = self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, 10))
        assert rc == 202
        assert self.svc.mine_block()[0] == 201
        assert self.svc.confirm_block(1)[0] == 200
        self.h1 = self.svc.store.chain[1].block_hash

    def query(self, svc: LedgerService, **params) -> tuple[int, dict]:
        return svc.list_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def snapshot(self, svc: LedgerService) -> dict:
        pages: list[list[dict]] = []
        cursor = 0
        total = None
        while True:
            status, body = self.query(
                svc, at_height="1", at_hash=self.h1,
                limit="1", cursor=str(cursor),
            )
            assert status == 200, body
            total = body["total"]
            pages.append(body["items"])
            if body["next_cursor"] is None:
                break
            cursor = body["next_cursor"]
        return {"total": total, "pages": pages}

    def test_prefix_stable_as_tail_grows(self) -> None:
        before = self.snapshot(self.svc)
        # Confirm more blocks after the anchor.
        rc, _ = self.svc.submit_transaction(signed_tx(self.kb, self.B, self.C, 5))
        assert rc == 202
        assert self.svc.mine_block()[0] == 201
        assert self.svc.confirm_block(2)[0] == 200
        rc, _ = self.svc.submit_transaction(signed_tx(self.kc, self.C, self.A, 2))
        assert rc == 202
        assert self.svc.mine_block()[0] == 201
        assert self.svc.confirm_block(3)[0] == 200
        # The unanchored index sees the new transactions.
        status, body = self.query(self.svc)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)
        # The anchored pages reconstruct exactly the same set.
        self.assertEqual(self.snapshot(self.svc), before)
        # Direct totals agree regardless of tail growth.
        status, body = self.query(self.svc, at_height="1", at_hash=self.h1)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], before["total"])

    def test_pending_tip_anchor_is_not_found(self) -> None:
        rc, _ = self.svc.submit_transaction(signed_tx(self.kb, self.B, self.C, 5))
        assert rc == 202
        assert self.svc.mine_block()[0] == 201
        pending_hash = self.svc.store.chain[2].block_hash
        status, body = self.query(
            self.svc, at_height="2", at_hash=pending_hash
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "anchor_not_found"})
        # Rolling the pending tail back leaves the established prefix intact.
        assert self.svc.rollback_block(2)[0] == 200
        status, body = self.query(self.svc, at_height="1", at_hash=self.h1)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)

    def test_restart_preserves_prefix(self) -> None:
        before = self.query(self.svc, at_height="1", at_hash=self.h1, limit="50")
        self.assertEqual(before[0], 200)
        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        after = self.query(reopened, at_height="1", at_hash=self.h1, limit="50")
        self.assertEqual(after, before)
        # And the paged set still reconstructs the same collection.
        self.assertEqual(self.snapshot(reopened), self.snapshot(self.svc))

    def test_candidate_fork_cannot_satisfy_anchor(self) -> None:
        genesis = self.svc.store.chain[0]
        # A competing block 1 with different transactions; its hash differs.
        alt_block = Block.create(
            1, genesis.block_hash, [tx_obj(self.kd, self.D, self.A, 9)],
            "confirmed",
        )
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), alt_block.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        # The candidate hash at height 1 must not resolve as an anchor.
        status, body = self.query(
            self.svc, at_height="1", at_hash=alt_block.block_hash
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "anchor_conflict"})

    def test_fork_adoption_keeps_or_rejects_prefix(self) -> None:
        genesis = self.svc.store.chain[0]
        original_block = self.svc.store.chain[1]
        # Same shared block 1 (same hash), then a longer fork on top.
        alt_block2 = Block.create(
            2, original_block.block_hash,
            [tx_obj(self.kd, self.D, self.C, 3)], "confirmed",
        )
        alt_block3 = Block.create(
            3, alt_block2.block_hash,
            [tx_obj(self.kd, self.D, self.B, 4)], "confirmed",
        )
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [
                genesis.to_dict(),
                original_block.to_dict(),
                alt_block2.to_dict(),
                alt_block3.to_dict(),
            ]}
        )
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        before = self.snapshot(self.svc)
        status, body = self.svc.adopt_fork(tip)
        self.assertEqual(status, 200, body)
        # The shared anchor stays confirmed with the same hash: identical set.
        self.assertEqual(self.snapshot(self.svc), before)
        status, body = self.query(self.svc, at_height="1", at_hash=self.h1)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)

        # A divergent adoption changes the block at height 1: the old anchor
        # is refused rather than silently returning new-chain data.
        divergent = Block.create(
            1, genesis.block_hash,
            [
                tx_obj(self.kd, self.D, self.A, 1),
                tx_obj(self.kd, self.D, self.C, 2),
            ],
            "confirmed",
        )
        divergent2 = Block.create(
            2, divergent.block_hash,
            [tx_obj(self.kc, self.C, self.D, 7)], "confirmed",
        )
        divergent3 = Block.create(
            3, divergent2.block_hash,
            [tx_obj(self.kd, self.D, self.B, 8)], "confirmed",
        )
        divergent4 = Block.create(
            4, divergent3.block_hash,
            [tx_obj(self.kc, self.C, self.A, 6)], "confirmed",
        )
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [
                genesis.to_dict(),
                divergent.to_dict(),
                divergent2.to_dict(),
                divergent3.to_dict(),
                divergent4.to_dict(),
            ]}
        )
        self.assertEqual(status, 201, body)
        status, adopted = self.svc.adopt_fork(body["tip_hash"])
        self.assertEqual(status, 200, adopted)
        status, body = self.query(
            self.svc, at_height="1", at_hash=self.h1
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "anchor_conflict"})


class AnchorHttpTests(unittest.TestCase):
    """The anchor parameters over the real HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        rc, body = cls.request(
            "POST", "/v1/transactions", signed_tx(cls.ka, cls.A, cls.B, 7)
        )
        assert rc == 202, body
        assert cls.request("POST", "/v1/blocks")[0] == 201
        assert cls.request("POST", "/v1/blocks/1/confirm")[0] == 200
        cls.h1 = cls.service.store.chain[1].block_hash
        # A candidate fork whose height-1 block has a different hash.
        genesis = cls.service.store.chain[0]
        cls.fork_block1 = Block.create(
            1, genesis.block_hash, [tx_obj(cls.kb, cls.B, cls.A, 3)], "confirmed"
        )
        rc, body = cls.request(
            "POST", "/v1/forks/candidates",
            {"blocks": [genesis.to_dict(), cls.fork_block1.to_dict()]},
        )
        assert rc == 201, body

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, method: str, path: str, payload=None):
        url = f"{cls.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_anchor_over_http(self) -> None:
        status, body = self.request(
            "GET", f"/v1/index/transactions?at_height=1&at_hash={self.h1}"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 1)
        # Genesis anchor -> empty set.
        ghash = self.service.store.chain[0].block_hash
        status, body = self.request(
            "GET", f"/v1/index/transactions?at_height=0&at_hash={ghash}"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["items"], [])
        # Unknown height and a hash mismatch.
        status, body = self.request(
            "GET", f"/v1/index/transactions?at_height=9&at_hash={'a'*64}"
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "anchor_not_found"})
        status, body = self.request(
            "GET", f"/v1/index/transactions?at_height=1&at_hash={'a'*64}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "anchor_conflict"})
        # A candidate-fork hash never satisfies the anchor.
        status, body = self.request(
            "GET",
            f"/v1/index/transactions?at_height=1"
            f"&at_hash={self.fork_block1.block_hash}",
        )
        self.assertEqual(status, 409)
        # Filters intersect the prefix; height past the anchor is an empty page.
        status, body = self.request(
            "GET",
            f"/v1/index/transactions?at_height=1&at_hash={self.h1}"
            "&min_height=2",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)

    def test_input_violations_over_http(self) -> None:
        for query in (
            "at_height=1",
            f"at_hash={self.h1}",
            f"at_height=&at_hash={self.h1}",
            f"at_height=1&at_hash=",
            f"at_height=01&at_hash={self.h1}",
            f"at_height=-1&at_hash={self.h1}",
            f"at_height=1.0&at_hash={self.h1}",
            "at_height=1&at_hash=ZZ" + "0" * 62,
            f"at_height=1&at_hash={self.h1.upper()}",
            f"at_height=1&at_hash={self.h1[:63]}",
            f"at_height=1&at_height=1&at_hash={self.h1}",
            f"at_height=1&at_hash={self.h1}&at_hash={self.h1}",
            # A repeated anchor with an identical value is still rejected.
            f"at_height=1&at_height=1&at_hash={self.h1}&at_hash={self.h1}",
        ):
            status, body = self.request(
                "GET", f"/v1/index/transactions?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "input"}, query)

    def test_legacy_repeated_params_keep_first_value(self) -> None:
        # Only the new pair and the range/direction params reject repeats.
        status, body = self.request(
            "GET",
            f"/v1/index/transactions?at_height=1&at_hash={self.h1}"
            "&height=1&height=2",
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 1)



class AnchorCliTests(unittest.TestCase):
    """The index CLI forwards --at-height/--at-hash verbatim."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        rc, _ = cls.service.submit_transaction(
            signed_tx(cls.ka, cls.A, cls.B, 9)
        )
        assert rc == 202
        assert cls.service.mine_block()[0] == 201
        assert cls.service.confirm_block(1)[0] == 200
        rc, _ = cls.service.submit_transaction(
            signed_tx(cls.kb, cls.B, cls.A, 4)
        )
        assert rc == 202
        assert cls.service.mine_block()[0] == 201
        assert cls.service.confirm_block(2)[0] == 200
        cls.hashes = {
            block.height: block.block_hash for block in cls.service.store.chain
        }

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

    def test_anchor_cli(self) -> None:
        rc, body = self.run_cli(
            "index", "--at-height", "1", "--at-hash", self.hashes[1]
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["height"], 1)
        # The anchor combines with the legacy options.
        rc, body = self.run_cli(
            "index", "--at-height", "2", "--at-hash", self.hashes[2],
            "--account", self.B, "--direction", "out", "--limit", "1",
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["next_cursor"], None)
        # Genesis anchor -> empty set, still a success.
        rc, body = self.run_cli(
            "index", "--at-height", "0", "--at-hash", self.hashes[0]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 0)
        # Anchor failures exit 1.
        rc, body = self.run_cli(
            "index", "--at-height", "99", "--at-hash", "a" * 64
        )
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "anchor_not_found"})
        rc, body = self.run_cli(
            "index", "--at-height", "1", "--at-hash", "a" * 64
        )
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "anchor_conflict"})

    def test_anchor_cli_input_failures(self) -> None:
        for args in (
            ("--at-height", "1"),
            ("--at-hash", self.hashes[1]),
            ("--at-height", "01", "--at-hash", self.hashes[1]),
            ("--at-height", "1", "--at-hash", "zz"),
            ("--at-height", "", "--at-hash", self.hashes[1]),
        ):
            rc, body = self.run_cli("index", *args)
            self.assertEqual(rc, 1, args)
            self.assertEqual(body, {"error": "input"}, args)

    def test_unanchored_cli_unchanged(self) -> None:
        rc, body = self.run_cli("index")
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 2)
