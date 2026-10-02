"""Tests for fork export, export-format candidate submission and the
confirmed-chain transaction index.

Covers GET /v1/forks/{tip_hash}/export (candidate-only; canonical, unknown
and malformed tips all 404; five-field response whose summary describes the
tip and whose blocks carry the genesis block, signed transactions and an
optional pending tip), POST /v1/forks/candidates accepting the exported
five-field document (summary re-verification failure -> 400, duplicate ->
409, fresh node -> 201), and GET /v1/index/transactions (confirmed chain
only, AND-combined tx_id/account/height filters, strict decimal
height/limit/cursor validation, (height, index, tx_id) ordering matching
the Merkle proof index, items/total/next_cursor pagination with
cursor == total -> empty page and cursor > total -> 400; the inclusive
min_height/max_height range intersecting an exact height, and the
direction filter — all/out/in with in/out requiring a non-empty account,
self-transfers listed once under every matching direction — where every
new-parameter violation, including repeats, is 400 {"error": "input"}),
plus the CLI ``export`` and ``index`` subcommands (non-2xx -> exit code 1).

Run: python3 tests/export_index_test.py
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


class ExportServiceTests(unittest.TestCase):
    """Fork export and export-format candidate submission at service level."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json"), initial_balance=1000),
            initial_balance=1000,
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        # Candidate: genesis + confirmed block 1 + pending tip block 2.
        block1 = Block.create(1, self.genesis.block_hash,
                              [tx_obj(self.ka, self.A, self.B, 10)], "confirmed")
        block2 = Block.create(2, block1.block_hash,
                              [tx_obj(self.kb, self.B, self.A, 5)], "pending")
        self.fork_blocks = [self.genesis, block1, block2]
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [b.to_dict() for b in self.fork_blocks]}
        )
        self.assertEqual(status, 201, body)
        self.tip_hash = body["tip_hash"]

    def test_export_candidate_shape(self) -> None:
        status, body = self.svc.export_fork(self.tip_hash)
        self.assertEqual(status, 200, body)
        self.assertEqual(
            set(body), {"tip_hash", "height", "length", "status", "blocks"}
        )
        # Summary describes the tip (last) block.
        self.assertEqual(body["tip_hash"], self.tip_hash)
        self.assertEqual(body["height"], 2)
        self.assertEqual(body["length"], 3)
        self.assertEqual(body["status"], "pending")
        # Blocks carry the genesis block, signed transactions and the
        # pending tip.
        self.assertEqual(len(body["blocks"]), 3)
        self.assertEqual(body["blocks"][0]["height"], 0)
        self.assertEqual(body["blocks"][0]["status"], "confirmed")
        self.assertEqual(body["blocks"][0]["transactions"], [])
        self.assertEqual(body["blocks"][-1]["status"], "pending")
        txs = body["blocks"][1]["transactions"]
        self.assertTrue(txs)
        for tx in txs:
            self.assertTrue(crypto.is_hex64(tx["tx_id"]))
            self.assertIn("signature", tx)

    def test_export_unknown_and_malformed_tips(self) -> None:
        # Canonical tip is not exportable.
        self.assertEqual(self.svc.export_fork(self.store.tip_hash())[0], 404)
        # Unknown but well-formed tip.
        self.assertEqual(self.svc.export_fork("a" * 64)[0], 404)
        # Malformed tips: non-hex, uppercase, wrong length, non-string.
        for bad in ("z" * 64, "A" * 64, "abc", "", None, 123):
            self.assertEqual(self.svc.export_fork(bad)[0], 404, bad)

    def test_resubmit_export_is_duplicate(self) -> None:
        status, body = self.svc.export_fork(self.tip_hash)
        self.assertEqual(status, 200)
        status, resub = self.svc.submit_fork_candidate(body)
        self.assertEqual(status, 409, resub)

    def test_export_roundtrip_to_fresh_node(self) -> None:
        status, exported = self.svc.export_fork(self.tip_hash)
        self.assertEqual(status, 200)
        other = LedgerService(
            LedgerStore(
                os.path.join(self.tmp, "other.json"), initial_balance=1000
            ),
            initial_balance=1000,
        )
        status, body = other.submit_fork_candidate(exported)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["tip_hash"], self.tip_hash)
        self.assertEqual(body["length"], 3)
        self.assertEqual(body["status"], "pending")

    def test_summary_mismatch_rejected(self) -> None:
        status, exported = self.svc.export_fork(self.tip_hash)
        self.assertEqual(status, 200)
        for field, bad in (
            ("tip_hash", "0" * 64),
            ("height", 1),
            ("length", 2),
            ("status", "confirmed"),
        ):
            tampered = dict(exported)
            tampered[field] = bad
            rc, body = self.svc.submit_fork_candidate(tampered)
            self.assertEqual(rc, 400, (field, body))

    def test_tampered_blocks_rejected(self) -> None:
        status, exported = self.svc.export_fork(self.tip_hash)
        self.assertEqual(status, 200)
        tampered = json.loads(json.dumps(exported))
        tampered["blocks"][1]["transactions"][0]["signature"] = "0" * 128
        rc, body = self.svc.submit_fork_candidate(tampered)
        self.assertEqual(rc, 400, body)


class IndexServiceTests(unittest.TestCase):
    """Confirmed-chain transaction index at service level."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.svc = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "state.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        # Block 1 (confirmed): A->B 10, A->C 20. Block 2 (confirmed): B->C 5.
        # Block 3 (pending tip): C->A 1 -- must never appear in the index.
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
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kc, cls.C, cls.A, 1))
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        cls.pending_tip_tx = cls.svc.store.tip().transactions[0].tx_id

    def query(self, **params) -> tuple[int, dict]:
        return self.svc.list_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def test_all_confirmed_ordered(self) -> None:
        status, body = self.query()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 3)
        self.assertIsNone(body["next_cursor"])
        items = body["items"]
        self.assertEqual(len(items), 3)
        keys = [(it["height"], it["index"], it["tx_id"]) for it in items]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([it["height"] for it in items], [1, 1, 2])
        self.assertEqual([it["index"] for it in items], [0, 1, 0])
        for item in items:
            self.assertEqual(
                set(item),
                {"tx_id", "height", "block_hash", "index", "from", "to", "amount"},
            )
            self.assertTrue(crypto.is_hex64(item["tx_id"]))
            self.assertTrue(crypto.is_hex64(item["block_hash"]))
        # The pending tip transaction is excluded.
        self.assertNotIn(self.pending_tip_tx, [it["tx_id"] for it in items])

    def test_index_matches_proof(self) -> None:
        status, body = self.query()
        self.assertEqual(status, 200)
        for item in body["items"]:
            rc, proof = self.svc.get_proof(item["height"], item["tx_id"])
            self.assertEqual(rc, 200)
            self.assertEqual(proof["index"], item["index"])
            self.assertEqual(proof["block_hash"], item["block_hash"])

    def test_tx_id_filter(self) -> None:
        status, body = self.query()
        target = body["items"][0]["tx_id"]
        status, filtered = self.query(tx_id=target)
        self.assertEqual(status, 200)
        self.assertEqual(filtered["total"], 1)
        self.assertEqual(filtered["items"][0]["tx_id"], target)
        # Unknown but well-formed id -> empty page.
        status, empty = self.query(tx_id="b" * 64)
        self.assertEqual(status, 200)
        self.assertEqual(empty["total"], 0)
        self.assertEqual(empty["items"], [])
        self.assertIsNone(empty["next_cursor"])
        # Malformed ids -> 400.
        for bad in ("B" * 64, "abc", "", "g" * 64):
            self.assertEqual(self.query(tx_id=bad)[0], 400, bad)

    def test_account_filter_matches_from_or_to(self) -> None:
        status, body = self.query(account=self.B)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)  # A->B (to) and B->C (from)
        for item in body["items"]:
            self.assertIn(self.B, (item["from"], item["to"]))
        status, body = self.query(account=self.A)
        self.assertEqual(body["total"], 2)  # two confirmed sends; pending C->A excluded
        self.assertEqual(self.query(account="d" * 64)[1]["total"], 0)
        self.assertEqual(self.query(account="")[0], 400)

    def test_height_filter_and_and_semantics(self) -> None:
        status, body = self.query(height="1")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        self.assertTrue(all(it["height"] == 1 for it in body["items"]))
        # AND combination: account A at height 2 matches nothing.
        status, body = self.query(account=self.A, height="2")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        status, body = self.query(account=self.B, height="2")
        self.assertEqual(body["total"], 1)
        # Malformed heights -> 400.
        for bad in ("01", "-1", "1.0", "abc", "", " 1"):
            self.assertEqual(self.query(height=bad)[0], 400, bad)
        # Genesis height 0 has no transactions.
        self.assertEqual(self.query(height="0")[1]["total"], 0)

    def test_limit_validation_and_pagination(self) -> None:
        status, page1 = self.query(limit="2")
        self.assertEqual(status, 200)
        self.assertEqual(len(page1["items"]), 2)
        self.assertEqual(page1["total"], 3)
        self.assertEqual(page1["next_cursor"], 2)
        status, page2 = self.query(limit="2", cursor="2")
        self.assertEqual(len(page2["items"]), 1)
        self.assertIsNone(page2["next_cursor"])
        # Pages are disjoint and together cover the unfiltered listing.
        all_ids = [it["tx_id"] for it in self.query()[1]["items"]]
        self.assertEqual(
            [it["tx_id"] for it in page1["items"] + page2["items"]], all_ids
        )
        for bad in ("0", "201", "007", "-3", "abc", ""):
            self.assertEqual(self.query(limit=bad)[0], 400, bad)
        self.assertEqual(self.query(limit="1")[0], 200)
        self.assertEqual(self.query(limit="200")[0], 200)

    def test_cursor_validation(self) -> None:
        # cursor == total -> empty page, not an error.
        status, body = self.query(cursor="3")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        self.assertEqual(body["total"], 3)
        self.assertIsNone(body["next_cursor"])
        # cursor > total -> 400.
        self.assertEqual(self.query(cursor="4")[0], 400)
        # cursor beyond the *filtered* total -> 400 as well.
        self.assertEqual(self.query(account=self.B, cursor="3")[0], 400)
        status, body = self.query(account=self.B, cursor="2")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        for bad in ("-1", "01", "abc", ""):
            self.assertEqual(self.query(cursor=bad)[0], 400, bad)

    def test_min_max_height_range(self) -> None:
        # Inclusive bounds on both ends.
        status, body = self.query(min_height="1", max_height="1")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        self.assertTrue(all(it["height"] == 1 for it in body["items"]))
        status, body = self.query(min_height="2")
        self.assertEqual([it["height"] for it in body["items"]], [2])
        status, body = self.query(max_height="1")
        self.assertEqual([it["height"] for it in body["items"]], [1, 1])
        # A bound of 0 simply includes the (transaction-less) genesis range.
        self.assertEqual(self.query(min_height="0")[1]["total"], 3)
        self.assertEqual(self.query(min_height="0", max_height="0")[1]["total"], 0)
        # An upper bound beyond the chain tip is not an error.
        self.assertEqual(self.query(max_height="99")[1]["total"], 3)
        # A range entirely beyond the tip -> 200 empty page.
        for params in ({"min_height": "3"}, {"min_height": "5", "max_height": "9"}):
            status, body = self.query(**params)
            self.assertEqual(status, 200, params)
            self.assertEqual(body["total"], 0)
            self.assertEqual(body["items"], [])
            self.assertIsNone(body["next_cursor"])

    def test_height_intersects_range(self) -> None:
        # An exact height inside the range -> intersection.
        status, body = self.query(height="1", min_height="1", max_height="2")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        # An exact height outside the range -> empty page, not an error.
        for params in (
            {"height": "1", "min_height": "2"},
            {"height": "2", "max_height": "1"},
            {"height": "1", "min_height": "2", "max_height": "3"},
        ):
            status, body = self.query(**params)
            self.assertEqual(status, 200, params)
            self.assertEqual(body["total"], 0)
            self.assertEqual(body["items"], [])

    def test_range_validation_input_error(self) -> None:
        # Empty values, signs, decimals, whitespace, leading zeros and
        # non-ASCII digits are all the fixed {"error": "input"}.
        for bad in ("", "01", "00", "-1", "+1", "1.0", " 1", "1 ", "1_0",
                    "abc", "１２", "٣", "²"):
            for key in ("min_height", "max_height"):
                status, body = self.query(**{key: bad})
                self.assertEqual(status, 400, (key, bad))
                self.assertEqual(body, {"error": "input"}, (key, bad))
        # Inverted bounds.
        status, body = self.query(min_height="2", max_height="1")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "input"})
        # Equal bounds are a valid single-height range.
        status, body = self.query(min_height="2", max_height="2")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)

    def test_direction_filter(self) -> None:
        # Default and explicit "all" keep the sender-or-recipient semantics.
        self.assertEqual(self.query(account=self.A)[1]["total"], 2)
        self.assertEqual(self.query(account=self.A, direction="all")[1]["total"], 2)
        # out matches the sender only, in the recipient only.
        status, body = self.query(account=self.B, direction="out")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)  # B->C
        self.assertTrue(all(it["from"] == self.B for it in body["items"]))
        status, body = self.query(account=self.B, direction="in")
        self.assertEqual(body["total"], 1)  # A->B
        self.assertTrue(all(it["to"] == self.B for it in body["items"]))
        status, body = self.query(account=self.C, direction="in")
        self.assertEqual(body["total"], 2)  # A->C, B->C
        status, body = self.query(account=self.C, direction="out")
        self.assertEqual(body["total"], 0)  # C->A sits in the pending tip
        # Unknown account with a direction -> 200 empty page.
        status, body = self.query(account="d" * 64, direction="out")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)

    def test_direction_validation_input_error(self) -> None:
        for bad in ("", "IN", "Out", "both", "none", "1"):
            status, body = self.query(account=self.A, direction=bad)
            self.assertEqual(status, 400, bad)
            self.assertEqual(body, {"error": "input"}, bad)
        # in/out require a non-empty account; all does not.
        for direction in ("in", "out"):
            status, body = self.query(direction=direction)
            self.assertEqual(status, 400)
            self.assertEqual(body, {"error": "input"})
            status, body = self.query(direction=direction, account="")
            self.assertEqual(status, 400)
            self.assertEqual(body, {"error": "input"})
        self.assertEqual(self.query(direction="all")[0], 200)

    def test_range_direction_and_legacy_filters_combine(self) -> None:
        status, body = self.query(
            account=self.A, direction="out", min_height="1", max_height="1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        status, body = self.query(account=self.A, direction="out", min_height="2")
        self.assertEqual(body["total"], 0)
        # total counts the whole filtered set while the page is sliced.
        status, body = self.query(
            account=self.A, direction="all", min_height="1", limit="1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(body["next_cursor"], 1)
        # cursor == filtered total -> empty page; beyond -> 400.
        status, body = self.query(account=self.A, direction="out", cursor="2")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        self.assertEqual(self.query(account=self.A, direction="out", cursor="3")[0], 400)


class IndexSelfTransferTests(unittest.TestCase):
    """Self-transfers appear exactly once under every matching direction."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.svc = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "state.json"), initial_balance=1000),
            initial_balance=1000,
        )
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        # Block 1 (confirmed): A->A 7 (self-transfer), A->B 3.
        for key, sender, to, amount in (
            (cls.ka, cls.A, cls.A, 7),
            (cls.ka, cls.A, cls.B, 3),
        ):
            rc, _ = cls.svc.submit_transaction(signed_tx(key, sender, to, amount))
            assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200

    def query(self, **params) -> tuple[int, dict]:
        return self.svc.list_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def test_self_transfer_listed_once_per_direction(self) -> None:
        # A->A and A->B are confirmed; the self-transfer matches every
        # direction while A->B matches only the sender side.
        expected = {None: 2, "all": 2, "out": 2, "in": 1}
        for direction, total in expected.items():
            params: dict = {"account": self.A}
            if direction is not None:
                params["direction"] = direction
            status, body = self.query(**params)
            self.assertEqual(status, 200, (direction, body))
            self.assertEqual(body["total"], total, direction)
            self_ids = [
                item["tx_id"]
                for item in body["items"]
                if item["from"] == item["to"] == self.A
            ]
            self.assertEqual(len(self_ids), 1, direction)
        # The other account is unaffected by the self-transfer.
        self.assertEqual(self.query(account=self.B, direction="in")[1]["total"], 1)
        self.assertEqual(self.query(account=self.B, direction="out")[1]["total"], 0)


class ExportIndexHttpTests(unittest.TestCase):
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
        # One confirmed transaction on chain, one candidate fork stored.
        rc, body = cls.request(
            "POST", "/v1/transactions", signed_tx(cls.ka, cls.A, cls.B, 7)
        )
        assert rc == 202, body
        cls.tx_id = body["tx_id"]
        assert cls.request("POST", "/v1/blocks")[0] == 201
        assert cls.request("POST", "/v1/blocks/1/confirm")[0] == 200
        genesis = cls.service.store.chain[0]
        fork_block = Block.create(
            1, genesis.block_hash, [tx_obj(cls.kb, cls.B, cls.A, 3)], "confirmed"
        )
        rc, body = cls.request(
            "POST",
            "/v1/forks/candidates",
            {"blocks": [genesis.to_dict(), fork_block.to_dict()]},
        )
        assert rc == 201, body
        cls.fork_tip = body["tip_hash"]

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

    def test_export_over_http(self) -> None:
        status, body = self.request("GET", f"/v1/forks/{self.fork_tip}/export")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tip_hash"], self.fork_tip)
        self.assertEqual(body["length"], 2)
        self.assertEqual(len(body["blocks"]), 2)
        # Resubmitting the export over HTTP is a duplicate.
        status, resub = self.request("POST", "/v1/forks/candidates", body)
        self.assertEqual(status, 409, resub)
        # Canonical tip / unknown / malformed -> 404.
        canonical_tip = self.service.store.tip_hash()
        self.assertEqual(
            self.request("GET", f"/v1/forks/{canonical_tip}/export")[0], 404
        )
        self.assertEqual(self.request("GET", f"/v1/forks/{'e' * 64}/export")[0], 404)
        self.assertEqual(self.request("GET", "/v1/forks/nothex/export")[0], 404)

    def test_index_over_http(self) -> None:
        status, body = self.request("GET", "/v1/index/transactions")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["tx_id"], self.tx_id)
        self.assertIsNone(body["next_cursor"])
        status, body = self.request(
            "GET", f"/v1/index/transactions?account={self.A}&height=1&limit=10"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(
            self.request("GET", "/v1/index/transactions?limit=0")[0], 400
        )
        self.assertEqual(
            self.request("GET", "/v1/index/transactions?cursor=2")[0], 400
        )
        self.assertEqual(
            self.request("GET", "/v1/index/transactions?tx_id=XYZ")[0], 400
        )
        self.assertEqual(
            self.request("GET", "/v1/index/transactions?height=01")[0], 400
        )

    def test_index_range_direction_over_http(self) -> None:
        status, body = self.request(
            "GET", "/v1/index/transactions?min_height=1&max_height=1"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 1)
        status, body = self.request(
            "GET", f"/v1/index/transactions?account={self.A}&direction=out"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        status, body = self.request(
            "GET", f"/v1/index/transactions?account={self.A}&direction=in"
        )
        self.assertEqual(body["total"], 0)
        # A range past the chain tip is an empty page, not an error.
        status, body = self.request("GET", "/v1/index/transactions?min_height=7")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        # Repeated legacy parameters keep the first-value-wins behaviour.
        status, body = self.request("GET", "/v1/index/transactions?height=1&height=2")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)

    def test_index_new_parameter_violations_over_http(self) -> None:
        # %D9%A3 is the Arabic-Indic digit three; %EF%BC%91%EF%BC%92 is
        # full-width "12" — both must be rejected like any malformed height.
        for query in (
            "min_height=",
            "max_height=",
            "direction=",
            "min_height=01",
            "max_height=-1",
            "min_height=+1",
            "max_height=1.0",
            "min_height=%201",
            "max_height=%D9%A3",
            "min_height=%EF%BC%91%EF%BC%92",
            "min_height=2&max_height=1",
            "direction=sideways",
            "direction=IN",
            "direction=in",
            "direction=out",
            "direction=in&account=",
            "min_height=1&min_height=1",
            "max_height=2&max_height=2",
            "direction=all&direction=all",
            "min_height=1&min_height=2",
        ):
            status, body = self.request("GET", f"/v1/index/transactions?{query}")
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "input"}, query)


class ExportIndexCliTests(unittest.TestCase):
    """The export and index CLI subcommands against a live server."""

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
        rc, _ = cls.service.submit_transaction(signed_tx(cls.ka, cls.A, cls.B, 9))
        assert rc == 202
        assert cls.service.mine_block()[0] == 201
        assert cls.service.confirm_block(1)[0] == 200
        genesis = cls.service.store.chain[0]
        fork_block = Block.create(
            1, genesis.block_hash, [tx_obj(cls.kb, cls.B, cls.A, 4)], "confirmed"
        )
        rc, body = cls.service.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), fork_block.to_dict()]}
        )
        assert rc == 201, body
        cls.fork_tip = body["tip_hash"]

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

    def test_export_cli(self) -> None:
        rc, body = self.run_cli("export", self.fork_tip)
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["tip_hash"], self.fork_tip)
        self.assertEqual(len(body["blocks"]), 2)
        # Unknown tip -> exit code 1.
        rc, body = self.run_cli("export", "f" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        # Malformed tip -> exit code 1.
        self.assertEqual(self.run_cli("export", "nope")[0], 1)

    def test_index_cli(self) -> None:
        rc, body = self.run_cli("index")
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["total"], 1)
        rc, body = self.run_cli("index", "--account", self.A, "--height", "1")
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 1)
        rc, body = self.run_cli("index", "--limit", "1", "--cursor", "1")
        self.assertEqual(rc, 0)
        self.assertEqual(body["items"], [])
        rc, body = self.run_cli("index", "--tx-id", body["items"][0]["tx_id"]
                                if body["items"] else "0" * 64)
        self.assertEqual(rc, 0)
        # Server-side validation failures exit 1.
        self.assertEqual(self.run_cli("index", "--limit", "0")[0], 1)
        self.assertEqual(self.run_cli("index", "--cursor", "99")[0], 1)
        self.assertEqual(self.run_cli("index", "--height", "01")[0], 1)
        self.assertEqual(self.run_cli("index", "--tx-id", "zz")[0], 1)

    def test_index_cli_range_direction(self) -> None:
        rc, body = self.run_cli("index", "--min-height", "1", "--max-height", "1")
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["total"], 1)
        rc, body = self.run_cli("index", "--account", self.A, "--direction", "out")
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 1)
        rc, body = self.run_cli("index", "--account", self.A, "--direction", "in")
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 0)
        # The new options combine with the legacy ones.
        rc, body = self.run_cli(
            "index", "--account", self.A, "--direction", "out",
            "--min-height", "1", "--height", "1", "--limit", "10",
        )
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 1)
        # A range past the chain tip is a successful empty page.
        rc, body = self.run_cli("index", "--min-height", "5")
        self.assertEqual(rc, 0)
        self.assertEqual(body["items"], [])
        self.assertEqual(body["total"], 0)
        # Server-side validation failures exit 1.
        self.assertEqual(self.run_cli("index", "--min-height", "01")[0], 1)
        self.assertEqual(self.run_cli("index", "--max-height", "1.5")[0], 1)
        self.assertEqual(self.run_cli("index", "--direction", "sideways")[0], 1)
        self.assertEqual(self.run_cli("index", "--direction", "in")[0], 1)
        self.assertEqual(
            self.run_cli("index", "--min-height", "2", "--max-height", "1")[0], 1
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
