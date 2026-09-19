"""Tests for candidate-fork export and the confirmed transaction index.

Covers GET /v1/forks/{tip_hash}/export (only a stored *candidate* fork is
exportable; the canonical chain, unknown and non-64-lowercase-hex tips all
return 404; on success the response carries exactly
{tip_hash, height, length, status, blocks}, blocks include the canonical
genesis, fully signed transactions and an optional pending tip, and the
summary matches the last block) and GET /v1/index/transactions (confirmed
chain only with pending blocks excluded; tx_id/account/height filters
combined with AND; strict decimal height/limit/cursor; limit default/range;
cursor empty-page vs past-total; (height, index, tx_id) ordering with index
matching the Merkle proof index; items/total/next_cursor response shape).
Service, HTTP and CLI are all exercised.

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


def tx_dict(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(tx_dict(key, sender, to, amount))


class ExportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json"), initial_balance=1000),
            initial_balance=1000,
        )
        self.genesis = self.svc.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def submit(self, blocks: list) -> tuple[int, dict]:
        return self.svc.submit_fork_candidate(
            {"blocks": [b.to_dict() if hasattr(b, "to_dict") else b for b in blocks]}
        )

    def test_only_candidate_is_exportable(self) -> None:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        status, body = self.submit([self.genesis, block])
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]

        status, exported = self.svc.export_fork(tip)
        self.assertEqual(status, 200, exported)
        # Exactly the five descriptor fields plus blocks.
        self.assertEqual(
            set(exported), {"tip_hash", "height", "length", "status", "blocks"}
        )
        # Summary equals the last block; length includes the genesis.
        self.assertEqual(exported["tip_hash"], block.block_hash)
        self.assertEqual(exported["height"], 1)
        self.assertEqual(exported["length"], 2)
        self.assertEqual(exported["status"], "confirmed")
        self.assertEqual(exported["blocks"], [self.genesis.to_dict(), block.to_dict()])

    def test_blocks_carry_signed_transactions(self) -> None:
        tx = tx_obj(self.ka, self.A, self.B, 10)
        block = Block.create(1, self.genesis.block_hash, [tx])
        tip = self.submit([self.genesis, block])[1]["tip_hash"]
        exported = self.svc.export_fork(tip)[1]
        raw_tx = exported["blocks"][1]["transactions"][0]
        self.assertEqual(
            set(raw_tx), {"from", "to", "amount", "signature", "tx_id"}
        )
        self.assertEqual(raw_tx["tx_id"], tx.tx_id)
        self.assertTrue(raw_tx["signature"])

    def test_pending_tip_is_exported(self) -> None:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)],
            status="pending",
        )
        tip = self.submit([self.genesis, block])[1]["tip_hash"]
        exported = self.svc.export_fork(tip)[1]
        self.assertEqual(exported["status"], "pending")
        self.assertEqual(exported["blocks"][-1]["status"], "pending")

    def test_canonical_unknown_and_malformed_tip_404(self) -> None:
        # A candidate exists, but the canonical genesis/chain tip is not one.
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)]
        )
        self.assertEqual(self.submit([self.genesis, block])[0], 201)
        self.assertEqual(self.svc.export_fork(self.genesis.block_hash)[0], 404)
        # Unknown but well-formed tip hash.
        self.assertEqual(self.svc.export_fork("f" * 64)[0], 404)
        # Malformed tips.
        for bad in ("not-hex", "A" * 64, "g" * 64, "f" * 63, "", None, 123):
            self.assertEqual(self.svc.export_fork(bad)[0], 404, bad)


class TransactionIndexServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")), initial_balance=100_000
        )
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()

    def send(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(tx_dict(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine_confirmed(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        status, body = self.svc.confirm_block(block["height"])
        self.assertEqual(status, 200, body)
        return block

    def test_empty_index_genesis_only(self) -> None:
        status, body = self.svc.get_transaction_index({})
        self.assertEqual(status, 200)
        self.assertEqual(body, {"items": [], "total": 0, "next_cursor": None})

    def test_ordering_fields_and_proof_index_consistency(self) -> None:
        ids = [
            self.send(self.ka, self.A, self.B, 10),
            self.send(self.ka, self.A, self.C, 5),
            self.send(self.kb, self.B, self.A, 2),
        ]
        block1 = self.mine_confirmed()  # height 1, three txs
        self.send(self.ka, self.A, self.B, 1)
        block2 = self.mine_confirmed()  # height 2

        status, body = self.svc.get_transaction_index({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 4)
        keys = [(it["height"], it["index"], it["tx_id"]) for it in body["items"]]
        self.assertEqual(keys, sorted(keys))
        # Items expose exactly the documented fields.
        for item in body["items"]:
            self.assertEqual(
                set(item),
                {"tx_id", "height", "block_hash", "index", "from", "to", "amount"},
            )
        # Block 1's in-block index is 0-based ascending tx_id.
        b1_items = [it for it in body["items"] if it["height"] == 1]
        self.assertEqual([it["tx_id"] for it in b1_items], sorted(ids))
        self.assertEqual([it["index"] for it in b1_items], [0, 1, 2])
        self.assertTrue(all(it["block_hash"] == block1["block_hash"] for it in b1_items))
        b2 = [it for it in body["items"] if it["height"] == 2][0]
        self.assertEqual((b2["index"], b2["block_hash"]), (0, block2["block_hash"]))

        # The index must agree with the Merkle proof index for every tx.
        for item in b1_items:
            status, proof = self.svc.get_proof(1, item["tx_id"])
            self.assertEqual(status, 200)
            self.assertEqual(proof["index"], item["index"])

    def test_pending_block_excluded(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_confirmed()
        self.send(self.kb, self.B, self.A, 2)
        status, _ = self.svc.mine_block()  # left pending
        self.assertEqual(status, 201)
        status, body = self.svc.get_transaction_index({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertTrue(all(it["height"] == 1 for it in body["items"]))

    def test_filters_combined_with_and(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.send(self.ka, self.A, self.C, 5)
        self.mine_confirmed()

        self.assertEqual(
            self.svc.get_transaction_index({"tx_id": "f" * 64})[1]["total"], 0
        )
        tx_id = self.svc.get_transaction_index({"account": self.C})[1]["items"][0]["tx_id"]
        status, body = self.svc.get_transaction_index({"tx_id": tx_id, "account": self.C})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        # Same tx but an unrelated account: AND yields nothing.
        status, body = self.svc.get_transaction_index({"tx_id": tx_id, "account": self.B})
        self.assertEqual(body["total"], 0)
        # account matches from OR to.
        self.assertEqual(
            self.svc.get_transaction_index({"account": self.A})[1]["total"], 2
        )
        self.assertEqual(
            self.svc.get_transaction_index({"account": self.B})[1]["total"], 1
        )
        # height + account.
        status, body = self.svc.get_transaction_index({"height": "1", "account": self.A})
        self.assertEqual(body["total"], 2)
        status, body = self.svc.get_transaction_index({"height": "9", "account": self.A})
        self.assertEqual(body["total"], 0)

    def test_invalid_parameters_400(self) -> None:
        q = self.svc.get_transaction_index
        for bad in ("zzz", "A" * 64, "g" * 64, "f" * 63):
            self.assertEqual(q({"tx_id": bad})[0], 400, bad)
        for bad in ("-1", "01", "1.0", "+1", "x", "", " 1"):
            self.assertEqual(q({"height": bad})[0], 400, ("height", bad))
            self.assertEqual(q({"cursor": bad})[0], 400, ("cursor", bad))
        for bad in ("0", "201", "-1", "01", "x", ""):
            self.assertEqual(q({"limit": bad})[0], 400, ("limit", bad))
        self.assertEqual(q({"account": ""})[0], 400)

    def test_limit_default_range_and_pagination(self) -> None:
        for i in range(5):
            self.send(self.ka, self.A, self.B, i + 1)
        self.mine_confirmed()
        # Default limit 50 returns everything in one page.
        body = self.svc.get_transaction_index({})[1]
        self.assertEqual(body["total"], 5)
        self.assertEqual(len(body["items"]), 5)
        self.assertIsNone(body["next_cursor"])

        # limit 2 walks three pages; next_cursor is the filtered offset.
        p0 = self.svc.get_transaction_index({"limit": "2"})[1]
        self.assertEqual(len(p0["items"]), 2)
        self.assertEqual(p0["next_cursor"], 2)
        p1 = self.svc.get_transaction_index({"limit": "2", "cursor": "2"})[1]
        self.assertEqual(len(p1["items"]), 2)
        self.assertEqual(p1["next_cursor"], 4)
        p2 = self.svc.get_transaction_index({"limit": "2", "cursor": "4"})[1]
        self.assertEqual(len(p2["items"]), 1)
        self.assertIsNone(p2["next_cursor"])
        # The pages concatenate back into the full ordering.
        full = p0["items"] + p1["items"] + p2["items"]
        self.assertEqual([it["tx_id"] for it in full], [it["tx_id"] for it in body["items"]])

        # Boundaries: limit 1 and 200 are accepted.
        self.assertEqual(self.svc.get_transaction_index({"limit": "1"})[0], 200)
        self.assertEqual(self.svc.get_transaction_index({"limit": "200"})[0], 200)

        # cursor == total is a valid empty trailing page; cursor > total is 400.
        last = self.svc.get_transaction_index({"cursor": "5"})[1]
        self.assertEqual(last["items"], [])
        self.assertEqual(last["total"], 5)
        self.assertIsNone(last["next_cursor"])
        self.assertEqual(self.svc.get_transaction_index({"cursor": "6"})[0], 400)


class ExportIndexHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=100_000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def request(self, method: str, path: str, payload=None):
        url = f"{self.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_export_and_index_over_http(self) -> None:
        # One confirmed transaction.
        self.assertEqual(
            self.request("POST", "/v1/transactions", tx_dict(self.ka, self.A, self.B, 10))[0],
            202,
        )
        block = self.request("POST", "/v1/blocks", {})[1]
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{block['height']}/confirm", {})[0], 200
        )

        # Submit a candidate fork, then export it.
        genesis = self.service.store.chain[0]
        fork_block = Block.create(
            1, genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 99)]
        )
        status, candidate = self.request(
            "POST",
            "/v1/forks/candidates",
            {"blocks": [genesis.to_dict(), fork_block.to_dict()]},
        )
        self.assertEqual(status, 201, candidate)
        tip = candidate["tip_hash"]

        status, exported = self.request("GET", f"/v1/forks/{tip}/export")
        self.assertEqual(status, 200)
        self.assertEqual(exported["length"], 2)
        self.assertEqual(exported["blocks"][-1]["block_hash"], fork_block.block_hash)

        # 404s.
        self.assertEqual(
            self.request("GET", f"/v1/forks/{genesis.block_hash}/export")[0], 404
        )
        self.assertEqual(self.request("GET", "/v1/forks/nothex/export")[0], 404)

        # Index: the one confirmed tx.
        status, body = self.request("GET", "/v1/index/transactions")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["from"], self.A)
        self.assertEqual(body["items"][0]["to"], self.B)
        # Malformed query parameters are 400.
        self.assertEqual(
            self.request("GET", "/v1/index/transactions?limit=0")[0], 400
        )
        self.assertEqual(
            self.request("GET", "/v1/index/transactions?height=01")[0], 400
        )
        self.assertEqual(
            self.request("GET", "/v1/index/transactions?cursor=99")[0], 400
        )


class ExportIndexCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=100_000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, dict, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw), raw

    def test_export_and_index_cli(self) -> None:
        self.service.submit_transaction(tx_dict(self.ka, self.A, self.B, 10))
        block = self.service.mine_block()[1]
        self.service.confirm_block(block["height"])

        genesis = self.service.store.chain[0]
        fork_block = Block.create(
            1, genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 42)]
        )
        tip = self.service.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), fork_block.to_dict()]}
        )[1]["tip_hash"]

        rc, exported, _ = self.run_cli("export", tip)
        self.assertEqual(rc, 0)
        self.assertEqual(exported["tip_hash"], tip)
        self.assertEqual(len(exported["blocks"]), 2)

        # Non-2xx prints JSON and exits 1.
        rc, body, _ = self.run_cli("export", genesis.block_hash)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)

        rc, body, _ = self.run_cli("index")
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 1)

        rc, body, _ = self.run_cli("index", "--account", self.A, "--limit", "1")
        self.assertEqual(rc, 0)
        self.assertEqual(len(body["items"]), 1)

        rc, _, _ = self.run_cli("index", "--limit", "0")
        self.assertEqual(rc, 1)
        rc, _, _ = self.run_cli("index", "--cursor", "99")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
