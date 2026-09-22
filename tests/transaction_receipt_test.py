"""Tests for GET /v1/transactions/{tx_id} transaction receipts.

Covers the full receipt state machine:

* mempool transactions are ``pending`` with height/block_hash/index null;
* transactions packed into the unconfirmed tip are ``pending`` anchored at
  that block with their 0-based, block-order index;
* confirmed transactions are ``confirmed`` against the canonical block;
* malformed or unknown ids return 404, candidate-fork transactions are
  never exposed, rollback restores the mempool shape, and fork adoption
  makes the receipt reflect the final canonical state (old-chain-only
  transactions return to the pool) with no reads from the superseded
  chain;
* restart rebuilds every shape from canonical chain, mempool and the
  pending tail without any new authoritative copy;
* HTTP status codes/fields and the ``tx`` CLI subcommand (exit 1 on
  non-2xx) behave exactly like the service.

Run: python3 tests/transaction_receipt_test.py
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

RECEIPT_FIELDS = {
    "tx_id",
    "from",
    "to",
    "amount",
    "signature",
    "status",
    "height",
    "block_hash",
    "index",
}


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(make_tx(key, sender, to, amount))


class ReceiptServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def submit(self, amount: int = 100) -> dict:
        status, body = self.svc.submit_transaction(
            make_tx(self.ka, self.A, self.B, amount)
        )
        self.assertEqual(status, 202, body)
        return body

    def mine(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        return block

    def test_malformed_and_unknown_tx_ids_are_404(self) -> None:
        for bad in ("", "zz", "g" * 64, "A" * 63, "a" * 65, 123, None, True):
            self.assertEqual(
                self.svc.get_transaction(bad)[0],
                404,
                f"malformed id {bad!r} must be 404",
            )
        # Well-formed but never seen.
        self.assertEqual(self.svc.get_transaction("0" * 64)[0], 404)
        self.assertEqual(self.svc.get_transaction("f" * 64)[0], 404)

    def test_mempool_receipt_is_pending_with_null_anchor(self) -> None:
        body = self.submit(100)
        status, receipt = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertEqual(
            receipt,
            {
                "tx_id": body["tx_id"],
                "from": self.A,
                "to": self.B,
                "amount": 100,
                "signature": self.svc.store.pending[body["tx_id"]].signature,
                "status": "pending",
                "height": None,
                "block_hash": None,
                "index": None,
            },
        )

    def test_packed_unconfirmed_receipt_is_pending_anchored_to_tip(self) -> None:
        tx1 = self.submit(100)
        tx2 = self.submit(200)
        block = self.mine()
        ordered_ids = sorted([tx1["tx_id"], tx2["tx_id"]])
        for expected_index, tx_id in enumerate(ordered_ids):
            status, receipt = self.svc.get_transaction(tx_id)
            self.assertEqual(status, 200, receipt)
            self.assertEqual(receipt["status"], "pending")
            self.assertEqual(receipt["height"], block["height"])
            self.assertEqual(receipt["block_hash"], block["block_hash"])
            # Index matches the ascending-tx_id block order.
            self.assertEqual(receipt["index"], expected_index)
            self.assertEqual(set(receipt), RECEIPT_FIELDS)

    def test_confirmed_receipt_anchors_to_canonical_block(self) -> None:
        body = self.submit(100)
        block = self.mine()
        self.svc.confirm_block(block["height"])
        status, receipt = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["height"], block["height"])
        self.assertEqual(receipt["block_hash"], block["block_hash"])
        self.assertEqual(receipt["index"], 0)

    def test_index_matches_block_order_across_blocks(self) -> None:
        # First confirmed block with two transactions.
        first = self.submit(10)
        second = self.submit(20)
        block1 = self.mine()
        self.svc.confirm_block(block1["height"])
        # Second block left pending with one transaction.
        third = self.submit(30)
        block2 = self.mine()
        ids_block1 = sorted([first["tx_id"], second["tx_id"]])
        for index, tx_id in enumerate(ids_block1):
            _, receipt = self.svc.get_transaction(tx_id)
            self.assertEqual(receipt["status"], "confirmed")
            self.assertEqual(receipt["height"], 1)
            self.assertEqual(receipt["block_hash"], block1["block_hash"])
            self.assertEqual(receipt["index"], index)
        _, receipt = self.svc.get_transaction(third["tx_id"])
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual((receipt["height"], receipt["index"]), (2, 0))
        self.assertEqual(receipt["block_hash"], block2["block_hash"])

    def test_rollback_restores_mempool_receipt_shape(self) -> None:
        body = self.submit(100)
        block = self.mine()
        _, packed = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(packed["status"], "pending")
        self.assertEqual(packed["height"], block["height"])
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 200)
        status, receipt = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])

    def test_fork_transactions_are_not_exposed(self) -> None:
        # A transaction that exists only in a stored candidate fork must be
        # invisible even though it is a valid, signed transaction.
        genesis = self.svc.store.chain[0]
        kc, C = keypair()
        fork_block = Block.create(
            1, genesis.block_hash, [tx_obj(kc, C, self.B, 7)]
        )
        fork_tx_id = fork_block.transactions[0].tx_id
        status, _ = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), fork_block.to_dict()]}
        )
        self.assertEqual(status, 201)
        self.assertEqual(self.svc.get_transaction(fork_tx_id)[0], 404)

    def test_adoption_reattaches_receipt_to_new_canonical_block(self) -> None:
        genesis = self.svc.store.chain[0]
        kc, C = keypair()

        # Canonical block 1 carries txA (A -> B).
        tx_a = tx_obj(self.ka, self.A, self.B, 10)
        old_block = Block.create(1, genesis.block_hash, [tx_a])
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), old_block.to_dict()]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(old_block.block_hash)[0], 200)
        status, receipt = self.svc.get_transaction(tx_a.tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(
            (receipt["status"], receipt["height"], receipt["block_hash"]),
            ("confirmed", 1, old_block.block_hash),
        )

        # A longer competing fork: txC at height 1, then txA again at
        # height 2. Adoption must move txA's receipt to the new block and
        # make txC visible; nothing may be read from the old chain cache.
        fork_block1 = Block.create(1, genesis.block_hash, [tx_obj(kc, C, self.B, 7)])
        fork_block2 = Block.create(2, fork_block1.block_hash, [tx_a])
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [
                    genesis.to_dict(),
                    fork_block1.to_dict(),
                    fork_block2.to_dict(),
                ]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(fork_block2.block_hash)[0], 200)

        status, receipt = self.svc.get_transaction(tx_a.tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["height"], 2)
        self.assertEqual(receipt["block_hash"], fork_block2.block_hash)
        self.assertEqual(receipt["index"], 0)
        tx_c_id = fork_block1.transactions[0].tx_id
        status, receipt = self.svc.get_transaction(tx_c_id)
        self.assertEqual(status, 200)
        self.assertEqual(
            (receipt["status"], receipt["height"], receipt["block_hash"]),
            ("confirmed", 1, fork_block1.block_hash),
        )

    def test_adoption_returns_old_chain_only_tx_to_mempool_shape(self) -> None:
        genesis = self.svc.store.chain[0]
        kc, C = keypair()

        tx_a = tx_obj(self.ka, self.A, self.B, 10)
        old_block = Block.create(1, genesis.block_hash, [tx_a])
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), old_block.to_dict()]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(old_block.block_hash)[0], 200)

        # A strictly longer fork containing none of the old transaction.
        fork_blocks = []
        prev = genesis.block_hash
        for height in (1, 2, 3):
            block = Block.create(
                height, prev, [tx_obj(kc, C, self.B, height)]
            )
            fork_blocks.append(block)
            prev = block.block_hash
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), *[b.to_dict() for b in fork_blocks]]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(fork_blocks[-1].block_hash)[0], 200)

        # txA is old-chain-only confirmed history: back in the mempool.
        status, receipt = self.svc.get_transaction(tx_a.tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])

    def test_receipt_rebuilt_after_restart(self) -> None:
        confirmed_body = self.submit(100)
        block1 = self.mine()
        self.svc.confirm_block(block1["height"])
        pending_block_tx = self.submit(30)
        block2 = self.mine()  # stays pending across the restart
        mempool_tx = self.submit(5)

        reopened = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )

        _, receipt = reopened.get_transaction(confirmed_body["tx_id"])
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["height"], block1["height"])
        self.assertEqual(receipt["block_hash"], block1["block_hash"])
        self.assertEqual(receipt["index"], 0)

        _, receipt = reopened.get_transaction(pending_block_tx["tx_id"])
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["height"], block2["height"])
        self.assertEqual(receipt["block_hash"], block2["block_hash"])
        self.assertEqual(receipt["index"], 0)

        _, receipt = reopened.get_transaction(mempool_tx["tx_id"])
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])

        self.assertEqual(reopened.get_transaction("f" * 64)[0], 404)


class ReceiptHttpTests(unittest.TestCase):
    """GET /v1/transactions/{tx_id} over the real HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
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

    def test_receipt_endpoint_lifecycle(self) -> None:
        # Unknown but well-formed id and malformed id are both 404.
        self.assertEqual(self.request("GET", "/v1/transactions/" + "f" * 64)[0], 404)
        self.assertEqual(self.request("GET", "/v1/transactions/not-hex")[0], 404)
        self.assertEqual(self.request("GET", "/v1/transactions/")[0], 404)

        # Mempool.
        _, body = self.request(
            "POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 10)
        )
        tx_id = body["tx_id"]
        status, receipt = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertEqual(
            (receipt["status"], receipt["height"], receipt["block_hash"], receipt["index"]),
            ("pending", None, None, None),
        )

        # Packed but unconfirmed.
        _, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(block["status"], "pending")
        status, receipt = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(
            (receipt["height"], receipt["block_hash"], receipt["index"]),
            (block["height"], block["block_hash"], 0),
        )

        # Confirmed.
        self.request("POST", f"/v1/blocks/{block['height']}/confirm", {})
        status, receipt = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(
            (receipt["height"], receipt["block_hash"], receipt["index"]),
            (block["height"], block["block_hash"], 0),
        )

        # Uppercase hex of the same id is a malformed id: 404, never a match.
        self.assertEqual(
            self.request("GET", f"/v1/transactions/{tx_id.upper()}")[0], 404
        )


class ReceiptCliTests(unittest.TestCase):
    """`ledger tx TX_ID`: forwards the JSON body, exits 1 on non-2xx."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=1000
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

    def test_tx_subcommand(self) -> None:
        # Unknown id: 404 forwarded, exit 1.
        rc, body, _ = self.run_cli("tx", "f" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)

        # Malformed id: 404 forwarded, exit 1.
        rc, _, _ = self.run_cli("tx", "nope")
        self.assertEqual(rc, 1)

        self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 42))
        tx_id = next(iter(self.service.store.pending))
        rc, body, _ = self.run_cli("tx", tx_id)
        self.assertEqual(rc, 0)
        self.assertEqual(set(body), RECEIPT_FIELDS)
        self.assertEqual(body["tx_id"], tx_id)
        self.assertEqual(body["status"], "pending")
        self.assertEqual(body["amount"], 42)
        self.assertIsNone(body["height"])


if __name__ == "__main__":
    unittest.main()
