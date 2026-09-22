"""Tests for GET /v1/transactions/{tx_id} transaction receipts.

Covers the fixed nine-field receipt shape; mempool transactions reported
pending with null height/block_hash/index; packed-but-unconfirmed tip
transactions reported pending against the pending block; confirmed
transactions anchored to canonical confirmed blocks; the 0-based in-block
index following block order; 404 for malformed (not 64 lowercase hex) and
unknown ids; rollback restoring the mempool receipt form; fork transactions
never exposed while the fork is a mere candidate; adoption making an
included tx reflect the new canonical block while an old-chain-only tx
returns to the pool (no stale-chain read); restart rebuilding receipts from
canonical, pending and the pending tip; HTTP status/field behaviour; and the
``ledger tx`` CLI forwarding JSON with exit code 1 on non-2xx.

Run: python3 tests/transaction_receipt_test.py
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
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
    "tx_id", "from", "to", "amount", "signature",
    "status", "height", "block_hash", "index",
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
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()

    # -- lookup plumbing -----------------------------------------------------

    def test_malformed_tx_id_is_404(self):
        for bad in ("", "abc", "A" * 64, "g" * 64, "0" * 63, "0" * 65, 123, None):
            self.assertEqual(
                self.svc.get_transaction_receipt(bad)[0], 404, repr(bad)
            )

    def test_unknown_well_formed_tx_id_is_404(self):
        self.assertEqual(self.svc.get_transaction_receipt("f" * 64)[0], 404)

    # -- lifecycle -----------------------------------------------------------

    def _submit(self, key, sender, to, amount):
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"], make_tx(key, sender, to, amount)

    def test_mempool_tx_is_pending_with_null_anchor(self):
        tx_id, raw = self._submit(self.ka, self.A, self.B, 10)
        status, receipt = self.svc.get_transaction_receipt(tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertEqual(
            receipt,
            {
                "tx_id": tx_id,
                "from": self.A,
                "to": self.B,
                "amount": 10,
                "signature": raw["signature"],
                "status": "pending",
                "height": None,
                "block_hash": None,
                "index": None,
            },
        )

    def test_tx_id_is_recomputed_from_signed_transaction(self):
        _, raw = self._submit(self.ka, self.A, self.B, 10)
        expected = crypto.compute_tx_id(
            crypto.canonical_message(self.A, self.B, 10)
        )
        status, receipt = self.svc.get_transaction_receipt(expected)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["tx_id"], expected)
        self.assertEqual(receipt["signature"], raw["signature"])

    def test_pending_tip_tx_is_pending_against_the_block(self):
        t1, _ = self._submit(self.ka, self.A, self.B, 10)
        t2, _ = self._submit(self.ka, self.A, self.C, 5)
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201)
        ordered = sorted([t1, t2])
        for index, tx_id in enumerate(ordered):
            status, receipt = self.svc.get_transaction_receipt(tx_id)
            self.assertEqual(status, 200, receipt)
            self.assertEqual(receipt["status"], "pending")
            self.assertEqual(receipt["height"], block["height"])
            self.assertEqual(receipt["block_hash"], block["block_hash"])
            self.assertEqual(receipt["index"], index)
        # The index follows the block's ascending tx_id order.
        r0 = self.svc.get_transaction_receipt(ordered[0])[1]
        r1 = self.svc.get_transaction_receipt(ordered[1])[1]
        self.assertEqual((r0["index"], r1["index"]), (0, 1))

    def test_confirmed_tx_is_confirmed_and_anchored(self):
        tx_id, _ = self._submit(self.ka, self.A, self.B, 10)
        _, block = self.svc.mine_block()
        self.assertEqual(self.svc.confirm_block(block["height"])[0], 200)
        status, receipt = self.svc.get_transaction_receipt(tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(
            receipt,
            {
                "tx_id": tx_id,
                "from": self.A,
                "to": self.B,
                "amount": 10,
                "signature": receipt["signature"],
                "status": "confirmed",
                "height": 1,
                "block_hash": block["block_hash"],
                "index": 0,
            },
        )

    def test_rollback_restores_mempool_receipt(self):
        tx_id, _ = self._submit(self.ka, self.A, self.B, 10)
        _, block = self.svc.mine_block()
        # Packed but unconfirmed: anchored pending receipt.
        receipt = self.svc.get_transaction_receipt(tx_id)[1]
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["height"], block["height"])
        self.assertEqual(receipt["index"], 0)
        # Roll back: the transaction is back in the mempool receipt form.
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 200)
        status, receipt = self.svc.get_transaction_receipt(tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])

    # -- forks ---------------------------------------------------------------

    def _canonical_block_one(self):
        canon_tx = tx_obj(self.ka, self.A, self.B, 10)
        c1 = Block.create(1, self.genesis.block_hash, [canon_tx])
        self.store.chain.append(c1)
        self.store.rebuild_derived()
        self.store.save()
        return canon_tx, c1

    def test_fork_only_tx_is_not_exposed_while_candidate(self):
        canon_tx, _ = self._canonical_block_one()
        gen = self.store.chain[0]
        # A two-block fork (strictly longer, so it wins) with its own txs.
        f1 = Block.create(1, gen.block_hash, [tx_obj(self.ka, self.A, self.C, 20)])
        f2 = Block.create(2, f1.block_hash, [tx_obj(self.kc, self.C, self.A, 1)])
        status, body = self.svc.submit_fork_candidate(
            {"blocks": [gen.to_dict(), f1.to_dict(), f2.to_dict()]}
        )
        self.assertEqual(status, 201, body)
        # The fork's transactions must not be visible while it is a candidate.
        for block in (f1, f2):
            for tx in block.transactions:
                self.assertEqual(
                    self.svc.get_transaction_receipt(tx.tx_id)[0], 404
                )
        # The canonical transaction is still reported from canonical chain.
        receipt = self.svc.get_transaction_receipt(canon_tx.tx_id)[1]
        self.assertEqual(receipt["status"], "confirmed")

    def test_adoption_old_chain_only_tx_returns_to_pool(self):
        canon_tx, c1 = self._canonical_block_one()
        gen = self.store.chain[0]
        f1 = Block.create(1, gen.block_hash, [tx_obj(self.ka, self.A, self.C, 20)])
        f2 = Block.create(2, f1.block_hash, [tx_obj(self.kc, self.C, self.A, 1)])
        tip = self.svc.submit_fork_candidate(
            {"blocks": [gen.to_dict(), f1.to_dict(), f2.to_dict()]}
        )[1]["tip_hash"]
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)
        # Old-chain-only confirmed tx is back in the mempool: its receipt is
        # pending with null anchors, never read from the superseded chain.
        status, receipt = self.svc.get_transaction_receipt(canon_tx.tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])
        # The new chain's tx is confirmed and anchored to its own block.
        new_tx = f1.transactions[0]
        status, receipt = self.svc.get_transaction_receipt(new_tx.tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["height"], 1)
        self.assertEqual(receipt["block_hash"], f1.block_hash)
        self.assertEqual(receipt["index"], 0)

    def test_adoption_tx_included_by_new_chain_reflects_final_state(self):
        canon_tx, c1 = self._canonical_block_one()
        gen = self.store.chain[0]
        # New f1 contains the same signed transaction plus another one, so its
        # block hash differs from the old canonical block 1; f2 makes it win.
        extra = tx_obj(self.ka, self.A, self.C, 2)
        f1 = Block.create(1, gen.block_hash, [canon_tx, extra])
        f2 = Block.create(2, f1.block_hash, [tx_obj(self.kc, self.C, self.A, 1)])
        tip = self.svc.submit_fork_candidate(
            {"blocks": [gen.to_dict(), f1.to_dict(), f2.to_dict()]}
        )[1]["tip_hash"]
        # Before adoption the receipt still anchors the old canonical block.
        before = self.svc.get_transaction_receipt(canon_tx.tx_id)[1]
        self.assertEqual(before["block_hash"], c1.block_hash)
        self.assertEqual(before["index"], 0)
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)
        # After adoption the receipt reflects the new canonical block, not any
        # cached view of the old chain.
        after = self.svc.get_transaction_receipt(canon_tx.tx_id)[1]
        self.assertEqual(after["status"], "confirmed")
        self.assertEqual(after["block_hash"], f1.block_hash)
        self.assertEqual(after["height"], 1)
        # canon_tx is the smaller/larger of the pair per ascending tx_id.
        expected_index = sorted([t.tx_id for t in f1.transactions]).index(
            canon_tx.tx_id
        )
        self.assertEqual(after["index"], expected_index)

    # -- restart -------------------------------------------------------------

    def test_restart_rebuilds_confirmed_and_mempool_receipts(self):
        tx_id, _ = self._submit(self.ka, self.A, self.B, 10)
        _, block = self.svc.mine_block()
        self.svc.confirm_block(block["height"])
        pending_id, _ = self._submit(self.ka, self.A, self.C, 3)
        reopened = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        confirmed = reopened.get_transaction_receipt(tx_id)[1]
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["block_hash"], block["block_hash"])
        pending = reopened.get_transaction_receipt(pending_id)[1]
        self.assertEqual(pending["status"], "pending")
        self.assertIsNone(pending["height"])
        self.assertEqual(reopened.get_transaction_receipt("e" * 64)[0], 404)

    def test_restart_rebuilds_pending_tip_receipt(self):
        tx_id, _ = self._submit(self.ka, self.A, self.B, 10)
        _, block = self.svc.mine_block()  # left pending
        reopened = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        status, receipt = reopened.get_transaction_receipt(tx_id)
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["height"], block["height"])
        self.assertEqual(receipt["block_hash"], block["block_hash"])
        self.assertEqual(receipt["index"], 0)


class ReceiptHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000), initial_balance=1000
        )
        cls.key = Ed25519PrivateKey.generate()
        cls.sender = cls.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        msg = crypto.canonical_message(cls.sender, "bob", 42)
        cls.payload = {
            "from": cls.sender,
            "to": "bob",
            "amount": 42,
            "signature": cls.key.sign(msg).hex(),
        }
        _, body = cls.svc.submit_transaction(cls.payload)
        cls.tx_id = body["tx_id"]
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.svc))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _get(self, path):
        url = f"http://127.0.0.1:{self.port}{path}"
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_pending_receipt_over_http(self):
        status, body = self._get(f"/v1/transactions/{self.tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(set(body), RECEIPT_FIELDS)
        self.assertEqual(body["tx_id"], self.tx_id)
        self.assertEqual(body["status"], "pending")
        self.assertIsNone(body["height"])
        self.assertEqual(body["amount"], 42)

    def test_malformed_and_unknown_are_404(self):
        self.assertEqual(self._get("/v1/transactions/zzz")[0], 404)
        self.assertEqual(self._get(f"/v1/transactions/{'A' * 64}")[0], 404)
        self.assertEqual(self._get(f"/v1/transactions/{'0' * 64}")[0], 404)
        self.assertEqual(self._get("/v1/transactions/")[0], 404)


class ReceiptCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.svc))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli_main(["--base-url", self.base, *argv])
        return code, out.getvalue()

    def test_cli_tx_forwards_json_success(self):
        code, output = self._run_cli("tx", "f" * 64)
        # Unknown well-formed id is a 404 -> CLI prints JSON and exits 1.
        self.assertEqual(code, 1)
        body = json.loads(output)
        self.assertIn("error", body)

    def test_cli_tx_success_exit_zero(self):
        # Submit via the service, then fetch through the CLI.
        key = Ed25519PrivateKey.generate()
        sender = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        msg = crypto.canonical_message(sender, "carol", 7)
        payload = {
            "from": sender, "to": "carol", "amount": 7,
            "signature": key.sign(msg).hex(),
        }
        _, body = self.svc.submit_transaction(payload)
        code, output = self._run_cli("tx", body["tx_id"])
        self.assertEqual(code, 0, output)
        receipt = json.loads(output)
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertEqual(receipt["tx_id"], body["tx_id"])
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["amount"], 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
