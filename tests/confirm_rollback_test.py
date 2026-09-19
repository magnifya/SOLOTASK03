"""Tests for the confirm/rollback block state machine.

Covers the pending/confirmed lifecycle end to end: mining gating, the
status/confirm/rollback endpoints, account balances that only count
confirmed blocks (pending spends deducted, pending credits ignored),
Merkle proofs refusing pending blocks, rollback restoring transactions
de-duplicated, deterministic re-mining, and restart index rebuilds.

Run: python3 tests/confirm_rollback_test.py
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

from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore
from ledger import crypto


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


class StateMachineServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.state_path), initial_balance=1000)

    def submit(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        return block

    def test_genesis_is_confirmed(self) -> None:
        status, genesis = self.svc.get_block(0)
        self.assertEqual(status, 200)
        self.assertEqual(genesis["status"], "confirmed")
        self.assertEqual(self.svc.get_block_status(0), (200, {"height": 0, "status": "confirmed"}))

    def test_mine_creates_pending_block_and_gates_on_tip(self) -> None:
        self.assertEqual(self.svc.mine_block()[0], 409)  # empty mempool
        tx_id = self.submit(self.ka, self.A, self.B, 100)
        block = self.mine()
        self.assertEqual(block["status"], "pending")
        self.assertEqual(set(block), {"height", "block_hash", "merkle_root", "status"})
        # Tip is pending: mining again is refused even with a fresh mempool tx.
        self.submit(self.ka, self.A, self.B, 5)
        self.assertEqual(self.svc.mine_block()[0], 409)
        # Block query exposes the status.
        _, summary = self.svc.get_block(block["height"])
        self.assertEqual(summary["status"], "pending")
        self.assertEqual(summary["transaction_ids"], [tx_id])
        self.assertEqual(
            self.svc.get_block_status(block["height"]),
            (200, {"height": block["height"], "status": "pending"}),
        )

    def test_get_block_status_unknown_height(self) -> None:
        self.assertEqual(self.svc.get_block_status(7)[0], 404)
        self.assertEqual(self.svc.get_block_status("nope")[0], 404)
        self.assertEqual(self.svc.get_block_status(-1)[0], 404)

    def test_pending_block_proof_is_409(self) -> None:
        tx_id = self.submit(self.ka, self.A, self.B, 100)
        block = self.mine()
        self.assertEqual(self.svc.get_proof(block["height"], tx_id)[0], 409)
        self.svc.confirm_block(block["height"])
        self.assertEqual(self.svc.get_proof(block["height"], tx_id)[0], 200)

    def test_accounts_count_confirmed_only(self) -> None:
        self.submit(self.ka, self.A, self.B, 100)
        block = self.mine()
        # Neither side is queryable while the only block is pending.
        self.assertEqual(self.svc.get_account(self.A)[0], 404)
        self.assertEqual(self.svc.get_account(self.B)[0], 404)
        self.svc.confirm_block(block["height"])
        _, acc_a = self.svc.get_account(self.A)
        _, acc_b = self.svc.get_account(self.B)
        self.assertEqual(acc_a["balance"], 900)
        self.assertEqual(acc_b["balance"], 1100)

        # A pending tip: spends are deducted from the reported balance,
        # pending income is not credited.
        self.submit(self.ka, self.A, self.B, 50)
        self.submit(self.kb, self.B, self.A, 20)
        self.mine()
        _, acc_a = self.svc.get_account(self.A)
        _, acc_b = self.svc.get_account(self.B)
        self.assertEqual(acc_a["balance"], 900 - 50)   # spend deducted, income ignored
        self.assertEqual(acc_b["balance"], 1100 - 20)  # spend deducted, income ignored
        # confirmed_transactions only lists confirmed txs.
        self.assertEqual(len(acc_a["confirmed_transactions"]), 1)

    def test_confirm_happy_path_and_idempotence(self) -> None:
        self.submit(self.ka, self.A, self.B, 100)
        block = self.mine()
        status, body = self.svc.confirm_block(block["height"])
        self.assertEqual(status, 200)
        self.assertEqual(body, {"height": block["height"], "status": "confirmed"})
        # Repeat confirm is idempotent.
        self.assertEqual(self.svc.confirm_block(block["height"])[0], 200)
        self.assertEqual(
            self.svc.get_block_status(block["height"]),
            (200, {"height": block["height"], "status": "confirmed"}),
        )

    def test_confirm_rejections(self) -> None:
        # Unknown heights and malformed input: 409.
        self.assertEqual(self.svc.confirm_block(3)[0], 409)
        self.assertEqual(self.svc.confirm_block("x")[0], 409)
        self.assertEqual(self.svc.confirm_block(-1)[0], 409)
        # Genesis is already confirmed -> idempotent 200, never an error.
        self.assertEqual(self.svc.confirm_block(0)[0], 200)

    def test_rollback_restores_transactions_deduped(self) -> None:
        tx1 = self.submit(self.ka, self.A, self.B, 100)
        tx2 = self.submit(self.ka, self.A, self.B, 200)
        block = self.mine()
        height = block["height"]
        # Mempool is empty after mining; rollback restores both txs.
        self.assertEqual(self.svc.store.pending, {})
        status, body = self.svc.rollback_block(height)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"height": height, "status": "rolled_back"})
        self.assertEqual(set(self.svc.store.pending), {tx1, tx2})
        # Block is gone.
        self.assertEqual(self.svc.get_block(height)[0], 404)
        self.assertEqual(self.svc.get_block_status(height)[0], 404)
        # Repeat rollback of the same height: 404.
        self.assertEqual(self.svc.rollback_block(height)[0], 404)

    def test_rollback_dedupes_against_resubmitted_mempool(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 100)
        _, body = self.svc.submit_transaction(payload)
        tx_id = body["tx_id"]
        block = self.mine()
        # Resubmitting while the tx sits in a pending block is a conflict...
        self.assertEqual(self.svc.submit_transaction(payload)[0], 409)
        # ...so pre-seed the mempool with the same id directly to prove the
        # restore path de-duplicates instead of overwriting.
        from ledger.models import Transaction
        self.svc.store.pending[tx_id] = Transaction(
            payload["from"], payload["to"], payload["amount"], payload["signature"]
        )
        self.svc.rollback_block(block["height"])
        self.assertEqual(list(self.svc.store.pending), [tx_id])

    def test_rollback_rejections(self) -> None:
        # Unknown / malformed heights: 404.
        self.assertEqual(self.svc.rollback_block(9)[0], 404)
        self.assertEqual(self.svc.rollback_block("x")[0], 404)
        # Confirmed block (genesis): 409.
        self.assertEqual(self.svc.rollback_block(0)[0], 409)
        # Confirm a mined block, then rollback must be 409.
        self.submit(self.ka, self.A, self.B, 10)
        block = self.mine()
        self.svc.confirm_block(block["height"])
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 409)

    def test_remining_after_rollback_is_deterministic(self) -> None:
        self.submit(self.ka, self.A, self.B, 100)
        self.submit(self.kb, self.B, self.A, 40)
        first = self.mine()
        self.svc.rollback_block(first["height"])
        second = self.mine()
        self.assertEqual(first["block_hash"], second["block_hash"])
        self.assertEqual(first["merkle_root"], second["merkle_root"])
        self.assertEqual(first["height"], second["height"])

    def test_state_file_is_atomic_and_complete(self) -> None:
        tx_id = self.submit(self.ka, self.A, self.B, 100)
        block = self.mine()
        self.svc.confirm_block(block["height"])
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(
            set(data), {"state", "chain", "pending", "index", "accounts"}
        )
        self.assertEqual(data["state"]["tip_status"], "confirmed")
        self.assertEqual(data["chain"][1]["status"], "confirmed")
        self.assertEqual(data["index"], {tx_id: block["height"]})
        self.assertEqual(data["pending"], [])
        self.assertIn(self.A, data["accounts"])
        # No temp files left behind by the atomic write.
        self.assertEqual(
            [n for n in os.listdir(self.tmp) if n.startswith(".ledger-")], []
        )

    def test_restart_rebuilds_index_excluding_pending(self) -> None:
        tx1 = self.submit(self.ka, self.A, self.B, 100)
        block1 = self.mine()
        self.svc.confirm_block(block1["height"])
        tx2 = self.submit(self.ka, self.A, self.B, 30)
        block2 = self.mine()  # left pending across the restart

        svc2 = LedgerService(LedgerStore(self.state_path), initial_balance=1000)
        # Index only covers the confirmed block.
        self.assertEqual(svc2.store.tx_index, {tx1: block1["height"]})
        self.assertNotIn(tx2, svc2.store.tx_index)
        # Balances ignore the pending block's income but deduct its spend.
        _, acc_a = svc2.get_account(self.A)
        self.assertEqual(acc_a["balance"], 900 - 30)
        _, acc_b = svc2.get_account(self.B)
        self.assertEqual(acc_b["balance"], 1100)
        # The pending block itself survived the restart as pending.
        self.assertEqual(
            svc2.get_block_status(block2["height"]),
            (200, {"height": block2["height"], "status": "pending"}),
        )
        # Confirming after restart works and updates the index.
        svc2.confirm_block(block2["height"])
        svc3 = LedgerService(LedgerStore(self.state_path), initial_balance=1000)
        self.assertEqual(
            svc3.store.tx_index, {tx1: block1["height"], tx2: block2["height"]}
        )

    def test_restart_rejects_orphan_chain(self) -> None:
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["chain"].append(
            {
                "height": 1,
                "prev_hash": "f" * 64,  # does not match the genesis hash
                "merkle_root": "0" * 64,
                "block_hash": "e" * 64,
                "status": "confirmed",
                "transactions": [],
            }
        )
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(ValueError):
            LedgerStore(self.state_path)


class StateMachineHttpTests(unittest.TestCase):
    """The three new endpoints over the real HTTP server."""

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

    def test_status_confirm_rollback_endpoints(self) -> None:
        # Genesis status over HTTP.
        status, body = self.request("GET", "/v1/blocks/0/status")
        self.assertEqual((status, body), (200, {"height": 0, "status": "confirmed"}))
        self.assertEqual(self.request("GET", "/v1/blocks/42/status")[0], 404)

        # Mine a pending block.
        self.request("POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 10))
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        self.assertEqual(block["status"], "pending")
        height = block["height"]

        status, body = self.request("GET", f"/v1/blocks/{height}/status")
        self.assertEqual((status, body), (200, {"height": height, "status": "pending"}))
        # Proof on the pending block is refused.
        tx_id = self.service.store.chain[height].transactions[0].tx_id
        self.assertEqual(
            self.request("GET", f"/v1/blocks/{height}/proof/{tx_id}")[0], 409
        )

        # Roll back over HTTP, then re-mine and confirm over HTTP.
        status, body = self.request("POST", f"/v1/blocks/{height}/rollback", {})
        self.assertEqual((status, body), (200, {"height": height, "status": "rolled_back"}))
        self.assertEqual(self.request("POST", f"/v1/blocks/{height}/rollback", {})[0], 404)
        status, block2 = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        self.assertEqual(block2["block_hash"], block["block_hash"])  # deterministic
        status, body = self.request("POST", f"/v1/blocks/{height}/confirm", {})
        self.assertEqual((status, body), (200, {"height": height, "status": "confirmed"}))
        # Idempotent confirm and proof now available.
        self.assertEqual(self.request("POST", f"/v1/blocks/{height}/confirm", {})[0], 200)
        self.assertEqual(
            self.request("GET", f"/v1/blocks/{height}/proof/{tx_id}")[0], 200
        )
        # Confirmed block cannot roll back; unknown confirm is 409.
        self.assertEqual(self.request("POST", f"/v1/blocks/{height}/rollback", {})[0], 409)
        self.assertEqual(self.request("POST", "/v1/blocks/99/confirm", {})[0], 409)


class StateMachineCliTests(unittest.TestCase):
    """confirm/rollback/status subcommands: one JSON line, exit 1 on non-2xx."""

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

    def test_confirm_rollback_status_cli(self) -> None:
        self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 10))
        _, block = self.service.mine_block()
        height = str(block["height"])

        rc, body, _ = self.run_cli("status", height)
        self.assertEqual(rc, 0)
        self.assertEqual(body, {"height": int(height), "status": "pending"})

        rc, body, _ = self.run_cli("confirm", height)
        self.assertEqual(rc, 0)
        self.assertEqual(body["status"], "confirmed")
        # Idempotent: confirming again still exits 0.
        rc, _, _ = self.run_cli("confirm", height)
        self.assertEqual(rc, 0)
        # Rolling back a confirmed block exits 1 with a JSON error.
        rc, body, _ = self.run_cli("rollback", height)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)

        # Mine again, roll back via CLI, check status is 404 afterwards.
        self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 5))
        _, block2 = self.service.mine_block()
        height2 = str(block2["height"])
        rc, body, _ = self.run_cli("rollback", height2)
        self.assertEqual(rc, 0)
        self.assertEqual(body, {"height": int(height2), "status": "rolled_back"})
        rc, body, _ = self.run_cli("status", height2)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        # Unknown heights: confirm -> 409 -> exit 1, rollback -> 404 -> exit 1.
        self.assertEqual(self.run_cli("confirm", "999")[0], 1)
        self.assertEqual(self.run_cli("rollback", "999")[0], 1)


if __name__ == "__main__":
    unittest.main()
