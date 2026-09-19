"""Tests for confirmed-transaction Merkle proofs.

Covers crypto.merkle_proof / verify_merkle_proof, the service proof lookup,
the HTTP route, and the CLI proof/account subcommands. The four pre-existing
interfaces (submit, mine, block, account) are exercised for regressions.

Run: python3 tests/merkle_proof_test.py
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
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def h(s: str) -> str:
    return crypto.sha256_hex(s.encode())


class MerkleProofCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.block_hash = h("block")

    def test_empty_tree(self) -> None:
        # Empty list: fixed root, and no proof can be built.
        self.assertEqual(crypto.merkle_root([]), crypto.EMPTY_MERKLE_ROOT)
        with self.assertRaises(ValueError):
            crypto.merkle_proof([], 0)

    def test_single_transaction(self) -> None:
        tx_ids = [h("only")]
        # One leaf: the leaf is the root and the sibling path is empty.
        self.assertEqual(crypto.merkle_root(tx_ids), tx_ids[0])
        siblings = crypto.merkle_proof(tx_ids, 0)
        self.assertEqual(siblings, [])
        self.assertTrue(
            crypto.verify_merkle_proof(
                tx_ids[0], siblings, tx_ids[0], self.block_hash, self.block_hash
            )
        )

    def test_zero_one_and_many_transactions(self) -> None:
        for n in (1, 2, 3, 4, 5, 6, 7, 8, 9):
            tx_ids = [h(f"tx-{n}-{i}") for i in range(n)]
            root = crypto.merkle_root(tx_ids)
            for index in range(n):
                siblings = crypto.merkle_proof(tx_ids, index)
                # Leaf-to-root order; depth is consistent with tree shape.
                self.assertTrue(all(
                    item["direction"] in ("left", "right")
                    and crypto.is_hex64(item["hash"])
                    for item in siblings
                ))
                self.assertTrue(
                    crypto.verify_merkle_proof(
                        tx_ids[index], siblings, root, self.block_hash, self.block_hash
                    ),
                    (n, index),
                )
                # Recomputing by hand must agree with the service root.
                current = tx_ids[index]
                for item in siblings:
                    if item["direction"] == "left":
                        current = h(item["hash"] + current)
                    else:
                        current = h(current + item["hash"])
                self.assertEqual(current, root)

    def test_odd_level_paired_with_itself(self) -> None:
        # 3 leaves: the rightmost node pairs with itself; the proof for
        # index 2 starts with a right sibling equal to the leaf hash itself.
        tx_ids = [h("a"), h("b"), h("c")]
        siblings = crypto.merkle_proof(tx_ids, 2)
        self.assertEqual(siblings[0], {"direction": "right", "hash": h("c")})
        root = crypto.merkle_root(tx_ids)
        self.assertTrue(
            crypto.verify_merkle_proof(h("c"), siblings, root, self.block_hash, self.block_hash)
        )

    def test_wrong_root_and_block_hash(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        root = crypto.merkle_root(tx_ids)
        siblings = crypto.merkle_proof(tx_ids, 1)
        good = self.block_hash
        self.assertFalse(
            crypto.verify_merkle_proof(tx_ids[1], siblings, h("other-root"), good, good)
        )
        self.assertFalse(
            crypto.verify_merkle_proof(tx_ids[1], siblings, root, good, h("other-block"))
        )
        # A proof for a different leaf does not verify.
        self.assertFalse(
            crypto.verify_merkle_proof(h("foreign"), siblings, root, good, good)
        )

    def test_malformed_inputs_return_false(self) -> None:
        tx_ids = [h(f"t{i}") for i in range(4)]
        root = crypto.merkle_root(tx_ids)
        siblings = crypto.merkle_proof(tx_ids, 2)
        good = self.block_hash
        verify = crypto.verify_merkle_proof

        # tx_id / hashes must be 64 lowercase hex chars.
        self.assertFalse(verify("abc", siblings, root, good, good))
        self.assertFalse(verify(tx_ids[2], siblings, root.upper(), good, good))
        self.assertFalse(verify(tx_ids[2], siblings, "z" * 64, good, good))
        self.assertFalse(verify(tx_ids[2], siblings, root[:63], good, good))
        self.assertFalse(verify(tx_ids[2], siblings, root, good, "0" * 63))
        self.assertFalse(verify(123, siblings, root, good, good))

        # Illegal / missing direction.
        self.assertFalse(
            verify(
                tx_ids[2],
                [{"direction": "up", "hash": siblings[0]["hash"]}],
                root, good, good,
            )
        )
        self.assertFalse(
            verify(tx_ids[2], [{"hash": siblings[0]["hash"]}], root, good, good)
        )
        # Sibling hash malformed, sibling entry not a dict, path not a list.
        self.assertFalse(
            verify(
                tx_ids[2],
                [{"direction": "left", "hash": "Z" * 64}],
                root, good, good,
            )
        )
        self.assertFalse(verify(tx_ids[2], ["nope"], root, good, good))
        self.assertFalse(verify(tx_ids[2], None, root, good, good))
        # Path that descends deeper than any plausible tree.
        deep = [{"direction": "left", "hash": tx_ids[0]}] * 65
        self.assertFalse(verify(tx_ids[2], deep, root, good, good))

    def test_index_validation(self) -> None:
        tx_ids = [h("a"), h("b")]
        for bad in (-1, 2, 99):
            with self.assertRaises(ValueError):
                crypto.merkle_proof(tx_ids, bad)


class MerkleProofServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")), initial_balance=100_000
        )

    def tx(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        # Proofs and accounts only cover confirmed blocks.
        status, body = self.svc.confirm_block(block["height"])
        self.assertEqual(status, 200, body)
        return block

    def test_proof_for_empty_genesis(self) -> None:
        # Zero transactions: every lookup is 404, including a well-formed id.
        self.assertEqual(self.svc.get_proof(0, "a" * 64)[0], 404)

    def test_single_and_multiple_txs_proofs(self) -> None:
        first = self.tx(self.ka, self.A, self.B, 10)
        block = self.mine()  # height 1, single tx

        status, proof = self.svc.get_proof(1, first)
        self.assertEqual(status, 200, proof)
        self.assertEqual(
            set(proof),
            {"height", "tx_id", "index", "merkle_root", "block_hash", "siblings"},
        )
        self.assertEqual(proof["height"], 1)
        self.assertEqual(proof["index"], 0)
        self.assertEqual(proof["tx_id"], first)
        self.assertEqual(proof["siblings"], [])  # lone leaf is the root
        self.assertEqual(proof["merkle_root"], first)
        self.assertEqual(proof["block_hash"], block["block_hash"])

        # A block with several transactions: every proof verifies, and the
        # reported indices match the block's ascending tx_id order.
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
        ]
        block2 = self.mine()  # height 2
        _, summary = self.svc.get_block(2)
        self.assertEqual(summary["transaction_ids"], sorted(ids))
        for index, tx_id in enumerate(sorted(ids)):
            status, proof = self.svc.get_proof(2, tx_id)
            self.assertEqual(status, 200)
            self.assertEqual(proof["index"], index)
            self.assertEqual(proof["merkle_root"], block2["merkle_root"])
            self.assertTrue(
                crypto.verify_merkle_proof(
                    proof["tx_id"],
                    proof["siblings"],
                    proof["merkle_root"],
                    proof["block_hash"],
                    block2["block_hash"],
                )
            )

    def test_multiple_blocks_and_wrong_block_hash(self) -> None:
        tx1 = self.tx(self.ka, self.A, self.B, 11)
        b1 = self.mine()
        tx2 = self.tx(self.kb, self.B, self.A, 7)
        b2 = self.mine()

        _, p1 = self.svc.get_proof(1, tx1)
        _, p2 = self.svc.get_proof(2, tx2)
        # Distinct blocks: the proof must not verify against the other
        # block's expected hash even though each path is empty (one leaf).
        self.assertNotEqual(b1["block_hash"], b2["block_hash"])
        self.assertTrue(
            crypto.verify_merkle_proof(tx1, p1["siblings"], p1["merkle_root"],
                                       b1["block_hash"], b1["block_hash"])
        )
        self.assertFalse(
            crypto.verify_merkle_proof(tx1, p1["siblings"], p1["merkle_root"],
                                       b1["block_hash"], b2["block_hash"])
        )
        self.assertEqual(self.svc.get_proof(2, tx1)[0], 404)  # tx not at height
        self.assertEqual(self.svc.get_proof(1, tx2)[0], 404)

    def test_unknown_transaction_and_bad_identifiers(self) -> None:
        self.tx(self.ka, self.A, self.B, 10)
        self.mine()
        self.assertEqual(self.svc.get_proof(1, "a" * 64)[0], 404)  # unknown tx
        self.assertEqual(self.svc.get_proof(99, "a" * 64)[0], 404)  # missing block
        self.assertEqual(self.svc.get_proof(-1, "a" * 64)[0], 404)
        self.assertEqual(self.svc.get_proof("x", "a" * 64)[0], 404)
        self.assertEqual(self.svc.get_proof("1.0", "a" * 64)[0], 404)
        self.assertEqual(self.svc.get_proof(1, "zzz")[0], 404)  # bad tx id format
        self.assertEqual(self.svc.get_proof(1, "A" * 64)[0], 404)  # uppercase hex


class MerkleProofHttpTests(unittest.TestCase):
    """End-to-end checks against the stdlib HTTP server (random local port)."""

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

    def test_proof_endpoint_and_regressions(self) -> None:
        payload1 = make_tx(self.ka, self.A, self.B, 10)
        payload2 = make_tx(self.kb, self.B, self.A, 4)
        status, t1 = self.request("POST", "/v1/transactions", payload1)
        self.assertEqual(status, 202)
        status, t2 = self.request("POST", "/v1/transactions", payload2)
        self.assertEqual(status, 202)
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        height = block["height"]
        status, confirmed = self.request("POST", f"/v1/blocks/{height}/confirm", {})
        self.assertEqual(status, 200, confirmed)
        self.assertEqual(confirmed["status"], "confirmed")

        status, proof = self.request("GET", f"/v1/blocks/{height}/proof/{t1['tx_id']}")
        self.assertEqual(status, 200, proof)
        self.assertEqual(proof["height"], height)
        self.assertEqual(proof["tx_id"], t1["tx_id"])
        self.assertEqual(proof["block_hash"], block["block_hash"])
        self.assertEqual(proof["merkle_root"], block["merkle_root"])
        for sibling in proof["siblings"]:
            self.assertEqual(set(sibling), {"direction", "hash"})
            self.assertIn(sibling["direction"], ("left", "right"))
            self.assertTrue(crypto.is_hex64(sibling["hash"]))
        self.assertTrue(
            crypto.verify_merkle_proof(
                proof["tx_id"], proof["siblings"], proof["merkle_root"],
                proof["block_hash"], block["block_hash"],
            )
        )

        # 404 cases: missing block, tx absent at height, malformed tx id.
        self.assertEqual(self.request("GET", f"/v1/blocks/999/proof/{t1['tx_id']}")[0], 404)
        self.assertEqual(self.request("GET", f"/v1/blocks/0/proof/{t1['tx_id']}")[0], 404)
        self.assertEqual(self.request("GET", f"/v1/blocks/{height}/proof/{'a' * 64}")[0], 404)
        self.assertEqual(self.request("GET", f"/v1/blocks/{height}/proof/nothex")[0], 404)
        self.assertEqual(self.request("GET", f"/v1/blocks/x/proof/{t1['tx_id']}")[0], 404)

        # The four pre-existing interfaces keep working unchanged.
        self.assertEqual(self.request("POST", "/v1/blocks", {})[0], 409)  # no pending
        self.assertEqual(self.request("GET", f"/v1/blocks/{height}")[0], 200)
        self.assertEqual(self.request("GET", f"/v1/accounts/{self.A}")[0], 200)
        self.assertEqual(self.request("GET", "/v1/accounts/unknown")[0], 404)
        status, dup = self.request("POST", "/v1/transactions", payload1)
        self.assertEqual(status, 409)  # already confirmed


class CliProofTests(unittest.TestCase):
    """CLI proof/account subcommands over HTTP; output is one JSON line."""

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

    def test_proof_and_account_cli(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 12)
        status = self.service.submit_transaction(payload)[0]
        self.assertEqual(status, 202)
        _, block = self.service.mine_block()
        self.service.confirm_block(block["height"])
        tx_id = self.service.store.chain[block["height"]].transactions[0].tx_id

        rc, proof, raw = self.run_cli("proof", str(block["height"]), tx_id)
        self.assertEqual(rc, 0, raw)
        self.assertEqual(proof["tx_id"], tx_id)
        self.assertEqual(proof["block_hash"], block["block_hash"])

        # Non-2xx still prints JSON and exits 1.
        rc, body, _ = self.run_cli("proof", str(block["height"]), "a" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)
        rc, _, _ = self.run_cli("proof", "999", tx_id)
        self.assertEqual(rc, 1)
        rc, _, _ = self.run_cli("proof", str(block["height"]), "malformed")
        self.assertEqual(rc, 1)

        # account subcommand: valid hex account and an encoded special-char
        # account (the URL-encoding regression must request the right path).
        rc, account, _ = self.run_cli("account", self.A)
        self.assertEqual(rc, 0)
        self.assertEqual(account["account"], self.A)
        rc, missing, _ = self.run_cli("account", "weird/id?x=1")
        self.assertEqual(rc, 1)
        self.assertEqual(missing["error"], "account not found")

        # block subcommand regression.
        rc, summary, _ = self.run_cli("block", str(block["height"]))
        self.assertEqual(rc, 0)
        self.assertEqual(summary["block_hash"], block["block_hash"])


if __name__ == "__main__":
    unittest.main()
