"""Tests for the account-state Merkle root and inclusion proofs.

Covers:

* crypto.account_state_leaf canonical JSON (sort_keys, ensure_ascii=False,
  compact separators, T kept in its original order) and account_state_root;
* crypto.verify_account_proof: recomputed leaf/root/anchor binding and every
  malformed hash / direction / index / leaf / anchor failure returning False;
* service GET /v1/state/root and GET /v1/accounts/{account}/proof, including
  ascending-account indices, leaf-to-root siblings, highest-block anchoring,
  and the pending-tip 404;
* the HTTP routes and the state-root / state-proof CLI subcommands;
* snapshot persistence of state_root, recomputation mismatch raising
  StateRecoveryError (never silently creating a fresh chain), and the root
  staying stable across a pending mine/rollback cycle.

Run: python3 tests/state_proof_test.py
"""
from __future__ import annotations

import hashlib
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
from ledger.store import LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def expected_leaf(account: str, balance: int, transactions: list[str]) -> str:
    document = {"account": account, "balance": balance,
                "confirmed_transactions": transactions}
    raw = json.dumps(
        document, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AccountStateCryptoTests(unittest.TestCase):
    def test_leaf_canonical_json_vector(self) -> None:
        tx1, tx2 = "a" * 64, "b" * 64
        # Exact canonical serialization: keys sorted, compact separators, T in
        # the supplied order.
        self.assertEqual(
            crypto.account_state_leaf("alice", 100, [tx1, tx2]),
            expected_leaf("alice", 100, [tx1, tx2]),
        )
        raw = json.dumps(
            {"account": "alice", "balance": 100,
             "confirmed_transactions": [tx1, tx2]},
            sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        )
        self.assertEqual(
            raw,
            f'{{"account":"alice","balance":100,"confirmed_transactions":["{tx1}","{tx2}"]}}',
        )
        # T order matters: a reordered list is a different leaf.
        self.assertNotEqual(
            crypto.account_state_leaf("alice", 100, [tx1, tx2]),
            crypto.account_state_leaf("alice", 100, [tx2, tx1]),
        )
        # ensure_ascii=False: non-ASCII account text is emitted verbatim.
        leaf = crypto.account_state_leaf("账户甲", 1, [])
        raw_doc = '{"account":"账户甲","balance":1,"confirmed_transactions":[]}'
        self.assertEqual(leaf, hashlib.sha256(raw_doc.encode("utf-8")).hexdigest())

    def test_empty_and_single_root(self) -> None:
        self.assertEqual(crypto.account_state_root([]), crypto.EMPTY_MERKLE_ROOT)
        only = crypto.account_state_leaf("a", 0, ["c" * 64])
        self.assertEqual(crypto.account_state_root([only]), only)

    def test_root_independent_of_input_order_of_identical_leaves(self) -> None:
        leaves = [crypto.account_state_leaf(f"a{i}", i, ["d" * 64]) for i in range(5)]
        # The service always passes ascending-account leaves; hashing the same
        # set in a different leaf order is expected to differ, documenting
        # that ordering is the caller's contract.
        self.assertEqual(
            crypto.account_state_root(leaves), crypto.account_state_root(list(leaves))
        )

    def build_proof(self, n: int, index: int) -> tuple[dict, str]:
        txs = [f"{i:064d}" for i in range(n)]
        accounts = [f"acct{i:03d}" for i in range(n)]
        leaves = [
            crypto.account_state_leaf(accounts[i], 100 * i, [txs[i]]) for i in range(n)
        ]
        root = crypto.account_state_root(leaves)
        proof = {
            "account": accounts[index],
            "balance": 100 * index,
            "confirmed_transactions": [txs[index]],
            "index": index,
            "state_root": root,
            "height": n,
            "block_hash": "a" * 64,
            "siblings": crypto.merkle_proof(leaves, index),
        }
        return proof, root

    def test_valid_proofs_all_sizes_and_indices(self) -> None:
        for n in range(1, 13):
            for index in range(n):
                proof, root = self.build_proof(n, index)
                self.assertTrue(
                    crypto.verify_account_proof(proof, root, n, "a" * 64),
                    (n, index),
                )
                # Siblings are leaf-to-root and well-formed.
                for sibling in proof["siblings"]:
                    self.assertEqual(set(sibling), {"direction", "hash"})
                    self.assertIn(sibling["direction"], ("left", "right"))
                    self.assertTrue(crypto.is_hex64(sibling["hash"]))

    def test_odd_self_paired_node(self) -> None:
        # Three accounts: the rightmost leaf pairs with itself (a "right"
        # sibling equal to its own hash); the genuine proof must verify.
        proof, root = self.build_proof(3, 2)
        self.assertEqual(
            proof["siblings"][0],
            {"direction": "right", "hash": expected_leaf("acct002", 200, ["0000000000000000000000000000000000000000000000000000000000000002"])},
        )
        self.assertTrue(crypto.verify_account_proof(proof, root, 3, "a" * 64))

    def test_anchor_and_root_mismatches_return_false(self) -> None:
        proof, root = self.build_proof(4, 1)
        good = "a" * 64
        self.assertFalse(crypto.verify_account_proof(proof, "0" * 64, 4, good))
        self.assertFalse(crypto.verify_account_proof(proof, root, 5, good))
        self.assertFalse(crypto.verify_account_proof(proof, root, 4, "0" * 64))
        # A state_root field disagreeing with the recomputed root is rejected
        # even when the caller passes that same wrong value as expected_root.
        other = dict(proof)
        other["state_root"] = "f" * 64
        self.assertFalse(crypto.verify_account_proof(other, "f" * 64, 4, good))

    def test_leaf_tampering_returns_false(self) -> None:
        proof, root = self.build_proof(4, 1)
        good = "a" * 64
        for mutated, key, value in (
            ("balance", "balance", proof["balance"] + 1),
            ("account", "account", proof["account"] + "x"),
        ):
            bad = dict(proof)
            bad[key] = value
            self.assertFalse(crypto.verify_account_proof(bad, root, 4, good), mutated)
        # Reorder / replace T: the recomputed leaf no longer matches the path.
        bad = dict(proof)
        bad["confirmed_transactions"] = ["9" * 64]
        self.assertFalse(crypto.verify_account_proof(bad, root, 4, good))
        bad = dict(proof)
        bad["confirmed_transactions"] = []
        self.assertFalse(crypto.verify_account_proof(bad, root, 4, good))

    def test_illegal_direction_hash_and_path(self) -> None:
        proof, root = self.build_proof(4, 1)
        good = "a" * 64
        if proof["siblings"]:
            tampered = dict(proof)
            first = dict(proof["siblings"][0])
            first["direction"] = "up"
            tampered["siblings"] = [first] + proof["siblings"][1:]
            self.assertFalse(crypto.verify_account_proof(tampered, root, 4, good))
            tampered = dict(proof)
            first = dict(proof["siblings"][0])
            first["hash"] = "Z" * 64
            tampered["siblings"] = [first] + proof["siblings"][1:]
            self.assertFalse(crypto.verify_account_proof(tampered, root, 4, good))
            # Direction inconsistent with the index.
            tampered = dict(proof)
            first = dict(proof["siblings"][0])
            first["direction"] = "left" if first["direction"] == "right" else "right"
            tampered["siblings"] = [first] + proof["siblings"][1:]
            self.assertFalse(crypto.verify_account_proof(tampered, root, 4, good))
        # Non-list path, non-dict entries, excessive depth.
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "siblings": None}, root, 4, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "siblings": ["nope"] * len(proof["siblings"])}, root, 4, good))
        deep = [{"direction": "left", "hash": "b" * 64}] * 65
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "siblings": deep}, root, 4, good))

    def test_illegal_index_returns_false(self) -> None:
        proof, root = self.build_proof(1, 0)
        good = "a" * 64
        for bad_index in (-1, 1, 5):
            tampered = dict(proof)
            tampered["index"] = bad_index
            self.assertFalse(
                crypto.verify_account_proof(tampered, root, 1, good), bad_index
            )
        # An index beyond the slots addressed by the path depth is rejected
        # even for a multi-leaf tree.
        proof4, root4 = self.build_proof(4, 0)
        proof4["index"] = 4
        self.assertFalse(crypto.verify_account_proof(proof4, root4, 4, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof4, "index": True}, root4, 4, good))

    def test_malformed_inputs_return_false(self) -> None:
        good = "a" * 64
        for bad in (None, 5, [], "proof", {"x": 1}):
            self.assertFalse(
                crypto.verify_account_proof(bad, "0" * 64, 0, "0" * 64)
            )
        proof, root = self.build_proof(2, 0)
        # Non-hex / wrong-length hashes and non-string account.
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "state_root": "abc"}, root, 2, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "block_hash": "z" * 64}, root, 2, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "account": ""}, root, 2, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "account": 7}, root, 2, good))
        # Negative / boolean balance, non-list or non-hex T.
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "balance": -1}, root, 2, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "balance": True}, root, 2, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "confirmed_transactions": "x"}, root, 2, good))
        self.assertFalse(crypto.verify_account_proof(
            {**proof, "confirmed_transactions": ["nothex"]}, root, 2, good))
        # Wrong-type expected anchors.
        self.assertFalse(crypto.verify_account_proof(proof, 5, 2, good))
        self.assertFalse(crypto.verify_account_proof(proof, root, "2", good))
        self.assertFalse(crypto.verify_account_proof(proof, root, 2, 7))


class StateServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")), initial_balance=100_000
        )

    def send(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine_pending(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        return block

    def confirm(self, height) -> dict:
        status, block = self.svc.confirm_block(height)
        self.assertEqual(status, 200, block)
        return block

    def test_state_root_at_genesis(self) -> None:
        status, body = self.svc.get_state_root()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["state_root"], crypto.EMPTY_MERKLE_ROOT)
        self.assertEqual(body["height"], 0)
        self.assertEqual(body["account_count"], 0)
        self.assertEqual(body["block_hash"], self.svc.store.chain[0].block_hash)

    def test_pending_tip_anchors_nothing(self) -> None:
        self.send(self.ka, self.A, self.B, 10)
        self.mine_pending()
        # Both endpoints 404 while the highest block is pending.
        self.assertEqual(self.svc.get_state_root()[0], 404)
        self.assertEqual(self.svc.get_account_proof(self.A)[0], 404)
        self.assertEqual(self.svc.get_account_proof(self.B)[0], 404)
        # The ordinary account endpoint also hides pending-only accounts, but
        # state/proof stay 404 uniformly.
        self.confirm(1)
        self.assertEqual(self.svc.get_state_root()[0], 200)

    def test_state_root_fields_and_account_ascending_proofs(self) -> None:
        # A->B and C->A land in one confirmed block; three accounts total.
        t1 = self.send(self.ka, self.A, self.B, 100)
        t2 = self.send(self.kc, self.C, self.A, 40)
        block = self.mine_pending()
        self.confirm(1)

        status, rootdoc = self.svc.get_state_root()
        self.assertEqual(status, 200, rootdoc)
        self.assertEqual(
            set(rootdoc), {"state_root", "height", "block_hash", "account_count"}
        )
        self.assertEqual(rootdoc["height"], 1)
        self.assertEqual(rootdoc["block_hash"], block["block_hash"])
        self.assertEqual(rootdoc["account_count"], 3)

        # Independent recomputation from the account documents.
        rows = self.svc.store.account_state_rows(
            self.svc.store.chain, self.svc.initial_balance
        )
        self.assertEqual([name for name, _b, _t in rows], sorted([self.A, self.B, self.C]))
        leaves = [crypto.account_state_leaf(a, b, t) for a, b, t in rows]
        self.assertEqual(rootdoc["state_root"], crypto.account_state_root(leaves))

        for index, (account, balance, txs) in enumerate(rows):
            status, proof = self.svc.get_account_proof(account)
            self.assertEqual(status, 200, proof)
            self.assertEqual(
                set(proof),
                {"account", "balance", "confirmed_transactions", "index",
                 "state_root", "height", "block_hash", "siblings"},
            )
            self.assertEqual(proof["index"], index)
            self.assertEqual(proof["account"], account)
            self.assertEqual(proof["balance"], balance)
            self.assertEqual(proof["confirmed_transactions"], txs)
            self.assertEqual(proof["state_root"], rootdoc["state_root"])
            self.assertEqual(proof["height"], 1)
            self.assertEqual(proof["block_hash"], block["block_hash"])
            self.assertTrue(
                crypto.verify_account_proof(
                    proof,
                    rootdoc["state_root"],
                    rootdoc["height"],
                    rootdoc["block_hash"],
                )
            )

        # Balances and original-order T for A (one send, one receive).
        _, proof_a = self.svc.get_account_proof(self.A)
        self.assertEqual(proof_a["balance"], 100_000 - 100 + 40)
        # T keeps on-chain order: within the block transactions are stored in
        # ascending tx_id order.
        self.assertEqual(proof_a["confirmed_transactions"], sorted([t1, t2]))
        _, proof_b = self.svc.get_account_proof(self.B)
        self.assertEqual(proof_b["balance"], 100_100)
        self.assertEqual(proof_b["confirmed_transactions"], [t1])

    def test_unknown_account_proof_404(self) -> None:
        self.assertEqual(self.svc.get_account_proof("unknown")[0], 404)
        self.assertEqual(self.svc.get_account_proof("d" * 64)[0], 404)

    def test_root_tracks_confirmed_blocks_only(self) -> None:
        # After a confirmed block the root changes; an unconfirmed second block
        # must leave the persisted/visible root exactly as after confirmation.
        self.send(self.ka, self.A, self.B, 10)
        self.mine_pending()
        self.confirm(1)
        _, root1 = self.svc.get_state_root()
        with open(self.svc.store.path, encoding="utf-8") as fh:
            snapshot_root = json.load(fh)["state"]["state_root"]
        self.assertEqual(snapshot_root, root1["state_root"])

        self.send(self.kb, self.B, self.A, 5)
        self.mine_pending()  # height 2 pending
        # Endpoints 404, but the persisted state_root still describes the
        # confirmed account set (unchanged from height 1).
        self.assertEqual(self.svc.get_state_root()[0], 404)
        self.confirm(2)
        _, root2 = self.svc.get_state_root()
        self.assertNotEqual(root1["state_root"], root2["state_root"])
        self.assertEqual(root2["height"], 2)


class StateHttpTests(unittest.TestCase):
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
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_state_routes(self) -> None:
        # Genesis root.
        status, rootdoc = self.request("GET", "/v1/state/root")
        self.assertEqual(status, 200, rootdoc)
        self.assertEqual(rootdoc["state_root"], crypto.EMPTY_MERKLE_ROOT)

        status, _ = self.request(
            "POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 77)
        )
        self.assertEqual(status, 202)
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        # Pending: both routes 404.
        self.assertEqual(self.request("GET", "/v1/state/root")[0], 404)
        self.assertEqual(
            self.request("GET", f"/v1/accounts/{self.B}/proof")[0], 404
        )
        self.request("POST", f"/v1/blocks/{block['height']}/confirm", {})

        status, rootdoc = self.request("GET", "/v1/state/root")
        self.assertEqual(status, 200)
        self.assertEqual(rootdoc["account_count"], 2)
        self.assertEqual(rootdoc["height"], block["height"])
        self.assertEqual(rootdoc["block_hash"], block["block_hash"])

        status, proof = self.request("GET", f"/v1/accounts/{self.B}/proof")
        self.assertEqual(status, 200, proof)
        self.assertEqual(proof["account"], self.B)
        self.assertTrue(
            crypto.verify_account_proof(
                proof, rootdoc["state_root"],
                rootdoc["height"], rootdoc["block_hash"],
            )
        )
        # Unknown account 404; the ordinary account route still works.
        self.assertEqual(
            self.request("GET", f"/v1/accounts/{'e' * 64}/proof")[0], 404
        )
        self.assertEqual(
            self.request("GET", f"/v1/accounts/{self.B}")[0], 200
        )

    def test_url_encoded_account_proof_route(self) -> None:
        # A hex account needs no encoding; a non-existent but encoded segment
        # must resolve to the decoded account and 404, not hit a different
        # route.
        encoded = urllib.request.quote("a/b?x", safe="")
        self.assertEqual(
            self.request("GET", f"/v1/accounts/{encoded}/proof")[0], 404
        )


class StateCliTests(unittest.TestCase):
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
        self.assertEqual(raw.count("\n"), 1)
        return rc, json.loads(raw), raw

    def test_state_root_and_state_proof_cli(self) -> None:
        self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 9))
        _, block = self.service.mine_block()
        self.service.confirm_block(block["height"])

        rc, rootdoc, raw = self.run_cli("state-root")
        self.assertEqual(rc, 0, raw)
        self.assertEqual(rootdoc["height"], block["height"])
        self.assertEqual(rootdoc["account_count"], 2)

        rc, proof, raw = self.run_cli("state-proof", self.B)
        self.assertEqual(rc, 0, raw)
        self.assertEqual(proof["account"], self.B)
        self.assertTrue(
            crypto.verify_account_proof(
                proof, rootdoc["state_root"],
                rootdoc["height"], rootdoc["block_hash"],
            )
        )
        # Non-2xx prints JSON and exits 1.
        rc, body, _ = self.run_cli("state-proof", "f" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)


class StateSnapshotRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=100_000)

    def confirmed_block(self) -> None:
        msg = crypto.canonical_message(self.A, self.B, 50)
        payload = {"from": self.A, "to": self.B, "amount": 50,
                   "signature": self.ka.sign(msg).hex()}
        self.assertEqual(self.svc.submit_transaction(payload)[0], 202)
        _, block = self.svc.mine_block()
        self.assertEqual(self.svc.confirm_block(block["height"])[0], 200)

    def test_snapshot_carries_state_root_and_reopens(self) -> None:
        self.confirmed_block()
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertIn("state_root", data["state"])
        _, expected = self.svc.get_state_root()
        self.assertEqual(data["state"]["state_root"], expected["state_root"])
        # A clean reopen recomputes the same root and serves it.
        reopened = LedgerService(LedgerStore(self.path), initial_balance=100_000)
        _, rootdoc = reopened.get_state_root()
        self.assertEqual(rootdoc["state_root"], expected["state_root"])

    def test_tampered_state_root_fails_recovery_no_fresh_chain(self) -> None:
        self.confirmed_block()
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["state"]["state_root"] = "f" * 64
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.path)
        self.assertEqual(ctx.exception.path, self.path)
        self.assertIn("state_root", ctx.exception.reason)
        # The corrupted file is still on disk: recovery never replaced it
        # with a freshly minted genesis chain.
        with open(self.path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["state"]["state_root"], "f" * 64)

    def test_malformed_state_root_fails_recovery(self) -> None:
        self.confirmed_block()
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["state"]["state_root"] = "not-hex"
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.path)

    def test_root_stable_through_pending_rollback(self) -> None:
        self.confirmed_block()
        _, after_first = self.svc.get_state_root()
        # Mine a pending block, then roll it back; the confirmed root and the
        # persisted snapshot must return to the identical value.
        msg = crypto.canonical_message(self.B, self.A, 10)
        payload = {"from": self.B, "to": self.A, "amount": 10,
                   "signature": self.kb.sign(msg).hex()}
        self.assertEqual(self.svc.submit_transaction(payload)[0], 202)
        _, block = self.svc.mine_block()
        self.assertEqual(
            self.svc.rollback_block(block["height"])[0], 200
        )
        _, after_rollback = self.svc.get_state_root()
        self.assertEqual(
            after_first["state_root"], after_rollback["state_root"]
        )
        # Reopening keeps serving the same confirmed root.
        reopened_store = LedgerStore(self.path)
        svc2 = LedgerService(reopened_store)
        _, reopened_root = svc2.get_state_root()
        self.assertEqual(
            reopened_root["state_root"], after_first["state_root"]
        )


if __name__ == "__main__":
    unittest.main()
