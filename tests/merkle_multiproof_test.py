"""Tests for compact multi-leaf Merkle inclusion proofs.

Covers crypto.merkle_multiproof / crypto.verify_merkle_multiproof (exact
node sets, ordering, types, boolean rejection, anchors, tampering), the
service lookup (strict 400 body validation, strict ASCII height, 404/409
semantics, response key ordering, reorder invariance, restart stability)
and the POST /v1/blocks/{height}/multiproof HTTP route.

Run: python3 tests/merkle_multiproof_test.py
"""
from __future__ import annotations

import copy
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


def make_multiproof(tx_ids: list[str], indices: list[int], block_hash: str) -> dict:
    """Build a well-formed multiproof document for the given leaf indices."""
    tx_ids = sorted(tx_ids)
    indices = sorted(indices)
    return {
        "height": 7,
        "block_hash": block_hash,
        "merkle_root": crypto.merkle_root(tx_ids),
        "leaf_count": len(tx_ids),
        "leaves": [{"tx_id": tx_ids[i], "index": i} for i in indices],
        "nodes": crypto.merkle_multiproof(tx_ids, indices),
    }


class MultiproofCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.block_hash = h("block")

    def check(self, doc, tx_count, block_hash=None, root=None) -> bool:
        if root is None:
            root = doc.get("merkle_root") if isinstance(doc, dict) else None
        return crypto.verify_merkle_multiproof(
            doc,
            block_hash if block_hash is not None else self.block_hash,
            root,
            tx_count,
        )

    def test_all_tree_shapes_and_subsets(self) -> None:
        for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17):
            tx_ids = sorted(h(f"tx-{n}-{i}") for i in range(n))
            subsets = [
                list(range(n)),
                [0],
                [n - 1],
                [i for i in range(n) if i % 2 == 0],
                [i for i in range(n) if i % 3 == 1],
            ]
            for indices in subsets:
                if not indices:
                    continue
                doc = make_multiproof(tx_ids, indices, self.block_hash)
                self.assertTrue(self.check(doc, n), (n, indices))
                # Nodes carry exactly level/index/hash and are ordered.
                coordinates = [(node["level"], node["index"]) for node in doc["nodes"]]
                self.assertEqual(coordinates, sorted(coordinates))
                self.assertEqual(len(coordinates), len(set(coordinates)))
                for node in doc["nodes"]:
                    self.assertEqual(set(node), {"level", "index", "hash"})
                    self.assertTrue(crypto.is_hex64(node["hash"]))
                for leaf in doc["leaves"]:
                    self.assertEqual(set(leaf), {"tx_id", "index"})

    def test_full_selection_and_single_leaf_have_empty_nodes(self) -> None:
        for n in (1, 2, 3, 4, 5, 8, 9):
            tx_ids = sorted(h(f"full-{n}-{i}") for i in range(n))
            doc = make_multiproof(tx_ids, list(range(n)), self.block_hash)
            self.assertEqual(doc["nodes"], [])
            self.assertTrue(self.check(doc, n))
        tx_ids = [h("only")]
        doc = make_multiproof(tx_ids, [0], self.block_hash)
        self.assertEqual(doc["nodes"], [])
        self.assertEqual(doc["merkle_root"], tx_ids[0])
        self.assertTrue(self.check(doc, 1))

    def test_nodes_match_manual_expectation(self) -> None:
        # 5 leaves, select index 0: sibling leaf 1 at level 0, then the
        # subtree roots at (1, 1) and (2, 1).
        tx_ids = sorted(h(f"m-{i}") for i in range(5))
        doc = make_multiproof(tx_ids, [0], self.block_hash)
        self.assertEqual(
            [(node["level"], node["index"]) for node in doc["nodes"]],
            [(0, 1), (1, 1), (2, 1)],
        )
        # 5 leaves, select indices 1 and 2: leaf siblings 0 and 3 at level 0,
        # then the level-2 sibling of the (self-paired) left subtree root.
        doc = make_multiproof(tx_ids, [1, 2], self.block_hash)
        self.assertEqual(
            [(node["level"], node["index"]) for node in doc["nodes"]],
            [(0, 0), (0, 3), (2, 1)],
        )
        self.assertTrue(self.check(doc, 5))

    def test_key_order_is_irrelevant(self) -> None:
        tx_ids = sorted(h(f"k{i}") for i in range(6))
        doc = make_multiproof(tx_ids, [1, 4], self.block_hash)
        root = doc["merkle_root"]
        reordered = {
            "nodes": [
                {"hash": node["hash"], "index": node["index"], "level": node["level"]}
                for node in doc["nodes"]
            ],
            "leaves": [
                {"index": leaf["index"], "tx_id": leaf["tx_id"]}
                for leaf in doc["leaves"]
            ],
            "leaf_count": doc["leaf_count"],
            "merkle_root": root,
            "block_hash": doc["block_hash"],
            "height": doc["height"],
        }
        self.assertTrue(self.check(reordered, 6))

    def test_missing_and_extra_keys(self) -> None:
        tx_ids = sorted(h(f"k{i}") for i in range(4))
        good = make_multiproof(tx_ids, [1, 2], self.block_hash)
        for key in ("height", "block_hash", "merkle_root", "leaf_count", "leaves", "nodes"):
            mutated = dict(good)
            del mutated[key]
            self.assertFalse(self.check(mutated, 4), key)
        mutated = dict(good)
        mutated["extra"] = 1
        self.assertFalse(self.check(mutated, 4))
        # Leaf / node entry key sets.
        mutated = copy.deepcopy(good)
        del mutated["leaves"][0]["index"]
        self.assertFalse(self.check(mutated, 4))
        mutated = copy.deepcopy(good)
        mutated["leaves"][0]["height"] = 7
        self.assertFalse(self.check(mutated, 4))
        mutated = copy.deepcopy(good)
        del mutated["nodes"][0]["hash"]
        self.assertFalse(self.check(mutated, 4))
        mutated = copy.deepcopy(good)
        mutated["nodes"][0]["direction"] = "left"
        self.assertFalse(self.check(mutated, 4))

    def test_wrong_types_and_booleans(self) -> None:
        tx_ids = sorted(h(f"t{i}") for i in range(4))
        good = make_multiproof(tx_ids, [0, 3], self.block_hash)
        root = good["merkle_root"]

        def rejects(mutated) -> None:
            self.assertFalse(self.check(mutated, 4))

        for bad_height in ("7", 7.0, True, -1, None):
            mutated = copy.deepcopy(good)
            mutated["height"] = bad_height
            rejects(mutated)
        for bad_count in (0, -1, True, "4", 4.0, None):
            mutated = copy.deepcopy(good)
            mutated["leaf_count"] = bad_count
            rejects(mutated)
        for bad_hash in (root.upper(), "z" * 64, root[:63], 123, None, True):
            mutated = copy.deepcopy(good)
            mutated["block_hash"] = bad_hash
            rejects(mutated)
            mutated = copy.deepcopy(good)
            mutated["merkle_root"] = bad_hash
            rejects(mutated)
        # Bad trusted anchors.
        self.assertFalse(
            crypto.verify_merkle_multiproof(good, "abc", root, 4)
        )
        self.assertFalse(
            crypto.verify_merkle_multiproof(good, self.block_hash, 7, 4)
        )
        for bad_count in (0, -3, True, "4", None):
            self.assertFalse(
                crypto.verify_merkle_multiproof(
                    good, self.block_hash, root, bad_count
                )
            )

        # Container types.
        mutated = copy.deepcopy(good)
        mutated["leaves"] = []
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["leaves"] = tuple(good["leaves"])
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["nodes"] = None
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["leaves"][0] = "nope"
        rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["nodes"][0] = 42
        rejects(mutated)

        # Leaf field types.
        for bad_index in (True, "1", 1.5, None, -1, 4, 99):
            mutated = copy.deepcopy(good)
            mutated["leaves"][0]["index"] = bad_index
            rejects(mutated)
        for bad_tx in (tx_ids[0].upper(), "z" * 64, 5, None, True):
            mutated = copy.deepcopy(good)
            mutated["leaves"][0]["tx_id"] = bad_tx
            rejects(mutated)

        # Node field types.
        for bad_level in (True, "0", -1, None):
            mutated = copy.deepcopy(good)
            mutated["nodes"][0]["level"] = bad_level
            rejects(mutated)
        for bad_index in (True, "1", -1, None):
            mutated = copy.deepcopy(good)
            mutated["nodes"][0]["index"] = bad_index
            rejects(mutated)
        mutated = copy.deepcopy(good)
        mutated["nodes"][0]["hash"] = "Z" * 64
        rejects(mutated)

    def test_leaf_ordering_and_duplicates(self) -> None:
        tx_ids = sorted(h(f"o{i}") for i in range(5))
        good = make_multiproof(tx_ids, [0, 2, 4], self.block_hash)

        # Index order violated.
        mutated = copy.deepcopy(good)
        mutated["leaves"] = [mutated["leaves"][1], mutated["leaves"][0], mutated["leaves"][2]]
        self.assertFalse(self.check(mutated, 5))
        # Duplicate leaf.
        mutated = copy.deepcopy(good)
        mutated["leaves"].append(copy.deepcopy(mutated["leaves"][0]))
        self.assertFalse(self.check(mutated, 5))
        # tx_id order violated while indices stay ascending.
        mutated = copy.deepcopy(good)
        # Keep indices 0,2,4 but replace the middle tx_id with a larger one.
        mutated["leaves"][1]["tx_id"] = tx_ids[4]
        self.assertFalse(self.check(mutated, 5))

    def test_node_set_must_be_exact(self) -> None:
        tx_ids = sorted(h(f"n{i}") for i in range(6))
        good = make_multiproof(tx_ids, [1, 2], self.block_hash)
        self.assertTrue(good["nodes"])

        # Missing node.
        mutated = copy.deepcopy(good)
        mutated["nodes"] = mutated["nodes"][1:]
        self.assertFalse(self.check(mutated, 6))
        # Redundant node (a real tree node that is derivable / not required).
        mutated = copy.deepcopy(good)
        mutated["nodes"].append({"level": 0, "index": 2, "hash": tx_ids[2]})
        mutated["nodes"].sort(key=lambda node: (node["level"], node["index"]))
        self.assertFalse(self.check(mutated, 6))
        # Duplicate coordinate.
        mutated = copy.deepcopy(good)
        mutated["nodes"].append(copy.deepcopy(mutated["nodes"][-1]))
        self.assertFalse(self.check(mutated, 6))
        # Out-of-range coordinate.
        mutated = copy.deepcopy(good)
        mutated["nodes"][0]["index"] = 99
        self.assertFalse(self.check(mutated, 6))
        mutated = copy.deepcopy(good)
        mutated["nodes"][0]["level"] = 12
        self.assertFalse(self.check(mutated, 6))
        # Unsorted nodes.
        mutated = copy.deepcopy(good)
        mutated["nodes"] = list(reversed(mutated["nodes"]))
        self.assertFalse(self.check(mutated, 6))
        # Tampered node hash.
        mutated = copy.deepcopy(good)
        mutated["nodes"][0]["hash"] = h("tampered")
        self.assertFalse(self.check(mutated, 6))

    def test_anchor_and_root_mismatch(self) -> None:
        tx_ids = sorted(h(f"a{i}") for i in range(4))
        good = make_multiproof(tx_ids, [0, 1], self.block_hash)
        root = good["merkle_root"]

        self.assertFalse(self.check(good, 5))  # leaf_count mismatch
        mutated = copy.deepcopy(good)
        mutated["leaf_count"] = 5
        self.assertFalse(self.check(mutated, 5))
        self.assertFalse(self.check(good, 4, root=h("other-root")))
        self.assertFalse(self.check(good, 4, block_hash=h("other-block")))
        mutated = copy.deepcopy(good)
        mutated["merkle_root"] = h("other-root")
        self.assertFalse(self.check(mutated, 4))
        mutated = copy.deepcopy(good)
        mutated["block_hash"] = h("other-block")
        self.assertFalse(self.check(mutated, 4))
        # A tampered leaf cannot be rescued.
        mutated = copy.deepcopy(good)
        mutated["leaves"][0]["tx_id"] = tx_ids[2]
        self.assertFalse(self.check(mutated, 4))
        self.assertTrue(self.check(good, 4, root=root))

    def test_junk_inputs_never_raise(self) -> None:
        for junk in (None, 42, "string", [], [1], {"height": 1}, object(), True):
            self.assertFalse(
                crypto.verify_merkle_multiproof(
                    junk, self.block_hash, h("r"), 4
                )
            )


class MultiproofServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.store_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.store_path), initial_balance=100_000
        )

    def tx(self, key, sender, to, amount) -> str:
        status, body = self.svc.submit_transaction(make_tx(key, sender, to, amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def mine(self, confirm: bool = True) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        if confirm:
            status, body = self.svc.confirm_block(block["height"])
            self.assertEqual(status, 200, body)
        return block

    def fingerprint(self) -> tuple:
        store = self.svc.store
        return (
            store.generation,
            len(store.chain),
            sorted(store.pending),
            len(store.audit_events),
        )

    def test_success_shape_order_and_reorder_invariance(self) -> None:
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
            self.tx(self.kb, self.B, self.A, 1),
            self.tx(self.ka, self.A, self.B, 4),
        ]
        block = self.mine()  # height 1, 5 txs
        ordered = sorted(ids)

        requested = [ids[4], ids[0], ids[2]]
        status, body = self.svc.get_multiproof("1", {"tx_ids": requested})
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "merkle_root", "leaf_count", "leaves", "nodes"],
        )
        self.assertEqual(body["height"], 1)
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(body["merkle_root"], block["merkle_root"])
        self.assertEqual(body["leaf_count"], 5)
        # Leaves carry only the requested transactions, ascending by index.
        expected_indices = sorted(ordered.index(tx_id) for tx_id in requested)
        self.assertEqual([leaf["index"] for leaf in body["leaves"]], expected_indices)
        self.assertEqual(
            [leaf["tx_id"] for leaf in body["leaves"]],
            [ordered[index] for index in expected_indices],
        )
        for leaf in body["leaves"]:
            self.assertEqual(list(leaf.keys()), ["tx_id", "index"])
        coordinates = [(node["level"], node["index"]) for node in body["nodes"]]
        self.assertEqual(coordinates, sorted(coordinates))
        for node in body["nodes"]:
            self.assertEqual(list(node.keys()), ["level", "index", "hash"])
        # The document verifies offline against the block's anchors.
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                body, block["block_hash"], block["merkle_root"], 5
            )
        )

        # Request order never changes the response.
        shuffled = list(reversed(requested))
        status, again = self.svc.get_multiproof("1", {"tx_ids": shuffled})
        self.assertEqual(status, 200, again)
        self.assertEqual(body, again)

        # Full selection yields an empty node list.
        status, full = self.svc.get_multiproof("1", {"tx_ids": ids})
        self.assertEqual(status, 200, full)
        self.assertEqual(full["nodes"], [])
        self.assertEqual([leaf["index"] for leaf in full["leaves"]], [0, 1, 2, 3, 4])
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                full, block["block_hash"], block["merkle_root"], 5
            )
        )

    def test_single_transaction_block(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        block = self.mine()
        status, body = self.svc.get_multiproof("1", {"tx_ids": [tx_id]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["leaf_count"], 1)
        self.assertEqual(body["leaves"], [{"tx_id": tx_id, "index": 0}])
        self.assertEqual(body["nodes"], [])
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                body, block["block_hash"], block["merkle_root"], 1
            )
        )

    def test_malformed_bodies_are_400_and_state_untouched(self) -> None:
        self.tx(self.ka, self.A, self.B, 10)
        self.mine()
        valid = "a" * 64
        bad_bodies = [
            None,
            [],
            "nope",
            42,
            {},
            {"tx_ids": []},
            {"tx_ids": [valid, valid]},
            {"tx_ids": [valid], "extra": 1},
            {"proofs": [valid]},
            {"tx_ids": valid},
            {"tx_ids": (valid,)},
            {"tx_ids": [valid, "b" * 63]},
            {"tx_ids": [valid, "B" * 64]},
            {"tx_ids": [123]},
            {"tx_ids": [None]},
        ]
        for body in bad_bodies:
            before = self.fingerprint()
            status, error = self.svc.get_multiproof(1, body)
            self.assertEqual(status, 400, (body, error))
            self.assertIn("error", error)
            self.assertEqual(self.fingerprint(), before)

    def test_lookup_semantics(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        self.mine()

        # Unknown heights and malformed heights (strict ASCII decimal, no
        # leading zeros, signs, whitespace or non-ASCII digits).
        for height in (99, "99", "x", "01", "+1", "-1", " 1", "1 ", "1.0", "１２", ""):
            self.assertEqual(
                self.svc.get_multiproof(height, {"tx_ids": [tx_id]})[0],
                404,
                height,
            )
        # Empty genesis never holds the transaction.
        self.assertEqual(self.svc.get_multiproof("0", {"tx_ids": [tx_id]})[0], 404)
        # One missing id among valid ids fails the whole batch with 404.
        other = self.tx(self.kb, self.B, self.A, 1)
        self.assertEqual(
            self.svc.get_multiproof("1", {"tx_ids": [tx_id, "a" * 64]})[0], 404
        )
        # A transaction still in the mempool is not at any height.
        self.assertEqual(self.svc.get_multiproof("1", {"tx_ids": [other]})[0], 404)

    def test_pending_block_is_409(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        self.mine(confirm=False)
        status, body = self.svc.get_multiproof("1", {"tx_ids": [tx_id]})
        self.assertEqual(status, 409, body)

    def test_restart_consistency(self) -> None:
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
        ]
        self.mine()
        status, before = self.svc.get_multiproof("1", {"tx_ids": ids})
        self.assertEqual(status, 200, before)

        revived = LedgerService(LedgerStore(self.store_path))
        status, after = revived.get_multiproof("1", {"tx_ids": ids})
        self.assertEqual(status, 200, after)
        self.assertEqual(before, after)


class MultiproofHttpTests(unittest.TestCase):
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

    def post_raw(self, path: str, raw: bytes):
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=raw,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_multiproof_endpoint_end_to_end(self) -> None:
        payloads = [
            make_tx(self.ka, self.A, self.B, 10),
            make_tx(self.kb, self.B, self.A, 4),
            make_tx(self.ka, self.A, self.B, 6),
        ]
        tx_ids = []
        for payload in payloads:
            status, body = self.request("POST", "/v1/transactions", payload)
            self.assertEqual(status, 202)
            tx_ids.append(body["tx_id"])
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        height = block["height"]
        status, _ = self.request("POST", f"/v1/blocks/{height}/confirm", {})
        self.assertEqual(status, 200)

        # Request order need not be sorted; the response sorts leaves.
        req = urllib.request.Request(
            f"{self.base}/v1/blocks/{height}/multiproof",
            data=json.dumps({"tx_ids": [tx_ids[2], tx_ids[0]]}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            status = resp.status
        body = json.loads(raw)
        self.assertEqual(status, 200)
        # The top-level key order is contract-fixed on the wire.
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "merkle_root", "leaf_count", "leaves", "nodes"],
        )
        self.assertTrue(raw.startswith('{"height"'))
        for earlier, later in (
            ("height", "block_hash"),
            ("block_hash", "merkle_root"),
            ("merkle_root", "leaf_count"),
            ("leaf_count", "leaves"),
            ("leaves", "nodes"),
        ):
            self.assertLess(raw.index(f'"{earlier}"'), raw.index(f'"{later}"'))
        self.assertEqual(body["height"], height)
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(body["merkle_root"], block["merkle_root"])
        self.assertEqual(body["leaf_count"], 3)
        ordered = sorted(tx_ids)
        self.assertEqual(
            [leaf["tx_id"] for leaf in body["leaves"]],
            sorted([tx_ids[0], tx_ids[2]]),
        )
        self.assertEqual(
            [leaf["index"] for leaf in body["leaves"]],
            sorted(ordered.index(tx_id) for tx_id in (tx_ids[0], tx_ids[2])),
        )
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                body, block["block_hash"], block["merkle_root"], 3
            )
        )

        # 400: invalid JSON, missing/extra keys, empty/duplicate/bad-format ids.
        self.assertEqual(
            self.post_raw(f"/v1/blocks/{height}/multiproof", b"{not json")[0], 400
        )
        self.assertEqual(self.post_raw(f"/v1/blocks/{height}/multiproof", b"")[0], 400)
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/multiproof", [])[0], 400
        )
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/multiproof", {})[0], 400
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof",
                {"tx_ids": [tx_ids[0]], "more": 1},
            )[0],
            400,
        )
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/multiproof", {"tx_ids": []})[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof",
                {"tx_ids": [tx_ids[0], tx_ids[0]]},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof",
                {"tx_ids": [tx_ids[0][:63]]},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof", {"tx_ids": ["Z" * 64]}
            )[0],
            400,
        )

        # 404: malformed/unknown height, missing transaction.
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/01/multiproof", {"tx_ids": [tx_ids[0]]}
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST", "/v1/blocks/999/multiproof", {"tx_ids": [tx_ids[0]]}
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof", {"tx_ids": ["a" * 64]}
            )[0],
            404,
        )

    def test_pending_block_is_409_over_http(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 7)
        status, tx = self.request("POST", "/v1/transactions", payload)
        self.assertEqual(status, 202)
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        status, body = self.request(
            "POST", f"/v1/blocks/{block['height']}/multiproof",
            {"tx_ids": [tx["tx_id"]]},
        )
        self.assertEqual(status, 409, body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
