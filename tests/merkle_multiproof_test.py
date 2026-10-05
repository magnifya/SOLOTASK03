"""Tests for compact multi-leaf Merkle inclusion proofs.

Covers crypto.merkle_multiproof / crypto.verify_merkle_multiproof (exact
field sets, strict types, strictly sorted leaves and node coordinates, the
minimal sibling set, odd-node self pairing, root/leaf-count/block-hash
binding and never raising), the service lookup (strict 400 body validation
ahead of height parsing, 404/409 semantics, fixed response key ordering, no
state mutation, restart stability), the POST
/v1/blocks/{height}/multiproof HTTP route and request-order invariance.

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


def make_document(
    tx_ids: list[str],
    indices: list[int],
    block_hash: str,
    height: int = 7,
) -> dict:
    """Build a well-formed multiproof document for the given leaf indices."""
    leaves, nodes = crypto.merkle_multiproof(tx_ids, indices)
    return {
        "height": height,
        "block_hash": block_hash,
        "merkle_root": crypto.merkle_root(tx_ids),
        "leaf_count": len(tx_ids),
        "leaves": leaves,
        "nodes": nodes,
    }


class MultiproofCryptoShapeTests(unittest.TestCase):
    def test_all_tree_shapes_and_subsets_verify(self) -> None:
        for n in range(1, 10):
            tx_ids = sorted(h(f"tx-{n}-{i}") for i in range(n))
            root = crypto.merkle_root(tx_ids)
            block_hash = h("block")
            for mask in range(1, 1 << n):
                indices = [i for i in range(n) if mask >> i & 1]
                doc = make_document(tx_ids, indices, block_hash)
                self.assertTrue(
                    crypto.verify_merkle_multiproof(doc, block_hash, root, n),
                    (n, indices),
                )

    def test_larger_trees_spot_checks(self) -> None:
        block_hash = h("block")
        for n, indices in (
            (15, [0, 14]),
            (16, [1, 5, 9, 13]),
            (17, [16]),
            (33, [0, 32]),
            (64, list(range(0, 64, 3))),
            (100, [99]),
            (127, [0, 63, 64, 126]),
            (255, [254]),
            (256, [0, 255]),
        ):
            tx_ids = sorted(h(f"big-{n}-{i}") for i in range(n))
            root = crypto.merkle_root(tx_ids)
            doc = make_document(tx_ids, indices, block_hash)
            self.assertTrue(
                crypto.verify_merkle_multiproof(doc, block_hash, root, n),
                (n, indices),
            )

    def test_full_selection_and_single_leaf_have_no_nodes(self) -> None:
        for n in (1, 2, 3, 5, 8):
            tx_ids = sorted(h(f"f-{n}-{i}") for i in range(n))
            leaves, nodes = crypto.merkle_multiproof(tx_ids, list(range(n)))
            self.assertEqual(nodes, [], n)
            self.assertEqual([leaf["index"] for leaf in leaves], list(range(n)))
        tx_one = [h("solo")]
        leaves, nodes = crypto.merkle_multiproof(tx_one, [0])
        self.assertEqual(nodes, [])
        self.assertEqual(
            leaves, [{"tx_id": tx_one[0], "index": 0}]
        )

    def test_response_shapes_sorted_and_minimal(self) -> None:
        # 5 leaves (odd levels all the way up), selecting the last leaf.
        tx_ids = sorted(h(f"o-{i}") for i in range(5))
        leaves, nodes = crypto.merkle_multiproof(tx_ids, [4])
        # The lone last leaf self-pairs at level 0; only the level-1 pair
        # covering leaves 0..3 is an external sibling, then nothing more.
        self.assertEqual(
            [(n["level"], n["index"]) for n in nodes], [(2, 0)]
        )
        for node in nodes:
            self.assertEqual(set(node), {"level", "index", "hash"})
            self.assertTrue(crypto.is_hex64(node["hash"]))
        for leaf in leaves:
            self.assertEqual(set(leaf), {"tx_id", "index"})

        # 8 leaves selecting leaf 0: three successive right siblings.
        tx_ids = sorted(h(f"e-{i}") for i in range(8))
        leaves, nodes = crypto.merkle_multiproof(tx_ids, [0])
        self.assertEqual(
            [(n["level"], n["index"]) for n in nodes],
            [(0, 1), (1, 1), (2, 1)],
        )

        # Selecting leaves 0 and 1 shares their subtree: one fewer level-0
        # node than the union of the two single-leaf proofs.
        _, nodes_pair = crypto.merkle_multiproof(tx_ids, [0, 1])
        self.assertEqual(
            [(n["level"], n["index"]) for n in nodes_pair],
            [(1, 1), (2, 1)],
        )

        # Nodes sorted by level then index; leaves by index.
        tx_ids = sorted(h(f"m-{i}") for i in range(8))
        _, nodes = crypto.merkle_multiproof(tx_ids, [0, 3, 6])
        coords = [(n["level"], n["index"]) for n in nodes]
        self.assertEqual(coords, sorted(coords))

    def test_builder_rejects_bad_arguments(self) -> None:
        tx_ids = sorted(h(f"b-{i}") for i in range(3))
        with self.assertRaises(ValueError):
            crypto.merkle_multiproof([], [0])
        with self.assertRaises(ValueError):
            crypto.merkle_multiproof(tx_ids, [])
        with self.assertRaises(ValueError):
            crypto.merkle_multiproof(tx_ids, [3])
        with self.assertRaises(ValueError):
            crypto.merkle_multiproof(tx_ids, [-1])
        with self.assertRaises(ValueError):
            crypto.merkle_multiproof(tx_ids, [True])


class MultiproofCryptoVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tx_ids = sorted(h(f"t-{i}") for i in range(8))
        self.root = crypto.merkle_root(self.tx_ids)
        self.block_hash = h("block")
        self.good = make_document(self.tx_ids, [0, 3, 6], self.block_hash)

    def rejects(self, mutated, **trusted) -> None:
        block_hash = trusted.get("block_hash", self.block_hash)
        root = trusted.get("root", self.root)
        leaf_count = trusted.get("leaf_count", 8)
        self.assertFalse(
            crypto.verify_merkle_multiproof(mutated, block_hash, root, leaf_count),
            mutated,
        )

    def test_good_document_verifies_in_any_key_order(self) -> None:
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                self.good, self.block_hash, self.root, 8
            )
        )
        reordered = {
            key: self.good[key]
            for key in ("nodes", "leaves", "leaf_count", "merkle_root",
                        "block_hash", "height")
        }
        self.assertTrue(
            crypto.verify_merkle_multiproof(reordered, self.block_hash, self.root, 8)
        )
        # Nested entry key order is irrelevant as well.
        shuffled = copy.deepcopy(self.good)
        shuffled["leaves"][0] = {
            "index": shuffled["leaves"][0]["index"],
            "tx_id": shuffled["leaves"][0]["tx_id"],
        }
        shuffled["nodes"][0] = {
            "hash": shuffled["nodes"][0]["hash"],
            "level": shuffled["nodes"][0]["level"],
            "index": shuffled["nodes"][0]["index"],
        }
        self.assertTrue(
            crypto.verify_merkle_multiproof(shuffled, self.block_hash, self.root, 8)
        )

    def test_missing_and_extract_top_level_keys(self) -> None:
        for key in list(self.good):
            mutated = dict(self.good)
            del mutated[key]
            self.rejects(mutated)
        mutated = dict(self.good)
        mutated["extra"] = 1
        self.rejects(mutated)

    def test_strict_integer_types(self) -> None:
        for bad_height in ("7", 7.0, True, -1, None, []):
            mutated = copy.deepcopy(self.good)
            mutated["height"] = bad_height
            self.rejects(mutated)
        for bad_count in (0, -1, "8", 8.0, True, None, 9):
            mutated = copy.deepcopy(self.good)
            mutated["leaf_count"] = bad_count
            self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["leaves"][0]["index"] = "0"
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["leaves"][1]["index"] = True
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["nodes"][0]["level"] = "0"
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["nodes"][0]["index"] = False
        self.rejects(mutated)
        # Trusted leaf count must be a positive non-boolean int.
        self.rejects(self.good, leaf_count=0)
        self.rejects(self.good, leaf_count=True)
        self.rejects(self.good, leaf_count="8")
        self.rejects(self.good, leaf_count=7)

    def test_bad_hashes_and_anchors(self) -> None:
        for bad_hash in (self.root.upper(), "z" * 64, self.root[:63], 123, None):
            mutated = copy.deepcopy(self.good)
            mutated["block_hash"] = bad_hash
            self.rejects(mutated)
            mutated = copy.deepcopy(self.good)
            mutated["merkle_root"] = bad_hash
            self.rejects(mutated)
            mutated = copy.deepcopy(self.good)
            mutated["nodes"][0]["hash"] = bad_hash
            self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["leaves"][0]["tx_id"] = h("other")
        self.rejects(mutated)
        self.rejects(self.good, block_hash=h("other-block"))
        self.rejects(self.good, root=h("other-root"))
        self.rejects(self.good, block_hash="abc")
        self.rejects(self.good, root=7)

    def test_leaf_ordering_uniqueness_and_range(self) -> None:
        # Not strictly ascending by index.
        mutated = copy.deepcopy(self.good)
        mutated["leaves"].reverse()
        self.rejects(mutated)
        # Duplicate index.
        mutated = copy.deepcopy(self.good)
        mutated["leaves"].append(dict(mutated["leaves"][0]))
        self.rejects(mutated)
        # Out-of-range index.
        mutated = copy.deepcopy(self.good)
        mutated["leaves"][-1]["index"] = 8
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["leaves"][0]["index"] = -1
        self.rejects(mutated)
        # tx_ids must be strictly ascending too.
        mutated = copy.deepcopy(self.good)
        mutated["leaves"][0]["tx_id"], mutated["leaves"][1]["tx_id"] = (
            mutated["leaves"][1]["tx_id"],
            mutated["leaves"][0]["tx_id"],
        )
        self.rejects(mutated)
        # Empty / wrong-typed leaves.
        mutated = copy.deepcopy(self.good)
        mutated["leaves"] = []
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["leaves"] = tuple(self.good["leaves"])
        self.rejects(mutated)
        # Bad leaf key set.
        mutated = copy.deepcopy(self.good)
        mutated["leaves"][0]["extra"] = 1
        self.rejects(mutated)

    def test_node_coordinates_sorted_unique_and_real(self) -> None:
        # Out-of-order coordinates.
        mutated = copy.deepcopy(self.good)
        mutated["nodes"].reverse()
        self.rejects(mutated)
        # Duplicate coordinate.
        mutated = copy.deepcopy(self.good)
        mutated["nodes"].append(dict(mutated["nodes"][0]))
        self.rejects(mutated)
        # Coordinate beyond the level's real size.
        mutated = copy.deepcopy(self.good)
        mutated["nodes"][0]["index"] = 7
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["nodes"][0]["level"] = 9
        self.rejects(mutated)
        # A node sharing a selected-leaf coordinate at level 0.
        tx3 = sorted(h(f"three-{i}") for i in range(3))
        doc = make_document(tx3, [0], self.block_hash)
        tampered = copy.deepcopy(doc)
        tampered["nodes"].append({"level": 0, "index": 0, "hash": tx3[0]})
        tampered["nodes"].sort(key=lambda n: (n["level"], n["index"]))
        self.rejects(tampered, leaf_count=3)
        # Bad node key set / wrong container type.
        mutated = copy.deepcopy(self.good)
        mutated["nodes"][0]["side"] = 1
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["nodes"] = tuple(self.good["nodes"])
        self.rejects(mutated)
        mutated = copy.deepcopy(self.good)
        mutated["nodes"] = None
        self.rejects(mutated)

    def test_missing_redundant_and_unrelated_nodes_rejected(self) -> None:
        # Drop a required node.
        mutated = copy.deepcopy(self.good)
        mutated["nodes"].pop()
        self.rejects(mutated)
        # A node whose coordinate the leaves already derive (redundant).
        tx4 = sorted(h(f"four-{i}") for i in range(4))
        doc = make_document(tx4, [0, 1], self.block_hash)
        levels = crypto._merkle_levels(tx4)
        tampered = copy.deepcopy(doc)
        tampered["nodes"].insert(
            0,
            {"level": 1, "index": 0, "hash": levels[1][0]},
        )
        self.assertFalse(
            crypto.verify_merkle_multiproof(tampered, self.block_hash,
                                            crypto.merkle_root(tx4), 4)
        )
        # An entirely unrelated extra subtree still hashing to the same root
        # is not part of the canonical minimal set.
        tx8 = sorted(h(f"eight-{i}") for i in range(8))
        doc = make_document(tx8, [0], self.block_hash)
        tampered = copy.deepcopy(doc)
        tampered["nodes"].append({"level": 0, "index": 6, "hash": tx8[6]})
        tampered["nodes"].sort(key=lambda n: (n["level"], n["index"]))
        self.assertFalse(
            crypto.verify_merkle_multiproof(tampered, self.block_hash,
                                            crypto.merkle_root(tx8), 8)
        )
        # A node with the right coordinate but wrong hash.
        mutated = copy.deepcopy(self.good)
        mutated["nodes"][0]["hash"] = h("tampered")
        self.rejects(mutated)

    def test_full_selection_requires_empty_nodes(self) -> None:
        doc = make_document(self.tx_ids, list(range(8)), self.block_hash)
        self.assertTrue(
            crypto.verify_merkle_multiproof(doc, self.block_hash, self.root, 8)
        )
        tampered = copy.deepcopy(doc)
        tampered["nodes"] = [
            {"level": 0, "index": 0, "hash": self.tx_ids[0]}
        ]
        self.rejects(tampered)

    def test_odd_self_pair_has_no_phantom_sibling(self) -> None:
        # 3 leaves, selecting the last one: level-0 self-pair contributes no
        # sibling node; the proof still verifies, and a phantom level-0 node
        # at coordinate 2 (or at the duplicated odd slot) is rejected.
        tx3 = sorted(h(f"odd-{i}") for i in range(3))
        root = crypto.merkle_root(tx3)
        doc = make_document(tx3, [2], self.block_hash)
        self.assertEqual(
            [(n["level"], n["index"]) for n in doc["nodes"]], [(1, 0)]
        )
        self.assertTrue(
            crypto.verify_merkle_multiproof(doc, self.block_hash, root, 3)
        )
        tampered = copy.deepcopy(doc)
        tampered["nodes"].append({"level": 0, "index": 2, "hash": tx3[2]})
        tampered["nodes"].sort(key=lambda n: (n["level"], n["index"]))
        self.assertFalse(
            crypto.verify_merkle_multiproof(tampered, self.block_hash, root, 3)
        )

    def test_junk_inputs_never_raise(self) -> None:
        for junk in (None, 42, "string", [], [1], {"height": 1}, object()):
            self.assertFalse(
                crypto.verify_merkle_multiproof(
                    junk, self.block_hash, self.root, 8
                )
            )
        # Trusted arguments of bad types must likewise be False, not raise.
        for bad_hash in (None, 7, b"x", []):
            self.assertFalse(
                crypto.verify_merkle_multiproof(self.good, bad_hash, self.root, 8)
            )
            self.assertFalse(
                crypto.verify_merkle_multiproof(self.good, self.block_hash, bad_hash, 8)
            )


class MultiproofServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.svc = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
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
            dict(store.idempotency),
        )

    def test_success_shape_order_and_verification(self) -> None:
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
            self.tx(self.kb, self.B, self.A, 9),
            self.tx(self.ka, self.A, self.B, 1),
        ]
        block = self.mine()
        ordered = sorted(ids)

        status, body = self.svc.get_multiproof("1", {"tx_ids": [ids[4], ids[0]]})
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "merkle_root", "leaf_count", "leaves", "nodes"],
        )
        self.assertEqual(body["height"], 1)
        self.assertEqual(body["block_hash"], block["block_hash"])
        self.assertEqual(body["merkle_root"], block["merkle_root"])
        self.assertEqual(body["leaf_count"], 5)
        # Only the requested leaves, ascending by block index (which matches
        # ascending tx_id in a block).
        selected = {ids[4], ids[0]}
        expected_leaves = [
            {"tx_id": tx_id, "index": index}
            for index, tx_id in enumerate(ordered)
            if tx_id in selected
        ]
        self.assertEqual(body["leaves"], expected_leaves)
        for leaf in body["leaves"]:
            self.assertEqual(list(leaf.keys()), ["tx_id", "index"])
        coords = [(n["level"], n["index"]) for n in body["nodes"]]
        self.assertEqual(coords, sorted(coords))
        for node in body["nodes"]:
            self.assertEqual(list(node.keys()), ["level", "index", "hash"])
            self.assertTrue(crypto.is_hex64(node["hash"]))
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                body, block["block_hash"], block["merkle_root"], 5
            )
        )

    def test_request_permutation_does_not_change_response(self) -> None:
        ids = [self.tx(self.ka, self.A, self.B, i) for i in range(1, 4)]
        block = self.mine()
        _, first = self.svc.get_multiproof("1", {"tx_ids": ids})
        _, second = self.svc.get_multiproof("1", {"tx_ids": list(reversed(ids))})
        self.assertEqual(first, second)
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                first, block["block_hash"], block["merkle_root"], 3
            )
        )

    def test_full_selection_and_single_tx_block_have_empty_nodes(self) -> None:
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
        ]
        block = self.mine()
        status, body = self.svc.get_multiproof("1", {"tx_ids": ids})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["nodes"], [])
        self.assertEqual(body["leaf_count"], 3)
        self.assertEqual(len(body["leaves"]), 3)
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                body, block["block_hash"], block["merkle_root"], 3
            )
        )

        solo = self.tx(self.kb, self.B, self.A, 4)
        block2 = self.mine()
        status, body = self.svc.get_multiproof("2", {"tx_ids": [solo]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["leaf_count"], 1)
        self.assertEqual(body["nodes"], [])
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                body, block2["block_hash"], block2["merkle_root"], 1
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
            {"tx_ids": valid},
            {"tx_ids": (valid,)},
            {"tx_ids": {valid}},
            {"tx_ids": [valid], "extra": 1},
            {"proofs": [valid]},
        ]
        for body in bad_bodies:
            before = self.fingerprint()
            status, error = self.svc.get_multiproof("1", body)
            self.assertEqual(status, 400, (body, error))
            self.assertIn("error", error)
            self.assertEqual(self.fingerprint(), before)

        for ids in (
            [valid, "b" * 63],
            [valid, "B" * 64],
            [valid, "z" * 64],
            [123],
            [None],
            [valid, 1.5],
        ):
            before = self.fingerprint()
            status, error = self.svc.get_multiproof("1", {"tx_ids": ids})
            self.assertEqual(status, 400, (ids, error))
            self.assertEqual(self.fingerprint(), before)

    def test_body_validation_precedes_height_parsing(self) -> None:
        status, _ = self.svc.get_multiproof("not-a-height", {"tx_ids": []})
        self.assertEqual(status, 400)
        status, _ = self.svc.get_multiproof("01", {})
        self.assertEqual(status, 400)

    def test_lookup_semantics(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        self.mine()

        # Malformed heights: strict non-negative ASCII decimal, no leading
        # zeros, signs, whitespace or non-ASCII digits.
        for bad_height in ("x", "01", "00", "+1", "-1", " 1", "1 ", "1.0",
                           "١", "1e0"):
            status, _ = self.svc.get_multiproof(bad_height, {"tx_ids": [tx_id]})
            self.assertEqual(status, 404, bad_height)
        # Unknown but well-formed height.
        self.assertEqual(
            self.svc.get_multiproof("99", {"tx_ids": [tx_id]})[0], 404
        )
        self.assertEqual(
            self.svc.get_multiproof("99", {"tx_ids": [tx_id]})[0], 404
        )
        # Empty genesis never holds the transaction.
        self.assertEqual(
            self.svc.get_multiproof("0", {"tx_ids": [tx_id]})[0], 404
        )
        # One missing id among valid ids fails the whole batch with no
        # partial proof.
        self.assertEqual(
            self.svc.get_multiproof("1", {"tx_ids": [tx_id, "a" * 64]})[0], 404
        )
        # A transaction still in the mempool is in no block.
        other = self.tx(self.kb, self.B, self.A, 1)
        self.assertEqual(
            self.svc.get_multiproof("1", {"tx_ids": [other]})[0], 404
        )

    def test_pending_block_is_409(self) -> None:
        tx_id = self.tx(self.ka, self.A, self.B, 10)
        self.mine(confirm=False)
        status, body = self.svc.get_multiproof("1", {"tx_ids": [tx_id]})
        self.assertEqual(status, 409, body)

    def test_read_only_does_not_change_generation_audit_or_idempotency(self) -> None:
        ids = [self.tx(self.ka, self.A, self.B, 10)]
        block = self.mine()
        before = self.fingerprint()
        for _ in range(3):
            status, _ = self.svc.get_multiproof("1", {"tx_ids": ids})
            self.assertEqual(status, 200)
        # Also exercise failure paths.
        self.svc.get_multiproof("1", {"tx_ids": ["a" * 64]})
        self.svc.get_multiproof("99", {"tx_ids": ids})
        self.assertEqual(self.fingerprint(), before)
        self.assertIsNotNone(block)

    def test_same_document_after_restart(self) -> None:
        ids = [
            self.tx(self.ka, self.A, self.B, 3),
            self.tx(self.kb, self.B, self.A, 2),
            self.tx(self.ka, self.A, self.B, 5),
        ]
        block = self.mine()
        _, before = self.svc.get_multiproof(
            "1", {"tx_ids": [ids[2], ids[0]]}
        )
        reopened = LedgerService(
            LedgerStore(self.path), initial_balance=100_000
        )
        status, after = reopened.get_multiproof(
            "1", {"tx_ids": [ids[0], ids[2]]}
        )
        self.assertEqual(status, 200, after)
        self.assertEqual(after, before)
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                after, block["block_hash"], block["merkle_root"], 3
            )
        )


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
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
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
        p1 = make_tx(self.ka, self.A, self.B, 10)
        p2 = make_tx(self.kb, self.B, self.A, 4)
        p3 = make_tx(self.ka, self.A, self.B, 7)
        txs = []
        for payload in (p1, p2, p3):
            status, body = self.request("POST", "/v1/transactions", payload)
            self.assertEqual(status, 202)
            txs.append(body["tx_id"])
        status, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(status, 201)
        height = block["height"]
        status, _ = self.request("POST", f"/v1/blocks/{height}/confirm", {})
        self.assertEqual(status, 200)

        req = urllib.request.Request(
            f"{self.base}/v1/blocks/{height}/multiproof",
            data=json.dumps({"tx_ids": [txs[2], txs[0]]}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            status = resp.status
        body = json.loads(raw)
        self.assertEqual(status, 200)
        # Contract-fixed top-level key order on the wire.
        self.assertTrue(raw.startswith('{"height"'))
        self.assertEqual(
            list(body.keys()),
            ["height", "block_hash", "merkle_root", "leaf_count", "leaves", "nodes"],
        )
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
        ordered = sorted(txs)
        selected = {txs[2], txs[0]}
        expected_leaves = [
            {"tx_id": tx_id, "index": index}
            for index, tx_id in enumerate(ordered)
            if tx_id in selected
        ]
        self.assertEqual(body["leaves"], expected_leaves)
        for node in body["nodes"]:
            self.assertEqual(set(node), {"level", "index", "hash"})
        self.assertTrue(
            crypto.verify_merkle_multiproof(
                body, block["block_hash"], block["merkle_root"], 3
            )
        )

        # 400: invalid JSON / empty body / bad shapes.
        self.assertEqual(
            self.post_raw(f"/v1/blocks/{height}/multiproof", b"{not json")[0], 400
        )
        self.assertEqual(
            self.post_raw(f"/v1/blocks/{height}/multiproof", b"")[0], 400
        )
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/multiproof", [])[0], 400
        )
        self.assertEqual(
            self.request("POST", f"/v1/blocks/{height}/multiproof", {})[0], 400
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof",
                {"tx_ids": [txs[0]], "more": 1},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof", {"tx_ids": []}
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof",
                {"tx_ids": [txs[0], txs[0]]},
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof",
                {"tx_ids": ["Z" * 64]},
            )[0],
            400,
        )

        # 404: malformed/unknown height, missing transaction.
        for bad_height in ("01", "x", "+1"):
            self.assertEqual(
                self.request(
                    "POST", f"/v1/blocks/{bad_height}/multiproof",
                    {"tx_ids": [txs[0]]},
                )[0],
                404,
            )
        self.assertEqual(
            self.request(
                "POST", "/v1/blocks/999/multiproof", {"tx_ids": [txs[0]]}
            )[0],
            404,
        )
        self.assertEqual(
            self.request(
                "POST", f"/v1/blocks/{height}/multiproof",
                {"tx_ids": ["a" * 64]},
            )[0],
            404,
        )

    def test_pending_block_is_409_over_http(self) -> None:
        payload = make_tx(self.ka, self.A, self.B, 11)
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
