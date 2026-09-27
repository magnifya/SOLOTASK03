"""Tests for ``ledger.light_client.receipt_proof``.

The read-only Merkle inclusion proof over the durable finalized-receipt
index (v1 format unchanged):

* leaves are the index items in their stored ascending ``tx_id`` order,
  each leaf ``SHA256(canonical_json(item))`` as 64 lowercase hex; parents
  are ``SHA256(ascii(left_hex + right_hex))`` with odd-node self-pairing.
* the success key order is ``ok, generation, finalized, root, item,
  index, siblings`` with ``generation``/``finalized``/``item`` taken from
  the index, ``index`` the 0-based leaf position and ``siblings`` the
  leaf-to-root path of ``{direction, hash}`` items; the sibling path
  recomputes to ``root``.
* error classification: a bad path or ``tx_id`` shape is ``input``, a
  missing or unreadable file is ``io``, an index failing its strict load
  checks (encoding, JSON, v1 key order, digest, item ordering or any
  item's stored semantics) is ``state`` and an unknown id is
  ``not_found``. Nothing is raised, the file is never modified and the
  same bytes yield the same result.

Run: python3 tests/receipt_proof_test.py
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    _canonical_json_bytes,
    advance_receipts,
    receipt_proof,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

RESULT_KEYS = [
    "ok",
    "generation",
    "finalized",
    "root",
    "item",
    "index",
    "siblings",
]
ITEM_KEYS = ["receipt", "proof"]
SIBLING_KEYS = ["direction", "hash"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def leaf_of(item: dict) -> str:
    return hashlib.sha256(_canonical_json_bytes(item)).hexdigest()


def pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("ascii")).hexdigest()


def replay(leaf: str, index: int, siblings: list[dict]) -> str:
    current = leaf
    position = index
    for sibling in siblings:
        if sibling["direction"] == "left":
            current = pair(sibling["hash"], current)
        else:
            current = pair(current, sibling["hash"])
        position //= 2
    return current


class ReceiptProofFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "ledger.json"))
        )
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        self.trust = self.service.get_trust_document()[1]
        self.path = os.path.join(self.tmp, "receipts.json")

    def tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def mine_confirmed_block(self, amounts: tuple[int, ...]) -> list[str]:
        ids = []
        for amount in amounts:
            status, body = self.service.submit_transaction(self.tx(amount))
            self.assertEqual(status, 202, body)
            ids.append(body["tx_id"])
        status, block = self.service.mine_block()
        self.assertEqual(status, 201, block)
        self.assertEqual(
            self.service.confirm_block(str(block["height"]))[0], 200
        )
        return sorted(ids)

    def fetch(self, tx_ids: list[str]) -> dict:
        status, body = self.service.get_finalized_receipts(
            {"tx_ids": tx_ids}
        )
        self.assertEqual(status, 200, body)
        return body

    def populate(self) -> list[str]:
        ids = self.mine_confirmed_block((10, 20, 30))
        document = self.fetch(ids)
        result = advance_receipts(self.path, document, ids, self.trust)
        self.assertTrue(result["ok"], result)
        return ids

    def read_index(self) -> dict:
        with open(self.path, "rb") as fh:
            return json.loads(fh.read())

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()


class ReceiptProofSuccessTests(ReceiptProofFixture):
    def setUp(self) -> None:
        super().setUp()
        self.ids = self.populate()
        self.stored = self.read_index()

    def test_success_key_order_and_fields(self) -> None:
        for position, tx_id in enumerate(self.ids):
            result = receipt_proof(self.path, tx_id)
            self.assertEqual(tuple(result), tuple(RESULT_KEYS))
            self.assertIs(result["ok"], True)
            self.assertEqual(result["generation"], self.stored["generation"])
            self.assertEqual(result["finalized"], self.stored["finalized"])
            self.assertEqual(list(result["finalized"]), ["height", "block_hash"])
            self.assertEqual(result["item"], self.stored["items"][position])
            self.assertEqual(list(result["item"]), ITEM_KEYS)
            self.assertEqual(result["index"], position)
            self.assertIsInstance(result["index"], int)
            self.assertRegex(result["root"], r"^[0-9a-f]{64}$")

    def test_root_matches_manual_tree(self) -> None:
        leaves = [leaf_of(item) for item in self.stored["items"]]
        # Three leaves: pair the first two, self-pair the odd third.
        expected = pair(pair(leaves[0], leaves[1]), pair(leaves[2], leaves[2]))
        for tx_id in self.ids:
            self.assertEqual(receipt_proof(self.path, tx_id)["root"], expected)

    def test_siblings_recompute_to_root(self) -> None:
        for position, tx_id in enumerate(self.ids):
            result = receipt_proof(self.path, tx_id)
            siblings = result["siblings"]
            self.assertIsInstance(siblings, list)
            for sibling in siblings:
                self.assertEqual(list(sibling), SIBLING_KEYS)
                self.assertIn(sibling["direction"], ("left", "right"))
                self.assertRegex(sibling["hash"], r"^[0-9a-f]{64}$")
            leaf = leaf_of(result["item"])
            self.assertEqual(
                replay(leaf, result["index"], siblings), result["root"]
            )

    def test_sibling_directions_match_positions(self) -> None:
        # Leaf 0 is a left child (right sibling), leaf 1 a right child
        # (left sibling); leaf 2 is the odd node and self-pairs right.
        first = receipt_proof(self.path, self.ids[0])["siblings"]
        second = receipt_proof(self.path, self.ids[1])["siblings"]
        third = receipt_proof(self.path, self.ids[2])["siblings"]
        self.assertEqual(first[0]["direction"], "right")
        self.assertEqual(second[0]["direction"], "left")
        self.assertEqual(third[0]["direction"], "right")
        leaves = [leaf_of(item) for item in self.stored["items"]]
        self.assertEqual(third[0]["hash"], leaves[2])
        self.assertEqual(first[0]["hash"], leaves[1])
        self.assertEqual(second[0]["hash"], leaves[0])

    def test_single_item_index_has_empty_path(self) -> None:
        other = os.path.join(self.tmp, "single.json")
        ids = self.mine_confirmed_block((40,))
        document = self.fetch(ids)
        self.assertTrue(
            advance_receipts(other, document, ids, self.trust)["ok"]
        )
        result = receipt_proof(other, ids[0])
        self.assertEqual(tuple(result), tuple(RESULT_KEYS))
        self.assertEqual(result["index"], 0)
        self.assertEqual(result["siblings"], [])
        self.assertEqual(result["root"], leaf_of(result["item"]))

    def test_deterministic_and_does_not_modify_file(self) -> None:
        before = self.read_raw()
        first = receipt_proof(self.path, self.ids[0])
        second = receipt_proof(self.path, self.ids[0])
        self.assertEqual(first, second)
        self.assertEqual(self.read_raw(), before)


class ReceiptProofFailureTests(ReceiptProofFixture):
    def setUp(self) -> None:
        super().setUp()
        self.ids = self.populate()

    def test_unknown_tx_id_is_not_found(self) -> None:
        result = receipt_proof(self.path, "0" * 64)
        self.assertEqual(result, {"ok": False, "error": "not_found"})

    def test_missing_file_is_io(self) -> None:
        result = receipt_proof(
            os.path.join(self.tmp, "absent.json"), self.ids[0]
        )
        self.assertEqual(result, {"ok": False, "error": "io"})

    def test_unreadable_file_is_io(self) -> None:
        path = os.path.join(self.tmp, "dir.json")
        os.mkdir(path)
        result = receipt_proof(path, self.ids[0])
        self.assertEqual(result, {"ok": False, "error": "io"})

    def test_bad_arguments_are_input(self) -> None:
        for bad_path in ("", None, 7, object()):
            self.assertEqual(
                receipt_proof(bad_path, self.ids[0]),  # type: ignore[arg-type]
                {"ok": False, "error": "input"},
            )
        for bad_id in ("", "0" * 63, "0" * 65, "A" * 64, None, 7):
            self.assertEqual(
                receipt_proof(self.path, bad_id),  # type: ignore[arg-type]
                {"ok": False, "error": "input"},
            )

    def test_malformed_json_is_state(self) -> None:
        with open(self.path, "wb") as fh:
            fh.write(b"{not json")
        self.assertEqual(
            receipt_proof(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )

    def test_bad_encoding_is_state(self) -> None:
        with open(self.path, "wb") as fh:
            fh.write(b"\xff\xfe{}")
        self.assertEqual(
            receipt_proof(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )

    def test_tampered_digest_is_state(self) -> None:
        data = self.read_index()
        data["hash"] = "0" * 64
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, separators=(",", ":")) + "\n")
        self.assertEqual(
            receipt_proof(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )

    def test_resealed_tampered_item_is_state(self) -> None:
        # A fresh hash over tampered content still fails the per-item
        # semantic replay on load.
        data = self.read_index()
        tampered = copy.deepcopy(data)
        tampered["items"][0]["receipt"]["status"] = "pending"
        body = {key: tampered[key] for key in tampered if key != "hash"}
        tampered["hash"] = hashlib.sha256(
            _canonical_json_bytes(body)
        ).hexdigest()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tampered, separators=(",", ":")) + "\n")
        self.assertEqual(
            receipt_proof(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )

    def test_unsorted_items_is_state(self) -> None:
        data = self.read_index()
        tampered = copy.deepcopy(data)
        tampered["items"] = list(reversed(tampered["items"]))
        body = {key: tampered[key] for key in tampered if key != "hash"}
        tampered["hash"] = hashlib.sha256(
            _canonical_json_bytes(body)
        ).hexdigest()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tampered, separators=(",", ":")) + "\n")
        self.assertEqual(
            receipt_proof(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )

    def test_junk_does_not_raise(self) -> None:
        result = receipt_proof(object(), None)  # type: ignore[arg-type]
        self.assertEqual(result, {"ok": False, "error": "input"})


if __name__ == "__main__":
    unittest.main()
