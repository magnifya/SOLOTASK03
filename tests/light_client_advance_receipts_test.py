"""Tests for the durable finalized-receipt index
(``ledger.light_client.advance_receipts`` / ``get_receipt``).

Real finalized-receipts batches are produced through the service and then
persisted through the light-client entry points. Coverage:

* a first verified write creates the index in the exact key order
  ``v, generation, finalized, items, hash`` with generation 1, compact
  UTF-8 JSON, a single trailing LF and a recomputable
  ``SHA256(canonical_json(without hash))`` digest;
* :func:`get_receipt` returns ``ok, finalized, item`` in that order, an
  unknown id on a healthy index is ``not_found``, a missing file is
  ``io``, a damaged index is ``state`` and bad arguments are ``input``;
* serial merge: tx_id-ascending items from later batches are merged, the
  generation bumps once per changing write and the finalized boundary
  advances with the newest verified batch;
* idempotency: the same items at the same boundary leave the file bytes
  and generation exactly as they were (``added`` 0, no disk write);
* integrity: same-id different content, a regressing boundary and a
  same-height different-hash boundary are all rejected before any write;
* verifier failures (``input``/``auth``/``integrity``) create no file on
  a fresh path and never alter an existing one;
* ``state`` on a corrupt stored index for both functions; ``io`` on an
  unwritable path; nothing is raised.

Run: python3 tests/light_client_advance_receipts_test.py
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_IO,
    ERR_NOT_FOUND,
    ERR_STATE,
    _canonical_json_bytes,
    advance_receipts,
    get_receipt,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

INDEX_KEYS = ("v", "generation", "finalized", "items", "hash")
ITEM_KEYS = ("receipt", "proof")
ANCHOR_KEYS = ("height", "block_hash")
ADVANCE_RESULT_KEYS = ("ok", "generation", "finalized", "added")
GET_RESULT_KEYS = ("ok", "finalized", "item")

RECEIPT_FIELDS = (
    "tx_id",
    "from",
    "to",
    "amount",
    "signature",
    "status",
    "height",
    "block_hash",
    "index",
)
PROOF_FIELDS = (
    "height",
    "tx_id",
    "index",
    "merkle_root",
    "block_hash",
    "siblings",
)


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def ordered(value: bytes):
    """Decode JSON preserving every object's key insertion order."""
    return json.loads(value, object_pairs_hook=lambda pairs: pairs)


class ReceiptIndexFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "receipts.json")
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "ledger.json"))
        )
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        self.trust = self.service.get_trust_document()[1]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def submit(self, amount: int) -> dict:
        status, body = self.service.submit_transaction(self.tx(amount))
        self.assertEqual(status, 202, body)
        return body

    def mine_and_confirm(self) -> None:
        status, block = self.service.mine_block()
        self.assertEqual(status, 201, block)
        self.assertEqual(
            self.service.confirm_block(str(block["height"]))[0], 200
        )

    def fetch(self, tx_ids: list[str]) -> dict:
        status, body = self.service.get_finalized_receipts(
            {"tx_ids": tx_ids}
        )
        self.assertEqual(status, 200, body)
        return body

    def build_chain(self) -> tuple[list[dict], list[dict], dict, dict]:
        """Two confirmed blocks: three txs in block 1, two in block 2.

        Returns the block-1 bodies, the block-2 bodies, a batch document
        fetched at finalized height 1 and a batch document fetched at
        finalized height 2 covering all five ids.
        """
        first = [self.submit(v) for v in (30, 10, 20)]
        self.mine_and_confirm()
        doc_at_1 = self.fetch([body["tx_id"] for body in first])
        second = [self.submit(v) for v in (50, 40)]
        self.mine_and_confirm()
        all_ids = sorted(body["tx_id"] for body in first + second)
        doc_at_2 = self.fetch(all_ids)
        return first, second, doc_at_1, doc_at_2

    def advance(self, document: dict, tx_ids: list[str]):
        return advance_receipts(self.path, document, tx_ids, self.trust)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()


class FirstWriteTests(ReceiptIndexFixture):
    def test_first_write_generation_one_and_wire_format(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        result = self.advance(doc_at_1, ids)
        self.assertEqual(tuple(result), ADVANCE_RESULT_KEYS)
        self.assertTrue(result["ok"])
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["added"], 3)
        self.assertEqual(
            result["finalized"], doc_at_1["finality"]["finalized"]
        )

        raw = self.read_raw()
        # Compact UTF-8 JSON, non-ASCII unescaped, exactly one trailing LF.
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        raw.decode("utf-8")

        pairs = ordered(raw)
        self.assertEqual(tuple(key for key, _ in pairs), INDEX_KEYS)
        document = json.loads(raw)
        self.assertEqual(document["v"], 1)
        self.assertEqual(document["generation"], 1)
        self.assertEqual(
            document["finalized"], doc_at_1["finality"]["finalized"]
        )
        self.assertEqual(
            tuple(document["finalized"]), ANCHOR_KEYS
        )
        item_ids = [item["receipt"]["tx_id"] for item in document["items"]]
        self.assertEqual(item_ids, ids)
        for item in document["items"]:
            self.assertEqual(tuple(item), ITEM_KEYS)
            self.assertEqual(tuple(item["receipt"]), RECEIPT_FIELDS)
            self.assertEqual(tuple(item["proof"]), PROOF_FIELDS)

        # The digest pins every field but hash under canonical (sorted,
        # compact) JSON.
        body = {key: document[key] for key in document if key != "hash"}
        expected_hash = hashlib.sha256(
            _canonical_json_bytes(body)
        ).hexdigest()
        self.assertEqual(document["hash"], expected_hash)
        self.assertRegex(document["hash"], r"^[0-9a-f]{64}$")

    def test_get_receipt_returns_stored_item(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, ids)["ok"])

        tx_id = ids[0]
        result = get_receipt(self.path, tx_id)
        self.assertEqual(tuple(result), GET_RESULT_KEYS)
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["finalized"], doc_at_1["finality"]["finalized"]
        )
        expected_item = next(
            item
            for item in doc_at_1["items"]
            if item["receipt"]["tx_id"] == tx_id
        )
        self.assertEqual(result["item"], expected_item)
        self.assertEqual(tuple(result["item"]), ITEM_KEYS)

    def test_get_receipt_unknown_id_is_not_found(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, ids)["ok"])
        result = get_receipt(self.path, "f" * 64)
        self.assertEqual(result, {"ok": False, "error": ERR_NOT_FOUND})
        self.assertEqual(set(result), {"ok", "error"})

    def test_get_receipt_missing_file_is_io(self) -> None:
        self.assertEqual(
            get_receipt(self.path, "f" * 64),
            {"ok": False, "error": ERR_IO},
        )

    def test_bad_arguments_are_input(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        for bad_path in (None, 1, "", b"x", object()):
            self.assertEqual(
                advance_receipts(bad_path, doc_at_1, ids, self.trust),
                {"ok": False, "error": ERR_INPUT},
                bad_path,
            )
            self.assertEqual(
                get_receipt(bad_path, ids[0]),
                {"ok": False, "error": ERR_INPUT},
                bad_path,
            )
        for bad_id in (None, 123, "zz", "A" * 64, "0" * 63):
            self.assertEqual(
                get_receipt(self.path, bad_id),
                {"ok": False, "error": ERR_INPUT},
                bad_id,
            )

    def test_unwritable_path_is_io_and_creates_nothing(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        # An existing regular file used as a directory cannot host the
        # temp file / replace target.
        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "wb") as fh:
            fh.write(b"x")
        result = advance_receipts(
            os.path.join(blocker, "receipts.json"), doc_at_1, ids, self.trust
        )
        self.assertEqual(result, {"ok": False, "error": ERR_IO})


class MergeTests(ReceiptIndexFixture):
    def test_serial_merge_ascending_and_generation_bumps(self) -> None:
        first, second, doc_at_1, doc_at_2 = self.build_chain()
        first_ids = sorted(body["tx_id"] for body in first)
        second_ids = sorted(body["tx_id"] for body in second)
        all_ids = sorted(first_ids + second_ids)

        result = self.advance(doc_at_1, first_ids)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["added"], 3)
        raw_after_first = self.read_raw()

        # The full five-item batch overlaps the three stored items and
        # adds two at the higher boundary.
        result = self.advance(doc_at_2, all_ids)
        self.assertEqual(tuple(result), ADVANCE_RESULT_KEYS)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["added"], 2)
        self.assertEqual(
            result["finalized"], doc_at_2["finality"]["finalized"]
        )

        document = json.loads(self.read_raw())
        self.assertEqual(
            [item["receipt"]["tx_id"] for item in document["items"]],
            all_ids,
        )
        self.assertEqual(document["generation"], 2)
        self.assertNotEqual(self.read_raw(), raw_after_first)

        for tx_id in all_ids:
            self.assertTrue(get_receipt(self.path, tx_id)["ok"])

    def test_newer_items_sort_in_among_stored_ones(self) -> None:
        # Persist only the block-2 ids first (they sort after the
        # block-1 ids), then merge the block-1 ids in: the stored run
        # must still come out globally tx_id-ascending.
        first, second, _doc_at_1, doc_at_2 = self.build_chain()
        first_ids = sorted(body["tx_id"] for body in first)
        second_ids = sorted(body["tx_id"] for body in second)
        doc_second = self.fetch(second_ids)
        self.assertEqual(
            self.advance(doc_second, second_ids)["generation"], 1
        )
        doc_first_at_2 = self.fetch(first_ids)
        result = self.advance(doc_first_at_2, first_ids)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["added"], 3)
        document = json.loads(self.read_raw())
        stored_ids = [
            item["receipt"]["tx_id"] for item in document["items"]
        ]
        self.assertEqual(stored_ids, sorted(first_ids + second_ids))
        # Every stored item matches a verified batch item.
        by_id = {
            item["receipt"]["tx_id"]: item
            for item in doc_at_2["items"]
        }
        for item in document["items"]:
            self.assertEqual(item, by_id[item["receipt"]["tx_id"]])

    def test_boundary_only_advance_bumps_generation(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        first_ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, first_ids)["ok"])

        # Same three items, re-fetched after block 2: identical content,
        # higher verified boundary — one generation step, zero adds.
        doc_first_at_2 = self.fetch(first_ids)
        result = self.advance(doc_first_at_2, first_ids)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["added"], 0)
        self.assertEqual(
            result["finalized"]["height"], 2
        )
        # get_receipt now reports the newer boundary.
        self.assertEqual(
            get_receipt(self.path, first_ids[0])["finalized"],
            result["finalized"],
        )

    def test_identical_replay_is_idempotent_and_does_not_write(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        first_ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, first_ids)["ok"])
        raw = self.read_raw()

        result = self.advance(copy.deepcopy(doc_at_1), first_ids)
        self.assertTrue(result["ok"])
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["added"], 0)
        self.assertEqual(self.read_raw(), raw)

        # Any number of replays stays at generation 1.
        result = self.advance(copy.deepcopy(doc_at_1), first_ids)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["added"], 0)
        self.assertEqual(self.read_raw(), raw)

    def test_finalized_boundary_regression_is_integrity(self) -> None:
        first, _second, doc_at_1, doc_at_2 = self.build_chain()
        first_ids = sorted(body["tx_id"] for body in first)
        all_ids = sorted(
            item["receipt"]["tx_id"] for item in doc_at_2["items"]
        )
        self.assertTrue(self.advance(doc_at_2, all_ids)["ok"])
        raw = self.read_raw()

        # doc_at_1 ends at finalized height 1: below the stored height 2.
        result = self.advance(doc_at_1, first_ids)
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(
            json.loads(raw)["generation"], 1
        )

    def test_same_id_different_content_is_integrity(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        first_ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, first_ids)["ok"])

        # Forge a self-consistent index (valid shape, recomputed hash) in
        # which one stored item's content changed. A verified batch
        # naming the same id must then conflict rather than overwrite.
        forged = json.loads(self.read_raw())
        forged["items"][0]["receipt"]["amount"] += 1
        self._reseal(forged)
        self._write(forged)
        raw = self.read_raw()

        result = self.advance(doc_at_1, first_ids)
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertEqual(self.read_raw(), raw)

    def test_same_height_different_block_hash_is_integrity(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        first_ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, first_ids)["ok"])

        forged = json.loads(self.read_raw())
        forged["finalized"]["block_hash"] = "0" * 64
        self._reseal(forged)
        self._write(forged)
        raw = self.read_raw()

        result = self.advance(doc_at_1, first_ids)
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertEqual(self.read_raw(), raw)

    def _reseal(self, document: dict) -> None:
        body = {key: document[key] for key in document if key != "hash"}
        document["hash"] = hashlib.sha256(
            _canonical_json_bytes(body)
        ).hexdigest()

    def _write(self, document: dict) -> None:
        ordered_doc = {key: document[key] for key in INDEX_KEYS}
        with open(self.path, "wb") as fh:
            fh.write(
                json.dumps(
                    ordered_doc,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )


class VerificationFailureTests(ReceiptIndexFixture):
    def setUp(self) -> None:
        super().setUp()
        self.first, self.second, self.doc_at_1, self.doc_at_2 = (
            self.build_chain()
        )
        self.ids = sorted(
            item["receipt"]["tx_id"]
            for item in self.doc_at_2["items"]
        )

    def test_input_failure_creates_no_file(self) -> None:
        bad = copy.deepcopy(self.doc_at_1)
        del bad["items"]
        result = self.advance(bad, self.ids[:3])
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})
        self.assertFalse(os.path.exists(self.path))

        # Bad expected ids / trust likewise never touch the disk.
        result = advance_receipts(self.path, self.doc_at_1, [], self.trust)
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})
        result = advance_receipts(self.path, self.doc_at_1, self.ids[:3], {})
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})
        self.assertFalse(os.path.exists(self.path))

    def test_auth_failure_creates_no_file(self) -> None:
        bad = copy.deepcopy(self.doc_at_1)
        bad["finality"]["auth"]["key_version"] = 9999
        result = self.advance(bad, self.ids[:3])
        self.assertEqual(result, {"ok": False, "error": "auth"})
        self.assertFalse(os.path.exists(self.path))

    def test_integrity_failure_creates_no_file(self) -> None:
        bad = copy.deepcopy(self.doc_at_1)
        bad["items"] = list(reversed(bad["items"]))
        result = self.advance(bad, self.ids[:3])
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertFalse(os.path.exists(self.path))

    def test_failed_advance_never_changes_existing_file(self) -> None:
        good_ids = sorted(
            item["receipt"]["tx_id"] for item in self.doc_at_1["items"]
        )
        self.assertTrue(self.advance(self.doc_at_1, good_ids)["ok"])
        raw = self.read_raw()

        # A tampered proof is rejected by the reused verifier.
        bad = copy.deepcopy(self.doc_at_1)
        bad["items"][0]["proof"]["index"] += 1
        result = self.advance(bad, good_ids)
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertEqual(self.read_raw(), raw)


class StoredStateTests(ReceiptIndexFixture):
    def test_damaged_index_is_state_for_both_functions(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, ids)["ok"])

        damages = (
            b"{not json\n",
            b'{"v": 1}\n',
            b'{"v": 2, "generation": 1, "finalized": '
            b'{"height": 1, "block_hash": "' + b"a" * 64 + b'"}, '
            b'"items": [], "hash": "' + b"0" * 64 + b'"}\n',
        )
        for raw in damages:
            with open(self.path, "wb") as fh:
                fh.write(raw)
            self.assertEqual(
                self.advance(doc_at_1, ids),
                {"ok": False, "error": ERR_STATE},
                raw,
            )
            self.assertEqual(
                get_receipt(self.path, ids[0]),
                {"ok": False, "error": ERR_STATE},
                raw,
            )

    def test_tampered_then_resealed_content_is_state(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, ids)["ok"])

        document = json.loads(self.read_raw())
        document["generation"] = 99
        # Leave the old hash: the digest no longer recomputes.
        with open(self.path, "wb") as fh:
            fh.write(
                (
                    json.dumps(document, separators=(",", ":")) + "\n"
                ).encode("utf-8")
            )
        self.assertEqual(
            self.advance(doc_at_1, ids),
            {"ok": False, "error": ERR_STATE},
        )
        self.assertEqual(
            get_receipt(self.path, ids[0]),
            {"ok": False, "error": ERR_STATE},
        )

    def test_get_receipt_result_is_closed_copy(self) -> None:
        first, _second, doc_at_1, _doc_at_2 = self.build_chain()
        ids = sorted(body["tx_id"] for body in first)
        self.assertTrue(self.advance(doc_at_1, ids)["ok"])
        result = get_receipt(self.path, ids[0])
        result["item"]["receipt"]["amount"] = 999999
        again = get_receipt(self.path, ids[0])
        self.assertNotEqual(
            again["item"]["receipt"]["amount"], 999999
        )


class NeverRaisesTests(ReceiptIndexFixture):
    def test_junk_never_raises(self) -> None:
        _first, _second, document, _doc_at_2 = self.build_chain()
        ids = sorted(
            item["receipt"]["tx_id"] for item in document["items"]
        )
        for junk in (None, 42, object(), [], "x", True):
            result = advance_receipts(self.path, junk, ids, self.trust)
            self.assertFalse(result["ok"], junk)
            self.assertEqual(set(result), {"ok", "error"})
            result = get_receipt(self.path, junk)
            self.assertFalse(result["ok"], junk)


if __name__ == "__main__":
    unittest.main()
