"""Tests for the durable finalized-receipt index.

Covers both sides of ``ledger.light_client.advance_receipts`` and
``ledger.light_client.get_receipt``:

* ``advance_receipts`` reuses ``verify_finalized_receipts`` and only then
  merges the verified ``receipt, proof`` items serially into a version-1
  index at ``path``. The first change writes generation 1 with the exact
  file key order ``v, generation, finalized, items, hash``; items stay
  sorted by ``tx_id`` and the hash recomputes as SHA-256 of the canonical
  JSON of the other fields. Serialization is compact UTF-8 JSON with one
  trailing LF and the file is atomically replaced.
* the success key order is ``ok, generation, finalized, added`` with
  ``added`` the number of previously unknown ids; generation starts at 1
  and increments exactly once per change, while a call that neither adds
  a receipt nor moves the finalized boundary writes nothing.
* a higher finalized boundary for already-known ids is still a change
  (generation + 1, new boundary); the same id with different content is a
  conflict, a regressing boundary and a same-height/different-hash
  boundary are ``integrity`` and leave the file and generation untouched.
* error classification: argument/structure defects are ``input``, an
  unknown key version or a bad finality signature is ``auth``, merge and
  verification defects are ``integrity``, a corrupt stored index is
  ``state``, a missing file (for ``get_receipt``) or a read/write failure
  is ``io``; ``get_receipt`` on an existing index that does not know the
  id returns ``not_found``. Nothing is raised for junk input.

Run: python3 tests/light_client_advance_receipts_test.py
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    _canonical_json_bytes,
    advance_receipts,
    get_receipt,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

INDEX_KEYS = ["v", "generation", "finalized", "items", "hash"]
ANCHOR_KEYS = ["height", "block_hash"]
ITEM_KEYS = ["receipt", "proof"]
RECEIPT_KEYS = [
    "tx_id",
    "from",
    "to",
    "amount",
    "signature",
    "status",
    "height",
    "block_hash",
    "index",
]
PROOF_KEYS = [
    "height",
    "tx_id",
    "index",
    "merkle_root",
    "block_hash",
    "siblings",
]
ADVANCE_RESULT_KEYS = ["ok", "generation", "finalized", "added"]
GET_RESULT_KEYS = ["ok", "finalized", "item"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class AdvanceReceiptsFixture(unittest.TestCase):
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

    def fetch(self, tx_ids: list[str]) -> dict:
        status, body = self.service.get_finalized_receipts(
            {"tx_ids": tx_ids}
        )
        self.assertEqual(status, 200, body)
        return body

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

    def read_index(self) -> dict:
        with open(self.path, "rb") as fh:
            return json.loads(fh.read())

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def advance(self, document: dict, tx_ids: list[str]) -> dict:
        return advance_receipts(self.path, document, tx_ids, self.trust)

    def recompute_hash(self, data: dict) -> str:
        body = {key: data[key] for key in INDEX_KEYS if key != "hash"}
        return hashlib.sha256(_canonical_json_bytes(body)).hexdigest()


class AdvanceReceiptsFormatTests(AdvanceReceiptsFixture):
    def setUp(self) -> None:
        super().setUp()
        # Snapshot the batch while its own block is the confirmed head so
        # its finalized boundary pins height 1.
        self.ids = self.mine_confirmed_block((10, 20, 30))
        self.document = self.fetch(self.ids)
        self.assertEqual(
            self.document["finality"]["finalized"]["height"], 1
        )

    def test_first_advance_writes_generation_one(self) -> None:
        result = self.advance(self.document, self.ids)
        self.assertEqual(tuple(result), tuple(ADVANCE_RESULT_KEYS))
        self.assertEqual(
            result,
            {
                "ok": True,
                "generation": 1,
                "finalized": self.document["finality"]["finalized"],
                "added": 3,
            },
        )
        self.assertIsInstance(result["generation"], int)
        self.assertIsInstance(result["added"], int)
        self.assertGreaterEqual(result["added"], 0)

    def test_file_format_key_order_and_hash(self) -> None:
        self.assertTrue(self.advance(self.document, self.ids)["ok"])
        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        # Compact JSON: no separator whitespace.
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        pairs = json.loads(raw, object_pairs_hook=lambda p: p)
        self.assertEqual([key for key, _ in pairs], INDEX_KEYS)
        data = json.loads(raw)
        self.assertEqual(data["v"], 1)
        self.assertEqual(data["generation"], 1)
        self.assertEqual(list(data["finalized"]), ANCHOR_KEYS)
        self.assertEqual(
            [item["receipt"]["tx_id"] for item in data["items"]], self.ids
        )
        for item in data["items"]:
            self.assertEqual(list(item), ITEM_KEYS)
            self.assertEqual(list(item["receipt"]), RECEIPT_KEYS)
            self.assertEqual(list(item["proof"]), PROOF_KEYS)
        self.assertEqual(self.recompute_hash(data), data["hash"])
        self.assertRegex(data["hash"], r"^[0-9a-f]{64}$")

    def test_idempotent_resubmission_does_not_write(self) -> None:
        self.assertTrue(self.advance(self.document, self.ids)["ok"])
        before = self.read_raw()
        result = self.advance(self.document, self.ids)
        self.assertEqual(
            result,
            {
                "ok": True,
                "generation": 1,
                "finalized": self.document["finality"]["finalized"],
                "added": 0,
            },
        )
        self.assertEqual(self.read_raw(), before)

    def test_higher_boundary_for_known_ids_is_a_change(self) -> None:
        self.assertTrue(self.advance(self.document, self.ids)["ok"])
        # After another confirmed block, a batch for the same known ids
        # carries the higher finalized boundary but adds no receipt.
        self.mine_confirmed_block((40, 50))
        refreshed = self.fetch(self.ids)
        self.assertEqual(refreshed["finality"]["finalized"]["height"], 2)
        result = self.advance(refreshed, self.ids)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["added"], 0)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(
            result["finalized"], refreshed["finality"]["finalized"]
        )
        data = self.read_index()
        self.assertEqual(len(data["items"]), 3)
        self.assertEqual(self.recompute_hash(data), data["hash"])

    def test_second_batch_merges_and_sorts(self) -> None:
        self.assertTrue(self.advance(self.document, self.ids)["ok"])
        second_ids = self.mine_confirmed_block((40, 50))
        # The second batch overlaps one block-1 id, so its shared run
        # starts in block 1; one id is already known and two are new.
        overlap_ids = sorted(set(self.ids[:1] + second_ids))
        document = self.fetch(overlap_ids)
        result = self.advance(document, overlap_ids)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["added"], 2)
        self.assertEqual(
            result["finalized"], document["finality"]["finalized"]
        )
        data = self.read_index()
        self.assertEqual(
            [item["receipt"]["tx_id"] for item in data["items"]],
            sorted(self.ids + second_ids),
        )
        self.assertEqual(self.recompute_hash(data), data["hash"])


class AdvanceReceiptsFailureTests(AdvanceReceiptsFixture):
    def setUp(self) -> None:
        super().setUp()
        self.ids = self.mine_confirmed_block((10, 20, 30))
        self.document = self.fetch(self.ids)
        self.assertTrue(self.advance(self.document, self.ids)["ok"])
        self.second_ids = self.mine_confirmed_block((40, 50))

    def boundary_document(self) -> tuple[dict, list[str]]:
        """A height-2 batch overlapping one stored block-1 id."""
        ids = sorted(set(self.ids[:1] + self.second_ids))
        return self.fetch(ids), ids

    def test_finalized_regression_is_integrity(self) -> None:
        document, ids = self.boundary_document()
        self.assertTrue(self.advance(document, ids)["ok"])
        # The stored boundary is now at height 2; the original height-1
        # document must be rejected as a regression.
        result = self.advance(self.document, self.ids)
        self.assertEqual(result, {"ok": False, "error": "integrity"})
        self.assertEqual(self.read_index()["generation"], 2)

    def test_same_height_different_hash_is_integrity(self) -> None:
        document, ids = self.boundary_document()
        self.assertTrue(self.advance(document, ids)["ok"])
        # Rewrite the stored boundary to a same-height foreign hash,
        # re-sealing the file so it loads; the genuine height-2 document
        # names a different block at that height.
        data = self.read_index()
        tampered = copy.deepcopy(data)
        tampered["finalized"] = {"height": 2, "block_hash": "0" * 64}
        tampered["hash"] = self.recompute_hash(tampered)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tampered, separators=(",", ":")) + "\n")
        result = self.advance(document, ids)
        self.assertEqual(result, {"ok": False, "error": "integrity"})
        self.assertEqual(self.read_index()["generation"], 2)

    def test_same_id_different_content_is_conflict(self) -> None:
        # A self-consistent (re-sealed) store whose item for a known id
        # carries foreign content must not be overwritten by the genuine
        # document.
        data = self.read_index()
        tampered = copy.deepcopy(data)
        target = next(
            item
            for item in tampered["items"]
            if item["receipt"]["tx_id"] == self.ids[0]
        )
        target["receipt"]["block_hash"] = "0" * 64
        target["proof"]["block_hash"] = "0" * 64
        tampered["hash"] = self.recompute_hash(tampered)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(tampered, separators=(",", ":")) + "\n")
        result = self.advance(self.document, self.ids)
        self.assertEqual(result, {"ok": False, "error": "integrity"})
        self.assertEqual(self.read_index()["generation"], 1)

    def test_auth_failure(self) -> None:
        bad = copy.deepcopy(self.document)
        bad["finality"] = copy.deepcopy(bad["finality"])
        bad["finality"]["auth"] = dict(
            bad["finality"]["auth"], key_version=9999
        )
        generation = self.read_index()["generation"]
        result = self.advance(bad, self.ids)
        self.assertEqual(result, {"ok": False, "error": "auth"})
        self.assertEqual(self.read_index()["generation"], generation)

    def test_input_failures(self) -> None:
        generation = self.read_index()["generation"]
        for document in (None, 1, "x", [], {}, True, {"items": []}):
            result = self.advance(document, self.ids)  # type: ignore[arg-type]
            self.assertEqual(
                result, {"ok": False, "error": "input"}, document
            )
        for bad_ids in (
            None,
            123,
            [],
            ["zz"],
            ["0" * 64, "0" * 64],
        ):
            result = advance_receipts(
                self.path, self.document, bad_ids, self.trust
            )
            self.assertEqual(
                result, {"ok": False, "error": "input"}, bad_ids
            )
        # An expected-id set mismatch is a verified-integrity failure.
        result = advance_receipts(
            self.path, self.document, self.ids + ["0" * 64], self.trust
        )
        self.assertEqual(result, {"ok": False, "error": "integrity"})
        result = advance_receipts(
            self.path, self.document, self.ids[:-1], self.trust
        )
        self.assertEqual(result, {"ok": False, "error": "integrity"})
        for bad_trust in (None, 1, {}, {"audit_signers": []}):
            result = advance_receipts(
                self.path, self.document, self.ids, bad_trust
            )
            self.assertEqual(
                result, {"ok": False, "error": "input"}, bad_trust
            )
        for bad_path in (None, "", 7):
            result = advance_receipts(
                bad_path, self.document, self.ids, self.trust  # type: ignore[arg-type]
            )
            self.assertEqual(
                result, {"ok": False, "error": "input"}, bad_path
            )
        # A failed verification never creates or changes the file.
        missing = os.path.join(self.tmp, "never-created.json")
        result = advance_receipts(
            missing, {"items": []}, self.ids, self.trust
        )
        self.assertEqual(result, {"ok": False, "error": "input"})
        self.assertFalse(os.path.exists(missing))
        self.assertEqual(self.read_index()["generation"], generation)

    def test_corrupt_index_is_state(self) -> None:
        document, ids = self.boundary_document()
        good = self.read_index()

        def seal(data: dict) -> None:
            with open(self.path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(data, separators=(",", ":")) + "\n")

        # Stale hash after a content change.
        bad = copy.deepcopy(good)
        bad["items"][0]["receipt"]["amount"] = 999
        seal(bad)
        self.assertEqual(
            self.advance(document, ids), {"ok": False, "error": "state"}
        )
        self.assertEqual(
            get_receipt(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )
        # Malformed JSON and bad UTF-8.
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(
            self.advance(document, ids), {"ok": False, "error": "state"}
        )
        with open(self.path, "wb") as fh:
            fh.write(b"\xff\xfe")
        self.assertEqual(
            get_receipt(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )
        # Wrong version / key order / unsorted items.
        bad = copy.deepcopy(good)
        bad["v"] = 2
        seal(bad)
        self.assertEqual(
            self.advance(document, ids), {"ok": False, "error": "state"}
        )
        bad = copy.deepcopy(good)
        reordered = {key: bad[key] for key in reversed(INDEX_KEYS)}
        seal(reordered)
        self.assertEqual(
            get_receipt(self.path, self.ids[0]),
            {"ok": False, "error": "state"},
        )
        bad = copy.deepcopy(good)
        if len(bad["items"]) > 1:
            bad["items"] = list(reversed(bad["items"]))
            seal(bad)
            self.assertEqual(
                get_receipt(self.path, self.ids[0]),
                {"ok": False, "error": "state"},
            )


class GetReceiptTests(AdvanceReceiptsFixture):
    def test_missing_file_is_io(self) -> None:
        result = get_receipt(self.path, "0" * 64)
        self.assertEqual(result, {"ok": False, "error": "io"})

    def test_lookup_round_trip_and_not_found(self) -> None:
        ids = self.mine_confirmed_block((10, 20, 30))
        document = self.fetch(ids)
        self.assertTrue(self.advance(document, ids)["ok"])
        result = get_receipt(self.path, ids[1])
        self.assertEqual(tuple(result), tuple(GET_RESULT_KEYS))
        self.assertEqual(
            result["finalized"], document["finality"]["finalized"]
        )
        self.assertEqual(list(result["item"]), ITEM_KEYS)
        self.assertEqual(result["item"]["receipt"]["tx_id"], ids[1])
        self.assertEqual(
            result["item"],
            next(
                item
                for item in document["items"]
                if item["receipt"]["tx_id"] == ids[1]
            ),
        )
        self.assertEqual(
            get_receipt(self.path, "f" * 64),
            {"ok": False, "error": "not_found"},
        )

    def test_bad_arguments_are_input(self) -> None:
        ids = self.mine_confirmed_block((10,))
        self.assertTrue(self.advance(self.fetch(ids), ids)["ok"])
        for bad_id in (None, 1, "zz", "F" * 64, "0" * 63, ""):
            self.assertEqual(
                get_receipt(self.path, bad_id),  # type: ignore[arg-type]
                {"ok": False, "error": "input"},
                bad_id,
            )
        for bad_path in (None, "", 42):
            self.assertEqual(
                get_receipt(bad_path, ids[0]),  # type: ignore[arg-type]
                {"ok": False, "error": "input"},
            )


class AdvanceReceiptsConcurrencyTests(AdvanceReceiptsFixture):
    def test_serial_merges_from_threads(self) -> None:
        ids = self.mine_confirmed_block((10, 20, 30, 40, 50))
        batches = [(self.fetch([tx_id]), [tx_id]) for tx_id in ids]
        errors = []

        def worker(batch: tuple[dict, list[str]]) -> None:
            result = advance_receipts(self.path, batch[0], batch[1], self.trust)
            if not result["ok"]:
                errors.append(result)

        threads = [
            threading.Thread(target=worker, args=(batch,)) for batch in batches
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        data = self.read_index()
        self.assertEqual(len(data["items"]), len(ids))
        self.assertEqual(
            [item["receipt"]["tx_id"] for item in data["items"]], ids
        )
        self.assertEqual(data["generation"], len(ids))
        self.assertEqual(self.recompute_hash(data), data["hash"])
        for tx_id in ids:
            result = get_receipt(self.path, tx_id)
            self.assertTrue(result["ok"], result)


class AdvanceReceiptsNeverRaisesTests(AdvanceReceiptsFixture):
    def test_junk_never_raises(self) -> None:
        self.mine_confirmed_block((10,))
        for junk in (
            None,
            42,
            object(),
            [1],
            {"items": [], "headers": [], "finality": {}},
            {"items": [object()], "headers": [], "finality": {}},
        ):
            result = advance_receipts(self.path, junk, ["0" * 64], self.trust)
            self.assertEqual(set(result), {"ok", "error"})
            self.assertFalse(result["ok"])
        result = get_receipt(object(), None)  # type: ignore[arg-type]
        self.assertEqual(result, {"ok": False, "error": "input"})


if __name__ == "__main__":
    unittest.main()
