"""Tests for the batch offline-verifiable finalized transaction receipts.

Covers both sides of the contract:

* ``POST /v1/transactions/finalized-receipts`` (service and HTTP): the body
  contains only ``tx_ids`` — a non-empty list of distinct 64-lowercase-hex
  strings; every shape defect is 400 and never touches state; any id the
  canonical chain does not hold is 404 (taking precedence); otherwise any
  mempool or packed-but-unconfirmed id is 409. The 200 body has the fixed
  key order ``items, headers, finality``: ``items`` sorted by tx_id, each
  item in the single-receipt ``receipt, proof`` order identical to
  ``GET /v1/transactions/{tx_id}/finalized-receipt``; ``headers`` is the
  continuous five-field confirmed run from the lowest transaction's block
  to the highest confirmed block, shared by every item; ``finality`` is
  exactly ``GET /v1/chain/finality`` with ``finalized`` naming the last
  header. The whole batch and the audit signer come from one store-lock
  snapshot, including with a pending chain tip.

* ``ledger.light_client.verify_finalized_receipts``: the happy round trip,
  per-item equivalence with ``verify_finalized_receipt`` and the failure
  matrix — shape/type/hex/trust and ``expected_tx_ids`` defects (including
  a valid batch answering a different set) are ``input``; unknown key
  version or a failed finality signature is ``auth``; ordering, duplicate,
  transaction-signature, proof, header-chain and shared-chain tampering is
  ``integrity``. Success key order is ``ok, tx_ids, finalized`` with
  ``tx_ids`` ascending and ``finalized`` the shared two-field anchor; a
  failure carries only ``ok, error``; nothing is raised for junk input.

Run: python3 tests/finalized_receipts_batch_test.py
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
from ledger.light_client import verify_finalized_receipt, verify_finalized_receipts
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

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
ITEM_FIELDS = ("receipt", "proof")
HEADER_FIELDS = ("height", "prev_hash", "merkle_root", "block_hash", "status")
FINALITY_FIELDS = ("finalized", "tip", "auth")
DOCUMENT_FIELDS = ("items", "headers", "finality")
SUCCESS_FIELDS = ("ok", "tx_ids", "finalized")


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def ordered(value: bytes):
    """Decode JSON preserving every object's key insertion order."""
    return json.loads(value, object_pairs_hook=lambda pairs: pairs)


class BatchFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "ledger.json"))
        )
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        self.trust = self.service.get_trust_document()[1]

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

    def mine(self) -> dict:
        status, block = self.service.mine_block()
        self.assertEqual(status, 201, block)
        return block

    def confirm(self, height: int) -> None:
        self.assertEqual(self.service.confirm_block(str(height))[0], 200)

    def build_confirmed_blocks(self, batches: tuple[tuple[int, ...], ...]):
        """Mine and confirm one block per tuple; returns the tx bodies."""
        bodies = []
        for batch in batches:
            for amount in batch:
                bodies.append(self.submit(amount))
            block = self.mine()
            self.confirm(block["height"])
        return bodies

    def fetch(self, tx_ids: list[str]) -> dict:
        status, body = self.service.get_finalized_receipts({"tx_ids": tx_ids})
        self.assertEqual(status, 200, body)
        return body


class BatchServiceTests(BatchFixture):
    def test_shape_defects_are_400(self) -> None:
        self.build_confirmed_blocks(((10,),))
        valid = self.submit(99)
        self.mine()
        for bad in (
            None,
            [],
            {},
            "x",
            42,
            {"tx_ids": []},
            {"tx_ids": ["zz"]},
            {"tx_ids": ["A" * 64]},
            {"tx_ids": ["a" * 63]},
            {"tx_ids": ["a" * 65]},
            {"tx_ids": [123]},
            {"tx_ids": [None]},
            {"tx_ids": [valid["tx_id"], valid["tx_id"]]},
            {"tx_ids": [valid["tx_id"]], "extra": 1},
            {"ids": [valid["tx_id"]]},
        ):
            status, body = self.service.get_finalized_receipts(bad)
            self.assertEqual(status, 400, bad)
            self.assertIn("error", body)

    def test_unknown_ids_are_404(self) -> None:
        bodies = self.build_confirmed_blocks(((10,),))
        for ids in (
            ["f" * 64],
            ["0" * 64],
            [bodies[0]["tx_id"], "f" * 64],
        ):
            self.assertEqual(
                self.service.get_finalized_receipts({"tx_ids": ids})[0],
                404,
                ids,
            )

    def test_unconfirmed_ids_are_409_and_unknown_takes_precedence(self) -> None:
        confirmed = self.build_confirmed_blocks(((10,),))[0]
        mempool = self.submit(20)
        self.assertEqual(
            self.service.get_finalized_receipts({"tx_ids": [mempool["tx_id"]]})[0],
            409,
        )
        # A confirmed id together with a mempool id is still unconfirmed.
        self.assertEqual(
            self.service.get_finalized_receipts(
                {"tx_ids": [confirmed["tx_id"], mempool["tx_id"]]}
            )[0],
            409,
        )
        pending = self.mine()  # packs the mempool tx, stays pending
        self.assertEqual(
            self.service.get_finalized_receipts({"tx_ids": [mempool["tx_id"]]})[0],
            409,
        )
        # An unknown id outranks the unconfirmed one.
        self.assertEqual(
            self.service.get_finalized_receipts(
                {"tx_ids": ["f" * 64, mempool["tx_id"]]}
            )[0],
            404,
        )
        self.assertEqual(pending["height"], 2)
        self.confirm(pending["height"])
        self.assertEqual(
            self.service.get_finalized_receipts({"tx_ids": [mempool["tx_id"]]})[0],
            200,
        )

    def test_document_shape_key_order_and_item_contents(self) -> None:
        bodies = self.build_confirmed_blocks(((10, 20, 30), (40, 50)))
        ids = [body["tx_id"] for body in bodies]
        document = self.fetch([ids[-1], ids[0]])  # deliberately unsorted
        self.assertEqual(tuple(document), DOCUMENT_FIELDS)

        # Items are sorted by tx_id regardless of request order.
        self.assertEqual(
            [item["receipt"]["tx_id"] for item in document["items"]],
            sorted([ids[-1], ids[0]]),
        )
        for item in document["items"]:
            self.assertEqual(tuple(item), ITEM_FIELDS)
            self.assertEqual(tuple(item["receipt"]), RECEIPT_FIELDS)
            self.assertEqual(tuple(item["proof"]), PROOF_FIELDS)
            receipt, proof = item["receipt"], item["proof"]
            self.assertEqual(receipt["status"], "confirmed")
            self.assertEqual(proof["tx_id"], receipt["tx_id"])
            self.assertEqual(proof["height"], receipt["height"])
            self.assertEqual(proof["index"], receipt["index"])
            self.assertEqual(proof["block_hash"], receipt["block_hash"])
            self.assertTrue(
                crypto.verify_merkle_proof(
                    proof["tx_id"],
                    proof["siblings"],
                    proof["merkle_root"],
                    proof["block_hash"],
                    receipt["block_hash"],
                )
            )
            # The item is byte-for-byte the single endpoint's receipt/proof.
            status, single = self.service.get_finalized_receipt(receipt["tx_id"])
            self.assertEqual(status, 200)
            self.assertEqual(item["receipt"], single["receipt"])
            self.assertEqual(item["proof"], single["proof"])

        # One shared continuous confirmed run from the lowest tx block (1)
        # to the highest confirmed block (2).
        heights = [item["height"] for item in document["headers"]]
        self.assertEqual(heights, [1, 2])
        for header in document["headers"]:
            self.assertEqual(tuple(header), HEADER_FIELDS)
            self.assertEqual(header["status"], "confirmed")
        self.assertEqual(tuple(document["finality"]), FINALITY_FIELDS)
        self.assertEqual(
            document["finality"]["finalized"],
            {
                "height": 2,
                "block_hash": document["headers"][-1]["block_hash"],
            },
        )

    def test_headers_start_at_the_lowest_requested_block(self) -> None:
        bodies = self.build_confirmed_blocks(((10,), (20,), (30,), (40,)))
        ids = [body["tx_id"] for body in bodies]
        # Only blocks 2 and 4 requested: the run starts at block 2, not 1.
        document = self.fetch([ids[1], ids[3]])
        self.assertEqual(
            [header["height"] for header in document["headers"]],
            [2, 3, 4],
        )
        # A single block-4 request gets just the suffix from block 4.
        document = self.fetch([ids[3]])
        self.assertEqual(
            [header["height"] for header in document["headers"]], [4]
        )

    def test_items_in_one_block_share_that_blocks_run(self) -> None:
        bodies = self.build_confirmed_blocks(((10, 20, 30), (40,)))
        first_block_ids = [body["tx_id"] for body in bodies[:3]]
        document = self.fetch(first_block_ids)
        self.assertEqual(
            [item["receipt"]["tx_id"] for item in document["items"]],
            sorted(first_block_ids),
        )
        for item in document["items"]:
            self.assertEqual(item["receipt"]["height"], 1)
        # Run from block 1 to the confirmed head block 2.
        self.assertEqual(
            [header["height"] for header in document["headers"]], [1, 2]
        )

    def test_snapshot_with_pending_tip(self) -> None:
        bodies = self.build_confirmed_blocks(((10, 20),))
        pending_tx = self.submit(5)
        pending_block = self.mine()
        document = self.fetch([body["tx_id"] for body in bodies])
        # The run stops at the confirmed head; the pending block is absent.
        self.assertEqual(
            [header["height"] for header in document["headers"]], [1]
        )
        self.assertFalse(
            any(header["status"] == "pending" for header in document["headers"])
        )
        status, chain_finality = self.service.get_chain_finality()
        self.assertEqual(status, 200)
        self.assertEqual(document["finality"], chain_finality)
        self.assertEqual(document["finality"]["finalized"]["height"], 1)
        self.assertEqual(document["finality"]["tip"]["status"], "pending")
        self.assertEqual(
            document["finality"]["tip"]["tip_hash"], pending_block["block_hash"]
        )
        self.assertEqual(
            self.service.get_finalized_receipts(
                {"tx_ids": [pending_tx["tx_id"]]}
            )[0],
            409,
        )


class BatchHttpTests(unittest.TestCase):
    """POST /v1/transactions/finalized-receipts over the real server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"))
        )
        cls.key = Ed25519PrivateKey.generate()
        cls.sender = pub_hex(cls.key)
        cls.bob = "b" * 64
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

    def request(self, payload=None, raw: bool = False):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"{self.base}/v1/transactions/finalized-receipts",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                payload_bytes = resp.read()
                if raw:
                    return resp.status, payload_bytes.decode()
                return resp.status, json.loads(payload_bytes.decode())
        except urllib.error.HTTPError as exc:
            payload_bytes = exc.read()
            if raw:
                return exc.code, payload_bytes.decode()
            return exc.code, json.loads(payload_bytes.decode())

    def tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def test_status_codes_and_wire_key_order(self) -> None:
        # Malformed body is 400.
        self.assertEqual(self.request({"tx_ids": []})[0], 400)
        self.assertEqual(self.request({"tx_ids": ["zz"]})[0], 400)
        # Unknown id is 404.
        self.assertEqual(self.request({"tx_ids": ["f" * 64]})[0], 404)

        # An unconfirmed tx is 409 in the mempool and in the pending tip.
        req = urllib.request.Request(
            f"{self.base}/v1/transactions",
            data=json.dumps(self.tx(10)).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            tx_id = json.loads(resp.read().decode())["tx_id"]
        self.assertEqual(self.request({"tx_ids": [tx_id]})[0], 409)
        req = urllib.request.Request(
            f"{self.base}/v1/blocks",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            height = json.loads(resp.read().decode())["height"]
        self.assertEqual(self.request({"tx_ids": [tx_id]})[0], 409)
        req = urllib.request.Request(
            f"{self.base}/v1/blocks/{height}/confirm",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            resp.read()

        status, raw = self.request({"tx_ids": [tx_id]}, raw=True)
        self.assertEqual(status, 200)
        pairs = ordered(raw)
        self.assertEqual([key for key, _ in pairs], list(DOCUMENT_FIELDS))
        document = json.loads(raw)
        items_pairs = next(value for key, value in pairs if key == "items")
        self.assertEqual([key for key, _ in items_pairs[0]], list(ITEM_FIELDS))
        receipt_pairs = next(
            value
            for key, value in items_pairs[0]
            if key == "receipt"
        )
        self.assertEqual([key for key, _ in receipt_pairs], list(RECEIPT_FIELDS))
        self.assertEqual(
            document["items"][0]["receipt"]["status"], "confirmed"
        )


class VerifyFinalizedReceiptsTests(BatchFixture):
    """ledger.light_client.verify_finalized_receipts classification matrix."""

    def setUp(self) -> None:
        super().setUp()
        # Block 1 holds three transactions (odd leaf count), block 2 two;
        # then an unconfirmed pending tip.
        self.txs: list[dict] = []
        for batch in ((10, 20, 30), (40, 50)):
            for amount in batch:
                self.txs.append(self.submit(amount))
            block = self.mine()
            self.confirm(block["height"])
        self.ids = [body["tx_id"] for body in self.txs]
        self.pending_tx = self.submit(60)
        self.mine()
        self.document = self.fetch(self.ids)
        self.pinned = sorted(self.ids)

    _DEFAULT = object()

    def verify(self, document=_DEFAULT, pinned=_DEFAULT, trust=_DEFAULT):
        return verify_finalized_receipts(
            self.document if document is self._DEFAULT else document,
            self.pinned if pinned is self._DEFAULT else pinned,
            self.trust if trust is self._DEFAULT else trust,
        )

    def mutate(self) -> dict:
        return copy.deepcopy(self.document)

    def test_happy_round_trip_key_order_and_anchor(self) -> None:
        result = self.verify()
        self.assertEqual(tuple(result), SUCCESS_FIELDS)
        self.assertTrue(result["ok"])
        self.assertEqual(result["tx_ids"], self.pinned)
        self.assertEqual(
            result["finalized"], self.document["finality"]["finalized"]
        )
        # The pin may arrive in any order; only the set matters.
        self.assertTrue(self.verify(pinned=list(reversed(self.pinned)))["ok"])

    def test_each_item_independently_verifies_as_a_single_receipt(self) -> None:
        for item in self.document["items"]:
            tx_id = item["receipt"]["tx_id"]
            offset = item["receipt"]["height"] - self.document["headers"][0]["height"]
            single = {
                "receipt": item["receipt"],
                "proof": item["proof"],
                "headers": self.document["headers"][offset:],
                "finality": self.document["finality"],
            }
            result = verify_finalized_receipt(single, tx_id, self.trust)
            self.assertTrue(result["ok"], result)
            self.assertEqual(
                result["finalized"], self.document["finality"]["finalized"]
            )

    def test_subset_batch_verifies(self) -> None:
        subset = [self.ids[4], self.ids[0]]  # block 2 and block 1
        document = self.fetch(subset)
        result = verify_finalized_receipts(document, sorted(subset), self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tx_ids"], sorted(subset))
        self.assertEqual(
            [header["height"] for header in document["headers"]], [1, 2]
        )

    # -- input -------------------------------------------------------------

    def test_shape_and_type_defects_are_input(self) -> None:
        for junk in (None, 1, "x", [], {}, True):
            self.assertEqual(self.verify(junk), {"ok": False, "error": "input"})

        bad = self.mutate()
        del bad["items"]
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["items"] = []
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["items"][0] = {"receipt": bad["items"][0]["receipt"]}
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["items"][0]["proof"] = {"not": "a proof"}
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["headers"] = []
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["headers"][0] = {"height": 1, "block_hash": "0" * 64}
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

    def test_key_order_defects_are_input(self) -> None:
        bad = {
            "headers": self.document["headers"],
            "items": self.document["items"],
            "finality": self.document["finality"],
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        item = bad["items"][0]
        bad["items"][0] = {"proof": item["proof"], "receipt": item["receipt"]}
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

    def test_expected_tx_ids_constraints_are_input(self) -> None:
        for bad_pin in (
            None,
            123,
            "x",
            {},
            [],
            ["zz"],
            ["A" * 64],
            [self.pinned[0], self.pinned[0]],
            [123],
        ):
            self.assertEqual(
                self.verify(pinned=bad_pin),
                {"ok": False, "error": "input"},
                bad_pin,
            )

    def test_trust_defects_are_input(self) -> None:
        for bad_trust in (None, 1, "x", [], {}, {"audit_signers": []}):
            self.assertEqual(
                self.verify(trust=bad_trust),
                {"ok": False, "error": "input"},
                bad_trust,
            )

    def test_wrong_pinned_set_is_input(self) -> None:
        # A perfectly valid document answering a different set than pinned
        # is an argument (input) mismatch, like the single-receipt pin.
        self.assertEqual(
            self.verify(pinned=[self.pinned[0]]),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self.verify(pinned=sorted(self.pinned) + ["0" * 64]),
            {"ok": False, "error": "input"},
        )

    def test_hex_defects_are_input(self) -> None:
        bad = self.mutate()
        bad["items"][0]["receipt"]["block_hash"] = "Z" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["finality"]["auth"]["signature"] = "q" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["items"][0]["receipt"]["signature"] = "q"
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

    # -- auth --------------------------------------------------------------

    def test_unknown_key_version_is_auth(self) -> None:
        bad = self.mutate()
        bad["finality"]["auth"]["key_version"] = 9999
        self.assertEqual(self.verify(bad), {"ok": False, "error": "auth"})

    def test_bad_finality_signature_is_auth(self) -> None:
        bad = self.mutate()
        bad["finality"]["auth"]["signature"] = "0" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "auth"})

    # -- integrity ---------------------------------------------------------

    def test_items_must_be_ascending_and_unique(self) -> None:
        bad = self.mutate()
        bad["items"] = bad["items"][::-1]
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["items"].append(bad["items"][0])
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        # Swap two receipts' positions without their proofs: the list is
        # still ascending tx_id-wise here, so this surfaces as an item
        # binding/proof integrity failure rather than ordering.
        bad = self.mutate()
        bad["items"][0]["receipt"], bad["items"][1]["receipt"] = (
            bad["items"][1]["receipt"],
            bad["items"][0]["receipt"],
        )
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_transaction_signature_is_integrity(self) -> None:
        bad = self.mutate()
        bad["items"][0]["receipt"]["signature"] = "0" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["items"][-1]["receipt"]["tx_id"] = "1" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_proof_tampering_is_integrity(self) -> None:
        bad = self.mutate()
        bad["items"][0]["proof"]["index"] += 1
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["items"][0]["proof"]["siblings"][0]["hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["items"][0]["proof"]["merkle_root"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_header_chain_tampering_is_integrity(self) -> None:
        bad = self.mutate()
        bad["headers"][0]["block_hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["headers"][-1]["status"] = "pending"
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_run_must_start_at_the_lowest_item_block(self) -> None:
        # Prepend the genesis header: the run now starts below every item.
        bad = self.mutate()
        genesis = self.service.store.chain[0]
        bad["headers"].insert(
            0,
            {
                "height": genesis.height,
                "prev_hash": genesis.prev_hash,
                "merkle_root": genesis.merkle_root,
                "block_hash": genesis.block_hash,
                "status": "confirmed",
            },
        )
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_item_block_outside_the_run_is_integrity(self) -> None:
        bad = self.mutate()
        # Drop the first (lowest, block-1) header so block-1 items no longer
        # bind to a header the document carries.
        bad["headers"] = bad["headers"][1:]
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_finality_binding_tampering_is_auth_then_integrity(self) -> None:
        # An unsigned change to the credential fails the envelope first.
        bad = self.mutate()
        bad["finality"]["finalized"]["height"] = 0
        self.assertEqual(self.verify(bad), {"ok": False, "error": "auth"})

    def test_failure_result_has_only_ok_and_error(self) -> None:
        bad = self.mutate()
        bad["items"] = bad["items"][::-1]
        result = self.verify(bad)
        self.assertEqual(set(result), {"ok", "error"})
        self.assertFalse(result["ok"])

    def test_never_raises(self) -> None:
        for junk in (None, 42, object(), [], 3.14):
            result = self.verify(junk)
            self.assertFalse(result["ok"])
            self.assertEqual(set(result), {"ok", "error"})
        for junk in (object(), 42, None, [1, 2]):
            result = self.verify(pinned=junk)
            self.assertEqual(result, {"ok": False, "error": "input"})
        for junk in (object(), 42, None):
            result = self.verify(trust=junk)
            self.assertEqual(result, {"ok": False, "error": "input"})


if __name__ == "__main__":
    unittest.main()
