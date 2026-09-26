"""Tests for the batch offline-verifiable finalized receipts.

Covers both sides of the contract:

* ``POST /v1/transactions/finalized-receipts`` (service and HTTP): the body
  contains only ``tx_ids`` — a non-empty list of distinct 64-lowercase-hex
  strings; any shape/type/hex/duplicate defect is 400, a well-formed but
  unknown id is 404, and an otherwise-present but unconfirmed transaction is
  409 (404 wins when both occur). A confirmed batch returns 200 with the
  exact fixed key order ``items, headers, finality``: ``items`` is ordered
  by tx_id ascending regardless of request order, each item in the exact
  ``receipt, proof`` single-receipt shape; ``headers`` run continuously from
  the lowest transaction's block through the highest confirmed block; and
  ``finality`` is the ``GET /v1/chain/finality`` credential with
  ``finalized`` equal to the last header. The chain and the audit signer are
  snapshotted together under one store lock, including when a pending chain
  tip sits above the confirmed head.

* ``ledger.light_client.verify_finalized_receipts``: the happy round trip
  over the real 200 documents and every failure classification — shape,
  type, hex, ``expected_tx_ids`` and trust defects are ``input``; an unknown
  key version or a failed finality signature is ``auth``; ordering, set,
  per-item proof/signature, shared-chain and binding tampering is
  ``integrity``. The success key order is ``ok, tx_ids, finalized`` with the
  ids ascending and a failure carries only ``ok, error``; nothing is raised
  for junk input.

Also covers the synchronized single-verifier correction: a
``receipt.signature`` that is not 128 lowercase hex is ``input`` (only a
well-shaped signature that fails verification is ``integrity``).

Run: python3 tests/finalized_receipts_test.py
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
from ledger.light_client import (
    verify_finalized_receipt,
    verify_finalized_receipts,
)
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
BATCH_DOCUMENT_FIELDS = ("items", "headers", "finality")
BATCH_SUCCESS_FIELDS = ("ok", "tx_ids", "finalized")


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def ordered(value: bytes):
    """Decode JSON preserving every object's key insertion order."""
    return json.loads(value, object_pairs_hook=lambda pairs: pairs)


class FinalizedReceiptsFixture(unittest.TestCase):
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

    def build_confirmed(self, amounts: tuple[int, ...]) -> list[dict]:
        """Mine and confirm one block per amount; return the tx bodies."""
        bodies = []
        for amount in amounts:
            bodies.append(self.submit(amount))
            block = self.mine()
            self.confirm(block["height"])
        return bodies

    def fetch(self, tx_ids: list[str]) -> dict:
        status, body = self.service.get_finalized_receipts({"tx_ids": tx_ids})
        self.assertEqual(status, 200, body)
        return body


class FinalizedReceiptsServiceTests(FinalizedReceiptsFixture):
    def test_malformed_bodies_are_400(self) -> None:
        bodies = (
            None,
            1,
            "x",
            [],
            {},
            True,
            {"tx_ids": []},
            {"tx_ids": ["0" * 64], "extra": 1},
            {"ids": ["0" * 64]},
            {"tx_ids": None},
            {"tx_ids": "0" * 64},
            {"tx_ids": ["0" * 64, 123]},
            {"tx_ids": ["0" * 64, "z" * 64]},
            {"tx_ids": ["0" * 64, "A" * 64]},
            {"tx_ids": ["0" * 64, "0" * 63]},
            {"tx_ids": ["1" * 64, "1" * 64]},
        )
        for body in bodies:
            self.assertEqual(
                self.service.get_finalized_receipts(body)[0], 400, body
            )

    def test_unknown_ids_are_404(self) -> None:
        self.build_confirmed((10,))
        for body in (
            {"tx_ids": ["0" * 64]},
            {"tx_ids": ["f" * 64]},
            # One known, one unknown: the batch cannot be served.
        ):
            self.assertEqual(
                self.service.get_finalized_receipts(body)[0], 404, body
            )

    def test_unknown_takes_precedence_over_unconfirmed(self) -> None:
        mempool = self.submit(10)
        # An unknown id alongside an unconfirmed one is still 404.
        status, _ = self.service.get_finalized_receipts(
            {"tx_ids": [mempool["tx_id"], "f" * 64]}
        )
        self.assertEqual(status, 404)

    def test_mempool_and_pending_tip_transactions_are_409(self) -> None:
        confirmed = self.build_confirmed((10,))[0]
        mempool = self.submit(20)
        self.assertEqual(
            self.service.get_finalized_receipts(
                {"tx_ids": [mempool["tx_id"]]}
            )[0],
            409,
        )
        # Mixing a confirmed id with a mempool id is still 409.
        self.assertEqual(
            self.service.get_finalized_receipts(
                {"tx_ids": [confirmed["tx_id"], mempool["tx_id"]]}
            )[0],
            409,
        )
        self.mine()  # packs the mempool tx, stays pending
        self.assertEqual(
            self.service.get_finalized_receipts(
                {"tx_ids": [mempool["tx_id"]]}
            )[0],
            409,
        )

    def test_single_item_document_shape_and_key_order(self) -> None:
        body = self.build_confirmed((10,))[0]
        document = self.fetch([body["tx_id"]])
        self.assertEqual(tuple(document), BATCH_DOCUMENT_FIELDS)
        self.assertEqual(len(document["items"]), 1)

        item = document["items"][0]
        self.assertEqual(tuple(item), ITEM_FIELDS)
        receipt, proof = item["receipt"], item["proof"]
        self.assertEqual(tuple(receipt), RECEIPT_FIELDS)
        self.assertEqual(tuple(proof), PROOF_FIELDS)
        self.assertEqual(receipt["tx_id"], body["tx_id"])
        self.assertEqual(receipt["status"], "confirmed")
        self.assertTrue(crypto.verify_merkle_proof(
            proof["tx_id"],
            proof["siblings"],
            proof["merkle_root"],
            proof["block_hash"],
            receipt["block_hash"],
        ))

        headers = document["headers"]
        self.assertTrue(headers)
        for header in headers:
            self.assertEqual(tuple(header), HEADER_FIELDS)
            self.assertEqual(header["status"], "confirmed")
        self.assertEqual(
            document["finality"]["finalized"],
            {
                "height": headers[-1]["height"],
                "block_hash": headers[-1]["block_hash"],
            },
        )

    def test_items_sorted_and_headers_span_lowest_to_highest(self) -> None:
        # Two blocks: three transactions in block 1, two in block 2.
        first_batch = [self.submit(v) for v in (30, 10, 20)]
        block1 = self.mine()
        self.confirm(block1["height"])
        second_batch = [self.submit(v) for v in (50, 40)]
        block2 = self.mine()
        self.confirm(block2["height"])
        all_ids = [body["tx_id"] for body in first_batch + second_batch]

        # Request in deliberately scrambled order.
        document = self.fetch(list(reversed(all_ids)))
        item_ids = [item["receipt"]["tx_id"] for item in document["items"]]
        self.assertEqual(item_ids, sorted(all_ids))

        heights = [header["height"] for header in document["headers"]]
        self.assertEqual(heights, [1, 2])

        # A batch touching only block 2 starts the run at block 2.
        second_ids = [body["tx_id"] for body in second_batch]
        document = self.fetch(second_ids)
        heights = [header["height"] for header in document["headers"]]
        self.assertEqual(heights, [2])
        self.assertEqual(
            sorted(item["receipt"]["tx_id"] for item in document["items"]),
            sorted(second_ids),
        )

        # Each item binds to the block its receipt names.
        for item in document["items"]:
            receipt = item["receipt"]
            self.assertEqual(receipt["height"], 2)
            self.assertEqual(
                item["proof"]["block_hash"], receipt["block_hash"]
            )

    def test_pending_tip_is_excluded_from_the_run(self) -> None:
        confirmed = self.build_confirmed((10, 20))
        pending_tx = self.submit(5)
        pending_block = self.mine()
        document = self.fetch([confirmed[0]["tx_id"], confirmed[1]["tx_id"]])
        self.assertEqual(
            [header["height"] for header in document["headers"]], [1, 2]
        )
        self.assertFalse(
            any(header["status"] == "pending"
                for header in document["headers"])
        )
        self.assertEqual(document["finality"]["finalized"]["height"], 2)
        self.assertEqual(document["finality"]["tip"]["status"], "pending")
        self.assertEqual(
            document["finality"]["tip"]["tip_hash"],
            pending_block["block_hash"],
        )

    def test_finality_equals_get_chain_finality(self) -> None:
        bodies = self.build_confirmed((10,))
        document = self.fetch([bodies[0]["tx_id"]])
        status, chain_finality = self.service.get_chain_finality()
        self.assertEqual(status, 200)
        self.assertEqual(document["finality"], chain_finality)

    def test_items_match_single_receipt_contract(self) -> None:
        body = self.build_confirmed((10, 20, 30))[1]
        batch = self.fetch([body["tx_id"]])
        status, single = self.service.get_finalized_receipt(body["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(batch["items"][0], {
            "receipt": single["receipt"],
            "proof": single["proof"],
        })
        self.assertEqual(batch["headers"], single["headers"])
        self.assertEqual(batch["finality"], single["finality"])


class FinalizedReceiptsHttpTests(unittest.TestCase):
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

    def request(self, method: str, path: str, payload=None, raw: bool = False):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
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

    def test_endpoint_lifecycle_and_wire_key_order(self) -> None:
        # Malformed body is 400.
        self.assertEqual(
            self.request(
                "POST", "/v1/transactions/finalized-receipts", {}
            )[0],
            400,
        )
        # Unknown id is 404.
        self.assertEqual(
            self.request(
                "POST",
                "/v1/transactions/finalized-receipts",
                {"tx_ids": ["f" * 64]},
            )[0],
            404,
        )
        # Unconfirmed is 409.
        _, body = self.request("POST", "/v1/transactions", self.tx(10))
        tx_id = body["tx_id"]
        self.assertEqual(
            self.request(
                "POST",
                "/v1/transactions/finalized-receipts",
                {"tx_ids": [tx_id]},
            )[0],
            409,
        )
        _, block = self.request("POST", "/v1/blocks", {})
        self.request("POST", f"/v1/blocks/{block['height']}/confirm", {})

        status, raw = self.request(
            "POST",
            "/v1/transactions/finalized-receipts",
            {"tx_ids": [tx_id]},
            raw=True,
        )
        self.assertEqual(status, 200)
        pairs = ordered(raw)
        self.assertEqual(
            [key for key, _ in pairs], list(BATCH_DOCUMENT_FIELDS)
        )
        document = json.loads(raw)
        item_pairs = next(value for key, value in pairs if key == "items")[0]
        self.assertEqual([key for key, _ in item_pairs], list(ITEM_FIELDS))
        self.assertEqual(document["items"][0]["receipt"]["status"], "confirmed")

        # The single-receipt endpoint is unaffected.
        status, receipt = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")


class VerifyFinalizedReceiptsTests(FinalizedReceiptsFixture):
    """verify_finalized_receipts classification matrix."""

    def setUp(self) -> None:
        super().setUp()
        # Two confirmed blocks: three transactions in block 1, two in block
        # 2; then a pending tip block.
        self.tx_groups: list[list[dict]] = []
        for batch in ((10, 20, 30), (40, 50)):
            group = [self.submit(amount) for amount in batch]
            block = self.mine()
            self.confirm(block["height"])
            self.tx_groups.append(group)
        self.tx_ids = sorted(
            body["tx_id"] for group in self.tx_groups for body in group
        )
        self.pending_tx = self.submit(60)
        self.mine()  # unconfirmed tip
        self.document = self.fetch(self.tx_ids)

    _DEFAULT = object()

    def verify(self, document=_DEFAULT, tx_ids=_DEFAULT, trust=_DEFAULT):
        return verify_finalized_receipts(
            self.document if document is self._DEFAULT else document,
            self.tx_ids if tx_ids is self._DEFAULT else tx_ids,
            self.trust if trust is self._DEFAULT else trust,
        )

    def mutate(self) -> dict:
        return copy.deepcopy(self.document)

    def test_happy_round_trip_with_pending_tip(self) -> None:
        result = self.verify()
        self.assertEqual(tuple(result), BATCH_SUCCESS_FIELDS)
        self.assertTrue(result["ok"])
        self.assertEqual(result["tx_ids"], self.tx_ids)
        self.assertEqual(
            result["finalized"], self.document["finality"]["finalized"]
        )
        # A request-order permutation does not matter; the result ids stay
        # ascending.
        result = verify_finalized_receipts(
            self.document, list(reversed(self.tx_ids)), self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tx_ids"], self.tx_ids)

    def test_every_real_batch_verifies(self) -> None:
        # Block-1-only and block-2-only subsets exercise a run starting at
        # height 1 versus height 2.
        for group in self.tx_groups:
            ids = sorted(body["tx_id"] for body in group)
            document = self.fetch(ids)
            result = verify_finalized_receipts(document, ids, self.trust)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["tx_ids"], ids)

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
        bad["items"] = [{"receipt": bad["items"][0]["receipt"]}]
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["items"][0]["receipt"] = {"not": "a receipt"}
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

    def test_top_level_key_order_defect_is_input(self) -> None:
        bad = {
            "finality": self.document["finality"],
            "items": self.document["items"],
            "headers": self.document["headers"],
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        receipt, proof = bad["items"][0]["receipt"], bad["items"][0]["proof"]
        bad["items"][0] = {"proof": proof, "receipt": receipt}
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

    def test_expected_tx_ids_and_trust_defects_are_input(self) -> None:
        for bad_ids in (
            None, 123, "x", {}, True, [], ["0" * 64, "0" * 64],
            ["zz"], ["A" * 64], [123],
        ):
            self.assertEqual(
                self.verify(tx_ids=bad_ids),
                {"ok": False, "error": "input"},
                bad_ids,
            )
        for bad_trust in (None, 1, "x", [], {}, {"audit_signers": []}):
            self.assertEqual(
                self.verify(trust=bad_trust),
                {"ok": False, "error": "input"},
                bad_trust,
            )

    def test_hex_defects_are_input(self) -> None:
        bad = self.mutate()
        bad["items"][0]["receipt"]["block_hash"] = "Z" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["finality"]["auth"]["signature"] = "q" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        # A malformed (non-128-lowercase-hex) transaction signature is
        # input; a well-shaped but cryptographically wrong one is integrity.
        bad = self.mutate()
        bad["items"][0]["receipt"]["signature"] = "q" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})
        bad = self.mutate()
        bad["items"][0]["receipt"]["signature"] = "ab" * 32
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

    def test_items_must_be_ascending_and_distinct(self) -> None:
        bad = self.mutate()
        bad["items"] = list(reversed(bad["items"]))
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["items"].append(copy.deepcopy(bad["items"][0]))
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_expected_set_mismatch_is_integrity(self) -> None:
        missing = self.tx_ids[:-1]
        self.assertEqual(
            self.verify(tx_ids=missing),
            {"ok": False, "error": "integrity"},
        )
        extra = self.tx_ids + ["0" * 64]
        self.assertEqual(
            self.verify(tx_ids=extra),
            {"ok": False, "error": "integrity"},
        )

    def test_transaction_signature_and_tx_id_are_integrity(self) -> None:
        bad = self.mutate()
        bad["items"][0]["receipt"]["signature"] = "0" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["items"][0]["receipt"]["tx_id"] = "1" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_per_item_proof_tampering_is_integrity(self) -> None:
        bad = self.mutate()
        bad["items"][0]["proof"]["index"] += 1
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["items"][-1]["proof"]["merkle_root"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        first_siblings = bad["items"][0]["proof"]["siblings"]
        if first_siblings:
            bad["items"][0]["proof"]["siblings"][0]["hash"] = "0" * 64
            self.assertEqual(
                self.verify(bad), {"ok": False, "error": "integrity"}
            )

    def test_shared_chain_tampering_is_integrity(self) -> None:
        # The run must start at the lowest transaction's block.
        bad = self.mutate()
        del bad["headers"][0]
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["headers"][1]["prev_hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["headers"][-1]["status"] = "pending"
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_item_block_not_on_shared_run_is_integrity(self) -> None:
        # Swap a block-2 item's receipt block hash for a bogus (well-formed)
        # hash: the item no longer binds to the shared run.
        bad = self.mutate()
        target = next(
            item for item in bad["items"]
            if item["receipt"]["height"] == 2
        )
        target["receipt"]["block_hash"] = "0" * 64
        target["proof"]["block_hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_forged_consistent_document_is_integrity(self) -> None:
        """Re-signing tampered finality with a foreign-but-trusted key moves
        the failure from auth to the run/finalized binding (integrity)."""
        from ledger.light_client import sign_finality

        foreign_key = Ed25519PrivateKey.generate()
        foreign_seed = foreign_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        bad = self.mutate()
        foreign_finalized = {
            "height": bad["headers"][-2]["height"],
            "block_hash": bad["headers"][-2]["block_hash"],
        }
        bad["finality"]["finalized"] = foreign_finalized
        bad["finality"]["auth"] = sign_finality(
            foreign_seed,
            7,
            foreign_finalized,
            dict(bad["finality"]["tip"]),
        )
        foreign_trust = {
            "audit_signers": [{"version": 7, "public_key": pub_hex(foreign_key)}]
        }
        self.assertEqual(
            self.verify(document=bad, trust=foreign_trust),
            {"ok": False, "error": "integrity"},
        )

    def test_failure_result_has_only_ok_and_error(self) -> None:
        bad = self.mutate()
        bad["items"] = list(reversed(bad["items"]))
        result = self.verify(bad)
        self.assertEqual(set(result), {"ok", "error"})
        self.assertFalse(result["ok"])

    def test_never_raises(self) -> None:
        for junk in (None, 42, object(),
                     {"items": [], "headers": [], "finality": {}},
                     {"items": [object()], "headers": [], "finality": {}}):
            result = verify_finalized_receipts(junk, self.tx_ids, self.trust)
            self.assertFalse(result["ok"])
            self.assertEqual(set(result), {"ok", "error"})
        for junk in (object(), 42, None, [1, 2]):
            result = verify_finalized_receipts(self.document, junk, self.trust)
            self.assertEqual(result, {"ok": False, "error": "input"})
        for junk in (object(), 42, None):
            result = verify_finalized_receipts(
                self.document, self.tx_ids, junk
            )
            self.assertEqual(result, {"ok": False, "error": "input"})


class SingleReceiptSignatureClassificationTests(FinalizedReceiptsFixture):
    """The synchronized correction to verify_finalized_receipt."""

    def test_malformed_receipt_signature_is_input(self) -> None:
        body = self.build_confirmed((10,))[0]
        document = self.service.get_finalized_receipt(body["tx_id"])[1]

        for bad_signature in ("q" * 128, "ab" * 32, "", 123, None):
            bad = copy.deepcopy(document)
            bad["receipt"]["signature"] = bad_signature
            self.assertEqual(
                verify_finalized_receipt(bad, body["tx_id"], self.trust),
                {"ok": False, "error": "input"},
                bad_signature,
            )

    def test_well_shaped_wrong_signature_is_integrity(self) -> None:
        body = self.build_confirmed((10,))[0]
        document = self.service.get_finalized_receipt(body["tx_id"])[1]
        bad = copy.deepcopy(document)
        bad["receipt"]["signature"] = "0" * 128
        self.assertEqual(
            verify_finalized_receipt(bad, body["tx_id"], self.trust),
            {"ok": False, "error": "integrity"},
        )


if __name__ == "__main__":
    unittest.main()
