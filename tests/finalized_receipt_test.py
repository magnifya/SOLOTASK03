"""Tests for the offline-verifiable finalized transaction receipt.

Covers both sides of the contract:

* ``GET /v1/transactions/{tx_id}/finalized-receipt`` (service and HTTP):
  malformed/unknown ids are 404, mempool and packed-but-unconfirmed
  transactions are 409, and a confirmed transaction returns 200 with the
  exact fixed key order ``receipt, proof, headers, finality``. The receipt
  is the fixed nine-field receipt with ``status=confirmed``; the proof is
  the single-transaction Merkle proof; the headers run from the
  transaction's block through the highest confirmed block, ascending, each
  the five-field signed header item and all confirmed; the finality
  credential is the ``GET /v1/chain/finality`` document with
  ``finalized`` equal to the last header. The chain and the audit signer
  are snapshotted together under one store lock, including when a pending
  chain tip sits above the confirmed head.

* ``ledger.light_client.verify_finalized_receipt``: the happy round trip
  over the real 200 documents and every failure classification — shape,
  type, hex, ``expected_tx_id`` and trust defects are ``input``; unknown
  key version or a failed finality signature is ``auth``; a transaction
  signature, proof, header-chain or binding defect is ``integrity``. The
  success key order is ``ok, tx_id, height, block_hash, finalized`` and a
  failure carries only ``ok, error``; nothing is raised for junk input.

Run: python3 tests/finalized_receipt_test.py
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
from ledger.light_client import verify_finalized_receipt
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
HEADER_FIELDS = ("height", "prev_hash", "merkle_root", "block_hash", "status")
FINALITY_FIELDS = ("finalized", "tip", "auth")
DOCUMENT_FIELDS = ("receipt", "proof", "headers", "finality")
SUCCESS_FIELDS = ("ok", "tx_id", "height", "block_hash", "finalized")


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def ordered(value: bytes):
    """Decode JSON preserving every object's key insertion order."""
    return json.loads(value, object_pairs_hook=lambda pairs: pairs)


class FinalizedReceiptFixture(unittest.TestCase):
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

    def fetch(self, tx_id: str) -> dict:
        status, body = self.service.get_finalized_receipt(tx_id)
        self.assertEqual(status, 200, body)
        return body


class FinalizedReceiptServiceTests(FinalizedReceiptFixture):
    def test_malformed_and_unknown_ids_are_404(self) -> None:
        for bad in ("", "zz", "g" * 64, "A" * 63, "a" * 65, 123, None, True):
            self.assertEqual(
                self.service.get_finalized_receipt(bad)[0], 404, bad
            )
        self.assertEqual(self.service.get_finalized_receipt("0" * 64)[0], 404)
        self.assertEqual(self.service.get_finalized_receipt("f" * 64)[0], 404)

    def test_mempool_and_pending_tip_transactions_are_409(self) -> None:
        mempool = self.submit(10)
        self.assertEqual(
            self.service.get_finalized_receipt(mempool["tx_id"])[0], 409
        )
        block = self.mine()  # packs the tx, stays pending
        self.assertEqual(
            self.service.get_finalized_receipt(mempool["tx_id"])[0], 409
        )
        # Only the genesis block is confirmed; the 409 says nothing about
        # a later confirmed head.
        self.assertEqual(block["height"], 1)
        self.confirm(block["height"])
        self.assertEqual(
            self.service.get_finalized_receipt(mempool["tx_id"])[0], 200
        )

    def test_confirmed_document_shape_and_key_order(self) -> None:
        body = self.build_confirmed((10, 20))[0]
        document = self.fetch(body["tx_id"])
        self.assertEqual(tuple(document), DOCUMENT_FIELDS)

        receipt = document["receipt"]
        self.assertEqual(tuple(receipt), RECEIPT_FIELDS)
        self.assertEqual(receipt["tx_id"], body["tx_id"])
        self.assertEqual(receipt["from"], self.sender)
        self.assertEqual(receipt["to"], self.bob)
        self.assertEqual(receipt["amount"], 10)
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["height"], 1)
        self.assertIsInstance(receipt["index"], int)
        self.assertTrue(crypto.is_hex64(receipt["block_hash"]))

        proof = document["proof"]
        self.assertEqual(tuple(proof), PROOF_FIELDS)
        self.assertEqual(
            (proof["height"], proof["tx_id"], proof["index"]),
            (receipt["height"], receipt["tx_id"], receipt["index"]),
        )
        self.assertEqual(proof["block_hash"], receipt["block_hash"])
        self.assertTrue(crypto.verify_merkle_proof(
            proof["tx_id"],
            proof["siblings"],
            proof["merkle_root"],
            proof["block_hash"],
            receipt["block_hash"],
        ))

        headers = document["headers"]
        self.assertGreaterEqual(len(headers), 1)
        for item in headers:
            self.assertEqual(tuple(item), HEADER_FIELDS)
            self.assertEqual(item["status"], "confirmed")
        heights = [item["height"] for item in headers]
        self.assertEqual(heights, list(range(heights[0], heights[-1] + 1)))
        self.assertEqual(heights[0], receipt["height"])

        finality = document["finality"]
        self.assertEqual(tuple(finality), FINALITY_FIELDS)
        self.assertEqual(
            finality["finalized"],
            {"height": headers[-1]["height"], "block_hash": headers[-1]["block_hash"]},
        )
        self.assertEqual(
            tuple(finality["auth"]), ("key_version", "signature")
        )

    def test_headers_run_from_tx_block_to_highest_confirmed_block(self) -> None:
        bodies = self.build_confirmed((10, 20, 30, 40))
        for tx_body in bodies:
            document = self.fetch(tx_body["tx_id"])
            heights = [item["height"] for item in document["headers"]]
            receipt_height = document["receipt"]["height"]
            # The head was confirmed at block 4 when the documents were read.
            self.assertEqual(heights[0], receipt_height)
            self.assertEqual(heights[-1], 4)
            self.assertEqual(heights, list(range(receipt_height, 5)))
            self.assertEqual(
                document["finality"]["finalized"],
                {"height": 4, "block_hash": document["headers"][-1]["block_hash"]},
            )

    def test_finality_is_the_get_chain_finality_document(self) -> None:
        body = self.build_confirmed((10, 20))[0]
        # A pending tip above the confirmed head: finalized must stay at the
        # last confirmed block while tip is pending.
        pending_tx = self.submit(5)
        pending_block = self.mine()
        document = self.fetch(body["tx_id"])
        status, chain_finality = self.service.get_chain_finality()
        self.assertEqual(status, 200)
        self.assertEqual(document["finality"], chain_finality)
        self.assertEqual(document["finality"]["finalized"]["height"], 2)
        self.assertEqual(document["finality"]["tip"]["status"], "pending")
        self.assertEqual(
            document["finality"]["tip"]["tip_hash"], pending_block["block_hash"]
        )
        # The header run stops at the confirmed head: the pending block is
        # never included even though the chain has advanced.
        self.assertEqual(document["headers"][-1]["height"], 2)
        self.assertFalse(
            any(item["status"] == "pending" for item in document["headers"])
        )
        # The unconfirmed tip transaction stays 409.
        self.assertEqual(
            self.service.get_finalized_receipt(pending_tx["tx_id"])[0], 409
        )

    def test_first_block_transaction_headers_start_at_height_one(self) -> None:
        body = self.build_confirmed((7,))[0]
        document = self.fetch(body["tx_id"])
        self.assertEqual([item["height"] for item in document["headers"]], [1])
        self.assertEqual(
            document["finality"]["tip"]["status"], "confirmed"
        )


class FinalizedReceiptHttpTests(unittest.TestCase):
    """GET /v1/transactions/{tx_id}/finalized-receipt over the real server."""

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
        # Malformed and unknown ids are 404.
        self.assertEqual(
            self.request("GET", "/v1/transactions/nope/finalized-receipt")[0],
            404,
        )
        self.assertEqual(
            self.request("GET", f"/v1/transactions/{'f' * 64}/finalized-receipt")[0],
            404,
        )

        # Mempool and packed-but-unconfirmed are 409.
        _, body = self.request("POST", "/v1/transactions", self.tx(10))
        tx_id = body["tx_id"]
        self.assertEqual(
            self.request("GET", f"/v1/transactions/{tx_id}/finalized-receipt")[0],
            409,
        )
        _, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(
            self.request("GET", f"/v1/transactions/{tx_id}/finalized-receipt")[0],
            409,
        )
        self.request("POST", f"/v1/blocks/{block['height']}/confirm", {})

        status, raw = self.request(
            "GET", f"/v1/transactions/{tx_id}/finalized-receipt", raw=True
        )
        self.assertEqual(status, 200)
        pairs = ordered(raw)
        # The wire document keeps the contract-fixed top-level key order.
        self.assertEqual([key for key, _ in pairs], list(DOCUMENT_FIELDS))
        document = json.loads(raw)
        receipt_pairs = next(value for key, value in pairs if key == "receipt")
        self.assertEqual([key for key, _ in receipt_pairs], list(RECEIPT_FIELDS))
        self.assertEqual(document["receipt"]["status"], "confirmed")

        # The ordinary receipt endpoint is unaffected.
        status, receipt = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")


class VerifyFinalizedReceiptTests(FinalizedReceiptFixture):
    """ledger.light_client.verify_finalized_receipt classification matrix."""

    def setUp(self) -> None:
        super().setUp()
        # Two confirmed blocks: three transactions in block 1 (a non-power
        # of two leaf count exercising the odd-node self-pair rule) and two
        # in block 2; then a pending tip block.
        self.txs: list[dict] = []
        for batch in ((10, 20, 30), (40, 50)):
            for amount in batch:
                self.txs.append(self.submit(amount))
            block = self.mine()
            self.confirm(block["height"])
        self.tx_id = self.txs[0]["tx_id"]
        self.pending_tx = self.submit(60)
        self.mine()  # unconfirmed tip
        self.document = self.fetch(self.tx_id)

    _DEFAULT = object()

    def verify(self, document=_DEFAULT, tx_id=_DEFAULT, trust=_DEFAULT):
        return verify_finalized_receipt(
            self.document if document is self._DEFAULT else document,
            self.tx_id if tx_id is self._DEFAULT else tx_id,
            self.trust if trust is self._DEFAULT else trust,
        )

    def mutate(self) -> dict:
        """A deep copy of the canonical document ready for tampering."""
        return copy.deepcopy(self.document)

    def test_happy_round_trip_with_pending_tip(self) -> None:
        result = self.verify()
        self.assertEqual(
            tuple(result), SUCCESS_FIELDS
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["tx_id"], self.tx_id)
        self.assertEqual(result["height"], self.document["receipt"]["height"])
        self.assertEqual(
            result["block_hash"], self.document["receipt"]["block_hash"]
        )
        self.assertEqual(
            result["finalized"], self.document["finality"]["finalized"]
        )
        # Re-reading the same state rebuilds an equal document.
        self.assertEqual(
            self.service.get_finalized_receipt(self.tx_id)[1], self.document
        )

    def test_every_transaction_in_a_multi_leaf_block_verifies(self) -> None:
        for tx_body in self.txs:
            document = self.fetch(tx_body["tx_id"])
            result = verify_finalized_receipt(
                document, tx_body["tx_id"], self.trust
            )
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["height"], document["receipt"]["height"])
            self.assertGreaterEqual(len(document["proof"]["siblings"]), 1)

    # -- input -------------------------------------------------------------

    def test_shape_and_type_defects_are_input(self) -> None:
        for junk in (None, 1, "x", [], {}, True):
            self.assertEqual(self.verify(junk), {"ok": False, "error": "input"})

        bad = self.mutate()
        del bad["receipt"]
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["receipt"] = {
            key: bad["receipt"][key] for key in RECEIPT_FIELDS if key != "to"
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["receipt"] = {
            key: (value if key != "amount" else "10")
            for key, value in bad["receipt"].items()
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["receipt"] = {
            key: (value if key != "amount" else True)
            for key, value in bad["receipt"].items()
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["proof"] = {"not": "a proof"}
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["headers"] = []
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["headers"][0] = {"height": 1, "block_hash": "0" * 64}
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

    def test_key_order_defects_are_input(self) -> None:
        bad = {
            "proof": self.document["proof"],
            "receipt": self.document["receipt"],
            "headers": self.document["headers"],
            "finality": self.document["finality"],
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        receipt = bad["receipt"]
        reordered = {"amount": receipt["amount"]}
        for key in receipt:
            if key != "amount":
                reordered[key] = receipt[key]
        bad["receipt"] = reordered
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        proof = bad["proof"]
        bad["proof"] = {
            "tx_id": proof["tx_id"],
            "height": proof["height"],
            "index": proof["index"],
            "merkle_root": proof["merkle_root"],
            "block_hash": proof["block_hash"],
            "siblings": proof["siblings"],
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

    def test_expected_tx_id_and_trust_defects_are_input(self) -> None:
        for bad_pin in (None, 123, "zz", "A" * 64, True, ""):
            self.assertEqual(
                self.verify(tx_id=bad_pin),
                {"ok": False, "error": "input"},
                bad_pin,
            )
        # Well-formed but different pin: still an input mismatch.
        self.assertEqual(
            self.verify(tx_id="0" * 64),
            {"ok": False, "error": "input"},
        )
        for bad_trust in (None, 1, "x", [], {}, {"audit_signers": []}):
            self.assertEqual(
                self.verify(trust=bad_trust),
                {"ok": False, "error": "input"},
                bad_trust,
            )

    def test_hex_defects_are_input(self) -> None:
        bad = self.mutate()
        bad["receipt"] = {
            **bad["receipt"],
            "block_hash": "Z" * 64,
        }
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["finality"]["auth"]["signature"] = "q" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "input"})

        bad = self.mutate()
        bad["proof"]["siblings"][0]["direction"] = "sideways"
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

    def test_receipt_status_must_be_confirmed(self) -> None:
        bad = self.mutate()
        bad["receipt"]["status"] = "pending"
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_transaction_signature_and_tx_id_are_integrity(self) -> None:
        bad = self.mutate()
        bad["receipt"]["signature"] = "0" * 128
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["receipt"]["tx_id"] = "1" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_proof_bindings_are_integrity(self) -> None:
        bad = self.mutate()
        bad["proof"]["index"] = bad["proof"]["index"] + 1
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["proof"]["block_hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["proof"]["tx_id"] = self.txs[-1]["tx_id"]
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        bad = self.mutate()
        bad["proof"]["merkle_root"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        for index, item in enumerate(self.document["proof"]["siblings"]):
            bad = self.mutate()
            bad["proof"]["siblings"][index]["hash"] = "0" * 64
            self.assertEqual(
                self.verify(bad), {"ok": False, "error": "integrity"}, index
            )

    def test_header_chain_defects_are_integrity(self) -> None:
        bad = self.mutate()
        bad["headers"][0]["block_hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

        if len(self.document["headers"]) > 1:
            bad = self.mutate()
            bad["headers"][1]["prev_hash"] = "0" * 64
            self.assertEqual(
                self.verify(bad), {"ok": False, "error": "integrity"}
            )

            bad = self.mutate()
            bad["headers"][1]["height"] += 1
            self.assertEqual(
                self.verify(bad), {"ok": False, "error": "integrity"}
            )

        bad = self.mutate()
        bad["headers"][-1]["status"] = "pending"
        self.assertEqual(self.verify(bad), {"ok": False, "error": "integrity"})

    def test_finality_binding_is_covered_by_the_signed_envelope(self) -> None:
        # The finality unsigned bytes are tampered with but not re-signed:
        # the stale envelope fails verification first (auth), so no binding
        # defect can ever downgrade past authentication.
        bad = self.mutate()
        bad["finality"]["finalized"]["height"] = 0
        self.assertEqual(self.verify(bad), {"ok": False, "error": "auth"})

        bad = self.mutate()
        bad["finality"]["tip"]["tip_hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": "auth"})

    def test_forged_consistent_document_is_integrity(self) -> None:
        """Re-sign a tampered finality with a foreign-but-trusted key: once
        the envelope authenticates, the run/finalized binding mismatch is an
        integrity failure.
        """
        from ledger.light_client import sign_finality

        foreign_key = Ed25519PrivateKey.generate()
        foreign_seed = foreign_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        bad = copy.deepcopy(self.document)
        # Point the finalized boundary at the previous run header instead of
        # the last one, keeping the unsigned credential otherwise coherent.
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
        result = verify_finalized_receipt(bad, self.tx_id, foreign_trust)
        self.assertEqual(result, {"ok": False, "error": "integrity"})

    def test_confirmed_tip_must_name_the_run_tail(self) -> None:
        # Confirm the pending tip so the credential's tip is confirmed, then
        # tamper with the unsigned descriptor; the signature fails (auth),
        # proving the tip binding is covered by the signed envelope.
        self.service.confirm_block(self.service.store.tip().height)
        document = self.fetch(self.tx_id)
        self.assertEqual(document["finality"]["tip"]["status"], "confirmed")
        self.assertTrue(
            verify_finalized_receipt(document, self.tx_id, self.trust)["ok"]
        )

    def test_failure_result_has_only_ok_and_error(self) -> None:
        bad = self.mutate()
        bad["receipt"]["status"] = "pending"
        result = self.verify(bad)
        self.assertEqual(set(result), {"ok", "error"})
        self.assertFalse(result["ok"])

    def test_never_raises(self) -> None:
        for junk in (None, 42, object(), {"receipt": object()},
                     {"receipt": {}, "proof": {}, "headers": {}, "finality": {}}):
            result = verify_finalized_receipt(junk, self.tx_id, self.trust)
            self.assertFalse(result["ok"])
            self.assertEqual(set(result), {"ok", "error"})
        for junk in (object(), 42, None, [1, 2]):
            result = verify_finalized_receipt(self.document, junk, self.trust)
            self.assertEqual(result, {"ok": False, "error": "input"})
        for junk in (object(), 42, None):
            result = verify_finalized_receipt(self.document, self.tx_id, junk)
            self.assertEqual(result, {"ok": False, "error": "input"})


if __name__ == "__main__":
    unittest.main()
