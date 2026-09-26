"""Tests for GET /v1/transactions/{tx_id}/finalized-receipt and the offline
verifier ``ledger.light_client.verify_finalized_receipt``.

Covers:

* the endpoint state machine: malformed/unknown ids are 404, mempool and
  packed-but-pending transactions are 409, and a confirmed transaction
  returns 200 with the contract key order ``receipt, proof, headers,
  finality`` — the nine-field confirmed receipt, the single-transaction
  Merkle proof, the ascending all-confirmed header chain from the
  transaction's block to the highest confirmed block, and the exact
  ``GET /v1/chain/finality`` credential whose ``finalized`` names the last
  header;
* the offline verifier: the happy path against the trust document, and
  the failure categories — shape/type/hex/argument defects ``input``,
  unknown key versions or bad finality signatures ``auth``, transaction
  signature, proof, header-chain or binding defects ``integrity``;
  nothing is raised;
* the HTTP layer preserves the contract key order on the wire.

Run: python3 tests/finalized_receipt_test.py
"""
from __future__ import annotations

import copy
import json
import os
import shutil
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

from ledger import crypto, light_client
from ledger.light_client import (
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    sign_finality,
    verify_finalized_receipt,
)
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

DOCUMENT_KEYS = ("receipt", "proof", "headers", "finality")
RECEIPT_KEYS = (
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
PROOF_KEYS = ("height", "tx_id", "index", "merkle_root", "block_hash", "siblings")
HEADER_KEYS = ("height", "prev_hash", "merkle_root", "block_hash", "status")
FINALITY_KEYS = ("finalized", "tip", "auth")
RESULT_KEYS = ("ok", "tx_id", "height", "block_hash", "finalized")


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class FinalizedReceiptFixture(unittest.TestCase):
    """A chain 0..3 confirmed (one transaction per block) plus a pending tip."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "ledger.json"))
        self.service = LedgerService(self.store)
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        self.tx_ids: list[str] = []
        for amount in (10, 20, 30):
            self.tx_ids.append(self._submit(amount))
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0],
                200,
            )
        # A mempool transaction packed into the pending tip at height 4.
        self.pending_tx_id = self._submit(5)
        self.assertEqual(self.service.mine_block()[0], 201)
        # And one transaction still sitting in the mempool.
        self.mempool_tx_id = self._submit(7)
        self.trust = self.service.get_trust_document()[1]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def _submit(self, amount: int) -> str:
        status, body = self.service.submit_transaction(self._tx(amount))
        self.assertEqual(status, 202, body)
        return body["tx_id"]

    def document(self, tx_id: str) -> dict:
        status, body = self.service.get_finalized_receipt(tx_id)
        self.assertEqual(status, 200, body)
        return body


class FinalizedReceiptServiceTests(FinalizedReceiptFixture):
    def test_malformed_and_unknown_tx_ids_are_404(self) -> None:
        for bad in ("", "zz", "g" * 64, "A" * 64, "a" * 63, "a" * 65, 123, None, True):
            self.assertEqual(
                self.service.get_finalized_receipt(bad)[0],
                404,
                f"malformed id {bad!r} must be 404",
            )
        self.assertEqual(self.service.get_finalized_receipt("0" * 64)[0], 404)
        self.assertEqual(self.service.get_finalized_receipt("f" * 64)[0], 404)

    def test_unconfirmed_transactions_are_409(self) -> None:
        # Still in the mempool.
        status, body = self.service.get_finalized_receipt(self.mempool_tx_id)
        self.assertEqual(status, 409)
        self.assertIn("error", body)
        # Packed into the pending tip block.
        status, body = self.service.get_finalized_receipt(self.pending_tx_id)
        self.assertEqual(status, 409)
        self.assertIn("error", body)

    def test_confirmed_document_shape_and_key_order(self) -> None:
        body = self.document(self.tx_ids[0])
        self.assertEqual(tuple(body.keys()), DOCUMENT_KEYS)

        receipt = body["receipt"]
        self.assertEqual(tuple(receipt.keys()), RECEIPT_KEYS)
        self.assertEqual(receipt["tx_id"], self.tx_ids[0])
        self.assertEqual(receipt["from"], self.sender)
        self.assertEqual(receipt["to"], self.bob)
        self.assertEqual(receipt["amount"], 10)
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(receipt["height"], 1)
        self.assertEqual(receipt["index"], 0)
        self.assertEqual(
            receipt["block_hash"], self.store.chain[1].block_hash
        )

        proof = body["proof"]
        self.assertEqual(tuple(proof.keys()), PROOF_KEYS)
        # The proof is exactly the single-transaction proof endpoint's body.
        self.assertEqual(
            proof, self.service.get_proof("1", self.tx_ids[0])[1]
        )

        headers = body["headers"]
        # From the transaction's block (height 1) to the highest confirmed
        # block (height 3); the pending tip at height 4 is never included.
        self.assertEqual([h["height"] for h in headers], [1, 2, 3])
        for header, block in zip(headers, self.store.chain[1:4]):
            self.assertEqual(tuple(header.keys()), HEADER_KEYS)
            self.assertEqual(header["status"], "confirmed")
            self.assertEqual(header["block_hash"], block.block_hash)
            self.assertEqual(header["prev_hash"], block.prev_hash)
            self.assertEqual(header["merkle_root"], block.merkle_root)

        finality = body["finality"]
        self.assertEqual(tuple(finality.keys()), FINALITY_KEYS)
        # Identical to GET /v1/chain/finality taken under the same lock.
        self.assertEqual(finality, self.service.get_chain_finality()[1])
        # finalized names the last header.
        self.assertEqual(
            finality["finalized"],
            {"height": headers[-1]["height"], "block_hash": headers[-1]["block_hash"]},
        )

    def test_headers_start_at_the_transactions_own_block(self) -> None:
        body = self.document(self.tx_ids[2])
        self.assertEqual(body["receipt"]["height"], 3)
        self.assertEqual([h["height"] for h in body["headers"]], [3])
        self.assertEqual(
            body["finality"]["finalized"]["block_hash"],
            body["headers"][-1]["block_hash"],
        )

    def test_pending_tip_never_advances_headers_or_finalized(self) -> None:
        body = self.document(self.tx_ids[1])
        self.assertEqual([h["height"] for h in body["headers"]], [2, 3])
        # The tip descriptor reports the pending chain tip...
        self.assertEqual(body["finality"]["tip"]["height"], 4)
        self.assertEqual(body["finality"]["tip"]["status"], "pending")
        # ...but finalized stays at the highest confirmed block.
        self.assertEqual(body["finality"]["finalized"]["height"], 3)


class FinalizedReceiptVerifyTests(FinalizedReceiptFixture):
    _UNSET = object()

    def verify(self, document: object, expected_tx_id: object = _UNSET, trust=_UNSET):
        return verify_finalized_receipt(
            document,
            self.tx_ids[0] if expected_tx_id is self._UNSET else expected_tx_id,
            self.trust if trust is self._UNSET else trust,
        )

    def test_happy_path(self) -> None:
        document = self.document(self.tx_ids[0])
        result = self.verify(document)
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)
        self.assertEqual(
            result,
            {
                "ok": True,
                "tx_id": self.tx_ids[0],
                "height": 1,
                "block_hash": self.store.chain[1].block_hash,
                "finalized": {
                    "height": 3,
                    "block_hash": self.store.chain[3].block_hash,
                },
            },
        )

    def test_every_confirmed_transaction_verifies(self) -> None:
        for tx_id, height in zip(self.tx_ids, (1, 2, 3)):
            result = self.verify(self.document(tx_id), tx_id)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["tx_id"], tx_id)
            self.assertEqual(result["height"], height)
            self.assertEqual(
                result["block_hash"], self.store.chain[height].block_hash
            )

    def test_input_category(self) -> None:
        document = self.document(self.tx_ids[0])
        cases = []
        # Not a document at all.
        cases.append("not-a-dict")
        # Wrong top-level key order and a missing key.
        reordered = {key: document[key] for key in reversed(DOCUMENT_KEYS)}
        cases.append(reordered)
        cases.append({k: v for k, v in document.items() if k != "proof"})
        # Receipt key order, a bad hex id and a bad type.
        bad = copy.deepcopy(document)
        bad["receipt"] = {k: bad["receipt"][k] for k in reversed(RECEIPT_KEYS)}
        cases.append(bad)
        bad = copy.deepcopy(document)
        bad["receipt"]["tx_id"] = "zz"
        cases.append(bad)
        bad = copy.deepcopy(document)
        bad["receipt"]["amount"] = True
        cases.append(bad)
        bad = copy.deepcopy(document)
        bad["receipt"]["signature"] = "not-hex"
        cases.append(bad)
        # Proof sibling shape and hex.
        bad = copy.deepcopy(document)
        bad["proof"]["siblings"] = [{"hash": "0" * 64, "direction": "left"}]
        cases.append(bad)
        bad = copy.deepcopy(document)
        bad["proof"]["siblings"] = [{"direction": "up", "hash": "0" * 64}]
        cases.append(bad)
        # Empty headers and a bad header status.
        bad = copy.deepcopy(document)
        bad["headers"] = []
        cases.append(bad)
        bad = copy.deepcopy(document)
        bad["headers"][0]["status"] = "unknown"
        cases.append(bad)
        # Finality envelope shape.
        bad = copy.deepcopy(document)
        bad["finality"]["auth"] = {"signature": "0" * 128, "key_version": 1}
        cases.append(bad)
        for case in cases:
            result = self.verify(case)
            self.assertEqual(
                result, {"ok": False, "error": ERR_INPUT}, f"case: {case!r}"
            )
        # Malformed expected_tx_id and trust arguments.
        self.assertEqual(
            self.verify(document, expected_tx_id="zz"),
            {"ok": False, "error": ERR_INPUT},
        )
        self.assertEqual(
            self.verify(document, expected_tx_id=123),
            {"ok": False, "error": ERR_INPUT},
        )
        for bad_trust in (None, {}, {"audit_signers": []}, {"audit_signers": "x"}):
            self.assertEqual(
                self.verify(document, trust=bad_trust),
                {"ok": False, "error": ERR_INPUT},
            )

    def test_auth_category(self) -> None:
        document = self.document(self.tx_ids[0])
        # Unknown key version.
        bad = copy.deepcopy(document)
        bad["finality"]["auth"]["key_version"] = 99
        self.assertEqual(
            self.verify(bad), {"ok": False, "error": ERR_AUTH}
        )
        # A tampered finalized target breaks the signature.
        bad = copy.deepcopy(document)
        bad["finality"]["finalized"] = {
            "height": 3,
            "block_hash": "0" * 64,
        }
        self.assertEqual(
            self.verify(bad), {"ok": False, "error": ERR_AUTH}
        )
        # A tampered tip descriptor breaks the signature.
        bad = copy.deepcopy(document)
        bad["finality"]["tip"]["height"] = 9
        self.assertEqual(
            self.verify(bad), {"ok": False, "error": ERR_AUTH}
        )
        # A trust document naming a different key fails the signature.
        other = Ed25519PrivateKey.generate()
        bad_trust = {
            "audit_signers": [{"version": 1, "public_key": pub_hex(other)}]
        }
        self.assertEqual(
            self.verify(document, trust=bad_trust),
            {"ok": False, "error": ERR_AUTH},
        )

    def _resign(self, document: dict) -> None:
        """Re-sign the finality credential in place with the real signer."""
        signer = self.store.audit_signer
        document["finality"]["auth"] = sign_finality(
            signer["private_key"],
            signer["version"],
            document["finality"]["finalized"],
            document["finality"]["tip"],
        )

    def test_integrity_transaction_and_receipt(self) -> None:
        document = self.document(self.tx_ids[0])
        # Amount tampered: the recomputed tx_id no longer matches.
        bad = copy.deepcopy(document)
        bad["receipt"]["amount"] = 11
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # Signature from a different key.
        bad = copy.deepcopy(document)
        other = Ed25519PrivateKey.generate()
        message = crypto.canonical_message(self.sender, self.bob, 10)
        bad["receipt"]["signature"] = other.sign(message).hex()
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # The expected_tx_id pin mismatches the proven transaction.
        self.assertEqual(
            self.verify(document, expected_tx_id="f" * 64),
            {"ok": False, "error": ERR_INTEGRITY},
        )
        # A non-confirmed receipt status.
        bad = copy.deepcopy(document)
        bad["receipt"]["status"] = "pending"
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # Receipt/proof disagreement on height, index and block hash.
        for field, value in (("height", 2), ("index", 1)):
            bad = copy.deepcopy(document)
            bad["proof"][field] = value
            self.assertEqual(
                self.verify(bad), {"ok": False, "error": ERR_INTEGRITY}
            )
        bad = copy.deepcopy(document)
        bad["receipt"]["block_hash"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})

    def test_integrity_merkle_path(self) -> None:
        # A two-transaction block so the proof carries a sibling: confirm
        # the fixture's pending tip first, then mine and confirm it.
        self.assertEqual(
            self.service.confirm_block(str(self.store.tip().height))[0], 200
        )
        extra = self._submit(40)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(
            self.service.confirm_block(str(self.store.tip().height))[0], 200
        )
        document = self.document(extra)
        self.assertEqual(len(document["proof"]["siblings"]), 1)
        # A tampered sibling hash no longer recomputes the root.
        bad = copy.deepcopy(document)
        bad["proof"]["siblings"][0]["hash"] = "0" * 64
        self.assertEqual(self.verify(bad, extra), {"ok": False, "error": ERR_INTEGRITY})
        # A flipped direction breaks the path/index agreement.
        bad = copy.deepcopy(document)
        sibling = bad["proof"]["siblings"][0]
        sibling["direction"] = "left" if sibling["direction"] == "right" else "right"
        self.assertEqual(self.verify(bad, extra), {"ok": False, "error": ERR_INTEGRITY})
        # A tampered merkle root breaks both path and header binding.
        bad = copy.deepcopy(document)
        bad["proof"]["merkle_root"] = "0" * 64
        self.assertEqual(self.verify(bad, extra), {"ok": False, "error": ERR_INTEGRITY})

    def test_integrity_header_chain(self) -> None:
        document = self.document(self.tx_ids[0])
        # A tampered header hash no longer recomputes.
        bad = copy.deepcopy(document)
        bad["headers"][1]["merkle_root"] = "0" * 64
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # A dropped header breaks both the height sequence and the finality
        # binding.
        bad = copy.deepcopy(document)
        del bad["headers"][1]
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # A pending header is never part of a finalized chain.
        bad = copy.deepcopy(document)
        bad["headers"][-1]["status"] = "pending"
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # The first header must be the receipt's own block.
        bad = copy.deepcopy(document)
        bad["receipt"]["height"] = 2
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})

    def test_integrity_finality_binding(self) -> None:
        document = self.document(self.tx_ids[0])
        # finalized names a header other than the last one (re-signed, so
        # only the binding can fail).
        bad = copy.deepcopy(document)
        bad["finality"]["finalized"] = {
            "height": 2,
            "block_hash": self.store.chain[2].block_hash,
        }
        self._resign(bad)
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # An incoherent tip descriptor (length != height + 1).
        bad = copy.deepcopy(document)
        bad["finality"]["tip"]["length"] = 99
        self._resign(bad)
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})
        # The finalized boundary above the tip.
        bad = copy.deepcopy(document)
        bad["finality"]["tip"]["height"] = 2
        bad["finality"]["tip"]["length"] = 3
        self._resign(bad)
        self.assertEqual(self.verify(bad), {"ok": False, "error": ERR_INTEGRITY})

    def test_never_raises(self) -> None:
        for garbage in (None, 42, [], ["x"], {"receipt": None}, object()):
            result = verify_finalized_receipt(garbage, "0" * 64, self.trust)
            self.assertEqual(result["ok"], False)
            self.assertIn(result["error"], (ERR_INPUT, ERR_AUTH, ERR_INTEGRITY))


class FinalizedReceiptHttpTests(unittest.TestCase):
    """GET /v1/transactions/{tx_id}/finalized-receipt over the real server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.key = Ed25519PrivateKey.generate()
        cls.sender = pub_hex(cls.key)
        cls.bob = "b" * 64
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"))
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
        shutil.rmtree(cls.tmp, ignore_errors=True)

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

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def test_endpoint_lifecycle_and_wire_key_order(self) -> None:
        # Unknown and malformed ids are 404.
        self.assertEqual(
            self.request("GET", "/v1/transactions/" + "f" * 64 + "/finalized-receipt")[0],
            404,
        )
        self.assertEqual(
            self.request("GET", "/v1/transactions/not-hex/finalized-receipt")[0],
            404,
        )
        self.assertEqual(
            self.request("GET", "/v1/transactions//finalized-receipt")[0], 404
        )

        # Mempool: 409.
        _, body = self.request("POST", "/v1/transactions", self._tx(10))
        tx_id = body["tx_id"]
        self.assertEqual(
            self.request("GET", f"/v1/transactions/{tx_id}/finalized-receipt")[0],
            409,
        )

        # Packed but unconfirmed: 409.
        _, block = self.request("POST", "/v1/blocks", {})
        self.assertEqual(
            self.request("GET", f"/v1/transactions/{tx_id}/finalized-receipt")[0],
            409,
        )

        # Confirmed: 200 with the contract key order on the wire.
        self.request("POST", f"/v1/blocks/{block['height']}/confirm", {})
        status, document = self.request(
            "GET", f"/v1/transactions/{tx_id}/finalized-receipt"
        )
        self.assertEqual(status, 200)
        self.assertEqual(tuple(document.keys()), DOCUMENT_KEYS)
        self.assertEqual(tuple(document["receipt"].keys()), RECEIPT_KEYS)
        self.assertEqual(tuple(document["proof"].keys()), PROOF_KEYS)
        self.assertEqual(tuple(document["finality"].keys()), FINALITY_KEYS)
        for header in document["headers"]:
            self.assertEqual(tuple(header.keys()), HEADER_KEYS)
            self.assertEqual(header["status"], "confirmed")
        self.assertEqual(document["receipt"]["status"], "confirmed")
        self.assertEqual(
            document["finality"]["finalized"],
            {
                "height": document["headers"][-1]["height"],
                "block_hash": document["headers"][-1]["block_hash"],
            },
        )
        # The wire document verifies offline against the node's trust document.
        _, trust = self.request("GET", "/v1/trust")
        result = verify_finalized_receipt(document, tx_id, trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)

        # The plain receipt endpoint is untouched.
        status, receipt = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(receipt["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
