"""Tests for the batch receipt-proof verifier and audit summary.

``ledger.light_client.verify_receipt_proofs(documents, expected_root)``
and ``ledger.light_client.receipt_proofs_audit(documents,
expected_root)`` share one non-short-circuiting batch pass:

* a batch is a non-empty list of :func:`receipt_proof` success
  documents against a 64-lowercase-hex ``expected_root``; a shape
  defect returns only ``{"ok": False, "error": "input"}``.
* every item keeps the single-item verdict, independently verified;
  the verifier result has key order ``ok, root, results``.
* an item claims its receipt ``tx_id`` as soon as the single-item
  contract yields a legal id, even when the item itself fails; every
  later item naming an already claimed id is pinned to ``integrity``.
* the audit result has key order
  ``ok, root, total, succeeded, errors, entries, digest``: ``errors``
  has key order ``input, integrity`` with non-boolean non-negative
  integer counts summing to the failure count, ``entries`` is the same
  length/order as the input with successful items exactly ``{tx_id}``
  and failed ones exactly ``{error}``, and ``digest`` is the SHA-256
  lowercase hex of the canonical UTF-8 JSON of the summary minus
  ``digest``.

Nothing is read or written, the arguments are never mutated and
nothing is raised.

Run: python3 tests/receipt_proofs_batch_test.py
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
    advance_receipts,
    receipt_proof,
    receipt_proofs_audit,
    verify_receipt_proofs,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

VERIFY_KEYS = ["ok", "root", "results"]
AUDIT_KEYS = [
    "ok",
    "root",
    "total",
    "succeeded",
    "errors",
    "entries",
    "digest",
]
BAD_BATCH = {"ok": False, "error": "input"}


def canonical_digest(summary: dict) -> str:
    body = {key: value for key, value in summary.items() if key != "digest"}
    return hashlib.sha256(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


class BatchFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "ledger.json"))
        )
        self.key = Ed25519PrivateKey.generate()
        self.sender = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
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

    def populate(self, amounts: tuple[int, ...] = (10, 20, 30)) -> list[str]:
        ids = []
        for amount in amounts:
            status, body = self.service.submit_transaction(self.tx(amount))
            self.assertEqual(status, 202, body)
            ids.append(body["tx_id"])
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("1")[0], 200)
        ids = sorted(ids)
        status, document = self.service.get_finalized_receipts(
            {"tx_ids": ids}
        )
        self.assertEqual(status, 200, document)
        result = advance_receipts(self.path, document, ids, self.trust)
        self.assertTrue(result["ok"], result)
        return ids

    def proofs(self, ids: list[str]) -> list[dict]:
        documents = [receipt_proof(self.path, tx_id) for tx_id in ids]
        self.root = documents[0]["root"]
        return documents


class VerifyBatchTests(BatchFixture):
    def setUp(self) -> None:
        super().setUp()
        self.ids = self.populate()
        self.docs = self.proofs(self.ids)

    def test_all_success(self) -> None:
        result = verify_receipt_proofs(self.docs, self.root)
        self.assertEqual(list(result), VERIFY_KEYS)
        self.assertIs(result["ok"], True)
        self.assertEqual(result["root"], self.root)
        self.assertEqual(len(result["results"]), len(self.docs))
        for position, (entry, tx_id) in enumerate(
            zip(result["results"], self.ids)
        ):
            self.assertIs(entry["ok"], True)
            self.assertEqual(entry["tx_id"], tx_id)
            self.assertEqual(entry["index"], position)

    def test_failure_does_not_short_circuit(self) -> None:
        documents = list(self.docs)
        documents[1] = {"ok": False}
        result = verify_receipt_proofs(documents, self.root)
        self.assertIs(result["ok"], False)
        self.assertEqual(len(result["results"]), 3)
        self.assertIs(result["results"][0]["ok"], True)
        self.assertEqual(
            result["results"][1], {"ok": False, "error": "input"}
        )
        self.assertIs(result["results"][2]["ok"], True)

    def test_duplicate_id_beyond_first_is_integrity(self) -> None:
        result = verify_receipt_proofs(
            [self.docs[0], self.docs[0]], self.root
        )
        self.assertIs(result["ok"], False)
        self.assertIs(result["results"][0]["ok"], True)
        self.assertEqual(
            result["results"][1], {"ok": False, "error": "integrity"}
        )

    def test_first_failing_item_still_claims_its_id(self) -> None:
        # An input defect fails the item but its receipt still names a
        # legal tx_id; that slot is spent, so the later valid document
        # for the same id becomes integrity.
        bad = copy.deepcopy(self.docs[0])
        bad["generation"] = 0
        result = verify_receipt_proofs([bad, self.docs[0]], self.root)
        self.assertEqual(
            result["results"][0], {"ok": False, "error": "input"}
        )
        self.assertEqual(
            result["results"][1], {"ok": False, "error": "integrity"}
        )

    def test_integrity_failure_still_claims_its_id(self) -> None:
        bad = copy.deepcopy(self.docs[1])
        bad["root"] = "a" * 64  # legal hex, wrong value
        result = verify_receipt_proofs([bad, self.docs[1]], self.root)
        self.assertEqual(
            result["results"][0], {"ok": False, "error": "integrity"}
        )
        self.assertEqual(
            result["results"][1], {"ok": False, "error": "integrity"}
        )

    def test_first_failure_keeps_own_verdict_for_one_id(self) -> None:
        first, second = copy.deepcopy(self.docs[0]), copy.deepcopy(
            self.docs[0]
        )
        first["generation"] = 0
        second["generation"] = -1
        result = verify_receipt_proofs([first, second], self.root)
        self.assertEqual(
            result["results"],
            [
                {"ok": False, "error": "input"},
                {"ok": False, "error": "integrity"},
            ],
        )

    def test_malformed_item_does_not_claim_an_id(self) -> None:
        # Wrong item key order -> input, and no legal id is obtained, so
        # the following genuine document still succeeds.
        reordered = copy.deepcopy(self.docs[0])
        reordered["item"] = {
            "proof": reordered["item"]["proof"],
            "receipt": reordered["item"]["receipt"],
        }
        result = verify_receipt_proofs(
            [reordered, self.docs[0]], self.root
        )
        self.assertEqual(
            result["results"][0], {"ok": False, "error": "input"}
        )
        self.assertIs(result["results"][1]["ok"], True)

    def test_batch_shape_defects(self) -> None:
        for documents, root in [
            ([], self.root),
            ("not-a-list", self.root),
            (None, self.root),
            (self.docs, "0" * 63),
            (self.docs, "A" * 64),
            (self.docs, None),
            (self.docs, 7),
        ]:
            result = verify_receipt_proofs(documents, root)
            self.assertEqual(result, BAD_BATCH, (documents, root))
            self.assertEqual(list(result), ["ok", "error"])

    def test_junk_items_never_raise(self) -> None:
        for junk in (object(), 7, True, [1], {object(): 1}, None):
            result = verify_receipt_proofs([junk], self.root)
            self.assertEqual(
                result["results"], [{"ok": False, "error": "input"}], junk
            )

    def test_arguments_not_mutated(self) -> None:
        documents_before = copy.deepcopy(self.docs)
        verify_receipt_proofs(self.docs, self.root)
        self.assertEqual(self.docs, documents_before)


class AuditTests(BatchFixture):
    def setUp(self) -> None:
        super().setUp()
        self.ids = self.populate()
        self.docs = self.proofs(self.ids)

    def test_all_success_summary(self) -> None:
        audit = receipt_proofs_audit(self.docs, self.root)
        self.assertEqual(list(audit), AUDIT_KEYS)
        self.assertIs(audit["ok"], True)
        self.assertEqual(audit["root"], self.root)
        self.assertEqual(audit["total"], 3)
        self.assertEqual(audit["succeeded"], 3)
        self.assertEqual(list(audit["errors"]), ["input", "integrity"])
        self.assertEqual(audit["errors"], {"input": 0, "integrity": 0})
        self.assertEqual(
            audit["entries"], [{"tx_id": tx_id} for tx_id in self.ids]
        )
        self.assertEqual(audit["digest"], canonical_digest(audit))
        self.assertRegex(audit["digest"], r"^[0-9a-f]{64}$")

    def test_error_counts_are_plain_ints(self) -> None:
        audit = receipt_proofs_audit(self.docs, self.root)
        for count in audit["errors"].values():
            self.assertIs(type(count), int)
            self.assertNotIsInstance(count, bool)
            self.assertGreaterEqual(count, 0)

    def test_mixed_results_counts_entries_and_digest(self) -> None:
        documents = [
            {"ok": False},
            self.docs[0],
            copy.deepcopy(self.docs[0]),  # duplicate id -> integrity
            copy.deepcopy(self.docs[1]),
        ]
        documents[3]["generation"] = 0  # input failure, id still legal
        audit = receipt_proofs_audit(documents, self.root)
        self.assertIs(audit["ok"], False)
        self.assertEqual(audit["total"], 4)
        self.assertEqual(audit["succeeded"], 1)
        self.assertEqual(audit["errors"], {"input": 2, "integrity": 1})
        self.assertEqual(audit["errors"]["input"] + audit["errors"]["integrity"], 3)
        self.assertEqual(
            audit["entries"],
            [
                {"error": "input"},
                {"tx_id": self.ids[0]},
                {"error": "integrity"},
                {"error": "input"},
            ],
        )
        self.assertEqual(len(audit["entries"]), 4)
        self.assertEqual(audit["digest"], canonical_digest(audit))

    def test_root_mismatch_marks_all_integrity(self) -> None:
        audit = receipt_proofs_audit(self.docs, "01" * 32)
        self.assertIs(audit["ok"], False)
        self.assertEqual(audit["root"], "01" * 32)
        self.assertEqual(audit["succeeded"], 0)
        self.assertEqual(audit["errors"], {"input": 0, "integrity": 3})
        self.assertEqual(
            audit["entries"], [{"error": "integrity"}] * 3
        )
        self.assertEqual(audit["digest"], canonical_digest(audit))

    def test_digest_is_deterministic_and_canonical(self) -> None:
        first = receipt_proofs_audit(self.docs, self.root)
        second = receipt_proofs_audit(self.docs, self.root)
        self.assertEqual(first["digest"], second["digest"])
        # Independently re-derive every serialized byte.
        body = {key: value for key, value in first.items() if key != "digest"}
        raw = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.assertEqual(first["digest"], hashlib.sha256(raw).hexdigest())

    def test_batch_shape_defects(self) -> None:
        for documents, root in [
            ([], self.root),
            (42, self.root),
            (self.docs, ""),
            (self.docs, "g" * 64),
            (self.docs, self.root.upper()),
        ]:
            audit = receipt_proofs_audit(documents, root)
            self.assertEqual(audit, BAD_BATCH, (documents, root))
            self.assertEqual(list(audit), ["ok", "error"])

    def test_junk_items_never_raise(self) -> None:
        documents = [object(), None, 7, [self.docs[0]], self.docs[0]]
        audit = receipt_proofs_audit(documents, self.root)
        self.assertEqual(audit["total"], 5)
        self.assertEqual(audit["succeeded"], 1)
        self.assertEqual(audit["errors"], {"input": 4, "integrity": 0})
        self.assertEqual(
            audit["entries"][-1], {"tx_id": self.ids[0]}
        )
        self.assertEqual(audit["digest"], canonical_digest(audit))

    def test_arguments_not_mutated(self) -> None:
        documents_before = copy.deepcopy(self.docs)
        root_before = self.root
        receipt_proofs_audit(self.docs, self.root)
        self.assertEqual(self.docs, documents_before)
        self.assertEqual(self.root, root_before)


if __name__ == "__main__":
    unittest.main()
