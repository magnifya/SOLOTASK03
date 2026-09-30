from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto, light_client
from ledger.service import LedgerService
from ledger.store import LedgerStore


def public_key(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


class StateAnchorsAuditReportArchiveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "store.json"))
        self.service = LedgerService(self.store, initial_balance=100_000)
        self.key_a = Ed25519PrivateKey.generate()
        self.key_b = Ed25519PrivateKey.generate()
        self.account_a = public_key(self.key_a)
        self.account_b = public_key(self.key_b)
        message = crypto.canonical_message(
            self.account_a, self.account_b, 100
        )
        transaction = {
            "from": self.account_a,
            "to": self.account_b,
            "amount": 100,
            "signature": self.key_a.sign(message).hex(),
        }
        self.assertEqual(self.service.submit_transaction(transaction)[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("1")[0], 200)
        self.trust = self.service.get_trust_document()[1]
        self.signing_key = Ed25519PrivateKey.generate()
        self.seed = self.signing_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        self.report_public_key = public_key(self.signing_key)

    def proof(self, accounts: list[str]) -> dict:
        status, document = self.service.get_attested_account_proofs(
            {"accounts": accounts, "height": "1"}
        )
        self.assertEqual(status, 200, document)
        return document

    def make_report(self, pairs: list[dict[str, object]]) -> dict:
        archive_path = os.path.join(self.tmp, "source.json")
        document = self.proof([self.account_a, self.account_b])
        recorded = light_client.record_state_anchors(
            archive_path,
            document,
            [self.account_a, self.account_b],
            self.trust,
        )
        self.assertTrue(recorded["ok"], recorded)
        exported = light_client.export_state_anchors_audit_report(
            [archive_path], pairs, self.seed
        )
        self.assertTrue(exported["ok"], exported)
        return exported["report"]

    def test_records_in_arrival_order_and_duplicate_is_idempotent(self) -> None:
        path = os.path.join(self.tmp, "reports.json")
        pairs_one = [{"height": 1, "account": self.account_a}]
        pairs_two = [{"height": 1, "account": self.account_b}]
        report_one = self.make_report(pairs_one)
        report_two = self.make_report(pairs_two)

        first = light_client.record_state_anchors_audit_report(
            path, report_one, pairs_one, self.report_public_key
        )
        second = light_client.record_state_anchors_audit_report(
            path, report_two, pairs_two, self.report_public_key
        )
        self.assertEqual(
            first,
            {"ok": True, "digest": report_one["digest"], "generation": 1},
        )
        self.assertEqual(second["generation"], 2)

        with open(path, "rb") as fh:
            bytes_after_second = fh.read()
        duplicate = light_client.record_state_anchors_audit_report(
            path, report_one, pairs_one, self.report_public_key
        )
        self.assertEqual(
            duplicate,
            {"ok": True, "digest": report_one["digest"], "generation": 1},
        )
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), bytes_after_second)

        with open(path, "r", encoding="utf-8") as fh:
            archive = json.load(fh)
        self.assertEqual(
            [record["digest"] for record in archive["records"]],
            [report_one["digest"], report_two["digest"]],
        )

        read_one = light_client.read_state_anchors_audit_report(
            path, report_one["digest"]
        )
        read_two = light_client.query_state_anchors_audit_report(
            path, report_two["digest"]
        )
        self.assertTrue(read_one["ok"], read_one)
        self.assertEqual(read_one["report"], report_one)
        self.assertEqual(read_one["generation"], 1)
        self.assertTrue(read_two["ok"], read_two)
        self.assertEqual(read_two["report"], report_two)
        self.assertEqual(read_two["generation"], 2)

    def test_input_auth_not_found_and_state_are_distinct(self) -> None:
        path = os.path.join(self.tmp, "reports.json")
        pairs = [{"height": 1, "account": self.account_a}]
        report = self.make_report(pairs)

        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                "", report, pairs, self.report_public_key
            )["error"],
            "input",
        )
        other_public_key = public_key(Ed25519PrivateKey.generate())
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                path, report, pairs, other_public_key
            )["error"],
            "auth",
        )
        self.assertEqual(
            light_client.read_state_anchors_audit_report(path, "bad")["error"],
            "input",
        )
        missing_path = os.path.join(self.tmp, "missing.json")
        self.assertEqual(
            light_client.read_state_anchors_audit_report(
                missing_path, report["digest"]
            )["error"],
            "not_found",
        )

        recorded = light_client.record_state_anchors_audit_report(
            path, report, pairs, self.report_public_key
        )
        self.assertTrue(recorded["ok"], recorded)
        self.assertEqual(
            light_client.read_state_anchors_audit_report(
                path, "0" * 64
            )["error"],
            "not_found",
        )

        with open(path, "rb") as fh:
            original = fh.read()
        damaged = original.replace(b'"generation":1', b'"generation":2', 1)
        with open(path, "wb") as fh:
            fh.write(damaged)
        self.assertEqual(
            light_client.read_state_anchors_audit_report(
                path, report["digest"]
            )["error"],
            "state",
        )


if __name__ == "__main__":
    unittest.main()
