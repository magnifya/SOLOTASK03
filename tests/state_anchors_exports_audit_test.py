from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import threading
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


class StateAnchorsExportsAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.archives = []
        self.store = LedgerStore(os.path.join(self.tmp, "store.json"))
        self.service = LedgerService(self.store, initial_balance=100_000)
        self.key_a = Ed25519PrivateKey.generate()
        self.key_b = Ed25519PrivateKey.generate()
        self.key_c = Ed25519PrivateKey.generate()
        self.account_a = public_key(self.key_a)
        self.account_b = public_key(self.key_b)
        self.account_c = public_key(self.key_c)
        self._submit(self.key_a, self.account_a, self.account_b, 100)
        self._submit(self.key_c, self.account_c, self.account_a, 40)
        self._mine_and_confirm()
        self.trust_v1 = self.service.get_trust_document()[1]

    def _submit(self, key, sender, recipient, amount) -> None:
        message = crypto.canonical_message(sender, recipient, amount)
        transaction = {
            "from": sender,
            "to": recipient,
            "amount": amount,
            "signature": key.sign(message).hex(),
        }
        self.assertEqual(self.service.submit_transaction(transaction)[0], 202)

    def _mine_and_confirm(self) -> None:
        self.assertEqual(self.service.mine_block()[0], 201)
        height = self.store.tip().height
        self.assertEqual(self.service.confirm_block(str(height))[0], 200)

    def proof(self, accounts: list[str], height: int) -> dict:
        status, document = self.service.get_attested_account_proofs(
            {"accounts": accounts, "height": str(height)}
        )
        self.assertEqual(status, 200, document)
        return document

    def archive(self) -> str:
        path = os.path.join(self.tmp, f"anchors-{len(self.archives)}.json")
        self.archives.append(path)
        return path

    def export(self, path: str, heights: list[int], accounts: list[str]) -> dict:
        result = light_client.export_state_anchors(path, heights, accounts)
        self.assertTrue(result["ok"], result)
        return result["document"]

    def audit(self, documents, pairs):
        return light_client.audit_state_anchors_exports(documents, pairs)

    def _build_agreeing_sources(self):
        path_one = self.archive()
        document = self.proof([self.account_a, self.account_b], 1)
        self.assertTrue(
            light_client.record_state_anchors(
                path_one, document, [self.account_a, self.account_b],
                self.trust_v1,
            )["ok"]
        )
        path_two = self.archive()
        document = self.proof([self.account_b, self.account_a], 1)
        self.assertTrue(
            light_client.record_state_anchors(
                path_two, document, [self.account_b, self.account_a],
                self.trust_v1,
            )["ok"]
        )
        export_one = self.export(path_one, [1], [self.account_a, self.account_b])
        export_two = self.export(path_two, [1], [self.account_a, self.account_b])
        return export_one, export_two

    def test_verified_missing_sorting_and_duplicate_pair_records(self) -> None:
        path = self.archive()
        document = self.proof([self.account_a, self.account_b], 1)
        self.assertTrue(
            light_client.record_state_anchors(
                path, document, [self.account_a, self.account_b], self.trust_v1
            )["ok"]
        )
        duplicate = self.proof([self.account_b], 1)
        self.assertTrue(
            light_client.record_state_anchors(
                path, duplicate, [self.account_b], self.trust_v1
            )["ok"]
        )
        export_document = self.export(
            path, [1], [self.account_a, self.account_b]
        )
        self.assertEqual(
            sum(
                1
                for record in export_document["records"]
                if record["account"] == self.account_b
            ),
            2,
        )
        pairs = [
            {"height": 1, "account": self.account_b},
            {"height": 1, "account": self.account_a},
            {"height": 2, "account": self.account_a},
        ]
        result = self.audit([export_document], pairs)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result), ["ok", "verified", "missing", "conflicts"])
        self.assertEqual(
            result["verified"],
            [
                {"height": 1, "account": account}
                for account in sorted([self.account_a, self.account_b])
            ],
        )
        self.assertEqual(
            result["missing"],
            [{"height": 2, "account": self.account_a}],
        )
        self.assertEqual(result["conflicts"], [])

    def test_agreeing_sources_verify_and_partial_coverage_is_not_conflict(self) -> None:
        export_one, export_two = self._build_agreeing_sources()
        # Second source only carries account_b; account_a must still verify.
        for record in export_two["records"]:
            if record["account"] == self.account_a:
                record["account"] = self.account_b
        export_two["accounts"] = [self.account_b]
        export_two["records"] = [
            record
            for record in export_two["records"]
            if record["account"] == self.account_b
        ][:1]
        for record in export_two["records"]:
            record["digest"] = (
                light_client._state_anchors_export_record_digest(record)
            )
        export_two["digest"] = light_client._state_anchors_export_digest(
            export_two
        )
        self.assertTrue(
            light_client.verify_state_anchors_export(export_two)["ok"]
        )
        result = self.audit(
            [export_one, export_two],
            [
                {"height": 1, "account": self.account_a},
                {"height": 1, "account": self.account_b},
            ],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["verified"],
            [
                {"height": 1, "account": account}
                for account in sorted([self.account_a, self.account_b])
            ],
        )
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["conflicts"], [])

    def test_proof_and_anchor_disagreements_are_conflicts(self) -> None:
        # Two independent chains with distinct signer trust both produce
        # individually valid height-1 anchors for the same accounts, but
        # block hash, state root and proof content differ across sources.
        export_one, _ = self._build_agreeing_sources()

        other_store = LedgerStore(os.path.join(self.tmp, "store-other.json"))
        other_service = LedgerService(other_store, initial_balance=100_000)
        other_service.submit_transaction(
            {
                "from": self.account_a,
                "to": self.account_b,
                "amount": 7,
                "signature": self.key_a.sign(
                    crypto.canonical_message(self.account_a, self.account_b, 7)
                ).hex(),
            }
        )
        self.assertEqual(other_service.mine_block()[0], 201)
        self.assertEqual(
            other_service.confirm_block(
                str(other_store.tip().height)
            )[0],
            200,
        )
        other_trust = other_service.get_trust_document()[1]
        status, other_document = (
            other_service.get_attested_account_proofs(
                {
                    "accounts": [self.account_a, self.account_b],
                    "height": "1",
                }
            )
        )
        self.assertEqual(status, 200, other_document)
        other_path = self.archive()
        self.assertTrue(
            light_client.record_state_anchors(
                other_path,
                other_document,
                [self.account_a, self.account_b],
                other_trust,
            )["ok"]
        )
        proof_conflict = self.export(
            other_path, [1], [self.account_a, self.account_b]
        )
        result = self.audit(
            [export_one, proof_conflict],
            [{"height": 1, "account": self.account_b}],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["missing"], [])
        self.assertEqual(
            result["conflicts"],
            [{"height": 1, "account": self.account_b}],
        )

    def test_input_auth_and_integrity_classification(self) -> None:
        export_one, export_two = self._build_agreeing_sources()
        pair = {"height": 1, "account": self.account_a}

        ok_result = self.audit([export_one], [pair])
        self.assertTrue(ok_result["ok"], ok_result)

        self.assertEqual(self.audit([], [pair])["error"], "input")
        self.assertEqual(self.audit([export_one], [])["error"], "input")
        self.assertEqual(
            self.audit("not-a-list", [pair])["error"], "input"
        )
        self.assertEqual(
            self.audit([export_one], [tuple()])["error"], "input"
        )
        self.assertEqual(
            self.audit(
                [export_one],
                [{"account": self.account_a, "height": 1}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit(
                [export_one],
                [{"height": -1, "account": self.account_a}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit(
                [export_one],
                [{"height": True, "account": self.account_a}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit(
                [export_one],
                [{"height": 1, "account": "z" * 64}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit([export_one], [pair, pair])["error"], "input"
        )

        unknown_signer = copy.deepcopy(export_two)
        unknown_signer["records"][0]["document"]["auth"]["key_version"] = 99
        self.assertEqual(
            self.audit([unknown_signer], [pair])["error"], "auth"
        )
        bad_signature = copy.deepcopy(export_two)
        bad_signature["records"][0]["document"]["auth"]["signature"] = (
            "0" * 128
        )
        self.assertEqual(
            self.audit([bad_signature], [pair])["error"], "auth"
        )

        tampered_digest = copy.deepcopy(export_two)
        tampered_digest["digest"] = "0" * 64
        self.assertEqual(
            self.audit([tampered_digest], [pair])["error"], "integrity"
        )
        tampered_anchor = copy.deepcopy(export_two)
        record = tampered_anchor["records"][0]
        record["anchor"]["block_hash"] = "0" * 64
        record["digest"] = (
            light_client._state_anchors_export_record_digest(record)
        )
        tampered_anchor["digest"] = (
            light_client._state_anchors_export_digest(tampered_anchor)
        )
        self.assertEqual(
            self.audit([tampered_anchor], [pair])["error"], "integrity"
        )

    def test_repeated_concurrent_and_stable_serialization(self) -> None:
        export_one, export_two = self._build_agreeing_sources()
        pairs = [
            {"height": 1, "account": self.account_b},
            {"height": 1, "account": self.account_a},
            {"height": 9, "account": self.account_c},
        ]
        expected = self.audit(
            [copy.deepcopy(export_one), copy.deepcopy(export_two)], pairs
        )
        again = self.audit(
            [copy.deepcopy(export_one), copy.deepcopy(export_two)], pairs
        )
        self.assertEqual(again, expected)
        serialized = json.dumps(expected, sort_keys=True)

        outputs: list[str] = []

        def worker() -> None:
            for _ in range(30):
                result = self.audit(
                    [copy.deepcopy(export_one), copy.deepcopy(export_two)],
                    pairs,
                )
                outputs.append(json.dumps(result, sort_keys=True))

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertTrue(outputs)
        self.assertEqual(set(outputs), {serialized})


if __name__ == "__main__":
    unittest.main()
