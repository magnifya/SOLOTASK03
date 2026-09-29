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

from ledger import crypto, light_client
from ledger.service import LedgerService
from ledger.store import LedgerStore


def public_key(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


class StateAnchorsExportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.archive = os.path.join(self.tmp, "anchors.json")
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

    def _submit(
        self,
        key: Ed25519PrivateKey,
        sender: str,
        recipient: str,
        amount: int,
    ) -> None:
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

    def record(self, document: dict, accounts: list[str], trust: dict) -> dict:
        return light_client.record_state_anchors(
            self.archive, document, accounts, trust
        )

    def test_empty_archive_exports_and_verifies_empty_records(self) -> None:
        result = light_client.export_state_anchors(
            self.archive, [1], [self.account_a]
        )
        self.assertTrue(result["ok"], result)
        document = result["document"]
        self.assertEqual(
            list(document),
            ["v", "generation", "heights", "accounts", "records", "digest"],
        )
        self.assertEqual(document["generation"], 0)
        self.assertEqual(document["records"], [])
        verified = light_client.verify_state_anchors_export(document)
        self.assertTrue(verified["ok"], verified)
        self.assertEqual(verified["records"], [])

    def test_discrete_heights_subset_rotation_duplicates_and_stable_export(self) -> None:
        first = self.proof([self.account_b, self.account_a], 1)
        recorded = self.record(first, [self.account_b, self.account_a], self.trust_v1)
        self.assertTrue(recorded["ok"], recorded)

        self._submit(self.key_b, self.account_b, self.account_c, 15)
        self._mine_and_confirm()
        duplicate = self.proof([self.account_b], 1)
        seed = crypto.generate_private_key()
        status, _ = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        trust_v2 = self.service.get_trust_document()[1]
        second = self.proof([self.account_c, self.account_b], 2)
        recorded = self.record(second, [self.account_c, self.account_b], trust_v2)
        self.assertTrue(recorded["ok"], recorded)

        recorded = self.record(duplicate, [self.account_b], self.trust_v1)
        self.assertTrue(recorded["ok"], recorded)
        self.assertEqual(recorded["generation"], 3)

        with open(self.archive, "rb") as fh:
            before = fh.read()
        result = light_client.export_state_anchors(
            self.archive,
            [2, 1, 1],
            [self.account_c, self.account_a, self.account_b],
        )
        self.assertTrue(result["ok"], result)
        with open(self.archive, "rb") as fh:
            self.assertEqual(fh.read(), before)
        document = result["document"]
        self.assertEqual(document["generation"], 3)
        self.assertEqual(document["heights"], [1, 2])
        self.assertEqual(
            document["accounts"],
            sorted([self.account_a, self.account_b, self.account_c]),
        )
        self.assertEqual(
            [
                (item["anchor"]["height"], item["account"])
                for item in document["records"]
            ],
            [
                (1, self.account_a),
                (1, self.account_b),
                (1, self.account_b),
                (2, self.account_b),
                (2, self.account_c),
            ] if self.account_b < self.account_c else [
                (1, self.account_a),
                (1, self.account_b),
                (1, self.account_b),
                (2, self.account_c),
                (2, self.account_b),
            ],
        )
        self.assertEqual(
            document["records"][1]["trust"],
            document["records"][2]["trust"],
        )
        self.assertNotEqual(
            document["records"][1]["trust"],
            document["records"][3]["trust"],
        )

        verified = light_client.verify_state_anchors_export(copy.deepcopy(document))
        self.assertTrue(verified["ok"], verified)
        self.assertEqual(verified["generation"], 3)
        self.assertEqual(
            verified["records"],
            [{"height": 1, "account": self.account_a}]
            + [{"height": 1, "account": self.account_b} for _ in range(2)]
            + [
                {"height": 2, "account": account}
                for account in sorted([self.account_b, self.account_c])
            ],
        )

        serialized = json.dumps(document, sort_keys=True, separators=(",", ":"))
        document_again = light_client.export_state_anchors(
            self.archive,
            [2, 1, 1],
            [self.account_c, self.account_a, self.account_b],
        )["document"]
        self.assertEqual(
            json.dumps(document_again, sort_keys=True, separators=(",", ":")),
            serialized,
        )

    def test_input_auth_and_integrity_classification(self) -> None:
        document = self.proof([self.account_a, self.account_b], 1)
        self.assertTrue(
            self.record(document, [self.account_a, self.account_b], self.trust_v1)["ok"]
        )
        export = light_client.export_state_anchors(
            self.archive, [1], [self.account_a, self.account_b]
        )["document"]

        bad_heights = copy.deepcopy(export)
        bad_heights["heights"] = [True]
        self.assertEqual(
            light_client.verify_state_anchors_export(bad_heights)["error"], "input"
        )
        bad_accounts = copy.deepcopy(export)
        bad_accounts["accounts"] = [self.account_a, self.account_a]
        self.assertEqual(
            light_client.verify_state_anchors_export(bad_accounts)["error"], "input"
        )
        mixed_trust = copy.deepcopy(export)
        mixed_trust["records"][0]["trust"]["mixed"] = {0: "x", "a": "y"}
        self.assertEqual(
            light_client.verify_state_anchors_export(mixed_trust)["error"], "input"
        )
        non_finite = copy.deepcopy(export)
        non_finite["records"][0]["trust"]["x"] = float("nan")
        self.assertEqual(
            light_client.verify_state_anchors_export(non_finite)["error"], "input"
        )

        unknown_signer = copy.deepcopy(export)
        unknown_signer["records"][0]["document"]["auth"]["key_version"] = 99
        self.assertEqual(
            light_client.verify_state_anchors_export(unknown_signer)["error"], "auth"
        )
        bad_signature = copy.deepcopy(export)
        bad_signature["records"][0]["document"]["auth"]["signature"] = "0" * 128
        self.assertEqual(
            light_client.verify_state_anchors_export(bad_signature)["error"], "auth"
        )

        tampered_digest = copy.deepcopy(export)
        tampered_digest["digest"] = "0" * 64
        self.assertEqual(
            light_client.verify_state_anchors_export(tampered_digest)["error"],
            "integrity",
        )
        tampered_anchor = copy.deepcopy(export)
        tampered_anchor["records"][0]["anchor"]["block_hash"] = "0" * 64
        tampered_anchor["records"][0]["digest"] = (
            light_client._state_anchors_export_record_digest(
                tampered_anchor["records"][0]
            )
        )
        tampered_anchor["digest"] = light_client._state_anchors_export_digest(
            tampered_anchor
        )
        self.assertEqual(
            light_client.verify_state_anchors_export(tampered_anchor)["error"],
            "integrity",
        )

    def test_conflicting_archive_is_state_and_unsafe_input_does_not_consume_generation(self) -> None:
        document = self.proof([self.account_a, self.account_b], 1)
        self.assertTrue(
            self.record(document, [self.account_a, self.account_b], self.trust_v1)["ok"]
        )
        with open(self.archive, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["records"][0]["anchor"]["state_root"] = "0" * 64
        raw["hash"] = hashlib.sha256(
            json.dumps(
                {key: raw[key] for key in ("v", "generation", "records")},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        with open(self.archive, "w", encoding="utf-8") as fh:
            json.dump(raw, fh)
        result = light_client.export_state_anchors(
            self.archive, [1], [self.account_a]
        )
        self.assertEqual(result, {"ok": False, "error": "state"})

        trust = copy.deepcopy(self.trust_v1)
        trust["non_serializable"] = object()
        result = self.record(document, [self.account_a], trust)
        self.assertEqual(result, {"ok": False, "error": "input"})
        with open(self.archive, "r", encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["generation"], 1)

    def test_concurrent_exports_are_stable(self) -> None:
        document = self.proof([self.account_a, self.account_b], 1)
        self.assertTrue(
            self.record(document, [self.account_a, self.account_b], self.trust_v1)["ok"]
        )
        outputs: list[str] = []

        def worker() -> None:
            for _ in range(20):
                result = light_client.export_state_anchors(
                    self.archive, [1], [self.account_b, self.account_a]
                )
                self.assertTrue(result["ok"], result)
                outputs.append(
                    json.dumps(
                        result["document"],
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertTrue(outputs)
        self.assertEqual(len(set(outputs)), 1)


if __name__ == "__main__":
    unittest.main()
