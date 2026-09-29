from __future__ import annotations

import copy
import json
import os
import subprocess
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


class _Fixture:
    def __init__(self, root: str, name: str) -> None:
        self.store = LedgerStore(os.path.join(root, f"{name}.store.json"))
        self.service = LedgerService(self.store, initial_balance=100_000)
        self.archive = os.path.join(root, f"{name}.anchors.json")
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.accounts = [public_key(key) for key in self.keys]

    def submit(self, sender: int, recipient: int, amount: int) -> None:
        message = crypto.canonical_message(
            self.accounts[sender], self.accounts[recipient], amount
        )
        transaction = {
            "from": self.accounts[sender],
            "to": self.accounts[recipient],
            "amount": amount,
            "signature": self.keys[sender].sign(message).hex(),
        }
        assert self.service.submit_transaction(transaction)[0] == 202

    def mine_and_confirm(self) -> None:
        assert self.service.mine_block()[0] == 201
        height = self.store.tip().height
        assert self.service.confirm_block(str(height))[0] == 200

    def proof(self, accounts: list[str], height: int) -> dict:
        status, document = self.service.get_attested_account_proofs(
            {"accounts": accounts, "height": str(height)}
        )
        assert status == 200, document
        return document

    def record(self, document: dict, accounts: list[str]) -> dict:
        trust = self.service.get_trust_document()[1]
        return light_client.record_state_anchors(
            self.archive, document, accounts, trust
        )

    def export(self, heights: list[int], accounts: list[str]) -> dict:
        result = light_client.export_state_anchors(
            self.archive, heights, accounts
        )
        assert result["ok"], result
        return result["document"]


class StateAnchorsExportsAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.a = _Fixture(self.tmp, "a")
        self.b = _Fixture(self.tmp, "b")

    def _seed(self, fixture: _Fixture, amount: int) -> None:
        fixture.submit(0, 1, amount)
        fixture.submit(2, 0, 40)
        fixture.mine_and_confirm()
        document = fixture.proof(list(fixture.accounts), 1)
        recorded = fixture.record(document, list(fixture.accounts))
        self.assertTrue(recorded["ok"], recorded)

    def _pair(self, height: int, account: str) -> dict:
        return {"height": height, "account": account}

    def test_verified_missing_and_partial_coverage_with_duplicate_sources(self) -> None:
        self._seed(self.a, 100)
        self._seed(self.b, 100)
        export_a = self.a.export([1], [self.a.accounts[0], self.a.accounts[1]])
        export_b = self.a.export([1], [self.a.accounts[2]])

        account0, account1, account2 = self.a.accounts
        other0 = self.b.accounts[0]
        documents = [
            export_a,
            export_b,
            copy.deepcopy(export_a),
            copy.deepcopy(export_b),
        ]
        result = light_client.audit_state_anchors_exports(
            documents,
            [
                self._pair(1, account1),
                self._pair(1, account0),
                self._pair(1, account2),
                self._pair(1, other0),
                self._pair(2, account1),
            ],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result), ["ok", "verified", "missing", "conflicts"]
        )
        self.assertEqual(
            result["verified"],
            [
                self._pair(1, account)
                for account in sorted([account0, account1, account2])
            ],
        )
        self.assertEqual(
            result["missing"],
            [self._pair(1, other0), self._pair(2, account1)],
        )
        self.assertEqual(result["conflicts"], [])

        repeated = light_client.audit_state_anchors_exports(
            documents,
            [
                self._pair(1, account2),
                self._pair(2, account1),
                self._pair(1, other0),
                self._pair(1, account0),
                self._pair(1, account1),
            ],
        )
        self.assertEqual(repeated, result)

    def test_pair_conflict_and_indirect_same_height_anchor_conflict(self) -> None:
        self._seed(self.a, 100)
        self._seed(self.b, 70)
        account0, account1, account2 = self.a.accounts
        other0, other1, other2 = self.b.accounts

        export_a = self.a.export([1], [account0, account1])
        export_b = self.b.export([1], [other0, other1])
        result = light_client.audit_state_anchors_exports(
            [export_a, export_b],
            [
                self._pair(1, account1),
                self._pair(1, other0),
                self._pair(1, other2),
            ],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["missing"], [self._pair(1, other2)])
        self.assertEqual(
            result["conflicts"],
            [
                self._pair(1, account)
                for account in sorted([account1, other0])
            ],
        )

        indirect_b = self.b.export([1], [other2])
        result = light_client.audit_state_anchors_exports(
            [export_a, indirect_b],
            [self._pair(1, account0), self._pair(1, other2)],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["missing"], [])
        self.assertEqual(
            result["conflicts"],
            [
                self._pair(1, account)
                for account in sorted([account0, other2])
            ],
        )

    def test_duplicate_equivalent_records_inside_one_export_count_once(self) -> None:
        self._seed(self.a, 100)
        duplicate = self.a.proof([self.a.accounts[1]], 1)
        self.assertTrue(
            self.a.record(duplicate, [self.a.accounts[1]])["ok"]
        )
        export = self.a.export([1, 1], [self.a.accounts[1]])
        pairs = [
            (item["anchor"]["height"], item["account"])
            for item in export["records"]
        ]
        self.assertEqual(pairs, [(1, self.a.accounts[1]), (1, self.a.accounts[1])])
        result = light_client.audit_state_anchors_exports(
            [export], [self._pair(1, self.a.accounts[1])]
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["verified"], [self._pair(1, self.a.accounts[1])]
        )
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["conflicts"], [])

    def test_input_errors(self) -> None:
        self._seed(self.a, 100)
        export = self.a.export([1], [self.a.accounts[0]])
        pair = self._pair(1, self.a.accounts[0])
        cases = [
            ([], [pair]),
            (export, [pair]),
            ([export], []),
            ([export], pair),
            ([export], [pair, pair]),
            ([export], [{"height": True, "account": self.a.accounts[0]}]),
            ([export], [{"height": -1, "account": self.a.accounts[0]}]),
            ([export], [{"height": 1, "account": self.a.accounts[0].upper()}]),
            ([export], [{"height": 1, "account": "x" * 64}]),
            ([export], [{"height": 1}]),
            ([export], [{"height": 1, "account": self.a.accounts[0], "x": 1}]),
            ([export], [("height", 1)]),
        ]
        for documents, expected_pairs in cases:
            result = light_client.audit_state_anchors_exports(
                documents, expected_pairs
            )
            self.assertEqual(result, {"ok": False, "error": "input"}, cases)

        non_stable = copy.deepcopy(export)
        non_stable["records"][0]["trust"]["x"] = float("nan")
        self.assertEqual(
            light_client.audit_state_anchors_exports(
                [non_stable], [pair]
            ),
            {"ok": False, "error": "input"},
        )

    def test_auth_and_integrity_propagate_from_document_verification(self) -> None:
        self._seed(self.a, 100)
        self._seed(self.b, 100)
        export_a = self.a.export([1], [self.a.accounts[0]])
        export_b = self.b.export([1], [self.b.accounts[0]])
        pair_a = self._pair(1, self.a.accounts[0])
        pair_b = self._pair(1, self.b.accounts[0])

        unknown_signer = copy.deepcopy(export_a)
        unknown_signer["records"][0]["document"]["auth"]["key_version"] = 99
        self.assertEqual(
            light_client.audit_state_anchors_exports(
                [unknown_signer, export_b], [pair_a, pair_b]
            ),
            {"ok": False, "error": "auth"},
        )

        bad_signature = copy.deepcopy(export_a)
        bad_signature["records"][0]["document"]["auth"]["signature"] = "0" * 128
        self.assertEqual(
            light_client.audit_state_anchors_exports(
                [bad_signature], [pair_a]
            ),
            {"ok": False, "error": "auth"},
        )

        tampered_digest = copy.deepcopy(export_a)
        tampered_digest["digest"] = "0" * 64
        self.assertEqual(
            light_client.audit_state_anchors_exports(
                [tampered_digest], [pair_a]
            ),
            {"ok": False, "error": "integrity"},
        )

        tampered_anchor = copy.deepcopy(export_a)
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
            light_client.audit_state_anchors_exports(
                [tampered_anchor], [pair_a]
            ),
            {"ok": False, "error": "integrity"},
        )

    def test_repeated_concurrent_and_cross_process_results_are_identical(self) -> None:
        self._seed(self.a, 100)
        self._seed(self.b, 100)
        export_a = self.a.export([1], [self.a.accounts[0]])
        export_b = self.b.export([1], [self.b.accounts[0]])
        expected_pairs = [
            self._pair(1, self.a.accounts[0]),
            self._pair(1, self.b.accounts[0]),
            self._pair(3, self.a.accounts[1]),
        ]
        documents = [export_a, export_b]
        baseline = light_client.audit_state_anchors_exports(
            documents, expected_pairs
        )
        serialized = json.dumps(
            baseline, sort_keys=True, separators=(",", ":")
        )

        outputs: list[str] = []

        def worker() -> None:
            for _ in range(20):
                result = light_client.audit_state_anchors_exports(
                    copy.deepcopy(documents), list(reversed(expected_pairs))
                )
                outputs.append(
                    json.dumps(result, sort_keys=True, separators=(",", ":"))
                )

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(set(outputs), {serialized})

        payload_path = os.path.join(self.tmp, "payload.json")
        with open(payload_path, "w", encoding="utf-8") as fh:
            json.dump(
                {"documents": documents, "expected_pairs": expected_pairs},
                fh,
            )
        script = (
            "import json, sys; "
            "from ledger import light_client; "
            "payload = json.load(open(sys.argv[1], encoding='utf-8')); "
            "print(json.dumps(light_client.audit_state_anchors_exports("
            "payload['documents'], payload['expected_pairs']), "
            "sort_keys=True, separators=(',', ':')))"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, payload_path],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.stdout.strip(), serialized)


if __name__ == "__main__":
    unittest.main()
