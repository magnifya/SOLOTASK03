from __future__ import annotations

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


class StateAnchorsArchivesAuditTest(unittest.TestCase):
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

    def record(self, path: str, accounts: list[str], height: int = 1) -> None:
        document = self.proof(accounts, height)
        result = light_client.record_state_anchors(
            path, document, accounts, self.trust_v1
        )
        self.assertTrue(result["ok"], result)

    def audit(self, paths, pairs):
        return light_client.audit_state_anchors_archives(paths, pairs)

    def _pairs(self, *height_accounts):
        return [
            {"height": height, "account": account}
            for height, account in height_accounts
        ]

    def test_verified_missing_sorting_and_duplicate_pair_records(self) -> None:
        path = self.archive()
        self.record(path, [self.account_a, self.account_b])
        # An equivalent record for account_b is stored a second time; the
        # audit must count that pair only once within this source.
        self.record(path, [self.account_b])
        pairs = self._pairs(
            (1, self.account_b),
            (1, self.account_a),
            (2, self.account_a),
        )
        result = self.audit([path], pairs)
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

    def test_missing_archives_are_empty_sources(self) -> None:
        present = self.archive()
        absent_one = self.archive()
        absent_two = self.archive()
        self.record(present, [self.account_a, self.account_b])
        pairs = self._pairs(
            (1, self.account_a),
            (1, self.account_b),
            (2, self.account_c),
        )
        # All sources absent: every pinned combination is missing.
        all_absent = self.audit([absent_one, absent_two], pairs)
        self.assertTrue(all_absent["ok"], all_absent)
        self.assertEqual(all_absent["verified"], [])
        self.assertEqual(all_absent["conflicts"], [])
        self.assertEqual(
            all_absent["missing"],
            [
                {"height": 1, "account": account}
                for account in sorted([self.account_a, self.account_b])
            ]
            + [
                {"height": 2, "account": self.account_c},
            ],
        )
        # A present source plus absent sources: hits verify, the unhit
        # combination stays missing, and absence never creates a conflict.
        result = self.audit([absent_one, present, absent_two], pairs)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["verified"],
            [
                {"height": 1, "account": account}
                for account in sorted([self.account_a, self.account_b])
            ],
        )
        self.assertEqual(
            result["missing"],
            [{"height": 2, "account": self.account_c}],
        )
        self.assertEqual(result["conflicts"], [])

    def test_sorting_is_independent_of_source_order(self) -> None:
        path_one = self.archive()
        path_two = self.archive()
        self.record(path_one, [self.account_a, self.account_b])
        self.record(path_two, [self.account_b, self.account_a])
        pairs = self._pairs(
            (1, self.account_b),
            (1, self.account_a),
        )
        forward = self.audit([path_one, path_two], pairs)
        reverse = self.audit([path_two, path_one], pairs)
        self.assertTrue(forward["ok"], forward)
        self.assertEqual(forward, reverse)
        self.assertEqual(
            forward["verified"],
            [
                {"height": 1, "account": account}
                for account in sorted([self.account_a, self.account_b])
            ],
        )

    def test_partial_coverage_is_not_conflict(self) -> None:
        path_one = self.archive()
        path_two = self.archive()
        self.record(path_one, [self.account_a, self.account_b])
        self.record(path_two, [self.account_b])
        result = self.audit(
            [path_one, path_two],
            self._pairs(
                (1, self.account_a),
                (1, self.account_b),
            ),
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

    def _other_chain_archive(self) -> str:
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
        status, document = other_service.get_attested_account_proofs(
            {"accounts": [self.account_b], "height": "1"}
        )
        self.assertEqual(status, 200, document)
        path = self.archive()
        result = light_client.record_state_anchors(
            path, document, [self.account_b], other_trust
        )
        self.assertTrue(result["ok"], result)
        return path

    def test_anchor_and_proof_disagreement_is_conflict(self) -> None:
        path_one = self.archive()
        self.record(path_one, [self.account_a, self.account_b])
        other_path = self._other_chain_archive()
        result = self.audit(
            [path_one, other_path],
            self._pairs((1, self.account_b)),
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified"], [])
        self.assertEqual(result["missing"], [])
        self.assertEqual(
            result["conflicts"],
            [{"height": 1, "account": self.account_b}],
        )

    def test_same_height_anchor_disagreement_conflicts_even_without_pair(self) -> None:
        # The second source never carries (1, account_a) but commits a
        # different anchor at height 1 through another account: the height
        # vote itself must drag account_a into conflicts.
        path_one = self.archive()
        self.record(path_one, [self.account_a])
        other_path = self._other_chain_archive()
        result = self.audit(
            [path_one, other_path],
            self._pairs((1, self.account_a)),
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["conflicts"],
            [{"height": 1, "account": self.account_a}],
        )
        self.assertEqual(result["verified"], [])

    def test_corrupt_archive_is_state_and_does_not_mutate_it(self) -> None:
        path = self.archive()
        self.record(path, [self.account_a])
        with open(path, "r", encoding="utf-8") as fh:
            before = fh.read()
        data = json.loads(before)
        data["hash"] = "0" * 64
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        result = self.audit(
            [path], self._pairs((1, self.account_a))
        )
        self.assertEqual(result, {"ok": False, "error": "state"})

    def test_directory_path_is_io(self) -> None:
        directory = os.path.join(self.tmp, "anchors-dir")
        os.mkdir(directory)
        result = self.audit(
            [directory], self._pairs((1, self.account_a))
        )
        self.assertEqual(result, {"ok": False, "error": "io"})

    def test_audit_is_read_only_repeatable_and_concurrency_safe(self) -> None:
        path = self.archive()
        self.record(path, [self.account_a, self.account_b])
        pairs = self._pairs(
            (1, self.account_a),
            (2, self.account_c),
        )
        before = os.stat(path)
        expected = self.audit([path], pairs)
        self.assertTrue(expected["ok"], expected)

        results = []
        errors = []

        def worker() -> None:
            try:
                for _ in range(20):
                    result = self.audit([path], pairs)
                    if result != expected:
                        errors.append(result)
                    results.append(result)
            except Exception as exc:  # pragma: no cover - nothing may raise
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 80)
        after = os.stat(path)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)
        self.assertEqual(before.st_size, after.st_size)

    def test_bad_path_and_pair_shapes_are_input(self) -> None:
        pair = {"height": 1, "account": self.account_a}
        path = self.archive()
        self.record(path, [self.account_a])

        self.assertEqual(self.audit([], [pair])["error"], "input")
        self.assertEqual(self.audit("not-a-list", [pair])["error"], "input")
        self.assertEqual(self.audit([path], [])["error"], "input")
        self.assertEqual(self.audit([""], [pair])["error"], "input")
        self.assertEqual(self.audit([1], [pair])["error"], "input")
        self.assertEqual(self.audit(None, [pair])["error"], "input")
        self.assertEqual(
            self.audit([path, path], [pair])["error"], "input"
        )
        self.assertEqual(
            self.audit([path], [tuple()])["error"], "input"
        )
        self.assertEqual(
            self.audit(
                [path],
                [{"account": self.account_a, "height": 1}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit(
                [path],
                [{"height": -1, "account": self.account_a}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit(
                [path],
                [{"height": True, "account": self.account_a}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit(
                [path],
                [{"height": 1, "account": "z" * 64}],
            )["error"],
            "input",
        )
        self.assertEqual(
            self.audit([path], [pair, pair])["error"], "input"
        )


if __name__ == "__main__":
    unittest.main()
