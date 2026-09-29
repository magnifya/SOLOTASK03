"""Regression tests for the self-contained state-anchor export.

Covers ``ledger.light_client.export_state_anchors`` and
``verify_state_anchors_export``: empty archives, discrete historical
heights, account subsets, signer rotation with per-record trust,
idempotent resubmission, archive and export conflict rules, the strict
input/auth/integrity classifications, restart determinism, the tightened
``record_state_anchors`` serialization boundary and concurrent reads.

Run: python3 tests/state_anchors_export_test.py
"""
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


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount,
            "signature": key.sign(msg).hex()}


def reseal_export(document: dict) -> dict:
    """Recompute an export document's self-hash after a crafted tamper."""
    document["hash"] = light_client._state_anchors_export_hash(
        document["heights"],
        document["accounts"],
        document["generation"],
        document["records"],
    )
    return document


class StateAnchorsExportTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "anchors.json")
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json")),
            initial_balance=100_000,
        )
        self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, 100))
        self.assertEqual(self.svc.mine_block()[0], 201)
        self.assertEqual(self.svc.confirm_block(1)[0], 200)
        self.svc.submit_transaction(make_tx(self.kc, self.C, self.A, 40))
        self.assertEqual(self.svc.mine_block()[0], 201)
        self.assertEqual(self.svc.confirm_block(2)[0], 200)
        self.svc.submit_transaction(make_tx(self.kb, self.B, self.C, 15))
        self.assertEqual(self.svc.mine_block()[0], 201)
        self.assertEqual(self.svc.confirm_block(3)[0], 200)
        self.trust_v1 = self.svc.get_trust_document()[1]

    def batch(self, height: int, accounts: list[str]) -> dict:
        status, doc = self.svc.get_attested_account_proofs(
            {"accounts": accounts, "height": str(height)}
        )
        self.assertEqual(status, 200, doc)
        return doc

    def record(self, height: int, accounts: list[str], trust=None) -> dict:
        doc = self.batch(height, accounts)
        result = light_client.record_state_anchors(
            self.path, doc, sorted(accounts), trust or self.trust_v1
        )
        self.assertTrue(result["ok"], result)
        return result


class ExportRoundTripTests(StateAnchorsExportTestBase):
    def test_empty_archive_export_is_self_consistent(self) -> None:
        exported = light_client.export_state_anchors(self.path, [1], [self.A])
        self.assertTrue(exported["ok"], exported)
        document = exported["document"]
        self.assertEqual(
            list(document),
            ["v", "heights", "accounts", "generation", "records", "hash"],
        )
        self.assertEqual(document["v"], 1)
        self.assertEqual(document["heights"], [1])
        self.assertEqual(document["accounts"], [self.A])
        self.assertEqual(document["generation"], 0)
        self.assertEqual(document["records"], [])
        self.assertTrue(crypto.is_hex64(document["hash"]))
        self.assertEqual(
            light_client.verify_state_anchors_export(document), {"ok": True}
        )

    def test_discrete_heights_account_subset_and_sorting(self) -> None:
        gen1 = self.record(1, [self.A, self.B])["generation"]
        self.record(3, [self.A, self.C])
        self.record(2, [self.B, self.C])
        exported = light_client.export_state_anchors(
            self.path, [3, 1, 2, 9], [self.C, self.A, "0" * 64]
        )
        self.assertTrue(exported["ok"], exported)
        document = exported["document"]
        # Filters are normalized ascending; unknown height/account hit
        # nothing.
        self.assertEqual(document["heights"], [1, 2, 3, 9])
        self.assertEqual(
            document["accounts"],
            ["0" * 64] + sorted([self.A, self.C]),
        )
        pairs = [
            (record["anchor"]["height"], record["account"])
            for record in document["records"]
        ]
        expected_pairs = sorted(
            [(1, self.A), (2, self.C), (3, self.A), (3, self.C)]
        )
        self.assertEqual(pairs, expected_pairs)
        self.assertEqual(pairs, sorted(pairs))
        for record in document["records"]:
            self.assertEqual(
                list(record),
                ["anchor", "account", "proof", "document", "trust"],
            )
            self.assertEqual(
                list(record["anchor"]),
                ["height", "block_hash", "state_root"],
            )
            self.assertEqual(record["proof"]["account"], record["account"])
            self.assertEqual(
                record["anchor"]["block_hash"],
                record["document"]["state"]["block_hash"],
            )
        self.assertEqual(document["generation"], 3)
        self.assertEqual(gen1, 1)
        self.assertEqual(
            light_client.verify_state_anchors_export(document), {"ok": True}
        )

    def test_missing_heights_keep_generation_with_empty_records(self) -> None:
        self.record(1, [self.A])
        exported = light_client.export_state_anchors(self.path, [9], [self.A])
        self.assertTrue(exported["ok"])
        document = exported["document"]
        self.assertEqual(document["generation"], 1)
        self.assertEqual(document["records"], [])
        self.assertEqual(
            light_client.verify_state_anchors_export(document), {"ok": True}
        )

    def test_export_is_read_only_and_restart_deterministic(self) -> None:
        self.record(1, [self.A, self.B])
        self.record(3, [self.A, self.C])
        with open(self.path, "rb") as fh:
            before = fh.read()
        first = light_client.export_state_anchors(
            self.path, [3, 1, 2], [self.C, self.A, self.B]
        )["document"]
        second = light_client.export_state_anchors(
            self.path, [1, 2, 3], [self.A, self.B, self.C]
        )["document"]
        with open(self.path, "rb") as fh:
            after = fh.read()
        self.assertEqual(before, after)
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(second, sort_keys=True),
        )
        # A fresh reload reproduces the same document regardless of the
        # order the filter arguments arrived in.
        third = light_client.export_state_anchors(
            self.path, [3, 2, 1], [self.B, self.C, self.A]
        )["document"]
        self.assertEqual(
            json.dumps(first, sort_keys=True),
            json.dumps(third, sort_keys=True),
        )

    def test_signer_rotation_records_keep_their_own_trust(self) -> None:
        self.record(1, [self.A, self.B], trust=self.trust_v1)
        new_seed = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        status, rotated = self.svc.rotate_audit_signer(
            {"private_key": new_seed, "expected_version": 1}
        )
        self.assertEqual(status, 200, rotated)
        self.assertEqual(rotated["version"], 2)
        trust_v2 = self.svc.get_trust_document()[1]
        doc2 = self.batch(3, [self.A, self.C])
        self.assertEqual(doc2["auth"]["key_version"], 2)
        result = light_client.record_state_anchors(
            self.path, doc2, [self.A, self.C], trust_v2
        )
        self.assertTrue(result["ok"], result)
        document = light_client.export_state_anchors(
            self.path, [1, 3], [self.A, self.B, self.C]
        )["document"]
        trusts = {
            record["anchor"]["height"]: record["trust"]
            for record in document["records"]
        }
        self.assertEqual(
            [entry["version"] for entry in trusts[1]["audit_signers"]], [1]
        )
        self.assertEqual(
            [entry["version"] for entry in trusts[3]["audit_signers"]],
            [1, 2],
        )
        self.assertEqual(
            [
                record["document"]["auth"]["key_version"]
                for record in document["records"]
                if record["anchor"]["height"] == 3
            ],
            [2, 2],
        )
        self.assertEqual(
            light_client.verify_state_anchors_export(document), {"ok": True}
        )

    def test_duplicate_resigned_batch_is_idempotent(self) -> None:
        doc = self.batch(2, [self.A, self.B])
        first = light_client.record_state_anchors(
            self.path, doc, [self.A, self.B], self.trust_v1
        )
        self.assertTrue(first["ok"], first)
        new_seed = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        self.assertEqual(
            self.svc.rotate_audit_signer(
                {"private_key": new_seed, "expected_version": 1}
            )[0],
            200,
        )
        trust_v2 = self.svc.get_trust_document()[1]
        resigned = copy.deepcopy(doc)
        resigned["auth"] = light_client.sign_state_proofs(
            new_seed, 2, doc["state"], doc["proofs"]
        )
        second = light_client.record_state_anchors(
            self.path, resigned, [self.B, self.A], trust_v2
        )
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], first["generation"])
        with open(self.path, "rb") as fh:
            archive = json.load(fh)
        self.assertEqual(len(archive["records"]), 1)
        # The original trust material is retained on idempotent resubmit.
        self.assertEqual(archive["records"][0]["trust"], self.trust_v1)


class ExportArgumentClassificationTests(StateAnchorsExportTestBase):
    def test_bad_export_arguments_are_input(self) -> None:
        bad_filters = [
            ("", [1], [self.A]),
            (self.path, [], [self.A]),
            (self.path, [-1], [self.A]),
            (self.path, [True], [self.A]),
            (self.path, [1.0], [self.A]),
            (self.path, ["1"], [self.A]),
            (self.path, [1, 1], [self.A]),
            (self.path, [1], []),
            (self.path, [1], [self.A, self.A]),
            (self.path, [1], [self.A.upper()]),
            (self.path, [1], ["zz"]),
            (self.path, [1], None),
            (self.path, None, [self.A]),
        ]
        for bad_path, heights, accounts in bad_filters:
            result = light_client.export_state_anchors(bad_path, heights, accounts)
            self.assertEqual(
                result,
                {"ok": False, "error": "input"},
                (bad_path, heights, accounts),
            )

    def test_unreadable_archive_is_io(self) -> None:
        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "wb") as fh:
            fh.write(b"x")
        result = light_client.export_state_anchors(
            os.path.join(blocker, "anchors"), [1], [self.A]
        )
        self.assertEqual(result, {"ok": False, "error": "io"})

    def test_corrupt_archive_is_state(self) -> None:
        self.record(1, [self.A, self.B])
        with open(self.path, "r", encoding="utf-8") as fh:
            archive = json.load(fh)
        archive["records"][0]["document"]["proofs"][0]["siblings"][0][
            "hash"
        ] = "f" * 64
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(archive, fh)
        result = light_client.export_state_anchors(self.path, [1], [self.A])
        self.assertEqual(result, {"ok": False, "error": "state"})

    def test_record_conflict_is_integrity_and_keeps_file(self) -> None:
        doc = self.batch(1, [self.A])
        first = light_client.record_state_anchors(
            self.path, doc, [self.A], self.trust_v1
        )
        self.assertTrue(first["ok"], first)
        with open(self.path, "rb") as fh:
            original = fh.read()
        tampered = copy.deepcopy(doc)
        tampered["proofs"][0]["balance"] += 1
        private_key = self.svc.store.audit_signer["private_key"]
        tampered["auth"] = light_client.sign_state_proofs(
            private_key, 1, tampered["state"], tampered["proofs"]
        )
        conflict = light_client.record_state_anchors(
            self.path, tampered, [self.A], self.trust_v1
        )
        self.assertEqual(conflict, {"ok": False, "error": "integrity"})
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), original)


class RecordInputBoundaryTests(StateAnchorsExportTestBase):
    def _record_raw(self, document: object, trust: object) -> dict:
        return light_client.record_state_anchors(
            self.path, document, [self.A], trust
        )

    def test_non_stable_document_values_are_input_before_disk(self) -> None:
        doc = self.batch(1, [self.A])
        for value in (float("nan"), float("inf"), float("-inf")):
            bad = copy.deepcopy(doc)
            bad["state"]["account_count"] = value
            self.assertEqual(
                self._record_raw(bad, self.trust_v1),
                {"ok": False, "error": "input"},
                value,
            )
        bad = copy.deepcopy(doc)
        bad["state"]["account_count"] = object()
        self.assertEqual(
            self._record_raw(bad, self.trust_v1),
            {"ok": False, "error": "input"},
        )
        self.assertFalse(os.path.exists(self.path))

    def test_non_stable_trust_values_are_input_before_disk(self) -> None:
        doc = self.batch(1, [self.A])
        for value in (float("nan"), float("inf")):
            bad_trust = copy.deepcopy(self.trust_v1)
            bad_trust["note"] = value
            self.assertEqual(
                self._record_raw(doc, bad_trust),
                {"ok": False, "error": "input"},
                value,
            )
        mixed_trust = copy.deepcopy(self.trust_v1)
        mixed_trust["note"] = {"a": 1, 2: 3}
        self.assertEqual(
            self._record_raw(doc, mixed_trust),
            {"ok": False, "error": "input"},
        )
        object_trust = copy.deepcopy(self.trust_v1)
        object_trust["note"] = object()
        self.assertEqual(
            self._record_raw(doc, object_trust),
            {"ok": False, "error": "input"},
        )
        self.assertFalse(os.path.exists(self.path))

    def test_input_failure_consumes_no_generation(self) -> None:
        good = self.record(1, [self.A])
        self.assertEqual(good["generation"], 1)
        doc = self.batch(2, [self.A])
        bad_trust = copy.deepcopy(self.trust_v1)
        bad_trust["note"] = float("nan")
        self.assertEqual(
            self._record_raw(doc, bad_trust),
            {"ok": False, "error": "input"},
        )
        readback = light_client.read_state_anchors(self.path)
        self.assertTrue(readback["ok"], readback)
        self.assertEqual(readback["generation"], 1)
        self.assertEqual(
            [item["anchor"]["height"] for item in readback["items"]], [1]
        )


class VerifyClassificationTests(StateAnchorsExportTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.record(1, [self.A, self.B])
        self.record(2, [self.A, self.C])
        self.document = light_client.export_state_anchors(
            self.path, [1, 2], [self.A, self.B, self.C]
        )["document"]

    def test_valid_document_passes(self) -> None:
        self.assertEqual(
            light_client.verify_state_anchors_export(self.document),
            {"ok": True},
        )

    def test_non_object_and_wrong_shapes_are_input(self) -> None:
        bad_documents = [
            None,
            [],
            "x",
            42,
            {},
            {**self.document, "extra": 1},
        ]
        ordered = [
            "v",
            "heights",
            "accounts",
            "generation",
            "records",
            "hash",
        ]
        reordered = {key: self.document[key] for key in reversed(ordered)}
        bad_documents.append(reordered)
        for bad in bad_documents:
            self.assertEqual(
                light_client.verify_state_anchors_export(bad),
                {"ok": False, "error": "input"},
                bad,
            )
        bad_versions = [
            {**self.document, "v": 2},
            {**self.document, "v": True},
            {**self.document, "v": "1"},
        ]
        for bad in bad_versions:
            self.assertEqual(
                light_client.verify_state_anchors_export(bad),
                {"ok": False, "error": "input"},
            )

    def test_bad_filters_and_records_are_input(self) -> None:
        cases = [
            {"heights": []},
            {"heights": [-1]},
            {"heights": [True]},
            {"heights": [1, 1]},
            {"heights": [2, 1]},
            {"accounts": []},
            {"accounts": [self.A, self.A]},
            {"accounts": [self.A.upper()]},
            {"accounts": list(reversed(sorted([self.A, self.B])))},
            {"generation": -1},
            {"generation": True},
            {"records": {}},
            {"hash": "z" * 64},
        ]
        for change in cases:
            bad = copy.deepcopy(self.document)
            bad.update(change)
            self.assertEqual(
                light_client.verify_state_anchors_export(bad),
                {"ok": False, "error": "input"},
                change,
            )
        # A record with a broken nested key order is input.
        bad = copy.deepcopy(self.document)
        record = bad["records"][0]
        record["anchor"] = {
            "state_root": record["anchor"]["state_root"],
            "height": record["anchor"]["height"],
            "block_hash": record["anchor"]["block_hash"],
        }
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "input"},
        )

    def test_non_serializable_envelopes_are_input_before_checks(self) -> None:
        nan_doc = copy.deepcopy(self.document)
        nan_doc["records"][0]["proof"]["balance"] = float("nan")
        self.assertEqual(
            light_client.verify_state_anchors_export(nan_doc),
            {"ok": False, "error": "input"},
        )
        inf_doc = copy.deepcopy(self.document)
        inf_doc["records"][0]["trust"]["note"] = float("infinity")
        self.assertEqual(
            light_client.verify_state_anchors_export(inf_doc),
            {"ok": False, "error": "input"},
        )
        mixed_doc = copy.deepcopy(self.document)
        mixed_doc["records"][0]["trust"]["note"] = {"a": 1, 2: 3}
        self.assertEqual(
            light_client.verify_state_anchors_export(mixed_doc),
            {"ok": False, "error": "input"},
        )
        object_doc = copy.deepcopy(self.document)
        object_doc["records"][0]["trust"]["note"] = object()
        self.assertEqual(
            light_client.verify_state_anchors_export(object_doc),
            {"ok": False, "error": "input"},
        )

    def test_tampered_digest_is_integrity(self) -> None:
        bad = copy.deepcopy(self.document)
        bad["hash"] = "f" * 64
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "integrity"},
        )

    def test_anchor_and_binding_tampers_are_integrity(self) -> None:
        bad = copy.deepcopy(self.document)
        bad["records"][0]["anchor"]["block_hash"] = "f" * 64
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "integrity"},
        )
        bad = copy.deepcopy(self.document)
        # Point the record at a proof the batch document does not carry.
        other = next(
            record
            for record in bad["records"]
            if record["account"] != bad["records"][0]["account"]
        )
        bad["records"][0]["proof"] = copy.deepcopy(other["proof"])
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "integrity"},
        )
        # A record outside the requested filter set is integrity.
        bad = copy.deepcopy(self.document)
        bad["records"][0]["account"] = self.B if (
            bad["records"][0]["account"] != self.B
        ) else self.A
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "integrity"},
        )

    def test_record_conflicts_are_integrity(self) -> None:
        bad = copy.deepcopy(self.document)
        duplicated = copy.deepcopy(bad["records"][0])
        bad["records"].insert(0, duplicated)
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "integrity"},
        )
        bad = copy.deepcopy(self.document)
        height_one = [
            record
            for record in bad["records"]
            if record["anchor"]["height"] == 1
        ]
        if len(height_one) >= 2:
            height_one[1]["anchor"]["state_root"] = "e" * 64
            reseal_export(bad)
            self.assertEqual(
                light_client.verify_state_anchors_export(bad),
                {"ok": False, "error": "integrity"},
            )

    def test_unknown_signer_version_is_auth(self) -> None:
        bad = copy.deepcopy(self.document)
        for record in bad["records"]:
            record["document"]["auth"]["key_version"] = 99
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "auth"},
        )

    def test_bad_signature_is_auth(self) -> None:
        bad = copy.deepcopy(self.document)
        signature = bad["records"][0]["document"]["auth"]["signature"]
        flipped = ("a" if signature[0] != "a" else "b") + signature[1:]
        bad["records"][0]["document"]["auth"]["signature"] = flipped
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "auth"},
        )

    def test_signed_merkle_tamper_is_integrity(self) -> None:
        doc = self.batch(1, [self.A])
        tampered = copy.deepcopy(doc)
        tampered["proofs"][0]["index"] = 0
        if tampered["proofs"][0]["siblings"]:
            tampered["proofs"][0]["siblings"][0]["direction"] = (
                "right"
                if tampered["proofs"][0]["siblings"][0]["direction"] == "left"
                else "left"
            )
        private_key = self.svc.store.audit_signer["private_key"]
        tampered["auth"] = light_client.sign_state_proofs(
            private_key, 1, tampered["state"], tampered["proofs"]
        )
        bad = copy.deepcopy(self.document)
        target = next(
            record
            for record in bad["records"]
            if record["anchor"]["height"] == 1 and record["account"] == self.A
        )
        target["document"] = tampered
        target["proof"] = tampered["proofs"][0]
        reseal_export(bad)
        self.assertEqual(
            light_client.verify_state_anchors_export(bad),
            {"ok": False, "error": "integrity"},
        )


class ConcurrentReadRegressionTests(StateAnchorsExportTestBase):
    def test_concurrent_records_exports_and_reads_stay_consistent(self) -> None:
        groups = [
            (1, [self.A, self.B]),
            (2, [self.B, self.C]),
            (3, [self.A, self.C]),
        ]
        errors: list[BaseException] = []

        def record_group(height: int, accounts: list[str]) -> None:
            try:
                result = light_client.record_state_anchors(
                    self.path,
                    self.batch(height, accounts),
                    accounts,
                    self.trust_v1,
                )
                self.assertTrue(result["ok"], result)
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        def export_forever(stop: threading.Event) -> None:
            try:
                while not stop.is_set():
                    exported = light_client.export_state_anchors(
                        self.path,
                        [1, 2, 3],
                        [self.A, self.B, self.C],
                    )
                    if not exported["ok"]:
                        raise AssertionError(exported)
                    verified = light_client.verify_state_anchors_export(
                        exported["document"]
                    )
                    if not verified.get("ok"):
                        raise AssertionError(verified)
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        stop = threading.Event()
        readers = [
            threading.Thread(target=export_forever, args=(stop,))
            for _ in range(4)
        ]
        for reader in readers:
            reader.start()
        writers = [
            threading.Thread(target=record_group, args=group)
            for group in groups
        ]
        for writer in writers:
            writer.start()
        for writer in writers:
            writer.join()
        stop.set()
        for reader in readers:
            reader.join()
        self.assertEqual(errors, [])

        readback = light_client.read_state_anchors(
            self.path, accounts=[self.A, self.B, self.C]
        )
        self.assertTrue(readback["ok"], readback)
        self.assertEqual(readback["generation"], 3)
        self.assertEqual(
            [(item["anchor"]["height"], item["account"])
             for item in readback["items"]],
            sorted(
                (height, account)
                for height, accounts in groups
                for account in accounts
            ),
        )
        final = light_client.export_state_anchors(
            self.path, [1, 2, 3], [self.A, self.B, self.C]
        )
        self.assertTrue(final["ok"], final)
        self.assertEqual(
            light_client.verify_state_anchors_export(final["document"]),
            {"ok": True},
        )
        self.assertEqual(final["document"]["generation"], 3)
        self.assertEqual(len(final["document"]["records"]), 6)




if __name__ == "__main__":
    unittest.main(verbosity=2)
