from __future__ import annotations

import copy
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


def public_key_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class StateAnchorsAuditReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.paths: list[str] = []
        self.store = LedgerStore(os.path.join(self.tmp, "store.json"))
        self.service = LedgerService(self.store, initial_balance=100_000)
        self.signing = Ed25519PrivateKey.generate()
        self.signing_hex = self.signing.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
        self.public_hex = public_key_hex(self.signing)
        self.key_a = Ed25519PrivateKey.generate()
        self.key_b = Ed25519PrivateKey.generate()
        self.account_a = public_key_hex(self.key_a)
        self.account_b = public_key_hex(self.key_b)
        msg = crypto.canonical_message(self.account_a, self.account_b, 100)
        txn = {
            "from": self.account_a,
            "to": self.account_b,
            "amount": 100,
            "signature": self.key_a.sign(msg).hex(),
        }
        self.assertEqual(self.service.submit_transaction(txn)[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("1")[0], 200)
        self.trust = self.service.get_trust_document()[1]

    def _record(self, path: str, accounts: list[str]) -> None:
        status, document = self.service.get_attested_account_proofs(
            {"accounts": accounts, "height": "1"}
        )
        self.assertEqual(status, 200, document)
        result = light_client.record_state_anchors(
            path, document, accounts, self.trust
        )
        self.assertTrue(result["ok"], result)

    def _path(self, name: str) -> str:
        path = os.path.join(self.tmp, name)
        self.paths.append(path)
        return path

    def test_roundtrip_determinism_missing_source_and_classifications(self) -> None:
        path_one = self._path("a.json")
        path_two = self._path("b.json")
        missing = self._path("missing.json")
        self._record(path_one, [self.account_a, self.account_b])
        self._record(path_two, [self.account_b])
        pairs = [
            {"height": 1, "account": self.account_b},
            {"height": 1, "account": self.account_a},
            {"height": 9, "account": self.account_a},
        ]
        ordered_paths = [path_one, path_two, missing]
        result = light_client.export_state_anchors_audit_report(
            ordered_paths, pairs, self.signing_hex
        )
        self.assertTrue(result["ok"], result)
        report = result["report"]
        self.assertEqual(
            list(report),
            [
                "v",
                "sources",
                "evidence",
                "pinned",
                "verified",
                "missing",
                "conflicts",
                "public_key",
                "digest",
                "signature",
            ],
        )
        self.assertEqual(report["public_key"], self.public_hex)
        self.assertEqual(report["sources"][2]["generation"], 0)
        self.assertEqual(
            [pair["account"] for pair in report["verified"]],
            sorted([self.account_a, self.account_b]),
        )
        self.assertEqual(
            report["missing"], [{"height": 9, "account": self.account_a}]
        )
        self.assertEqual(report["conflicts"], [])
        self.assertEqual(len(report["evidence"]), 2)

        # Source order must not change groups or bytes.
        swapped = light_client.export_state_anchors_audit_report(
            [path_two, path_one, missing], pairs, self.signing_hex
        )
        self.assertTrue(swapped["ok"], swapped)
        self.assertEqual(
            json.dumps(swapped["report"]["verified"], sort_keys=True),
            json.dumps(report["verified"], sort_keys=True),
        )
        again = light_client.export_state_anchors_audit_report(
            ordered_paths, copy.deepcopy(pairs), self.signing_hex
        )
        self.assertEqual(
            json.dumps(again["report"], sort_keys=True),
            json.dumps(report, sort_keys=True),
        )

        verdict = light_client.verify_state_anchors_audit_report(
            copy.deepcopy(report), pairs, self.public_hex
        )
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(
            list(verdict), ["ok", "verified", "missing", "conflicts"]
        )
        self.assertEqual(verdict["verified"], report["verified"])
        self.assertEqual(verdict["missing"], report["missing"])

        # Parameter shape problems.
        self.assertEqual(
            light_client.export_state_anchors_audit_report(
                [], pairs, self.signing_hex
            )["error"],
            "input",
        )
        self.assertEqual(
            light_client.export_state_anchors_audit_report(
                ordered_paths, [], self.signing_hex
            )["error"],
            "input",
        )
        self.assertEqual(
            light_client.export_state_anchors_audit_report(
                ordered_paths, pairs, "zz"
            )["error"],
            "input",
        )
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                report, pairs, "zz"
            )["error"],
            "input",
        )
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                "nope", pairs, self.public_hex
            )["error"],
            "input",
        )
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                report, pairs + pairs[:1], self.public_hex
            )["error"],
            "input",
        )

        # Wrong public key and bad signature -> auth.
        other_hex = public_key_hex(Ed25519PrivateKey.generate())
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                copy.deepcopy(report), pairs, other_hex
            )["error"],
            "auth",
        )
        bad_sig = copy.deepcopy(report)
        bad_sig["signature"] = "0" * 128
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                bad_sig, pairs, self.public_hex
            )["error"],
            "auth",
        )

        # Tampered body -> digest integrity failure.
        tampered = copy.deepcopy(report)
        tampered["missing"] = []
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                tampered, pairs, self.public_hex
            )["error"],
            "integrity",
        )

        # Tampered evidence content with a fresh valid signature but stale
        # groups -> integrity.
        moved = copy.deepcopy(report)
        moved["verified"] = report["verified"][:0]
        moved["conflicts"] = report["verified"]
        moved["digest"] = light_client._state_anchors_audit_report_digest(moved)
        moved["signature"] = crypto.sign_message(
            self.signing_hex,
            light_client._state_anchors_audit_report_message(moved["digest"]),
        )
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                moved, pairs, self.public_hex
            )["error"],
            "integrity",
        )

        # Tampered anchor evidence with re-sealed body -> integrity.
        resealed = copy.deepcopy(report)
        hit = resealed["evidence"][0]["hits"][0]
        hit["anchor"]["block_hash"] = "0" * 64
        resealed["digest"] = light_client._state_anchors_audit_report_digest(
            resealed
        )
        resealed["signature"] = crypto.sign_message(
            self.signing_hex,
            light_client._state_anchors_audit_report_message(
                resealed["digest"]
            ),
        )
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                resealed, pairs, self.public_hex
            )["error"],
            "integrity",
        )

        # Tampering the signed proof content invalidates the embedded batch
        # Ed25519 signature -> auth.
        resealed_proof = copy.deepcopy(report)
        resealed_proof["evidence"][0]["hits"][0]["proof"]["balance"] += 1
        resealed_proof["digest"] = (
            light_client._state_anchors_audit_report_digest(resealed_proof)
        )
        resealed_proof["signature"] = crypto.sign_message(
            self.signing_hex,
            light_client._state_anchors_audit_report_message(
                resealed_proof["digest"]
            ),
        )
        self.assertEqual(
            light_client.verify_state_anchors_audit_report(
                resealed_proof, pairs, self.public_hex
            )["error"],
            "auth",
        )

        # Corrupt archive on disk -> state; verify must not read files.
        with open(path_two, "w", encoding="utf-8") as fh:
            fh.write("{")
        self.assertEqual(
            light_client.export_state_anchors_audit_report(
                ordered_paths, pairs, self.signing_hex
            )["error"],
            "state",
        )
        verdict_two = light_client.verify_state_anchors_audit_report(
            copy.deepcopy(report), pairs, self.public_hex
        )
        self.assertTrue(verdict_two["ok"], verdict_two)


if __name__ == "__main__":
    unittest.main()
