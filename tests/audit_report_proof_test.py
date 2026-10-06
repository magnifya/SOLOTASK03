"""Audit-report archive inclusion proofs.

Covers ``ledger.light_client.audit_report_proof`` /
``ledger.light_client.verify_audit_report_proof`` and the
``python -m ledger.cli audit-report-proof`` /
``audit-report-verify`` commands: an auditor holding only one proof
document and the pinned archive root can re-verify that a single signed
audit report belongs to the pinned archive version, offline.
"""
from __future__ import annotations

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

PROOF_KEYS = (
    "ok",
    "generation",
    "archive_root",
    "digest",
    "index",
    "total",
    "report",
    "siblings",
)
VERIFY_KEYS = ("ok", "archive_root", "digest", "index")


def public_key(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


class AuditReportProofFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
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
        self.seed = os.urandom(32).hex()
        self.report_key = crypto.derive_public_key(self.seed)

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

    def _proof_document(self, accounts, height=1):
        status, document = self.service.get_attested_account_proofs(
            {"accounts": accounts, "height": str(height)}
        )
        self.assertEqual(status, 200, document)
        return document

    def _anchor_archive(self, name, accounts, height=1):
        path = os.path.join(self.tmp, name)
        document = self._proof_document(accounts, height)
        result = light_client.record_state_anchors(
            path, document, accounts, self.trust_v1
        )
        self.assertTrue(result["ok"], result)
        return path

    def _report(self, source_paths, pairs):
        result = light_client.export_state_anchors_audit_report(
            source_paths, pairs, self.seed
        )
        self.assertTrue(result["ok"], result)
        return result["report"]

    def _pairs(self, *items):
        return [{"height": h, "account": a} for h, a in items]

    def _record(self, archive, report, pairs):
        result = light_client.record_state_anchors_audit_report(
            archive, report, pairs, self.report_key
        )
        self.assertTrue(result["ok"], result)
        return result

    def _three_report_archive(self):
        """One archive with three distinctly-paired reports.

        Returns ``(archive, pairs, reports, report_pairs)`` with ``pairs``
        the full pinned list and ``report_pairs[i]`` the exact pinned list
        report ``i`` was recorded under.
        """
        sources = []
        pair_list = []
        for index, account in enumerate(
            (self.account_a, self.account_b, self.account_c)
        ):
            sources.append(
                self._anchor_archive(f"anchors-{index}.json", [account])
            )
            pair_list.append((1, account))
        pairs = self._pairs(*pair_list)
        reports = []
        report_pairs = []
        for index in range(3):
            sub_pairs = self._pairs(*pair_list[: index + 1])
            report_pairs.append(sub_pairs)
            reports.append(self._report(sources[: index + 1], sub_pairs))
        archive = os.path.join(self.tmp, "reports.json")
        for index, report in enumerate(reports):
            self._record(archive, report, report_pairs[index])
        return archive, pairs, reports, report_pairs


class AuditReportProofTest(AuditReportProofFixture):
    def test_proof_round_trip_verifies_offline(self) -> None:
        archive, _all_pairs, reports, report_pairs = (
            self._three_report_archive()
        )
        leaves = [report["digest"] for report in reports]
        expected_root = crypto.merkle_root(leaves)

        for index, report in enumerate(reports):
            proof = light_client.audit_report_proof(archive, report["digest"])
            self.assertTrue(proof["ok"], proof)
            self.assertEqual(tuple(proof.keys()), PROOF_KEYS)
            self.assertEqual(proof["generation"], 3)
            self.assertEqual(proof["archive_root"], expected_root)
            self.assertEqual(proof["digest"], report["digest"])
            self.assertEqual(proof["index"], index)
            self.assertEqual(proof["total"], 3)
            self.assertEqual(proof["report"], report)
            self.assertEqual(
                proof["siblings"], crypto.merkle_proof(leaves, index)
            )
            for sibling in proof["siblings"]:
                self.assertEqual(tuple(sibling.keys()), ("direction", "hash"))
                self.assertIn(sibling["direction"], ("left", "right"))
                self.assertTrue(crypto.is_hex64(sibling["hash"]))

            verified = light_client.verify_audit_report_proof(
                proof,
                expected_root,
                report["digest"],
                report_pairs[index],
                self.report_key,
            )
            self.assertTrue(verified["ok"], verified)
            self.assertEqual(tuple(verified.keys()), VERIFY_KEYS)
            self.assertEqual(verified["archive_root"], expected_root)
            self.assertEqual(verified["digest"], report["digest"])
            self.assertEqual(verified["index"], index)

    def test_single_report_archive_has_empty_path(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        report = self._report([source], pairs)
        archive = os.path.join(self.tmp, "reports.json")
        self._record(archive, report, pairs)

        proof = light_client.audit_report_proof(archive, report["digest"])
        self.assertTrue(proof["ok"], proof)
        self.assertEqual(proof["generation"], 1)
        self.assertEqual(proof["archive_root"], report["digest"])
        self.assertEqual(proof["index"], 0)
        self.assertEqual(proof["total"], 1)
        self.assertEqual(proof["siblings"], [])

        verified = light_client.verify_audit_report_proof(
            proof, report["digest"], report["digest"], pairs, self.report_key
        )
        self.assertEqual(
            verified,
            {
                "ok": True,
                "archive_root": report["digest"],
                "digest": report["digest"],
                "index": 0,
            },
        )

    def test_repeated_reads_and_restart_give_identical_proof(self) -> None:
        archive, _pairs, reports, _report_pairs = self._three_report_archive()
        first = light_client.audit_report_proof(archive, reports[1]["digest"])
        second = light_client.audit_report_proof(archive, reports[1]["digest"])
        self.assertEqual(first, second)

        code = (
            "import json, sys; sys.path.insert(0, %r);"
            "from ledger import light_client;"
            "print(json.dumps(light_client.audit_report_proof(%r, %r)))"
            % (
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                archive,
                reports[1]["digest"],
            )
        )
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            check=True,
        )
        self.assertEqual(json.loads(completed.stdout), first)

    def test_proof_stays_valid_for_its_pinned_version(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        source_b = self._anchor_archive("anchors-b.json", [self.account_b])
        pairs_a = self._pairs((1, self.account_a))
        pairs_b = self._pairs((1, self.account_a), (1, self.account_b))
        first = self._report([source], pairs_a)
        second = self._report([source, source_b], pairs_b)
        archive = os.path.join(self.tmp, "reports.json")
        self._record(archive, first, pairs_a)

        pinned = light_client.audit_report_proof(archive, first["digest"])
        self.assertTrue(pinned["ok"], pinned)
        pinned_root = pinned["archive_root"]

        # Appending another report grows the tree; the earlier proof still
        # verifies offline against its own pinned root and total.
        self._record(archive, second, pairs_b)
        verified = light_client.verify_audit_report_proof(
            pinned, pinned_root, first["digest"], pairs_a, self.report_key
        )
        self.assertTrue(verified["ok"], verified)

        grown = light_client.audit_report_proof(archive, first["digest"])
        self.assertTrue(grown["ok"], grown)
        self.assertEqual(grown["index"], 0)
        self.assertEqual(grown["total"], 2)
        self.assertNotEqual(grown["archive_root"], pinned_root)
        self.assertTrue(
            light_client.verify_audit_report_proof(
                grown,
                grown["archive_root"],
                first["digest"],
                pairs_a,
                self.report_key,
            )["ok"]
        )

    def test_proof_read_error_categories(self) -> None:
        archive = os.path.join(self.tmp, "reports.json")
        self.assertEqual(
            light_client.audit_report_proof("", "a" * 64),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.audit_report_proof(archive, "xyz"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.audit_report_proof(None, "a" * 64),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.audit_report_proof(archive, "a" * 64),
            {"ok": False, "error": "not_found"},
        )

        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        report = self._report([source], pairs)
        self._record(archive, report, pairs)
        self.assertEqual(
            light_client.audit_report_proof(archive, "b" * 64),
            {"ok": False, "error": "not_found"},
        )

        with open(archive, "rb") as fh:
            before = fh.read()
        with open(archive, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(
            light_client.audit_report_proof(archive, report["digest"]),
            {"ok": False, "error": "state"},
        )
        with open(archive, "wb") as fh:
            fh.write(before)
        self.assertTrue(
            light_client.audit_report_proof(archive, report["digest"])["ok"]
        )

    def test_proof_read_io_error(self) -> None:
        # A directory at the archive path fails the read with io.
        directory = os.path.join(self.tmp, "reports.json")
        os.makedirs(directory)
        self.assertEqual(
            light_client.audit_report_proof(directory, "a" * 64),
            {"ok": False, "error": "io"},
        )

    def test_concurrent_appends_never_yield_torn_proofs(self) -> None:
        sources = []
        pair_list = []
        for index, account in enumerate(
            (self.account_a, self.account_b, self.account_c)
        ):
            sources.append(
                self._anchor_archive(f"anchors-{index}.json", [account])
            )
            pair_list.append((1, account))
        reports = []
        report_pairs = []
        for index in range(3):
            sub_pairs = self._pairs(*pair_list[: index + 1])
            report_pairs.append(sub_pairs)
            reports.append(self._report(sources[: index + 1], sub_pairs))
        archive = os.path.join(self.tmp, "reports.json")
        errors = []

        def recorder():
            for index, report in enumerate(reports):
                result = light_client.record_state_anchors_audit_report(
                    archive, report, report_pairs[index], self.report_key
                )
                if not result["ok"]:
                    errors.append(result)

        def reader():
            for _ in range(20):
                for position, report in enumerate(reports):
                    proof = light_client.audit_report_proof(
                        archive, report["digest"]
                    )
                    if not proof["ok"]:
                        if proof["error"] != "not_found":
                            errors.append(proof)
                        continue
                    # Whatever version the read observed must be one
                    # complete prefix of the recording order.
                    leaves = [
                        item["digest"] for item in reports[: proof["total"]]
                    ]
                    if proof["archive_root"] != crypto.merkle_root(leaves):
                        errors.append(proof)
                        continue
                    if proof["index"] != position:
                        errors.append(proof)
                        continue
                    verified = light_client.verify_audit_report_proof(
                        proof,
                        proof["archive_root"],
                        report["digest"],
                        report_pairs[position],
                        self.report_key,
                    )
                    if not verified["ok"]:
                        errors.append(verified)

        threads = [threading.Thread(target=recorder)] + [
            threading.Thread(target=reader) for _ in range(3)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])


class AuditReportProofVerifyTest(AuditReportProofFixture):
    def setUp(self) -> None:
        super().setUp()
        self.archive, self.pairs, self.reports, self.report_pairs = (
            self._three_report_archive()
        )
        self.report = self.reports[1]
        self.report_pair_list = self.report_pairs[1]
        self.proof = light_client.audit_report_proof(
            self.archive, self.report["digest"]
        )
        self.assertTrue(self.proof["ok"], self.proof)
        self.root = self.proof["archive_root"]

    def _verify(self, document=None, **overrides):
        arguments = {
            "expected_root": self.root,
            "expected_digest": self.report["digest"],
            "expected_pairs": self.report_pair_list,
            "public_key": self.report_key,
        }
        arguments.update(overrides)
        return light_client.verify_audit_report_proof(
            self.proof if document is None else document,
            arguments["expected_root"],
            arguments["expected_digest"],
            arguments["expected_pairs"],
            arguments["public_key"],
        )

    def _tampered(self, **changes):
        document = json.loads(json.dumps(self.proof))
        document.update(changes)
        return document

    def test_input_category(self) -> None:
        self.assertEqual(
            self._verify(document="not-a-dict"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document={"ok": True}),
            {"ok": False, "error": "input"},
        )
        # Key order matters.
        document = json.loads(json.dumps(self.proof))
        reordered = {key: document[key] for key in reversed(PROOF_KEYS)}
        self.assertEqual(
            self._verify(document=reordered),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(ok=False)),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(generation=0)),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(index=-1)),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(total=0)),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(archive_root="zz")),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(digest="zz")),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(siblings="nope")),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(
                document=self._tampered(
                    siblings=[{"direction": "left", "hash": "zz"}]
                )
            ),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(report={"v": 1})),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(expected_root="zz"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(expected_digest="zz"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(expected_pairs=[]),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            self._verify(public_key="not-hex"),
            {"ok": False, "error": "input"},
        )

    def test_auth_category(self) -> None:
        other_key = crypto.derive_public_key(os.urandom(32).hex())
        self.assertEqual(
            self._verify(public_key=other_key),
            {"ok": False, "error": "auth"},
        )
        # A report sealed by another key fails authentication too.
        other_seed = os.urandom(32).hex()
        sources = [
            self._anchor_archive("anchors-x.json", [self.account_a]),
        ]
        foreign = light_client.export_state_anchors_audit_report(
            sources, self._pairs((1, self.account_a)), other_seed
        )["report"]
        document = self._tampered(report=foreign, digest=foreign["digest"])
        self.assertEqual(
            self._verify(document=document),
            {"ok": False, "error": "auth"},
        )
        # A broken Ed25519 seal on the carried report is auth as well.
        forged = json.loads(json.dumps(self.report))
        forged["signature"] = "0" * 128
        self.assertEqual(
            self._verify(document=self._tampered(report=forged)),
            {"ok": False, "error": "auth"},
        )

    def test_integrity_category(self) -> None:
        # Pinned values disagreeing with the proof.
        self.assertEqual(
            self._verify(expected_root="0" * 64),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            self._verify(expected_digest="0" * 64),
            {"ok": False, "error": "integrity"},
        )
        # Document fields tampered after issuance.
        self.assertEqual(
            self._verify(document=self._tampered(archive_root="0" * 64)),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(digest="0" * 64)),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(index=0)),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(index=3)),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(total=2)),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(total=4)),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            self._verify(document=self._tampered(generation=2)),
            {"ok": False, "error": "integrity"},
        )
        # A tampered sibling hash or direction breaks the path.
        siblings = json.loads(json.dumps(self.proof["siblings"]))
        siblings[0]["hash"] = "0" * 64
        self.assertEqual(
            self._verify(document=self._tampered(siblings=siblings)),
            {"ok": False, "error": "integrity"},
        )
        siblings = json.loads(json.dumps(self.proof["siblings"]))
        siblings[0]["direction"] = (
            "left" if siblings[0]["direction"] == "right" else "right"
        )
        self.assertEqual(
            self._verify(document=self._tampered(siblings=siblings)),
            {"ok": False, "error": "integrity"},
        )
        # A dropped or reordered path no longer matches the total.
        siblings = self.proof["siblings"][:-1]
        self.assertEqual(
            self._verify(document=self._tampered(siblings=siblings)),
            {"ok": False, "error": "integrity"},
        )
        siblings = list(reversed(self.proof["siblings"]))
        self.assertEqual(
            self._verify(document=self._tampered(siblings=siblings)),
            {"ok": False, "error": "integrity"},
        )
        # A report whose digest field was replaced fails its own digest.
        tampered_report = json.loads(json.dumps(self.report))
        tampered_report["digest"] = "d" * 64
        self.assertEqual(
            self._verify(document=self._tampered(report=tampered_report)),
            {"ok": False, "error": "integrity"},
        )
        # Pinned pairs that do not match the report's coverage.
        self.assertEqual(
            self._verify(
                expected_pairs=self._pairs((1, self.account_a))
            ),
            {"ok": False, "error": "integrity"},
        )

    def test_odd_node_self_pair_rules(self) -> None:
        # The third leaf of a three-leaf tree pairs with itself; pointing
        # that self-pair to the left addresses the phantom slot.
        proof = light_client.audit_report_proof(
            self.archive, self.reports[2]["digest"]
        )
        self.assertTrue(proof["ok"], proof)
        self.assertEqual(proof["siblings"][0]["direction"], "right")
        self.assertEqual(
            proof["siblings"][0]["hash"], self.reports[2]["digest"]
        )
        self.assertTrue(
            light_client.verify_audit_report_proof(
                proof,
                proof["archive_root"],
                self.reports[2]["digest"],
                self.pairs,
                self.report_key,
            )["ok"]
        )
        document = json.loads(json.dumps(proof))
        document["siblings"][0]["direction"] = "left"
        self.assertEqual(
            light_client.verify_audit_report_proof(
                document,
                proof["archive_root"],
                self.reports[2]["digest"],
                self.pairs,
                self.report_key,
            ),
            {"ok": False, "error": "integrity"},
        )

    def test_verify_never_raises_on_garbage(self) -> None:
        for garbage in (
            None,
            42,
            [],
            {"ok": True, "generation": float("nan")},
            {"ok": True, "generation": 1, "archive_root": object()},
        ):
            result = light_client.verify_audit_report_proof(
                garbage, self.root, self.report["digest"], self.pairs,
                self.report_key,
            )
            self.assertEqual(result, {"ok": False, "error": "input"})


class AuditReportProofCliTest(AuditReportProofFixture):
    def run_cli(self, *args: str, stdin: str | None = None):
        proc = subprocess.run(
            [sys.executable, "-m", "ledger.cli", *args],
            input=stdin,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.stderr, "")
        lines = proc.stdout.strip().splitlines()
        self.assertEqual(len(lines), 1)
        return proc.returncode, json.loads(lines[0])

    def test_cli_proof_and_verify_round_trip(self) -> None:
        archive, _pairs, reports, report_pairs = self._three_report_archive()
        digest = reports[1]["digest"]
        pairs = report_pairs[1]

        code, proof = self.run_cli("audit-report-proof", archive, digest)
        self.assertEqual(code, 0, proof)
        self.assertEqual(tuple(proof.keys()), PROOF_KEYS)
        self.assertEqual(proof["digest"], digest)
        self.assertEqual(proof["index"], 1)

        proof_file = os.path.join(self.tmp, "proof.json")
        with open(proof_file, "w", encoding="utf-8") as fh:
            json.dump(proof, fh)
        pairs_file = os.path.join(self.tmp, "pairs.json")
        with open(pairs_file, "w", encoding="utf-8") as fh:
            json.dump(pairs, fh)

        code, body = self.run_cli(
            "audit-report-verify",
            proof_file,
            "--expected-root",
            proof["archive_root"],
            "--expected-digest",
            digest,
            "--pairs",
            pairs_file,
            "--public-key",
            self.report_key,
        )
        self.assertEqual(code, 0, body)
        self.assertEqual(tuple(body.keys()), VERIFY_KEYS)
        self.assertEqual(body["archive_root"], proof["archive_root"])
        self.assertEqual(body["digest"], digest)
        self.assertEqual(body["index"], 1)

    def test_cli_verify_reads_stdin(self) -> None:
        archive, _pairs, reports, report_pairs = self._three_report_archive()
        digest = reports[0]["digest"]
        pairs = report_pairs[0]
        proof = light_client.audit_report_proof(archive, digest)
        self.assertTrue(proof["ok"], proof)

        pairs_file = os.path.join(self.tmp, "pairs.json")
        with open(pairs_file, "w", encoding="utf-8") as fh:
            json.dump(pairs, fh)

        # The proof document itself may come from standard input.
        code, body = self.run_cli(
            "audit-report-verify",
            "-",
            "--expected-root",
            proof["archive_root"],
            "--expected-digest",
            digest,
            "--pairs",
            pairs_file,
            "--public-key",
            self.report_key,
            stdin=json.dumps(proof),
        )
        self.assertEqual(code, 0, body)
        self.assertTrue(body["ok"], body)

        # And so may the pairs file.
        proof_file = os.path.join(self.tmp, "proof.json")
        with open(proof_file, "w", encoding="utf-8") as fh:
            json.dump(proof, fh)
        code, body = self.run_cli(
            "audit-report-verify",
            proof_file,
            "--expected-root",
            proof["archive_root"],
            "--expected-digest",
            digest,
            "--pairs",
            "-",
            "--public-key",
            self.report_key,
            stdin=json.dumps(pairs),
        )
        self.assertEqual(code, 0, body)
        self.assertTrue(body["ok"], body)

    def test_cli_failures_exit_1(self) -> None:
        archive, _pairs, reports, report_pairs = self._three_report_archive()
        digest = reports[0]["digest"]
        pairs = report_pairs[0]
        proof = light_client.audit_report_proof(archive, digest)
        self.assertTrue(proof["ok"], proof)
        proof_file = os.path.join(self.tmp, "proof.json")
        with open(proof_file, "w", encoding="utf-8") as fh:
            json.dump(proof, fh)
        pairs_file = os.path.join(self.tmp, "pairs.json")
        with open(pairs_file, "w", encoding="utf-8") as fh:
            json.dump(pairs, fh)

        # Unknown digest in the archive.
        code, body = self.run_cli("audit-report-proof", archive, "b" * 64)
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "not_found"})

        # Missing archive.
        code, body = self.run_cli(
            "audit-report-proof",
            os.path.join(self.tmp, "absent.json"),
            digest,
        )
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "not_found"})

        # Missing positional argument.
        code, body = self.run_cli("audit-report-proof", archive)
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "input"})

        # A pinned root that does not match is integrity.
        code, body = self.run_cli(
            "audit-report-verify",
            proof_file,
            "--expected-root",
            "0" * 64,
            "--expected-digest",
            digest,
            "--pairs",
            pairs_file,
            "--public-key",
            self.report_key,
        )
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "integrity"})

        # A missing required option is an input failure.
        code, body = self.run_cli(
            "audit-report-verify",
            proof_file,
            "--expected-root",
            proof["archive_root"],
            "--expected-digest",
            digest,
            "--pairs",
            pairs_file,
        )
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "input"})

        # An unreadable proof file is an input failure.
        code, body = self.run_cli(
            "audit-report-verify",
            os.path.join(self.tmp, "absent-proof.json"),
            "--expected-root",
            proof["archive_root"],
            "--expected-digest",
            digest,
            "--pairs",
            pairs_file,
            "--public-key",
            self.report_key,
        )
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "input"})

        # Non-JSON pairs input is an input failure.
        code, body = self.run_cli(
            "audit-report-verify",
            proof_file,
            "--expected-root",
            proof["archive_root"],
            "--expected-digest",
            digest,
            "--pairs",
            "-",
            "--public-key",
            self.report_key,
            stdin="{not json",
        )
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "input"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
