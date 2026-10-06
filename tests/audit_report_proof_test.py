from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto, light_client
from ledger.cli import main as cli_main
from ledger.service import LedgerService
from ledger.store import LedgerStore


def public_key(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


class AuditReportProofTest(unittest.TestCase):
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

    def _proof(self, accounts, height):
        status, document = self.service.get_attested_account_proofs(
            {"accounts": accounts, "height": str(height)}
        )
        self.assertEqual(status, 200, document)
        return document

    def _anchor_archive(self, name, accounts, height=1):
        path = os.path.join(self.tmp, name)
        document = self._proof(accounts, height)
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

    def _recorded_archive(self, count=3):
        accounts = (self.account_a, self.account_b, self.account_c)
        sources = []
        pair_lists = []
        reports = []
        for index in range(count):
            sources.append(self._anchor_archive(
                f"anchors-{index}.json", [accounts[index]]))
            pair_lists.append(self._pairs(
                *((1, account) for account in accounts[: index + 1])))
            reports.append(self._report(
                sources[: index + 1], pair_lists[index]))
        archive = os.path.join(self.tmp, "reports.json")
        for report, pairs in zip(reports, pair_lists):
            recorded = light_client.record_state_anchors_audit_report(
                archive, report, pairs, self.report_key)
            self.assertTrue(recorded["ok"], recorded)
        return archive, reports, pair_lists

    def test_proof_round_trip_verifies_offline(self) -> None:
        archive, reports, pair_lists = self._recorded_archive()
        leaves = [report["digest"] for report in reports]
        expected_root = crypto.merkle_root(leaves)

        for index, (report, pairs) in enumerate(zip(reports, pair_lists)):
            proof = light_client.audit_report_proof(archive, report["digest"])
            self.assertTrue(proof["ok"], proof)
            self.assertEqual(
                tuple(proof.keys()),
                ("ok", "generation", "archive_root", "digest", "index",
                 "total", "report", "siblings"),
            )
            self.assertEqual(proof["generation"], index + 1)
            self.assertEqual(proof["archive_root"], expected_root)
            self.assertEqual(proof["digest"], report["digest"])
            self.assertEqual(proof["index"], index)
            self.assertEqual(proof["total"], len(reports))
            self.assertEqual(proof["report"], report)
            self.assertEqual(
                proof["siblings"], crypto.merkle_proof(leaves, index))
            for sibling in proof["siblings"]:
                self.assertEqual(
                    tuple(sibling.keys()), ("direction", "hash"))
                self.assertIn(sibling["direction"], ("left", "right"))
                self.assertTrue(crypto.is_hex64(sibling["hash"]))

            verified = light_client.verify_audit_report_proof(
                proof, expected_root, report["digest"], pairs,
                self.report_key)
            self.assertEqual(
                verified,
                {
                    "ok": True,
                    "archive_root": expected_root,
                    "digest": report["digest"],
                    "index": index,
                },
            )

    def test_single_report_proof_has_empty_path(self) -> None:
        archive, reports, pair_lists = self._recorded_archive(count=1)
        report = reports[0]
        proof = light_client.audit_report_proof(archive, report["digest"])
        self.assertTrue(proof["ok"], proof)
        self.assertEqual(proof["siblings"], [])
        self.assertEqual(proof["archive_root"], report["digest"])
        self.assertEqual(proof["index"], 0)
        self.assertEqual(proof["total"], 1)
        verified = light_client.verify_audit_report_proof(
            proof, report["digest"], report["digest"], pair_lists[0],
            self.report_key)
        self.assertTrue(verified["ok"], verified)

    def test_repeated_reads_and_restart_yield_same_root_and_path(self) -> None:
        archive, reports, _ = self._recorded_archive()
        digest = reports[1]["digest"]
        first = light_client.audit_report_proof(archive, digest)
        second = light_client.audit_report_proof(archive, digest)
        self.assertEqual(first, second)

        code = (
            "import json, sys; sys.path.insert(0, %r);"
            "from ledger import light_client;"
            "print(json.dumps(light_client.audit_report_proof(%r, %r)))"
            % (
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                archive,
                digest,
            )
        )
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            check=True,
        )
        restarted = json.loads(completed.stdout)
        self.assertEqual(restarted, first)

    def test_proof_is_stable_under_concurrent_appends(self) -> None:
        archive, reports, pair_lists = self._recorded_archive(count=2)
        digest = reports[0]["digest"]
        before = light_client.audit_report_proof(archive, digest)
        self.assertTrue(before["ok"], before)

        extra_source = self._anchor_archive("anchors-x.json", [self.account_c])
        extra_pairs = self._pairs((1, self.account_c))
        extra = self._report([extra_source], extra_pairs)
        errors = []

        def worker():
            outcome = light_client.record_state_anchors_audit_report(
                archive, extra, extra_pairs, self.report_key)
            if not outcome.get("ok"):
                errors.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(errors, errors)

        # The pre-append proof still verifies against the pre-append root.
        verified = light_client.verify_audit_report_proof(
            before, before["archive_root"], digest, pair_lists[0],
            self.report_key)
        self.assertTrue(verified["ok"], verified)

        # The new archive version yields a new root but the same leaf index.
        after = light_client.audit_report_proof(archive, digest)
        self.assertTrue(after["ok"], after)
        self.assertNotEqual(after["archive_root"], before["archive_root"])
        self.assertEqual(after["index"], before["index"])
        self.assertEqual(after["total"], 3)
        repeat = light_client.audit_report_proof(archive, digest)
        self.assertEqual(repeat, after)
        verified = light_client.verify_audit_report_proof(
            after, after["archive_root"], digest, pair_lists[0],
            self.report_key)
        self.assertTrue(verified["ok"], verified)

    def test_proof_error_categories(self) -> None:
        archive, reports, _ = self._recorded_archive(count=1)
        digest = reports[0]["digest"]

        self.assertEqual(
            light_client.audit_report_proof("", digest),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.audit_report_proof(archive, "xyz"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.audit_report_proof(archive, digest.upper()),
            {"ok": False, "error": "input"},
        )
        missing = os.path.join(self.tmp, "missing.json")
        self.assertEqual(
            light_client.audit_report_proof(missing, digest),
            {"ok": False, "error": "not_found"},
        )
        self.assertEqual(
            light_client.audit_report_proof(archive, "b" * 64),
            {"ok": False, "error": "not_found"},
        )

        with open(archive, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(
            light_client.audit_report_proof(archive, digest),
            {"ok": False, "error": "state"},
        )

    def test_verify_input_defects(self) -> None:
        archive, reports, pair_lists = self._recorded_archive(count=1)
        report = reports[0]
        pairs = pair_lists[0]
        proof = light_client.audit_report_proof(archive, report["digest"])

        self.assertEqual(
            light_client.verify_audit_report_proof(
                proof, "zz", report["digest"], pairs, self.report_key),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.verify_audit_report_proof(
                proof, proof["archive_root"], "zz", pairs, self.report_key),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.verify_audit_report_proof(
                proof, proof["archive_root"], report["digest"], pairs, "zz"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.verify_audit_report_proof(
                proof, proof["archive_root"], report["digest"], [],
                self.report_key),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.verify_audit_report_proof(
                {"ok": True}, proof["archive_root"], report["digest"], pairs,
                self.report_key),
            {"ok": False, "error": "input"},
        )

        tampered = json.loads(json.dumps(proof))
        tampered["index"] = -1
        self.assertEqual(
            light_client.verify_audit_report_proof(
                tampered, proof["archive_root"], report["digest"], pairs,
                self.report_key),
            {"ok": False, "error": "input"},
        )
        tampered = json.loads(json.dumps(proof))
        tampered["siblings"] = [{"direction": "up", "hash": "a" * 64}]
        self.assertEqual(
            light_client.verify_audit_report_proof(
                tampered, proof["archive_root"], report["digest"], pairs,
                self.report_key),
            {"ok": False, "error": "input"},
        )
        tampered = json.loads(json.dumps(proof))
        tampered["report"] = {"v": 1}
        self.assertEqual(
            light_client.verify_audit_report_proof(
                tampered, proof["archive_root"], report["digest"], pairs,
                self.report_key),
            {"ok": False, "error": "input"},
        )

    def test_verify_auth_failures(self) -> None:
        archive, reports, pair_lists = self._recorded_archive(count=1)
        report = reports[0]
        pairs = pair_lists[0]
        proof = light_client.audit_report_proof(archive, report["digest"])

        other_key = crypto.derive_public_key(os.urandom(32).hex())
        self.assertEqual(
            light_client.verify_audit_report_proof(
                proof, proof["archive_root"], report["digest"], pairs,
                other_key),
            {"ok": False, "error": "auth"},
        )

        tampered = json.loads(json.dumps(proof))
        tampered["report"]["signature"] = "0" * 128
        self.assertEqual(
            light_client.verify_audit_report_proof(
                tampered, proof["archive_root"], report["digest"], pairs,
                self.report_key),
            {"ok": False, "error": "auth"},
        )

    def test_verify_integrity_failures(self) -> None:
        archive, reports, pair_lists = self._recorded_archive()
        pairs = pair_lists[1]
        proof = light_client.verify_audit_report_proof
        document = light_client.audit_report_proof(
            archive, reports[1]["digest"])
        self.assertTrue(document["ok"], document)
        root = document["archive_root"]
        digest = reports[1]["digest"]

        # A wrong pinned root, digest or pairs set is integrity.
        self.assertEqual(
            proof(document, "c" * 64, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            proof(document, root, reports[0]["digest"], pairs,
                  self.report_key),
            {"ok": False, "error": "integrity"},
        )
        self.assertEqual(
            proof(document, root, digest, pair_lists[0], self.report_key),
            {"ok": False, "error": "integrity"},
        )

        # A tampered leaf, path, index, generation or total is integrity.
        tampered = json.loads(json.dumps(document))
        tampered["digest"] = "d" * 64
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        tampered = json.loads(json.dumps(document))
        tampered["siblings"][0]["hash"] = "e" * 64
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        tampered = json.loads(json.dumps(document))
        tampered["siblings"] = tampered["siblings"][:-1]
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        tampered = json.loads(json.dumps(document))
        tampered["index"] = 0
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        tampered = json.loads(json.dumps(document))
        tampered["generation"] = 3
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        tampered = json.loads(json.dumps(document))
        # A total inconsistent with the sibling-path depth is integrity
        # (a 3-leaf tree has a 2-deep path; a 2-leaf tree a 1-deep one).
        tampered["total"] = 2
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        tampered = json.loads(json.dumps(document))
        tampered["archive_root"] = "f" * 64
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )
        # A report body digest that no longer matches its content.
        tampered = json.loads(json.dumps(document))
        tampered["report"]["digest"] = "1" * 64
        self.assertEqual(
            proof(tampered, root, digest, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )

        # The untouched document still verifies.
        self.assertTrue(
            proof(document, root, digest, pairs, self.report_key)["ok"])

    def test_cli_round_trip_and_exit_codes(self) -> None:
        archive, reports, pair_lists = self._recorded_archive()
        digest = reports[2]["digest"]
        pairs = pair_lists[2]
        pairs_file = os.path.join(self.tmp, "pairs.json")
        with open(pairs_file, "w", encoding="utf-8") as fh:
            json.dump(pairs, fh)

        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_main(["audit-report-proof", archive, digest])
        self.assertEqual(rc, 0)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        proof = json.loads(lines[0])
        self.assertTrue(proof["ok"], proof)
        proof_file = os.path.join(self.tmp, "proof.json")
        with open(proof_file, "w", encoding="utf-8") as fh:
            fh.write(lines[0])

        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_main([
                "audit-report-verify", proof_file,
                "--expected-root", proof["archive_root"],
                "--expected-digest", digest,
                "--pairs", pairs_file,
                "--public-key", self.report_key,
            ])
        self.assertEqual(rc, 0)
        verified = json.loads(out.getvalue())
        self.assertEqual(
            verified,
            {
                "ok": True,
                "archive_root": proof["archive_root"],
                "digest": digest,
                "index": 2,
            },
        )

        # A wrong pinned root exits 1 with a single-line JSON body.
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_main([
                "audit-report-verify", proof_file,
                "--expected-root", "a" * 64,
                "--expected-digest", digest,
                "--pairs", pairs_file,
                "--public-key", self.report_key,
            ])
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(out.getvalue()),
            {"ok": False, "error": "integrity"},
        )

        # An unknown digest exits 1.
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_main(["audit-report-proof", archive, "b" * 64])
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(out.getvalue()),
            {"ok": False, "error": "not_found"},
        )

        # Missing arguments are an input failure, exit 1.
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_main(["audit-report-proof", archive])
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(out.getvalue()),
            {"ok": False, "error": "input"},
        )
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli_main(["audit-report-verify", proof_file])
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(out.getvalue()),
            {"ok": False, "error": "input"},
        )

    def test_cli_reads_pairs_and_proof_from_stdin(self) -> None:
        archive, reports, pair_lists = self._recorded_archive(count=1)
        digest = reports[0]["digest"]
        proof = light_client.audit_report_proof(archive, digest)
        self.assertTrue(proof["ok"], proof)
        proof_file = os.path.join(self.tmp, "proof.json")
        with open(proof_file, "w", encoding="utf-8") as fh:
            json.dump(proof, fh)

        code = (
            "import json, sys; sys.path.insert(0, %r);"
            "from ledger.cli import main;"
            "sys.exit(main([\"audit-report-verify\", %r,"
            " \"--expected-root\", %r, \"--expected-digest\", %r,"
            " \"--pairs\", \"-\", \"--public-key\", %r]))"
            % (
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                proof_file,
                proof["archive_root"],
                digest,
                self.report_key,
            )
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            input=json.dumps(pair_lists[0]),
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertTrue(json.loads(completed.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
