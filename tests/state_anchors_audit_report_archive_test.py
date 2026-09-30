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

    def test_record_and_query_round_trip(self) -> None:
        source = self._anchor_archive("anchors-a.json", [
            self.account_a, self.account_b])
        pairs = self._pairs(
            (1, self.account_a), (1, self.account_b), (1, self.account_c))
        report = self._report([source], pairs)
        archive = os.path.join(self.tmp, "reports.json")

        recorded = light_client.record_state_anchors_audit_report(
            archive, report, pairs, self.report_key)
        self.assertEqual(
            recorded,
            {"ok": True, "digest": report["digest"], "generation": 1},
        )

        fetched = light_client.read_state_anchors_audit_report(
            archive, report["digest"])
        self.assertTrue(fetched["ok"], fetched)
        self.assertEqual(fetched["generation"], 1)
        self.assertEqual(fetched["report"], report)

    def test_idempotent_same_digest_keeps_order_and_generation(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        first = self._report([source], pairs)

        source_b = self._anchor_archive("anchors-b.json", [self.account_b])
        second = self._report(
            [source, source_b],
            self._pairs((1, self.account_a), (1, self.account_b)),
        )
        self.assertNotEqual(first["digest"], second["digest"])
        archive = os.path.join(self.tmp, "reports.json")

        self.assertTrue(light_client.record_state_anchors_audit_report(
            archive, first, pairs, self.report_key)["ok"])
        self.assertTrue(light_client.record_state_anchors_audit_report(
            archive, second,
            self._pairs((1, self.account_a), (1, self.account_b)),
            self.report_key)["ok"])

        before = open(archive, "rb").read()
        repeat = light_client.record_state_anchors_audit_report(
            archive, json.loads(json.dumps(first)), pairs, self.report_key)
        self.assertEqual(
            repeat,
            {"ok": True, "digest": first["digest"], "generation": 1},
        )
        self.assertEqual(open(archive, "rb").read(), before)

        document = json.loads(before)
        self.assertEqual(
            [item["digest"] for item in document["reports"]],
            [first["digest"], second["digest"]],
        )
        self.assertEqual(document["generation"], 2)

        fetched = light_client.read_state_anchors_audit_report(
            archive, first["digest"])
        self.assertTrue(fetched["ok"], fetched)
        self.assertEqual(fetched["generation"], 1)
        self.assertEqual(fetched["report"], first)
        self.assertEqual(open(archive, "rb").read(), before)

    def test_restart_consistency_in_another_process(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        report = self._report([source], pairs)
        archive = os.path.join(self.tmp, "reports.json")
        self.assertTrue(light_client.record_state_anchors_audit_report(
            archive, report, pairs, self.report_key)["ok"])

        code = (
            "import json, sys; sys.path.insert(0, %r);"
            "from ledger import light_client;"
            "print(json.dumps(light_client.read_state_anchors_audit_report("
            "%r, %r)))"
            % (
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                archive,
                report["digest"],
            )
        )
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["report"]["digest"], report["digest"])

    def test_query_inputs_not_found_and_state(self) -> None:
        archive = os.path.join(self.tmp, "reports.json")
        self.assertEqual(
            light_client.read_state_anchors_audit_report("", "a" * 64),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.read_state_anchors_audit_report(archive, "xyz"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.read_state_anchors_audit_report(archive, "a" * 64),
            {"ok": False, "error": "not_found"},
        )

        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        report = self._report([source], pairs)
        self.assertTrue(light_client.record_state_anchors_audit_report(
            archive, report, pairs, self.report_key)["ok"])
        self.assertEqual(
            light_client.read_state_anchors_audit_report(
                archive, "b" * 64),
            {"ok": False, "error": "not_found"},
        )

        with open(archive, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(
            light_client.read_state_anchors_audit_report(
                archive, report["digest"]),
            {"ok": False, "error": "state"},
        )

    def test_corrupt_archive_hash_is_state(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        report = self._report([source], pairs)
        archive = os.path.join(self.tmp, "reports.json")
        self.assertTrue(light_client.record_state_anchors_audit_report(
            archive, report, pairs, self.report_key)["ok"])

        document = json.loads(open(archive, encoding="utf-8").read())
        document["hash"] = "c" * 64
        with open(archive, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, report, pairs, self.report_key),
            {"ok": False, "error": "state"},
        )

    def test_record_error_categories(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        report = self._report([source], pairs)
        archive = os.path.join(self.tmp, "reports.json")

        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                "", report, pairs, self.report_key),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, {"v": 1}, pairs, self.report_key),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, report, pairs, "not-hex"),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, report, [], self.report_key),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, report, pairs, "0" * 64),
            {"ok": False, "error": "auth"},
        )

        other_seed = os.urandom(32).hex()
        other_key = crypto.derive_public_key(other_seed)
        foreign = self._report([source], pairs)
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, foreign, pairs, other_key),
            {"ok": False, "error": "auth"},
        )

        tampered = json.loads(json.dumps(report))
        tampered["digest"] = "d" * 64
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, tampered, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )

        tampered = json.loads(json.dumps(report))
        tampered["verified"], tampered["missing"] = (
            tampered["missing"], tampered["verified"])
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, tampered, pairs, self.report_key),
            {"ok": False, "error": "integrity"},
        )

        self.assertFalse(os.path.exists(archive))

    def test_pinned_pair_mismatch_is_integrity(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        report = self._report([source], self._pairs((1, self.account_a)))
        archive = os.path.join(self.tmp, "reports.json")
        self.assertEqual(
            light_client.record_state_anchors_audit_report(
                archive, report,
                self._pairs((1, self.account_a), (1, self.account_b)),
                self.report_key),
            {"ok": False, "error": "integrity"},
        )

    def test_concurrent_same_path_records_are_serialized(self) -> None:
        sources = []
        pair_list = []
        for index, account in enumerate(
            (self.account_a, self.account_b, self.account_c)
        ):
            sources.append(self._anchor_archive(
                f"anchors-{index}.json", [account]))
            pair_list.append((1, account))
        reports = []
        for index in range(3):
            pairs = self._pairs(*pair_list[: index + 1])
            reports.append(self._report(sources[: index + 1], pairs))
        archive = os.path.join(self.tmp, "reports.json")
        results = []
        errors = []

        def worker(report, pairs):
            outcome = light_client.record_state_anchors_audit_report(
                archive, report, pairs, self.report_key)
            if outcome.get("ok"):
                results.append(outcome["generation"])
            else:
                errors.append(outcome)

        threads = [
            threading.Thread(target=worker, args=(report, self._pairs(
                *pair_list[: index + 1])))
            for index, report in enumerate(reports)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(errors, errors)
        self.assertEqual(sorted(results), [1, 2, 3])
        document = json.loads(open(archive, encoding="utf-8").read())
        self.assertEqual(document["generation"], 3)
        self.assertEqual(len(document["reports"]), 3)
        expected_position = {
            item["digest"]: position
            for position, item in enumerate(document["reports"], start=1)
        }
        for report in reports:
            fetched = light_client.read_state_anchors_audit_report(
                archive, report["digest"])
            self.assertTrue(fetched["ok"], fetched)
            self.assertEqual(
                fetched["generation"], expected_position[report["digest"]])

    def test_concurrent_records_from_separate_processes(self) -> None:
        sources = []
        pair_lists = []
        for index, account in enumerate(
            (self.account_a, self.account_b, self.account_c)
        ):
            sources.append(self._anchor_archive(
                f"anchors-x-{index}.json", [account]))
            pairs = self._pairs(
                *((1, acc) for acc in
                  (self.account_a, self.account_b, self.account_c)[: index + 1])
            )
            pair_lists.append(pairs)
        reports = [
            self._report(sources[: index + 1], pair_lists[index])
            for index in range(3)
        ]
        archive = os.path.join(self.tmp, "multi-reports.json")
        payload = os.path.join(self.tmp, "pending-reports.json")
        with open(payload, "w", encoding="utf-8") as fh:
            json.dump(
                [
                    {
                        "report": report,
                        "pairs": pairs,
                        "public_key": self.report_key,
                    }
                    for report, pairs in zip(reports, pair_lists)
                ],
                fh,
            )

        repo_root = os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))
        code = (
            "import json, sys; sys.path.insert(0, %r);"
            "from ledger import light_client;"
            "items = json.load(open(%r, encoding='utf-8'));"
            "item = items[int(sys.argv[1])];"
            "print(json.dumps(light_client."
            "record_state_anchors_audit_report("
            "%r, item['report'], item['pairs'], item['public_key'])))"
            % (repo_root, payload, archive)
        )
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", code, str(index)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index in range(3)
        ]
        outcomes = []
        for index, process in enumerate(processes):
            stdout, stderr = process.communicate()
            self.assertEqual(process.returncode, 0, stderr)
            outcomes.append(json.loads(stdout))

        self.assertTrue(all(item["ok"] for item in outcomes), outcomes)
        generations = sorted(item["generation"] for item in outcomes)
        self.assertEqual(generations, [1, 2, 3])
        digest_generation = {
            item["digest"]: item["generation"] for item in outcomes
        }

        document = json.loads(open(archive, encoding="utf-8").read())
        self.assertEqual(document["generation"], 3)
        self.assertEqual(len(document["reports"]), 3)
        ordered_digests = [item["digest"] for item in document["reports"]]
        self.assertEqual(
            ordered_digests,
            sorted(ordered_digests, key=digest_generation.__getitem__),
        )

        query_errors = []

        def reader(repeat: int) -> None:
            for _ in range(repeat):
                for report in reports:
                    fetched = light_client.read_state_anchors_audit_report(
                        archive, report["digest"])
                    if not fetched["ok"]:
                        query_errors.append(fetched)
                        continue
                    if (fetched["generation"]
                            != digest_generation[report["digest"]]):
                        query_errors.append(fetched)
                    if fetched["report"] != report:
                        query_errors.append(fetched)

        threads = [threading.Thread(target=reader, args=(5,))
                   for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(query_errors, query_errors)

        # The first recorded generation is preserved verbatim across a
        # fresh-process restart.
        first_digest = min(digest_generation, key=digest_generation.get)
        first_report = next(
            report for report in reports if report["digest"] == first_digest)
        code = (
            "import json, sys; sys.path.insert(0, %r);"
            "from ledger import light_client;"
            "print(json.dumps(light_client."
            "read_state_anchors_audit_report(%r, %r)))"
            % (repo_root, archive, first_digest)
        )
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            check=True)
        restarted = json.loads(completed.stdout)
        self.assertTrue(restarted["ok"], restarted)
        self.assertEqual(
            restarted["generation"], digest_generation[first_digest])
        self.assertEqual(restarted["report"], first_report)


if __name__ == "__main__":
    unittest.main()
