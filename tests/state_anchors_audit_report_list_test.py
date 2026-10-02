from __future__ import annotations

import json
import os
import subprocess
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


class StateAnchorsAuditReportListTest(unittest.TestCase):
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
        self.other_seed = os.urandom(32).hex()
        self.other_report_key = crypto.derive_public_key(self.other_seed)

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

    def _report(self, source_paths, pairs, seed=None):
        result = light_client.export_state_anchors_audit_report(
            source_paths, pairs, self.seed if seed is None else seed
        )
        self.assertTrue(result["ok"], result)
        return result["report"]

    def _pairs(self, *items):
        return [{"height": h, "account": a} for h, a in items]

    def _record(self, archive, report, pairs, public_key=None):
        result = light_client.record_state_anchors_audit_report(
            archive,
            report,
            pairs,
            self.report_key if public_key is None else public_key,
        )
        self.assertTrue(result["ok"], result)
        return result

    def _three_report_archive(self):
        """Archive with three reports: key, other key, key (gens 1, 2, 3)."""
        sources = []
        pair_lists = []
        accounts = (self.account_a, self.account_b, self.account_c)
        for index, account in enumerate(accounts):
            sources.append(self._anchor_archive(
                f"anchors-{index}.json", [account]))
            pair_lists.append(self._pairs(
                *((1, acc) for acc in accounts[: index + 1])))
        first = self._report([sources[0]], pair_lists[0])
        second = self._report(
            sources[:2], pair_lists[1], seed=self.other_seed)
        third = self._report(sources, pair_lists[2])
        archive = os.path.join(self.tmp, "reports.json")
        self._record(archive, first, pair_lists[0])
        self._record(
            archive, second, pair_lists[1], public_key=self.other_report_key)
        self._record(archive, third, pair_lists[2])
        return archive, [first, second, third], pair_lists

    def test_list_all_reports_in_recording_order(self) -> None:
        archive, reports, _ = self._three_report_archive()
        before = open(archive, "rb").read()

        result = light_client.list_state_anchors_audit_reports(archive)
        self.assertEqual(
            list(result.keys()),
            ["ok", "generation", "items", "total", "next_cursor"],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["total"], 3)
        self.assertIsNone(result["next_cursor"])
        self.assertEqual(
            [item["generation"] for item in result["items"]], [1, 2, 3])
        self.assertEqual(
            [item["report"] for item in result["items"]], reports)
        # The listing is read-only.
        self.assertEqual(open(archive, "rb").read(), before)

    def test_listed_reports_still_verify_offline(self) -> None:
        archive, reports, pair_lists = self._three_report_archive()
        keys = [self.report_key, self.other_report_key, self.report_key]
        result = light_client.list_state_anchors_audit_reports(archive)
        self.assertTrue(result["ok"], result)
        for item, pairs, key in zip(result["items"], pair_lists, keys):
            verified = light_client.verify_state_anchors_audit_report(
                item["report"], pairs, key)
            self.assertTrue(verified["ok"], verified)

    def test_pagination_walks_the_filtered_matches(self) -> None:
        archive, reports, _ = self._three_report_archive()

        first_page = light_client.list_state_anchors_audit_reports(
            archive, limit=2)
        self.assertTrue(first_page["ok"], first_page)
        self.assertEqual(first_page["total"], 3)
        self.assertEqual(first_page["next_cursor"], 2)
        self.assertEqual(
            [item["generation"] for item in first_page["items"]], [1, 2])

        second_page = light_client.list_state_anchors_audit_reports(
            archive, limit=2, cursor=first_page["next_cursor"])
        self.assertTrue(second_page["ok"], second_page)
        self.assertEqual(second_page["total"], 3)
        self.assertIsNone(second_page["next_cursor"])
        self.assertEqual(
            [item["generation"] for item in second_page["items"]], [3])
        self.assertEqual(second_page["items"][0]["report"], reports[2])

        # cursor == total is a legal empty page.
        empty = light_client.list_state_anchors_audit_reports(
            archive, cursor=3)
        self.assertEqual(
            empty,
            {"ok": True, "generation": 3, "items": [], "total": 3,
             "next_cursor": None},
        )
        # cursor beyond total is an input error.
        self.assertEqual(
            light_client.list_state_anchors_audit_reports(archive, cursor=4),
            {"ok": False, "error": "input"},
        )

    def test_public_key_filter_keeps_matching_reports_only(self) -> None:
        archive, reports, _ = self._three_report_archive()

        filtered = light_client.list_state_anchors_audit_reports(
            archive, public_key=self.report_key)
        self.assertTrue(filtered["ok"], filtered)
        self.assertEqual(filtered["generation"], 3)
        self.assertEqual(filtered["total"], 2)
        self.assertIsNone(filtered["next_cursor"])
        # Filtering never renumbers: generations stay 1 and 3.
        self.assertEqual(
            [item["generation"] for item in filtered["items"]], [1, 3])
        self.assertEqual(
            [item["report"] for item in filtered["items"]],
            [reports[0], reports[2]],
        )

        other = light_client.list_state_anchors_audit_reports(
            archive, public_key=self.other_report_key, limit=1)
        self.assertTrue(other["ok"], other)
        self.assertEqual(other["total"], 1)
        self.assertIsNone(other["next_cursor"])
        self.assertEqual(other["items"][0]["generation"], 2)
        self.assertEqual(other["items"][0]["report"], reports[1])

        # A legal filter with no matches: total 0, empty items, null cursor.
        unknown = light_client.list_state_anchors_audit_reports(
            archive, public_key=crypto.derive_public_key(os.urandom(32).hex()))
        self.assertEqual(
            unknown,
            {"ok": True, "generation": 3, "items": [], "total": 0,
             "next_cursor": None},
        )

    def test_idempotent_repeat_still_occupies_one_item(self) -> None:
        source = self._anchor_archive("anchors-a.json", [self.account_a])
        pairs = self._pairs((1, self.account_a))
        report = self._report([source], pairs)
        archive = os.path.join(self.tmp, "reports.json")
        self._record(archive, report, pairs)
        self._record(archive, json.loads(json.dumps(report)), pairs)

        result = light_client.list_state_anchors_audit_reports(archive)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["total"], 1)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["generation"], 1)
        self.assertEqual(result["items"][0]["report"], report)

    def test_input_errors(self) -> None:
        archive, _, _ = self._three_report_archive()
        bad_calls = [
            {"path": ""},
            {"path": 123},
            {"public_key": "not-hex"},
            {"public_key": "A" * 64},
            {"public_key": 64},
            {"limit": 0},
            {"limit": 201},
            {"limit": True},
            {"limit": "50"},
            {"limit": 1.5},
            {"cursor": -1},
            {"cursor": False},
            {"cursor": "0"},
        ]
        for overrides in bad_calls:
            arguments = {"path": archive}
            arguments.update(overrides)
            path = arguments.pop("path")
            self.assertEqual(
                light_client.list_state_anchors_audit_reports(
                    path, **arguments),
                {"ok": False, "error": "input"},
                overrides,
            )
        # Explicit None public_key means no filtering.
        result = light_client.list_state_anchors_audit_reports(
            archive, public_key=None)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["total"], 3)
        # Boundary limits are legal.
        for limit in (1, 200):
            result = light_client.list_state_anchors_audit_reports(
                archive, limit=limit)
            self.assertTrue(result["ok"], result)

    def test_missing_archive_is_not_found(self) -> None:
        archive = os.path.join(self.tmp, "reports.json")
        self.assertEqual(
            light_client.list_state_anchors_audit_reports(archive),
            {"ok": False, "error": "not_found"},
        )

    def test_corrupt_archive_is_state(self) -> None:
        archive, _, _ = self._three_report_archive()
        document = json.loads(open(archive, encoding="utf-8").read())
        document["hash"] = "c" * 64
        with open(archive, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        self.assertEqual(
            light_client.list_state_anchors_audit_reports(archive),
            {"ok": False, "error": "state"},
        )

    def test_filtering_never_masks_sibling_corruption(self) -> None:
        archive, reports, _ = self._three_report_archive()
        document = json.loads(open(archive, encoding="utf-8").read())
        # Corrupt the second report (sealed by the other key), then fix the
        # archive hash so only the embedded report is defective.
        document["reports"][1]["digest"] = "d" * 64
        document["hash"] = light_client._audit_report_archive_hash(
            document["generation"], document["reports"])
        with open(archive, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        # Filtering to the intact key must still surface the corruption.
        self.assertEqual(
            light_client.list_state_anchors_audit_reports(
                archive, public_key=self.report_key),
            {"ok": False, "error": "state"},
        )

    def test_restart_consistency_in_another_process(self) -> None:
        archive, reports, _ = self._three_report_archive()
        code = (
            "import json, sys; sys.path.insert(0, %r);"
            "from ledger import light_client;"
            "print(json.dumps(light_client.list_state_anchors_audit_reports("
            "%r, limit=2)))"
            % (
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                archive,
            )
        )
        completed = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["next_cursor"], 2)
        self.assertEqual(
            [item["report"] for item in result["items"]], reports[:2])


if __name__ == "__main__":
    unittest.main()
