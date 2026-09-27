"""Behavioral tests for ``ledger.light_client.audit_sync_state``.

Reuses the real-service fixture from the ``advance_sync_state`` suite to
build a confirmed chain, commit a synced header/state pair and then
exercise the read-only audit: success key order
``ok, status, header, state, transaction`` (header order
``status, generation, tip, finalized``; state order
``status, generation, account, anchor``; transaction order
``status, header_generation, state_generation``), the per-target
``missing|valid|invalid`` and ``absent|valid|invalid`` classifications,
the five overall statuses ``empty|consistent|recoverable|split|corrupt``
in their fixed decision order, the ``input``/``io`` failure shape, and
the read-only guarantees (a leftover journal is never rolled forward and
no queried file changes a byte).

Run: python3 tests/light_client_audit_sync_state_test.py
"""
from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ledger.light_client as light_client
from ledger.light_client import advance_sync_state, audit_sync_state
from light_client_advance_sync_state_test import SyncStateFixture

TOP_KEYS = ["ok", "status", "header", "state", "transaction"]
HEADER_KEYS = ["status", "generation", "tip", "finalized"]
STATE_KEYS = ["status", "generation", "account", "anchor"]
TXN_KEYS = ["status", "header_generation", "state_generation"]


class AuditSyncStateInputTests(SyncStateFixture):
    def test_non_string_or_empty_path_is_input(self) -> None:
        for bad in ("", None, 7, b"x", []):
            self.assertEqual(
                audit_sync_state(bad), {"ok": False, "error": "input"}
            )
        self.assertFalse(os.path.exists(self.path))

    def test_io_when_path_is_a_directory(self) -> None:
        os.mkdir(self.path)
        self.assertEqual(audit_sync_state(self.path), {"ok": False, "error": "io"})


class AuditSyncStateEmptyTests(SyncStateFixture):
    def test_all_absent_is_empty(self) -> None:
        result = audit_sync_state(self.path)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), TOP_KEYS)
        self.assertEqual(result["status"], "empty")
        self.assertEqual(list(result["header"].keys()), HEADER_KEYS)
        self.assertEqual(
            result["header"],
            {"status": "missing", "generation": None, "tip": None,
             "finalized": None},
        )
        self.assertEqual(list(result["state"].keys()), STATE_KEYS)
        self.assertEqual(
            result["state"],
            {"status": "missing", "generation": None, "account": None,
             "anchor": None},
        )
        self.assertEqual(list(result["transaction"].keys()), TXN_KEYS)
        self.assertEqual(
            result["transaction"],
            {"status": "absent", "header_generation": None,
             "state_generation": None},
        )


class AuditSyncStateConsistentTests(SyncStateFixture):
    def test_committed_pair_is_consistent(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "consistent", result)
        self.assertEqual(result["header"]["status"], "valid")
        self.assertEqual(result["header"]["generation"], 1)
        self.assertEqual(
            list(result["header"]["tip"].keys()),
            ["tip_hash", "height", "length", "status"],
        )
        self.assertEqual(result["header"]["tip"]["height"], 3)
        self.assertEqual(
            list(result["header"]["finalized"].keys()), ["height", "block_hash"]
        )
        self.assertEqual(
            result["header"]["finalized"],
            {"height": 3, "block_hash": self.h(3)},
        )
        self.assertEqual(result["state"]["status"], "valid")
        self.assertEqual(result["state"]["generation"], 1)
        self.assertEqual(result["state"]["account"], self.sender)
        self.assertEqual(
            list(result["state"]["anchor"].keys()),
            ["height", "block_hash", "state_root"],
        )
        self.assertEqual(result["state"]["anchor"]["height"], 3)
        self.assertEqual(result["state"]["anchor"]["block_hash"], self.h(3))
        self.assertEqual(result["transaction"]["status"], "absent")

    def test_query_does_not_change_a_byte(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )

        def snapshot() -> dict:
            return {
                target: open(target, "rb").read()
                for target in (self.path, self.state_path(), self.txn_path())
                if os.path.exists(target)
            }

        before = snapshot()
        audit_sync_state(self.path)
        audit_sync_state(self.path)
        self.assertEqual(snapshot(), before)


class AuditSyncStateRecoverableTests(SyncStateFixture):
    def _crash_between_header_and_sidecar(self, bundle: dict) -> None:
        original = light_client._atomic_write_bytes
        counter = {"calls": 0}

        def flaky(target, payload):
            counter["calls"] += 1
            if counter["calls"] == 3:
                raise OSError("injected crash")
            return original(target, payload)

        light_client._atomic_write_bytes = flaky
        try:
            result = advance_sync_state(self.path, bundle)
        finally:
            light_client._atomic_write_bytes = original
        self.assertEqual(result, {"ok": False, "error": "io"})
        self.assertTrue(os.path.exists(self.txn_path()))

    def test_sealed_journal_is_recoverable_and_not_rolled_forward(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        self._crash_between_header_and_sidecar(bundle)

        journal_before = self.read_raw(self.txn_path())
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "recoverable", result)
        self.assertEqual(result["transaction"]["status"], "valid")
        self.assertEqual(result["transaction"]["header_generation"], 2)
        self.assertEqual(result["transaction"]["state_generation"], 2)
        # The audit never rolls the journal forward and never unlinks it.
        self.assertTrue(os.path.exists(self.txn_path()))
        self.assertEqual(self.read_raw(self.txn_path()), journal_before)


class AuditSyncStateSplitTests(SyncStateFixture):
    def test_missing_sidecar_is_split(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        os.unlink(self.state_path())
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "split", result)
        self.assertEqual(result["header"]["status"], "valid")
        self.assertEqual(result["state"]["status"], "missing")
        self.assertIsNone(result["state"]["generation"])
        self.assertEqual(result["transaction"]["status"], "absent")

    def test_missing_header_next_to_sidecar_is_split(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        os.unlink(self.path)
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "split", result)
        self.assertEqual(result["header"]["status"], "missing")
        self.assertEqual(result["state"]["status"], "valid")
        self.assertEqual(result["state"]["anchor"]["height"], 3)

    def test_valid_targets_with_mismatched_binding_are_split(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        # A standalone-valid sidecar produced by a different chain: its
        # proof still reverifies, but the anchor hash is not this header's
        # finalized boundary.
        other = SyncStateFixture()
        other.setUp()
        try:
            self.assertTrue(
                advance_sync_state(other.path, other.first_bundle())["ok"]
            )
            foreign = other.read_raw(other.state_path())
            with open(self.state_path(), "wb") as fh:
                fh.write(foreign)
        finally:
            other.tearDown()
        result = audit_sync_state(self.path)
        self.assertEqual(result["header"]["status"], "valid", result)
        self.assertEqual(result["state"]["status"], "valid", result)
        self.assertEqual(result["status"], "split", result)
        self.assertNotEqual(
            result["state"]["anchor"]["block_hash"],
            result["header"]["finalized"]["block_hash"],
        )


class AuditSyncStateCorruptTests(SyncStateFixture):
    def test_corrupt_header_is_corrupt(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("garbage")
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "corrupt", result)
        self.assertEqual(result["header"]["status"], "invalid")
        self.assertIsNone(result["header"]["generation"])
        self.assertIsNone(result["header"]["tip"])
        self.assertEqual(result["state"]["status"], "valid")
        self.assertEqual(result["transaction"]["status"], "absent")

    def test_corrupt_sidecar_is_corrupt(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.state_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "corrupt", result)
        self.assertEqual(result["state"]["status"], "invalid")
        self.assertIsNone(result["state"]["generation"])
        self.assertIsNone(result["state"]["anchor"])
        self.assertEqual(result["header"]["status"], "valid")

    def test_corrupt_journal_is_corrupt(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.txn_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "corrupt", result)
        self.assertEqual(result["transaction"]["status"], "invalid")
        self.assertIsNone(result["transaction"]["header_generation"])
        self.assertIsNone(result["transaction"]["state_generation"])
        # The audit never cleans the defective journal up.
        self.assertTrue(os.path.exists(self.txn_path()))

    def test_resealed_tampered_journal_is_corrupt(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        original = light_client._atomic_write_bytes
        counter = {"calls": 0}

        def flaky(target, payload):
            counter["calls"] += 1
            if counter["calls"] == 3:
                raise OSError("injected crash")
            return original(target, payload)

        light_client._atomic_write_bytes = flaky
        try:
            self.assertEqual(
                advance_sync_state(self.path, bundle),
                {"ok": False, "error": "io"},
            )
        finally:
            light_client._atomic_write_bytes = original

        journal = self.read_json(self.txn_path())
        journal["state"]["generation"] = 99
        body = {key: journal[key] for key in ("v", "header", "state")}
        journal["hash"] = light_client.hashlib.sha256(
            light_client._canonical_json_bytes(body)
        ).hexdigest()
        with open(self.txn_path(), "w", encoding="utf-8") as fh:
            json.dump(journal, fh)
        result = audit_sync_state(self.path)
        self.assertEqual(result["status"], "corrupt", result)
        self.assertEqual(result["transaction"]["status"], "invalid")


if __name__ == "__main__":
    unittest.main(verbosity=2)
