"""Tests for offline whole-snapshot consistency verification.

Covers ``ledger.consistency.verify_snapshot`` and the
``python -m ledger.cli consistency FILE|-`` command:

* a snapshot written by the node always verifies, including one with a
  pending tip block, a non-empty mempool, audit events and every extension
  section;
* the success document always has the fixed key order
  ``ok,error,generation,height,tip_hash,state_root,audit_checkpoint`` and a
  failure document pins every summary field to null;
* missing/wrong-type required sections, unknown top-level keys and disguised
  integer/string field types are ``input``;
* every recomputed artifact mismatch — tx_id, Ed25519 signature, tx ordering,
  Merkle root, block hash, prev_hash linkage, height, genesis and
  pending-only-at-tip rules, mempool uniqueness/disjointness, the derived
  index/accounts and ``state_root`` — is ``integrity``;
* a present ``audit_events`` list must hash-chain and pin the checkpoint; an
  absent list still requires the empty-log ``{0, "0"*64}`` checkpoint;
* CLI exit codes are 1 for unreadable/non-JSON input and for integrity
  failures, 0 for a verified snapshot.

Run: python3 tests/consistency_verify_test.py
"""
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

from ledger import audit, crypto
from ledger.consistency import verify_snapshot
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

FUTURE = 1_900_000_000
RESULT_KEYS = (
    "ok",
    "error",
    "generation",
    "height",
    "tip_hash",
    "state_root",
    "audit_checkpoint",
)


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


class SnapshotFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def _confirm_tx(self, amount: int = 10) -> None:
        self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, amount))
        block = self.svc.mine_block()[1]
        self.svc.confirm_block(block["height"])

    def load_snapshot(self) -> dict:
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def write_snapshot(self, doc: dict) -> str:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return self.path


class VerifySuccessTests(SnapshotFixture):
    def test_genesis_only_snapshot_verifies(self) -> None:
        doc = self.load_snapshot()
        result = verify_snapshot(doc)
        self.assertTrue(result["ok"], result)
        self.assertIsNone(result["error"])
        self.assertEqual(result["generation"], self.store.generation)
        self.assertEqual(result["height"], 0)
        self.assertEqual(result["tip_hash"], self.store.tip_hash())
        self.assertEqual(
            result["audit_checkpoint"],
            {"event_id": 0, "event_hash": "0" * 64},
        )
        self.assertTrue(crypto.is_hex64(result["state_root"]))

    def test_confirmed_blocks_pending_and_audit_verify(self) -> None:
        self._confirm_tx(10)
        # A mempool entry and an audit event (trust registration) exercise
        # the pending uniqueness and audit-chain branches.
        self.svc.submit_transaction(signed_tx(self.kb, self.B, self.A, 3))
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "node-1", "public_key": "ab" * 32, "expires_at": FUTURE}
            )[0],
            201,
        )
        doc = self.load_snapshot()
        result = verify_snapshot(doc)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["tip_hash"], self.store.tip_hash())
        self.assertEqual(
            result["state_root"], self.store.state_root_for(self.store.chain, 1000)[0]
        )
        self.assertEqual(result["audit_checkpoint"], self.store.audit_checkpoint)
        self.assertEqual(result["audit_checkpoint"]["event_id"], 1)

    def test_pending_tip_snapshot_verifies(self) -> None:
        self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, 5))
        self.svc.mine_block()  # pending tip, never confirmed
        self.assertTrue(self.store.tip_is_pending())
        doc = self.load_snapshot()
        result = verify_snapshot(doc)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["height"], 1)
        self.assertEqual(result["tip_hash"], self.store.tip_hash())

    def test_extension_sections_are_accepted(self) -> None:
        self._confirm_tx(1)
        doc = self.load_snapshot()
        doc.update(
            {
                "forks": [],
                "syncs": [],
                "attested_syncs": [],
                "trust_sources": [],
                "allowlist": {},
            }
        )
        self.assertTrue(verify_snapshot(doc)["ok"])

    def test_result_key_order_is_fixed(self) -> None:
        result = verify_snapshot(self.load_snapshot())
        self.assertEqual(tuple(result.keys()), RESULT_KEYS)
        failure = verify_snapshot({"nope": 1})
        self.assertEqual(tuple(failure.keys()), RESULT_KEYS)

    def test_recorded_endowment_governs_state_root(self) -> None:
        self._confirm_tx(10)
        doc = self.load_snapshot()
        # The recorded endowment (1000) is what the recomputation uses, so the
        # document must verify without any ambient initial-balance parameter.
        self.assertEqual(doc["state"]["initial_balance"], 1000)
        self.assertTrue(verify_snapshot(doc)["ok"])


class InputErrorTests(SnapshotFixture):
    def assert_input(self, mutate) -> None:
        doc = self.load_snapshot()
        mutate(doc)
        result = verify_snapshot(doc)
        self.assertEqual(result, _failure_shape("input"), result)

    def test_non_object_documents(self) -> None:
        for bad in (None, [], "x", 3, 3.5, True):
            self.assertEqual(verify_snapshot(bad)["error"], "input")

    def test_missing_required_sections(self) -> None:
        for section in (
            "state",
            "chain",
            "pending",
            "index",
            "accounts",
            "audit_checkpoint",
        ):
            self.assert_input(lambda d, s=section: d.pop(s))

    def test_unknown_top_level_key(self) -> None:
        self.assert_input(lambda d: d.__setitem__("unexpected", 1))

    def test_core_section_wrong_types(self) -> None:
        self.assert_input(lambda d: d.__setitem__("state", []))
        self.assert_input(lambda d: d.__setitem__("chain", {}))
        self.assert_input(lambda d: d.__setitem__("chain", []))
        self.assert_input(lambda d: d.__setitem__("pending", {}))
        self.assert_input(lambda d: d.__setitem__("index", []))
        self.assert_input(lambda d: d.__setitem__("accounts", []))
        self.assert_input(lambda d: d.__setitem__("audit_checkpoint", []))

    def test_generation_wrong_types(self) -> None:
        self.assert_input(lambda d: d["state"].__setitem__("generation", "1"))
        self.assert_input(lambda d: d["state"].__setitem__("generation", -1))
        self.assert_input(lambda d: d["state"].__setitem__("generation", True))
        self.assert_input(lambda d: d["state"].__setitem__("generation", 1.0))

    def test_initial_balance_wrong_types(self) -> None:
        self.assert_input(lambda d: d["state"].__setitem__("initial_balance", "1000"))
        self.assert_input(lambda d: d["state"].__setitem__("initial_balance", 0))
        self.assert_input(lambda d: d["state"].__setitem__("initial_balance", True))

    def test_disguised_block_and_tx_field_types(self) -> None:
        self._confirm_tx(10)
        self.assert_input(lambda d: d["chain"][1].__setitem__("height", "1"))
        self.assert_input(lambda d: d["chain"][1].__setitem__("height", True))
        self.assert_input(lambda d: d["chain"][1]["transactions"][0].__setitem__("amount", "10"))
        self.assert_input(lambda d: d["chain"][1]["transactions"][0].__setitem__("amount", 10.0))
        self.assert_input(lambda d: d["chain"][1]["transactions"][0].__setitem__("amount", True))
        self.assert_input(lambda d: d["chain"][1].__setitem__("transactions", {}))

    def test_missing_block_and_tx_fields(self) -> None:
        self._confirm_tx(10)
        for field in ("height", "prev_hash", "merkle_root", "block_hash", "transactions"):
            self.assert_input(lambda d, f=field: d["chain"][1].pop(f))
        for field in ("from", "to", "amount", "signature", "tx_id"):
            self.assert_input(
                lambda d, f=field: d["chain"][1]["transactions"][0].pop(f)
            )

    def test_audit_section_types(self) -> None:
        self.assert_input(lambda d: d.__setitem__("audit_events", {}))
        self.assert_input(lambda d: d.__setitem__("audit_events", [1]))
        self.assert_input(lambda d: d["audit_checkpoint"].__setitem__("event_id", "0"))
        self.assert_input(
            lambda d: d["audit_checkpoint"].__setitem__("event_hash", 0)
        )
        self.assert_input(lambda d: d["audit_checkpoint"].pop("event_hash"))
        self.assert_input(
            lambda d: d["audit_checkpoint"].__setitem__("extra", 1)
        )

    def test_index_and_account_value_types(self) -> None:
        self._confirm_tx(10)
        self.assert_input(lambda d: d["index"].__setitem__("ab", "1"))
        self.assert_input(lambda d: d["index"].__setitem__("ab", True))
        account = list(d for d in self.load_snapshot()["accounts"])[0]
        self.assert_input(
            lambda d, a=account: d["accounts"][a].__setitem__("sent", "10")
        )
        self.assert_input(
            lambda d, a=account: d["accounts"][a].__setitem__("transactions", {})
        )
        self.assert_input(
            lambda d, a=account: d["accounts"][a]["transactions"].__setitem__(0, 9)
        )
        self.assert_input(lambda d: d.__setitem__("accounts", {1: d["accounts"][account]}))


class IntegrityErrorTests(SnapshotFixture):
    def setUp(self) -> None:
        super().setUp()
        self._confirm_tx(10)
        self.svc.submit_transaction(signed_tx(self.kb, self.B, self.A, 3))
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "node-1", "public_key": "ab" * 32, "expires_at": FUTURE}
            )[0],
            201,
        )

    def assert_integrity(self, mutate) -> None:
        doc = self.load_snapshot()
        mutate(doc)
        result = verify_snapshot(doc)
        self.assertEqual(result, _failure_shape("integrity"), result)

    def test_block_hash_and_linkage_tampering(self) -> None:
        self.assert_integrity(lambda d: d["chain"][1].__setitem__("block_hash", "0" * 64))
        self.assert_integrity(lambda d: d["chain"][1].__setitem__("merkle_root", "0" * 64))
        self.assert_integrity(lambda d: d["chain"][1].__setitem__("prev_hash", "0" * 64))
        self.assert_integrity(lambda d: d["chain"][1].__setitem__("height", 9))
        self.assert_integrity(lambda d: d["chain"][0].__setitem__("block_hash", "9" * 64))

    def test_genesis_and_pending_status_rules(self) -> None:
        self.assert_integrity(lambda d: d["chain"][0].__setitem__("status", "pending"))
        self.assert_integrity(lambda d: d["chain"][1].__setitem__("status", "bogus"))

    def test_transaction_tampering(self) -> None:
        self.assert_integrity(
            lambda d: d["chain"][1]["transactions"][0].__setitem__("tx_id", "0" * 64)
        )
        # A changed amount changes the canonical message, so both the stored
        # tx_id and signature fail to recompute.
        self.assert_integrity(
            lambda d: d["chain"][1]["transactions"][0].__setitem__("amount", 11)
        )
        self.assert_integrity(
            lambda d: d["chain"][1]["transactions"][0].__setitem__("signature", "ab" * 64)
        )

    def test_mempool_uniqueness_and_disjointness(self) -> None:
        self.assert_integrity(lambda d: d["pending"].append(d["pending"][0]))
        self.assert_integrity(
            lambda d: d["pending"].append(d["chain"][1]["transactions"][0])
        )

    def test_derived_index_tampering(self) -> None:
        self.assert_integrity(lambda d: d["index"].popitem())
        self.assert_integrity(lambda d: d["index"].__setitem__("f" * 64, 1))

    def test_derived_accounts_tampering(self) -> None:
        account = next(iter(self.load_snapshot()["accounts"]))
        self.assert_integrity(lambda d: d["accounts"].popitem())
        self.assert_integrity(
            lambda d, a=account: d["accounts"][a].__setitem__("sent", 999)
        )
        self.assert_integrity(
            lambda d, a=account: d["accounts"][a]["transactions"].pop()
        )

    def test_state_summary_and_state_root_tampering(self) -> None:
        self.assert_integrity(lambda d: d["state"].__setitem__("state_root", "0" * 64))
        self.assert_integrity(lambda d: d["state"].__setitem__("height", 99))
        self.assert_integrity(lambda d: d["state"].__setitem__("tip_hash", "0" * 64))
        self.assert_integrity(lambda d: d["state"].__setitem__("tip_status", "pending"))
        # A malformed hex digest stored as state_root is corruption, not a
        # shape error.
        self.assert_integrity(lambda d: d["state"].__setitem__("state_root", "zz"))

    def test_audit_chain_tampering(self) -> None:
        self.assert_integrity(lambda d: d["audit_events"][0].__setitem__("event_id", 2))
        self.assert_integrity(lambda d: d["audit_events"][0].__setitem__("prev_hash", "1" * 64))
        self.assert_integrity(lambda d: d["audit_events"][0].__setitem__("event_hash", "0" * 64))
        # Any payload change must invalidate the recomputed event_hash.
        self.assert_integrity(lambda d: d["audit_events"][0].__setitem__("kind", "tampered"))

    def test_checkpoint_tampering(self) -> None:
        self.assert_integrity(lambda d: d["audit_checkpoint"].__setitem__("event_id", 7))
        self.assert_integrity(
            lambda d: d["audit_checkpoint"].__setitem__("event_hash", "1" * 64)
        )

    def test_empty_log_requires_zero_checkpoint(self) -> None:
        def mutate(doc: dict) -> None:
            doc.pop("audit_events", None)
            doc["audit_checkpoint"] = {"event_id": 0, "event_hash": "1" * 64}

        self.assert_integrity(mutate)

    def test_replaced_event_list_must_rechain(self) -> None:
        def mutate(doc: dict) -> None:
            doc["audit_events"] = audit.link_events([{"kind": "x", "at": 1.0}])
            # Checkpoint still pins the original head.

        self.assert_integrity(mutate)


class TrustKeyOrderTests(SnapshotFixture):
    """Out-of-order trust extension arrays are shape (input) errors."""

    def _trust_snapshot(self) -> dict:
        # Register two sources so the stored arrays have two ascending items.
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "node-a", "public_key": "a" * 64, "expires_at": FUTURE}
            )[0],
            201,
        )
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "node-b", "public_key": "b" * 64, "expires_at": FUTURE}
            )[0],
            201,
        )
        return self.load_snapshot()

    def test_unsorted_trust_sources_item_is_input(self) -> None:
        doc = self._trust_snapshot()
        doc["trust_sources"] = list(reversed(doc["trust_sources"]))
        self.assertEqual(
            verify_snapshot(doc), _failure_shape("input"), doc
        )

    def test_duplicate_trust_sources_item_is_input(self) -> None:
        doc = self._trust_snapshot()
        doc["trust_sources"] = [
            dict(doc["trust_sources"][0]),
            dict(doc["trust_sources"][0]),
        ]
        self.assertEqual(verify_snapshot(doc), _failure_shape("input"))

    def test_unsorted_source_key_history_item_is_input(self) -> None:
        doc = self._trust_snapshot()
        doc["source_key_history"] = list(reversed(doc["source_key_history"]))
        self.assertEqual(verify_snapshot(doc), _failure_shape("input"))

    def test_non_dense_keys_versions_are_input(self) -> None:
        doc = self._trust_snapshot()
        # Rotate node-a so its keys list has two versions, then make the
        # versions non-dense (out of order) without changing any value type.
        self.svc.rotate_trust_source(
            "node-a",
            {"public_key": "c" * 64, "expires_at": FUTURE, "expected_version": 1},
        )
        doc = self.load_snapshot()
        for item in doc["source_key_history"]:
            if item["source"] == "node-a":
                item["keys"] = list(reversed(item["keys"]))
                # Reversed versions/activations are out of order; the audit
                # reconciliation would also notice, but ordering is input first.
        self.assertEqual(verify_snapshot(doc)["error"], "input")

    def test_value_corruption_stays_integrity(self) -> None:
        # An invalid public key (a value defect) remains integrity, distinct
        # from the key-order/shape defects above.
        doc = self._trust_snapshot()
        doc["trust_sources"][0]["public_key"] = "z" * 64
        self.assertEqual(verify_snapshot(doc), _failure_shape("integrity"))

    def test_recovery_rejects_out_of_order_arrays_with_path_and_reason(self) -> None:
        # The same key-order defects that verify_snapshot reports as input are
        # fatal at startup: recovery raises StateRecoveryError carrying the
        # offending path and a non-empty reason.
        doc = self._trust_snapshot()
        for mutate in (
            lambda d: d.__setitem__(
                "trust_sources", list(reversed(d["trust_sources"]))
            ),
            lambda d: d.__setitem__(
                "source_key_history", list(reversed(d["source_key_history"]))
            ),
        ):
            with self.subTest(mutate=mutate):
                broken = json.loads(json.dumps(doc))
                mutate(broken)
                broken_path = os.path.join(self.tmp, "broken.json")
                with open(broken_path, "w", encoding="utf-8") as fh:
                    json.dump(broken, fh)
                with self.assertRaises(StateRecoveryError) as ctx:
                    LedgerStore(broken_path, initial_balance=1000)
                self.assertEqual(ctx.exception.path, broken_path)
                self.assertTrue(ctx.exception.reason)
                os.unlink(broken_path)


class AuditChainAcceptanceTests(SnapshotFixture):
    def test_externally_rechained_events_and_checkpoint_verify(self) -> None:
        self._confirm_tx(10)
        doc = self.load_snapshot()
        events = audit.link_events(
            [{"kind": "first", "at": 1.0}, {"kind": "second", "at": 2.0}]
        )
        doc["audit_events"] = events
        doc["audit_checkpoint"] = audit.make_checkpoint(events)
        result = verify_snapshot(doc)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["audit_checkpoint"],
            {"event_id": 2, "event_hash": events[-1]["event_hash"]},
        )


class ConsistencyCliTests(SnapshotFixture):
    def run_cli(self, *args: str, stdin: str | None = None) -> tuple[int, dict]:
        proc = subprocess.run(
            [sys.executable, "-m", "ledger.cli", "consistency", *args],
            input=stdin,
            capture_output=True,
            text=True,
        )
        return proc.returncode, json.loads(proc.stdout)

    def test_file_arg_verifies_snapshot(self) -> None:
        self._confirm_tx(10)
        code, body = self.run_cli(self.path)
        self.assertEqual(code, 0)
        self.assertTrue(body["ok"], body)
        self.assertEqual(tuple(body.keys()), RESULT_KEYS)

    def test_stdin_arg_verifies_snapshot(self) -> None:
        code, body = self.run_cli("-", stdin=json.dumps(self.load_snapshot()))
        self.assertEqual(code, 0)
        self.assertTrue(body["ok"])

    def test_missing_file_is_input_exit_1(self) -> None:
        code, body = self.run_cli(os.path.join(self.tmp, "does-not-exist.json"))
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "input"})

    def test_non_json_input_is_input_exit_1(self) -> None:
        code, body = self.run_cli("-", stdin="{not json")
        self.assertEqual(code, 1)
        self.assertEqual(body, {"ok": False, "error": "input"})

    def test_tampered_snapshot_is_integrity_exit_1(self) -> None:
        self._confirm_tx(10)
        doc = self.load_snapshot()
        doc["chain"][1]["block_hash"] = "0" * 64
        code, body = self.run_cli("-", stdin=json.dumps(doc))
        self.assertEqual(code, 1)
        self.assertEqual(body["error"], "integrity")
        self.assertIsNone(body["generation"])
        self.assertIsNone(body["tip_hash"])


def _failure_shape(error: str) -> dict:
    return {
        "ok": False,
        "error": error,
        "generation": None,
        "height": None,
        "tip_hash": None,
        "state_root": None,
        "audit_checkpoint": None,
    }


if __name__ == "__main__":
    unittest.main(verbosity=2)
