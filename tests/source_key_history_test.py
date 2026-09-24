"""Tests for the persistent per-source public-key history (source_key_history).

Covers:

* registration writes the version 1 history item
  ``{version: 1, public_key, activated_event_id}`` whose activation event is
  the ``source_registered`` audit event; rotation increments the version and
  appends the new key activated by the ``source_rotated`` event; revocation
  retains the full history; every write is atomic with the registry and its
  event;
* GET /v1/trust serializes the document in the fixed key order
  ``genesis_hash, sources, allowlist, audit_signers, source_key_history``;
  the mapping is ascending by source and each item is the ascending array of
  ``{version, public_key, activated_event_id}``;
* the section is persisted in the same atomic snapshot and survives restart
  byte-for-byte; a legacy snapshot without the section reconstructs the
  history from the registry and audit log in memory on recovery without a
  forced write (generation stable) and persists it on the next ordinary save;
* restart raises StateRecoveryError(path, reason) when the history structure
  or the history/registry/event agreement is wrong;
* ledger.light_client.verify_range_export authenticates an attested export by
  attestation version against trust.source_key_history: an unknown source or
  version and a mismatched key are ``auth``, a failing signature is
  ``integrity``; documents verified under a since-rotated/revoked key remain
  valid; a trust document without the mapping keeps the legacy rules;
  malformed history shapes are ``input``;

Run: python3 tests/source_key_history_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import audit as audit_mod
from ledger import crypto
from ledger.light_client import verify_range_export
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError, attested_range_message

FUTURE = 1_900_000_000
NOW = 1_000_000_000

TRUST_KEY_ORDER = [
    "genesis_hash",
    "sources",
    "allowlist",
    "audit_signers",
    "source_key_history",
]
HISTORY_ITEM_KEYS = ["version", "public_key", "activated_event_id"]
RESULT_KEY_ORDER = [
    "ok",
    "source",
    "request_id",
    "mode",
    "anchor",
    "tip",
    "verified_tx_ids",
]


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


class SourceKeyHistoryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.k1, self.pk1 = keypair()
        self.k2, self.pk2 = keypair()
        self.k3, self.pk3 = keypair()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def register(self, source="node-1", public_key=None) -> tuple[int, dict]:
        return self.svc.register_trust_source(
            {
                "source": source,
                "public_key": self.pk1 if public_key is None else public_key,
                "expires_at": FUTURE,
            }
        )

    def rotate(self, source="node-1", public_key=None, expected=1) -> tuple[int, dict]:
        return self.svc.rotate_trust_source(
            source,
            {
                "public_key": public_key,
                "expires_at": FUTURE,
                "expected_version": expected,
            },
        )

    def test_registration_writes_version_1_item_at_registered_event(self) -> None:
        status, body = self.register()
        self.assertEqual(status, 201, body)
        history = self.store.source_key_history["node-1"]
        self.assertEqual(len(history), 1)
        self.assertEqual(
            history[0],
            {
                "version": 1,
                "public_key": self.pk1,
                "activated_event_id": 1,
            },
        )
        event = self.store.audit_events[0]
        self.assertEqual(event["kind"], "source_registered")
        self.assertEqual(event["event_id"], history[0]["activated_event_id"])
        # Persisted in the same atomic snapshot as the registry and event.
        on_disk = read_json(self.path)["source_key_history"]
        self.assertEqual(
            on_disk,
            [
                {
                    "source": "node-1",
                    "keys": [
                        {
                            "version": 1,
                            "public_key": self.pk1,
                            "activated_event_id": 1,
                        }
                    ],
                }
            ],
        )

    def test_idempotent_repost_does_not_append_history(self) -> None:
        self.register()
        status, _ = self.register()
        self.assertEqual(status, 200)
        self.assertEqual(len(self.store.source_key_history["node-1"]), 1)
        self.assertEqual(
            [e["kind"] for e in self.store.audit_events],
            ["source_registered"],
        )

    def test_rotation_appends_new_key_at_rotation_event(self) -> None:
        self.register()
        status, body = self.rotate(public_key=self.pk2, expected=1)
        self.assertEqual(status, 200, body)
        history = self.store.source_key_history["node-1"]
        self.assertEqual([entry["version"] for entry in history], [1, 2])
        self.assertEqual(
            [entry["public_key"] for entry in history], [self.pk1, self.pk2]
        )
        events = {e["kind"]: e for e in self.store.audit_events}
        self.assertEqual(
            history[0]["activated_event_id"],
            events["source_registered"]["event_id"],
        )
        self.assertEqual(
            history[1]["activated_event_id"],
            events["source_rotated"]["event_id"],
        )
        self.assertGreater(
            history[1]["activated_event_id"],
            history[0]["activated_event_id"],
        )

        status, _ = self.rotate(public_key=self.pk3, expected=2)
        self.assertEqual(status, 200)
        history = self.store.source_key_history["node-1"]
        self.assertEqual([entry["version"] for entry in history], [1, 2, 3])
        self.assertEqual(history[-1]["public_key"], self.pk3)

    def test_revoke_retains_history(self) -> None:
        self.register()
        self.rotate(public_key=self.pk2, expected=1)
        status, _ = self.svc.revoke_trust_source("node-1", {"expected_version": 2})
        self.assertEqual(status, 200)
        history = self.store.source_key_history["node-1"]
        self.assertEqual([entry["version"] for entry in history], [1, 2])
        self.assertEqual(
            [entry["public_key"] for entry in history], [self.pk1, self.pk2]
        )
        # Restart keeps the full history too.
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(
            reopened.source_key_history["node-1"],
            self.store.source_key_history["node-1"],
        )

    def test_history_survives_restart_byte_for_byte(self) -> None:
        self.register("a", self.pk1)
        self.rotate("a", self.pk2, expected=1)
        self.register("b", self.pk3)
        expected = {
            source: [dict(entry) for entry in history]
            for source, history in self.store.source_key_history.items()
        }
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(reopened.source_key_history, expected)
        # Mapping is ascending by source in the public document.
        status, doc = LedgerService(reopened, initial_balance=1000).get_trust_document()
        self.assertEqual(status, 200)
        self.assertEqual(list(doc["source_key_history"]), ["a", "b"])
        self.assertEqual(
            [entry["version"] for entry in doc["source_key_history"]["a"]],
            [1, 2],
        )

    def test_trust_document_fixed_key_order_and_item_shape(self) -> None:
        self.register()
        self.rotate(public_key=self.pk2, expected=1)
        status, doc = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        self.assertEqual(list(doc.keys()), TRUST_KEY_ORDER)
        items = doc["source_key_history"]["node-1"]
        self.assertEqual([entry["version"] for entry in items], [1, 2])
        for entry in items:
            self.assertEqual(list(entry.keys()), HISTORY_ITEM_KEYS)
            self.assertIsInstance(entry["version"], int)
            self.assertNotIsInstance(entry["version"], bool)
            self.assertIsInstance(entry["activated_event_id"], int)
            self.assertTrue(crypto.is_hex64(entry["public_key"]))


class SourceKeyHistoryRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.k1, self.pk1 = keypair()
        self.k2, self.pk2 = keypair()
        self.assertEqual(
            svc.register_trust_source(
                {"source": "node-1", "public_key": self.pk1, "expires_at": FUTURE}
            )[0],
            201,
        )
        self.assertEqual(
            svc.rotate_trust_source(
                "node-1",
                {
                    "public_key": self.pk2,
                    "expires_at": FUTURE,
                    "expected_version": 1,
                },
            )[0],
            200,
        )
        self.generation = read_json(self.path)["state"]["generation"]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _reopen_mutated(self, mutate) -> None:
        data = read_json(self.path)
        mutate(data)
        out_dir = tempfile.mkdtemp()
        path = os.path.join(out_dir, "state.json")
        write_json(path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(path, initial_balance=1000)
        self.assertTrue(ctx.exception.path)
        self.assertTrue(ctx.exception.reason)
        shutil.rmtree(out_dir, ignore_errors=True)

    def test_legacy_snapshot_without_section_reconstructs_without_write(self) -> None:
        data = read_json(self.path)
        del data["source_key_history"]
        legacy = os.path.join(self.tmp, "legacy.json")
        write_json(legacy, data)
        reopened = LedgerStore(legacy, initial_balance=1000)
        history = reopened.source_key_history["node-1"]
        self.assertEqual([entry["version"] for entry in history], [1, 2])
        self.assertEqual(
            [entry["public_key"] for entry in history], [self.pk1, self.pk2]
        )
        # No migration write is forced on restart: the recovered generation is
        # unchanged and the on-disk snapshot still lacks the section.
        self.assertEqual(reopened.generation, self.generation)
        self.assertNotIn("source_key_history", read_json(legacy))
        # The next ordinary mutating save persists the reconstructed history.
        reopened.save()
        self.assertIn("source_key_history", read_json(legacy))
        self.assertEqual(read_json(legacy)["state"]["generation"], self.generation + 1)

    def test_tampered_history_public_key_fails_recovery(self) -> None:
        self._reopen_mutated(
            lambda d: d["source_key_history"][0]["keys"][0].__setitem__(
                "public_key", "c" * 64
            )
        )

    def test_tampered_history_activation_event_fails_recovery(self) -> None:
        self._reopen_mutated(
            lambda d: d["source_key_history"][0]["keys"][1].__setitem__(
                "activated_event_id", 99
            )
        )

    def test_non_dense_versions_fail_recovery(self) -> None:
        def mutate(data) -> None:
            data["source_key_history"][0]["keys"][1]["version"] = 3

        self._reopen_mutated(mutate)

    def test_missing_registry_source_in_history_fails_recovery(self) -> None:
        self._reopen_mutated(lambda d: d.__setitem__("source_key_history", []))

    def test_malformed_history_item_fails_recovery(self) -> None:
        def mutate(data) -> None:
            data["source_key_history"][0]["keys"][0] = {
                "version": 1,
                "public_key": self.pk1,
                # activated_event_id missing
            }

        self._reopen_mutated(mutate)

    def test_history_event_mismatch_fails_recovery(self) -> None:
        # Tamper the registered audit event's public key, relink the chain
        # and re-pin the checkpoint: the history reconstruction must detect
        # the registry/event disagreement and refuse recovery.
        def mutate(data) -> None:
            for event in data["audit_events"]:
                if event["kind"] == "source_registered":
                    event["public_key"] = "d" * 64
            data["audit_events"] = audit_mod.link_events(data["audit_events"])
            data["audit_checkpoint"] = audit_mod.make_checkpoint(
                data["audit_events"]
            )

        self._reopen_mutated(mutate)

    def test_history_version_gap_from_events_fails_recovery(self) -> None:
        # Rewrite the rotate event to jump straight to version 3: the
        # reconstructed history is non-dense and fails recovery.
        def mutate(data) -> None:
            for event in data["audit_events"]:
                if event["kind"] == "source_rotated":
                    event["version"] = 3
            data["audit_events"] = audit_mod.link_events(data["audit_events"])
            data["audit_checkpoint"] = audit_mod.make_checkpoint(
                data["audit_events"]
            )

        self._reopen_mutated(mutate)


class SourceKeyHistoryHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "http.json")), initial_balance=1000
        )
        self.k1, self.pk1 = keypair()
        self.k2, self.pk2 = keypair()
        self.svc.register_trust_source(
            {"source": "node-1", "public_key": self.pk1, "expires_at": FUTURE}
        )
        self.svc.rotate_trust_source(
            "node-1",
            {
                "public_key": self.pk2,
                "expires_at": FUTURE,
                "expected_version": 1,
            },
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        import threading

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_wire_key_order(self) -> None:
        with urllib.request.urlopen(f"{self.base}/v1/trust") as resp:
            raw = resp.read().decode("utf-8")
        self.assertEqual(resp.status, 200)
        # The wire document uses the contract-fixed order, not alphabetical
        # (alphabetical would put allowlist first).
        body = json.loads(raw)
        self.assertEqual(list(body.keys()), TRUST_KEY_ORDER)
        self.assertEqual(
            [entry["version"] for entry in body["source_key_history"]["node-1"]],
            [1, 2],
        )


class RangeExportHistoryVerifyTests(unittest.TestCase):
    """verify_range_export attested authentication via source_key_history."""

    def setUp(self) -> None:
        self.k1, self.pk1 = keypair()
        self.k2, self.pk2 = keypair()
        self.ka, self.alice = keypair()
        self.bob = "b" * 64
        genesis = LedgerStore.create_genesis()
        self.anchor = {"height": 0, "block_hash": genesis.block_hash}
        message = crypto.canonical_message(self.alice, self.bob, 100)
        tx = Transaction(self.alice, self.bob, 100, self.ka.sign(message).hex())
        self.block = Block.create(1, genesis.block_hash, [tx])
        self.tip = {
            "tip_hash": self.block.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
        }
        self.source = "node-att"
        self.history = {
            self.source: [
                {"version": 1, "public_key": self.pk1, "activated_event_id": 5},
                {"version": 2, "public_key": self.pk2, "activated_event_id": 9},
            ]
        }
        self.trust = {
            "sources": {},
            "allowlist": {},
            "source_key_history": self.history,
        }

    def _document(self, version: int, key: Ed25519PrivateKey) -> dict:
        blocks = [self.block.to_dict()]
        message = attested_range_message(
            self.source, "req-1", FUTURE, self.anchor, blocks, self.tip
        )
        signature = key.sign(hashlib.sha256(message).digest()).hex()
        return {
            "source": self.source,
            "request_id": "req-1",
            "mode": "attested",
            "expires_at": FUTURE,
            "anchor": dict(self.anchor),
            "blocks": blocks,
            "tip": dict(self.tip),
            "attestation": {
                "public_key": key.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ).hex(),
                "version": version,
                "signature": signature,
            },
        }

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})

    def test_old_version_verifies_after_rotation_and_revocation(self) -> None:
        # Version 1 signed the export; the trust document only carries the
        # history mapping (the source is absent from current sources, i.e.
        # rotated away / revoked), yet the old attestation still verifies.
        doc = self._document(1, self.k1)
        result = verify_range_export(doc, self.anchor, self.trust, now=NOW)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), RESULT_KEY_ORDER)
        self.assertEqual(result["mode"], "attested")
        self.assertEqual(result["tip"], self.tip)
        self.assertEqual(
            result["verified_tx_ids"], [self.block.transactions[0].tx_id]
        )

    def test_current_version_verifies_via_history(self) -> None:
        doc = self._document(2, self.k2)
        result = verify_range_export(doc, self.anchor, self.trust, now=NOW)
        self.assertTrue(result["ok"], result)

    def test_unknown_version_is_auth(self) -> None:
        doc = self._document(1, self.k1)
        doc["attestation"]["version"] = 3
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW), "auth"
        )
        doc["attestation"]["version"] = 0  # structurally rejected as input
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW), "input"
        )

    def test_attestation_public_key_must_match_historical_key(self) -> None:
        doc = self._document(1, self.k1)
        doc["attestation"]["public_key"] = self.pk2
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW), "auth"
        )

    def test_unknown_source_is_auth(self) -> None:
        doc = self._document(1, self.k1)
        doc["source"] = "ghost"
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW), "auth"
        )

    def test_bad_signature_is_integrity(self) -> None:
        doc = self._document(1, self.k1)
        doc["attestation"]["signature"] = "ab" * 64
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW),
            "integrity",
        )

    def test_signature_under_wrong_historical_key_is_integrity(self) -> None:
        # version 1 claims pk1 but the signature was made with the v2 key.
        blocks = [self.block.to_dict()]
        message = attested_range_message(
            self.source, "req-1", FUTURE, self.anchor, blocks, self.tip
        )
        doc = self._document(1, self.k1)
        doc["attestation"]["signature"] = self.k2.sign(
            hashlib.sha256(message).digest()
        ).hex()
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW),
            "integrity",
        )

    def test_document_deadline_still_expired_with_history(self) -> None:
        doc = self._document(1, self.k1)
        doc["expires_at"] = NOW
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW), "expired"
        )

    def test_anchor_chain_integrity_still_checked(self) -> None:
        doc = self._document(1, self.k1)
        doc["blocks"][0]["block_hash"] = "0" * 64
        self.assert_error(
            verify_range_export(doc, self.anchor, self.trust, now=NOW),
            "integrity",
        )

    def test_legacy_trust_without_history_keeps_old_rules(self) -> None:
        # No source_key_history mapping: a missing sources entry is auth.
        doc = self._document(1, self.k1)
        legacy = {"sources": {}, "allowlist": {}}
        self.assert_error(
            verify_range_export(doc, self.anchor, legacy, now=NOW), "auth"
        )
        # A matching current sources entry authenticates under the pinned key.
        legacy = {
            "sources": {self.source: {"public_key": self.pk1, "expires_at": FUTURE}},
            "allowlist": {},
        }
        result = verify_range_export(doc, self.anchor, legacy, now=NOW)
        self.assertTrue(result["ok"], result)
        # A pinned current key that differs from the attestation key is auth.
        legacy = {
            "sources": {self.source: {"public_key": self.pk2, "expires_at": FUTURE}},
            "allowlist": {},
        }
        self.assert_error(
            verify_range_export(doc, self.anchor, legacy, now=NOW), "auth"
        )
        # The legacy sources entry's own deadline still applies.
        legacy = {
            "sources": {
                self.source: {"public_key": self.pk1, "expires_at": NOW}
            },
            "allowlist": {},
        }
        self.assert_error(
            verify_range_export(doc, self.anchor, legacy, now=NOW), "expired"
        )

    def test_malformed_history_is_input(self) -> None:
        doc = self._document(1, self.k1)
        bad_trusts = [
            {"sources": {}, "allowlist": {}, "source_key_history": []},
            {
                "sources": {},
                "allowlist": {},
                "source_key_history": {self.source: []},
            },
            {
                "sources": {},
                "allowlist": {},
                "source_key_history": {
                    self.source: [
                        {"version": 2, "public_key": self.pk1, "activated_event_id": 1}
                    ]
                },
            },
            {
                "sources": {},
                "allowlist": {},
                "source_key_history": {
                    self.source: [
                        {"version": 1, "public_key": "zz", "activated_event_id": 1}
                    ]
                },
            },
            {
                "sources": {},
                "allowlist": {},
                "source_key_history": {
                    self.source: [
                        # activated_event_id 0 is not a positive integer
                        {"version": 1, "public_key": self.pk1, "activated_event_id": 0}
                    ]
                },
            },
            {
                "sources": {},
                "allowlist": {},
                "source_key_history": {
                    self.source: [
                        # bool version rejected
                        {"version": True, "public_key": self.pk1, "activated_event_id": 1}
                    ]
                },
            },
            {
                "sources": {},
                "allowlist": {},
                "source_key_history": {
                    "": [
                        {"version": 1, "public_key": self.pk1, "activated_event_id": 1}
                    ]
                },
            },
            {
                "sources": {},
                "allowlist": {},
                "source_key_history": {
                    self.source: [
                        {
                            "version": 1,
                            "public_key": self.pk1,
                            "activated_event_id": 1,
                            "extra": 1,
                        }
                    ]
                },
            },
        ]
        for trust in bad_trusts:
            with self.subTest(trust=trust):
                self.assert_error(
                    verify_range_export(doc, self.anchor, trust, now=NOW),
                    "input",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
