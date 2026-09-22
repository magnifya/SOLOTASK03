"""Tests for rotatable Ed25519 checkpoint authentication of the audit chain.

Covers:

* a brand-new node mints its version 1 audit signer; GET /v1/trust lists it
  under ``audit_signers`` as ``{version, public_key, activated_event_id: 0}``;
* GET /v1/audit/export carries ``checkpoint_auth = {key_version, signature}``
  on every page, all pages binding the identical checkpoint/envelope;
* POST /v1/audit/signer/rotate — 400 on malformed private_key/version/missing
  fields, 409 on a stale expected_version, 200 returning {version, public_key},
  appending an audit_signer_rotated event and retaining every old public key;
* offline verify_export(document, trust): genesis anchor, key version,
  signature, activation ordering and cross-page authentication; failures map
  to the new ``auth`` category while chain failures stay input/integrity;
* atomic persistence (failed rotate write rolls key, history and event back),
  restart durability, strict recovery rejection of a tampered signer/history
  and a same-generation signer conflict;
* the one-time migration of an unsigned (pre-feature) snapshot, performed only
  on the unique winner and saved atomically;
* the HTTP surface and the CLI ``audit-signer-rotate`` /
  ``audit-verify --trust`` commands.

Run: python3 tests/audit_signer_test.py
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ledger import audit, crypto
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError, STATE_VERSION

FUTURE = 1_900_000_000
PRIV_A = "11" * 32
PUB_A = crypto.derive_public_key(PRIV_A)
PRIV_B = "22" * 32
PUB_B = crypto.derive_public_key(PRIV_B)


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


def make_service(tmp: str) -> LedgerService:
    return LedgerService(
        LedgerStore(os.path.join(tmp, "state.json"), initial_balance=1000),
        initial_balance=1000,
    )


class SignerBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.store = self.svc.store

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_brand_new_node_has_version_1_signer(self) -> None:
        signer = self.store.audit_signer
        self.assertIsNotNone(signer)
        self.assertEqual(signer["version"], 1)
        self.assertEqual(signer["activated_event_id"], 0)
        self.assertEqual(
            crypto.derive_public_key(signer["private_key"]), signer["public_key"]
        )
        self.assertEqual(
            self.store.audit_signer_history,
            [
                {
                    "version": 1,
                    "public_key": signer["public_key"],
                    "activated_event_id": 0,
                }
            ],
        )

    def test_trust_document_lists_audit_signers(self) -> None:
        status, doc = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        self.assertEqual(doc["genesis_hash"], self.store.chain[0].block_hash)
        self.assertEqual(
            doc["audit_signers"],
            [
                {
                    "version": 1,
                    "public_key": self.store.audit_signer["public_key"],
                    "activated_event_id": 0,
                }
            ],
        )

    def test_empty_log_checkpoint_auth_is_signed_by_version_1(self) -> None:
        status, page = self.svc.export_audit_events({})
        self.assertEqual(status, 200)
        envelope = page["checkpoint_auth"]
        self.assertEqual(envelope["key_version"], 1)
        self.assertTrue(crypto.is_hex128(envelope["signature"]))
        self.assertTrue(
            audit.verify_checkpoint_auth(
                self.store.audit_signer["public_key"],
                self.store.chain[0].block_hash,
                page["checkpoint"],
                1,
                envelope["signature"],
            )
        )


class RotateServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.store = self.svc.store
        # The node mints a random version 1 key on first creation; capture it.
        self.initial_priv = self.store.audit_signer["private_key"]
        self.initial_pub = self.store.audit_signer["public_key"]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_rotate_success_event_and_history(self) -> None:
        status, body = self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"version": 2, "public_key": PUB_B})
        self.assertEqual(self.store.audit_signer["version"], 2)
        self.assertEqual(self.store.audit_signer["private_key"], PRIV_B)
        # The activation event id is the rotation event's own dense id.
        event = self.store.audit_events[-1]
        self.assertEqual(event["kind"], "audit_signer_rotated")
        self.assertEqual(event["event_id"], 1)
        self.assertEqual(event["version"], 2)
        self.assertEqual(event["public_key"], PUB_B)
        self.assertEqual(self.store.audit_signer["activated_event_id"], 1)
        # Old public key retained, versions ascending.
        self.assertEqual(
            [(h["version"], h["public_key"]) for h in self.store.audit_signer_history],
            [(1, self.initial_pub), (2, PUB_B)],
        )
        self.assertEqual(
            self.store.audit_signer_history[1]["activated_event_id"], 1
        )
        # Subsequent exports authenticate under the new key.
        _, page = self.svc.export_audit_events({})
        self.assertEqual(page["checkpoint_auth"]["key_version"], 2)

    def test_rotate_validation_400(self) -> None:
        for bad in (
            {"private_key": "zz", "expected_version": 1},
            {"private_key": "1" * 63, "expected_version": 1},
            {"private_key": "Z" * 64, "expected_version": 1},
            {"private_key": PRIV_B, "expected_version": 0},
            {"private_key": PRIV_B, "expected_version": "1"},
            {"private_key": PRIV_B, "expected_version": True},
            {"private_key": PRIV_B},
            {"expected_version": 1},
            ["not", "an", "object"],
        ):
            status, body = self.svc.rotate_audit_signer(bad)
            self.assertEqual(status, 400, bad)

    def test_rotate_version_conflict_409(self) -> None:
        status, _ = self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 9}
        )
        self.assertEqual(status, 409)
        # Nothing changed.
        self.assertEqual(self.store.audit_signer["version"], 1)
        self.assertEqual(self.store.audit_events, [])

    def test_rotate_persists_and_reloads(self) -> None:
        self.assertEqual(
            self.svc.rotate_audit_signer(
                {"private_key": PRIV_B, "expected_version": 1}
            )[0],
            200,
        )
        reopened = LedgerStore(os.path.join(self.tmp, "state.json"), initial_balance=1000)
        self.assertEqual(reopened.audit_signer["version"], 2)
        self.assertEqual(reopened.audit_signer["private_key"], PRIV_B)
        self.assertEqual([h["version"] for h in reopened.audit_signer_history], [1, 2])

    def test_failed_rotate_write_rolls_back_everything(self) -> None:
        original_save = self.store.save
        calls = {"n": 0}

        def failing_save():
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("simulated write failure")
            return original_save()

        self.store.save = failing_save  # type: ignore[assignment]
        with self.assertRaises(OSError):
            self.svc.rotate_audit_signer(
                {"private_key": PRIV_B, "expected_version": 1}
            )
        self.assertEqual(self.store.audit_signer["version"], 1)
        self.assertEqual(self.store.audit_signer["private_key"], self.initial_priv)
        self.assertEqual(len(self.store.audit_signer_history), 1)
        self.assertEqual(self.store.audit_events, [])
        # A retry succeeds once.
        status, body = self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.store.audit_events), 1)


class ExportAuthOfflineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.store = self.svc.store

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _trust(self) -> dict:
        return self.svc.get_trust_document()[1]

    def test_pages_share_envelope_and_verify(self) -> None:
        self.svc.register_trust_source(
            {"source": "n1", "public_key": "a" * 64, "expires_at": FUTURE}
        )
        self.svc.register_trust_source(
            {"source": "n2", "public_key": "b" * 64, "expires_at": FUTURE}
        )
        _, p1 = self.svc.export_audit_events({"limit": "1", "cursor": "0"})
        _, p2 = self.svc.export_audit_events({"limit": "1", "cursor": "1"})
        _, p3 = self.svc.export_audit_events({"cursor": "2"})
        trust = self._trust()
        # Intermediate pages cannot meet the terminal checkpoint on their own;
        # every page still pins the same checkpoint and carries the identical
        # authentication envelope.
        for page in (p1, p2, p3):
            self.assertEqual(page["checkpoint"], p1["checkpoint"])
        self.assertEqual(p1["checkpoint_auth"], p2["checkpoint_auth"])
        self.assertEqual(p2["checkpoint_auth"], p3["checkpoint_auth"])
        # The ordered multi-page document verifies as one. (Individual
        # non-terminal pages cannot meet the terminal checkpoint, matching the
        # existing hash-chain verification semantics.)
        result = audit.verify_export([p1, p2, p3], trust)
        self.assertTrue(result["ok"], result)

    def test_without_trust_behavior_unchanged(self) -> None:
        _, page = self.svc.export_audit_events({})
        result = audit.verify_export(page)
        self.assertTrue(result["ok"])
        self.assertNotIn("error", result)

    def test_missing_envelope_is_auth(self) -> None:
        _, page = self.svc.export_audit_events({})
        page.pop("checkpoint_auth")
        self.assertEqual(audit.verify_export(page, self._trust())["error"], "auth")

    def test_bad_signature_is_auth(self) -> None:
        _, page = self.svc.export_audit_events({})
        page["checkpoint_auth"]["signature"] = "3" * 128
        self.assertEqual(audit.verify_export(page, self._trust())["error"], "auth")

    def test_unknown_key_version_is_auth(self) -> None:
        _, page = self.svc.export_audit_events({})
        page["checkpoint_auth"]["key_version"] = 7
        self.assertEqual(audit.verify_export(page, self._trust())["error"], "auth")

    def test_wrong_genesis_anchor_is_auth(self) -> None:
        _, page = self.svc.export_audit_events({})
        trust = self._trust()
        trust["genesis_hash"] = "f" * 64
        self.assertEqual(audit.verify_export(page, trust)["error"], "auth")

    def test_cross_page_envelope_mismatch_is_auth(self) -> None:
        _, p1 = self.svc.export_audit_events({"limit": "1", "cursor": "0"})
        self.svc.register_trust_source(
            {"source": "n1", "public_key": "a" * 64, "expires_at": FUTURE}
        )
        _, p2 = self.svc.export_audit_events({"cursor": "1"})
        # Two checkpoints: p1 (older) and p2 (newer) — different checkpoints is
        # an integrity failure; same checkpoint but differing signatures is
        # auth. Construct the latter by pinning p1's checkpoint with a forged
        # signature.
        forged = dict(p2)
        forged["checkpoint"] = dict(p1["checkpoint"])
        forged["total"] = p1["total"]
        forged["anchor_hash"] = p1["anchor_hash"]
        forged["items"] = []
        forged["next_cursor"] = None
        forged["checkpoint_auth"] = {
            "key_version": p1["checkpoint_auth"]["key_version"],
            "signature": "4" * 128,
        }
        self.assertEqual(audit.verify_export([p1, forged], self._trust())["error"], "auth")

    def test_chain_tamper_still_integrity(self) -> None:
        _, page = self.svc.export_audit_events({})
        # Forge an event into an otherwise authenticated page.
        page["items"] = [
            {"event_id": 1, "kind": "forged", "at": 1,
             "prev_hash": audit.ZERO_HASH, "event_hash": "9" * 64}
        ]
        page["total"] = 1
        self.assertEqual(audit.verify_export(page, self._trust())["error"], "integrity")

    def test_malformed_trust_is_input(self) -> None:
        _, page = self.svc.export_audit_events({})
        for bad in ({}, {"genesis_hash": "zz"}, {"genesis_hash": "a" * 64},
                    {"genesis_hash": "a" * 64, "audit_signers": []},
                    {"genesis_hash": "a" * 64,
                     "audit_signers": [{"version": 2, "public_key": PUB_A,
                                        "activated_event_id": 0}]}):
            self.assertEqual(audit.verify_export(page, bad)["error"], "input", bad)

    def test_signer_activated_after_checkpoint_is_auth(self) -> None:
        # Rotate to v2 (activation event 1) then present a trust document whose
        # v2 claims activation at an event id beyond the checkpoint.
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        _, page = self.svc.export_audit_events({})
        trust = self._trust()
        trust["audit_signers"][1]["activated_event_id"] = 99
        self.assertEqual(audit.verify_export(page, trust)["error"], "auth")

    def test_old_key_cannot_authenticate_new_checkpoint(self) -> None:
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        _, page = self.svc.export_audit_events({})
        # Trust with only the retired v1 public key cannot verify the v2
        # checkpoint signature.
        trust = self._trust()
        trust["audit_signers"] = [trust["audit_signers"][0]]
        self.assertEqual(audit.verify_export(page, trust)["error"], "auth")

    def test_trust_version_gap_or_out_of_order_is_input(self) -> None:
        _, page = self.svc.export_audit_events({})
        good = self._trust()["audit_signers"]
        v1 = good[0]
        for bad_signers in (
            [{"version": 2, "public_key": PUB_A, "activated_event_id": 0}],
            [v1, {"version": 3, "public_key": PUB_B, "activated_event_id": 1}],
            [v1, {"version": 2, "public_key": PUB_B, "activated_event_id": 0}],
        ):
            trust = {"genesis_hash": self._trust()["genesis_hash"],
                     "audit_signers": bad_signers}
            self.assertEqual(
                audit.verify_export(page, trust)["error"], "input", bad_signers
            )

    def test_trust_activation_regression_is_input(self) -> None:
        _, page = self.svc.export_audit_events({})
        genesis = self._trust()["genesis_hash"]
        # Equal activation ids are not strictly ascending; a later activation
        # smaller than an earlier one is a regression. Both are input errors.
        for activated in ((0, 0), (0, 5, 3)):
            signers = [
                {"version": i + 1, "public_key": "ab"[i % 2] * 64,
                 "activated_event_id": act}
                for i, act in enumerate(activated)
            ]
            trust = {"genesis_hash": genesis, "audit_signers": signers}
            self.assertEqual(
                audit.verify_export(page, trust)["error"], "input", activated
            )

    def test_unselected_signer_beyond_checkpoint_is_input(self) -> None:
        # Rotate to v2 (activation event 1), then advance the log one more
        # event without rotating the signer: exports stay signed by v2 at a
        # checkpoint of event 2. A trust document that additionally lists a
        # legitimate-looking v3 activated beyond that checkpoint is internally
        # inconsistent with the verified head and is an input error — even
        # though the selected v2 key itself is active and the signature is
        # valid.
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        self.svc.register_trust_source(
            {"source": "n1", "public_key": "a" * 64, "expires_at": FUTURE}
        )
        _, page = self.svc.export_audit_events({})
        self.assertEqual(page["checkpoint"]["event_id"], 2)
        self.assertEqual(page["checkpoint_auth"]["key_version"], 2)
        trust = self._trust()
        trust["audit_signers"].append(
            {"version": 3, "public_key": "c" * 64, "activated_event_id": 50}
        )
        self.assertEqual(audit.verify_export(page, trust)["error"], "input")

    def test_selected_key_activated_after_checkpoint_stays_auth(self) -> None:
        # Contrast with the case above: when the *selected* envelope key is
        # the one activated beyond the checkpoint, the failure is auth (an
        # unactivated key authenticating the page), not input.
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        self.svc.register_trust_source(
            {"source": "n1", "public_key": "a" * 64, "expires_at": FUTURE}
        )
        _, page = self.svc.export_audit_events({})
        trust = self._trust()
        trust["audit_signers"][1]["activated_event_id"] = 50
        self.assertEqual(audit.verify_export(page, trust)["error"], "auth")


class RecoverySignerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = make_service(self.tmp)
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _reopen(self) -> LedgerStore:
        return LedgerStore(self.state_path, initial_balance=1000)

    def test_tampered_signer_seed_fails_recovery(self) -> None:
        data = read_json(self.state_path)
        data["state"]["audit_signer"]["private_key"] = "33" * 32
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            self._reopen()
        self.assertIn("public_key", ctx.exception.reason)

    def test_tampered_history_public_key_fails_recovery(self) -> None:
        data = read_json(self.state_path)
        data["state"]["audit_signer_history"][1]["public_key"] = "c" * 64
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError):
            self._reopen()

    def test_history_without_rotation_event_fails_recovery(self) -> None:
        # Add a second, non-rotation event, then repoint the v2 history entry
        # (and the current signer) at it instead of the rotation event: the
        # rotation event then has no matching history entry / the history
        # entry has no matching rotation event.
        self.svc.register_trust_source(
            {"source": "n1", "public_key": "c" * 64, "expires_at": FUTURE}
        )
        data = read_json(self.state_path)
        data["state"]["audit_signer"]["activated_event_id"] = 2
        data["state"]["audit_signer_history"][1]["activated_event_id"] = 2
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            self._reopen()
        self.assertIn("audit_signer_rotated", ctx.exception.reason)

    def test_legacy_unsigned_snapshot_is_migrated_once(self) -> None:
        # A genuinely pre-checkpoint-auth snapshot carries a schema version
        # below 9 and no signer sections: recovery mints v1 on the unique
        # winner and saves it atomically.
        data = read_json(self.state_path)
        data["state"]["version"] = STATE_VERSION - 1
        data["state"].pop("audit_signer", None)
        data["state"].pop("audit_signer_history", None)
        # Drop the v2 rotation event too, so the migrated v1 has no dangling
        # history to reconcile (modeling a genuinely older snapshot).
        data["audit_events"] = []
        data["audit_events"] = audit.link_events(data["audit_events"])
        data["audit_checkpoint"] = audit.make_checkpoint(data["audit_events"])
        write_json(self.state_path, data)

        reopened = self._reopen()
        self.assertEqual(reopened.audit_signer["version"], 1)
        self.assertEqual(reopened.audit_signer_history[0]["activated_event_id"], 0)
        # The migration is durable: a second restart neither re-mints nor
        # rewrites.
        persisted = read_json(self.state_path)
        self.assertIn("audit_signer", persisted["state"])
        first_pub = persisted["state"]["audit_signer"]["public_key"]
        again = self._reopen()
        self.assertEqual(
            again.audit_signer["public_key"], first_pub
        )

    def _assert_recovery_rejected(self) -> None:
        with self.assertRaises(StateRecoveryError) as ctx:
            self._reopen()
        self.assertEqual(
            os.path.dirname(self.state_path), ctx.exception.path
        )

    def test_missing_version_without_signer_sections_fails(self) -> None:
        # No state.version at all and both signer sections gone: never reset a
        # schema-less snapshot to version 1.
        data = read_json(self.state_path)
        data["state"].pop("version", None)
        data["state"].pop("audit_signer", None)
        data["state"].pop("audit_signer_history", None)
        write_json(self.state_path, data)
        self._assert_recovery_rejected()
        self.assertNotIn("audit_signer", read_json(self.state_path)["state"])

    def test_current_version_without_signer_sections_fails(self) -> None:
        # state.version >= 9 must carry the signer sections; their absence is
        # corruption, not a migration trigger.
        data = read_json(self.state_path)
        data["state"]["version"] = STATE_VERSION
        data["state"].pop("audit_signer", None)
        data["state"].pop("audit_signer_history", None)
        write_json(self.state_path, data)
        self._assert_recovery_rejected()

    def test_future_version_without_signer_sections_fails(self) -> None:
        data = read_json(self.state_path)
        data["state"]["version"] = STATE_VERSION + 5
        data["state"].pop("audit_signer", None)
        data["state"].pop("audit_signer_history", None)
        write_json(self.state_path, data)
        self._assert_recovery_rejected()

    def test_old_version_missing_one_section_fails(self) -> None:
        # Even an old version cannot carry exactly one of the two sections.
        original = read_json(self.state_path)
        for removed in ("audit_signer", "audit_signer_history"):
            data = json.loads(json.dumps(original))
            data["state"]["version"] = STATE_VERSION - 1
            data["state"].pop(removed, None)
            write_json(self.state_path, data)
            self._assert_recovery_rejected()
            write_json(self.state_path, original)

    def test_current_version_missing_one_section_fails(self) -> None:
        original = read_json(self.state_path)
        for removed in ("audit_signer", "audit_signer_history"):
            data = json.loads(json.dumps(original))
            data["state"].pop(removed, None)
            write_json(self.state_path, data)
            self._assert_recovery_rejected()
            write_json(self.state_path, original)

    def test_non_positive_state_version_fails(self) -> None:
        original = read_json(self.state_path)
        for bad_version in (0, -1, True, "9"):
            data = json.loads(json.dumps(original))
            data["state"]["version"] = bad_version
            write_json(self.state_path, data)
            self._assert_recovery_rejected()
            write_json(self.state_path, original)

    def test_non_strictly_ascending_activation_ids_fail(self) -> None:
        # Two history entries sharing an activation id is corruption.
        data = read_json(self.state_path)
        data["state"]["audit_signer_history"][1]["activated_event_id"] = 0
        data["state"]["audit_signer"]["activated_event_id"] = 0
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError):
            self._reopen()

    def test_same_generation_signer_conflict_fails(self) -> None:
        data = read_json(self.state_path)
        generation = data["state"]["generation"]
        # An individually valid twin with a different v2 key: re-sign the
        # checkpoint with the alternate seed and re-pin history/event.
        alt_priv = "44" * 32
        alt_pub = crypto.derive_public_key(alt_priv)
        for event in data["audit_events"]:
            if event.get("kind") == "audit_signer_rotated":
                event["public_key"] = alt_pub
        data["audit_events"] = audit.link_events(data["audit_events"])
        data["audit_checkpoint"] = audit.make_checkpoint(data["audit_events"])
        data["state"]["audit_signer"] = {
            "version": 2,
            "private_key": alt_priv,
            "public_key": alt_pub,
            "activated_event_id": 1,
        }
        data["state"]["audit_signer_history"][1]["public_key"] = alt_pub
        snapshot = os.path.join(self.tmp, f".ledger-twin.gen{generation}")
        write_json(snapshot, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            self._reopen()
        self.assertIn("conflicting snapshots", ctx.exception.reason)


class HTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_rotate_and_trust(self) -> None:
        status, body = self._request(
            "POST", "/v1/audit/signer/rotate",
            {"private_key": PRIV_B, "expected_version": 1},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"version": 2, "public_key": PUB_B})
        self.assertEqual(
            self._request(
                "POST", "/v1/audit/signer/rotate",
                {"private_key": "55" * 32, "expected_version": 9},
            )[0],
            409,
        )
        self.assertEqual(
            self._request(
                "POST", "/v1/audit/signer/rotate", {"private_key": "zz"}
            )[0],
            400,
        )
        status, trust = self._request("GET", "/v1/trust")
        self.assertEqual(status, 200)
        self.assertEqual([s["version"] for s in trust["audit_signers"]], [1, 2])
        status, page = self._request("GET", "/v1/audit/export")
        self.assertEqual(status, 200)
        self.assertEqual(page["checkpoint_auth"]["key_version"], 2)
        self.assertTrue(audit.verify_export(page, trust)["ok"])


class CLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cli(self, *argv) -> tuple[int, str]:
        out = StringIO()
        with redirect_stdout(out):
            rc = cli_main(["--base-url", self.base, *argv])
        return rc, out.getvalue().strip()

    def test_cli_rotate_and_trusted_audit_verify(self) -> None:
        rc, line = self._cli(
            "audit-signer-rotate",
            "--private-key", PRIV_B,
            "--expected-version", "1",
        )
        self.assertEqual(rc, 0, line)
        self.assertEqual(json.loads(line), {"version": 2, "public_key": PUB_B})
        # Stale version exits non-zero with a JSON error.
        rc, _ = self._cli(
            "audit-signer-rotate",
            "--private-key", "66" * 32,
            "--expected-version", "1",
        )
        self.assertEqual(rc, 1)

        rc, line = self._cli("trust", "export")
        self.assertEqual(rc, 0)
        trust_path = os.path.join(self.tmp, "trust.json")
        with open(trust_path, "w", encoding="utf-8") as fh:
            fh.write(line)

        rc, line = self._cli("audit-export")
        self.assertEqual(rc, 0)
        export_path = os.path.join(self.tmp, "export.json")
        with open(export_path, "w", encoding="utf-8") as fh:
            fh.write(line)

        # Plain verify still works; trusted verify succeeds.
        rc, line = self._cli("audit-verify", export_path)
        self.assertEqual(rc, 0, line)
        self.assertTrue(json.loads(line)["ok"])
        rc, line = self._cli("audit-verify", export_path, "--trust", trust_path)
        self.assertEqual(rc, 0, line)
        self.assertTrue(json.loads(line)["ok"])

        # A forged signature fails under --trust as the auth category.
        page = json.loads(open(export_path, encoding="utf-8").read())
        page["checkpoint_auth"]["signature"] = "7" * 128
        with open(export_path, "w", encoding="utf-8") as fh:
            json.dump(page, fh)
        rc, line = self._cli("audit-verify", export_path, "--trust", trust_path)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "auth"})

        # A malformed trust document is an input error.
        bad_trust = os.path.join(self.tmp, "bad-trust.json")
        with open(bad_trust, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        rc, line = self._cli("audit-verify", export_path, "--trust", bad_trust)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "input"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
