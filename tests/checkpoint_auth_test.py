"""Tests for rotatable Ed25519 checkpoint authentication of the audit hash chain.

Covers:

* a node creates signer version 1 on first start and GET /v1/trust exposes
  ``audit_signers`` (ascending versions, first activated_event_id 0);
* POST /v1/audit/signer/rotate: malformed body 400, expected_version
  conflict 409, success 200 returning {version, public_key}, appending an
  ``audit_signer_rotated`` event and retaining every historical public key;
* every GET /v1/audit/export page carries a ``checkpoint_auth`` signature over
  SHA256(sorted compact UTF-8 JSON of
  {genesis_hash, checkpoint, key_version}), identical across pages;
* offline ``audit-verify --trust`` checks the genesis anchor, key version,
  signature and cross-page binding; without ``--trust`` behavior is unchanged;
  failures keep input/integrity and add auth;
* status, events and generation land atomically (a failed write rolls the
  signer, history and event back together); recovery re-validates and a
  tampered signer / conflicting same-generation snapshot raises
  StateRecoveryError;
* an unsigned legacy snapshot (no signer sections) migrates once, atomically,
  only after the unique winner is chosen.
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
from ledger.store import EVENT_AUDIT_SIGNER_ROTATED, LedgerStore, StateRecoveryError

FUTURE = 2_000_000_000


def _keypair():
    return crypto.generate_keypair_hex()


class SignerServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fresh_node_creates_version_1_signer(self) -> None:
        store = self.svc.store
        self.assertEqual(store.audit_signer["version"], 1)
        self.assertEqual(store.audit_signer["activated_event_id"], 0)
        self.assertTrue(crypto.is_private_hex64(store.audit_signer["private_key"]))
        self.assertEqual(
            crypto.public_key_from_private_hex(store.audit_signer["private_key"]),
            store.audit_signer["public_key"],
        )
        self.assertEqual(
            store.audit_signer_history,
            [
                {
                    "key_version": 1,
                    "public_key": store.audit_signer["public_key"],
                    "activated_event_id": 0,
                }
            ],
        )

    def test_trust_document_lists_audit_signers(self) -> None:
        status, doc = self.svc.get_trust_document()
        self.assertEqual(status, 200)
        signers = doc["audit_signers"]
        self.assertEqual([s["key_version"] for s in signers], [1])
        self.assertEqual(signers[0]["activated_event_id"], 0)
        self.assertEqual(signers[0]["public_key"], self.svc.store.audit_signer["public_key"])
        self.assertEqual(doc["genesis_hash"], self.svc.store.chain[0].block_hash)

    def test_rotate_validation_codes(self) -> None:
        priv, _ = _keypair()
        # not an object
        self.assertEqual(self.svc.rotate_audit_signer("x")[0], 400)
        # missing field
        self.assertEqual(
            self.svc.rotate_audit_signer({"private_key": priv})[0], 400
        )
        # non-hex / wrong length / uppercase private key
        self.assertEqual(
            self.svc.rotate_audit_signer(
                {"private_key": "z" * 64, "expected_version": 1}
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.rotate_audit_signer(
                {"private_key": priv[:62], "expected_version": 1}
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.rotate_audit_signer(
                {"private_key": priv.upper(), "expected_version": 1}
            )[0],
            400,
        )
        # boolean / non-positive expected_version
        self.assertEqual(
            self.svc.rotate_audit_signer(
                {"private_key": priv, "expected_version": True}
            )[0],
            400,
        )
        self.assertEqual(
            self.svc.rotate_audit_signer(
                {"private_key": priv, "expected_version": 0}
            )[0],
            400,
        )
        # well-formed but stale version -> 409
        status, body = self.svc.rotate_audit_signer(
            {"private_key": priv, "expected_version": 7}
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"] is not None, True)
        # nothing changed after all the rejections
        self.assertEqual(self.svc.store.audit_signer["version"], 1)
        self.assertEqual(self.svc.store.audit_signer_history[-1]["key_version"], 1)
        self.assertEqual(self.svc.store.audit_events, [])

    def test_successful_rotation_appends_event_and_keeps_history(self) -> None:
        priv2, pub2 = _keypair()
        status, body = self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"version": 2, "public_key": pub2})
        self.assertNotIn("private_key", body)

        store = self.svc.store
        self.assertEqual(store.audit_signer["version"], 2)
        self.assertEqual(store.audit_signer["private_key"], priv2)
        self.assertEqual(store.audit_signer["activated_event_id"], 1)
        event = store.audit_events[0]
        self.assertEqual(event["kind"], EVENT_AUDIT_SIGNER_ROTATED)
        self.assertEqual(event["event_id"], 1)
        self.assertEqual(event["key_version"], 2)
        self.assertEqual(event["public_key"], pub2)
        # the rotation event is itself hash-linked
        self.assertEqual(event["prev_hash"], audit.ZERO_HASH)
        self.assertEqual(
            event["event_hash"], audit.event_hash(audit.ZERO_HASH, event)
        )
        self.assertEqual(store.audit_checkpoint, audit.make_checkpoint(store.audit_events))

        # rotate again
        priv3, pub3 = _keypair()
        status, body = self.svc.rotate_audit_signer(
            {"private_key": priv3, "expected_version": 2}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], 3)
        versions = [s["key_version"] for s in store.audit_signer_history]
        self.assertEqual(versions, [1, 2, 3])
        self.assertEqual(
            [s["activated_event_id"] for s in store.audit_signer_history], [0, 1, 2]
        )
        self.assertEqual(store.audit_signer_history[1]["public_key"], pub2)
        self.assertEqual(store.audit_signer_history[2]["public_key"], pub3)
        self.assertEqual(
            [e["kind"] for e in store.audit_events],
            [EVENT_AUDIT_SIGNER_ROTATED, EVENT_AUDIT_SIGNER_ROTATED],
        )

    def test_export_carries_checkpoint_auth_bound_to_current_key(self) -> None:
        genesis = self.svc.store.chain[0].block_hash
        priv2, _ = _keypair()
        self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        status, page = self.svc.export_audit_events({"limit": "50", "cursor": "0"})
        self.assertEqual(status, 200)
        ca = page["checkpoint_auth"]
        self.assertEqual(set(ca), {"key_version", "signature"})
        self.assertEqual(ca["key_version"], 2)
        self.assertEqual(len(ca["signature"]), 128)
        # signature verifies over the specified message with the current key
        digest = audit.checkpoint_auth_digest(
            genesis, page["checkpoint"], ca["key_version"]
        )
        self.assertTrue(
            crypto.verify_signature(
                self.svc.store.audit_signer["public_key"], digest, ca["signature"]
            )
        )
        # every page of the export binds the same checkpoint_auth
        p1 = self.svc.export_audit_events({"limit": "1", "cursor": "0"})[1]
        self.assertEqual(p1["checkpoint_auth"], ca)
        p2 = self.svc.export_audit_events({"limit": "1", "cursor": "1"})[1]
        self.assertEqual(p2["checkpoint_auth"], ca)

    def test_old_export_still_verifies_against_historical_key(self) -> None:
        # Capture an export signed by version 1 while version 1 is current.
        pre = self.svc.export_audit_events({})[1]
        trust_pre = self.svc.get_trust_document()[1]
        self.assertTrue(audit.verify_export(pre, trust_pre)["ok"])
        # Rotate; the trust doc now lists both keys. The pre-rotation page is
        # signed by key version 1 and must still verify using the history.
        priv2, _ = _keypair()
        self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        trust_post = self.svc.get_trust_document()[1]
        self.assertEqual([s["key_version"] for s in trust_post["audit_signers"]], [1, 2])
        result = audit.verify_export(pre, trust_post)
        self.assertTrue(result["ok"], result)
        # the new export is signed by key version 2
        post = self.svc.export_audit_events({})[1]
        self.assertEqual(post["checkpoint_auth"]["key_version"], 2)
        self.assertTrue(audit.verify_export(post, trust_post)["ok"])

    def test_offline_trust_verification_failures(self) -> None:
        genesis = self.svc.store.chain[0].block_hash
        page = self.svc.export_audit_events({})[1]
        trust = self.svc.get_trust_document()[1]

        # without trust: hash chain only, still ok (default behavior unchanged)
        self.assertTrue(audit.verify_export(page)["ok"])

        # wrong genesis anchor -> auth (signature fails to verify)
        other = dict(trust)
        other["genesis_hash"] = "f" * 64
        self.assertEqual(audit.verify_export(page, other)["error"], "auth")

        # tampered signature -> auth
        tampered = json.loads(json.dumps(page))
        sig = tampered["checkpoint_auth"]["signature"]
        tampered["checkpoint_auth"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        self.assertEqual(audit.verify_export(tampered, trust)["error"], "auth")

        # unknown key version -> auth
        tampered = json.loads(json.dumps(page))
        tampered["checkpoint_auth"]["key_version"] = 99
        self.assertEqual(audit.verify_export(tampered, trust)["error"], "auth")

        # missing checkpoint_auth while trust supplied -> input
        no_auth = {k: v for k, v in page.items() if k != "checkpoint_auth"}
        self.assertEqual(audit.verify_export(no_auth, trust)["error"], "input")

        # malformed trust documents -> input
        self.assertEqual(
            audit.verify_export(page, {"genesis_hash": "x", "audit_signers": []})["error"],
            "input",
        )
        self.assertEqual(
            audit.verify_export(
                page, {"genesis_hash": genesis, "audit_signers": [
                    {"key_version": 2, "public_key": "a" * 64, "activated_event_id": 0}
                ]}
            )["error"],
            "input",
        )

        # a tampered event hash is still an integrity failure, not auth
        tampered = json.loads(json.dumps(page))
        tampered["anchor_hash"] = "f" * 64
        self.assertEqual(audit.verify_export(tampered, trust)["error"], "integrity")

    def test_failed_rotation_save_rolls_back_together(self) -> None:
        priv2, pub2 = _keypair()
        original_save = self.svc.store.save

        def failing_save():
            raise OSError("simulated write failure")

        self.svc.store.save = failing_save  # type: ignore[assignment]
        with self.assertRaises(OSError):
            self.svc.rotate_audit_signer(
                {"private_key": priv2, "expected_version": 1}
            )
        self.svc.store.save = original_save  # type: ignore[assignment]

        # signer, history, event and checkpoint all rolled back
        self.assertEqual(self.svc.store.audit_signer["version"], 1)
        self.assertEqual(
            [s["key_version"] for s in self.svc.store.audit_signer_history], [1]
        )
        self.assertEqual(self.svc.store.audit_events, [])
        self.assertEqual(
            self.svc.store.audit_checkpoint, audit.make_checkpoint([])
        )
        # retry succeeds cleanly
        status, body = self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["public_key"], pub2)
        self.assertEqual(len(self.svc.store.audit_events), 1)

    def test_persistence_generation_advances_with_rotation(self) -> None:
        before = self.svc.store.generation
        self.svc.rotate_audit_signer(
            {"private_key": _keypair()[0], "expected_version": 1}
        )
        self.assertEqual(self.svc.store.generation, before + 1)


class SignerRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_signer_survives_restart(self) -> None:
        priv2, pub2 = _keypair()
        self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        page = self.svc.export_audit_events({})[1]
        trust = self.svc.get_trust_document()[1]

        reopened_store = LedgerStore(self.state_path, initial_balance=1000)
        reopened = LedgerService(reopened_store, initial_balance=1000)
        self.assertEqual(reopened_store.audit_signer["version"], 2)
        self.assertEqual(reopened_store.audit_signer["private_key"], priv2)
        self.assertEqual(
            [s["key_version"] for s in reopened_store.audit_signer_history], [1, 2]
        )
        # signatures from the reopened node still verify offline
        self.assertTrue(
            audit.verify_export(
                reopened.export_audit_events({})[1],
                reopened.get_trust_document()[1],
            )["ok"]
        )
        # old captured page still verifies
        self.assertTrue(audit.verify_export(page, trust)["ok"])
        self.assertEqual(pub2 == reopened_store.audit_signer["public_key"], True)

    def test_tampered_current_signer_fails_recovery(self) -> None:
        priv2, _ = _keypair()
        self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        # swap the private key for a different valid seed -> pubkey mismatch
        data["audit_signer"]["private_key"] = _keypair()[0]
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_tampered_history_public_key_fails_recovery(self) -> None:
        priv2, _ = _keypair()
        self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        # the version-2 history entry must match its rotation event
        data["audit_signer_history"][1]["public_key"] = "b" * 64
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_history_activation_pointing_at_wrong_event_fails(self) -> None:
        priv2, _ = _keypair()
        self.svc.rotate_audit_signer(
            {"private_key": priv2, "expected_version": 1}
        )
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["audit_signer_history"][1]["activated_event_id"] = 0
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_partial_signer_section_fails_recovery(self) -> None:
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        del data["audit_signer_history"]
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_legacy_unsigned_snapshot_migrates_once(self) -> None:
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        # Simulate a snapshot written before checkpoint authentication: no
        # signer sections and an unlinked legacy audit log (no checkpoint).
        data.pop("audit_signer")
        data.pop("audit_signer_history")
        data.pop("audit_checkpoint")
        data["audit_events"] = [
            {
                "event_id": 1,
                "kind": "source_registered",
                "at": 1.0,
                "source": "n1",
                "public_key": "a" * 64,
                "expires_at": FUTURE,
                "version": 1,
            }
        ]
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        migrated = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(migrated.audit_signer["version"], 1)
        self.assertEqual(migrated.audit_signer["activated_event_id"], 0)
        # the legacy event was hash-linked as part of the same repair
        event = migrated.audit_events[0]
        self.assertIn("prev_hash", event)
        self.assertIn("event_hash", event)
        self.assertEqual(
            migrated.audit_checkpoint, audit.make_checkpoint(migrated.audit_events)
        )
        # no spurious rotation event was added
        self.assertEqual(
            [e["kind"] for e in migrated.audit_events], ["source_registered"]
        )
        # migration is durable: a second restart keeps the same key and does
        # not generate another one
        persisted_private = migrated.audit_signer["private_key"]
        gen_after_migration = migrated.generation
        again = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(again.audit_signer["private_key"], persisted_private)
        self.assertEqual(again.generation, gen_after_migration)

    def test_differing_signer_is_a_same_generation_conflict(self) -> None:
        with open(self.state_path, encoding="utf-8") as fh:
            base = json.load(fh)
        peer = json.loads(json.dumps(base))
        peer["audit_signer"]["private_key"] = _keypair()[0]
        peer["audit_signer"]["public_key"] = crypto.public_key_from_private_hex(
            peer["audit_signer"]["private_key"]
        )
        peer["audit_signer_history"][0]["public_key"] = peer["audit_signer"]["public_key"]
        with open(os.path.join(self.tmp, ".ledger-peer"), "w", encoding="utf-8") as fh:
            json.dump(peer, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)


class SignerHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
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

    def test_rotate_and_export_http(self) -> None:
        priv, pub = _keypair()
        status, body = self._request(
            "POST", "/v1/audit/signer/rotate",
            {"private_key": priv, "expected_version": 1},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"version": 2, "public_key": pub})

        # malformed 400 and conflict 409 over the wire
        self.assertEqual(
            self._request(
                "POST", "/v1/audit/signer/rotate",
                {"private_key": "nope", "expected_version": 2},
            )[0],
            400,
        )
        self.assertEqual(
            self._request(
                "POST", "/v1/audit/signer/rotate",
                {"private_key": _keypair()[0], "expected_version": 1},
            )[0],
            409,
        )

        status, page = self._request("GET", "/v1/audit/export")
        self.assertEqual(status, 200)
        self.assertEqual(page["checkpoint_auth"]["key_version"], 2)
        status, trust = self._request("GET", "/v1/trust")
        self.assertEqual(status, 200)
        self.assertEqual(
            [s["key_version"] for s in trust["audit_signers"]], [1, 2]
        )
        self.assertTrue(audit.verify_export(page, trust)["ok"])


class SignerCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
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

    def test_signer_rotate_cli(self) -> None:
        priv, _ = _keypair()
        rc, line = self._cli(
            "signer-rotate", "--private-key", priv, "--expected-version", "1"
        )
        self.assertEqual(rc, 0, line)
        body = json.loads(line)
        self.assertEqual(body["version"], 2)
        self.assertEqual(len(body["public_key"]), 64)
        # conflict exits non-zero
        rc, line = self._cli(
            "signer-rotate", "--private-key", _keypair()[0],
            "--expected-version", "1",
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line)["error"] is not None, True)

    def test_audit_verify_with_trust_cli(self) -> None:
        page = self.svc.export_audit_events({})[1]
        trust = self.svc.get_trust_document()[1]
        page_path = os.path.join(self.tmp, "page.json")
        trust_path = os.path.join(self.tmp, "trust.json")
        with open(page_path, "w", encoding="utf-8") as fh:
            json.dump(page, fh)
        with open(trust_path, "w", encoding="utf-8") as fh:
            json.dump(trust, fh)

        # hash-chain-only (default) still ok
        rc, line = self._cli("audit-verify", page_path)
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(line)["ok"])

        # with a valid trust document
        rc, line = self._cli("audit-verify", page_path, "--trust", trust_path)
        self.assertEqual(rc, 0, line)
        result = json.loads(line)
        self.assertTrue(result["ok"])
        self.assertEqual(result["checkpoint"], page["checkpoint"])

        # tamper the signature -> auth failure, exit 1
        page["checkpoint_auth"]["signature"] = "00" + page["checkpoint_auth"]["signature"][2:]
        with open(page_path, "w", encoding="utf-8") as fh:
            json.dump(page, fh)
        rc, line = self._cli("audit-verify", page_path, "--trust", trust_path)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "auth"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
