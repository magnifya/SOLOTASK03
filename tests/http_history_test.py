"""Tests for the online /v1/history endpoints exposing the offline
``history_trust`` / ``export_history`` library contracts over HTTP.

Covers:

* startup flags: ``--history``/``--history-trust``/``--history-token`` are
  all-or-nothing (a partial set, or an empty value, exits 2; all absent keeps
  every other interface unchanged);
* bearer gate: a missing/wrong ``Authorization`` header is 401 with the
  ``{"ok", "error"}`` envelope and no side effects (no file, no event);
* GET /v1/history/trust reads the log (200), POST appends with exactly
  ``root_seed, at, key, status`` (new entry 201, identical-tail replay 200
  idempotent with no write/event/generation change);
* POST /v1/history/export with exactly ``key, after, limit`` returns one
  contract-key-order page (200) cut at the configured signer log boundary;
* library category mapping input/auth/state/io -> 400/403/409/500;
* each successful access appends one history_access event with payload key
  order ``action, trust_head, history_head`` (missing values null; action
  read/update/export), persisted with the heads, audit_checkpoint and
  generation in one atomic write; a snapshot-save failure restores the
  external bytes and the in-memory state and returns 500/io;
* recovery strictly revalidates the signer log, the sidecar and the tip
  checkpoint and binds them to the last history_access event; tampering
  raises StateRecoveryError carrying the offending path and a reason.

Run: python3 tests/http_history_test.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import advance, history_trust
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError
from ledger.store import attested_range_message

NOW = 1_000_000_000
FUTURE = NOW + 10_000
BOB = "b" * 64
TOKEN = "secret-token"

TRUST_KEYS = ["root", "records", "head"]
RECORD_KEYS = ["at", "key", "status", "prev", "signature"]
PAGE_KEYS = ["base", "records", "next", "head", "checkpoint", "auth"]
EXPORT_KEY_ORDER = [
    "source", "request_id", "mode", "expires_at", "anchor",
    "blocks", "tip", "attestation",
]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class HistoryHttpFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.history_path = os.path.join(self.tmp, "checkpoint.json")
        self.trust_path = os.path.join(self.tmp, "signers.json")
        self._build_checkpoint()
        self.root_seed = crypto.generate_private_key()
        self.root_pub = crypto.derive_public_key(self.root_seed)
        self.signer_seed = crypto.generate_private_key()
        self.signer_pub = crypto.derive_public_key(self.signer_seed)
        self.store = LedgerStore(
            self.state_path,
            history_path=self.history_path,
            history_trust_path=self.trust_path,
        )
        self.svc = LedgerService(self.store, history_token=TOKEN)
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.svc)
        )
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build_checkpoint(self) -> None:
        alice_key = Ed25519PrivateKey.generate()
        alice_pub = pub_hex(alice_key)
        genesis = LedgerStore.create_genesis()
        anchor = {"height": 0, "block_hash": genesis.block_hash}
        tx = Transaction(
            alice_pub, BOB, 100,
            alice_key.sign(crypto.canonical_message(alice_pub, BOB, 100)).hex(),
        )
        block = Block.create(1, genesis.block_hash, [tx])
        tip = {
            "tip_hash": block.block_hash, "height": 1, "length": 2,
            "status": block.status,
        }
        doc = {
            "source": "node-plain", "request_id": "r", "mode": "plain",
            "expires_at": FUTURE, "anchor": dict(anchor),
            "blocks": [block.to_dict()], "tip": tip, "attestation": None,
        }
        doc = {key: doc[key] for key in EXPORT_KEY_ORDER}
        result = advance(
            self.history_path, [doc], {"allowlist": {"node-plain": FUTURE}},
            anchor, NOW,
        )
        self.assertTrue(result["ok"], result)

    def request(self, method, path, token=TOKEN, body=None):
        url = f"http://127.0.0.1:{self.httpd.server_address[1]}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def active_entry(self, at=10, seed=None, pub=None):
        return {
            "root_seed": seed or self.root_seed,
            "at": at,
            "key": pub or self.signer_pub,
            "status": "active",
        }


class HistoryHttpAuthTests(HistoryHttpFixture):
    def test_missing_and_wrong_token_are_401_without_side_effects(self) -> None:
        status, body = self.request("GET", "/v1/history/trust", token=None)
        self.assertEqual((status, body), (401, {"ok": False, "error": "auth"}))
        status, body = self.request(
            "POST", "/v1/history/trust", token="nope", body={"x": 1}
        )
        self.assertEqual((status, body), (401, {"ok": False, "error": "auth"}))
        self.assertFalse(os.path.exists(self.trust_path))
        self.assertEqual(self.store.audit_events, [])
        # A fresh store writes its genesis snapshot at generation 1; the
        # unauthorized requests must not advance past it.
        self.assertEqual(self.store.generation, 1)

    def test_routes_absent_without_history_configuration(self) -> None:
        store = LedgerStore(os.path.join(self.tmp, "plain.json"))
        svc = LedgerService(store)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(svc))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = (
                f"http://127.0.0.1:{httpd.server_address[1]}/v1/history/trust"
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(urllib.request.Request(url))
            self.assertEqual(raised.exception.code, 404)
        finally:
            httpd.shutdown()
            httpd.server_close()


class HistoryTrustHttpTests(HistoryHttpFixture):
    def test_create_201_and_document_contract(self) -> None:
        status, body = self.request(
            "POST", "/v1/history/trust", body=self.active_entry()
        )
        self.assertEqual(status, 201)
        self.assertEqual(list(body.keys()), TRUST_KEYS)
        self.assertEqual(body["root"], self.root_pub)
        self.assertEqual(len(body["records"]), 1)
        self.assertEqual(list(body["records"][0].keys()), RECORD_KEYS)

    def test_identical_tail_replay_is_200_idempotent(self) -> None:
        entry = self.active_entry()
        status, first = self.request("POST", "/v1/history/trust", body=entry)
        self.assertEqual(status, 201)
        generation = self.store.generation
        status, second = self.request("POST", "/v1/history/trust", body=entry)
        self.assertEqual(status, 200)
        self.assertEqual(second, first)
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(len(self.store.audit_events), 1)

    def test_input_400_for_bad_bodies(self) -> None:
        cases = [
            {},
            {"root_seed": self.root_seed, "at": 1, "key": self.signer_pub},
            dict(self.active_entry(), extra=1),
            dict(self.active_entry(), at="10"),
            dict(self.active_entry(), at=True),
            dict(self.active_entry(), key="Z" * 64),
            dict(self.active_entry(), root_seed="zz"),
            dict(self.active_entry(), status="revoked-but-open"),
            [],
        ]
        for body in cases:
            status, parsed = self.request(
                "POST", "/v1/history/trust", body=body
            )
            self.assertEqual(
                (status, parsed), (400, {"ok": False, "error": "input"}), body
            )

    def test_auth_403_for_wrong_root(self) -> None:
        self.request("POST", "/v1/history/trust", body=self.active_entry())
        other = crypto.generate_private_key()
        status, body = self.request(
            "POST", "/v1/history/trust",
            body=self.active_entry(at=20, seed=other),
        )
        self.assertEqual((status, body), (403, {"ok": False, "error": "auth"}))

    def test_state_409_for_conflicts(self) -> None:
        # A fresh log may not open with a revocation.
        status, body = self.request(
            "POST", "/v1/history/trust",
            body=dict(self.active_entry(), status="revoked"),
        )
        self.assertEqual((status, body), (409, {"ok": False, "error": "state"}))
        self.request("POST", "/v1/history/trust", body=self.active_entry())
        # at must strictly ascend.
        status, body = self.request(
            "POST", "/v1/history/trust", body=self.active_entry(at=5)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "state")
        # A revoke must name the currently active key.
        other_pub = crypto.derive_public_key(crypto.generate_private_key())
        status, body = self.request(
            "POST", "/v1/history/trust",
            body=dict(self.active_entry(at=20, pub=other_pub),
                      status="revoked"),
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "state")

    def test_read_200_records_read_event(self) -> None:
        create = self.request(
            "POST", "/v1/history/trust", body=self.active_entry()
        )[1]
        status, body = self.request("GET", "/v1/history/trust")
        self.assertEqual(status, 200)
        self.assertEqual(body, create)
        event = self.store.audit_events[-1]
        self.assertEqual(event["kind"], "history_access")
        self.assertEqual(
            list(event.keys()),
            ["event_id", "kind", "at", "prev_hash", "action",
             "trust_head", "history_head", "event_hash"],
        )
        self.assertEqual(event["action"], "read")
        self.assertEqual(event["trust_head"], create["head"])
        # The fixture advances a checkpoint first, so the sidecar exists and
        # its head is bound; a deployment without a sidecar would record null.
        from ledger.light_client import history_sidecar_document
        sidecar = history_sidecar_document(self.history_path)
        self.assertIsNotNone(sidecar)
        self.assertEqual(event["history_head"], sidecar["head"])
        self.assertEqual(self.store.history_trust_head, create["head"])
        self.assertEqual(self.store.history_head, sidecar["head"])

    def test_read_with_absent_sidecar_records_null_history_head(self) -> None:
        # Point a fresh store at a history path with no checkpoint/sidecar;
        # the update still works and both events bind history_head = null.
        bare_history = os.path.join(self.tmp, "bare.json")
        bare_trust = os.path.join(self.tmp, "bare-trust.json")
        store = LedgerStore(
            os.path.join(self.tmp, "bare-state.json"),
            history_path=bare_history,
            history_trust_path=bare_trust,
        )
        svc = LedgerService(store, history_token=TOKEN)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(svc))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{httpd.server_address[1]}/v1/history/trust"
            entry = json.dumps(self.active_entry()).encode()
            req = urllib.request.Request(
                url, data=entry, method="POST",
                headers={
                    "Authorization": f"Bearer {TOKEN}",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 201)
            req = urllib.request.Request(
                url, headers={"Authorization": f"Bearer {TOKEN}"}
            )
            with urllib.request.urlopen(req) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            httpd.shutdown()
            httpd.server_close()
        for event in store.audit_events:
            self.assertEqual(event["kind"], "history_access")
            self.assertIsNone(event["history_head"])
        self.assertIsNone(store.history_head)


class HistoryExportHttpTests(HistoryHttpFixture):
    def setUp(self) -> None:
        super().setUp()
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry(at=NOW)
        )

    def test_export_200_page_contract_and_event(self) -> None:
        body_in = {"key": self.signer_seed, "after": None, "limit": 50}
        status, page = self.request("POST", "/v1/history/export", body=body_in)
        self.assertEqual(status, 200)
        self.assertEqual(list(page.keys()), PAGE_KEYS)
        self.assertEqual(list(page["auth"].keys()), ["public_key", "signature"])
        self.assertEqual(page["auth"]["public_key"], self.signer_pub)
        event = self.store.audit_events[-1]
        self.assertEqual(event["action"], "export")
        self.assertEqual(event["history_head"], page["head"])
        self.assertEqual(event["trust_head"], self.request(
            "GET", "/v1/history/trust")[1]["head"])

    def test_export_bad_body_400(self) -> None:
        for body in (
            {},
            {"key": self.signer_seed, "after": None},
            {"key": self.signer_seed, "after": None, "limit": 50, "x": 1},
            {"key": "zz", "after": None, "limit": 50},
            {"key": self.signer_seed, "after": -1, "limit": 50},
            {"key": self.signer_seed, "after": None, "limit": 0},
        ):
            status, parsed = self.request(
                "POST", "/v1/history/export", body=body
            )
            self.assertEqual(status, 400, body)
            self.assertEqual(parsed, {"ok": False, "error": "input"})

    def test_export_unknown_signer_is_auth_403(self) -> None:
        stranger = crypto.generate_private_key()
        status, body = self.request(
            "POST", "/v1/history/export",
            body={"key": stranger, "after": None, "limit": 50},
        )
        self.assertEqual((status, body), (403, {"ok": False, "error": "auth"}))


class HistoryAccessEventTests(HistoryHttpFixture):
    def test_update_event_binds_both_heads(self) -> None:
        create = self.request(
            "POST", "/v1/history/trust", body=self.active_entry(at=NOW)
        )[1]
        page = self.request(
            "POST", "/v1/history/export",
            body={"key": self.signer_seed, "after": None, "limit": 50},
        )[1]
        signer2 = crypto.generate_private_key()
        signer2_pub = crypto.derive_public_key(signer2)
        status, rotated = self.request(
            "POST", "/v1/history/trust",
            body=self.active_entry(at=NOW + 10, pub=signer2_pub),
        )
        self.assertEqual(status, 201)
        event = self.store.audit_events[-1]
        self.assertEqual(event["action"], "update")
        self.assertEqual(event["trust_head"], rotated["head"])
        self.assertEqual(event["history_head"], page["head"])
        self.assertNotEqual(rotated["head"], create["head"])


class HistoryPersistenceRollbackTests(HistoryHttpFixture):
    def test_snapshot_failure_restores_file_and_memory_500(self) -> None:
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry()
        )
        original_bytes = open(self.trust_path, "rb").read()
        generation = self.store.generation
        event_count = len(self.store.audit_events)

        def fail_save():
            raise OSError("simulated disk failure")

        self.store.save = fail_save  # type: ignore[assignment]
        status, body = self.request(
            "POST", "/v1/history/trust",
            body=dict(self.active_entry(), status="revoked", at=20),
        )
        self.assertEqual((status, body), (500, {"ok": False, "error": "io"}))
        self.assertEqual(open(self.trust_path, "rb").read(), original_bytes)
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(len(self.store.audit_events), event_count)
        self.assertEqual(
            self.store.history_trust_head, json.loads(original_bytes)["head"]
        )


class HistoryRecoveryTests(HistoryHttpFixture):
    def _tamper_json(self, path, mutate):
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
        original = open(path, "rb").read()
        mutate(document)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(document, separators=(",", ":")) + "\n")
        return original

    def test_clean_restart_rebinds_heads(self) -> None:
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry()
        )
        page = self.request(
            "POST", "/v1/history/export",
            body={"key": self.signer_seed, "after": None, "limit": 50},
        )[1]
        reopened = LedgerStore(
            self.state_path,
            history_path=self.history_path,
            history_trust_path=self.trust_path,
        )
        self.assertEqual(reopened.history_head, page["head"])
        self.assertEqual(reopened.history_trust_head,
                         self.store.history_trust_head)

    def test_tampered_signer_log_fails_recovery(self) -> None:
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry()
        )
        self._tamper_json(self.trust_path, lambda doc: doc.__setitem__(
            "head", "f" * 64))
        with self.assertRaises(StateRecoveryError) as raised:
            LedgerStore(
                self.state_path,
                history_path=self.history_path,
                history_trust_path=self.trust_path,
            )
        self.assertEqual(
            os.path.abspath(raised.exception.path),
            os.path.abspath(self.trust_path),
        )
        self.assertTrue(raised.exception.reason)

    def test_tampered_sidecar_fails_recovery(self) -> None:
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry(at=NOW)
        )
        self.request(
            "POST", "/v1/history/export",
            body={"key": self.signer_seed, "after": None, "limit": 50},
        )
        sidecar = self.history_path + ".history"
        self._tamper_json(sidecar, lambda doc: doc.__setitem__(
            "head", "e" * 64))
        with self.assertRaises(StateRecoveryError) as raised:
            LedgerStore(
                self.state_path,
                history_path=self.history_path,
                history_trust_path=self.trust_path,
            )
        self.assertEqual(
            os.path.abspath(raised.exception.path), os.path.abspath(sidecar)
        )

    def test_tampered_checkpoint_fails_recovery(self) -> None:
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry(at=NOW)
        )
        self.request(
            "POST", "/v1/history/export",
            body={"key": self.signer_seed, "after": None, "limit": 50},
        )
        self._tamper_json(self.history_path, lambda doc: doc.__setitem__(
            "state_hash", "1" * 64))
        with self.assertRaises(StateRecoveryError) as raised:
            LedgerStore(
                self.state_path,
                history_path=self.history_path,
                history_trust_path=self.trust_path,
            )
        self.assertEqual(
            os.path.abspath(raised.exception.path),
            os.path.abspath(self.history_path),
        )

    def test_offline_signer_change_after_last_access_fails_recovery(self) -> None:
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry(at=NOW)
        )
        # Rotate the log offline with the same root after the last bound read.
        signer2 = crypto.generate_private_key()
        result = history_trust(
            self.trust_path, root_seed=self.root_seed, at=NOW + 10,
            key=crypto.derive_public_key(signer2), status="active",
        )
        self.assertIn("root", result)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(
                self.state_path,
                history_path=self.history_path,
                history_trust_path=self.trust_path,
            )

    def test_recovery_without_flags_ignores_history(self) -> None:
        self.request(
            "POST", "/v1/history/trust", body=self.active_entry()
        )
        reopened = LedgerStore(self.state_path)
        self.assertIsNone(reopened.history_path)
        self.assertIsNone(reopened.history_trust_path)


class StartupFlagsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *extra):
        return subprocess.run(
            [
                sys.executable, "-m", "ledger",
                "--state", os.path.join(self.tmp, "state.json"),
                "--port", "0",
                *extra,
            ],
            capture_output=True, text=True, timeout=30,
        )

    def test_partial_flags_exit_2(self) -> None:
        proc = self._run(
            "--history", os.path.join(self.tmp, "cp.json"),
            "--history-trust", os.path.join(self.tmp, "trust.json"),
        )
        self.assertEqual(proc.returncode, 2)

    def test_empty_token_exits_2(self) -> None:
        proc = self._run(
            "--history", os.path.join(self.tmp, "cp.json"),
            "--history-trust", os.path.join(self.tmp, "trust.json"),
            "--history-token", "",
        )
        self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
