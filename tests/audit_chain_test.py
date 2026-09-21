"""Tests for the append-only audit hash chain, checkpoint, export and offline
verification.

Covers:

* the exact event hash vector: ``prev_hash`` ASCII (64 zeroes for event 1)
  concatenated with the sorted-key compact UTF-8 JSON of the event with both
  hash fields removed (non-ASCII emitted raw);
* dense event ids, prev/event linkage and the ``audit_checkpoint`` head,
  persisted atomically with every event append and rolled back together when
  the write fails (a retry is neither duplicated nor lost);
* GET /v1/audit/export pagination (shared with /v1/audit/events),
  ``anchor_hash`` semantics (zero root at cursor 0, predecessor hash for a
  non-empty page, log head at the terminal empty page) and the per-page
  ``checkpoint``; repeated query parameters are 400;
* recovery: a legacy unlinked snapshot is backlinked once (then byte-stable on
  the next restart), expiry backfill is linked too, while a present-but-wrong
  link/checkpoint or a partially linked log fails with StateRecoveryError and
  the checkpoint participates in same-generation conflict comparison;
* CLI ``audit-export`` and offline ``audit-verify FILE|-``: single JSON line,
  ok+checkpoint vs error(input|integrity), exit codes 0/1.

Run: python3 tests/audit_chain_test.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ledger import audit
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

KEY_A = "a" * 64
FUTURE = 1_900_000_000


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


class HashVectorTests(unittest.TestCase):
    def test_event_hash_matches_spec_vector(self) -> None:
        import hashlib

        event = {"event_id": 1, "kind": "source_registered", "at": 1.5}
        canonical = json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        expected = hashlib.sha256(
            audit.ZERO_HASH.encode("ascii") + canonical
        ).hexdigest()
        self.assertEqual(audit.event_hash(audit.ZERO_HASH, event), expected)

    def test_hash_excludes_both_link_fields(self) -> None:
        event = {"event_id": 1, "kind": "k", "at": 1}
        base = audit.event_hash(audit.ZERO_HASH, event)
        decorated = dict(event, prev_hash="f" * 64, event_hash="e" * 64)
        self.assertEqual(audit.event_hash(audit.ZERO_HASH, decorated), base)
        self.assertNotIn(b"prev_hash", audit.canonical_event(decorated))
        self.assertNotIn(b"event_hash", audit.canonical_event(decorated))

    def test_non_ascii_payload_hashed_as_raw_utf8(self) -> None:
        import hashlib

        event = {"event_id": 1, "kind": "k", "at": 1, "note": "审计✓"}
        canonical = json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        self.assertIn("审".encode("utf-8"), canonical)
        self.assertEqual(
            audit.event_hash(audit.ZERO_HASH, event),
            hashlib.sha256(audit.ZERO_HASH.encode("ascii") + canonical).hexdigest(),
        )

    def test_linking_is_dense_and_checkpoint_pins_head(self) -> None:
        linked = audit.link_events(
            [
                {"event_id": 1, "kind": "a", "at": 1},
                {"event_id": 2, "kind": "b", "at": 2},
            ]
        )
        self.assertEqual(linked[0]["prev_hash"], audit.ZERO_HASH)
        self.assertEqual(linked[1]["prev_hash"], linked[0]["event_hash"])
        self.assertEqual([e["event_id"] for e in linked], [1, 2])
        audit.validate_event_chain(linked)
        self.assertEqual(
            audit.make_checkpoint(linked),
            {"event_id": 2, "event_hash": linked[1]["event_hash"]},
        )
        self.assertEqual(
            audit.make_checkpoint([]),
            {"event_id": 0, "event_hash": audit.ZERO_HASH},
        )

    def test_validate_rejects_broken_link(self) -> None:
        linked = audit.link_events([{"event_id": 1, "kind": "a", "at": 1}])
        tampered = [dict(linked[0], kind="x")]
        with self.assertRaises(audit.AuditChainError):
            audit.validate_event_chain(tampered)
        with self.assertRaises(audit.AuditChainError):
            audit.validate_checkpoint(
                {"event_id": 1, "event_hash": "f" * 64}, linked
            )


class ChainPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.store = self.svc.store

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def register(self, source: str = "node-1", key_hex: str = KEY_A) -> None:
        status, body = self.svc.register_trust_source(
            {"source": source, "public_key": key_hex, "expires_at": FUTURE}
        )
        self.assertIn(status, (200, 201), body)

    def test_events_link_and_checkpoint_persist_and_reload(self) -> None:
        self.register("n1")
        self.register("n2")
        events = self.store.audit_events
        self.assertEqual(events[0]["prev_hash"], audit.ZERO_HASH)
        self.assertEqual(events[1]["prev_hash"], events[0]["event_hash"])
        self.assertEqual(
            self.store.audit_checkpoint,
            {"event_id": 2, "event_hash": events[1]["event_hash"]},
        )
        on_disk = read_json(self.state_path)
        self.assertEqual(on_disk["audit_checkpoint"], self.store.audit_checkpoint)
        self.assertIn("prev_hash", on_disk["audit_events"][0])

        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(reopened.audit_events, events)
        self.assertEqual(reopened.audit_checkpoint, self.store.audit_checkpoint)

    def test_failed_append_save_rolls_back_event_link_and_checkpoint(self) -> None:
        self.register("n1")
        head_before = dict(self.store.audit_checkpoint)
        events_before = len(self.store.audit_events)
        original_save = self.store.save
        calls = {"n": 0}

        def failing_save():
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("simulated write failure")
            return original_save()

        self.store.save = failing_save  # type: ignore[assignment]
        with self.assertRaises(OSError):
            self.svc.register_trust_source(
                {"source": "n2", "public_key": "b" * 64, "expires_at": FUTURE}
            )
        # Memory rolled fully back: no half event, head unchanged.
        self.assertEqual(len(self.store.audit_events), events_before)
        self.assertEqual(self.store.audit_checkpoint, head_before)
        self.assertNotIn("n2", self.store.trust_sources)
        # A retry succeeds exactly once (no duplicate, no loss).
        status, body = self.svc.register_trust_source(
            {"source": "n2", "public_key": "b" * 64, "expires_at": FUTURE}
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(len(self.store.audit_events), events_before + 1)
        self.assertEqual(
            [e["source"] for e in self.store.audit_events], ["n1", "n2"]
        )
        # Restart sees the retried event with a valid chain.
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(len(reopened.audit_events), 2)
        self.assertEqual(reopened.audit_checkpoint, self.store.audit_checkpoint)


class RecoveryChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.svc.register_trust_source(
            {"source": "node-1", "public_key": KEY_A, "expires_at": FUTURE}
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _legacy_snapshot(self) -> dict:
        data = read_json(self.state_path)
        for event in data["audit_events"]:
            event.pop("prev_hash", None)
            event.pop("event_hash", None)
        data.pop("audit_checkpoint", None)
        return data

    def test_legacy_unlinked_snapshot_is_backlinked_once(self) -> None:
        data = self._legacy_snapshot()
        write_json(self.state_path, data)
        reopened = LedgerStore(self.state_path, initial_balance=1000)
        event = reopened.audit_events[0]
        self.assertEqual(event["prev_hash"], audit.ZERO_HASH)
        self.assertEqual(
            reopened.audit_checkpoint,
            {"event_id": 1, "event_hash": event["event_hash"]},
        )
        # The completion is persisted; a second restart neither rewrites nor
        # recomputes a different chain.
        persisted = read_json(self.state_path)
        generation_after = persisted["state"]["generation"]
        self.assertEqual(persisted["audit_checkpoint"], reopened.audit_checkpoint)
        again = LedgerStore(self.state_path, initial_balance=1000)
        self.assertEqual(again.audit_events, reopened.audit_events)
        self.assertEqual(again.generation, generation_after)

    def test_legacy_empty_log_without_checkpoint_loads_and_saves_zero_root(self) -> None:
        path = os.path.join(self.tmp, "fresh", "state.json")
        store = LedgerStore(path, initial_balance=1000)
        self.assertEqual(
            store.audit_checkpoint,
            {"event_id": 0, "event_hash": audit.ZERO_HASH},
        )
        data = read_json(path)
        self.assertEqual(
            data["audit_checkpoint"],
            {"event_id": 0, "event_hash": audit.ZERO_HASH},
        )

    def test_bad_event_hash_fails_recovery(self) -> None:
        data = read_json(self.state_path)
        data["audit_events"][0]["kind"] = "tampered"
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("event_hash", ctx.exception.reason)

    def test_bad_prev_hash_fails_recovery(self) -> None:
        # Add a second event first so there is a non-root link to break.
        self.svc.register_trust_source(
            {"source": "node-2", "public_key": "c" * 64, "expires_at": FUTURE}
        )
        data = read_json(self.state_path)
        data["audit_events"][1]["prev_hash"] = "f" * 64
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("prev_hash", ctx.exception.reason)

    def test_bad_checkpoint_fails_recovery(self) -> None:
        data = read_json(self.state_path)
        data["audit_checkpoint"]["event_id"] = 42
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("checkpoint", ctx.exception.reason)

    def test_partially_linked_log_fails_recovery(self) -> None:
        self.svc.register_trust_source(
            {"source": "node-2", "public_key": "c" * 64, "expires_at": FUTURE}
        )
        data = read_json(self.state_path)
        for event in data["audit_events"]:
            event.pop("prev_hash", None)
            event.pop("event_hash", None)
        data.pop("audit_checkpoint", None)
        # Re-link only the first event: a half-migrated log must not load.
        linked = audit.link_events(data["audit_events"])
        data["audit_events"] = [
            linked[0],
            {k: v for k, v in linked[1].items() if k not in ("prev_hash", "event_hash")},
        ]
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("partially", ctx.exception.reason)

    def test_checkpoint_on_unlinked_log_fails_recovery(self) -> None:
        data = self._legacy_snapshot()
        data["audit_checkpoint"] = {"event_id": 1, "event_hash": "f" * 64}
        write_json(self.state_path, data)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.state_path, initial_balance=1000)

    def test_checkpoint_difference_is_a_same_generation_conflict(self) -> None:
        data = read_json(self.state_path)
        generation = data["state"]["generation"]
        # An individually-valid alternative candidate with one extra event and
        # therefore a different checkpoint head.
        data["audit_events"].append(
            {"event_id": 2, "kind": "source_registered", "at": 1.0, "source": "x"}
        )
        data["audit_events"] = audit.link_events(data["audit_events"])
        data["audit_checkpoint"] = audit.make_checkpoint(data["audit_events"])
        snapshot = os.path.join(self.tmp, f".ledger-conflict.gen{generation}")
        write_json(snapshot, data)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.state_path, initial_balance=1000)
        self.assertIn("conflicting snapshots", ctx.exception.reason)

    def test_legacy_backfill_and_expiry_events_are_linked_together(self) -> None:
        # Deliver a sync, then turn the snapshot into a legacy one whose sync
        # record has already expired: recovery must backfill one
        # sync_expired event and link both events plus the checkpoint in a
        # single repair.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from ledger.models import Block, Transaction
        from ledger import crypto

        signer = Ed25519PrivateKey.generate()
        sender = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        recipient = "b" * 64
        msg = crypto.canonical_message(sender, recipient, 10)
        tx = {
            "from": sender,
            "to": recipient,
            "amount": 10,
            "signature": signer.sign(msg).hex(),
        }
        genesis = self.svc.store.chain[0]
        block = Block.create(
            1,
            genesis.block_hash,
            [Transaction.from_dict(tx)],
            "confirmed",
        )
        candidate = {
            "tip_hash": block.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
            "blocks": [genesis.to_dict(), block.to_dict()],
        }
        status, body = self.svc.submit_fork_sync(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "candidate": candidate,
            }
        )
        self.assertEqual(status, 201, body)

        data = read_json(self.state_path)
        for event in data["audit_events"]:
            event.pop("prev_hash", None)
            event.pop("event_hash", None)
        data.pop("audit_checkpoint", None)
        data["syncs"][0]["expires_at"] = int(time.time()) - 5
        write_json(self.state_path, data)

        reopened = LedgerStore(self.state_path, initial_balance=1000)
        kinds = [e["kind"] for e in reopened.audit_events]
        self.assertEqual(kinds, ["source_registered", "sync_received", "sync_expired"])
        # Whole repaired log verifies and the checkpoint pins the expiry event.
        audit.validate_event_chain(reopened.audit_events)
        audit.validate_checkpoint(reopened.audit_checkpoint, reopened.audit_events)
        self.assertEqual(
            reopened.audit_checkpoint,
            audit.make_checkpoint(reopened.audit_events),
        )


class ExportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        for i in range(3):
            self.svc.register_trust_source(
                {
                    "source": f"n{i}",
                    "public_key": format(i + 1, "064x"),
                    "expires_at": FUTURE,
                }
            )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_export_pages_anchors_and_checkpoint(self) -> None:
        events = self.svc.store.audit_events
        status, page = self.svc.export_audit_events({"limit": "2", "cursor": "0"})
        self.assertEqual(status, 200)
        self.assertEqual(set(page), {"items", "total", "next_cursor", "anchor_hash", "checkpoint", "checkpoint_auth"})
        self.assertEqual(page["total"], 3)
        self.assertEqual([e["event_id"] for e in page["items"]], [1, 2])
        self.assertEqual(page["anchor_hash"], audit.ZERO_HASH)
        self.assertEqual(page["next_cursor"], 2)
        self.assertEqual(
            page["checkpoint"],
            {"event_id": 3, "event_hash": events[2]["event_hash"]},
        )
        # Every item carries both links.
        from ledger import crypto as ledger_crypto

        for item in page["items"]:
            self.assertIn("prev_hash", item)
            self.assertIn("event_hash", item)
            self.assertTrue(ledger_crypto.is_hex64(item["event_hash"]))

        status, page2 = self.svc.export_audit_events({"limit": "2", "cursor": "2"})
        self.assertEqual([e["event_id"] for e in page2["items"]], [3])
        self.assertEqual(page2["anchor_hash"], events[1]["event_hash"])
        self.assertIsNone(page2["next_cursor"])

        # Terminal empty page: anchor equals the checkpoint head.
        status, last = self.svc.export_audit_events({"cursor": "3"})
        self.assertEqual(status, 200)
        self.assertEqual(last["items"], [])
        self.assertEqual(last["anchor_hash"], events[2]["event_hash"])
        self.assertEqual(last["anchor_hash"], last["checkpoint"]["event_hash"])

        # The pages verify offline in order.
        self.assertTrue(audit.verify_export([page, page2])["ok"])

    def test_export_param_errors(self) -> None:
        self.assertEqual(self.svc.export_audit_events({"cursor": "4"})[0], 400)
        self.assertEqual(self.svc.export_audit_events({"limit": "0"})[0], 400)
        self.assertEqual(self.svc.export_audit_events({"limit": "201"})[0], 400)
        self.assertEqual(self.svc.export_audit_events({"limit": "x"})[0], 400)
        self.assertEqual(self.svc.export_audit_events({"cursor": "01"})[0], 400)


class ExportHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.svc.register_trust_source(
            {"source": "n1", "public_key": KEY_A, "expires_at": FUTURE}
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _get(self, path: str) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(self.base + path) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_export_endpoint_and_repeated_params(self) -> None:
        status, body = self._get("/v1/audit/export")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 1)
        self.assertIn("event_hash", body["items"][0])
        status, body = self._get("/v1/audit/export?limit=1&limit=2")
        self.assertEqual(status, 400)
        status, body = self._get("/v1/audit/export?cursor=0&cursor=1")
        self.assertEqual(status, 400)
        status, body = self._get("/v1/audit/export?cursor=99")
        self.assertEqual(status, 400)


class AuditVerifyCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        for i in range(2):
            self.svc.register_trust_source(
                {
                    "source": f"n{i}",
                    "public_key": format(i + 1, "064x"),
                    "expires_at": FUTURE,
                }
            )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cli(self, *argv, stdin: str | None = None) -> tuple[int, str]:
        if stdin is None:
            out = StringIO()
            with redirect_stdout(out):
                rc = cli_main(["--base-url", self.base, *argv])
            return rc, out.getvalue().strip()
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from ledger.cli import main; sys.exit(main())",
                "--base-url",
                self.base,
                *argv,
            ],
            input=stdin,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))},
        )
        return proc.returncode, proc.stdout.strip()

    def _fetch_pages(self) -> list[dict]:
        pages = []
        cursor = "0"
        while True:
            rc, line = self._cli(
                "audit-export", "--limit", "1", "--cursor", cursor
            )
            self.assertEqual(rc, 0, line)
            page = json.loads(line)
            pages.append(page)
            if page["next_cursor"] is None:
                break
            cursor = str(page["next_cursor"])
        return pages

    def test_audit_export_command(self) -> None:
        rc, line = self._cli("audit-export")
        self.assertEqual(rc, 0)
        self.assertEqual(len(line.splitlines()), 1)
        body = json.loads(line)
        self.assertEqual(body["total"], 2)
        self.assertIn("anchor_hash", body)
        self.assertIn("checkpoint", body)

    def test_verify_ok_from_stdin_and_file(self) -> None:
        pages = self._fetch_pages()
        rc, line = self._cli("audit-verify", "-", stdin=json.dumps(pages))
        self.assertEqual(rc, 0, line)
        body = json.loads(line)
        self.assertTrue(body["ok"])
        self.assertEqual(body["checkpoint"], pages[-1]["checkpoint"])
        self.assertEqual(len(line.splitlines()), 1)

        path = os.path.join(self.tmp, "pages.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(pages, fh)
        rc, line = self._cli("audit-verify", path)
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(line)["ok"])

    def test_verify_integrity_error_exit_1(self) -> None:
        pages = self._fetch_pages()
        pages[0]["items"][0]["kind"] = "forged"
        rc, line = self._cli("audit-verify", "-", stdin=json.dumps(pages))
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "integrity"})

    def test_verify_bad_anchor_is_integrity(self) -> None:
        pages = self._fetch_pages()
        if len(pages) > 1:
            pages[1]["anchor_hash"] = audit.ZERO_HASH
        rc, line = self._cli("audit-verify", "-", stdin=json.dumps(pages))
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line)["error"], "integrity")

    def test_verify_checkpoint_mismatch_is_integrity(self) -> None:
        pages = self._fetch_pages()
        pages[-1]["checkpoint"]["event_hash"] = "f" * 64
        rc, line = self._cli("audit-verify", "-", stdin=json.dumps(pages))
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line)["error"], "integrity")

    def test_verify_input_errors(self) -> None:
        rc, line = self._cli("audit-verify", "-", stdin="not json{")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "input"})
        rc, line = self._cli("audit-verify", os.path.join(self.tmp, "missing.json"))
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line)["error"], "input")
        rc, line = self._cli("audit-verify", "-", stdin='{"items": []}')
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line)["error"], "input")


if __name__ == "__main__":
    unittest.main(verbosity=2)
