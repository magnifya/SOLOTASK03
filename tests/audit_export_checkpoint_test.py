"""Tests for checkpoint-pinned audit export (GET /v1/audit/export).

Covers:

* the optional ``checkpoint_event_id``/``checkpoint_hash`` pair: both must
  appear together, each exactly once, the id a non-negative ASCII decimal
  without leading zeros and the hash 64 lowercase hex characters — a lone,
  repeated or malformed value is 400 ``{"error": "input"}``;
* validation against the persisted chain: an event id the log has not
  reached or a mismatched hash is 409 ``{"error": "checkpoint_conflict"}``
  and changes neither the ledger, the generation nor the audit log;
* a pinned export pages only the pinned prefix: ``total`` is exactly
  ``checkpoint_event_id``, ``cursor == total`` returns the empty terminal
  page, ``cursor > total`` is 400, ``anchor_hash`` is computed over the
  prefix and ``checkpoint`` echoes the request verbatim;
* pinned pages are stable across later appends, rotations and restarts, and
  ``checkpoint_auth`` is signed by the key version activated at or before
  the checkpoint so old checkpoints stay exportable (and offline-verifiable
  with ``ledger.audit.verify_export``) after a rotation;
* the HTTP surface (repeated-parameter handling) and the CLI
  ``audit-export --checkpoint-event-id/--checkpoint-hash`` flags.

Run: python3 tests/audit_export_checkpoint_test.py
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

from ledger import audit
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

FUTURE = 1_900_000_000
PRIV_B = "22" * 32


def make_service(tmp: str) -> LedgerService:
    return LedgerService(
        LedgerStore(os.path.join(tmp, "state.json"), initial_balance=1000),
        initial_balance=1000,
    )


class PinnedExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.store = self.svc.store
        # Three durable audit events (ids 1..3).
        for index in range(3):
            self.svc.register_trust_source(
                {
                    "source": f"n{index}",
                    "public_key": f"{index:x}" * 64,
                    "expires_at": FUTURE,
                }
            )
        self.events = list(self.store.audit_events)
        self.assertEqual(len(self.events), 3)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pin(self, event_id: int) -> dict:
        event_hash = (
            audit.ZERO_HASH if event_id == 0
            else self.store.audit_events[event_id - 1]["event_hash"]
        )
        return {
            "checkpoint_event_id": str(event_id),
            "checkpoint_hash": event_hash,
        }

    def test_unpinned_behavior_unchanged(self) -> None:
        status, page = self.svc.export_audit_events({})
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 3)
        self.assertEqual(page["checkpoint"], self.store.audit_checkpoint)
        self.assertEqual(len(page["items"]), 3)
        self.assertIsNone(page["next_cursor"])
        self.assertEqual(page["anchor_hash"], audit.ZERO_HASH)

    def test_pinned_total_items_and_checkpoint(self) -> None:
        status, page = self.svc.export_audit_events(self._pin(2))
        self.assertEqual(status, 200)
        # total is exactly the pinned event id, not the current log length.
        self.assertEqual(page["total"], 2)
        self.assertEqual([item["event_id"] for item in page["items"]], [1, 2])
        # The checkpoint echoes the request verbatim.
        self.assertEqual(
            page["checkpoint"],
            {"event_id": 2, "event_hash": self.events[1]["event_hash"]},
        )
        self.assertIsNone(page["next_cursor"])
        self.assertEqual(page["anchor_hash"], audit.ZERO_HASH)

    def test_pinned_pagination_and_terminal_page(self) -> None:
        pin = self._pin(2)
        _, p1 = self.svc.export_audit_events({**pin, "limit": "1", "cursor": "0"})
        _, p2 = self.svc.export_audit_events({**pin, "limit": "1", "cursor": "1"})
        _, p3 = self.svc.export_audit_events({**pin, "cursor": "2"})
        self.assertEqual([i["event_id"] for i in p1["items"]], [1])
        self.assertEqual(p1["next_cursor"], 1)
        self.assertEqual([i["event_id"] for i in p2["items"]], [2])
        self.assertIsNone(p2["next_cursor"])
        self.assertEqual(p2["anchor_hash"], self.events[0]["event_hash"])
        # cursor == total: the empty terminal page anchored at the pinned head.
        self.assertEqual(p3["items"], [])
        self.assertEqual(p3["total"], 2)
        self.assertEqual(p3["anchor_hash"], self.events[1]["event_hash"])
        self.assertIsNone(p3["next_cursor"])
        # Every page pins the identical checkpoint and envelope.
        self.assertEqual(p1["checkpoint"], p2["checkpoint"])
        self.assertEqual(p2["checkpoint"], p3["checkpoint"])
        self.assertEqual(p1["checkpoint_auth"], p2["checkpoint_auth"])
        self.assertEqual(p2["checkpoint_auth"], p3["checkpoint_auth"])
        # cursor beyond the pinned total is 400.
        status, _ = self.svc.export_audit_events({**pin, "cursor": "3"})
        self.assertEqual(status, 400)
        # The ordered pages verify offline as one export.
        trust = self.svc.get_trust_document()[1]
        result = audit.verify_export([p1, p2, p3], trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["checkpoint"],
            {"event_id": 2, "event_hash": self.events[1]["event_hash"]},
        )

    def test_pin_at_current_head_matches_unpinned_export(self) -> None:
        # Pinning the exact current head yields the same page content as the
        # legacy unpinned export, with the checkpoint echoed from the request.
        _, unpinned = self.svc.export_audit_events({})
        _, pinned = self.svc.export_audit_events(self._pin(3))
        self.assertEqual(pinned, unpinned)
        self.assertEqual(pinned["total"], 3)

    def test_pinned_zero_checkpoint_of_empty_prefix(self) -> None:
        status, page = self.svc.export_audit_events(self._pin(0))
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 0)
        self.assertEqual(page["items"], [])
        self.assertEqual(page["anchor_hash"], audit.ZERO_HASH)
        self.assertEqual(
            page["checkpoint"], {"event_id": 0, "event_hash": audit.ZERO_HASH}
        )
        self.assertTrue(audit.verify_export(page)["ok"])

    def test_pairing_and_format_validation(self) -> None:
        event_hash = self.events[0]["event_hash"]
        for params in (
            {"checkpoint_event_id": "1"},
            {"checkpoint_hash": event_hash},
            {"checkpoint_event_id": "", "checkpoint_hash": event_hash},
            {"checkpoint_event_id": "01", "checkpoint_hash": event_hash},
            {"checkpoint_event_id": "-1", "checkpoint_hash": event_hash},
            {"checkpoint_event_id": "+1", "checkpoint_hash": event_hash},
            {"checkpoint_event_id": "1.0", "checkpoint_hash": event_hash},
            {"checkpoint_event_id": "1 ", "checkpoint_hash": event_hash},
            {"checkpoint_event_id": "١", "checkpoint_hash": event_hash},
            {"checkpoint_event_id": "1", "checkpoint_hash": ""},
            {"checkpoint_event_id": "1", "checkpoint_hash": event_hash[:-1]},
            {"checkpoint_event_id": "1", "checkpoint_hash": event_hash + "0"},
            {"checkpoint_event_id": "1", "checkpoint_hash": event_hash.upper()},
            {"checkpoint_event_id": "1", "checkpoint_hash": "z" * 64},
        ):
            status, body = self.svc.export_audit_events(params)
            self.assertEqual(status, 400, params)
            self.assertEqual(body, {"error": "input"}, params)

    def test_checkpoint_conflict_beyond_log_and_hash_mismatch(self) -> None:
        generation = self.store.generation
        for params in (
            {"checkpoint_event_id": "4",
             "checkpoint_hash": self.events[2]["event_hash"]},
            {"checkpoint_event_id": "99", "checkpoint_hash": "a" * 64},
            # A well-formed but absurdly large id folds to "not reached yet".
            {"checkpoint_event_id": "1" * 40, "checkpoint_hash": "a" * 64},
            {"checkpoint_event_id": "2",
             "checkpoint_hash": self.events[0]["event_hash"]},
            {"checkpoint_event_id": "0", "checkpoint_hash": "a" * 64},
            {"checkpoint_event_id": "1",
             "checkpoint_hash": self.events[1]["event_hash"]},
        ):
            status, body = self.svc.export_audit_events(params)
            self.assertEqual(status, 409, params)
            self.assertEqual(body, {"error": "checkpoint_conflict"}, params)
        # A conflict changes nothing: no events, no generation, same head.
        self.assertEqual(len(self.store.audit_events), 3)
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(
            self.store.audit_checkpoint, audit.make_checkpoint(self.events)
        )

    def test_pinned_pages_stable_across_appends(self) -> None:
        pin = self._pin(2)
        _, before = self.svc.export_audit_events({**pin, "limit": "1"})
        # Later ledger changes append audit events; the pinned prefix and its
        # authentication must not move.
        self.svc.register_trust_source(
            {"source": "late", "public_key": "e" * 64, "expires_at": FUTURE}
        )
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        _, after = self.svc.export_audit_events({**pin, "limit": "1"})
        self.assertEqual(before, after)
        self.assertEqual(after["total"], 2)
        self.assertEqual(after["checkpoint_auth"]["key_version"], 1)

    def test_key_version_tracks_checkpoint_activation(self) -> None:
        # Rotate at event 4; a checkpoint at or after the rotation is signed
        # by v2, an older checkpoint stays with v1.
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        self.assertEqual(self.store.audit_signer["activated_event_id"], 4)
        _, old_page = self.svc.export_audit_events(self._pin(3))
        self.assertEqual(old_page["checkpoint_auth"]["key_version"], 1)
        _, new_page = self.svc.export_audit_events(self._pin(4))
        self.assertEqual(new_page["checkpoint_auth"]["key_version"], 2)
        # Both envelopes verify offline against a trust document that knows
        # the respective signer set.
        trust = self.svc.get_trust_document()[1]
        self.assertTrue(audit.verify_export(new_page, trust)["ok"])
        old_trust = {
            "genesis_hash": trust["genesis_hash"],
            "audit_signers": trust["audit_signers"][:1],
        }
        self.assertTrue(audit.verify_export(old_page, old_trust)["ok"])

    def test_pinned_export_reproducible_after_restart(self) -> None:
        self.svc.rotate_audit_signer(
            {"private_key": PRIV_B, "expected_version": 1}
        )
        pin = self._pin(2)
        _, before = self.svc.export_audit_events({**pin, "limit": "1"})
        reopened = LedgerStore(
            os.path.join(self.tmp, "state.json"), initial_balance=1000
        )
        svc2 = LedgerService(reopened, initial_balance=1000)
        _, after = svc2.export_audit_events({**pin, "limit": "1"})
        self.assertEqual(before, after)
        self.assertEqual(after["checkpoint_auth"]["key_version"], 1)
        # The rotated-away seed was retained durably.
        self.assertEqual(sorted(reopened.audit_signer_keys), [1, 2])


class HTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.svc.register_trust_source(
            {"source": "n1", "public_key": "a" * 64, "expires_at": FUTURE}
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _get(self, path: str):
        request = urllib.request.Request(self.base + path, method="GET")
        try:
            with urllib.request.urlopen(request) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_pinned_export_and_errors(self) -> None:
        event_hash = self.svc.store.audit_events[0]["event_hash"]
        status, page = self._get(
            f"/v1/audit/export?checkpoint_event_id=1&checkpoint_hash={event_hash}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 1)
        self.assertEqual(
            page["checkpoint"], {"event_id": 1, "event_hash": event_hash}
        )
        # A lone parameter is 400 input.
        status, body = self._get("/v1/audit/export?checkpoint_event_id=1")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "input"})
        status, body = self._get(f"/v1/audit/export?checkpoint_hash={event_hash}")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "input"})
        # Repeated checkpoint parameters are 400 input (even identical ones).
        status, body = self._get(
            "/v1/audit/export?checkpoint_event_id=1&checkpoint_event_id=1"
            f"&checkpoint_hash={event_hash}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "input"})
        status, body = self._get(
            f"/v1/audit/export?checkpoint_event_id=1&checkpoint_hash={event_hash}"
            f"&checkpoint_hash={event_hash}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "input"})
        # A hash that does not match the recorded event is 409.
        status, body = self._get(
            "/v1/audit/export?checkpoint_event_id=1&checkpoint_hash=" + "b" * 64
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "checkpoint_conflict"})
        # Repeated legacy parameters keep their existing rejection.
        status, body = self._get("/v1/audit/export?cursor=0&cursor=0")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "query parameters must not be repeated"})


class CLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = make_service(self.tmp)
        self.svc.register_trust_source(
            {"source": "n1", "public_key": "a" * 64, "expires_at": FUTURE}
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

    def test_cli_checkpoint_flags(self) -> None:
        event_hash = self.svc.store.audit_events[0]["event_hash"]
        rc, line = self._cli(
            "audit-export",
            "--checkpoint-event-id", "1",
            "--checkpoint-hash", event_hash,
        )
        self.assertEqual(rc, 0, line)
        page = json.loads(line)
        self.assertEqual(page["total"], 1)
        self.assertEqual(
            page["checkpoint"], {"event_id": 1, "event_hash": event_hash}
        )

        # Only one of the pair: a single JSON error line and exit 1.
        rc, line = self._cli("audit-export", "--checkpoint-event-id", "1")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"error": "input"})
        rc, line = self._cli("audit-export", "--checkpoint-hash", event_hash)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"error": "input"})

        # A malformed value and a server conflict likewise exit 1.
        rc, line = self._cli(
            "audit-export",
            "--checkpoint-event-id", "01",
            "--checkpoint-hash", event_hash,
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"error": "input"})
        rc, line = self._cli(
            "audit-export",
            "--checkpoint-event-id", "1",
            "--checkpoint-hash", "c" * 64,
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"error": "checkpoint_conflict"})

        # No flags: the legacy unpinned export is unchanged.
        rc, line = self._cli("audit-export")
        self.assertEqual(rc, 0, line)
        self.assertEqual(json.loads(line)["total"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
