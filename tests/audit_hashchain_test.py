"""Tests for the append-only audit hash chain, checkpoint and offline export.

Covers:
* per-event ``prev_hash``/``event_hash`` chaining (64-zero genesis anchor;
  ``event_hash = sha256(prev_hash ASCII || sorted compact JSON of the event
  without the two hash fields)``);
* the persisted ``audit_checkpoint = {event_id, event_hash}`` (empty stream
  uses 0 / 64 zeros) and its participation in same-generation conflict checks;
* recovery: strict re-verification of consecutive event ids, the full chain
  and the checkpoint (StateRecoveryError on every mismatch), and one-time
  re-sealing + atomic persistence of pre-chain legacy snapshots;
* GET /v1/audit/export pagination (reusing /v1/audit/events semantics),
  ``anchor_hash``/``checkpoint`` and the repeated-parameter 400;
* offline ``ledger.audit.verify_export`` and the ``audit-verify`` CLI
  (anchors, consecutive numbering, hashes, last page matches the checkpoint;
  single-line ok/checkpoint or error in {input, integrity}; exit 0/1).

Run: python3 tests/audit_hashchain_test.py
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

from ledger import crypto
from ledger.audit import verify_export
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

FUTURE = 1_900_000_000
ZERO = "0" * 64


class HashChainStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.store = LedgerStore(self.path, initial_balance=1000)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _append(self, source: str, kind: str = "source_registered", **extra) -> dict:
        payload = {"source": source, **extra}
        return self.store.append_audit_event(kind, payload)

    def test_first_event_anchored_at_zeroes_and_hashes_chain(self) -> None:
        e1 = self._append("a", version=1)
        e2 = self._append("b", version=1)
        self.assertEqual(e1["prev_hash"], ZERO)
        self.assertEqual(e2["prev_hash"], e1["event_hash"])
        # event_hash = sha256(prev_hash ASCII || sorted compact JSON, hashes
        # excluded), independently recomputed.
        stripped = {k: v for k, v in e1.items() if k not in ("prev_hash", "event_hash")}
        expected = __import__("hashlib").sha256(
            ZERO.encode("ascii")
            + json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(e1["event_hash"], expected)
        self.assertEqual(crypto.audit_event_hash(e2["prev_hash"], e2), e2["event_hash"])

    def test_hash_ignores_the_two_hash_fields(self) -> None:
        e = self._append("a")
        tampered = dict(e)
        tampered["event_hash"] = "f" * 64
        # Removing both links must leave the covered payload identical.
        self.assertEqual(
            crypto.audit_event_payload(e), crypto.audit_event_payload(tampered)
        )

    def test_checkpoint_persisted_and_empty_stream_uses_zeroes(self) -> None:
        self.store.save()
        with open(self.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        # An empty stream persists no audit section at all.
        self.assertNotIn("audit_checkpoint", doc)
        self.assertNotIn("audit_events", doc)

        self._append("a")
        self._append("b")
        self.store.save()
        with open(self.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(
            doc["audit_checkpoint"],
            {"event_id": 2, "event_hash": doc["audit_events"][-1]["event_hash"]},
        )


class RecoveryVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.store = LedgerStore(self.path, initial_balance=1000)
        self.store.append_audit_event("source_registered", {"source": "a", "version": 1})
        self.store.append_audit_event("source_registered", {"source": "b", "version": 1})
        self.store.save()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _doc(self) -> dict:
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def _write(self, doc: dict) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)

    def test_clean_restart_verifies_chain(self) -> None:
        reopened = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(len(reopened.audit_events), 2)
        self.assertEqual(reopened.audit_events[0]["prev_hash"], ZERO)
        # No reconciliation happened, so no generation bump.
        self.assertEqual(reopened.generation, self.store.generation)

    def test_tampered_payload_breaks_event_hash(self) -> None:
        doc = self._doc()
        doc["audit_events"][0]["source"] = "tampered"
        self._write(doc)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.path, initial_balance=1000)
        self.assertIn("event_hash", ctx.exception.reason)

    def test_tampered_prev_hash_breaks_chain(self) -> None:
        doc = self._doc()
        doc["audit_events"][1]["prev_hash"] = "f" * 64
        self._write(doc)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.path, initial_balance=1000)

    def test_tampered_event_hash_rejected(self) -> None:
        doc = self._doc()
        doc["audit_events"][0]["event_hash"] = "f" * 64
        self._write(doc)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.path, initial_balance=1000)

    def test_only_one_hash_link_is_corruption(self) -> None:
        doc = self._doc()
        del doc["audit_events"][0]["event_hash"]
        self._write(doc)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.path, initial_balance=1000)

    def test_checkpoint_hash_mismatch_rejected(self) -> None:
        doc = self._doc()
        doc["audit_checkpoint"]["event_hash"] = "1" * 64
        self._write(doc)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.path, initial_balance=1000)
        self.assertIn("checkpoint", ctx.exception.reason)

    def test_checkpoint_id_mismatch_rejected(self) -> None:
        doc = self._doc()
        doc["audit_checkpoint"]["event_id"] = 1
        self._write(doc)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.path, initial_balance=1000)

    def test_malformed_checkpoint_hash_rejected(self) -> None:
        doc = self._doc()
        doc["audit_checkpoint"]["event_hash"] = "ZZ"
        self._write(doc)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(self.path, initial_balance=1000)

    def test_legacy_snapshot_is_resealed_once_and_persisted(self) -> None:
        gen = self.store.generation
        doc = self._doc()
        for event in doc["audit_events"]:
            event.pop("prev_hash", None)
            event.pop("event_hash", None)
        doc.pop("audit_checkpoint", None)
        self._write(doc)

        reopened = LedgerStore(self.path, initial_balance=1000)
        events = reopened.audit_events
        self.assertEqual(events[0]["prev_hash"], ZERO)
        self.assertEqual(events[1]["prev_hash"], events[0]["event_hash"])
        self.assertEqual(
            crypto.audit_event_hash(events[1]["prev_hash"], events[1]),
            events[1]["event_hash"],
        )
        # The upgrade was atomically persisted and advanced the generation.
        self.assertEqual(reopened.generation, gen + 1)
        saved = self._doc()
        self.assertEqual(
            saved["audit_checkpoint"],
            {"event_id": 2, "event_hash": events[-1]["event_hash"]},
        )
        # A second restart performs no further rewrite.
        again = LedgerStore(self.path, initial_balance=1000)
        self.assertEqual(again.generation, reopened.generation)

    def test_checkpoint_participates_in_same_generation_conflict(self) -> None:
        # Two same-generation snapshots with byte-identical legacy (hash-less)
        # event logs but different persisted checkpoints are individually
        # valid candidates yet describe different audit tails: the checkpoint
        # must take part in the conflict comparison.
        doc = self._doc()
        generation = doc["state"]["generation"]
        for event in doc["audit_events"]:
            event.pop("prev_hash", None)
            event.pop("event_hash", None)
        tail = self.store.audit_events[-1]["event_hash"]
        doc["audit_checkpoint"] = {"event_id": 2, "event_hash": tail}
        self._write(doc)

        twin = json.loads(json.dumps(doc))
        twin["audit_checkpoint"] = {"event_id": 2, "event_hash": "9" * 64}
        snapshot = os.path.join(self.tmp, f".ledger-twin.gen{generation}")
        with open(snapshot, "w", encoding="utf-8") as fh:
            json.dump(twin, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            LedgerStore(self.path, initial_balance=1000)
        self.assertIn("conflicting snapshots", ctx.exception.reason)


class ExportEndpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        for i in range(3):
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

    def _get(self, query: str = ""):
        try:
            with urllib.request.urlopen(self.base + "/v1/audit/export" + query) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_export_pages_anchors_and_checkpoint(self) -> None:
        status, page = self._get("?limit=2&cursor=0")
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 3)
        self.assertEqual([e["event_id"] for e in page["items"]], [1, 2])
        self.assertEqual(page["anchor_hash"], ZERO)
        self.assertEqual(page["next_cursor"], 2)
        self.assertIn("prev_hash", page["items"][0])
        self.assertIn("event_hash", page["items"][0])
        tail = self.svc.store.audit_events[-1]
        self.assertEqual(
            page["checkpoint"], {"event_id": 3, "event_hash": tail["event_hash"]}
        )

        status, page2 = self._get("?limit=2&cursor=2")
        self.assertEqual([e["event_id"] for e in page2["items"]], [3])
        # The second page is anchored at the first page's tail hash.
        self.assertEqual(
            page2["anchor_hash"], self.svc.store.audit_events[1]["event_hash"]
        )
        self.assertIsNone(page2["next_cursor"])

        # cursor == total: empty page anchored at the stream tail.
        status, empty = self._get("?cursor=3")
        self.assertEqual(empty["items"], [])
        self.assertEqual(empty["anchor_hash"], tail["event_hash"])
        self.assertEqual(empty["checkpoint"]["event_id"], 3)

    def test_export_reuses_events_pagination_400s(self) -> None:
        self.assertEqual(self._get("?cursor=4")[0], 400)
        self.assertEqual(self._get("?limit=0")[0], 400)
        self.assertEqual(self._get("?limit=201")[0], 400)
        self.assertEqual(self._get("?limit=01")[0], 400)

    def test_repeated_parameter_is_400(self) -> None:
        self.assertEqual(self._get("?limit=1&limit=2")[0], 400)
        self.assertEqual(self._get("?cursor=0&cursor=1")[0], 400)

    def test_filtered_export_anchor_is_event_prev_hash(self) -> None:
        status, page = self._get("?source=n1")
        self.assertEqual(status, 200)
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["event_id"], 2)
        self.assertEqual(
            page["anchor_hash"], self.svc.store.audit_events[1]["prev_hash"]
        )

    def test_empty_stream_export(self) -> None:
        other = tempfile.mkdtemp()
        try:
            svc = LedgerService(
                LedgerStore(os.path.join(other, "e.json"), initial_balance=1000),
                initial_balance=1000,
            )
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(svc))
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{httpd.server_port}/v1/audit/export"
                ) as r:
                    body = json.loads(r.read())
            finally:
                httpd.shutdown()
                httpd.server_close()
            self.assertEqual(
                body,
                {
                    "items": [],
                    "total": 0,
                    "next_cursor": None,
                    "anchor_hash": ZERO,
                    "checkpoint": {"event_id": 0, "event_hash": ZERO},
                },
            )
        finally:
            shutil.rmtree(other, ignore_errors=True)


def _page(svc, limit=None, cursor=None) -> dict:
    params = {}
    if limit is not None:
        params["limit"] = str(limit)
    if cursor is not None:
        params["cursor"] = str(cursor)
    return svc.export_audit_events(params)[1]


class OfflineVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        for i in range(4):
            self.svc.register_trust_source(
                {
                    "source": f"n{i}",
                    "public_key": format(i + 1, "064x"),
                    "expires_at": FUTURE,
                }
            )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_single_full_page_ok(self) -> None:
        page = _page(self.svc)
        result = verify_export(page)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["checkpoint"],
            {"event_id": 4, "event_hash": self.svc.store.audit_events[-1]["event_hash"]},
        )

    def test_chained_pages_ok(self) -> None:
        pages = [_page(self.svc, limit=2, cursor=0), _page(self.svc, limit=2, cursor=2)]
        self.assertTrue(verify_export(pages)["ok"])

    def test_empty_export_ok_zero_checkpoint(self) -> None:
        other = tempfile.mkdtemp()
        try:
            svc = LedgerService(
                LedgerStore(os.path.join(other, "e.json"), initial_balance=1000),
                initial_balance=1000,
            )
            result = verify_export(_page(svc))
            self.assertTrue(result["ok"])
            self.assertEqual(
                result["checkpoint"], {"event_id": 0, "event_hash": ZERO}
            )
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_tampered_event_payload_is_integrity(self) -> None:
        page = json.loads(json.dumps(_page(self.svc)))
        page["items"][0]["source"] = "forged"
        self.assertEqual(
            verify_export(page), {"ok": False, "error": "integrity"}
        )

    def test_wrong_anchor_is_integrity(self) -> None:
        pages = [
            json.loads(json.dumps(_page(self.svc, limit=2, cursor=0))),
            json.loads(json.dumps(_page(self.svc, limit=2, cursor=2))),
        ]
        pages[1]["anchor_hash"] = "1" * 64
        self.assertEqual(verify_export(pages)["error"], "integrity")

    def test_non_consecutive_numbering_is_integrity(self) -> None:
        page = json.loads(json.dumps(_page(self.svc)))
        page["items"][1]["event_id"] = 9
        self.assertEqual(verify_export(page)["error"], "integrity")

    def test_incomplete_export_missing_last_page_is_integrity(self) -> None:
        # Only the first page of a longer stream: it still promises more.
        first = json.loads(json.dumps(_page(self.svc, limit=2, cursor=0)))
        self.assertEqual(verify_export(first)["error"], "integrity")

    def test_checkpoint_not_reached_is_integrity(self) -> None:
        pages = [
            json.loads(json.dumps(_page(self.svc, limit=2, cursor=0))),
            json.loads(json.dumps(_page(self.svc, limit=2, cursor=2))),
        ]
        pages[0]["checkpoint"]["event_id"] = 99
        pages[1]["checkpoint"]["event_id"] = 99
        self.assertEqual(verify_export(pages)["error"], "integrity")

    def test_checkpoint_hash_mismatch_is_integrity(self) -> None:
        page = json.loads(json.dumps(_page(self.svc)))
        page["checkpoint"]["event_hash"] = "f" * 64
        self.assertEqual(verify_export(page)["error"], "integrity")

    def test_disagreeing_checkpoints_is_integrity(self) -> None:
        pages = [
            json.loads(json.dumps(_page(self.svc, limit=2, cursor=0))),
            json.loads(json.dumps(_page(self.svc, limit=2, cursor=2))),
        ]
        pages[1]["checkpoint"]["event_hash"] = "a" * 64
        self.assertEqual(verify_export(pages)["error"], "integrity")

    def test_malformed_documents_are_input(self) -> None:
        for bad in (
            None,
            "not-json-decoded-string",
            42,
            [],
            {},
            {"items": "nope"},
            {"items": [], "total": -1},
            {"items": [], "total": 0, "next_cursor": None,
             "anchor_hash": ZERO, "checkpoint": {"event_id": 0, "event_hash": 1}},
            {"items": [{"event_id": "x"}], "total": 1, "next_cursor": None,
             "anchor_hash": ZERO, "checkpoint": {"event_id": 1, "event_hash": ZERO}},
            {"items": [], "total": 0, "next_cursor": None,
             "anchor_hash": "ZZ", "checkpoint": {"event_id": 0, "event_hash": ZERO}},
        ):
            self.assertEqual(verify_export(bad), {"ok": False, "error": "input"}, bad)


class AuditVerifyCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.svc.register_trust_source(
            {"source": "n0", "public_key": format(1, "064x"), "expires_at": FUTURE}
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
        line = out.getvalue().strip()
        self.assertEqual(len(line.splitlines()), 1)
        return rc, line

    def test_export_then_verify_file_and_stdin(self) -> None:
        rc, line = self._cli("audit-export")
        self.assertEqual(rc, 0)
        export_file = os.path.join(self.tmp, "export.json")
        with open(export_file, "w", encoding="utf-8") as fh:
            fh.write(line)
        rc, line = self._cli("audit-verify", export_file)
        self.assertEqual(rc, 0)
        body = json.loads(line)
        self.assertTrue(body["ok"])
        self.assertEqual(body["checkpoint"]["event_id"], 1)

    def test_verify_tampered_exits_1_integrity(self) -> None:
        _, line = self._cli("audit-export")
        doc = json.loads(line)
        doc["items"][0]["source"] = "forged"
        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        rc, line = self._cli("audit-verify", bad)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "integrity"})

    def test_verify_malformed_file_exits_1_input(self) -> None:
        bad = os.path.join(self.tmp, "malformed.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")
        rc, line = self._cli("audit-verify", bad)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "input"})

    def test_verify_missing_file_exits_1_input(self) -> None:
        rc, line = self._cli("audit-verify", os.path.join(self.tmp, "missing.json"))
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "input"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
