"""Tests for GET /v1/forks/sync/history — the sync lifecycle history query.

The history is backed by the append-only audit log and returns one row per
durable sync_received / sync_adopted / sync_expired event, each carrying the
tip summary frozen when the event was recorded. These tests cover parameter
validation (tip_hash/kind 400 vs. unknown-empty-page, strict non-negative
decimal parsing with no leading zeros/signs/whitespace/decimals, repeated
query parameters, limit 1-200 defaulting to 50, min_height > max_height and
cursor > total -> 400, cursor == total -> empty page), the
(height, tip_hash, source, request_id, event_id) ordering, pagination via
next_cursor, frozen-summary immutability across adoption and expiry (an
adopted-then-expired record leaves the canonical chain untouched), restart
persistence and legacy-snapshot compatibility (records/events written before
frozen summaries still load and resolve), plus the HTTP and CLI surfaces.

Run: python3 tests/sync_history_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    msg = crypto.canonical_message(sender, to, amount)
    return Transaction.from_dict(
        {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}
    )


def make_fork(genesis: Block, blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class HistoryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self._trust_seq = 0

    def _trust(self, source: str) -> None:
        self._trust_seq += 1
        key_hex = format(0x1000 + self._trust_seq, "064x")
        status, _ = self.svc.register_trust_source(
            {
                "source": source,
                "public_key": key_hex,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        self.assertIn(status, (200, 201))

    def _block1(self, amount: int, to: str | None = None, *, status: str = "confirmed") -> Block:
        return Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, to or self.B, amount)],
            status,
        )

    def _sync_block1(
        self, source: str, request_id: str, amount: int, to: str | None = None
    ) -> dict:
        self._trust(source)
        block = self._block1(amount, to)
        status, body = self.svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork(self.genesis, [self.genesis, block]),
            }
        )
        self.assertEqual(status, 201, body)
        return body

    def _history(self, **params) -> tuple[int, dict]:
        return self.svc.list_fork_sync_history(params)

    # -- basics / validation ------------------------------------------------

    def test_empty_history_is_empty_page(self) -> None:
        status, body = self._history()
        self.assertEqual(status, 200)
        self.assertEqual(body, {"items": [], "total": 0, "next_cursor": None})

    def test_unknown_tip_hash_is_empty_page_malformed_is_400(self) -> None:
        status, body = self._history(tip_hash="f" * 64)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        for bad in ("", "z" * 64, "A" * 64, "0" * 63, "0" * 65, "  " + "0" * 64, 123):
            self.assertEqual(self._history(tip_hash=bad)[0], 400, bad)

    def test_kind_filter_and_unknown_kind_400(self) -> None:
        self._sync_block1("node-1", "r1", 10)
        for kind in ("sync_received", "sync_adopted", "sync_expired"):
            status, body = self._history(kind=kind)
            self.assertEqual(status, 200)
        self.assertEqual(self._history(kind="sync_adopted")[1]["total"], 0)
        self.assertEqual(self._history(kind="sync_received")[1]["total"], 1)
        for bad in ("received", "SYNC_RECEIVED", "", "sync_received "):
            self.assertEqual(self._history(kind=bad)[0], 400, bad)

    def test_numeric_params_strict_decimal(self) -> None:
        bad_values = ("01", "-1", "+1", "1 ", " 1", "1.0", "x", "")
        for name in ("min_height", "max_height", "cursor"):
            for bad in bad_values:
                self.assertEqual(self._history(**{name: bad})[0], 400, (name, bad))
        for bad in ("0", "201", "01", "-1", "1.0"):
            self.assertEqual(self._history(limit=bad)[0], 400, bad)
        for good in ("1", "50", "200", "0"):
            # limit=0 is rejected; everything else parses (an over-total
            # cursor is validated separately below).
            status = self._history(
                **{"limit" if good in ("1", "50", "200") else "cursor": good}
            )[0]
            self.assertEqual(status, 200, good)

    def test_height_range_and_cursor_rules(self) -> None:
        self._sync_block1("node-1", "r1", 10)
        self.assertEqual(self._history(min_height="1", max_height="1")[1]["total"], 1)
        self.assertEqual(self._history(min_height="2")[1]["total"], 0)
        self.assertEqual(self._history(min_height="2", max_height="1")[0], 400)
        # cursor == total -> empty page; cursor > total -> 400.
        self.assertEqual(
            self._history(cursor="1")[1],
            {"items": [], "total": 1, "next_cursor": None},
        )
        self.assertEqual(self._history(cursor="2")[0], 400)

    # -- item shape / ordering / pagination ---------------------------------

    def test_received_row_shape_and_frozen_summary(self) -> None:
        body = self._sync_block1("node-1", "r1", 10)
        _, page = self._history()
        self.assertEqual(page["total"], 1)
        item = page["items"][0]
        self.assertEqual(
            set(item),
            {
                "event_id",
                "kind",
                "at",
                "source",
                "request_id",
                "tip_hash",
                "height",
                "length",
                "status",
                "expires_at",
            },
        )
        self.assertEqual(item["kind"], "sync_received")
        self.assertEqual(item["event_id"], 2)  # event 1 is source_registered
        self.assertEqual(item["source"], "node-1")
        self.assertEqual(item["request_id"], "r1")
        self.assertEqual(item["tip_hash"], body["tip_hash"])
        self.assertEqual(item["height"], 1)
        self.assertEqual(item["length"], 2)
        self.assertEqual(item["status"], "confirmed")
        self.assertEqual(item["expires_at"], body["expires_at"])
        self.assertIsInstance(item["at"], (int, float))

    def test_ordering_and_pagination(self) -> None:
        # Three height-1 tips from distinct sources plus one height-2 tip.
        b1 = self._sync_block1("s1", "r1", 10)
        b2 = self._sync_block1("s2", "r2", 20, self.C)
        b3 = self._sync_block1("s3", "r3", 30)
        # A two-block candidate: A->B 5 at height 1, then B->C 2 at height 2.
        self._trust("s4")
        h1 = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.B, 5)],
            "confirmed",
        )
        h2 = Block.create(
            2, h1.block_hash, [tx_obj(self.kb, self.B, self.C, 2)], "confirmed"
        )
        status, b4 = self.svc.submit_fork_sync(
            {
                "source": "s4",
                "request_id": "r4",
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork(self.genesis, [self.genesis, h1, h2]),
            }
        )
        self.assertEqual(status, 201, b4)

        _, page = self._history(limit="200")
        self.assertEqual(page["total"], 4)
        ordered = [
            (it["height"], it["tip_hash"], it["source"], it["request_id"], it["event_id"])
            for it in page["items"]
        ]
        self.assertEqual(ordered, sorted(ordered))
        # The height-2 row sorts last regardless of source/event order.
        self.assertEqual(page["items"][-1]["tip_hash"], b4["tip_hash"])
        # The three height-1 rows are tip_hash ordered.
        height1_tips = sorted([b1["tip_hash"], b2["tip_hash"], b3["tip_hash"]])
        self.assertEqual(
            [it["tip_hash"] for it in page["items"][:3]], height1_tips
        )
        # Pagination: pages of 2, next_cursor walks 0 -> 2 -> None.
        _, first = self._history(limit="2", cursor="0")
        self.assertEqual(len(first["items"]), 2)
        self.assertEqual(first["total"], 4)
        self.assertEqual(first["next_cursor"], 2)
        _, second = self._history(limit="2", cursor="2")
        self.assertEqual([it["tip_hash"] for it in second["items"]],
                         [it["tip_hash"] for it in page["items"][2:]])
        self.assertIsNone(second["next_cursor"])

    def test_source_filter(self) -> None:
        self._sync_block1("s1", "r1", 10)
        self._sync_block1("s2", "r2", 20)
        _, page = self._history(source="s1")
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["source"], "s1")
        self.assertEqual(self._history(source="")[0], 400)

    # -- lifecycle: adoption and expiry freeze past rows --------------------

    def test_adoption_adds_row_without_rewriting_received(self) -> None:
        # Canonical confirmed block 1 so a length-3 synced fork can win.
        canon = Block.create(
            1,
            self.genesis.block_hash,
            [tx_obj(self.ka, self.A, self.C, 1)],
            "confirmed",
        )
        self.store.chain.append(canon)
        self.store.rebuild_derived()
        self.store.save()
        f1 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)],
            "confirmed",
        )
        f2 = Block.create(
            2, f1.block_hash, [tx_obj(self.kb, self.B, self.C, 4)], "confirmed"
        )
        self._trust("node-1")
        status, body = self.svc.submit_fork_sync(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork(self.genesis, [self.genesis, f1, f2]),
            }
        )
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)

        _, page = self._history()
        kinds = [it["kind"] for it in page["items"]]
        self.assertIn("sync_received", kinds)
        self.assertIn("sync_adopted", kinds)
        received = next(it for it in page["items"] if it["kind"] == "sync_received")
        adopted = next(it for it in page["items"] if it["kind"] == "sync_adopted")
        # One adopted row per source provenance entry.
        self.assertEqual(kinds.count("sync_adopted"), 1)
        for row in (received, adopted):
            self.assertEqual(row["tip_hash"], tip)
            self.assertEqual(row["height"], 2)
            self.assertEqual(row["length"], 3)
            self.assertEqual(row["status"], "confirmed")
        self.assertNotEqual(received["event_id"], adopted["event_id"])

    def test_expiry_adds_row_and_keeps_frozen_history(self) -> None:
        exp = int(time.time()) + 3600
        body = self._sync_block1("node-1", "r1", 10)
        tip = body["tip_hash"]
        received_before = self._history(kind="sync_received")[1]["items"][0]

        # Force the record past its deadline in place of waiting for wall time.
        self.store.syncs[("node-1", "r1")]["expires_at"] = int(time.time()) - 5
        self.store.save()
        _, page = self._history()  # triggers the lazy sweep
        kinds = [it["kind"] for it in page["items"]]
        self.assertEqual(kinds, ["sync_received", "sync_expired"])
        expired = next(it for it in page["items"] if it["kind"] == "sync_expired")
        self.assertEqual(expired["tip_hash"], tip)
        self.assertEqual(expired["height"], 1)
        self.assertEqual(expired["length"], 2)
        self.assertEqual(expired["status"], "confirmed")
        # The received row is byte-for-byte the same history entry.
        received_after = self._history(kind="sync_received")[1]["items"][0]
        self.assertEqual(received_after, received_before)
        # Candidate and metadata are gone but history rows remain.
        self.assertNotIn(("node-1", "r1"), self.store.syncs)
        self.assertNotIn(tip, self.store.forks)
        # A second sweep produces no duplicate expiry event.
        self.assertEqual(
            self._history()[1]["items"].count(
                self._history(kind="sync_expired")[1]["items"][0]
            ),
            1,
        )

    def test_adopted_tip_expiry_leaves_canonical_and_history(self) -> None:
        # Canonical length 2; synced fork length 3 wins and is adopted.
        c1 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.C, 1)],
            "confirmed",
        )
        c2 = Block.create(
            2, c1.block_hash, [tx_obj(self.ka, self.A, self.C, 1)], "confirmed"
        )
        self.store.chain.extend([c1, c2])
        self.store.rebuild_derived()
        self.store.save()
        f1 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 10)],
            "confirmed",
        )
        f2 = Block.create(
            2, f1.block_hash, [tx_obj(self.kb, self.B, self.C, 4)], "confirmed"
        )
        f3 = Block.create(
            3, f2.block_hash, [tx_obj(self.kc, self.C, self.B, 1)], "confirmed"
        )
        self._trust("node-1")
        status, body = self.svc.submit_fork_sync(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork(self.genesis, [self.genesis, f1, f2, f3]),
            }
        )
        self.assertEqual(status, 201, body)
        tip = body["tip_hash"]
        self.assertEqual(self.svc.adopt_fork(tip)[0], 200)
        # Expire the now-adopted record; canonical must not change.
        self.store.syncs[("node-1", "req-1")]["expires_at"] = int(time.time()) - 5
        self.store.save()
        self._history()
        self.assertEqual(self.store.tip_hash(), tip)
        kinds = [it["kind"] for it in self._history()[1]["items"]]
        self.assertEqual(
            sorted(kinds), ["sync_adopted", "sync_expired", "sync_received"]
        )

    # -- restart persistence and legacy compatibility -----------------------

    def test_history_survives_restart(self) -> None:
        body = self._sync_block1("node-1", "r1", 10)
        tip = body["tip_hash"]
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        rec = data["syncs"][0]
        for field in ("height", "length", "status"):
            self.assertIn(field, rec)
        self.assertEqual((rec["height"], rec["length"], rec["status"]), (1, 2, "confirmed"))

        reopened = LedgerStore(self.state_path, initial_balance=1000)
        svc2 = LedgerService(reopened, initial_balance=1000)
        _, page = svc2.list_fork_sync_history({})
        self.assertEqual(page["total"], 1)
        item = page["items"][0]
        self.assertEqual(item["tip_hash"], tip)
        self.assertEqual((item["height"], item["length"], item["status"]),
                         (1, 2, "confirmed"))

    def test_legacy_snapshot_without_frozen_summaries_loads(self) -> None:
        self._sync_block1("node-1", "r1", 10)
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        # Simulate a pre-feature snapshot: no frozen summary anywhere and no
        # audit hash chain/checkpoint (older on-disk format).
        for rec in data["syncs"]:
            for field in ("height", "length", "status"):
                rec.pop(field, None)
        for event in data["audit_events"]:
            if event.get("kind") == "sync_received":
                for field in ("height", "length", "status"):
                    event.pop(field, None)
            for field in ("prev_hash", "event_hash"):
                event.pop(field, None)
        data.pop("audit_checkpoint", None)
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        reopened = LedgerStore(self.state_path, initial_balance=1000)
        # The legacy log is re-sealed and atomically persisted on recovery.
        self.assertIn("prev_hash", reopened.audit_events[0])
        self.assertEqual(reopened.audit_events[0]["prev_hash"], "0" * 64)
        # The live record is repaired from its surviving candidate.
        rec = reopened.syncs[("node-1", "r1")]
        self.assertEqual((rec["height"], rec["length"], rec["status"]),
                         (1, 2, "confirmed"))
        # The legacy event resolves live and still reports the right summary.
        svc2 = LedgerService(reopened, initial_balance=1000)
        _, page = svc2.list_fork_sync_history({})
        self.assertEqual(page["total"], 1)
        item = page["items"][0]
        self.assertEqual((item["height"], item["length"], item["status"]),
                         (1, 2, "confirmed"))

    def test_corrupt_history_metadata_fails_recovery(self) -> None:
        self._sync_block1("node-1", "r1", 10)
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["audit_events"][-1]["tip_hash"] = "z" * 64
        out = os.path.join(tempfile.mkdtemp(), "state.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        with self.assertRaises(StateRecoveryError):
            LedgerStore(out, initial_balance=1000)

    def test_backfilled_expiry_event_carries_frozen_summary(self) -> None:
        body = self._sync_block1("node-1", "r1", 10)
        tip = body["tip_hash"]
        with open(self.state_path, encoding="utf-8") as fh:
            data = json.load(fh)
        data["syncs"][0]["expires_at"] = int(time.time()) - 5
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)

        reopened = LedgerStore(self.state_path, initial_balance=1000)
        svc2 = LedgerService(reopened, initial_balance=1000)
        _, page = svc2.list_fork_sync_history({"kind": "sync_expired"})
        self.assertEqual(page["total"], 1)
        item = page["items"][0]
        self.assertEqual(item["tip_hash"], tip)
        self.assertEqual((item["height"], item["length"], item["status"]),
                         (1, 2, "confirmed"))


class HistoryHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.port = self.httpd.server_address[1]
        import threading

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def _get(self, query: str) -> tuple[int, dict]:
        url = f"http://127.0.0.1:{self.port}/v1/forks/sync/history{query}"
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:  # type: ignore[name-defined]
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_http_empty_page_and_repeated_param_400(self) -> None:
        status, body = self._get("")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        status, body = self._get("?limit=1&limit=2")
        self.assertEqual(status, 400)
        status, body = self._get("?cursor=00")
        self.assertEqual(status, 400)
        status, body = self._get("?tip_hash=zz")
        self.assertEqual(status, 400)
        status, body = self._get("?kind=nope")
        self.assertEqual(status, 400)


class HistoryCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.port = self.httpd.server_address[1]
        import threading

        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"--base-url=http://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def _run_cli(self, *args: str) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main([self.base, "sync-history", *args])
        return rc, json.loads(buf.getvalue())

    def test_cli_sync_history(self) -> None:
        rc, body = self._run_cli()
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 0)
        rc, body = self._run_cli("--kind", "sync_adopted")
        self.assertEqual(rc, 0)
        rc, _ = self._run_cli("--kind", "bogus")
        self.assertEqual(rc, 1)
        rc, _ = self._run_cli("--limit", "0")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
