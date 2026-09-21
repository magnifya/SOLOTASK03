"""Tests for GET /v1/forks/sync/history — the sync lifecycle history listing.

Covers the item shape ({event_id, kind, at, source, request_id, tip_hash,
height, length, status, expires_at}), the filters (source, tip_hash, kind,
min_height, max_height) with their 400 rules (malformed tip_hash, unknown
kind, strict decimals, min_height > max_height), the (height, tip_hash,
source, request_id, event_id) ordering, items/total/next_cursor pagination
(cursor == total -> empty page, cursor > total -> 400, repeated parameters
-> 400 at the HTTP layer), the reception-time frozen summary (adoption,
expiry and even a later canonical confirm never rewrite it), retry
idempotency (no duplicate events), and restart recovery (history metadata
survives; a downtime expiry is backfilled once with the frozen summary).

Run: python3 tests/sync_history_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


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


def make_fork(blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class SyncHistoryServiceTests(unittest.TestCase):
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
        self._trusted: set[str] = set()
        self._trust_seq = 0

    def _trust(self, source: str) -> None:
        if source in self._trusted:
            return
        self._trust_seq += 1
        status, body = self.svc.register_trust_source(
            {
                "source": source,
                "public_key": format(0x1000 + self._trust_seq, "064x"),
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        self.assertIn(status, (200, 201), body)
        self._trusted.add(source)

    def sync(
        self,
        blocks: list[Block],
        *,
        source: str = "node-1",
        request_id: str = "req-1",
        expires_at: int | None = None,
    ) -> tuple[int, dict]:
        if expires_at is None:
            expires_at = int(time.time()) + 3600
        self._trust(source)
        return self.svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": make_fork(blocks),
            }
        )

    def fork1(self, amount: int = 10, *, status: str = "confirmed") -> list[Block]:
        block = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, amount)], status
        )
        return [self.genesis, block]

    def fork2(self) -> list[Block]:
        first = self.fork1()
        second = Block.create(
            2, first[-1].block_hash, [tx_obj(self.kb, self.B, self.A, 5)]
        )
        return first + [second]

    def history(self, **params: str) -> tuple[int, dict]:
        return self.svc.list_fork_sync_history(params)

    # -- shape and frozen summary -------------------------------------------

    def test_received_event_carries_all_fields(self) -> None:
        fork = self.fork1()
        exp = int(time.time()) + 3600
        status, _ = self.sync(fork, expires_at=exp)
        self.assertEqual(status, 201)
        status, body = self.history()
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        item = body["items"][0]
        self.assertEqual(
            item,
            {
                "event_id": 2,  # event 1 is the trust registration
                "kind": "sync_received",
                "at": item["at"],
                "source": "node-1",
                "request_id": "req-1",
                "tip_hash": fork[-1].block_hash,
                "height": 1,
                "length": 2,
                "status": "confirmed",
                "expires_at": exp,
            },
        )
        self.assertIsInstance(item["at"], (int, float))

    def test_adoption_appends_one_event_per_source_with_frozen_summary(self) -> None:
        fork = self.fork2()
        self.sync(fork, source="node-1", request_id="r1")
        self._trust("node-2")
        # A second source delivering the identical tip gets its own record via
        # a distinct request key... but the duplicate tip conflicts, so deliver
        # the same content only from node-1 and check the single adoption row.
        status, _ = self.svc.adopt_fork(fork[-1].block_hash)
        self.assertEqual(status, 200)
        status, body = self.history(kind="sync_adopted")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        item = body["items"][0]
        self.assertEqual(item["source"], "node-1")
        self.assertEqual(item["request_id"], "r1")
        self.assertEqual(item["tip_hash"], fork[-1].block_hash)
        self.assertEqual(
            (item["height"], item["length"], item["status"]), (2, 3, "confirmed")
        )
        self.assertIsInstance(item["expires_at"], int)

    def test_frozen_summary_survives_later_canonical_confirm(self) -> None:
        # Receive and adopt a fork whose tip is pending, then confirm the
        # canonical tip: the history rows must keep the reception-time
        # "pending" status — adoption or later chain changes never rewrite it.
        fork = self.fork1(status="pending")
        self.sync(fork, source="node-1", request_id="r1")
        status, _ = self.svc.adopt_fork(fork[-1].block_hash)
        self.assertEqual(status, 200)
        status, _ = self.svc.confirm_block("1")
        self.assertEqual(status, 200)
        self.assertEqual(self.store.chain[1].status, "confirmed")
        status, body = self.history(tip_hash=fork[-1].block_hash)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        for item in body["items"]:
            self.assertEqual(item["status"], "pending")
            self.assertEqual((item["height"], item["length"]), (1, 2))

    def test_expiry_appends_one_event_with_frozen_summary(self) -> None:
        fork = self.fork1()
        exp = int(time.time()) + 1
        self.sync(fork, source="node-1", request_id="r1", expires_at=exp)
        time.sleep(1.1)
        status, body = self.history(kind="sync_expired")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        item = body["items"][0]
        self.assertEqual(item["tip_hash"], fork[-1].block_hash)
        self.assertEqual(item["expires_at"], exp)
        self.assertEqual(
            (item["height"], item["length"], item["status"]), (1, 2, "confirmed")
        )
        # The candidate is gone but the full history remains queryable.
        status, body = self.history(tip_hash=fork[-1].block_hash)
        self.assertEqual(body["total"], 2)
        self.assertEqual([i["kind"] for i in body["items"]], ["sync_received", "sync_expired"])

    def test_adopted_tip_expiry_keeps_canonical_and_history(self) -> None:
        fork = self.fork2()
        exp = int(time.time()) + 1
        self.sync(fork, source="node-1", request_id="r1", expires_at=exp)
        status, _ = self.svc.adopt_fork(fork[-1].block_hash)
        self.assertEqual(status, 200)
        time.sleep(1.1)
        status, body = self.history(kind="sync_expired")
        self.assertEqual(body["total"], 1)
        # The adopted chain is untouched by the record's expiry.
        self.assertEqual(self.store.tip_hash(), fork[-1].block_hash)
        self.assertEqual(len(self.store.chain), 3)

    def test_retry_does_not_duplicate_events(self) -> None:
        fork = self.fork1()
        self.sync(fork, source="node-1", request_id="r1")
        status, body = self.history()
        first_total = body["total"]
        # Same key, same content: 200 replay, no new sync_received event.
        status, _ = self.sync(fork, source="node-1", request_id="r1")
        self.assertEqual(status, 200)
        status, body = self.history()
        self.assertEqual(body["total"], first_total)
        self.assertEqual(
            [i["kind"] for i in body["items"]].count("sync_received"), 1
        )

    # -- ordering and pagination --------------------------------------------

    def test_ordering_by_height_tip_source_request_event(self) -> None:
        fork_a = self.fork1(amount=11)
        fork_b = self.fork1(amount=22)
        fork_c = self.fork2()
        self.sync(fork_b, source="node-b", request_id="r1")
        self.sync(fork_a, source="node-a", request_id="r1")
        self.sync(fork_a, source="node-a", request_id="r2", expires_at=int(time.time()) + 3600)
        # Same tip from a second source conflicts; use distinct tips per source.
        self.sync(fork_c, source="node-c", request_id="r1")
        status, body = self.history()
        self.assertEqual(status, 200)
        keys = [
            (i["height"], i["tip_hash"], i["source"], i["request_id"], i["event_id"])
            for i in body["items"]
        ]
        self.assertEqual(keys, sorted(keys))
        # Height-1 rows precede the height-2 row.
        self.assertEqual(keys[-1][0], 2)

    def test_pagination(self) -> None:
        for n in range(3):
            self.sync(self.fork1(amount=n + 1), source="node-1", request_id=f"r{n}")
        status, body = self.history(limit="2")
        self.assertEqual(body["total"], 3)
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual(body["next_cursor"], 2)
        status, body = self.history(limit="2", cursor="2")
        self.assertEqual(len(body["items"]), 1)
        self.assertIsNone(body["next_cursor"])
        # cursor == total -> empty page; cursor > total -> 400.
        status, body = self.history(cursor="3")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        self.assertEqual(body["total"], 3)
        self.assertEqual(self.history(cursor="4")[0], 400)

    # -- filters and validation ---------------------------------------------

    def test_filters(self) -> None:
        fork_a = self.fork1(amount=1)
        fork_b = self.fork2()
        self.sync(fork_a, source="node-1", request_id="r1")
        self.sync(fork_b, source="node-2", request_id="r2")
        self.assertEqual(self.history(source="node-1")[1]["total"], 1)
        self.assertEqual(self.history(source="node-2")[1]["total"], 1)
        self.assertEqual(self.history(source="ghost")[1]["total"], 0)
        self.assertEqual(
            self.history(tip_hash=fork_a[-1].block_hash)[1]["total"], 1
        )
        self.assertEqual(self.history(min_height="2")[1]["total"], 1)
        self.assertEqual(self.history(max_height="1")[1]["total"], 1)
        self.assertEqual(
            self.history(min_height="1", max_height="2")[1]["total"], 2
        )
        self.assertEqual(self.history(kind="sync_received")[1]["total"], 2)
        self.assertEqual(self.history(kind="sync_adopted")[1]["total"], 0)

    def test_tip_hash_malformed_400_unknown_empty_page(self) -> None:
        self.sync(self.fork1())
        for bad in ("zz", "A" * 64, "a" * 63, "a" * 65, ""):
            self.assertEqual(self.history(tip_hash=bad)[0], 400, bad)
        status, body = self.history(tip_hash="0" * 64)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"items": [], "total": 0, "next_cursor": None})

    def test_kind_unknown_400(self) -> None:
        for bad in ("sync", "received", "source_registered", "", "SYNC_RECEIVED"):
            self.assertEqual(self.history(kind=bad)[0], 400, bad)
        for good in ("sync_received", "sync_adopted", "sync_expired"):
            self.assertEqual(self.history(kind=good)[0], 200, good)

    def test_numeric_params_strict(self) -> None:
        self.sync(self.fork1())
        for param in ("min_height", "max_height", "limit", "cursor"):
            for bad in ("01", "+1", "-1", "1.0", " 1", "1 ", "", "x", "0x1"):
                self.assertEqual(
                    self.history(**{param: bad})[0], 400, (param, bad)
                )
        # "0" itself is allowed where the range admits it.
        self.assertEqual(self.history(min_height="0")[0], 200)
        self.assertEqual(self.history(cursor="0")[0], 200)
        self.assertEqual(self.history(limit="0")[0], 400)
        self.assertEqual(self.history(limit="201")[0], 400)
        self.assertEqual(self.history(limit="200")[0], 200)
        self.assertEqual(self.history(min_height="2", max_height="1")[0], 400)

    def test_defaults_limit_50(self) -> None:
        for n in range(55):
            self.sync(self.fork1(amount=n + 1), source="node-1", request_id=f"r{n}")
        status, body = self.history()
        self.assertEqual(body["total"], 55)
        self.assertEqual(len(body["items"]), 50)
        self.assertEqual(body["next_cursor"], 50)

    # -- restart --------------------------------------------------------------

    def test_restart_preserves_history_and_backfills_expiry_once(self) -> None:
        fork = self.fork1()
        exp = int(time.time()) + 1
        self.sync(fork, source="node-1", request_id="r1", expires_at=exp)
        live = self.fork1(amount=99)
        self.sync(live, source="node-2", request_id="r2")
        time.sleep(1.1)
        # Restart: the downtime expiry is pruned and backfilled exactly once,
        # carrying the frozen summary; the live record survives.
        svc2 = LedgerService(LedgerStore(self.state_path))
        status, body = svc2.list_fork_sync_history({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)
        expired = [i for i in body["items"] if i["kind"] == "sync_expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["tip_hash"], fork[-1].block_hash)
        self.assertEqual(
            (expired[0]["height"], expired[0]["length"], expired[0]["status"]),
            (1, 2, "confirmed"),
        )
        self.assertEqual(expired[0]["expires_at"], exp)
        # A second restart neither re-derives nor duplicates the event.
        svc3 = LedgerService(LedgerStore(self.state_path))
        status, body = svc3.list_fork_sync_history({"kind": "sync_expired"})
        self.assertEqual(body["total"], 1)
        # Full history is stable across restarts, contract ordering included.
        status, again = svc3.list_fork_sync_history({})
        self.assertEqual(
            sorted((i["event_id"], i["kind"]) for i in again["items"]),
            [(2, "sync_received"), (4, "sync_received"), (5, "sync_expired")],
        )
        keys = [
            (i["height"], i["tip_hash"], i["source"], i["request_id"], i["event_id"])
            for i in again["items"]
        ]
        self.assertEqual(keys, sorted(keys))

    def test_restart_rejects_tampered_record_summary(self) -> None:
        fork = self.fork1()
        self.sync(fork, source="node-1", request_id="r1")
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        # Tamper with the frozen summary persisted on the sync record.
        doc["syncs"][0]["height"] = 999
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        # The tampered summary no longer matches the delivered candidate: the
        # record is dropped on recovery; the history event stays queryable.
        svc2 = LedgerService(LedgerStore(self.state_path))
        self.assertEqual(svc2.store.syncs, {})
        status, body = svc2.list_fork_sync_history({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["height"], 1)

    def test_restart_rejects_invalid_event_metadata(self) -> None:
        fork = self.fork1()
        self.sync(fork, source="node-1", request_id="r1")
        with open(self.state_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for event in doc["audit_events"]:
            if event["kind"] == "sync_received":
                event["height"] = -1
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        # Structurally invalid history metadata fails recovery outright.
        with self.assertRaises(ValueError):
            LedgerStore(self.state_path)


class SyncHistoryHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(LedgerStore(os.path.join(self.tmp, "state.json")))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(self.svc))
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def get(self, query: str) -> tuple[int, dict]:
        url = f"http://127.0.0.1:{self.port}/v1/forks/sync/history{query}"
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_route_and_empty_page(self) -> None:
        status, body = self.get("")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"items": [], "total": 0, "next_cursor": None})

    def test_repeated_parameter_is_400(self) -> None:
        for query in (
            "?limit=10&limit=20",
            "?cursor=0&cursor=0",
            "?source=a&source=b",
            "?kind=sync_received&kind=sync_adopted",
            "?tip_hash=" + "0" * 64 + "&tip_hash=" + "1" * 64,
            "?min_height=1&min_height=2",
            "?max_height=1&max_height=2",
        ):
            status, body = self.get(query)
            self.assertEqual(status, 400, query)
            self.assertIn("error", body)

    def test_query_reaches_service(self) -> None:
        status, body = self.get("?kind=sync_received&limit=10&cursor=0")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        self.assertEqual(self.get("?limit=01")[0], 400)
        self.assertEqual(self.get("?tip_hash=zz")[0], 400)


if __name__ == "__main__":
    unittest.main()
