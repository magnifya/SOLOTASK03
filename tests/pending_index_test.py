"""Tests for GET /v1/index/pending and the CLI ``pending`` subcommand.

The pending index merges the persisted mempool with the transactions packed
into the unconfirmed tip block — exactly the set that can still be packed,
cancelled, confirmed or rolled back — and never touches confirmed blocks or
candidate forks. Rows are ordered by ascending tx_id; the success body has
the contract-fixed key order ``generation, items, total, next_cursor`` and
each item the fixed order ``tx_id, from, to, amount, signature, status,
height, block_hash, index, location, nonce`` (mempool rows carry null
height/block_hash/index, pending-block rows their real position, legacy
transfers a null nonce). Covers the strict parameter rules (unknown /
repeated / empty / malformed -> 400 {"error": "input"}), direction/account
coupling, limit/cursor ranges, the generation pin (409 stale_snapshot, no
partial data), pagination, lifecycle transitions (mine/confirm/rollback/
cancel), restart rebuild, read-only behaviour and the HTTP/CLI surface.

Run: python3 tests/pending_index_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
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
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def signed_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(msg).hex(),
    }


def sequenced_payload(
    key: Ed25519PrivateKey, sender: str, to: str, amount: int, nonce: int
) -> dict:
    msg = crypto.sequenced_message(sender, to, amount, nonce)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "nonce": nonce,
        "signature": key.sign(msg).hex(),
    }


ITEM_KEYS = (
    "tx_id",
    "from",
    "to",
    "amount",
    "signature",
    "status",
    "height",
    "block_hash",
    "index",
    "location",
    "nonce",
)


class PendingIndexServiceTests(unittest.TestCase):
    """Pending-index semantics at service level."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(LedgerStore(cls.path), initial_balance=1000)
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls.kd, cls.D = keypair()

        # Block 1 (confirmed): A->B 10. Confirmed rows must never appear.
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.ka, cls.A, cls.B, 10))
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200

        # Pending tip block 2: B->A 5 (legacy) and C->A 2 (sequenced nonce 0).
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kb, cls.B, cls.A, 5))
        assert rc == 202
        rc, _ = cls.svc.submit_sequenced_transaction(
            sequenced_payload(cls.kc, cls.C, cls.A, 2, 0)
        )
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201

        # Mempool: D->A 50 (legacy) and A->D 7 (sequenced nonce 0).
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kd, cls.D, cls.A, 50))
        assert rc == 202
        rc, _ = cls.svc.submit_sequenced_transaction(
            sequenced_payload(cls.ka, cls.A, cls.D, 7, 0)
        )
        assert rc == 202

        cls.block2 = cls.svc.store.chain[2]
        assert cls.block2.status == "pending"

    def query(self, **params) -> tuple[int, dict]:
        return self.svc.list_pending_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def test_merges_mempool_and_pending_block_sorted_by_tx_id(self) -> None:
        status, body = self.query()
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 4)
        self.assertEqual(len(body["items"]), 4)
        ids = [item["tx_id"] for item in body["items"]]
        self.assertEqual(ids, sorted(ids))
        self.assertIsNone(body["next_cursor"])
        self.assertEqual(body["generation"], self.svc.store.generation)
        # Contract key order of the body and of every item.
        self.assertEqual(
            list(body), ["generation", "items", "total", "next_cursor"]
        )
        for item in body["items"]:
            self.assertEqual(list(item), list(ITEM_KEYS))
            self.assertEqual(item["status"], "pending")
        by_id = {item["tx_id"]: item for item in body["items"]}
        # The two pending-block rows carry their real in-block position.
        block_ids = [tx.tx_id for tx in self.block2.transactions]
        for index, tx_id in enumerate(block_ids):
            item = by_id[tx_id]
            self.assertEqual(item["location"], "pending_block")
            self.assertEqual(item["height"], 2)
            self.assertEqual(item["block_hash"], self.block2.block_hash)
            self.assertEqual(item["index"], index)
        # The two mempool rows carry nulls.
        for tx_id in self.svc.store.pending:
            item = by_id[tx_id]
            self.assertEqual(item["location"], "mempool")
            self.assertIsNone(item["height"])
            self.assertIsNone(item["block_hash"])
            self.assertIsNone(item["index"])
        # Nonce: null for legacy transfers, the sequence number otherwise.
        nonces = sorted(
            (item["nonce"] for item in body["items"]), key=lambda n: n is None
        )
        self.assertEqual(nonces[:2], [0, 0])
        self.assertIsNone(nonces[2])
        self.assertIsNone(nonces[3])

    def test_confirmed_chain_and_forks_excluded(self) -> None:
        status, body = self.query(account=self.B)
        self.assertEqual(status, 200)
        # B's confirmed A->B 10 (block 1) is invisible; only the pending
        # B->A 5 in the unconfirmed tip matches.
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["location"], "pending_block")
        self.assertEqual(body["items"][0]["amount"], 5)

    def test_account_and_direction_filters(self) -> None:
        # all: sender or recipient.
        status, body = self.query(account=self.A)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 4)
        # out: sender only.
        status, body = self.query(account=self.A, direction="out")
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["from"], self.A)
        self.assertEqual(body["items"][0]["nonce"], 0)
        # in: recipient only.
        status, body = self.query(account=self.A, direction="in")
        self.assertEqual(body["total"], 3)
        self.assertTrue(
            all(item["to"] == self.A for item in body["items"])
        )
        # direction=all explicitly behaves like the default.
        status, explicit = self.query(account=self.A, direction="all")
        status, default = self.query(account=self.A)
        self.assertEqual(explicit, default)
        self.assertEqual(explicit["total"], 4)
        # Unknown account: 200 with an empty set.
        status, body = self.query(account="f" * 64)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])

    def test_pagination(self) -> None:
        status, page1 = self.query(limit="1", cursor="0")
        self.assertEqual(status, 200)
        self.assertEqual(len(page1["items"]), 1)
        self.assertEqual(page1["total"], 4)
        self.assertEqual(page1["next_cursor"], 1)
        status, page2 = self.query(limit="1", cursor="1")
        self.assertEqual(page2["next_cursor"], 2)
        status, last = self.query(limit="3", cursor="1")
        self.assertEqual(len(last["items"]), 3)
        self.assertIsNone(last["next_cursor"])
        # cursor == total: an empty page, not an error.
        status, body = self.query(cursor="4")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        self.assertEqual(body["total"], 4)
        self.assertIsNone(body["next_cursor"])
        # Default limit is 50.
        status, body = self.query()
        self.assertEqual(len(body["items"]), 4)

    def test_validation_errors(self) -> None:
        cases = (
            {"unknown": "1"},
            {"account": ""},
            {"direction": ""},
            {"direction": "sideways", "account": self.A},
            {"direction": "in"},
            {"direction": "out"},
            {"direction": "in", "account": ""},
            {"limit": ""},
            {"limit": "0"},
            {"limit": "201"},
            {"limit": "01"},
            {"limit": "1.5"},
            {"limit": " 1"},
            {"limit": "١"},  # non-ASCII digit
            {"cursor": ""},
            {"cursor": "-1"},
            {"cursor": "00"},
            {"cursor": "5"},  # beyond the total of 4
            {"generation": ""},
            {"generation": "01"},
            {"generation": "-1"},
            {"generation": "abc"},
        )
        for params in cases:
            status, body = self.query(**params)
            self.assertEqual(status, 400, params)
            self.assertEqual(body, {"error": "input"}, params)

    def test_generation_pin(self) -> None:
        generation = self.svc.store.generation
        status, body = self.query(generation=str(generation))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["generation"], generation)
        self.assertEqual(body["total"], 4)
        # A stale or future generation answers 409 with no partial data.
        for stale in (generation - 1, generation + 1, 0):
            status, body = self.query(generation=str(stale))
            self.assertEqual(status, 409, stale)
            self.assertEqual(body, {"error": "stale_snapshot"})
        # The 409 wins over the cursor-out-of-range check.
        status, body = self.query(generation=str(generation + 1), cursor="99")
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "stale_snapshot"})

    def test_query_is_read_only(self) -> None:
        store = self.svc.store
        with store.lock:
            before = {
                "generation": store.generation,
                "audit": len(store.audit_events),
                "chain": [(b.height, b.block_hash, b.status) for b in store.chain],
                "pending": sorted(store.pending),
                "forks": sorted(store.forks),
            }
        for params in (
            {},
            {"account": self.A, "direction": "in"},
            {"generation": str(store.generation)},
            {"limit": "1", "cursor": "3"},
            {"direction": "bogus"},
            {"generation": "0"},
        ):
            self.svc.list_pending_transactions(params)
        with store.lock:
            after = {
                "generation": store.generation,
                "audit": len(store.audit_events),
                "chain": [(b.height, b.block_hash, b.status) for b in store.chain],
                "pending": sorted(store.pending),
                "forks": sorted(store.forks),
            }
        self.assertEqual(before, after)


class PendingIndexLifecycleTests(unittest.TestCase):
    """The index tracks mining, confirmation, rollback, cancel and restart."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def submit(self, key, sender, to, amount) -> str:
        rc, body = self.svc.submit_transaction(signed_tx(key, sender, to, amount))
        assert rc == 202, body
        return body["tx_id"]

    def test_mine_confirm_rollback_cycle(self) -> None:
        tx_id = self.submit(self.ka, self.A, self.B, 10)
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["location"], "mempool")
        self.assertIsNone(body["items"][0]["height"])
        generation_before = body["generation"]

        # Mining moves the row into the pending block with real positions.
        assert self.svc.mine_block()[0] == 201
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 1)
        item = body["items"][0]
        self.assertEqual(item["tx_id"], tx_id)
        self.assertEqual(item["location"], "pending_block")
        self.assertEqual(item["height"], 1)
        self.assertEqual(item["index"], 0)
        self.assertEqual(
            item["block_hash"], self.svc.store.chain[1].block_hash
        )
        self.assertGreater(body["generation"], generation_before)

        # Rollback returns the row to the mempool shape.
        assert self.svc.rollback_block(1)[0] == 200
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 1)
        item = body["items"][0]
        self.assertEqual(item["location"], "mempool")
        self.assertIsNone(item["height"])
        self.assertIsNone(item["block_hash"])
        self.assertIsNone(item["index"])

        # Mine again and confirm: the row leaves the pending index.
        assert self.svc.mine_block()[0] == 201
        assert self.svc.confirm_block(1)[0] == 200
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])

    def test_cancel_removes_mempool_row(self) -> None:
        tx_id = self.submit(self.ka, self.A, self.B, 10)
        signature = self.ka.sign(crypto.cancel_message(tx_id)).hex()
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 1)
        rc, _ = self.svc.cancel_transaction(tx_id, {"signature": signature})
        assert rc == 200, _
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 0)

    def test_generation_advances_with_lifecycle(self) -> None:
        self.submit(self.ka, self.A, self.B, 10)
        status, body = self.svc.list_pending_transactions({})
        pinned = body["generation"]
        # The pinned generation still reads fine until any write happens.
        status, again = self.svc.list_pending_transactions(
            {"generation": str(pinned)}
        )
        self.assertEqual(status, 200)
        self.assertEqual(again, body)
        assert self.svc.mine_block()[0] == 201
        status, body = self.svc.list_pending_transactions(
            {"generation": str(pinned)}
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "stale_snapshot"})

    def test_restart_rebuilds_same_view(self) -> None:
        self.submit(self.ka, self.A, self.B, 10)
        self.submit(self.kb, self.B, self.A, 4)
        assert self.svc.mine_block()[0] == 201
        self.submit(self.ka, self.A, self.A, 1)
        status, before = self.svc.list_pending_transactions({})
        self.assertEqual(status, 200)
        self.assertEqual(before["total"], 3)
        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        status, after = reopened.list_pending_transactions({})
        self.assertEqual(status, 200)
        self.assertEqual(after, before)
        # The generation pin survives the restart too.
        status, pinned = reopened.list_pending_transactions(
            {"generation": str(before["generation"])}
        )
        self.assertEqual(status, 200)
        self.assertEqual(pinned, before)


class PendingIndexHttpTests(unittest.TestCase):
    """The endpoint over the real HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        rc, body = cls.request(
            "POST", "/v1/transactions", signed_tx(cls.ka, cls.A, cls.B, 12)
        )
        assert rc == 202, body
        rc, body = cls.request(
            "POST", "/v1/transactions", signed_tx(cls.kb, cls.B, cls.A, 5)
        )
        assert rc == 202, body
        assert cls.request("POST", "/v1/blocks")[0] == 201
        # Leave block 1 pending and one transaction in the mempool.
        rc, body = cls.request(
            "POST", "/v1/transactions", signed_tx(cls.ka, cls.A, cls.A, 3)
        )
        assert rc == 202, body

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, method: str, path: str, payload=None):
        url = f"{cls.base}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            url, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def raw_get(self, path: str) -> tuple[int, str]:
        req = urllib.request.Request(f"{self.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_pending_over_http(self) -> None:
        status, body = self.request("GET", "/v1/index/pending")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 3)
        self.assertEqual(
            list(body), ["generation", "items", "total", "next_cursor"]
        )
        locations = sorted(item["location"] for item in body["items"])
        self.assertEqual(locations, ["mempool", "pending_block", "pending_block"])

    def test_wire_key_order(self) -> None:
        status, text = self.raw_get("/v1/index/pending?limit=1")
        self.assertEqual(status, 200)
        positions = [
            text.index(f'"{name}"')
            for name in ("generation", "items", "total", "next_cursor")
        ]
        self.assertEqual(positions, sorted(positions))
        item_positions = [text.index(f'"{name}"') for name in ITEM_KEYS]
        self.assertEqual(item_positions, sorted(item_positions))

    def test_parameter_violations_over_http(self) -> None:
        for query in (
            "unknown=1",
            "account=",
            "direction=in",  # missing account
            "limit=0",
            "limit=201",
            "limit=abc",
            "cursor=-1",
            "cursor=99",  # beyond the total
            "generation=01",
            "account=a&account=b",  # repeated
            "limit=1&limit=1",  # repeated, even identical
            "generation=1&generation=2",
        ):
            status, body = self.request("GET", f"/v1/index/pending?{query}")
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "input"}, query)

    def test_bare_question_mark_accepted(self) -> None:
        status, body = self.request("GET", "/v1/index/pending?")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 3)

    def test_stale_generation_over_http(self) -> None:
        status, body = self.request("GET", "/v1/index/pending")
        self.assertEqual(status, 200)
        generation = body["generation"]
        status, body = self.request(
            "GET", f"/v1/index/pending?generation={generation}"
        )
        self.assertEqual(status, 200)
        status, body = self.request(
            "GET", f"/v1/index/pending?generation={generation + 1}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "stale_snapshot"})

    def test_legacy_index_route_unchanged(self) -> None:
        # The confirmed-chain index keeps its behaviour: nothing confirmed
        # yet, so it is an empty page with its legacy shape.
        status, body = self.request("GET", "/v1/index/transactions")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"items": [], "next_cursor": None, "total": 0})


class PendingIndexCliTests(unittest.TestCase):
    """The ``pending`` CLI subcommand."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        rc, _ = cls.service.submit_transaction(
            signed_tx(cls.ka, cls.A, cls.B, 20)
        )
        assert rc == 202
        rc, _ = cls.service.submit_transaction(
            signed_tx(cls.kb, cls.B, cls.A, 6)
        )
        assert rc == 202

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, raw

    def test_pending_cli(self) -> None:
        rc, raw = self.run_cli("pending")
        self.assertEqual(rc, 0, raw)
        body = json.loads(raw)
        self.assertEqual(body["total"], 2)
        self.assertEqual(
            list(body), ["generation", "items", "total", "next_cursor"]
        )
        for item in body["items"]:
            self.assertEqual(list(item), list(ITEM_KEYS))
            self.assertEqual(item["location"], "mempool")

    def test_pending_cli_filters(self) -> None:
        rc, raw = self.run_cli(
            "pending", "--account", self.A, "--direction", "out"
        )
        self.assertEqual(rc, 0, raw)
        body = json.loads(raw)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["from"], self.A)
        rc, raw = self.run_cli("pending", "--limit", "1", "--cursor", "1")
        self.assertEqual(rc, 0, raw)
        body = json.loads(raw)
        self.assertEqual(len(body["items"]), 1)
        self.assertIsNone(body["next_cursor"])

    def test_pending_cli_generation(self) -> None:
        rc, raw = self.run_cli("pending")
        self.assertEqual(rc, 0)
        generation = json.loads(raw)["generation"]
        rc, raw = self.run_cli("pending", "--generation", str(generation))
        self.assertEqual(rc, 0, raw)
        rc, raw = self.run_cli("pending", "--generation", str(generation + 1))
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(raw), {"error": "stale_snapshot"})

    def test_pending_cli_input_error_exits_1(self) -> None:
        rc, raw = self.run_cli("pending", "--direction", "in")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(raw), {"error": "input"})

    def test_pending_cli_unreachable_server_exits_1(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(
                ["--base-url", "http://127.0.0.1:1", "pending"]
            )
        self.assertEqual(rc, 1)
        self.assertEqual(buf.getvalue().count("\n"), 1)


if __name__ == "__main__":
    unittest.main()
