"""Tests for GET /v1/index/pending and the CLI ``pending`` subcommand.

The pending index merges the persisted mempool with the canonical chain's
unconfirmed pending tip block — exactly the transactions that can still be
packed or rolled back. Confirmed transactions and candidate forks are always
excluded. Covers the strict parameter contract (only
account/direction/limit/cursor/generation; repeats, unknown names, empty or
malformed values all answer 400 {"error":"input"}), the generation snapshot
guard (409 stale_snapshot, no partial data), the fixed response key order
(generation, items, total, next_cursor) and eleven-field item shape
(mempool nulls vs. real pending-block positions, null nonce for legacy
transfers), tx_id-ascending order, account/direction filters, pagination
(empty page at cursor == total, 400 beyond), read-only behaviour, lifecycle
transitions (confirm removes, rollback re-pools) and restart consistency,
plus the HTTP wire format and the CLI.

Run: python3 tests/index_pending_test.py
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
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


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
RESPONSE_KEYS = ("generation", "items", "total", "next_cursor")


class PendingIndexServiceTests(unittest.TestCase):
    """Service-level semantics of list_pending_transactions."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(LedgerStore(cls.path), initial_balance=1000)
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()

        # Block 1 (confirmed): A->B 10 — must never appear in the index.
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.ka, cls.A, cls.B, 10))
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200

        # Block 2 (pending tip): legacy B->A 20 and sequenced C->A 1 (nonce 0).
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kb, cls.B, cls.A, 20))
        assert rc == 202
        rc, _ = cls.svc.submit_sequenced_transaction(
            sequenced_payload(cls.kc, cls.C, cls.A, 1, 0)
        )
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201

        # Mempool: legacy A->A 5 self-transfer and sequenced C->B 2 (nonce 1).
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.ka, cls.A, cls.A, 5))
        assert rc == 202
        rc, _ = cls.svc.submit_sequenced_transaction(
            sequenced_payload(cls.kc, cls.C, cls.B, 2, 1)
        )
        assert rc == 202

        cls.tip = cls.svc.store.chain[-1]
        assert cls.tip.status == "pending"
        cls.generation = cls.svc.store.generation

    def query(self, **params) -> tuple[int, dict]:
        return self.svc.list_pending_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def items(self, **params) -> list[dict]:
        status, body = self.query(**params)
        assert status == 200, body
        return body["items"]

    def test_merges_mempool_and_pending_tip_sorted_by_tx_id(self) -> None:
        status, body = self.query()
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), list(RESPONSE_KEYS))
        self.assertEqual(body["generation"], self.generation)
        self.assertEqual(body["total"], 4)
        self.assertIsNone(body["next_cursor"])
        tx_ids = [item["tx_id"] for item in body["items"]]
        self.assertEqual(tx_ids, sorted(tx_ids))
        self.assertEqual(len(set(tx_ids)), 4)
        # The confirmed block-1 transaction is excluded.
        confirmed_id = self.svc.store.chain[1].transactions[0].tx_id
        self.assertNotIn(confirmed_id, tx_ids)

    def test_item_shape_and_locations(self) -> None:
        by_id = {item["tx_id"]: item for item in self.items()}
        self.assertEqual(len(by_id), 4)
        for item in by_id.values():
            self.assertEqual(list(item), list(ITEM_KEYS))
            self.assertEqual(item["status"], "pending")
        block_txs = {tx.tx_id: i for i, tx in enumerate(self.tip.transactions)}
        mempool_ids = set(self.svc.store.pending)
        for tx_id, item in by_id.items():
            if tx_id in block_txs:
                self.assertEqual(item["location"], "pending_block")
                self.assertEqual(item["height"], self.tip.height)
                self.assertEqual(item["block_hash"], self.tip.block_hash)
                self.assertEqual(item["index"], block_txs[tx_id])
            else:
                self.assertIn(tx_id, mempool_ids)
                self.assertEqual(item["location"], "mempool")
                self.assertIsNone(item["height"])
                self.assertIsNone(item["block_hash"])
                self.assertIsNone(item["index"])

    def test_nonce_null_for_legacy_present_for_sequenced(self) -> None:
        by_id = {item["tx_id"]: item for item in self.items()}
        sequenced = {
            tx.tx_id: tx.nonce
            for tx in list(self.tip.transactions)
            + list(self.svc.store.pending.values())
            if tx.nonce is not None
        }
        self.assertEqual(len(sequenced), 2)
        for tx_id, item in by_id.items():
            if tx_id in sequenced:
                self.assertEqual(item["nonce"], sequenced[tx_id])
            else:
                self.assertIsNone(item["nonce"])

    def test_account_and_direction_filters(self) -> None:
        # A: pending-tip incoming B->A 20 and C->A 1, mempool self-transfer
        # A->A 5.
        items = self.items(account=self.A)
        self.assertEqual(len(items), 3)
        # direction=all is the default; an explicit all matches identically.
        self.assertEqual(items, self.items(account=self.A, direction="all"))
        # out: only the self-transfer leaves from A.
        out_items = self.items(account=self.A, direction="out")
        self.assertEqual(len(out_items), 1)
        self.assertEqual(out_items[0]["from"], self.A)
        self.assertEqual(out_items[0]["to"], self.A)
        # in: the self-transfer plus the two pending-tip incoming transfers.
        in_items = self.items(account=self.A, direction="in")
        self.assertEqual(len(in_items), 3)
        # B: outgoing pending-tip B->A 20, incoming mempool C->B 2.
        self.assertEqual(len(self.items(account=self.B, direction="out")), 1)
        self.assertEqual(len(self.items(account=self.B, direction="in")), 1)
        self.assertEqual(len(self.items(account=self.B)), 2)
        # C: two outgoing sequenced transfers, nothing incoming.
        self.assertEqual(len(self.items(account=self.C, direction="out")), 2)
        self.assertEqual(len(self.items(account=self.C, direction="in")), 0)
        # Unknown account: empty page, still 200.
        status, body = self.query(account="f" * 64)
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])
        self.assertIsNone(body["next_cursor"])

    def test_pagination(self) -> None:
        status, body = self.query(limit="2")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual(body["total"], 4)
        self.assertEqual(body["next_cursor"], 2)
        status, second = self.query(limit="2", cursor="2")
        self.assertEqual(second["next_cursor"], None)
        first_page = body["items"]
        self.assertEqual(
            [i["tx_id"] for i in first_page + second["items"]],
            [i["tx_id"] for i in self.items()],
        )
        # cursor == total: empty page.
        status, body = self.query(cursor="4")
        self.assertEqual(status, 200)
        self.assertEqual(body["items"], [])
        self.assertEqual(body["total"], 4)
        self.assertIsNone(body["next_cursor"])
        # cursor beyond total: the fixed 400 input body.
        status, body = self.query(cursor="5")
        self.assertEqual(status, 400)
        self.assertEqual(body, {"error": "input"})
        # limit larger than the set is fine.
        status, body = self.query(limit="200")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["items"]), 4)

    def test_generation_guard(self) -> None:
        status, body = self.query(generation=str(self.generation))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["generation"], self.generation)
        # A stale or future generation answers 409 with no partial data.
        for stale in (str(self.generation + 1), "0", "999999"):
            if int(stale) == self.generation:
                continue
            status, body = self.query(generation=stale)
            self.assertEqual(status, 409, stale)
            self.assertEqual(body, {"error": "stale_snapshot"})

    def test_validation_errors(self) -> None:
        cases = (
            {"unknown": "1"},
            {"tx_id": "a" * 64},
            {"height": "1"},
            {"account": ""},
            {"direction": ""},
            {"direction": "both"},
            {"direction": "IN"},
            {"direction": "in"},  # in/out require a non-empty account
            {"direction": "out"},
            {"direction": "in", "account": ""},
            {"limit": ""},
            {"limit": "0"},
            {"limit": "201"},
            {"limit": "01"},
            {"limit": "1.0"},
            {"limit": " 1"},
            {"limit": "１２"},  # non-ASCII digits
            {"cursor": ""},
            {"cursor": "-1"},
            {"cursor": "00"},
            {"generation": ""},
            {"generation": "01"},
            {"generation": "-1"},
            {"generation": "1.5"},
        )
        for params in cases:
            status, body = self.query(**params)
            self.assertEqual(status, 400, params)
            self.assertEqual(body, {"error": "input"}, params)

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
            {"limit": "1", "cursor": "3"},
            {"generation": str(self.generation)},
            {"generation": str(self.generation + 1)},
            {"cursor": "99"},
            {"bogus": "1"},
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

    def test_restart_rebuilds_same_page(self) -> None:
        status, before = self.query()
        self.assertEqual(status, 200)
        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        status, after = reopened.list_pending_transactions({})
        self.assertEqual(status, 200)
        self.assertEqual(after, before)


class PendingIndexLifecycleTests(unittest.TestCase):
    """Confirm/rollback transitions and the generation guard."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def test_confirm_rollback_and_mine_transitions(self) -> None:
        rc, _ = self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, 7))
        assert rc == 202
        # One mempool entry, no pending block yet.
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["location"], "mempool")
        gen_before_mine = body["generation"]

        # Mining moves the entry into the pending tip with a real position.
        assert self.svc.mine_block()[0] == 201
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 1)
        item = body["items"][0]
        self.assertEqual(item["location"], "pending_block")
        self.assertEqual(item["height"], 1)
        self.assertEqual(item["block_hash"], self.svc.store.chain[1].block_hash)
        self.assertEqual(item["index"], 0)
        # The pre-mine generation is now stale.
        status, stale = self.svc.list_pending_transactions(
            {"generation": str(gen_before_mine)}
        )
        self.assertEqual(status, 409)
        self.assertEqual(stale, {"error": "stale_snapshot"})

        # Rollback returns the transaction to the mempool shape.
        assert self.svc.rollback_block(1)[0] == 200
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 1)
        item = body["items"][0]
        self.assertEqual(item["location"], "mempool")
        self.assertIsNone(item["height"])
        self.assertIsNone(item["block_hash"])
        self.assertIsNone(item["index"])

        # Re-mine and confirm: the index drains to an empty page.
        assert self.svc.mine_block()[0] == 201
        assert self.svc.confirm_block(1)[0] == 200
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])
        self.assertIsNone(body["next_cursor"])
        # Restart keeps the drained view.
        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        status, again = reopened.list_pending_transactions({})
        self.assertEqual(again, body)

    def test_cancel_removes_mempool_entry(self) -> None:
        payload = signed_tx(self.ka, self.A, self.B, 3)
        rc, _ = self.svc.submit_transaction(payload)
        assert rc == 202
        tx_id = crypto.compute_tx_id(
            crypto.canonical_message(self.A, self.B, 3)
        )
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 1)
        cancel_sig = self.ka.sign(crypto.cancel_message(tx_id)).hex()
        rc, cancel_body = self.svc.cancel_transaction(
            tx_id, {"signature": cancel_sig}
        )
        assert rc == 200, cancel_body
        status, body = self.svc.list_pending_transactions({})
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])


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
        assert cls.request("POST", "/v1/blocks")[0] == 201
        # Leave block 1 pending and add one mempool transaction.
        rc, body = cls.request(
            "POST", "/v1/transactions", signed_tx(cls.kb, cls.B, cls.A, 4)
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

    def test_page_over_http(self) -> None:
        status, body = self.request("GET", "/v1/index/pending")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), ["generation", "items", "total", "next_cursor"])
        self.assertEqual(body["generation"], self.service.store.generation)
        self.assertEqual(body["total"], 2)
        locations = sorted(item["location"] for item in body["items"])
        self.assertEqual(locations, ["mempool", "pending_block"])
        for item in body["items"]:
            self.assertEqual(list(item), list(ITEM_KEYS))

    def test_raw_key_order_on_the_wire(self) -> None:
        req = urllib.request.Request(f"{self.base}/v1/index/pending?limit=1")
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
        body = json.loads(raw)
        item = body["items"][0]
        expected = {
            "generation": body["generation"],
            "items": [
                {
                    "tx_id": item["tx_id"],
                    "from": item["from"],
                    "to": item["to"],
                    "amount": item["amount"],
                    "signature": item["signature"],
                    "status": "pending",
                    "height": item["height"],
                    "block_hash": item["block_hash"],
                    "index": item["index"],
                    "location": item["location"],
                    "nonce": item["nonce"],
                }
            ],
            "total": body["total"],
            "next_cursor": body["next_cursor"],
        }
        self.assertEqual(
            raw, json.dumps(expected, ensure_ascii=False, sort_keys=False)
        )

    def test_parameter_violations_over_http(self) -> None:
        bad_queries = (
            "account=",  # empty value
            "direction=",  # empty value
            "limit=",  # empty value
            "cursor=",  # empty value
            "generation=",  # empty value
            "account",  # bare name is an empty value
            "limit=0",
            "limit=201",
            "limit=abc",
            "cursor=-1",
            "generation=007",
            "direction=sideways",
            "direction=in",  # in/out need an account
            "bogus=1",  # unknown parameter
            "tx_id=" + "a" * 64,  # confirmed-index parameter, unknown here
            "limit=1&limit=1",  # repeated, even identical
            "account=x&account=x",
            "generation=1&generation=1",
        )
        for query in bad_queries:
            status, body = self.request("GET", f"/v1/index/pending?{query}")
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "input"}, query)

    def test_stale_generation_over_http(self) -> None:
        current = self.service.store.generation
        status, body = self.request(
            "GET", f"/v1/index/pending?generation={current}"
        )
        self.assertEqual(status, 200, body)
        status, body = self.request(
            "GET", f"/v1/index/pending?generation={current + 1}"
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "stale_snapshot"})

    def test_bare_question_mark_accepted(self) -> None:
        req = urllib.request.Request(f"{self.base}/v1/index/pending?")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)


class PendingIndexCliTests(unittest.TestCase):
    """The pending CLI subcommand."""

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
        assert cls.service.mine_block()[0] == 201
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

    def test_pending_cli_prints_contract_key_order(self) -> None:
        rc, raw = self.run_cli("pending")
        self.assertEqual(rc, 0, raw)
        body = json.loads(raw)
        self.assertEqual(list(body), ["generation", "items", "total", "next_cursor"])
        self.assertEqual(body["total"], 2)
        # The line is serialized in contract order, not alphabetically.
        self.assertLess(raw.index('"generation"'), raw.index('"items"'))
        self.assertLess(raw.index('"items"'), raw.index('"total"'))
        self.assertLess(raw.index('"total"'), raw.index('"next_cursor"'))

    def test_pending_cli_filters(self) -> None:
        rc, raw = self.run_cli(
            "pending", "--account", self.A, "--direction", "out", "--limit", "5"
        )
        self.assertEqual(rc, 0, raw)
        body = json.loads(raw)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["items"][0]["from"], self.A)
        rc, raw = self.run_cli(
            "pending", "--generation", str(self.service.store.generation)
        )
        self.assertEqual(rc, 0, raw)

    def test_pending_cli_non_2xx_exits_1(self) -> None:
        # 400 input (direction=in without an account).
        rc, raw = self.run_cli("pending", "--direction", "in")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(raw), {"error": "input"})
        # 409 stale_snapshot.
        rc, raw = self.run_cli(
            "pending", "--generation", str(self.service.store.generation + 1)
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(raw), {"error": "stale_snapshot"})

    def test_pending_cli_unreachable_exits_1(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", "http://127.0.0.1:1", "pending"])
        self.assertEqual(rc, 1)
        json.loads(buf.getvalue())


if __name__ == "__main__":
    unittest.main()
