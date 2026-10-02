"""Tests for POST /v1/transactions/receipts batch ordinary receipts.

Covers both sides of the contract plus the ``txs`` CLI subcommand:

* service input validation — the body must be an object containing only
  ``tx_ids``, an array of 1..200 distinct 64-lowercase-hex strings; every
  parse/shape/type/range/duplicate defect is 400 ``{"error": "input"}``
  before any lookup, while a well-formed but unknown id is a normal 200
  item with ``error`` ``not_found``;
* the 200 document has the fixed key order ``items, total``; ``total``
  equals the request count; ``items`` preserves request order exactly and
  each item has the fixed order ``tx_id, receipt, error`` (hit: the exact
  single-receipt document and null error; miss: null receipt and
  ``not_found``);
* mempool / unconfirmed-tip / confirmed receipt shapes, sequenced-tx
  ``nonce`` retention (legacy transactions gain no field), candidate-fork
  invisibility, and per-item equality with the single-receipt endpoint
  after rollback and fork adoption;
* the whole batch resolves under one store lock (a concurrent confirm
  cannot split one response across two states), the query mutates
  nothing (mempool, sequences, generation, audit history, files), and the
  same persisted state answers identically across a restart;
* HTTP behavior over the real server — bad JSON / non-UTF-8 bodies and
  any query string are 400 ``{"error": "input"}`` and the wire key order
  is fixed;
* the ``txs`` CLI validates count/shape/duplicates locally (printing
  ``{"error": "input"}`` and exiting 1 without contacting the server),
  prints one JSON line, exits 0 on HTTP 200 (not_found items included),
  and exits 1 with the existing error output on other statuses or a
  connection failure.

Run: python3 tests/transaction_receipts_test.py
"""
from __future__ import annotations

import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

RECEIPT_FIELDS = {
    "tx_id",
    "from",
    "to",
    "amount",
    "signature",
    "status",
    "height",
    "block_hash",
    "index",
}
BAD_INPUT = {"error": "input"}


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}


def make_sequenced_tx(
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


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(make_tx(key, sender, to, amount))


def ordered(value: bytes):
    """Decode JSON preserving every object's key insertion order."""
    return json.loads(value, object_pairs_hook=lambda pairs: pairs)


class BatchReceiptFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()

    def submit(self, amount: int = 100) -> dict:
        status, body = self.svc.submit_transaction(make_tx(self.ka, self.A, self.B, amount))
        self.assertEqual(status, 202, body)
        return body

    def submit_sequenced(self, amount: int, nonce: int) -> dict:
        status, body = self.svc.submit_sequenced_transaction(
            make_sequenced_tx(self.ka, self.A, self.B, amount, nonce)
        )
        self.assertEqual(status, 202, body)
        return body

    def mine(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        return block

    def confirm(self, height: int) -> None:
        self.assertEqual(self.svc.confirm_block(height)[0], 200)

    def batch(self, tx_ids: list[str]) -> tuple[int, dict]:
        return self.svc.get_transaction_receipts({"tx_ids": tx_ids})

    def assert_batch_matches_singles(self, tx_ids: list[str]) -> dict:
        """Every batch item must equal the same-state single-receipt answer."""
        status, body = self.batch(tx_ids)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], len(tx_ids))
        self.assertEqual([item["tx_id"] for item in body["items"]], tx_ids)
        by_id = {item["tx_id"]: item for item in body["items"]}
        for tx_id in tx_ids:
            single_status, single = self.svc.get_transaction(tx_id)
            item = by_id[tx_id]
            self.assertEqual(tuple(item), ("tx_id", "receipt", "error"))
            if single_status == 200:
                self.assertIsNone(item["error"], item)
                self.assertEqual(item["receipt"], single)
            else:
                self.assertEqual(single_status, 404)
                self.assertIsNone(item["receipt"])
                self.assertEqual(item["error"], "not_found")
        return body


class BatchReceiptInputTests(BatchReceiptFixture):
    def test_malformed_bodies_are_400_input(self) -> None:
        bodies = (
            None,
            1,
            "x",
            [],
            {},
            True,
            False,
            {"ids": ["0" * 64]},
            {"tx_ids": ["0" * 64], "extra": 1},
            {"tx_ids": None},
            {"tx_ids": "0" * 64},
            {"tx_ids": 123},
            {"tx_ids": {}},
            {"tx_ids": ()},  # tuple is not the required JSON array type
            {"tx_ids": []},
            {"tx_ids": [None]},
            {"tx_ids": [123]},
            {"tx_ids": [True]},
            {"tx_ids": [b"0" * 64]},
            {"tx_ids": ["z" * 64]},
            {"tx_ids": ["A" * 64]},
            {"tx_ids": ["0" * 63]},
            {"tx_ids": ["1" * 65]},
            {"tx_ids": ["0" * 64, " " + "0" * 63]},
            {"tx_ids": ["0" * 64, "0" * 64]},  # duplicate
        )
        for body in bodies:
            self.assertEqual(
                self.svc.get_transaction_receipts(body),
                (400, BAD_INPUT),
                body,
            )

    def test_count_bounds_are_one_to_two_hundred(self) -> None:
        self.assertEqual(
            self.svc.get_transaction_receipts({"tx_ids": []}), (400, BAD_INPUT)
        )
        two_hundred = [f"{i:064x}" for i in range(200)]
        status, body = self.svc.get_transaction_receipts({"tx_ids": two_hundred})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 200)
        self.assertTrue(all(item["error"] == "not_found" for item in body["items"]))

        two_hundred_one = [f"{i:064x}" for i in range(201)]
        self.assertEqual(
            self.svc.get_transaction_receipts({"tx_ids": two_hundred_one}),
            (400, BAD_INPUT),
        )

    def test_validation_runs_before_lookup(self) -> None:
        # A mix where a known id sits next to a malformed one: the whole
        # request is 400 and returns no query entries at all.
        known = self.submit(10)["tx_id"]
        status, body = self.svc.get_transaction_receipts(
            {"tx_ids": [known, "z" * 64]}
        )
        self.assertEqual((status, body), (400, BAD_INPUT))
        status, body = self.svc.get_transaction_receipts(
            {"tx_ids": [known, known]}
        )
        self.assertEqual((status, body), (400, BAD_INPUT))

    def test_unknown_ids_are_not_input_errors(self) -> None:
        # Nothing exists yet: a legal batch is still 200 with a full array.
        status, body = self.batch(["0" * 64, "f" * 64])
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 2)
        self.assertEqual(
            body["items"],
            [
                {"tx_id": "0" * 64, "receipt": None, "error": "not_found"},
                {"tx_id": "f" * 64, "receipt": None, "error": "not_found"},
            ],
        )


class BatchReceiptLifecycleTests(BatchReceiptFixture):
    def test_document_and_item_key_order_and_total(self) -> None:
        tx_id = self.submit(10)["tx_id"]
        status, body = self.batch([tx_id, "f" * 64])
        self.assertEqual(status, 200)
        self.assertEqual(tuple(body), ("items", "total"))
        self.assertEqual(body["total"], 2)
        hit, miss = body["items"]
        self.assertEqual(tuple(hit), ("tx_id", "receipt", "error"))
        self.assertEqual(tuple(miss), ("tx_id", "receipt", "error"))
        self.assertEqual(hit["tx_id"], tx_id)
        self.assertIsNone(hit["error"])
        self.assertEqual(miss, {"tx_id": "f" * 64, "receipt": None, "error": "not_found"})

    def test_request_order_is_preserved(self) -> None:
        first = self.submit(1)["tx_id"]
        second = self.submit(2)["tx_id"]
        third = self.submit(3)["tx_id"]
        unknown = "f" * 64
        order = [unknown, third, first, second]
        status, body = self.batch(order)
        self.assertEqual(status, 200)
        self.assertEqual([item["tx_id"] for item in body["items"]], order)

        # Descending and ascending request orders both survive verbatim.
        ids = sorted([first, second, third])
        self.assertEqual(
            [item["tx_id"] for item in self.batch(list(reversed(ids)))[1]["items"]],
            list(reversed(ids)),
        )
        self.assertEqual(
            [item["tx_id"] for item in self.batch(ids)[1]["items"]], ids
        )

    def test_mempool_pending_tip_and_confirmed_shapes(self) -> None:
        pool = self.submit(10)["tx_id"]
        self.assert_batch_matches_singles([pool, "f" * 64])

        block = self.mine()
        packed = pool
        more_pool = self.submit(20)["tx_id"]
        body = self.assert_batch_matches_singles([more_pool, packed, "0" * 64])
        packed_item = next(i for i in body["items"] if i["tx_id"] == packed)
        self.assertEqual(packed_item["receipt"]["status"], "pending")
        self.assertEqual(
            (
                packed_item["receipt"]["height"],
                packed_item["receipt"]["block_hash"],
                packed_item["receipt"]["index"],
            ),
            (block["height"], block["block_hash"], 0),
        )
        pool_item = next(i for i in body["items"] if i["tx_id"] == more_pool)
        self.assertEqual(pool_item["receipt"]["status"], "pending")
        self.assertIsNone(pool_item["receipt"]["height"])
        self.assertIsNone(pool_item["receipt"]["block_hash"])
        self.assertIsNone(pool_item["receipt"]["index"])

        self.confirm(block["height"])
        body = self.assert_batch_matches_singles([packed, more_pool])
        packed_item = body["items"][0]
        self.assertEqual(packed_item["receipt"]["status"], "confirmed")
        self.assertEqual(set(packed_item["receipt"]), RECEIPT_FIELDS)

    def test_block_order_indices_match_across_a_batch(self) -> None:
        bodies = [self.submit(v) for v in (30, 10, 20)]
        block = self.mine()
        self.confirm(block["height"])
        ordered_ids = sorted(body["tx_id"] for body in bodies)
        body = self.assert_batch_matches_singles(list(reversed(ordered_ids)))
        for index, tx_id in enumerate(ordered_ids):
            item = next(i for i in body["items"] if i["tx_id"] == tx_id)
            self.assertEqual(item["receipt"]["index"], index)
            self.assertEqual(item["receipt"]["block_hash"], block["block_hash"])

    def test_sequenced_tx_keeps_nonce_legacy_has_none(self) -> None:
        legacy_id = self.submit(7)["tx_id"]
        sequenced_id = self.submit_sequenced(9, 0)["tx_id"]
        block = self.mine()
        self.confirm(block["height"])
        body = self.assert_batch_matches_singles([sequenced_id, legacy_id])
        seq_receipt = body["items"][0]["receipt"]
        legacy_receipt = body["items"][1]["receipt"]
        self.assertEqual(seq_receipt["nonce"], 0)
        self.assertEqual(list(seq_receipt)[-1], "nonce")
        self.assertNotIn("nonce", legacy_receipt)
        self.assertEqual(set(legacy_receipt), RECEIPT_FIELDS)

    def test_candidate_fork_transactions_are_not_found(self) -> None:
        genesis = self.svc.store.chain[0]
        kc, C = keypair()
        fork_block = Block.create(1, genesis.block_hash, [tx_obj(kc, C, self.B, 7)])
        fork_tx_id = fork_block.transactions[0].tx_id
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), fork_block.to_dict()]}
            )[0],
            201,
        )
        body = self.assert_batch_matches_singles([fork_tx_id, "f" * 64])
        self.assertEqual(
            body["items"][0],
            {"tx_id": fork_tx_id, "receipt": None, "error": "not_found"},
        )

    def test_rollback_and_adoption_match_single_queries(self) -> None:
        # Rollback: the packed transaction returns to its mempool shape.
        tx_id = self.submit(100)["tx_id"]
        block = self.mine()
        self.assertEqual(self.svc.rollback_block(block["height"])[0], 200)
        self.assert_batch_matches_singles([tx_id])

        # Fork adoption moves a receipt onto the new canonical block; an
        # old-chain-only transaction goes back to the mempool.
        genesis = self.svc.store.chain[0]
        kc, C = keypair()
        tx_a = tx_obj(self.ka, self.A, self.B, 10)
        old_block = Block.create(1, genesis.block_hash, [tx_a])
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), old_block.to_dict()]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(old_block.block_hash)[0], 200)
        self.assert_batch_matches_singles([tx_a.tx_id])

        fork_blocks = []
        prev = genesis.block_hash
        for height in (1, 2, 3):
            fb = Block.create(height, prev, [tx_obj(kc, C, self.B, height)])
            fork_blocks.append(fb)
            prev = fb.block_hash
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), *[b.to_dict() for b in fork_blocks]]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(fork_blocks[-1].block_hash)[0], 200)
        self.assert_batch_matches_singles([tx_a.tx_id, fork_blocks[0].transactions[0].tx_id])
        # The retired old block's location must no longer be exposed.
        _, batch_body = self.batch([tx_a.tx_id])
        receipt = batch_body["items"][0]["receipt"]
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])

    def test_query_is_read_only(self) -> None:
        self.submit(10)
        block = self.mine()
        self.confirm(block["height"])
        self.submit_sequenced(5, 0)

        store = self.svc.store
        before = {
            "generation": store.generation,
            "audit": len(store.audit_events),
            "pending": sorted(store.pending),
            "sequences": json.dumps(store.sequences, sort_keys=True),
            "accounts": json.dumps(store.accounts, sort_keys=True),
            "mtime": os.path.getmtime(self.state_path),
        }
        for _ in range(5):
            status, _ = self.batch(
                ["f" * 64, next(iter(store.pending)), "0" * 64]
            )
            self.assertEqual(status, 200)
        self.assertEqual(store.generation, before["generation"])
        self.assertEqual(len(store.audit_events), before["audit"])
        self.assertEqual(sorted(store.pending), before["pending"])
        self.assertEqual(json.dumps(store.sequences, sort_keys=True), before["sequences"])
        self.assertEqual(json.dumps(store.accounts, sort_keys=True), before["accounts"])
        # A read-only query performs no save(): no newer state file.
        self.assertEqual(os.path.getmtime(self.state_path), before["mtime"])

    def test_results_are_stable_across_restart(self) -> None:
        confirmed_id = self.submit(100)["tx_id"]
        block1 = self.mine()
        self.confirm(block1["height"])
        tip_tx = self.submit(30)["tx_id"]
        block2 = self.mine()  # stays pending
        pool_tx = self.submit(5)["tx_id"]
        unknown = "d" * 64

        ids = [unknown, pool_tx, confirmed_id, tip_tx]
        _, before = self.batch(ids)

        reopened = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        status, after = reopened.get_transaction_receipts({"tx_ids": ids})
        self.assertEqual(status, 200)
        self.assertEqual(after, before)

    def test_whole_batch_uses_one_state_snapshot(self) -> None:
        # While a batch is parked mid-construction (holding the store lock
        # inside the lookup), a concurrent confirm must block; the batch
        # answer therefore describes the pre-confirm state in every item.
        tx_id = self.submit(10)["tx_id"]
        self.mine()
        original = LedgerService._transaction_receipt
        ready = threading.Event()
        release = threading.Event()
        entered = 0

        def parked(tx, status, height, block_hash, index):
            nonlocal entered
            entered += 1
            ready.set()
            release.wait(timeout=5)
            return original(tx, status, height, block_hash, index)

        LedgerService._transaction_receipt = staticmethod(parked)
        try:
            result: dict = {}

            def run_query() -> None:
                result["body"] = self.batch([tx_id, "f" * 64])[1]

            query = threading.Thread(target=run_query)
            query.start()
            self.assertTrue(ready.wait(timeout=5))

            def run_confirm() -> None:
                result["confirm"] = self.svc.confirm_block(1)

            confirmer = threading.Thread(target=run_confirm)
            confirmer.start()
            time.sleep(0.2)
            self.assertTrue(confirmer.is_alive(), "confirm must wait for the batch lock")
            self.assertEqual(self.svc.store.chain[-1].status, "pending")

            release.set()
            query.join(timeout=5)
            confirmer.join(timeout=5)
        finally:
            LedgerService._transaction_receipt = staticmethod(original)

        self.assertFalse(query.is_alive())
        self.assertFalse(confirmer.is_alive())
        self.assertEqual(result["confirm"][0], 200)
        # The parked batch saw the pending shape, never a mixed answer.
        self.assertEqual(result["body"]["items"][0]["receipt"]["status"], "pending")
        self.assertEqual(
            result["body"]["items"][0]["receipt"]["height"], 1
        )
        self.assertEqual(result["body"]["items"][1]["error"], "not_found")
        # After the commit lands, a fresh batch sees the confirmed shape.
        self.assert_batch_matches_singles([tx_id])


class BatchReceiptHttpTests(unittest.TestCase):
    """POST /v1/transactions/receipts over the real HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def raw_request(self, path: str, raw: bytes | None, method: str = "POST"):
        headers = {"Content-Type": "application/json"} if raw is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=raw, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = resp.read()
                return resp.status, data
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def request(self, path: str, payload=None, method: str = "POST"):
        data = json.dumps(payload).encode() if payload is not None else None
        status, raw = self.raw_request(path, data, method=method)
        return status, json.loads(raw.decode())

    def test_bad_bodies_are_400_input(self) -> None:
        for path, raw in (
            ("/v1/transactions/receipts", b"not json"),
            ("/v1/transactions/receipts", b"\xff\xfe\x00invalid"),
            ("/v1/transactions/receipts", b"{}"),
            ("/v1/transactions/receipts", b'{"tx_ids": []}'),
            ("/v1/transactions/receipts", b'{"tx_ids": ["zz"]}'),
            ("/v1/transactions/receipts", None),  # missing body
        ):
            status, body = self.raw_request(path, raw)
            self.assertEqual(status, 400, raw)
            self.assertEqual(json.loads(body), BAD_INPUT, raw)

    def test_query_parameters_are_400(self) -> None:
        for path in (
            "/v1/transactions/receipts?x=1",
            "/v1/transactions/receipts?tx_ids=1",
            "/v1/transactions/receipts?",  # bare '?' carries none: accepted
        ):
            if path.endswith("?"):
                # The bare-question form parses to no parameters and must
                # behave exactly like the plain path for the same body.
                plain_status, plain_body = self.request(
                    "/v1/transactions/receipts", {"tx_ids": ["f" * 64]}
                )
                status, body = self.request(path, {"tx_ids": ["f" * 64]})
                self.assertEqual((status, body), (plain_status, plain_body))
                continue
            status, body = self.request(path, {"tx_ids": ["f" * 64]})
            self.assertEqual(status, 400, path)
            self.assertEqual(body, BAD_INPUT, path)

    def test_endpoint_lifecycle_and_wire_key_order(self) -> None:
        # All-unknown legal batch is 200.
        status, raw = self.raw_request(
            "/v1/transactions/receipts", b'{"tx_ids": ["' + b"f" * 64 + b'"]}'
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(raw),
            {"items": [{"tx_id": "f" * 64, "receipt": None, "error": "not_found"}],
             "total": 1},
        )

        # A real transaction: mempool -> pending tip -> confirmed.
        tx_body = make_tx(self.ka, self.A, self.B, 11)
        req = urllib.request.Request(
            f"{self.base}/v1/transactions",
            data=json.dumps(tx_body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            submitted = json.loads(resp.read())
        tx_id = submitted["tx_id"]

        ids = [tx_id, "0" * 64]
        status, raw = self.raw_request(
            "/v1/transactions/receipts",
            json.dumps({"tx_ids": ids}).encode(),
        )
        self.assertEqual(status, 200)
        pairs = ordered(raw)
        self.assertEqual([key for key, _ in pairs], ["items", "total"])
        item_pairs = pairs[0][1]
        self.assertEqual(
            [[key for key, _ in item] for item in item_pairs],
            [["tx_id", "receipt", "error"], ["tx_id", "receipt", "error"]],
        )
        decoded = json.loads(raw)
        self.assertEqual(decoded["total"], 2)
        self.assertEqual([i["tx_id"] for i in decoded["items"]], ids)
        self.assertEqual(decoded["items"][0]["receipt"]["status"], "pending")
        self.assertEqual(decoded["items"][1]["error"], "not_found")

        _, block = self.request("/v1/blocks", {})
        req = urllib.request.Request(
            f"{self.base}/v1/blocks/{block['height']}/confirm",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req):
            pass
        status, body = self.request("/v1/transactions/receipts", {"tx_ids": ids})
        self.assertEqual(status, 200)
        self.assertEqual(body["items"][0]["receipt"]["status"], "confirmed")

        # The single-receipt endpoint is unaffected.
        status, single = self.request(
            f"/v1/transactions/{tx_id}", None, method="GET"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["items"][0]["receipt"], single)


class BatchReceiptCliTests(unittest.TestCase):
    """`ledger txs TX_ID...`: local validation, one-line JSON, exit codes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json")), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.service))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, dict, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw), raw

    def test_local_validation_fails_without_a_request(self) -> None:
        # A recording server proves no request was sent for a rejected
        # argument list: the local input body is printed instead.
        received: list[dict] = []

        class RecordHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                received.append(
                    {"path": self.path, "body": self.rfile.read(length)}
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"items": [], "total": 0}')

            def log_message(self, *args) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), RecordHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            cases = (
                [],
                ["nope"],
                ["z" * 64],
                ["A" * 64],
                ["0" * 63],
                ["0" * 64, "0" * 64],
                [f"{i:064x}" for i in range(201)],
            )
            for extra in cases:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main(["--base-url", base, "txs", *extra])
                raw = buf.getvalue()
                self.assertEqual(raw.count("\n"), 1, extra)
                self.assertEqual(rc, 1, extra)
                self.assertEqual(json.loads(raw), BAD_INPUT, extra)
            self.assertEqual(received, [])
        finally:
            server.shutdown()
            server.server_close()

    def test_txs_happy_path_preserves_order(self) -> None:
        first = self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 1))[1]["tx_id"]
        second = self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 2))[1]["tx_id"]
        unknown = "e" * 64
        ids = [unknown, second, first]
        rc, body, _ = self.run_cli("txs", *ids)
        self.assertEqual(rc, 0)  # not_found items are still a 200 success
        self.assertEqual(tuple(body), ("items", "total"))
        self.assertEqual(body["total"], 3)
        self.assertEqual([item["tx_id"] for item in body["items"]], ids)
        self.assertEqual(body["items"][0]["error"], "not_found")
        self.assertIsNone(body["items"][0]["receipt"])
        for item in body["items"][1:]:
            self.assertIsNone(item["error"])
            self.assertEqual(item["receipt"]["status"], "pending")

    def test_txs_takes_two_hundred_ids(self) -> None:
        ids = [f"{i:064x}" for i in range(200)]
        rc, body, _ = self.run_cli("txs", *ids)
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 200)

    def test_connection_failure_exits_one_with_existing_output(self) -> None:
        # A port that is bound and immediately closed refuses quickly
        # (ECONNREFUSED), unlike a firewalled port that may hang.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(
                ["--base-url", f"http://127.0.0.1:{dead_port}", "txs", "f" * 64]
            )
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1)
        self.assertEqual(rc, 1)
        body = json.loads(raw)
        self.assertIn("error", body)
        self.assertIn("cannot reach ledger server", body["error"])

    def test_non_2xx_response_exits_one(self) -> None:
        class FailHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "boom"}')

            def log_message(self, *args) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), FailHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["--base-url", url, "txs", "f" * 64])
            self.assertEqual(rc, 1)
            self.assertEqual(json.loads(buf.getvalue()), {"error": "boom"})
        finally:
            server.shutdown()
            server.server_close()

    def test_single_tx_command_is_unaffected(self) -> None:
        tx_id = self.service.submit_transaction(
            make_tx(self.ka, self.A, self.B, 42)
        )[1]["tx_id"]
        rc, body, _ = self.run_cli("tx", tx_id)
        self.assertEqual(rc, 0)
        self.assertEqual(set(body), RECEIPT_FIELDS)
        self.assertEqual(body["tx_id"], tx_id)
        rc, _, _ = self.run_cli("tx", "nope")
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
