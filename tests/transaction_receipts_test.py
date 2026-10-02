"""Tests for POST /v1/transactions/receipts batch plain receipts.

Covers the full contract:

* input validation precedes any lookup: an unparseable body, a
  non-object, missing/extra keys, a non-array ``tx_ids``, a count outside
  1..200, a malformed element or a duplicate — and any query parameter —
  are all 400 ``{"error": "input"}`` with no items returned and no state
  touched; a well-formed but unknown id is not an input error;
* a valid request always answers 200 with the fixed key order
  ``items,total``: ``total`` is the requested id count and ``items``
  preserves the exact request order, each item ``tx_id,receipt,error``;
* a hit carries the exact single-receipt document (mempool transactions
  keep the three null block-locator fields, a packed-but-unconfirmed one
  stays ``pending`` anchored at the tip, a confirmed one is
  ``confirmed``; a sequenced transfer keeps its ``nonce``, a legacy one
  gains no field) with ``error`` null; a miss carries ``receipt`` null
  and ``error`` ``not_found`` — even when every id misses;
* candidate-fork transactions are never exposed, rollback restores the
  mempool shape, fork adoption reattaches receipts to the new canonical
  state, and a restart rebuilds identical answers;
* the query is read-only (mempool, sequences, generation, idempotency
  records and audit history are untouched) and the whole batch is
  resolved under one store lock;
* the ``txs`` CLI subcommand validates count/shape/distinctness locally
  (printing ``{"error": "input"}`` and exiting 1 without a request),
  posts the ids in argument order, prints one JSON line and exits 0 on
  HTTP 200 — even with not_found items — and 1 otherwise.

Run: python3 tests/transaction_receipts_test.py
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
ITEM_FIELDS = ("tx_id", "receipt", "error")
DOCUMENT_FIELDS = ("items", "total")


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def make_tx(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> dict:
    msg = crypto.canonical_message(sender, to, amount)
    return {
        "from": sender,
        "to": to,
        "amount": amount,
        "signature": key.sign(msg).hex(),
    }


def make_sequenced(
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


class ReceiptsServiceTests(unittest.TestCase):
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
        status, body = self.svc.submit_transaction(
            make_tx(self.ka, self.A, self.B, amount)
        )
        self.assertEqual(status, 202, body)
        return body

    def mine(self) -> dict:
        status, block = self.svc.mine_block()
        self.assertEqual(status, 201, block)
        return block

    def fetch(self, tx_ids: list[str]) -> dict:
        status, body = self.svc.get_transaction_receipts({"tx_ids": tx_ids})
        self.assertEqual(status, 200, body)
        return body

    # -- input validation --------------------------------------------------

    def test_malformed_bodies_are_400_input(self) -> None:
        bodies = (
            None,
            1,
            "x",
            [],
            {},
            True,
            {"tx_ids": []},
            {"tx_ids": ["0" * 64], "extra": 1},
            {"ids": ["0" * 64]},
            {"tx_ids": None},
            {"tx_ids": "0" * 64},
            {"tx_ids": ["0" * 64, 123]},
            {"tx_ids": ["0" * 64, True]},
            {"tx_ids": ["0" * 64, None]},
            {"tx_ids": ["z" * 64]},
            {"tx_ids": ["A" * 64]},
            {"tx_ids": ["0" * 63]},
            {"tx_ids": ["0" * 65]},
            {"tx_ids": ["1" * 64, "1" * 64]},
            {"tx_ids": ["{:064x}".format(i) for i in range(201)]},
        )
        for body in bodies:
            status, result = self.svc.get_transaction_receipts(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(result, {"error": "input"}, body)

    def test_count_boundaries(self) -> None:
        one = self.fetch(["0" * 64])
        self.assertEqual(one["total"], 1)
        self.assertEqual(len(one["items"]), 1)
        two_hundred = self.fetch(["{:064x}".format(i) for i in range(200)])
        self.assertEqual(two_hundred["total"], 200)
        self.assertEqual(len(two_hundred["items"]), 200)

    def test_input_error_returns_no_items_and_touches_nothing(self) -> None:
        body = self.submit(100)
        before_pending = dict(self.svc.store.pending)
        before_events = list(self.svc.store.audit_events)
        before_generation = self.svc.store.generation
        status, result = self.svc.get_transaction_receipts(
            {"tx_ids": [body["tx_id"], "nope"]}
        )
        self.assertEqual(status, 400)
        self.assertEqual(result, {"error": "input"})
        self.assertNotIn("items", result)
        self.assertEqual(self.svc.store.pending, before_pending)
        self.assertEqual(self.svc.store.audit_events, before_events)
        self.assertEqual(self.svc.store.generation, before_generation)

    # -- result shape ------------------------------------------------------

    def test_unknown_ids_are_not_found_items_not_input_errors(self) -> None:
        body = self.fetch(["0" * 64, "f" * 64])
        self.assertEqual(tuple(body), DOCUMENT_FIELDS)
        self.assertEqual(body["total"], 2)
        self.assertEqual(len(body["items"]), 2)
        for item, tx_id in zip(body["items"], ["0" * 64, "f" * 64]):
            self.assertEqual(tuple(item), ITEM_FIELDS)
            self.assertEqual(
                item, {"tx_id": tx_id, "receipt": None, "error": "not_found"}
            )

    def test_items_preserve_request_order_with_mixed_outcomes(self) -> None:
        first = self.submit(10)
        second = self.submit(20)
        requested = ["0" * 64, second["tx_id"], "f" * 64, first["tx_id"]]
        body = self.fetch(requested)
        self.assertEqual(body["total"], 4)
        self.assertEqual([item["tx_id"] for item in body["items"]], requested)
        outcomes = [
            (item["receipt"] is not None, item["error"]) for item in body["items"]
        ]
        self.assertEqual(
            outcomes,
            [(False, "not_found"), (True, None), (False, "not_found"), (True, None)],
        )

    def test_mempool_hit_matches_single_receipt(self) -> None:
        body = self.submit(100)
        item = self.fetch([body["tx_id"]])["items"][0]
        self.assertIsNone(item["error"])
        receipt = item["receipt"]
        self.assertEqual(set(receipt), RECEIPT_FIELDS)
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])
        status, single = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(status, 200)
        self.assertEqual(receipt, single)

    def test_packed_unconfirmed_hit_matches_single_receipt(self) -> None:
        body = self.submit(100)
        block = self.mine()
        item = self.fetch([body["tx_id"]])["items"][0]
        receipt = item["receipt"]
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(
            (receipt["height"], receipt["block_hash"], receipt["index"]),
            (block["height"], block["block_hash"], 0),
        )
        _, single = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(receipt, single)

    def test_confirmed_hit_matches_single_receipt(self) -> None:
        body = self.submit(100)
        block = self.mine()
        self.assertEqual(self.svc.confirm_block(str(block["height"]))[0], 200)
        item = self.fetch([body["tx_id"]])["items"][0]
        receipt = item["receipt"]
        self.assertEqual(receipt["status"], "confirmed")
        self.assertEqual(
            (receipt["height"], receipt["block_hash"], receipt["index"]),
            (block["height"], block["block_hash"], 0),
        )
        _, single = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(receipt, single)

    def test_sequenced_transfer_keeps_nonce_legacy_gains_none(self) -> None:
        status, sequenced = self.svc.submit_sequenced_transaction(
            make_sequenced(self.ka, self.A, self.B, 30, 0)
        )
        self.assertEqual(status, 202, sequenced)
        legacy = self.submit(40)
        block = self.mine()
        self.assertEqual(self.svc.confirm_block(str(block["height"]))[0], 200)
        body = self.fetch([sequenced["tx_id"], legacy["tx_id"]])
        sequenced_receipt, legacy_receipt = (
            item["receipt"] for item in body["items"]
        )
        self.assertEqual(sequenced_receipt["nonce"], 0)
        self.assertEqual(sequenced_receipt["status"], "confirmed")
        self.assertNotIn("nonce", legacy_receipt)
        # Both receipts match the same-state single queries exactly.
        for item in body["items"]:
            _, single = self.svc.get_transaction(item["tx_id"])
            self.assertEqual(item["receipt"], single)

    def test_receipt_tx_id_matches_signed_transaction(self) -> None:
        body = self.submit(55)
        item = self.fetch([body["tx_id"]])["items"][0]
        tx = self.svc.store.pending[body["tx_id"]]
        recomputed = Transaction.from_dict(tx.to_dict()).tx_id
        self.assertEqual(item["receipt"]["tx_id"], recomputed)
        self.assertEqual(item["tx_id"], body["tx_id"])

    # -- chain-state transitions --------------------------------------------

    def test_fork_transactions_are_not_exposed(self) -> None:
        genesis = self.svc.store.chain[0]
        kc, C = keypair()
        fork_block = Block.create(
            1, genesis.block_hash, [tx_obj(kc, C, self.B, 7)]
        )
        fork_tx_id = fork_block.transactions[0].tx_id
        status, _ = self.svc.submit_fork_candidate(
            {"blocks": [genesis.to_dict(), fork_block.to_dict()]}
        )
        self.assertEqual(status, 201)
        item = self.fetch([fork_tx_id])["items"][0]
        self.assertEqual(
            item, {"tx_id": fork_tx_id, "receipt": None, "error": "not_found"}
        )

    def test_rollback_restores_mempool_shape(self) -> None:
        body = self.submit(100)
        block = self.mine()
        packed = self.fetch([body["tx_id"]])["items"][0]["receipt"]
        self.assertEqual(packed["height"], block["height"])
        self.assertEqual(self.svc.rollback_block(str(block["height"]))[0], 200)
        item = self.fetch([body["tx_id"]])["items"][0]
        receipt = item["receipt"]
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])
        _, single = self.svc.get_transaction(body["tx_id"])
        self.assertEqual(receipt, single)

    def test_adoption_reattaches_and_retires_old_positions(self) -> None:
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
        receipt = self.fetch([tx_a.tx_id])["items"][0]["receipt"]
        self.assertEqual(
            (receipt["status"], receipt["height"], receipt["block_hash"]),
            ("confirmed", 1, old_block.block_hash),
        )

        # A strictly longer fork without txA: the old confirmed position
        # is retired and txA is back in the mempool with null locators.
        fork_blocks = []
        prev = genesis.block_hash
        for height in (1, 2, 3):
            block = Block.create(
                height, prev, [tx_obj(kc, C, self.B, height)]
            )
            fork_blocks.append(block)
            prev = block.block_hash
        self.assertEqual(
            self.svc.submit_fork_candidate(
                {"blocks": [genesis.to_dict(), *[b.to_dict() for b in fork_blocks]]}
            )[0],
            201,
        )
        self.assertEqual(self.svc.adopt_fork(fork_blocks[-1].block_hash)[0], 200)
        item = self.fetch([tx_a.tx_id])["items"][0]
        receipt = item["receipt"]
        self.assertEqual(receipt["status"], "pending")
        self.assertIsNone(receipt["height"])
        self.assertIsNone(receipt["block_hash"])
        self.assertIsNone(receipt["index"])
        _, single = self.svc.get_transaction(tx_a.tx_id)
        self.assertEqual(receipt, single)

    def test_query_is_read_only(self) -> None:
        mempool = self.submit(10)
        packed = self.submit(20)
        block = self.mine()
        before_pending = dict(self.svc.store.pending)
        before_events = list(self.svc.store.audit_events)
        before_generation = self.svc.store.generation
        before_idempotency = dict(self.svc.store.idempotency)
        before_sequences = {
            account: {k: dict(v) for k, v in state.items()}
            for account, state in self.svc.store.sequences.items()
        }
        self.fetch([mempool["tx_id"], packed["tx_id"], "0" * 64])
        self.assertEqual(self.svc.store.pending, before_pending)
        self.assertEqual(self.svc.store.audit_events, before_events)
        self.assertEqual(self.svc.store.generation, before_generation)
        self.assertEqual(self.svc.store.idempotency, before_idempotency)
        self.assertEqual(self.svc.store.sequences, before_sequences)
        # No new files beyond the state file the mutations already wrote.
        self.assertEqual(
            sorted(os.listdir(self.tmp)), ["state.json"]
        )

    def test_receipts_rebuilt_identically_after_restart(self) -> None:
        confirmed_body = self.submit(100)
        block1 = self.mine()
        self.svc.confirm_block(str(block1["height"]))
        pending_block_tx = self.submit(30)
        self.mine()  # stays pending across the restart
        mempool_tx = self.submit(5)
        tx_ids = [
            confirmed_body["tx_id"],
            pending_block_tx["tx_id"],
            mempool_tx["tx_id"],
            "0" * 64,
        ]
        before = self.fetch(tx_ids)

        reopened = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        status, after = reopened.get_transaction_receipts({"tx_ids": tx_ids})
        self.assertEqual(status, 200)
        self.assertEqual(after, before)


class ReceiptsHttpTests(unittest.TestCase):
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

    def request(self, method: str, path: str, payload=None, raw_body=None):
        if raw_body is not None:
            data = raw_body
        elif payload is not None:
            data = json.dumps(payload).encode()
        else:
            data = None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_unparseable_and_non_object_bodies_are_400_input(self) -> None:
        for raw in (b"{not json", b"\xff\xfe{}", b"[1]", b"42", b'"x"'):
            status, body = self.request(
                "POST", "/v1/transactions/receipts", raw_body=raw
            )
            self.assertEqual(status, 400, raw)
            self.assertEqual(json.loads(body), {"error": "input"}, raw)

    def test_query_parameters_are_400_input(self) -> None:
        for path in (
            "/v1/transactions/receipts?x=1",
            "/v1/transactions/receipts?tx_ids=" + "0" * 64,
            "/v1/transactions/receipts?blank",
        ):
            status, body = self.request(
                "POST", path, {"tx_ids": ["0" * 64]}
            )
            self.assertEqual(status, 400, path)
            self.assertEqual(json.loads(body), {"error": "input"}, path)
        # A bare trailing "?" carries no parameter and is accepted.
        status, _ = self.request(
            "POST", "/v1/transactions/receipts?", {"tx_ids": ["0" * 64]}
        )
        self.assertEqual(status, 200)

    def test_endpoint_lifecycle_and_wire_key_order(self) -> None:
        # Validation failures are 400 {"error": "input"} with no items.
        status, body = self.request("POST", "/v1/transactions/receipts", {})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "input"})

        _, submitted = self.request(
            "POST", "/v1/transactions", make_tx(self.ka, self.A, self.B, 10)
        )
        tx_id = json.loads(submitted)["tx_id"]

        # Mempool hit plus an unknown id, in request order.
        status, raw = self.request(
            "POST",
            "/v1/transactions/receipts",
            {"tx_ids": ["f" * 64, tx_id]},
        )
        self.assertEqual(status, 200)
        pairs = ordered(raw.encode())
        self.assertEqual([key for key, _ in pairs], list(DOCUMENT_FIELDS))
        items = next(value for key, value in pairs if key == "items")
        self.assertEqual(
            [[key for key, _ in item] for item in items],
            [list(ITEM_FIELDS), list(ITEM_FIELDS)],
        )
        document = json.loads(raw)
        self.assertEqual(document["total"], 2)
        miss, hit = document["items"]
        self.assertEqual(
            miss, {"tx_id": "f" * 64, "receipt": None, "error": "not_found"}
        )
        self.assertIsNone(hit["error"])
        self.assertEqual(hit["receipt"]["status"], "pending")
        self.assertIsNone(hit["receipt"]["height"])

        # Packed but unconfirmed, then confirmed.
        _, block_raw = self.request("POST", "/v1/blocks", {})
        block = json.loads(block_raw)
        _, raw = self.request(
            "POST", "/v1/transactions/receipts", {"tx_ids": [tx_id]}
        )
        receipt = json.loads(raw)["items"][0]["receipt"]
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["block_hash"], block["block_hash"])
        self.request("POST", f"/v1/blocks/{block['height']}/confirm", {})
        _, raw = self.request(
            "POST", "/v1/transactions/receipts", {"tx_ids": [tx_id]}
        )
        receipt = json.loads(raw)["items"][0]["receipt"]
        self.assertEqual(receipt["status"], "confirmed")

        # The single-receipt endpoint is unaffected and agrees.
        status, single_raw = self.request("GET", f"/v1/transactions/{tx_id}")
        self.assertEqual(status, 200)
        self.assertEqual(receipt, json.loads(single_raw))


class ReceiptsCliTests(unittest.TestCase):
    """`ledger txs TX_ID...`: local validation, one JSON line, exit codes."""

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

    def run_cli(self, *args, base_url=None) -> tuple[int, dict, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", base_url or self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw), raw

    def test_local_validation_failures_send_no_request(self) -> None:
        # An unreachable base URL proves no request is attempted: every
        # defect must print {"error": "input"} rather than a connection
        # error, and exit 1.
        dead = "http://127.0.0.1:1"
        cases = [
            (),  # no ids at all
            ("nope",),
            ("A" * 64,),
            ("0" * 63,),
            ("0" * 64, "0" * 64),  # duplicate
            tuple("{:064x}".format(i) for i in range(201)),  # too many
        ]
        for ids in cases:
            rc, body, _ = self.run_cli("txs", *ids, base_url=dead)
            self.assertEqual(rc, 1, ids)
            self.assertEqual(body, {"error": "input"}, ids)

    def test_success_with_misses_is_exit_zero(self) -> None:
        self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 42))
        tx_id = next(iter(self.service.store.pending))
        requested = [tx_id, "0" * 64]
        rc, body, raw = self.run_cli("txs", *requested)
        self.assertEqual(rc, 0, raw)
        self.assertEqual(body["total"], 2)
        self.assertEqual([item["tx_id"] for item in body["items"]], requested)
        hit, miss = body["items"]
        self.assertIsNone(hit["error"])
        self.assertEqual(hit["receipt"]["status"], "pending")
        self.assertEqual(hit["receipt"]["amount"], 42)
        self.assertEqual(miss["error"], "not_found")
        self.assertIsNone(miss["receipt"])

    def test_two_hundred_ids_are_accepted(self) -> None:
        rc, body, _ = self.run_cli(
            "txs", *["{:064x}".format(i) for i in range(200)]
        )
        self.assertEqual(rc, 0)
        self.assertEqual(body["total"], 200)

    def test_connection_failure_is_exit_one(self) -> None:
        rc, body, _ = self.run_cli("txs", "0" * 64, base_url="http://127.0.0.1:1")
        self.assertEqual(rc, 1)
        self.assertIn("error", body)

    def test_tx_subcommand_is_unchanged(self) -> None:
        self.service.submit_transaction(make_tx(self.ka, self.A, self.B, 7))
        tx_id = next(iter(self.service.store.pending))
        rc, body, _ = self.run_cli("tx", tx_id)
        self.assertEqual(rc, 0)
        self.assertEqual(body["tx_id"], tx_id)
        rc, body, _ = self.run_cli("tx", "f" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("error", body)


if __name__ == "__main__":
    unittest.main()
