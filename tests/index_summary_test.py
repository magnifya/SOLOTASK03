"""Tests for the include_summary option of GET /v1/index/transactions.

``include_summary=true`` adds a per-account income/expense summary
(``incoming_count``/``outgoing_count``, ``incoming_amount``/``outgoing_amount``
and ``net_amount``) computed over the WHOLE filtered confirmed set rather
than the current page. Covers the strict flag validation (single
occurrence of true/false, account required, 400 input taking precedence
over anchor lookup), self-transfer accounting (one row, both sides, zero
net contribution), direction interaction, legacy and sequenced transfers
counted identically without nonce de-duplication, empty intersections,
genesis anchors and unknown accounts (200 zeros), full summary on the
empty last page, pending-tip/mempool/candidate exclusion, anchor
stability, restart consistency, read-only behaviour, and the HTTP/CLI
surface.

Run: python3 tests/index_summary_test.py
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


SUMMARY_KEYS = (
    "incoming_count",
    "outgoing_count",
    "incoming_amount",
    "outgoing_amount",
    "net_amount",
)


class SummaryServiceTests(unittest.TestCase):
    """Summary semantics at service level."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(LedgerStore(cls.path), initial_balance=1000)
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls.kd, cls.D = keypair()

        # Block 1 (confirmed, legacy): A->B 10, A->C 20.
        for payload in (
            signed_tx(cls.ka, cls.A, cls.B, 10),
            signed_tx(cls.ka, cls.A, cls.C, 20),
        ):
            rc, _ = cls.svc.submit_transaction(payload)
            assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200

        # Block 2 (confirmed): B->C 5 legacy plus two sequenced transfers
        # C->A 2 (nonce 0) and C->A 8 (nonce 1); both sequenced rows must
        # count independently.
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kb, cls.B, cls.C, 5))
        assert rc == 202
        rc, _ = cls.svc.submit_sequenced_transaction(
            sequenced_payload(cls.kc, cls.C, cls.A, 2, 0)
        )
        assert rc == 202, rc
        rc, _ = cls.svc.submit_sequenced_transaction(
            sequenced_payload(cls.kc, cls.C, cls.A, 8, 1)
        )
        assert rc == 202, rc
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(2)[0] == 200

        # Block 3 (confirmed): an A->A 7 self-transfer.
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.ka, cls.A, cls.A, 7))
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(3)[0] == 200

        # A pending tip (B->A 99) and a mempool entry (D->A 50) that must
        # never participate in the summary.
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kb, cls.B, cls.A, 99))
        assert rc == 202
        assert cls.svc.mine_block()[0] == 201
        rc, _ = cls.svc.submit_transaction(signed_tx(cls.kd, cls.D, cls.A, 50))
        assert rc == 202

        cls.hashes = {
            block.height: block.block_hash for block in cls.svc.store.chain
        }

    def query(self, **params) -> tuple[int, dict]:
        return self.svc.list_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def summary_for(self, account: str, **params) -> dict:
        params.update(include_summary="true", account=account)
        status, body = self.query(**params)
        assert status == 200, body
        return body

    def test_summary_full_set_for_accounts(self) -> None:
        # A rows: A->B 10, A->C 20 (block 1), C->A 2, C->A 8 (block 2),
        # A->A 7 (block 3) — five unique rows; the self-transfer counts on
        # both sides of the summary but occupies only one total.
        body = self.summary_for(self.A)
        self.assertEqual(body["total"], 5)
        self.assertEqual(set(body["summary"]), set(SUMMARY_KEYS))
        self.assertEqual(body["summary"]["incoming_count"], 3)
        self.assertEqual(body["summary"]["outgoing_count"], 3)
        self.assertEqual(body["summary"]["incoming_amount"], 17)
        self.assertEqual(body["summary"]["outgoing_amount"], 37)
        self.assertEqual(body["summary"]["net_amount"], -20)
        # Every figure is an integer (bool is an int subclass and must not
        # appear).
        for name in SUMMARY_KEYS:
            value = body["summary"][name]
            self.assertIsInstance(value, int)
            self.assertNotIsInstance(value, bool)
        # B: in 10, out 5; C: in 25, out 10 (two sequenced transfers).
        body = self.summary_for(self.B)
        self.assertEqual(body["total"], 2)
        self.assertEqual(
            body["summary"],
            {
                "incoming_count": 1,
                "outgoing_count": 1,
                "incoming_amount": 10,
                "outgoing_amount": 5,
                "net_amount": 5,
            },
        )
        body = self.summary_for(self.C)
        self.assertEqual(body["total"], 4)
        self.assertEqual(body["summary"]["incoming_count"], 2)
        self.assertEqual(body["summary"]["outgoing_count"], 2)
        self.assertEqual(body["summary"]["incoming_amount"], 25)
        self.assertEqual(body["summary"]["outgoing_amount"], 10)
        self.assertEqual(body["summary"]["net_amount"], 15)

    def test_self_transfer_counts_once_per_total_but_both_sides(self) -> None:
        # Restrict to block 3: only the A->A self-transfer.
        body = self.summary_for(self.A, height="3")
        self.assertEqual(body["total"], 1)
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(body["summary"]["incoming_count"], 1)
        self.assertEqual(body["summary"]["outgoing_count"], 1)
        self.assertEqual(body["summary"]["incoming_amount"], 7)
        self.assertEqual(body["summary"]["outgoing_amount"], 7)
        self.assertEqual(body["summary"]["net_amount"], 0)

    def test_direction_filters_first_account_classifies_after(self) -> None:
        # direction=out keeps A's three outgoing rows; the self-transfer is
        # also incoming for A, so it still contributes to incoming figures.
        body = self.summary_for(self.A, direction="out")
        self.assertEqual(body["total"], 3)
        self.assertEqual(body["summary"]["outgoing_count"], 3)
        self.assertEqual(body["summary"]["outgoing_amount"], 37)
        self.assertEqual(body["summary"]["incoming_count"], 1)
        self.assertEqual(body["summary"]["incoming_amount"], 7)
        self.assertEqual(body["summary"]["net_amount"], -30)
        # direction=in keeps C->A 2, C->A 8 and A->A 7; the self-transfer
        # is also outgoing.
        body = self.summary_for(self.A, direction="in")
        self.assertEqual(body["total"], 3)
        self.assertEqual(body["summary"]["incoming_count"], 3)
        self.assertEqual(body["summary"]["incoming_amount"], 17)
        self.assertEqual(body["summary"]["outgoing_count"], 1)
        self.assertEqual(body["summary"]["outgoing_amount"], 7)
        self.assertEqual(body["summary"]["net_amount"], 10)

    def test_summary_covers_whole_set_not_only_the_page(self) -> None:
        # Page size 1: the page has one row but the full five-row summary.
        body = self.summary_for(self.A, limit="1", cursor="0")
        self.assertEqual(len(body["items"]), 1)
        self.assertEqual(body["total"], 5)
        self.assertEqual(body["next_cursor"], 1)
        self.assertEqual(body["summary"]["incoming_amount"], 17)
        self.assertEqual(body["summary"]["outgoing_amount"], 37)
        # A middle page is identical in its summary.
        body = self.summary_for(self.A, limit="2", cursor="2")
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual(body["summary"]["incoming_count"], 3)
        self.assertEqual(body["summary"]["net_amount"], -20)
        # cursor == total: empty page, complete summary.
        body = self.summary_for(self.A, cursor="5")
        self.assertEqual(body["items"], [])
        self.assertIsNone(body["next_cursor"])
        self.assertEqual(body["total"], 5)
        self.assertEqual(body["summary"]["outgoing_amount"], 37)
        # cursor > total stays the existing 400 and carries no summary.
        status, body = self.query(
            include_summary="true", account=self.A, cursor="6"
        )
        self.assertEqual(status, 400)
        self.assertNotIn("summary", body)

    def test_filters_and_anchor_intersect_summary(self) -> None:
        # min_height=2 keeps C->A 2, C->A 8 (block 2) and A->A 7 (block 3).
        body = self.summary_for(self.A, min_height="2")
        self.assertEqual(body["total"], 3)
        self.assertEqual(body["summary"]["incoming_amount"], 17)
        self.assertEqual(body["summary"]["outgoing_amount"], 7)
        self.assertEqual(body["summary"]["net_amount"], 10)
        # Anchor at block 2 keeps A's four block-1/block-2 rows:
        # outgoing 30, incoming 10 (C->A 2 + C->A 8).
        body = self.summary_for(
            self.A, at_height="2", at_hash=self.hashes[2]
        )
        self.assertEqual(body["total"], 4)
        self.assertEqual(body["summary"]["incoming_amount"], 10)
        self.assertEqual(body["summary"]["outgoing_amount"], 30)
        self.assertEqual(body["summary"]["net_amount"], -20)
        # Anchor at block 1: A has no incoming yet.
        body = self.summary_for(
            self.A, at_height="1", at_hash=self.hashes[1]
        )
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["summary"]["incoming_count"], 0)
        self.assertEqual(body["summary"]["outgoing_count"], 2)
        self.assertEqual(body["summary"]["outgoing_amount"], 30)
        # Anchor + height past the anchor is an empty set with zeros.
        body = self.summary_for(
            self.A, height="3",
            at_height="1", at_hash=self.hashes[1],
        )
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["summary"], self._zero_summary())
        # The genesis anchor always yields zeros.
        body = self.summary_for(
            self.A, at_height="0", at_hash=self.hashes[0]
        )
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["summary"], self._zero_summary())

    @staticmethod
    def _zero_summary() -> dict:
        return {
            "incoming_count": 0,
            "outgoing_count": 0,
            "incoming_amount": 0,
            "outgoing_amount": 0,
            "net_amount": 0,
        }

    def test_unknown_account_and_empty_intersection(self) -> None:
        unknown = "f" * 64
        body = self.summary_for(unknown)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["items"], [])
        self.assertIsNone(body["next_cursor"])
        self.assertEqual(body["summary"], self._zero_summary())
        # An account that exists but does not meet the height filter.
        body = self.summary_for(self.A, min_height="9")
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["summary"], self._zero_summary())

    def test_pending_tip_and_mempool_excluded(self) -> None:
        # Block 4 (pending B->A 99) and the queued D->A 50 are invisible;
        # this fixture is never mutated by the tests.
        body = self.summary_for(self.A)
        self.assertEqual(body["total"], 5)
        self.assertEqual(body["summary"]["incoming_amount"], 17)
        self.assertEqual(self.svc.store.chain[-1].status, "pending")
        body = self.summary_for(self.D)
        self.assertEqual(body["total"], 0)
        self.assertEqual(body["summary"], self._zero_summary())

    def test_anchor_summary_stable_when_tail_grows(self) -> None:
        # The block-2 anchored answer must not depend on the pending tail
        # behind it (the pending block 4 and the mempool entry).
        params = {
            "at_height": "2", "at_hash": self.hashes[2],
            "include_summary": "true", "account": self.A,
        }
        status, body = self.svc.list_transactions(params)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total"], 4)
        self.assertEqual(body["summary"]["incoming_amount"], 10)
        self.assertEqual(body["summary"]["outgoing_amount"], 30)
        self.assertEqual(body["summary"]["net_amount"], -20)

    def test_restart_preserves_summary(self) -> None:
        params = {"include_summary": "true", "account": self.A, "limit": "50"}
        status, before = self.svc.list_transactions(params)
        self.assertEqual(status, 200)
        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        status, after = reopened.list_transactions(params)
        self.assertEqual(status, 200)
        self.assertEqual(after, before)

    def test_validation_errors(self) -> None:
        good_anchor = {"at_height": "1", "at_hash": self.hashes[1]}
        cases = (
            {"include_summary": ""},
            {"include_summary": "yes"},
            {"include_summary": "1"},
            {"include_summary": "0"},
            {"include_summary": "True"},
            {"include_summary": "false "},
            {"include_summary": " true"},
            # Enabled without an account, or with an empty one.
            {"include_summary": "true"},
            {"include_summary": "true", "account": ""},
            # Bad flag beats anchor lookup, even when the anchor is bad too.
            {"include_summary": "bogus", **good_anchor},
            {"include_summary": "true", "at_height": "9", "at_hash": "a" * 64},
        )
        for params in cases:
            status, body = self.query(**params)
            self.assertEqual(status, 400, params)
            self.assertEqual(body, {"error": "input"}, params)

    def test_anchor_errors_still_reported_with_valid_flag(self) -> None:
        status, body = self.query(
            include_summary="true", account=self.A,
            at_height="99", at_hash="a" * 64,
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "anchor_not_found"})
        status, body = self.query(
            include_summary="true", account=self.A,
            at_height="1", at_hash="a" * 64,
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"error": "anchor_conflict"})

    def test_false_and_omitted_keep_legacy_response(self) -> None:
        status, omitted = self.query(account=self.A)
        self.assertEqual(status, 200)
        self.assertNotIn("summary", omitted)
        status, false_body = self.query(account=self.A, include_summary="false")
        self.assertEqual(status, 200)
        self.assertNotIn("summary", false_body)
        self.assertEqual(false_body, omitted)
        # false without an account is legal and behaves as before.
        status, body = self.query(include_summary="false", direction="all")
        self.assertEqual(status, 200)
        self.assertNotIn("summary", body)

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
            {"include_summary": "true", "account": self.A},
            {"include_summary": "true", "account": "f" * 64},
            {"include_summary": "true", "account": self.A,
             "at_height": "0", "at_hash": self.hashes[0]},
            {"include_summary": "true"},
            {"include_summary": "bad"},
        ):
            self.svc.list_transactions(params)
        with store.lock:
            after = {
                "generation": store.generation,
                "audit": len(store.audit_events),
                "chain": [(b.height, b.block_hash, b.status) for b in store.chain],
                "pending": sorted(store.pending),
                "forks": sorted(store.forks),
            }
        self.assertEqual(before, after)


class SummaryLifecycleTests(unittest.TestCase):
    """Summary stability across confirmation, tail growth and restart."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(LedgerStore(self.path), initial_balance=1000)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        # Block 1 (confirmed): A->B 10.
        rc, _ = self.svc.submit_transaction(signed_tx(self.ka, self.A, self.B, 10))
        assert rc == 202
        assert self.svc.mine_block()[0] == 201
        assert self.svc.confirm_block(1)[0] == 200
        self.h1 = self.svc.store.chain[1].block_hash

    def query(self, svc: LedgerService, **params) -> tuple[int, dict]:
        return svc.list_transactions(
            {k: v for k, v in params.items() if v is not None}
        )

    def test_anchor_summary_stable_as_tail_grows_and_restarts(self) -> None:
        params = {
            "include_summary": "true", "account": self.A,
            "at_height": "1", "at_hash": self.h1,
        }
        status, before = self.query(self.svc, **params)
        self.assertEqual(status, 200, before)
        self.assertEqual(before["summary"]["outgoing_amount"], 10)
        self.assertEqual(before["summary"]["incoming_amount"], 0)
        # Grow the chain: block 2 B->A 4 confirmed, block 3 C->A 1 pending.
        rc, _ = self.svc.submit_transaction(signed_tx(self.kb, self.B, self.A, 4))
        assert rc == 202
        assert self.svc.mine_block()[0] == 201
        assert self.svc.confirm_block(2)[0] == 200
        rc, _ = self.svc.submit_transaction(signed_tx(self.kc, self.C, self.A, 1))
        assert rc == 202
        assert self.svc.mine_block()[0] == 201
        # Anchored view unchanged by growth and the pending tip.
        status, after = self.query(self.svc, **params)
        self.assertEqual(status, 200, after)
        self.assertEqual(after, before)
        # Unanchored view sees block 2 but not pending block 3.
        status, live = self.query(self.svc, include_summary="true", account=self.A)
        self.assertEqual(status, 200, live)
        self.assertEqual(live["total"], 2)
        self.assertEqual(live["summary"]["incoming_amount"], 4)
        self.assertEqual(live["summary"]["outgoing_amount"], 10)
        # Restart preserves both views.
        reopened = LedgerService(LedgerStore(self.path), initial_balance=1000)
        status, restarted = reopened.list_transactions(params)
        self.assertEqual(status, 200, restarted)
        self.assertEqual(restarted, before)
        status, live2 = reopened.list_transactions(
            {"include_summary": "true", "account": self.A}
        )
        self.assertEqual(live2, live)
        # Confirming the tip changes the unanchored summary, not the anchor.
        assert self.svc.confirm_block(3)[0] == 200
        status, grown = self.query(self.svc, include_summary="true", account=self.A)
        self.assertEqual(status, 200, grown)
        self.assertEqual(grown["total"], 3)
        self.assertEqual(grown["summary"]["incoming_amount"], 5)
        status, still = self.query(self.svc, **params)
        self.assertEqual(still, before)


class SummaryHttpTests(unittest.TestCase):
    """The include_summary flag over the real HTTP server."""

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
        assert cls.request("POST", "/v1/blocks/1/confirm")[0] == 200
        rc, _ = cls.request(
            "POST", "/v1/transactions", signed_tx(cls.ka, cls.A, cls.A, 3)
        )
        assert rc == 202
        assert cls.request("POST", "/v1/blocks")[0] == 201
        # Leave block 2 pending: it must not enter the summary.

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

    def test_summary_over_http(self) -> None:
        status, body = self.request(
            "GET", f"/v1/index/transactions?include_summary=true&account={self.A}"
        )
        self.assertEqual(status, 200, body)
        # Only confirmed block 1 counts: A outgoing 12, incoming 5; the
        # pending A->A 3 is excluded.
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["summary"]["outgoing_amount"], 12)
        self.assertEqual(body["summary"]["incoming_amount"], 5)
        self.assertEqual(body["summary"]["net_amount"], -7)
        self.assertEqual(body["summary"]["incoming_count"], 1)
        self.assertEqual(body["summary"]["outgoing_count"], 1)

    def test_flag_violations_over_http(self) -> None:
        for query in (
            "include_summary=",
            "include_summary=yes",
            "include_summary=TRUE",
            "include_summary=1",
            "include_summary=true&include_summary=true",
            "include_summary=true&include_summary=false",
            "include_summary=true",
            "include_summary=true&account=",
        ):
            status, body = self.request(
                "GET", f"/v1/index/transactions?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "input"}, query)

    def test_legacy_response_unchanged_over_http(self) -> None:
        status, body = self.request(
            "GET", f"/v1/index/transactions?account={self.A}"
        )
        self.assertEqual(status, 200)
        self.assertNotIn("summary", body)
        status, body = self.request(
            "GET",
            f"/v1/index/transactions?account={self.A}&include_summary=false",
        )
        self.assertEqual(status, 200)
        self.assertNotIn("summary", body)

    def test_anchor_precedence_over_http(self) -> None:
        # A valid flag with a valid account still surfaces anchor errors.
        status, body = self.request(
            "GET",
            f"/v1/index/transactions?include_summary=true&account={self.A}"
            "&at_height=99&at_hash=" + "a" * 64,
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "anchor_not_found"})


class SummaryCliTests(unittest.TestCase):
    """The index CLI forwards --include-summary."""

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
        assert cls.service.mine_block()[0] == 201
        assert cls.service.confirm_block(1)[0] == 200

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1, "CLI must print exactly one line")
        return rc, json.loads(raw)

    def test_include_summary_cli(self) -> None:
        rc, body = self.run_cli(
            "index", "--include-summary", "--account", self.A
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["total"], 2)
        self.assertEqual(body["summary"]["incoming_amount"], 6)
        self.assertEqual(body["summary"]["outgoing_amount"], 20)
        self.assertEqual(body["summary"]["net_amount"], -14)

    def test_without_flag_keeps_legacy_shape(self) -> None:
        rc, body = self.run_cli("index", "--account", self.A)
        self.assertEqual(rc, 0)
        self.assertNotIn("summary", body)

    def test_flag_without_account_is_input_error(self) -> None:
        rc, body = self.run_cli("index", "--include-summary")
        self.assertEqual(rc, 1)
        self.assertEqual(body, {"error": "input"})


if __name__ == "__main__":
    unittest.main()
