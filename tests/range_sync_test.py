"""Tests for the incremental range protocol on top of full-chain sync.

Covers GET /v1/chain/range (required after_height/after_hash, strict decimal
and 64-hex formats, limit default 100 / range 1-500, repeated parameters 400,
unknown anchor height 404, malformed anchor hash 400, anchor mismatch 409; the
locked {anchor, blocks, canonical, next_height} response, paging via
next_height and pending-tip export) and POST /v1/forks/sync/range (new-request
precedence format 400 -> authorization 403 -> expiry 410 -> stale anchor 409
-> assembled whole-chain re-validation/tip check 400 -> duplicate tip 409;
201 with the same five fields as a full sync; same-key identical-content
retry 200 replaying the first result independently of later authorization or
canonical advancement; malformed retry body 400; different content 409;
assembled candidate adoption by the longest-chain rule; atomic save-failure
rollback of candidate/record/event/generation; restart persistence,
standalone fingerprint re-verification and tamper pruning) at the service,
HTTP and CLI surfaces.

Run: python3 tests/range_sync_test.py
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import threading
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
from ledger.models import STATUS_PENDING, Block, Transaction
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


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    return Transaction.from_dict(signed_tx(key, sender, to, amount))


def make_tail(
    prev_hash: str, start_height: int, specs, pending_last: bool = False
) -> list[Block]:
    """Build a linked list of blocks from (key, sender, recipient, amount) specs."""
    blocks: list[Block] = []
    prev = prev_hash
    for i, group in enumerate(specs):
        txs = [tx_obj(k, s, r, a) for (k, s, r, a) in group]
        status = STATUS_PENDING if pending_last and i == len(specs) - 1 else "confirmed"
        block = Block.create(start_height + i, prev, txs, status)
        blocks.append(block)
        prev = block.block_hash
    return blocks


class RangeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "range.json")
        self.store = LedgerStore(self.path, initial_balance=1_000_000)
        self.service = LedgerService(self.store, initial_balance=1_000_000)
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.exp = int(time.time()) + 10_000_000
        # A confirmed chain 0..3 on the receiver.
        for amount in (10, 20, 30):
            self.assertEqual(
                self.service.submit_transaction(
                    signed_tx(self.ka, self.A, self.B, amount)
                )[0],
                202,
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0], 200
            )
        self.assertEqual(
            self.service.register_trust_source(
                {"source": "node-x", "public_key": self.A, "expires_at": self.exp}
            )[0],
            201,
        )

    # -- GET /v1/chain/range ------------------------------------------------

    def test_range_page_shapes_and_paging(self) -> None:
        g = self.store.chain[0].block_hash
        status, page = self.service.get_chain_range(
            {"after_height": "0", "after_hash": g, "limit": "2"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(page["anchor"], {"height": 0, "block_hash": g})
        self.assertEqual([b["height"] for b in page["blocks"]], [1, 2])
        self.assertEqual(page["next_height"], 3)
        self.assertEqual(page["canonical"]["height"], 3)
        # Continue at the returned next_height.
        anchor2 = self.store.chain[2]
        status, page2 = self.service.get_chain_range(
            {
                "after_height": "2",
                "after_hash": anchor2.block_hash,
            }
        )
        self.assertEqual([b["height"] for b in page2["blocks"]], [3])
        self.assertIsNone(page2["next_height"])
        # A page at the tip is empty but still reports a null next_height.
        status, tip_page = self.service.get_chain_range(
            {
                "after_height": "3",
                "after_hash": self.store.chain[3].block_hash,
            }
        )
        self.assertEqual(status, 200)
        self.assertEqual(tip_page["blocks"], [])
        self.assertIsNone(tip_page["next_height"])

    def test_range_exports_pending_tip(self) -> None:
        self.service.submit_transaction(signed_tx(self.ka, self.A, self.B, 5))
        self.assertEqual(self.service.mine_block()[0], 201)
        status, page = self.service.get_chain_range(
            {"after_height": "3", "after_hash": self.store.chain[3].block_hash}
        )
        self.assertEqual(status, 200)
        self.assertEqual([b["height"] for b in page["blocks"]], [4])
        self.assertEqual(page["blocks"][0]["status"], STATUS_PENDING)
        self.assertIsNone(page["next_height"])

    def test_range_query_errors(self) -> None:
        g = self.store.chain[0].block_hash
        good = {"after_height": "0", "after_hash": g}
        self.assertEqual(self.service.get_chain_range({})[0], 400)
        self.assertEqual(self.service.get_chain_range({"after_height": "0"})[0], 400)
        self.assertEqual(self.service.get_chain_range({"after_hash": g})[0], 400)
        self.assertEqual(
            self.service.get_chain_range(
                {"after_height": "00", "after_hash": g}
            )[0],
            400,
        )
        self.assertEqual(
            self.service.get_chain_range(
                {"after_height": "-1", "after_hash": g}
            )[0],
            400,
        )
        self.assertEqual(
            self.service.get_chain_range(
                {"after_height": "0", "after_hash": g, "limit": "0"}
            )[0],
            400,
        )
        self.assertEqual(
            self.service.get_chain_range(
                {"after_height": "0", "after_hash": g, "limit": "501"}
            )[0],
            400,
        )
        self.assertEqual(
            self.service.get_chain_range(
                {"after_height": "0", "after_hash": "z" * 64}
            )[0],
            400,
        )
        self.assertEqual(
            self.service.get_chain_range(
                {"after_height": "99", "after_hash": g}
            )[0],
            404,
        )
        other = self.store.chain[1].block_hash
        self.assertEqual(
            self.service.get_chain_range(
                {"after_height": "0", "after_hash": other}
            )[0],
            409,
        )
        # Default limit is 100 and accepted without an explicit value.
        self.assertEqual(self.service.get_chain_range(dict(good))[0], 200)

    # -- POST /v1/forks/sync/range ------------------------------------------

    def _range_payload(
        self,
        anchor_height: int,
        tail: list[Block],
        request_id: str = "r1",
        source: str = "node-x",
        expires_at: int | None = None,
        tip: dict | None = None,
    ) -> dict:
        end = tail[-1]
        return {
            "source": source,
            "request_id": request_id,
            "expires_at": self.exp if expires_at is None else expires_at,
            "anchor": {
                "height": anchor_height,
                "block_hash": self.store.chain[anchor_height].block_hash,
            },
            "blocks": [b.to_dict() for b in tail],
            "tip": tip
            or {
                "tip_hash": end.block_hash,
                "height": end.height,
                "length": anchor_height + 1 + len(tail),
                "status": end.status,
            },
        }

    def test_range_acceptance_assembles_and_adopts(self) -> None:
        # A strictly longer alternative tail anchored at block 1: blocks
        # 2', 3', 4' (the receiver canonical chain ends at height 3).
        combined = make_tail(
            self.store.chain[1].block_hash,
            2,
            [
                [(self.ka, self.A, self.B, 40)],
                [(self.kb, self.B, self.A, 5)],
                [(self.ka, self.A, self.B, 7)],
            ],
        )
        payload = self._range_payload(1, combined, request_id="r-long")
        status, body = self.service.submit_fork_sync_range(payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["height"], 4)
        self.assertEqual(body["length"], 5)
        self.assertEqual(body["status"], "confirmed")
        self.assertEqual(body["expires_at"], self.exp)
        self.assertEqual(body["tip_hash"], combined[-1].block_hash)
        # The ASSEMBLED full candidate (genesis..tip) is stored for adoption.
        self.assertIn(body["tip_hash"], self.store.forks)
        assembled = self.store.forks[body["tip_hash"]]
        self.assertEqual(len(assembled), 5)
        self.assertEqual(assembled[0], self.store.chain[0])
        # Longest-chain rule is unchanged: strictly longer, so it wins.
        status, adopted = self.service.adopt_fork(body["tip_hash"])
        self.assertEqual(status, 200, adopted)
        self.assertEqual(self.store.tip().block_hash, body["tip_hash"])
        self.assertEqual([b.height for b in self.store.chain], [0, 1, 2, 3, 4])

    def test_new_request_status_precedence(self) -> None:
        tail = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 40)]]
        )
        good = self._range_payload(1, tail, request_id="m")
        n = {"v": 0}

        def variant(**changes) -> dict:
            n["v"] += 1
            body = json.loads(json.dumps(good))
            body["request_id"] = f"m{n['v']}"
            body.update(changes)
            return body

        # Format 400.
        self.assertEqual(
            self.service.submit_fork_sync_range({"source": "node-x"})[0], 400
        )
        body = variant()
        body["anchor"] = {"height": "1", "block_hash": self.store.chain[1].block_hash}
        self.assertEqual(self.service.submit_fork_sync_range(body)[0], 400)
        body = variant(blocks=[])
        self.assertEqual(self.service.submit_fork_sync_range(body)[0], 400)
        body = variant()
        del body["tip"]
        self.assertEqual(self.service.submit_fork_sync_range(body)[0], 400)
        # Authorization 403 beats expiry/anchor/chain checks.
        self.assertEqual(
            self.service.submit_fork_sync_range(variant(source="ghost"))[0], 403
        )
        # Expiry 410 beats anchor and chain validation.
        self.assertEqual(
            self.service.submit_fork_sync_range(
                variant(expires_at=int(time.time()) - 1)
            )[0],
            410,
        )
        self.assertEqual(
            self.service.submit_fork_sync_range(
                variant(
                    expires_at=int(time.time()) - 1,
                    anchor={"height": 1, "block_hash": "0" * 64},
                )
            )[0],
            410,
        )
        # Stale anchor 409 (unknown height or mismatched hash) beats 400 chain
        # validation.
        self.assertEqual(
            self.service.submit_fork_sync_range(
                variant(anchor={"height": 1, "block_hash": "0" * 64})
            )[0],
            409,
        )
        self.assertEqual(
            self.service.submit_fork_sync_range(
                variant(anchor={"height": 99, "block_hash": "0" * 64})
            )[0],
            409,
        )
        # Assembled whole-chain re-validation failures are 400: a tail tx that
        # duplicates a canonical-prefix txid, and a replay overspend.
        dup = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 10)]]
        )
        self.assertEqual(
            self.service.submit_fork_sync_range(
                self._range_payload(1, dup, request_id="dup")
            )[0],
            400,
        )
        overspend = make_tail(
            self.store.chain[1].block_hash,
            2,
            [[(self.ka, self.A, self.B, 10_000_000)]],
        )
        self.assertEqual(
            self.service.submit_fork_sync_range(
                self._range_payload(1, overspend, request_id="over")
            )[0],
            400,
        )
        # Tampered tip summary is 400.
        body = variant()
        body["tip"] = {"tip_hash": "0" * 64}
        self.assertEqual(self.service.submit_fork_sync_range(body)[0], 400)

    def test_duplicate_tip_conflicts(self) -> None:
        tail = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 40)]]
        )
        payload = self._range_payload(1, tail, request_id="d1")
        self.assertEqual(self.service.submit_fork_sync_range(payload)[0], 201)
        # Same assembled tip under a different idempotency key -> 409.
        self.assertEqual(
            self.service.submit_fork_sync_range(
                self._range_payload(1, tail, request_id="d2")
            )[0],
            409,
        )

    def test_retry_replays_independently(self) -> None:
        tail = make_tail(
            self.store.chain[1].block_hash,
            2,
            [
                [(self.ka, self.A, self.B, 40)],
                [(self.kb, self.B, self.A, 5)],
                [(self.ka, self.A, self.B, 7)],
            ],
        )
        payload = self._range_payload(1, tail)
        status, first = self.service.submit_fork_sync_range(payload)
        self.assertEqual(status, 201)
        # The assembled candidate (5 blocks) is strictly longer than canonical
        # (4), so the unchanged longest-chain rule lets it win adoption.
        self.assertEqual(self.service.adopt_fork(first["tip_hash"])[0], 200)
        self.assertEqual(self.store.tip().height, 4)
        # Extend the canonical chain one more block past the adopted tip.
        self.service.submit_transaction(signed_tx(self.kb, self.B, self.A, 9))
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("5")[0], 200)
        # Revoke the source after delivery: the retry bypasses authorization
        # and replays the first result even though the canonical anchor moved.
        self.assertEqual(
            self.service.revoke_trust_source("node-x", {"expected_version": 1})[0],
            200,
        )
        status, replay = self.service.submit_fork_sync_range(payload)
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        # A malformed retry body must fail 400, never replay the cached 200.
        bad = json.loads(json.dumps(payload))
        bad["blocks"] = [{"height": 3}]
        self.assertEqual(self.service.submit_fork_sync_range(bad)[0], 400)
        bad = json.loads(json.dumps(payload))
        bad["tip"] = {"tip_hash": "0" * 64}
        self.assertEqual(self.service.submit_fork_sync_range(bad)[0], 400)
        # Same key with a different but valid tail conflicts 409.
        other = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 41)]]
        )
        changed = self._range_payload(1, other)
        self.assertEqual(self.service.submit_fork_sync_range(changed)[0], 409)

    def test_pending_tip_range(self) -> None:
        tail = make_tail(
            self.store.chain[0].block_hash,
            1,
            [[(self.ka, self.A, self.B, 3)]],
            pending_last=True,
        )
        payload = self._range_payload(0, tail, request_id="pend")
        status, body = self.service.submit_fork_sync_range(payload)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], STATUS_PENDING)
        self.assertEqual(
            self.store.forks[body["tip_hash"]][-1].status, STATUS_PENDING
        )

    def test_save_failure_changes_nothing(self) -> None:
        tail = make_tail(
            self.store.chain[1].block_hash, 2, [[(self.ka, self.A, self.B, 40)]]
        )
        payload = self._range_payload(1, tail, request_id="atomic")
        gen = self.store.generation
        n_forks = len(self.store.forks)
        n_syncs = len(self.store.syncs)
        n_events = len(self.store.audit_events)

        def failing() -> None:
            raise OSError("disk full")

        self.store.save = failing  # type: ignore[method-assign]
        with self.assertRaises(OSError):
            self.service.submit_fork_sync_range(payload)
        del self.store.save
        self.assertEqual(self.store.generation, gen)
        self.assertEqual(len(self.store.forks), n_forks)
        self.assertEqual(len(self.store.syncs), n_syncs)
        self.assertEqual(len(self.store.audit_events), n_events)
        # The same request then succeeds normally.
        self.assertEqual(
            self.service.submit_fork_sync_range(payload)[0], 201
        )
        self.assertEqual(self.store.generation, gen + 1)
        self.assertEqual(len(self.store.syncs), n_syncs + 1)
        self.assertEqual(len(self.store.audit_events), n_events + 1)
        self.assertEqual(
            self.store.audit_events[-1]["kind"], "sync_received"
        )

    def test_restart_persists_and_verifies_range(self) -> None:
        tail = make_tail(
            self.store.chain[1].block_hash,
            2,
            [[(self.ka, self.A, self.B, 40)], [(self.kb, self.B, self.A, 5)]],
        )
        payload = self._range_payload(1, tail)
        status, first = self.service.submit_fork_sync_range(payload)
        self.assertEqual(status, 201)
        # Restart with the source still active and the canonical chain moved
        # forward: the record and assembled candidate survive, and the retry
        # still replays without re-splicing.
        self.service.submit_transaction(signed_tx(self.kb, self.B, self.A, 2))
        self.service.mine_block()
        self.service.confirm_block("4")
        del self.store
        self.store = LedgerStore(self.path)
        self.service = LedgerService(self.store)
        key = ("node-x", "r1")
        self.assertIn(key, self.store.syncs)
        record = self.store.syncs[key]
        self.assertIn("range", record)
        self.assertEqual(record["fingerprint"], self.store.range_fingerprint(
            record["range"]["anchor"],
            self.store.validate_range_tail(
                record["range"]["anchor"], record["range"]["blocks"]
            ),
        ))
        status, replay = self.service.submit_fork_sync_range(payload)
        self.assertEqual(status, 200)
        self.assertEqual(replay, first)
        # Tampering with the persisted range payload invalidates the record
        # (and drops the fork it alone kept alive) on the next restart.
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        for rec in raw["syncs"]:
            if rec.get("request_id") == "r1":
                rec["range"]["blocks"][0]["transactions"][0]["amount"] += 1
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, sort_keys=True)
        self.store = LedgerStore(self.path)
        self.assertNotIn(key, self.store.syncs)
        self.assertNotIn(first["tip_hash"], self.store.forks)


class RangeHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(LedgerStore(os.path.join(cls.tmp, "http.json")))
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    @classmethod
    def request(cls, method: str, path: str, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if data is not None else {}
        req = urllib.request.Request(
            f"{cls.base}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_chain_range_http(self) -> None:
        g = self.service.store.chain[0].block_hash
        status, body = self.request(
            "GET", f"/v1/chain/range?after_height=0&after_hash={g}"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["blocks"], [])
        self.assertIsNone(body["next_height"])
        self.assertEqual(self.request("GET", "/v1/chain/range")[0], 400)
        self.assertEqual(
            self.request(
                "GET", f"/v1/chain/range?after_height=0&after_hash={g}&limit=501"
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "GET",
                f"/v1/chain/range?after_height=0&after_hash={g}&after_height=1",
            )[0],
            400,
        )
        self.assertEqual(
            self.request("GET", "/v1/chain/range?after_height=99&after_hash=" + g)[0],
            404,
        )

    def test_sync_range_http(self) -> None:
        # Unauthorized without a trust registration: envelope is well formed,
        # so the new-request gate returns 403.
        genesis = self.service.store.chain[0]
        tail = make_tail(
            genesis.block_hash, 1, [[(self.ka, self.A, self.B, 5)]]
        )
        payload = {
            "source": "http-x",
            "request_id": "h-range",
            "expires_at": int(time.time()) + 3600,
            "anchor": {"height": 0, "block_hash": genesis.block_hash},
            "blocks": [b.to_dict() for b in tail],
            "tip": {
                "tip_hash": tail[-1].block_hash,
                "height": 1,
                "length": 2,
                "status": "confirmed",
            },
        }
        self.assertEqual(
            self.request("POST", "/v1/forks/sync/range", payload)[0], 403
        )
        self.assertEqual(
            self.request("POST", "/v1/forks/sync/range", {"nope": True})[0], 400
        )


class RangeCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.service = LedgerService(LedgerStore(os.path.join(cls.tmp, "cli.json")))
        cls.exp = int(time.time()) + 10_000_000
        cls.service.register_trust_source(
            {"source": "cli-x", "public_key": cls.A, "expires_at": cls.exp}
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.service)
        )
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def run_cli(self, *args) -> tuple[int, dict]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["--base-url", self.base_url, *args])
        raw = buf.getvalue()
        self.assertEqual(raw.count("\n"), 1)
        return rc, json.loads(raw)

    def test_chain_range_and_sync_range_cli(self) -> None:
        genesis = self.service.store.chain[0]
        # chain-range at genesis: empty page, exit 0.
        rc, page = self.run_cli(
            "chain-range", "--after-height", "0", "--after-hash", genesis.block_hash
        )
        self.assertEqual(rc, 0, page)
        self.assertEqual(page["blocks"], [])
        # Bad anchor hash format exits 1 with one JSON line.
        rc, _ = self.run_cli(
            "chain-range", "--after-height", "0", "--after-hash", "zz"
        )
        self.assertEqual(rc, 1)
        # Build and push one tail block via sync-range, deriving tip from the
        # document's final block (tip omitted, as in a chain-range page).
        tail = make_tail(
            genesis.block_hash, 1, [[(self.ka, self.A, self.B, 5)]]
        )
        document = json.dumps(
            {
                "anchor": {"height": 0, "block_hash": genesis.block_hash},
                "blocks": [b.to_dict() for b in tail],
            }
        )
        rc, body = self.run_cli(
            "sync-range",
            "--source", "cli-x",
            "--request-id", "cr1",
            "--expires-at", str(self.exp),
            document,
        )
        self.assertEqual(rc, 0, body)
        self.assertEqual(body["tip_hash"], tail[-1].block_hash)
        self.assertEqual(body["length"], 2)
        # Idempotent retry: same single-line body, exit 0.
        rc, retry = self.run_cli(
            "sync-range",
            "--source", "cli-x",
            "--request-id", "cr1",
            "--expires-at", str(self.exp),
            document,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(retry, body)
        # Unauthorized source exits 1.
        rc, _ = self.run_cli(
            "sync-range",
            "--source", "ghost",
            "--request-id", "cr2",
            "--expires-at", str(self.exp),
            document,
        )
        self.assertEqual(rc, 1)
        # Malformed JSON document exits 1.
        rc, _ = self.run_cli(
            "sync-range",
            "--source", "cli-x",
            "--request-id", "cr3",
            "--expires-at", str(self.exp),
            "{not json",
        )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
