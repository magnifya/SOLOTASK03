"""Tests for the read-only synchronization precheck.

Covers POST /v1/chain/sync-plan end to end:

* service validation — the body is a JSON object containing exactly the
  ordered keys locators, tip, finalized; locators follow the
  headers/locate contract (1-64 strictly descending height/block_hash
  items) and the first item must pin tip; tip is a closed descriptor S
  (tip_hash, height, length == height + 1, status); finalized is an
  anchor no higher than tip (equal height requires the same hash and a
  confirmed tip); every defect is 400 {"ok": false, "error": "input"}
  with no state read;
* in-lock canonical matching — the first in-order locator naming a
  canonical block is the common ancestor, otherwise 409
  no_common_ancestor;
* the 200 document keeps key order ok, ancestor, relation, pull, error:
  relation is same / remote_ahead / local_ahead / fork in that priority,
  pull is the closed {from_height, to_height} interval only when the
  remote is longer or equal-length with the smaller tip hash, and the
  rejection reasons remote_behind / not_preferred / finality_conflict
  live only in error;
* the HTTP wire boundary (parse failures are 400, key order preserved)
  and the CLI `sync-plan FILE|-` subcommand (single line, exit 1 on any
  non-2xx or local input failure).

Run: python3 tests/sync_plan_test.py
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore

SUCCESS_KEYS = ["ok", "ancestor", "relation", "pull", "error"]
INPUT_BODY = {"ok": False, "error": "input"}


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class SyncPlanFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "plan.json"))
        self.service = LedgerService(self.store)
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        # A confirmed chain 0..3; individual tests may append a pending tip.
        for amount in (10, 20, 30):
            self.assertEqual(
                self.service.submit_transaction(self._tx(amount))[0], 202
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0],
                200,
            )

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def anchor(self, height: int) -> dict:
        return {
            "height": height,
            "block_hash": self.store.chain[height].block_hash,
        }

    def local_summary(self) -> dict:
        return self.service._fork_summary(self.store.chain)

    def plan(self, locators, tip, finalized):
        return self.service.sync_plan(
            {"locators": locators, "tip": tip, "finalized": finalized}
        )

    @staticmethod
    def remote(height: int, block_hash: str, status: str = "confirmed") -> dict:
        return {
            "tip_hash": block_hash,
            "height": height,
            "length": height + 1,
            "status": status,
        }


class SyncPlanServiceTests(SyncPlanFixture):
    # -- success relations ---------------------------------------------------

    def test_same_confirmed_chain(self) -> None:
        tip = self.local_summary()
        status, body = self.plan(
            [self.anchor(3)], tip, self.anchor(3)
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body.keys()), SUCCESS_KEYS)
        self.assertTrue(body["ok"])
        self.assertEqual(body["ancestor"], self.anchor(3))
        self.assertEqual(body["relation"], "same")
        self.assertIsNone(body["pull"])
        self.assertIsNone(body["error"])

    def test_same_with_pending_local_tip(self) -> None:
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip = self.local_summary()
        self.assertEqual(tip["status"], "pending")
        status, body = self.plan(
            [self.anchor(4), self.anchor(3)], tip, self.anchor(3)
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "same")
        self.assertEqual(body["ancestor"], self.anchor(4))
        self.assertIsNone(body["pull"])

    def test_remote_ahead_plans_closed_interval(self) -> None:
        # Peer tip at height 5; its second locator is the local tip at 3.
        status, body = self.plan(
            [{"height": 5, "block_hash": "a" * 64}, self.anchor(3)],
            self.remote(5, "a" * 64),
            self.anchor(3),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["ancestor"], self.anchor(3))
        self.assertEqual(body["relation"], "remote_ahead")
        self.assertEqual(
            body["pull"], {"from_height": 4, "to_height": 5}
        )
        self.assertEqual(list(body["pull"].keys()), ["from_height", "to_height"])
        self.assertIsNone(body["error"])

    def test_remote_ahead_from_pending_local_tip(self) -> None:
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        # The peer finalizes exactly the block the local node still has
        # pending; the same hash is part of the common prefix, so it is not a
        # finality contradiction.
        status, body = self.plan(
            [{"height": 6, "block_hash": "a" * 64}, self.anchor(4)],
            self.remote(6, "a" * 64),
            self.anchor(4),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "remote_ahead")
        self.assertEqual(body["pull"], {"from_height": 5, "to_height": 6})
        self.assertIsNone(body["error"])

    def test_local_ahead_is_remote_behind(self) -> None:
        # Peer tip is local block 2: ancestor == remote tip, shorter chain.
        status, body = self.plan(
            [self.anchor(2)],
            self.remote(2, self.store.chain[2].block_hash),
            self.anchor(2),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "local_ahead")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "remote_behind")

    def test_equal_length_fork_smaller_remote_tip_wins_pull(self) -> None:
        # Local tip is a pending height-4 block (finalized head stays 3), so a
        # competing height-4 fork splits above finality and may be preferred.
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        local_tip_hash = self.store.tip_hash()
        small = "0" * 64  # lexicographically below the real local tip hash
        self.assertLess(small, local_tip_hash)
        status, body = self.plan(
            [{"height": 4, "block_hash": small}, self.anchor(3)],
            self.remote(4, small),
            self.anchor(3),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertEqual(body["ancestor"], self.anchor(3))
        self.assertEqual(body["pull"], {"from_height": 4, "to_height": 4})
        self.assertIsNone(body["error"])

    def test_equal_length_fork_larger_remote_tip_not_preferred(self) -> None:
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        local_tip_hash = self.store.tip_hash()
        large = "f" * 64
        self.assertGreater(large, local_tip_hash)
        status, body = self.plan(
            [{"height": 4, "block_hash": large}, self.anchor(3)],
            self.remote(4, large),
            self.anchor(3),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "not_preferred")

    def test_longer_fork_plans_pull(self) -> None:
        # A pending local tip at 4 and a longer remote chain forking above the
        # shared finalized boundary at 3.
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        status, body = self.plan(
            [{"height": 5, "block_hash": "9" * 64}, self.anchor(3)],
            self.remote(5, "9" * 64),
            self.anchor(3),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertEqual(body["pull"], {"from_height": 4, "to_height": 5})
        self.assertIsNone(body["error"])

    def test_first_in_order_locator_is_the_ancestor(self) -> None:
        # A non-matching high locator is skipped; the first canonical hit
        # wins even though a deeper locator also matches later. The peer
        # finalizes the local boundary at 3, so the shallow height-2 anchor
        # stays consistent (the divergence is above finality).
        status, body = self.plan(
            [
                {"height": 5, "block_hash": "a" * 64},
                {"height": 3, "block_hash": "c" * 64},
                self.anchor(2),
                self.anchor(0),
            ],
            self.remote(5, "a" * 64),
            self.anchor(3),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["ancestor"], self.anchor(2))
        self.assertEqual(body["relation"], "fork")
        self.assertEqual(body["pull"], {"from_height": 3, "to_height": 5})

    # -- no common ancestor --------------------------------------------------

    def test_no_common_ancestor_is_409(self) -> None:
        status, body = self.plan(
            [
                {"height": 4, "block_hash": "a" * 64},
                {"height": 3, "block_hash": "b" * 64},
            ],
            self.remote(4, "a" * 64),
            self.anchor(0),
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, {"ok": False, "error": "no_common_ancestor"})
        self.assertEqual(list(body.keys()), ["ok", "error"])

    # -- finality conflicts ---------------------------------------------------

    def test_ancestor_below_local_finalized_is_conflict(self) -> None:
        # Local finalized head is height 3; the only common block is 1.
        status, body = self.plan(
            [
                {"height": 5, "block_hash": "a" * 64},
                {"height": 3, "block_hash": "d" * 64},
                self.anchor(1),
            ],
            self.remote(5, "a" * 64),
            self.anchor(0),
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "finality_conflict")

    def test_peer_finalized_above_ancestor_on_other_fork_is_conflict(self) -> None:
        # Ancestor is height 2 (no height-3 locator); the peer claims a
        # finalized height-3 block different from the local confirmed one.
        status, body = self.plan(
            [{"height": 5, "block_hash": "a" * 64}, self.anchor(2)],
            self.remote(5, "a" * 64),
            {"height": 3, "block_hash": "d" * 64},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["error"], "finality_conflict")
        self.assertIsNone(body["pull"])

    def test_peer_finalized_matching_local_confirmed_is_not_conflict(self) -> None:
        status, body = self.plan(
            [{"height": 5, "block_hash": "a" * 64}, self.anchor(2)],
            self.remote(5, "a" * 64),
            self.anchor(3),
        )
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["error"])
        self.assertEqual(body["pull"], {"from_height": 3, "to_height": 5})

    def test_peer_finalized_below_ancestor_with_matching_hash_ok(self) -> None:
        status, body = self.plan(
            [{"height": 5, "block_hash": "a" * 64}, self.anchor(3)],
            self.remote(5, "a" * 64),
            self.anchor(1),
        )
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["error"])

    def test_peer_finalized_below_ancestor_with_wrong_hash_conflict(self) -> None:
        # The claimed finalized height-1 block is not the canonical block the
        # ancestor's own hash commits to.
        status, body = self.plan(
            [{"height": 5, "block_hash": "a" * 64}, self.anchor(3)],
            self.remote(5, "a" * 64),
            {"height": 1, "block_hash": "d" * 64},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["error"], "finality_conflict")
        self.assertIsNone(body["pull"])

    # -- 400 validation -------------------------------------------------------

    def assert400(self, payload) -> None:
        status, body = self.service.sync_plan(payload)
        self.assertEqual(status, 400, payload)
        self.assertEqual(body, INPUT_BODY)

    def test_body_must_be_closed_ordered_object(self) -> None:
        self.assert400([])
        self.assert400("nope")
        self.assert400(None)
        self.assert400({})
        self.assert400({"tip": {}, "finalized": {}, "locators": []})
        self.assert400({"locators": [], "tip": {}})
        self.assert400(
            {"locators": [], "tip": {}, "finalized": {}, "extra": 1}
        )
        self.assert400(
            {"finalized": {}, "tip": {}, "locators": []}
        )

    def test_locators_contract(self) -> None:
        tip = self.remote(3, self.store.chain[3].block_hash)
        good = [self.anchor(3)]
        self.assert400({"locators": [], "tip": tip, "finalized": self.anchor(3)})
        self.assert400({"locators": {}, "tip": tip, "finalized": self.anchor(3)})
        self.assert400(
            {"locators": [self.anchor(3), "x"], "tip": tip,
             "finalized": self.anchor(3)}
        )
        self.assert400(
            {"locators": [[3, tip["tip_hash"]]], "tip": tip,
             "finalized": self.anchor(3)}
        )
        # Reordered locator item keys.
        self.assert400(
            {"locators": [{"block_hash": tip["tip_hash"], "height": 3}],
             "tip": tip, "finalized": self.anchor(3)}
        )
        # Bool/negative/float locator heights (the first item still pins the
        # tip structurally so the locator-level check is what fails).
        self.assert400(
            {"locators": [{"height": True, "block_hash": tip["tip_hash"]}],
             "tip": {**tip, "height": True, "length": 2},
             "finalized": {"height": 0, "block_hash": "0" * 64}}
        )
        self.assert400(
            {"locators": [{"height": -1, "block_hash": tip["tip_hash"]}],
             "tip": {**tip, "height": -1, "length": 0, "status": "pending"},
             "finalized": {"height": -1, "block_hash": tip["tip_hash"]}}
        )
        self.assert400(
            {"locators": [{"height": 3.0, "block_hash": tip["tip_hash"]}],
             "tip": tip, "finalized": self.anchor(3)}
        )
        self.assert400(
            {"locators": [{"height": 3, "block_hash": "Z" * 64}],
             "tip": tip, "finalized": self.anchor(3)}
        )
        # Not strictly descending.
        self.assert400(
            {"locators": [self.anchor(3), self.anchor(3)], "tip": tip,
             "finalized": self.anchor(3)}
        )
        self.assert400(
            {"locators": [self.anchor(2), self.anchor(3)], "tip": tip,
             "finalized": self.anchor(2)}
        )
        # 65 items (heights stay strictly descending).
        too_many = [
            {"height": 100 - i, "block_hash": "1" * 64} for i in range(65)
        ]
        self.assert400(
            {"locators": too_many,
             "tip": self.remote(100, "1" * 64),
             "finalized": self.anchor(0)}
        )

    def test_tip_contract(self) -> None:
        loc = [self.anchor(3)]
        base = self.remote(3, self.store.chain[3].block_hash)
        self.assert400({"locators": loc, "tip": [], "finalized": self.anchor(3)})
        # Missing a descriptor field is 400 (nested key order itself follows
        # the sync-range precedent and is not enforced).
        self.assert400(
            {"locators": loc,
             "tip": {"height": 3, "length": 4, "status": "confirmed"},
             "finalized": self.anchor(3)}
        )
        self.assert400(
            {"locators": loc,
             "tip": {**base, "status": "confirmed", "extra": 1},
             "finalized": self.anchor(3)}
        )
        self.assert400(
            {"locators": loc, "tip": {**base, "tip_hash": "Z" * 64},
             "finalized": self.anchor(3)}
        )
        self.assert400(
            {"locators": loc, "tip": {**base, "height": True},
             "finalized": {"height": True, "block_hash": base["tip_hash"]}}
        )
        self.assert400(
            {"locators": loc, "tip": {**base, "height": -1, "length": 0},
             "finalized": {"height": -1, "block_hash": base["tip_hash"]}}
        )
        self.assert400(
            {"locators": loc, "tip": {**base, "length": 0},
             "finalized": self.anchor(3)}
        )
        # A descriptor whose length is not height + 1 denies the S shape.
        self.assert400(
            {"locators": loc, "tip": {**base, "length": 5},
             "finalized": self.anchor(3)}
        )
        self.assert400(
            {"locators": loc, "tip": {**base, "status": "weird"},
             "finalized": self.anchor(3)}
        )

    def test_finalized_contract(self) -> None:
        loc = [self.anchor(3)]
        tip = self.remote(3, self.store.chain[3].block_hash)
        self.assert400({"locators": loc, "tip": tip, "finalized": []})
        self.assert400(
            {"locators": loc, "tip": tip,
             "finalized": {"height": 3}}
        )
        self.assert400(
            {"locators": loc, "tip": tip,
             "finalized": {"height": 3, "block_hash": tip["tip_hash"],
                           "extra": 1}}
        )
        self.assert400(
            {"locators": loc, "tip": tip,
             "finalized": {"height": 3, "block_hash": "Z" * 64}}
        )
        self.assert400(
            {"locators": loc, "tip": tip,
             "finalized": {"height": True, "block_hash": tip["tip_hash"]}}
        )
        # Finalized above the tip.
        self.assert400(
            {"locators": loc, "tip": tip,
             "finalized": {"height": 4, "block_hash": "1" * 64}}
        )

    def test_first_locator_must_pin_tip(self) -> None:
        # Same height, different hash.
        self.assert400(
            {"locators": [{"height": 3, "block_hash": "1" * 64}],
             "tip": self.remote(3, self.store.chain[3].block_hash),
             "finalized": self.anchor(3)}
        )
        # Same hash, different height.
        self.assert400(
            {"locators": [self.anchor(2), self.anchor(3)],
             "tip": self.remote(3, self.store.chain[3].block_hash),
             "finalized": self.anchor(2)}
        )

    def test_equal_height_finalized_requires_tip_hash_and_confirmation(self) -> None:
        # Same height, different hash.
        self.assert400(
            {"locators": [self.anchor(3)],
             "tip": self.remote(3, self.store.chain[3].block_hash),
             "finalized": {"height": 3, "block_hash": "1" * 64}}
        )
        # Same hash but the tip is still pending.
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip = self.local_summary()
        self.assertEqual(tip["status"], "pending")
        self.assert400(
            {"locators": [self.anchor(4)], "tip": tip,
             "finalized": self.anchor(4)}
        )

    def test_read_only_no_state_mutation(self) -> None:
        before = self.store.generation
        tip = self.local_summary()
        for payload in (
            {"locators": [self.anchor(3)], "tip": tip,
             "finalized": self.anchor(3)},
            {"locators": [{"height": 9, "block_hash": "a" * 64}],
             "tip": self.remote(9, "a" * 64),
             "finalized": self.anchor(0)},
            {"locators": "bad", "tip": tip, "finalized": self.anchor(3)},
        ):
            self.service.sync_plan(payload)
        self.assertEqual(self.store.generation, before)


class SyncPlanHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"))
        )
        cls.key = Ed25519PrivateKey.generate()
        cls.sender = pub_hex(cls.key)
        bob = "b" * 64
        for amount in (10, 20):
            message = crypto.canonical_message(cls.sender, bob, amount)
            cls.service.submit_transaction(
                {
                    "from": cls.sender,
                    "to": bob,
                    "amount": amount,
                    "signature": cls.key.sign(message).hex(),
                }
            )
            cls.service.mine_block()
            cls.service.confirm_block(str(cls.service.store.tip().height))
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

    def post(self, raw: bytes | str):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}/v1/chain/sync-plan",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def payload(self, **overrides) -> dict:
        tip = self.service._fork_summary(self.service.store.chain)
        body = {
            "locators": [
                {"height": tip["height"], "block_hash": tip["tip_hash"]}
            ],
            "tip": tip,
            "finalized": {
                "height": tip["height"],
                "block_hash": tip["tip_hash"],
            },
        }
        body.update(overrides)
        return body

    def test_success_key_order_on_wire(self) -> None:
        status, raw = self.post(json.dumps(self.payload()))
        self.assertEqual(status, 200, raw)
        self.assertEqual(
            [
                segment
                for segment in ("ok", "ancestor", "relation", "pull", "error")
                if f'"{segment}"' in raw
            ],
            ["ok", "ancestor", "relation", "pull", "error"],
        )
        document = json.loads(raw)
        self.assertEqual(document["relation"], "same")
        self.assertTrue(document["ok"])

    def test_parse_and_input_failures_are_ordered_400(self) -> None:
        self.assertEqual(self.post("{not json}")[0], 400)
        self.assertEqual(self.post("")[0], 400)
        status, raw = self.post(json.dumps({}))
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw), INPUT_BODY)
        self.assertEqual(
            [name for name in ("ok", "error") if f'"{name}"' in raw],
            ["ok", "error"],
        )
        # First locator does not pin the tip -> input.
        bad = self.payload(
            locators=[{"height": 0, "block_hash": "1" * 64}]
        )
        self.assertEqual(self.post(json.dumps(bad))[0], 400)

    def test_no_common_ancestor_is_409(self) -> None:
        status, raw = self.post(
            json.dumps(
                self.payload(
                    locators=[{"height": 9, "block_hash": "a" * 64}],
                    tip={
                        "tip_hash": "a" * 64,
                        "height": 9,
                        "length": 10,
                        "status": "confirmed",
                    },
                    finalized={"height": 0, "block_hash": "1" * 64},
                )
            )
        )
        self.assertEqual(status, 409)
        self.assertEqual(
            json.loads(raw), {"ok": False, "error": "no_common_ancestor"}
        )


class SyncPlanCliTests(SyncPlanFixture):
    def run_cli(self, *argv: str) -> tuple[int, str]:
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            rc = cli_main(["--base-url", "http://127.0.0.1:1", *argv])
        return rc, capture.getvalue()

    def write_plan(self, document: dict) -> str:
        path = os.path.join(self.tmp, "plan-request.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(document))
        return path

    def valid_document(self) -> dict:
        tip = self.local_summary()
        return {
            "locators": [self.anchor(3)],
            "tip": tip,
            "finalized": self.anchor(3),
        }

    def test_local_bad_json_exits_one_without_server(self) -> None:
        path = os.path.join(self.tmp, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        rc, output = self.run_cli("sync-plan", path)
        self.assertEqual(rc, 1)
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(json.loads(output), INPUT_BODY)

    def test_missing_file_exits_one_without_server(self) -> None:
        rc, output = self.run_cli(
            "sync-plan", os.path.join(self.tmp, "missing.json")
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(output), INPUT_BODY)


class SyncPlanCliHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "cli.json"))
        )
        cls.key = Ed25519PrivateKey.generate()
        cls.sender = pub_hex(cls.key)
        bob = "b" * 64
        for amount in (10, 20, 30):
            message = crypto.canonical_message(cls.sender, bob, amount)
            cls.service.submit_transaction(
                {
                    "from": cls.sender,
                    "to": bob,
                    "amount": amount,
                    "signature": cls.key.sign(message).hex(),
                }
            )
            cls.service.mine_block()
            cls.service.confirm_block(str(cls.service.store.tip().height))
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

    def run_cli(self, *argv: str, stdin: str | None = None) -> tuple[int, str]:
        capture = io.StringIO()
        if stdin is None:
            with contextlib.redirect_stdout(capture):
                rc = cli_main(["--base-url", self.base_url, *argv])
        else:
            with contextlib.redirect_stdout(capture), \
                    unittest.mock.patch("sys.stdin", io.StringIO(stdin)):
                rc = cli_main(["--base-url", self.base_url, *argv])
        return rc, capture.getvalue()

    def document(self, **overrides) -> dict:
        tip = self.service._fork_summary(self.service.store.chain)
        body = {
            "locators": [
                {"height": tip["height"], "block_hash": tip["tip_hash"]}
            ],
            "tip": tip,
            "finalized": {
                "height": tip["height"],
                "block_hash": tip["tip_hash"],
            },
        }
        body.update(overrides)
        return body

    def test_success_from_file_one_line_exit_zero(self) -> None:
        path = os.path.join(self.tmp, "request.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.document(), fh)
        rc, output = self.run_cli("sync-plan", path)
        self.assertEqual(rc, 0, output)
        self.assertEqual(output.count("\n"), 1)
        body = json.loads(output)
        self.assertEqual(list(body.keys()), SUCCESS_KEYS)
        self.assertEqual(body["relation"], "same")
        self.assertTrue(body["ok"])

    def test_success_from_stdin(self) -> None:
        rc, output = self.run_cli(
            "sync-plan", "-", stdin=json.dumps(self.document())
        )
        self.assertEqual(rc, 0, output)
        self.assertEqual(json.loads(output)["relation"], "same")

    def test_remote_ahead_body_round_trips(self) -> None:
        document = self.document(
            locators=[
                {"height": 6, "block_hash": "a" * 64},
                {
                    "height": 3,
                    "block_hash": self.service.store.chain[3].block_hash,
                },
            ],
            tip={
                "tip_hash": "a" * 64,
                "height": 6,
                "length": 7,
                "status": "confirmed",
            },
            finalized={
                "height": 3,
                "block_hash": self.service.store.chain[3].block_hash,
            },
        )
        path = os.path.join(self.tmp, "ahead.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        rc, output = self.run_cli("sync-plan", path)
        self.assertEqual(rc, 0, output)
        body = json.loads(output)
        self.assertEqual(body["relation"], "remote_ahead")
        self.assertEqual(body["pull"], {"from_height": 4, "to_height": 6})

    def test_400_exits_one_ordered(self) -> None:
        document = self.document(finalized={"height": 9, "block_hash": "1" * 64})
        path = os.path.join(self.tmp, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        rc, output = self.run_cli("sync-plan", path)
        self.assertEqual(rc, 1)
        self.assertEqual(output.count("\n"), 1)
        self.assertEqual(json.loads(output), INPUT_BODY)

    def test_409_exits_one_ordered(self) -> None:
        document = self.document(
            locators=[{"height": 9, "block_hash": "a" * 64}],
            tip={
                "tip_hash": "a" * 64,
                "height": 9,
                "length": 10,
                "status": "confirmed",
            },
            finalized={"height": 0, "block_hash": "1" * 64},
        )
        rc, output = self.run_cli(
            "sync-plan", "-", stdin=json.dumps(document)
        )
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(output), {"ok": False, "error": "no_common_ancestor"}
        )


if __name__ == "__main__":
    unittest.main()
