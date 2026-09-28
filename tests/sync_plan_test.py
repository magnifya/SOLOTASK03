"""Tests for the read-only sync precheck.

Covers POST /v1/chain/sync-plan end to end:

* service validation — the body is the closed ordered object
  ``locators``, ``tip``, ``finalized``; ``locators`` follows the
  headers/locate contract (1-64 ``{height, block_hash}`` items, strictly
  descending non-boolean heights, 64-lowercase-hex hashes) and its first
  item must name ``tip``; ``tip`` follows the chain descriptor S
  (``tip_hash, height, length, status`` with ``length == height + 1``);
  ``finalized`` follows the anchor shape, never sits above ``tip`` and at
  the same height requires the same hash and a confirmed tip. Every
  defect is a 400 with the ordered ``{ok, error}`` input body and no
  state read;
* the lock-held canonical probe — locators are matched in order, the
  first main-chain hit is the common ancestor and no hit (outside an
  identical tip) is 409 ``no_common_ancestor``;
* the plan — fixed 200 key order ``ok, ancestor, relation, pull, error``
  with relations ``same``/``remote_ahead``/``local_ahead``/``fork``, the
  closed ``{from_height, to_height}`` pull interval, and the
  ``remote_behind``/``not_preferred``/``finality_conflict`` rejection
  reasons (finality conflicts take priority and never pull);
* the HTTP wire boundary (parse failures are the ordered 400 body,
  contract key order is preserved) and the ``sync-plan`` CLI (FILE|-
  input, single line, exit 1 on any non-2xx).

Run: python3 tests/sync_plan_test.py
"""
from __future__ import annotations

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
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


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
        # A confirmed chain 0..3 plus a pending tip at height 4, so the
        # local finalized boundary is height 3.
        for amount in (10, 20, 30):
            self.assertEqual(
                self.service.submit_transaction(self._tx(amount))[0], 202
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0],
                200,
            )
        self.assertEqual(self.service.submit_transaction(self._tx(5))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.genesis_hash = self.store.chain[0].block_hash
        self.tip_hash = self.store.tip_hash()
        self.assertEqual(self.store.chain[3].status, "confirmed")
        self.assertEqual(self.store.chain[4].status, "pending")

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def hash_at(self, height: int) -> str:
        return self.store.chain[height].block_hash

    def loc(self, height: int, block_hash: str | None = None) -> dict:
        if block_hash is None:
            block_hash = self.hash_at(height)
        return {"height": height, "block_hash": block_hash}

    def tip(self, height: int, block_hash: str, status: str) -> dict:
        return {
            "tip_hash": block_hash,
            "height": height,
            "length": height + 1,
            "status": status,
        }

    def plan(
        self,
        locators: list,
        tip: dict,
        finalized: dict,
    ) -> dict:
        return {"locators": locators, "tip": tip, "finalized": finalized}

    def remote_plan(
        self,
        remote_height: int,
        remote_hash: str,
        status: str,
        finalized_height: int,
        finalized_hash: str,
        extra_locators: list | None = None,
    ) -> dict:
        locators = [self.loc(remote_height, remote_hash)]
        if extra_locators:
            locators.extend(extra_locators)
        return self.plan(
            locators,
            self.tip(remote_height, remote_hash, status),
            {"height": finalized_height, "block_hash": finalized_hash},
        )

    def build(self, payload):
        return self.service.build_sync_plan(payload)

    def assertBodyOrder(self, body: dict) -> None:
        self.assertEqual(
            list(body.keys()), ["ok", "ancestor", "relation", "pull", "error"]
        )
        self.assertEqual(list(body["ancestor"].keys()), ["height", "block_hash"])
        if body["pull"] is not None:
            self.assertEqual(
                list(body["pull"].keys()), ["from_height", "to_height"]
            )


class SyncPlanServiceTests(SyncPlanFixture):
    # -- 200 relations --------------------------------------------------------

    def test_same_tip(self) -> None:
        payload = self.remote_plan(4, self.tip_hash, "pending", 3, self.hash_at(3))
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertBodyOrder(body)
        self.assertTrue(body["ok"])
        self.assertEqual(body["ancestor"], self.loc(4))
        self.assertEqual(body["relation"], "same")
        self.assertIsNone(body["pull"])
        self.assertIsNone(body["error"])

    def test_same_tip_with_contradictory_finalized_is_conflict(self) -> None:
        # The tips agree but the remote claims a finalized hash that
        # contradicts the shared canonical prefix: the conflict still takes
        # priority over the same report.
        payload = self.remote_plan(4, self.tip_hash, "pending", 2, "9" * 64)
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "same")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "finality_conflict")

    def test_same_confirmed_tip_agrees_when_finalized_matches(self) -> None:
        payload = self.remote_plan(4, self.tip_hash, "confirmed", 4, self.tip_hash)
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "same")
        self.assertIsNone(body["error"])

    def test_remote_ahead_pulls_after_local_tip(self) -> None:
        # The local tip is pending at height 4; a longer remote sharing it
        # pulls the closed interval 5..6.
        payload = self.remote_plan(
            6,
            "f" * 64,
            "confirmed",
            4,
            self.tip_hash,
            extra_locators=[self.loc(4)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "remote_ahead")
        self.assertEqual(body["ancestor"], self.loc(4))
        self.assertEqual(body["pull"], {"from_height": 5, "to_height": 6})
        self.assertIsNone(body["error"])

    def test_local_ahead_reports_remote_behind(self) -> None:
        # The remote tip is the local finalized block at height 3: the
        # ancestor is the remote tip and the remote is shorter.
        payload = self.remote_plan(
            3, self.hash_at(3), "confirmed", 3, self.hash_at(3)
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "local_ahead")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "remote_behind")

    def test_fork_remote_wins_tie_break_and_pulls(self) -> None:
        # Equal length, fork at height 4; the smaller lexicographic tip hash
        # wins and pulls the single height 4.
        payload = self.remote_plan(
            4,
            "0" * 64,
            "pending",
            3,
            self.hash_at(3),
            extra_locators=[self.loc(3)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertEqual(body["ancestor"], self.loc(3))
        self.assertEqual(body["pull"], {"from_height": 4, "to_height": 4})
        self.assertIsNone(body["error"])

    def test_fork_remote_loses_tie_break(self) -> None:
        payload = self.remote_plan(
            4,
            "f" * 64,
            "pending",
            3,
            self.hash_at(3),
            extra_locators=[self.loc(3)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "not_preferred")

    def test_longer_remote_always_pulls_regardless_of_hash(self) -> None:
        # A tip hash lexicographically larger than the local one still pulls
        # when the chain is strictly longer.
        payload = self.remote_plan(
            5,
            "f" * 64,
            "confirmed",
            3,
            self.hash_at(3),
            extra_locators=[self.loc(3)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertEqual(body["pull"], {"from_height": 4, "to_height": 5})
        self.assertIsNone(body["error"])

    def test_first_in_order_locator_is_the_ancestor(self) -> None:
        # A forked head and a forked intermediate locator are skipped; the
        # next canonical hit (the finalized boundary) anchors.
        payload = self.remote_plan(
            6,
            "0" * 64,
            "confirmed",
            3,
            self.hash_at(3),
            extra_locators=[self.loc(4, "e" * 64), self.loc(3)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["ancestor"], self.loc(3))
        self.assertEqual(body["relation"], "fork")
        self.assertEqual(body["pull"], {"from_height": 4, "to_height": 6})

    def test_remote_finalized_above_ancestor_is_not_comparable(self) -> None:
        # The remote finalized point sits above the split and is absent
        # locally; it cannot contradict the shared prefix, so the pull stands.
        payload = self.remote_plan(
            6,
            "0" * 64,
            "confirmed",
            5,
            "e" * 64,
            extra_locators=[self.loc(3)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["error"])
        self.assertEqual(body["pull"], {"from_height": 4, "to_height": 6})

    # -- finality conflicts ---------------------------------------------------

    def test_ancestor_below_local_finalized_is_conflict_even_when_behind(self) -> None:
        # A shorter remote (tip h2) whose tip is below the local finalized
        # boundary: local_ahead topology but the finality conflict takes
        # priority over remote_behind.
        payload = self.remote_plan(
            2, self.hash_at(2), "confirmed", 2, self.hash_at(2)
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "local_ahead")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "finality_conflict")

    def test_ancestor_below_local_finalized_blocks_a_pull(self) -> None:
        # A longer remote that forks before the local finalized block would
        # otherwise pull; the conflict vetoes the pull.
        payload = self.remote_plan(
            6,
            "0" * 64,
            "confirmed",
            2,
            self.hash_at(2),
            extra_locators=[self.loc(2)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "fork")
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "finality_conflict")

    def test_remote_finalized_contradicts_common_prefix_blocks_pull(self) -> None:
        # Split at height 3 but the remote claims a different finalized hash
        # for a canonical height on the shared prefix.
        payload = self.remote_plan(
            6,
            "0" * 64,
            "confirmed",
            3,
            "9" * 64,
            extra_locators=[self.loc(3)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["pull"])
        self.assertEqual(body["error"], "finality_conflict")

    def test_ancestor_equal_to_local_finalized_is_not_a_conflict(self) -> None:
        # Split exactly at the finalized boundary is allowed; the equal-length
        # fork simply loses the tie-break.
        payload = self.remote_plan(
            4,
            "f" * 64,
            "pending",
            3,
            self.hash_at(3),
            extra_locators=[self.loc(3)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["error"], "not_preferred")

    # -- 409 ------------------------------------------------------------------

    def test_no_common_ancestor_is_409(self) -> None:
        payload = self.remote_plan(
            4,
            "a" * 64,
            "pending",
            1,
            "a" * 64,
            extra_locators=[self.loc(2, "c" * 64), self.loc(1, "d" * 64)],
        )
        status, body = self.build(payload)
        self.assertEqual(status, 409)
        self.assertEqual(body, {"ok": False, "error": "no_common_ancestor"})

    # -- 400 validation -------------------------------------------------------

    def assert400(self, payload) -> None:
        status, body = self.build(payload)
        self.assertEqual(status, 400, body)
        self.assertEqual(body, {"ok": False, "error": "input"})

    def test_body_must_be_closed_ordered_object(self) -> None:
        self.assert400([])
        self.assert400("nope")
        self.assert400(None)
        self.assert400({})
        self.assert400(
            self.remote_plan(4, self.tip_hash, "pending", 3, self.hash_at(3))
            | {"extra": 1}
        )
        self.assert400({"locators": [], "tip": 1})  # missing finalized
        good = self.remote_plan(4, self.tip_hash, "pending", 3, self.hash_at(3))
        self.assert400(
            {
                "finalized": good["finalized"],
                "tip": good["tip"],
                "locators": good["locators"],
            }
        )

    def test_locators_contract(self) -> None:
        tip = self.tip(4, self.tip_hash, "pending")
        fin = {"height": 3, "block_hash": self.hash_at(3)}
        self.assert400(self.plan([], tip, fin))
        self.assert400(self.plan({}, tip, fin))
        self.assert400(self.plan(["x"], tip, fin))
        self.assert400(self.plan([[4, self.tip_hash]], tip, fin))
        self.assert400(
            self.plan(
                [{"block_hash": self.tip_hash, "height": 4}], tip, fin
            )
        )
        self.assert400(self.plan([{"height": 4}], tip, fin))
        self.assert400(
            self.plan(
                [{"height": 4, "block_hash": self.tip_hash, "x": 1}], tip, fin
            )
        )
        self.assert400(self.plan([{"height": "4", "block_hash": self.tip_hash}], tip, fin))
        self.assert400(self.plan([{"height": True, "block_hash": self.tip_hash}], tip, fin))
        self.assert400(self.plan([{"height": -1, "block_hash": self.tip_hash}], tip, fin))
        self.assert400(self.plan([{"height": 4.0, "block_hash": self.tip_hash}], tip, fin))
        self.assert400(self.plan([{"height": 4, "block_hash": "Z" * 64}], tip, fin))
        self.assert400(self.plan([{"height": 4, "block_hash": "a" * 63}], tip, fin))
        # Not strictly descending.
        self.assert400(
            self.plan(
                [self.loc(4, self.tip_hash), self.loc(4, self.tip_hash)], tip, fin
            )
        )
        self.assert400(
            self.plan(
                [self.loc(3), self.loc(4, self.tip_hash)], tip, fin
            )
        )
        # 65 items (heights stay descending); 64 is structurally accepted.
        too_many = [
            {"height": 100 - i, "block_hash": "1" * 64} for i in range(65)
        ]
        self.assert400(self.plan(too_many, tip, fin))

    def test_tip_contract(self) -> None:
        locators = [self.loc(4, self.tip_hash)]
        fin = {"height": 3, "block_hash": self.hash_at(3)}
        self.assert400(self.plan(locators, [], fin))
        self.assert400(
            self.plan(
                locators,
                {
                    "height": 4,
                    "tip_hash": self.tip_hash,
                    "length": 5,
                    "status": "pending",
                },
                fin,
            )
        )
        self.assert400(
            self.plan(
                locators,
                {
                    "tip_hash": self.tip_hash,
                    "height": 4,
                    "length": 5,
                },
                fin,
            )
        )
        self.assert400(
            self.plan(locators, self.tip(4, "Z" * 64, "pending"), fin)
        )
        self.assert400(
            self.plan(locators, self.tip(-1, "0" * 64, "pending"), fin)
        )
        self.assert400(
            self.plan(locators, self.tip(4, self.tip_hash, "bogus"), fin)
        )
        # length must equal height + 1.
        bad_length = dict(self.tip(4, self.tip_hash, "pending"))
        bad_length["length"] = 4
        self.assert400(self.plan(locators, bad_length, fin))
        bad_length = dict(self.tip(0, self.genesis_hash, "confirmed"))
        bad_length["length"] = 0
        self.assert400(self.plan([self.loc(0)], bad_length, fin))

    def test_first_locator_must_name_tip(self) -> None:
        fin = {"height": 3, "block_hash": self.hash_at(3)}
        # Same height, different hash.
        self.assert400(
            self.plan(
                [self.loc(4, "a" * 64)],
                self.tip(4, self.tip_hash, "pending"),
                fin,
            )
        )
        # Same hash, different height.
        self.assert400(
            self.plan(
                [self.loc(3)],
                self.tip(4, self.tip_hash, "pending"),
                fin,
            )
        )

    def test_finalized_contract(self) -> None:
        locators = [self.loc(4, self.tip_hash)]
        tip = self.tip(4, self.tip_hash, "pending")
        self.assert400(self.plan(locators, tip, []))
        self.assert400(
            self.plan(locators, tip, {"block_hash": self.hash_at(3), "height": 3})
        )
        self.assert400(
            self.plan(locators, tip, {"height": True, "block_hash": "a" * 64})
        )
        self.assert400(
            self.plan(locators, tip, {"height": -1, "block_hash": "a" * 64})
        )
        self.assert400(
            self.plan(locators, tip, {"height": 3, "block_hash": "Z" * 64})
        )
        # Above the tip.
        self.assert400(
            self.plan(locators, tip, {"height": 5, "block_hash": "a" * 64})
        )
        # Same height as the tip: different hash.
        self.assert400(
            self.plan(
                locators, tip, {"height": 4, "block_hash": "a" * 64}
            )
        )
        # Same height/hash as the tip but the tip is still pending.
        self.assert400(
            self.plan(
                locators, tip, {"height": 4, "block_hash": self.tip_hash}
            )
        )
        # Same height/hash with a confirmed tip is valid and reports same.
        confirmed_tip = self.tip(4, self.tip_hash, "confirmed")
        status, body = self.build(
            self.plan(
                locators,
                confirmed_tip,
                {"height": 4, "block_hash": self.tip_hash},
            )
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["relation"], "same")


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

    def _same_payload(self) -> dict:
        tip_hash = self.service.store.tip_hash()
        return {
            "locators": [{"height": 2, "block_hash": tip_hash}],
            "tip": {
                "tip_hash": tip_hash,
                "height": 2,
                "length": 3,
                "status": "confirmed",
            },
            "finalized": {"height": 2, "block_hash": tip_hash},
        }

    def test_http_success_key_order(self) -> None:
        status, raw = self.post(json.dumps(self._same_payload()))
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

    def test_http_errors(self) -> None:
        # Malformed/empty JSON is the ordered 400 input body.
        for raw in ("{not json}", ""):
            status, text = self.post(raw)
            self.assertEqual(status, 400, raw)
            self.assertEqual(json.loads(text), {"ok": False, "error": "input"})
        # Structural defects never touch state.
        status, text = self.post(json.dumps({}))
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(text), {"ok": False, "error": "input"})
        # No shared ancestor is 409.
        payload = self._same_payload()
        payload["locators"] = [{"height": 2, "block_hash": "a" * 64}]
        payload["tip"]["tip_hash"] = "a" * 64
        payload["finalized"] = {"height": 2, "block_hash": "a" * 64}
        status, text = self.post(json.dumps(payload))
        self.assertEqual(status, 409, text)
        self.assertEqual(
            json.loads(text), {"ok": False, "error": "no_common_ancestor"}
        )


class SyncPlanCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.service = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json"))
        )
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        bob = "b" * 64
        for amount in (10,):
            message = crypto.canonical_message(self.sender, bob, amount)
            self.service.submit_transaction(
                {
                    "from": self.sender,
                    "to": bob,
                    "amount": amount,
                    "signature": self.key.sign(message).hex(),
                }
            )
            self.service.mine_block()
            self.service.confirm_block(str(self.service.store.tip().height))
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def _cli(self, *argv) -> tuple[int, str]:
        out = StringIO()
        with redirect_stdout(out):
            rc = cli_main(["--base-url", self.base, *argv])
        return rc, out.getvalue().strip()

    def _payload(self, **overrides) -> dict:
        tip_hash = self.service.store.tip_hash()
        payload = {
            "locators": [{"height": 1, "block_hash": tip_hash}],
            "tip": {
                "tip_hash": tip_hash,
                "height": 1,
                "length": 2,
                "status": "confirmed",
            },
            "finalized": {"height": 1, "block_hash": tip_hash},
        }
        payload.update(overrides)
        return payload

    def test_cli_file_success_single_line(self) -> None:
        path = os.path.join(self.tmp, "plan.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._payload(), fh)
        rc, line = self._cli("sync-plan", path)
        self.assertEqual(rc, 0, line)
        self.assertEqual(len(line.splitlines()), 1)
        document = json.loads(line)
        self.assertEqual(document["ok"], True)
        self.assertEqual(document["relation"], "same")
        # The response keeps the contract key order.
        self.assertEqual(
            list(document.keys()),
            ["ok", "ancestor", "relation", "pull", "error"],
        )

    def test_cli_stdin_success(self) -> None:
        out = StringIO()
        saved_stdin = sys.stdin
        try:
            sys.stdin = StringIO(json.dumps(self._payload()))
            with redirect_stdout(out):
                rc = cli_main(["--base-url", self.base, "sync-plan", "-"])
        finally:
            sys.stdin = saved_stdin
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["relation"], "same")

    def test_cli_missing_file_is_input_error(self) -> None:
        rc, line = self._cli("sync-plan", os.path.join(self.tmp, "missing.json"))
        self.assertEqual(rc, 1)
        self.assertEqual(line, json.dumps({"ok": False, "error": "input"}))

    def test_cli_invalid_json_is_input_error(self) -> None:
        path = os.path.join(self.tmp, "bad.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        rc, line = self._cli("sync-plan", path)
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(line), {"ok": False, "error": "input"})

    def test_cli_non_2xx_exits_1(self) -> None:
        # A well-formed document with no common ancestor is 409.
        payload = self._payload()
        payload["locators"] = [{"height": 1, "block_hash": "a" * 64}]
        payload["tip"]["tip_hash"] = "a" * 64
        payload["finalized"] = {"height": 1, "block_hash": "a" * 64}
        path = os.path.join(self.tmp, "fork.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        rc, line = self._cli("sync-plan", path)
        self.assertEqual(rc, 1)
        self.assertEqual(
            json.loads(line), {"ok": False, "error": "no_common_ancestor"}
        )


if __name__ == "__main__":
    unittest.main()
