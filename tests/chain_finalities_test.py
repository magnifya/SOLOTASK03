"""Tests for the paginated finality history ``GET /v1/chain/finalities``.

Builds a confirmed chain with a pending tip through the real service and
covers: the strict query-parameter rules (unknown/repeated/malformed 400,
unknown height 404, hash mismatch or pending anchor 409, all without side
effects); the 200 document's contract key order ``anchor, finalities, next,
head`` with per-item ``finalized, tip, auth`` credentials signed under
``ledger-finality-v1`` (``finalized`` names the block, ``tip`` is that
block's chain descriptor S); the ``next`` pagination semantics (the last
item's ``finalized`` until the head is reached, then null; an empty page
with null ``next`` when the anchor already is the head); and the
light-client round trip — every page feeds ``apply_finalities`` verbatim
and advances the checkpoint boundary to the finalized head. The existing
``GET /v1/chain/finality`` surface is covered by
tests/light_client_apply_finality_test.py and stays unchanged.

Run: python3 tests/chain_finalities_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    FINALITY_DOMAIN,
    advance_headers,
    apply_finalities,
)
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class FinalitiesFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "ledger.json"))
        self.service = LedgerService(self.store)
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        # A confirmed chain 0..3 plus a pending tip at height 4.
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
        self.trust = self.service.get_trust_document()[1]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def h(self, height: int) -> str:
        return self.store.chain[height].block_hash

    def loc(self, height: int) -> dict:
        return {"height": height, "block_hash": self.h(height)}

    def get(self, height=0, block_hash=None, limit=None):
        params = {
            "after_height": str(height),
            "after_hash": self.h(0) if block_hash is None else block_hash,
        }
        if limit is not None:
            params["limit"] = str(limit)
        return self.service.get_chain_finalities(params)

    def page(self, height=0, block_hash=None, limit=None) -> dict:
        status, body = self.get(height, block_hash, limit)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit: int) -> list:
        """Every finalities page from the genesis anchor in ``limit`` steps."""
        bodies = []
        anchor = self.loc(0)
        while True:
            body = self.page(anchor["height"], anchor["block_hash"], limit)
            bodies.append(body)
            if body["next"] is None:
                return bodies
            anchor = body["next"]


class FinalitiesShapeTests(FinalitiesFixture):
    def test_success_key_order_and_items(self) -> None:
        body = self.page(0, limit=2)
        self.assertEqual(
            list(body.keys()), ["anchor", "finalities", "next", "head"]
        )
        self.assertEqual(list(body["anchor"].keys()), ["height", "block_hash"])
        self.assertEqual(body["anchor"], self.loc(0))
        self.assertEqual(len(body["finalities"]), 2)
        for height, item in enumerate(body["finalities"], start=1):
            self.assertEqual(list(item.keys()), ["finalized", "tip", "auth"])
            self.assertEqual(
                list(item["finalized"].keys()), ["height", "block_hash"]
            )
            self.assertEqual(item["finalized"], self.loc(height))
            # tip is the chain descriptor S of the finalized block itself.
            self.assertEqual(
                item["tip"],
                {
                    "tip_hash": self.h(height),
                    "height": height,
                    "length": height + 1,
                    "status": "confirmed",
                },
            )
            self.assertEqual(
                list(item["auth"].keys()), ["key_version", "signature"]
            )
        self.assertEqual(body["next"], self.loc(2))
        # head is the current credential: the last confirmed block is
        # finalized while the pending tip stays in tip.
        self.assertEqual(list(body["head"].keys()), ["finalized", "tip", "auth"])
        self.assertEqual(body["head"]["finalized"], self.loc(3))
        self.assertEqual(
            body["head"]["tip"],
            {
                "tip_hash": self.tip_hash,
                "height": 4,
                "length": 5,
                "status": "pending",
            },
        )

    def test_signatures_verify_under_finality_domain(self) -> None:
        body = self.page(0, limit=3)
        signers = {
            entry["version"]: entry["public_key"]
            for entry in self.trust["audit_signers"]
        }
        for item in [*body["finalities"], body["head"]]:
            unsigned = {"finalized": item["finalized"], "tip": item["tip"]}
            digest = hashlib.sha256(
                FINALITY_DOMAIN.encode("utf-8")
                + json.dumps(
                    unsigned,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).digest()
            self.assertTrue(
                crypto.verify_signature(
                    signers[item["auth"]["key_version"]],
                    digest,
                    item["auth"]["signature"],
                )
            )

    def test_default_limit_and_page_bounds(self) -> None:
        # Default limit 100 covers the whole confirmed tail in one page.
        body = self.page(0)
        self.assertEqual(len(body["finalities"]), 3)
        self.assertIsNone(body["next"])
        # The limit bounds are accepted.
        self.assertEqual(self.get(0, limit=1)[0], 200)
        self.assertEqual(self.get(0, limit=500)[0], 200)
        # A small limit stops at the confirmed run, never at the pending tip.
        for limit in (1, 2, 3):
            pages = self.paged(limit)
            delivered = [
                item["finalized"] for body in pages for item in body["finalities"]
            ]
            self.assertEqual(delivered, [self.loc(h) for h in (1, 2, 3)])
            self.assertIsNone(pages[-1]["next"])

    def test_anchor_at_head_and_pending_tip(self) -> None:
        # The anchor is the finalized head: an empty page and a null next.
        body = self.page(3, self.h(3))
        self.assertEqual(body["finalities"], [])
        self.assertIsNone(body["next"])
        self.assertEqual(body["head"]["finalized"], self.loc(3))
        # Confirming the tip makes it the new head with the same rules.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        body = self.page(3, self.h(3))
        self.assertEqual([i["finalized"] for i in body["finalities"]], [self.loc(4)])
        self.assertIsNone(body["next"])
        self.assertEqual(body["head"]["finalized"], self.loc(4))
        self.assertEqual(body["head"]["tip"]["status"], "confirmed")


class FinalitiesErrorTests(FinalitiesFixture):
    def assert_400s(self, *param_dicts: dict) -> None:
        for params in param_dicts:
            status, _body = self.service.get_chain_finalities(params)
            self.assertEqual(status, 400, params)

    def test_parameter_errors(self) -> None:
        good = {"after_height": "0", "after_hash": self.genesis_hash}
        self.assert_400s(
            {},  # both required
            {"after_hash": self.genesis_hash},
            {"after_height": "0"},
            {**good, "after_height": ""},
            {**good, "after_height": "00"},  # leading zero
            {**good, "after_height": "-1"},
            {**good, "after_height": "1.0"},
            {**good, "after_height": " 1"},
            {**good, "after_hash": ""},
            {**good, "after_hash": "zz"},
            {**good, "after_hash": "A" * 64},  # uppercase hex
            {**good, "after_hash": "0" * 63},
            {**good, "limit": ""},
            {**good, "limit": "0"},
            {**good, "limit": "501"},
            {**good, "limit": "01"},
            {**good, "limit": "1.5"},
            {**good, "bogus": "1"},  # unknown parameter
            {"after_height": "0", "after_hash": self.genesis_hash, "x": ""},
        )

    def test_anchor_errors(self) -> None:
        # Unknown height is 404.
        status, _ = self.get(99, self.genesis_hash)
        self.assertEqual(status, 404)
        # A well-formed hash that does not match the height is 409.
        status, _ = self.get(1, self.genesis_hash)
        self.assertEqual(status, 409)
        # A pending anchor is 409.
        status, _ = self.get(4, self.tip_hash)
        self.assertEqual(status, 409)

    def test_errors_have_no_side_effects(self) -> None:
        before = self.service.get_chain()[1]
        self.get(99, self.genesis_hash)
        self.get(1, self.genesis_hash)
        self.get(4, self.tip_hash)
        self.service.get_chain_finalities({"bogus": "1"})
        self.assertEqual(self.service.get_chain()[1], before)


class FinalitiesLightClientTests(FinalitiesFixture):
    def test_pages_feed_apply_finalities(self) -> None:
        # Checkpoint the chain to the pending tip via the header pages.
        def header_page(height, block_hash, limit=None):
            params = {"after_height": str(height), "after_hash": block_hash}
            if limit is not None:
                params["limit"] = str(limit)
            status, body = self.service.get_chain_headers(params)
            self.assertEqual(status, 200, body)
            return body

        anchor = self.loc(0)
        documents = []
        while True:
            page = header_page(anchor["height"], anchor["block_hash"], 2)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == self.tip_hash:
                break
        checkpoint = os.path.join(self.tmp, "checkpoint.json")
        result = advance_headers(
            checkpoint,
            documents,
            self.loc(0),
            self.tip_hash,
            self.trust,
        )
        self.assertTrue(result["ok"], result)

        # Every finalities page applies verbatim, in order, to the head.
        anchor = self.loc(0)
        applied = 0
        while True:
            body = self.page(anchor["height"], anchor["block_hash"], 2)
            if not body["finalities"]:
                self.assertIsNone(body["next"])
                break
            result = apply_finalities(checkpoint, body["finalities"], self.trust)
            self.assertTrue(result["ok"], result)
            self.assertEqual(
                result["finalized"], body["finalities"][-1]["finalized"]
            )
            applied += result["applied"]
            if body["next"] is None:
                break
            anchor = body["next"]
        self.assertEqual(applied, 3)
        with open(checkpoint, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        self.assertEqual(stored["finalized"], self.loc(3))


class FinalitiesHttpTests(FinalitiesFixture):
    def setUp(self) -> None:
        super().setUp()
        self.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(self.service)
        )
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def request(self, path: str):
        req = urllib.request.Request(f"{self.base}{path}", method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_http_contract(self) -> None:
        status, raw = self.request(
            f"/v1/chain/finalities?after_height=0&after_hash={self.genesis_hash}"
            "&limit=2"
        )
        self.assertEqual(status, 200, raw)
        # The raw document keeps the contract key order.
        self.assertLess(raw.index('"anchor"'), raw.index('"finalities"'))
        self.assertLess(raw.index('"finalities"'), raw.index('"next"'))
        self.assertLess(raw.index('"next"'), raw.index('"head"'))
        body = json.loads(raw)
        self.assertEqual(
            list(body.keys()), ["anchor", "finalities", "next", "head"]
        )
        self.assertEqual(body["next"], self.loc(2))

    def test_http_repeated_and_unknown_parameters(self) -> None:
        anchor = f"after_height=0&after_hash={self.genesis_hash}"
        for path in (
            f"/v1/chain/finalities?after_height=0&after_height=1&after_hash={self.genesis_hash}",
            f"/v1/chain/finalities?{anchor}&limit=1&limit=2",
            f"/v1/chain/finalities?{anchor}&bogus=1",
            f"/v1/chain/finalities?{anchor}&blank=",
        ):
            status, _ = self.request(path)
            self.assertEqual(status, 400, path)
        # A bare trailing "?" carries no parameters: both are still required.
        status, _ = self.request("/v1/chain/finalities?")
        self.assertEqual(status, 400)
        # The sibling endpoint is untouched.
        status, _ = self.request("/v1/chain/finality")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
