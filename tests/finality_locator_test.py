"""Tests for finality-history fork location.

Covers POST /v1/chain/finalities/locate end to end:

* service validation — the body has ordered keys ``locators`` (and the
  optional ``limit``), the locators array is 1-64 items with ordered
  ``height, block_hash`` keys, heights are non-boolean non-negative integers
  in strictly descending unique order, hashes are 64 lowercase hex and
  ``limit`` is a non-boolean integer 1-500 (default 100); every defect is a
  400 with no state read;
* the first in-order locator naming a **confirmed** main-chain block
  anchors the response (a pending block never matches), a locator list
  with no confirmed main-chain hit is 409, and the success body fully
  reuses the ``GET /v1/chain/finalities`` contract — fixed key order
  ``anchor, finalities, next, head`` — with only ``anchor`` naming the
  matched item;
* the offline verifier
  ``ledger.light_client.verify_finality_locator_pages`` — success key
  order ``ok, anchor, head, matched_index, pages, verified_block_hashes``
  with the index starting at 0, and input/auth/integrity categorization
  (a malformed locator list is ``input``, a first anchor absent from the
  list is ``integrity``);
* the HTTP wire boundary (parse failures are 400, contract key order is
  preserved).

Run: python3 tests/finality_locator_test.py
"""
from __future__ import annotations

import copy
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
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    verify_finality_locator_pages,
    verify_finality_pages,
)
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class FinalityLocatorFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "locate.json"))
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

    def loc(self, height: int, block_hash: str | None = None) -> dict:
        if block_hash is None:
            block_hash = self.h(height)
        return {"height": height, "block_hash": block_hash}

    def locate(self, payload):
        return self.service.locate_finality_fork(payload)


class FinalityLocatorServiceTests(FinalityLocatorFixture):
    def test_locates_first_matching_locator_in_order(self) -> None:
        # A locator set whose first item forks (same height, wrong hash)
        # and whose second item is a confirmed main-chain block.
        payload = {
            "locators": [
                {"height": 3, "block_hash": "f" * 64},
                self.loc(2),
                self.loc(1),
            ]
        }
        status, body = self.locate(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(
            list(body.keys()), ["anchor", "finalities", "next", "head"]
        )
        self.assertEqual(body["anchor"], self.loc(2))
        # Credentials run ascending strictly after the height-2 anchor and
        # stop at the confirmed boundary (the pending tip is excluded).
        self.assertEqual(
            [item["finalized"]["height"] for item in body["finalities"]], [3]
        )
        self.assertIsNone(body["next"])
        self.assertEqual(body["head"]["tip"]["tip_hash"], self.tip_hash)
        # And the page verifies offline under the ordinary pages contract.
        self.assertTrue(
            verify_finality_pages(
                [body], body["anchor"], self.tip_hash, self.trust
            )["ok"]
        )

    def test_first_in_order_match_wins_not_a_deeper_one(self) -> None:
        payload = {"locators": [self.loc(3), self.loc(1)]}
        status, body = self.locate(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(3))
        self.assertEqual(body["finalities"], [])

    def test_a_fork_above_the_first_match_does_not_short_circuit(self) -> None:
        payload = {"locators": [self.loc(3, "f" * 64), self.loc(2), self.loc(0)]}
        status, body = self.locate(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(2))

    def test_pending_tip_locator_never_matches(self) -> None:
        # The pending chain tip is not a confirmed block: a locator naming
        # it is skipped, and alone it is a 409.
        status, body = self.locate({"locators": [self.loc(4), self.loc(2)]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(2))
        status, _ = self.locate({"locators": [self.loc(4)]})
        self.assertEqual(status, 409)

    def test_genesis_locator_and_limit(self) -> None:
        status, body = self.locate({"locators": [self.loc(0)], "limit": 2})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(0))
        self.assertEqual(
            [item["finalized"]["height"] for item in body["finalities"]],
            [1, 2],
        )
        # The page does not reach the finalized head: next chains on.
        self.assertEqual(body["next"], self.loc(2))

    def test_limit_boundaries(self) -> None:
        base = {"locators": [self.loc(0)]}
        for good in (1, 500):
            status, body = self.locate({**base, "limit": good})
            self.assertEqual(status, 200, (good, body))
        for bad in (0, 501, -1, True, False, 1.0, "100", None):
            status, body = self.locate({**base, "limit": bad})
            self.assertEqual(status, 400, (bad, body))

    def test_default_limit_is_100(self) -> None:
        # Chain is shorter than 100 so the whole confirmed tail is returned.
        status, body = self.locate({"locators": [self.loc(0)]})
        self.assertEqual(status, 200, body)
        self.assertEqual(
            [item["finalized"]["height"] for item in body["finalities"]],
            [1, 2, 3],
        )
        self.assertIsNone(body["next"])

    def test_anchor_at_finalized_head_is_empty_page(self) -> None:
        status, body = self.locate({"locators": [self.loc(3)]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(3))
        self.assertEqual(body["finalities"], [])
        self.assertIsNone(body["next"])
        self.assertEqual(body["head"]["finalized"], self.loc(3))

    def test_no_confirmed_main_chain_match_is_409(self) -> None:
        cases = [
            # A locator at an existing height with a fork hash.
            {"locators": [self.loc(2, "a" * 64)]},
            # A locator at a height above the tip, with a lower fork after.
            {"locators": [{"height": 99, "block_hash": "2" * 64}, self.loc(0, "1" * 64)]},
        ]
        for payload in cases:
            status, body = self.locate(payload)
            self.assertEqual(status, 409, body)

    # -- 400 validation ------------------------------------------------------

    def assert400(self, payload) -> None:
        status, body = self.locate(payload)
        self.assertEqual(status, 400, body)

    def test_body_must_be_closed_ordered_object(self) -> None:
        self.assert400([])
        self.assert400("nope")
        self.assert400(None)
        self.assert400({})
        self.assert400({"limit": 10})  # missing locators
        self.assert400({"locators": [self.loc(0)], "extra": 1})
        # Wrong top-level key order.
        self.assert400({"limit": 10, "locators": [self.loc(0)]})

    def test_locators_array_shape(self) -> None:
        self.assert400({"locators": []})
        self.assert400({"locators": {}})
        self.assert400({"locators": "no"})
        self.assert400({"locators": [self.loc(0), "x"]})
        self.assert400({"locators": [[0, self.genesis_hash]]})
        # 65 items is too many; the heights stay strictly descending.
        too_many = [
            {"height": 100 - i, "block_hash": "1" * 64} for i in range(65)
        ]
        self.assert400({"locators": too_many})
        # Exactly 64 is accepted structurally (none matches, so 409).
        sixty_four = [
            {"height": 100 - i, "block_hash": "1" * 64} for i in range(64)
        ]
        self.assertEqual(self.locate({"locators": sixty_four})[0], 409)

    def test_locator_item_key_order_and_shape(self) -> None:
        good_height, good_hash = 3, self.h(3)
        self.assert400({"locators": [{"block_hash": good_hash, "height": good_height}]})
        self.assert400({"locators": [{"height": good_height}]})
        self.assert400(
            {"locators": [{"height": good_height, "block_hash": good_hash, "x": 1}]}
        )
        self.assert400({"locators": [{"height": "3", "block_hash": good_hash}]})
        self.assert400({"locators": [{"height": True, "block_hash": good_hash}]})
        self.assert400({"locators": [{"height": -1, "block_hash": good_hash}]})
        self.assert400({"locators": [{"height": 1.0, "block_hash": good_hash}]})
        self.assert400({"locators": [{"height": 3, "block_hash": "ABC" + "0" * 61}]})
        self.assert400({"locators": [{"height": 3, "block_hash": "a" * 63}]})
        self.assert400({"locators": [{"height": 3, "block_hash": None}]})

    def test_heights_strictly_descending_and_unique(self) -> None:
        self.assert400({"locators": [self.loc(3), self.loc(3)]})
        self.assert400({"locators": [self.loc(2), self.loc(3)]})
        # Equal-height duplicate even with a different hash.
        self.assert400(
            {"locators": [{"height": 3, "block_hash": self.h(3)}, {"height": 3, "block_hash": "9" * 64}]}
        )
        # Strictly descending valid order locates.
        status, _ = self.locate({"locators": [self.loc(3), self.loc(2), self.loc(0)]})
        self.assertEqual(status, 200)


class FinalityLocatorVerifyTests(FinalityLocatorFixture):
    _UNSET = object()

    def verify(self, pages, locators, tip_hash=_UNSET, trust=_UNSET):
        return verify_finality_locator_pages(
            pages,
            locators,
            self.tip_hash if tip_hash is self._UNSET else tip_hash,
            self.trust if trust is self._UNSET else trust,
        )

    def assert_failed(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})

    def finalities_page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_finalities(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, anchor: dict, limit: int) -> list:
        """Every finalities page from ``anchor`` in ``limit`` steps."""
        bodies = []
        while True:
            body = self.finalities_page(
                anchor["height"], anchor["block_hash"], limit
            )
            bodies.append(body)
            if body["next"] is None:
                return bodies
            anchor = body["next"]

    def test_verifies_genuine_history_and_reports_index(self) -> None:
        pages = self.paged(self.loc(1), 1)
        self.assertEqual(len(pages), 2)
        locators = [
            {"height": 3, "block_hash": "f" * 64},  # fork near the head
            self.loc(1),  # the actual anchor -> index 1
            self.loc(0),
        ]
        result = self.verify(pages, locators)
        self.assertEqual(
            list(result.keys()),
            ["ok", "anchor", "head", "matched_index", "pages", "verified_block_hashes"],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["anchor"], self.loc(1))
        self.assertEqual(result["matched_index"], 1)
        self.assertEqual(result["head"], pages[0]["head"])
        self.assertEqual(result["pages"], 2)
        self.assertEqual(
            result["verified_block_hashes"], [self.h(2), self.h(3)]
        )

    def test_index_zero_and_empty_page_at_head(self) -> None:
        empty = self.finalities_page(3, self.h(3))
        result = self.verify([empty], [self.loc(3)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["verified_block_hashes"], [])

    def test_located_response_verifies(self) -> None:
        # The genuine locate response verifies against its request list.
        locators = [self.loc(4, "f" * 64), self.loc(2), self.loc(0)]
        status, body = self.locate({"locators": locators})
        self.assertEqual(status, 200, body)
        result = self.verify([body], locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["matched_index"], 1)

    def test_input_errors(self) -> None:
        pages = self.paged(self.loc(0), 2)

        def check(locators, **kwargs):
            self.assert_failed(
                self.verify(pages, locators, **kwargs), ERR_INPUT
            )

        check("not-a-list")
        check([])
        check({})
        check([self.loc(0), "x"])
        check([{"block_hash": self.genesis_hash, "height": 0}])  # reordered
        check([{"height": 0}])
        check([{"height": True, "block_hash": self.genesis_hash}])
        check([{"height": -1, "block_hash": self.genesis_hash}])
        check([{"height": 0, "block_hash": "Z" * 64}])
        check([self.loc(1), self.loc(1)])  # duplicate
        check([self.loc(0), self.loc(1)])  # ascending
        # 65 items.
        check([{"height": 100 - i, "block_hash": "1" * 64} for i in range(65)])
        # A malformed page stays input even with good locators.
        bad_pages = copy.deepcopy(pages)
        del bad_pages[0]["head"]
        self.assert_failed(self.verify(bad_pages, [self.loc(0)]), ERR_INPUT)
        # Malformed pinned tip hash / trust.
        check([self.loc(0)], tip_hash="nope")
        check([self.loc(0)], trust={"audit_signers": []})
        # Empty pages array.
        self.assert_failed(self.verify([], [self.loc(0)]), ERR_INPUT)

    def test_auth_errors(self) -> None:
        pages = self.paged(self.loc(0), 2)
        locators = [self.loc(0)]
        tampered = copy.deepcopy(pages)
        tampered[0]["finalities"][0]["auth"] = {
            "key_version": 99,
            "signature": "0" * 128,
        }
        self.assert_failed(self.verify(tampered, locators), ERR_AUTH)
        tampered = copy.deepcopy(pages)
        tampered[1]["head"]["auth"]["signature"] = "0" * 128
        self.assert_failed(self.verify(tampered, locators), ERR_AUTH)
        other_pub = pub_hex(Ed25519PrivateKey.generate())
        self.assert_failed(
            self.verify(pages, locators, trust={"audit_signers": [
                {"version": 1, "public_key": other_pub}
            ]}),
            ERR_AUTH,
        )

    def test_integrity_errors(self) -> None:
        pages = self.paged(self.loc(0), 2)

        # The first page's anchor is not in the locator list.
        self.assert_failed(
            self.verify(pages, [self.loc(2), self.loc(1)]), ERR_INTEGRITY
        )
        # Same height, different hash is not membership.
        self.assert_failed(
            self.verify(pages, [{"height": 0, "block_hash": "a" * 64}]),
            ERR_INTEGRITY,
        )
        # Pinned tip hash disagrees.
        self.assert_failed(
            self.verify(pages, [self.loc(0)], tip_hash="a" * 64),
            ERR_INTEGRITY,
        )
        # A later page's anchor must chain from the predecessor's next.
        broken = copy.deepcopy(pages)
        broken[1]["anchor"] = self.loc(1)
        self.assert_failed(self.verify(broken, [self.loc(0)]), ERR_INTEGRITY)
        # The heads must be identical across pages.
        broken = copy.deepcopy(pages)
        broken[1]["head"] = pages[0]["finalities"][0]
        self.assert_failed(self.verify(broken, [self.loc(0)]), ERR_INTEGRITY)

    def test_membership_uses_exact_closed_document(self) -> None:
        # An equal document at the right position matches even if it is a
        # distinct object; the reported index is its 0-based position.
        pages = self.paged(self.loc(1), 100)
        locators = [self.loc(3), {"height": 1, "block_hash": self.h(1)}]
        result = self.verify(pages, locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["matched_index"], 1)


class FinalityLocatorHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.service = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "http.json"))
        )
        # Mine a couple of confirmed blocks so there is something to locate.
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
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def post(self, raw: bytes | str, *, ctype="application/json"):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}/v1/chain/finalities/locate",
            data=raw,
            method="POST",
            headers={"Content-Type": ctype},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_locate_http_success_and_order(self) -> None:
        genesis = self.service.store.chain[0].block_hash
        locators = [{"height": 0, "block_hash": genesis}]
        status, raw = self.post(json.dumps({"locators": locators}))
        self.assertEqual(status, 200, raw)
        self.assertEqual(
            [
                segment
                for segment in ("anchor", "finalities", "next", "head")
                if f'"{segment}"' in raw
            ],
            ["anchor", "finalities", "next", "head"],
        )
        document = json.loads(raw)
        trust = self.service.get_trust_document()[1]
        tip_hash = document["head"]["tip"]["tip_hash"]
        result = verify_finality_locator_pages(
            [document], locators, tip_hash, trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["matched_index"], 0)

    def test_locate_http_errors(self) -> None:
        genesis = self.service.store.chain[0].block_hash
        # Malformed JSON is a 400.
        self.assertEqual(self.post("{not json}")[0], 400)
        # Missing body is a 400.
        self.assertEqual(self.post("")[0], 400)
        # Closed-object/key violations are 400.
        self.assertEqual(self.post(json.dumps({}))[0], 400)
        self.assertEqual(
            self.post(
                json.dumps({"limit": 1, "locators": [{"height": 0, "block_hash": genesis}]})
            )[0],
            400,
        )
        self.assertEqual(
            self.post(
                json.dumps({"locators": [{"height": True, "block_hash": genesis}]})
            )[0],
            400,
        )
        # No confirmed main-chain match is a 409.
        self.assertEqual(
            self.post(
                json.dumps({"locators": [{"height": 0, "block_hash": "a" * 64}]})
            )[0],
            409,
        )


if __name__ == "__main__":
    unittest.main()
