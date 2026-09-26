"""Tests for signed block-header fork location.

Covers POST /v1/chain/headers/locate end to end:

* service validation — the body has ordered keys ``locators`` (and the
  optional ``limit``), the locators array is 1-64 items with ordered
  ``height, block_hash`` keys, heights are non-boolean non-negative integers
  in strictly descending unique order, hashes are 64 lowercase hex and
  ``limit`` is a non-boolean integer 1-500 (default 100); every defect is a
  400 with no state read;
* the first in-order locator naming a main-chain block anchors the signed
  page (the probe order matters, not the highest match), a locator list with
  no main-chain hit is 409, and the success body reuses the fixed
  ``anchor, headers, tip, auth`` signed-header-page shape with ascending
  headers after the anchor (at most ``limit``);
* the offline verifier
  ``ledger.light_client.verify_header_locator_page`` — success key order
  ``ok, anchor, tip, matched_index, verified_block_hashes`` with the index
  starting at 0, and input/auth/integrity categorization;
* the HTTP wire boundary (parse failures are 400, contract key order is
  preserved).

Run: python3 tests/header_locator_test.py
"""
from __future__ import annotations

import copy
import json
import os
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
    sign_header_page,
    verify_header_locator_page,
    verify_header_page,
)
from ledger.models import STATUS_PENDING
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class HeaderLocatorFixture(unittest.TestCase):
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

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def loc(self, height: int, block_hash: str | None = None) -> dict:
        if block_hash is None:
            block_hash = self.store.chain[height].block_hash
        return {"height": height, "block_hash": block_hash}

    def locate(self, payload):
        return self.service.locate_header_fork(payload)

    def re_sign(self, document: dict) -> None:
        signer = self.store.audit_signer
        envelope = sign_header_page(
            signer["private_key"],
            signer["version"],
            document["anchor"],
            document["headers"],
            document["tip"],
        )
        self.assertIsNotNone(envelope)
        document["auth"] = envelope


class HeaderLocatorServiceTests(HeaderLocatorFixture):
    def test_locates_first_matching_locator_in_order(self) -> None:
        # A locator set whose first item forks (same height, wrong hash) and
        # whose second item is a main-chain block.
        payload = {
            "locators": [
                {"height": 4, "block_hash": "f" * 64},
                self.loc(2),
                self.loc(1),
            ]
        }
        status, body = self.locate(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body.keys()), ["anchor", "headers", "tip", "auth"])
        self.assertEqual(body["anchor"], self.loc(2))
        # Headers run ascending strictly after the height-2 anchor.
        self.assertEqual([h["height"] for h in body["headers"]], [3, 4])
        self.assertEqual(body["tip"]["tip_hash"], self.tip_hash)
        # And the page verifies offline under the ordinary page contract.
        self.assertTrue(
            verify_header_page(
                body, body["anchor"], self.tip_hash, self.trust
            )["ok"]
        )

    def test_first_in_order_match_wins_not_a_deeper_one(self) -> None:
        # The newest locator that is on the main chain anchors; a deeper
        # common block listed afterwards must not be chosen instead.
        payload = {"locators": [self.loc(3), self.loc(1)]}
        status, body = self.locate(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(3))
        self.assertEqual([h["height"] for h in body["headers"]], [4])

    def test_a_fork_above_the_first_match_does_not_short_circuit(self) -> None:
        # A non-matching fork hash at a higher height is skipped and the next
        # main-chain locator anchors.
        payload = {"locators": [self.loc(4, "f" * 64), self.loc(2), self.loc(0)]}
        status, body = self.locate(payload)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(2))

    def test_genesis_locator_and_limit(self) -> None:
        status, body = self.locate(
            {"locators": [self.loc(0)], "limit": 2}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["anchor"], self.loc(0))
        self.assertEqual([h["height"] for h in body["headers"]], [1, 2])

    def test_limit_boundaries(self) -> None:
        base = {"locators": [self.loc(0)]}
        for good in (1, 500):
            status, body = self.locate({**base, "limit": good})
            self.assertEqual(status, 200, (good, body))
        for bad in (0, 501, -1, True, False, 1.0, "100", None):
            status, body = self.locate({**base, "limit": bad})
            self.assertEqual(status, 400, (bad, body))

    def test_default_limit_is_100(self) -> None:
        # Chain is shorter than 100 so the whole tail is returned.
        status, body = self.locate({"locators": [self.loc(0)]})
        self.assertEqual(status, 200, body)
        self.assertEqual([h["height"] for h in body["headers"]], [1, 2, 3, 4])

    def test_anchor_at_tip_is_empty_signed_page(self) -> None:
        status, body = self.locate({"locators": [self.loc(4)]})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["headers"], [])
        self.assertEqual(body["anchor"], self.loc(4))
        self.assertIn("auth", body)
        self.assertTrue(
            verify_header_page(body, body["anchor"], self.tip_hash, self.trust)[
                "ok"
            ]
        )

    def test_no_main_chain_match_is_409(self) -> None:
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
        good_height, good_hash = 3, self.store.chain[3].block_hash
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
        h = lambda i: self.store.chain[i].block_hash  # noqa: E731
        self.assert400({"locators": [self.loc(3), self.loc(3)]})
        self.assert400({"locators": [self.loc(2), self.loc(3)]})
        # Equal-height duplicate even with the same hash.
        self.assert400(
            {"locators": [{"height": 3, "block_hash": h(3)}, {"height": 3, "block_hash": "9" * 64}]}
        )
        # Strictly descending valid order locates.
        status, _ = self.locate({"locators": [self.loc(3), self.loc(2), self.loc(0)]})
        self.assertEqual(status, 200)


class HeaderLocatorVerifyTests(HeaderLocatorFixture):
    def verify(self, document, locators, tip_hash=None, trust=None):
        return verify_header_locator_page(
            document,
            locators,
            self.tip_hash if tip_hash is None else tip_hash,
            self.trust if trust is None else trust,
        )

    def page(self, height, block_hash, limit=None):
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def test_verifies_genuine_page_and_reports_index(self) -> None:
        page = self.page(2, self.store.chain[2].block_hash)
        locators = [
            {"height": 4, "block_hash": "f" * 64},  # fork at the tip
            self.loc(2),  # the actual anchor -> index 1
            self.loc(0),
        ]
        result = self.verify(page, locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result.keys()),
            ["ok", "anchor", "tip", "matched_index", "verified_block_hashes"],
        )
        self.assertEqual(result["anchor"], self.loc(2))
        self.assertEqual(result["matched_index"], 1)
        self.assertEqual(result["tip"], page["tip"])
        self.assertEqual(
            result["verified_block_hashes"],
            [b.block_hash for b in self.store.chain[3:]],
        )

    def test_index_zero_and_empty_page(self) -> None:
        page = self.page(4, self.tip_hash)
        result = self.verify(page, [self.loc(4)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["verified_block_hashes"], [])

    def test_input_errors(self) -> None:
        page = self.page(0, self.genesis_hash)

        def check(locators, **kwargs):
            result = self.verify(page, locators, **kwargs)
            self.assertEqual(result, {"ok": False, "error": ERR_INPUT}, result)

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
        # A malformed document stays input even with good locators.
        bad_doc = copy.deepcopy(page)
        del bad_doc["tip"]
        self.assertEqual(
            self.verify(bad_doc, [self.loc(0)]),
            {"ok": False, "error": ERR_INPUT},
        )
        # Malformed pinned tip hash.
        check([self.loc(0)], tip_hash="nope")
        check([self.loc(0)], trust={"audit_signers": []})

    def test_auth_errors(self) -> None:
        page = self.page(0, self.genesis_hash)
        locators = [self.loc(0)]
        tampered = copy.deepcopy(page)
        tampered["auth"] = {"key_version": 99, "signature": "0" * 128}
        self.assertEqual(
            self.verify(tampered, locators), {"ok": False, "error": ERR_AUTH}
        )
        tampered = copy.deepcopy(page)
        tampered["auth"]["signature"] = "0" * 128
        self.assertEqual(
            self.verify(tampered, locators), {"ok": False, "error": ERR_AUTH}
        )
        other_pub = pub_hex(Ed25519PrivateKey.generate())
        self.assertEqual(
            self.verify(page, locators, trust={"audit_signers": [
                {"version": 1, "public_key": other_pub}
            ]}),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_integrity_errors(self) -> None:
        page = self.page(0, self.genesis_hash)

        # The signed page's anchor is not in the locator list.
        result = self.verify(page, [self.loc(2), self.loc(1)])
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY}, result)
        # Same height, different hash is not membership.
        result = self.verify(
            page, [{"height": 0, "block_hash": "a" * 64}]
        )
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        # Pinned tip hash disagrees.
        result = self.verify(page, [self.loc(0)], tip_hash="a" * 64)
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        # A tampered header hash, re-signed (auth passes), anchor still
        # listed: the broken chain is integrity.
        tampered = copy.deepcopy(page)
        tampered["headers"][0]["block_hash"] = "f" * 64
        self.re_sign(tampered)
        result = self.verify(tampered, [self.loc(0)])
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})

    def test_membership_uses_exact_closed_document(self) -> None:
        # A locator equal in content but with a different key order is an
        # input defect (it never reaches membership); an equal document at the
        # right position matches even if it is a distinct object.
        page = self.page(1, self.store.chain[1].block_hash)
        locators = [self.loc(3), {"height": 1, "block_hash": self.store.chain[1].block_hash}]
        result = self.verify(page, locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["matched_index"], 1)


class HeaderLocatorHttpTests(unittest.TestCase):
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

    def post(self, raw: bytes | str, *, ctype="application/json"):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}/v1/chain/headers/locate",
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
        body = json.dumps({"locators": [{"height": 0, "block_hash": genesis}]})
        status, raw = self.post(body)
        self.assertEqual(status, 200, raw)
        self.assertEqual(
            [
                segment
                for segment in ("anchor", "headers", "tip", "auth")
                if f'"{segment}"' in raw
            ],
            ["anchor", "headers", "tip", "auth"],
        )
        document = json.loads(raw)
        trust = self.service.get_trust_document()[1]
        tip_hash = document["tip"]["tip_hash"]
        self.assertTrue(
            verify_header_locator_page(
                document,
                [{"height": 0, "block_hash": genesis}],
                tip_hash,
                trust,
            )["ok"]
        )

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
        # No main-chain match is a 409.
        self.assertEqual(
            self.post(
                json.dumps({"locators": [{"height": 0, "block_hash": "a" * 64}]})
            )[0],
            409,
        )


if __name__ == "__main__":
    unittest.main()
