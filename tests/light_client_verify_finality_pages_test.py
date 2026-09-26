"""Tests for the offline paginated finality-history verifier
``ledger.light_client.verify_finality_pages``.

Builds a confirmed chain with a pending tip through the real service and
covers:

* the happy path: a multi-page and a single-page ``GET
  /v1/chain/finalities`` history verifies offline against the pinned
  anchor and tip hash — the success key order is ``ok, anchor, head,
  pages, verified_block_hashes`` with the hashes in ascending chain
  order and the anchor itself not included;
* the empty single page whose anchor already is the finalized head;
* failure categories: parameter/key-order/type/encoding/trust defects
  ``input``, unknown key versions or bad signatures ``auth`` and anchor,
  continuity, pagination, tip or head defects ``integrity``; nothing is
  raised.

Run: python3 tests/light_client_verify_finality_pages_test.py
"""
from __future__ import annotations

import copy
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    sign_finality,
    verify_finality_pages,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class PagesFixture(unittest.TestCase):
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
        self.anchor = {"height": 0, "block_hash": self.genesis_hash}

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

    def finalities_page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_finalities(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit: int) -> list:
        """Every finalities page from the genesis anchor in ``limit`` steps."""
        bodies = []
        anchor = self.loc(0)
        while True:
            body = self.finalities_page(
                anchor["height"], anchor["block_hash"], limit
            )
            bodies.append(body)
            if body["next"] is None:
                return bodies
            anchor = body["next"]

    _UNSET = object()

    def verify(self, pages, anchor=_UNSET, tip_hash=_UNSET, trust=_UNSET) -> dict:
        return verify_finality_pages(
            pages,
            self.anchor if anchor is self._UNSET else anchor,
            self.tip_hash if tip_hash is self._UNSET else tip_hash,
            self.trust if trust is self._UNSET else trust,
        )

    def assert_failed(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class PagesSuccessTests(PagesFixture):
    def test_multi_page_batch(self) -> None:
        pages = self.paged(2)
        self.assertEqual(len(pages), 2)
        result = self.verify(pages)
        self.assertEqual(
            list(result.keys()),
            ["ok", "anchor", "head", "pages", "verified_block_hashes"],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["anchor"], self.anchor)
        self.assertEqual(result["head"], pages[0]["head"])
        self.assertEqual(result["pages"], 2)
        self.assertEqual(
            result["verified_block_hashes"], [self.h(1), self.h(2), self.h(3)]
        )

    def test_single_page_batch(self) -> None:
        pages = self.paged(100)
        self.assertEqual(len(pages), 1)
        result = self.verify(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(
            result["verified_block_hashes"], [self.h(1), self.h(2), self.h(3)]
        )

    def test_every_page_size(self) -> None:
        for limit in (1, 2, 3, 500):
            result = self.verify(self.paged(limit))
            self.assertTrue(result["ok"], (limit, result))
            self.assertEqual(
                result["verified_block_hashes"],
                [self.h(1), self.h(2), self.h(3)],
            )

    def test_later_anchor(self) -> None:
        # A history pinned at a later public anchor verifies too.
        result = self.verify(self.paged(1), anchor=self.anchor)
        self.assertTrue(result["ok"], result)
        pages = []
        anchor = self.loc(2)
        while True:
            body = self.finalities_page(anchor["height"], anchor["block_hash"], 1)
            pages.append(body)
            if body["next"] is None:
                break
            anchor = body["next"]
        result = self.verify(pages, anchor=self.loc(2))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["anchor"], self.loc(2))
        self.assertEqual(result["verified_block_hashes"], [self.h(3)])

    def test_empty_single_page_at_head(self) -> None:
        # The anchor already is the finalized head: an empty single page.
        empty = self.finalities_page(3, self.h(3))
        self.assertEqual(empty["finalities"], [])
        self.assertIsNone(empty["next"])
        result = self.verify([empty], anchor=self.loc(3))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["verified_block_hashes"], [])
        self.assertEqual(result["head"], empty["head"])


class PagesInputTests(PagesFixture):
    def test_argument_shape(self) -> None:
        pages = self.paged(2)
        for bad_pages in (None, {}, "x", 0, 1.5, []):
            self.assert_failed(self.verify(bad_pages), ERR_INPUT)
        for bad_anchor in (None, {}, {"height": 0}, {"height": "0", "block_hash": self.h(0)},
                           {"block_hash": self.h(0), "height": 0},
                           {"height": -1, "block_hash": self.h(0)},
                           {"height": True, "block_hash": self.h(0)},
                           {"height": 0, "block_hash": "zz" * 32}):
            self.assert_failed(self.verify(pages, anchor=bad_anchor), ERR_INPUT)
        for bad_tip in (None, "", 0, "AB" * 32, "g" * 64, "a" * 63):
            self.assert_failed(self.verify(pages, tip_hash=bad_tip), ERR_INPUT)

    def test_page_structure(self) -> None:
        pages = self.paged(2)
        good = copy.deepcopy(pages)
        cases = []
        # Not a dict.
        cases.append(["x", *good[1:]])
        # Wrong top-level key order / missing / extra keys.
        reordered = {"finalities": [], "anchor": good[0]["anchor"],
                     "next": None, "head": good[0]["head"]}
        cases.append([reordered, *good[1:]])
        extra = dict(good[0])
        extra["bogus"] = 1
        cases.append([extra, *good[1:]])
        shrunk = {k: good[0][k] for k in ("anchor", "finalities", "next")}
        cases.append([shrunk, *good[1:]])
        # Bad anchor/next shapes.
        bad_anchor = copy.deepcopy(good)
        bad_anchor[0]["anchor"] = {"block_hash": self.h(0), "height": 0}
        cases.append(bad_anchor)
        bad_next = copy.deepcopy(good)
        bad_next[0]["next"] = {"height": "2", "block_hash": self.h(2)}
        cases.append(bad_next)
        bad_next2 = copy.deepcopy(good)
        bad_next2[0]["next"] = 0
        cases.append(bad_next2)
        # finalities not a list / item shape defects.
        bad_items = copy.deepcopy(good)
        bad_items[0]["finalities"] = {}
        cases.append(bad_items)
        bad_item = copy.deepcopy(good)
        bad_item[0]["finalities"][0] = {
            "tip": good[0]["finalities"][0]["tip"],
            "finalized": good[0]["finalities"][0]["finalized"],
            "auth": good[0]["finalities"][0]["auth"],
        }
        cases.append(bad_item)
        bad_item2 = copy.deepcopy(good)
        bad_item2[0]["finalities"][0]["auth"] = {
            "key_version": 0,
            "signature": "ab" * 64,
        }
        cases.append(bad_item2)
        bad_item3 = copy.deepcopy(good)
        bad_item3[0]["finalities"][0]["tip"] = {
            "tip_hash": self.h(1),
            "height": 1,
            "length": 2,
            "status": "bogus",
        }
        cases.append(bad_item3)
        # head shape defects.
        bad_head = copy.deepcopy(good)
        bad_head[0]["head"] = {"finalized": self.loc(3)}
        cases.append(bad_head)
        for case in cases:
            self.assert_failed(self.verify(case), ERR_INPUT)

    def test_trust_shape(self) -> None:
        pages = self.paged(2)
        for bad_trust in (None, {}, {"audit_signers": []}, {"audit_signers": [{}]},
                          {"audit_signers": [{"version": 1, "public_key": "zz"}]}):
            self.assert_failed(self.verify(pages, trust=bad_trust), ERR_INPUT)


class PagesAuthTests(PagesFixture):
    def test_unknown_key_version(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["finalities"][0]["auth"]["key_version"] = 99
        self.assert_failed(self.verify(pages), ERR_AUTH)

    def test_unknown_head_key_version(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["head"]["auth"]["key_version"] = 99
        self.assert_failed(self.verify(pages), ERR_AUTH)

    def test_bad_item_signature(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["finalities"][0]["auth"]["signature"] = "00" * 64
        self.assert_failed(self.verify(pages), ERR_AUTH)

    def test_bad_head_signature(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["head"]["auth"]["signature"] = "00" * 64
        self.assert_failed(self.verify(pages), ERR_AUTH)

    def test_tampered_signed_content(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["finalities"][1]["finalized"]["block_hash"] = "0" * 64
        self.assert_failed(self.verify(pages), ERR_AUTH)


class PagesIntegrityTests(PagesFixture):
    def test_first_anchor_must_be_pinned_anchor(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["anchor"] = self.loc(1)
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)
        # A genuine batch pinned at the wrong anchor fails too.
        self.assert_failed(
            self.verify(self.paged(2), anchor=self.loc(1)), ERR_INTEGRITY
        )

    def test_later_anchor_must_chain(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["anchor"] = self.loc(1)
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)

    def test_heads_must_be_identical(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        # Re-sign a different head with the genuine signer.
        signer = self.trust["audit_signers"][-1]
        head = {
            "finalized": self.loc(2),
            "tip": {
                "tip_hash": self.tip_hash,
                "height": 4,
                "length": 5,
                "status": "pending",
            },
        }
        pages[1]["head"] = {
            **head,
            "auth": sign_finality(
                self.service.store.audit_signer["private_key"],
                signer["version"],
                head["finalized"],
                head["tip"],
            ),
        }
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)

    def test_head_tip_must_name_pinned_tip_hash(self) -> None:
        pages = self.paged(2)
        self.assert_failed(
            self.verify(pages, tip_hash="0" * 64), ERR_INTEGRITY
        )

    def test_non_last_page_must_be_non_empty_with_matching_next(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["next"] = self.loc(1)
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)
        pages = copy.deepcopy(self.paged(2))
        pages[0]["next"] = None
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)
        pages = copy.deepcopy(self.paged(2))
        pages[0]["finalities"] = []
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)

    def test_last_page_must_close(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["next"] = self.loc(3)
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)
        # A multi-page batch may not end on an empty page.
        pages = copy.deepcopy(self.paged(2))
        pages[1]["finalities"] = []
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)
        # The last page must reach head.finalized.
        pages = copy.deepcopy(self.paged(1))
        pages[1]["finalities"] = pages[1]["finalities"][:1]
        pages[1]["next"] = None
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)

    def test_credentials_must_be_consecutive(self) -> None:
        pages = copy.deepcopy(self.paged(1))
        # Drop the middle credential of the second page: heights skip.
        del pages[1]["finalities"][0]
        pages[0]["next"] = self.loc(1)
        pages[1]["anchor"] = self.loc(1)
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)

    def test_tip_descriptor_mismatch(self) -> None:
        # A genuine credential whose tip descriptor is replaced by a
        # signed but wrong S (length off).
        pages = self.paged(1)
        item = copy.deepcopy(pages[0]["finalities"][0])
        item["tip"] = {
            "tip_hash": self.h(1),
            "height": 1,
            "length": 3,
            "status": "confirmed",
        }
        signer = self.service.store.audit_signer
        item["auth"] = sign_finality(
            signer["private_key"],
            signer["version"],
            item["finalized"],
            item["tip"],
        )
        pages[0]["finalities"][0] = item
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)

    def test_tip_must_point_at_own_finalized(self) -> None:
        # A signed credential whose tip names another block.
        pages = self.paged(1)
        item = copy.deepcopy(pages[0]["finalities"][0])
        item["tip"] = {
            "tip_hash": self.h(2),
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        signer = self.service.store.audit_signer
        item["auth"] = sign_finality(
            signer["private_key"],
            signer["version"],
            item["finalized"],
            item["tip"],
        )
        pages[0]["finalities"][0] = item
        self.assert_failed(self.verify(pages), ERR_INTEGRITY)

    def test_empty_page_rules(self) -> None:
        # An empty single page whose anchor is not the finalized head.
        empty = self.finalities_page(3, self.h(3))
        forged = copy.deepcopy(empty)
        forged["anchor"] = self.loc(0)
        self.assert_failed(self.verify([forged]), ERR_INTEGRITY)
        # A genuine empty page pinned at the wrong anchor.
        self.assert_failed(
            self.verify([empty], anchor=self.loc(0)), ERR_INTEGRITY
        )


if __name__ == "__main__":
    unittest.main()
