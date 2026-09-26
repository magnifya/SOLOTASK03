"""Tests for the offline paginated finality-history verifier
``ledger.light_client.verify_finality_pages``.

Builds a confirmed chain with a pending tip through the real service and
covers:

* the happy path: multi-page, single-page and every page size verify —
  the success key order is ``ok, anchor, head, pages,
  verified_block_hashes`` with the hashes ascending and the anchor not
  included;
* the empty single page whose anchor already is the finalized head;
* failure categories: parameter/key-order/type/trust defects ``input``,
  unknown key versions or bad signatures ``auth`` and anchor,
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


class VerifyFinalityPagesFixture(unittest.TestCase):
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

    def paged(self, limit: int, start: int = 0) -> list:
        """Every finalities page from the height-``start`` anchor."""
        bodies = []
        anchor = self.loc(start)
        while True:
            body = self.finalities_page(
                anchor["height"], anchor["block_hash"], limit
            )
            bodies.append(body)
            if body["next"] is None:
                return bodies
            anchor = body["next"]

    def assert_failed(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class VerifyFinalityPagesSuccessTests(VerifyFinalityPagesFixture):
    def test_multi_page_batch(self) -> None:
        pages = self.paged(2)
        self.assertEqual(len(pages), 2)
        result = verify_finality_pages(
            pages, self.anchor, self.tip_hash, self.trust
        )
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
        result = verify_finality_pages(
            pages, self.anchor, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(
            result["verified_block_hashes"], [self.h(1), self.h(2), self.h(3)]
        )

    def test_every_page_size(self) -> None:
        for limit in (1, 2, 3, 4, 100):
            pages = self.paged(limit)
            result = verify_finality_pages(
                pages, self.anchor, self.tip_hash, self.trust
            )
            self.assertTrue(result["ok"], (limit, result))
            self.assertEqual(result["pages"], len(pages))
            self.assertEqual(
                result["verified_block_hashes"],
                [self.h(1), self.h(2), self.h(3)],
            )

    def test_empty_single_page_at_head(self) -> None:
        # An anchor that already is the finalized head yields one empty
        # page; the verified hashes are empty and the anchor is echoed.
        pages = self.paged(100, start=3)
        self.assertEqual(len(pages), 1)
        self.assertEqual(pages[0]["finalities"], [])
        result = verify_finality_pages(
            pages, self.loc(3), self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["anchor"], self.loc(3))
        self.assertEqual(result["verified_block_hashes"], [])


class VerifyFinalityPagesInputTests(VerifyFinalityPagesFixture):
    def test_argument_shape(self) -> None:
        pages = self.paged(2)
        good = verify_finality_pages(
            pages, self.anchor, self.tip_hash, self.trust
        )
        self.assertTrue(good["ok"], good)
        for bad_pages in (None, "x", {}, [], 1, True):
            self.assert_failed(
                verify_finality_pages(
                    bad_pages, self.anchor, self.tip_hash, self.trust
                ),
                ERR_INPUT,
            )
        for bad_anchor in (None, "x", {"height": 0}, {"height": -1, "block_hash": self.genesis_hash}, {"block_hash": self.genesis_hash, "height": 0}):
            self.assert_failed(
                verify_finality_pages(pages, bad_anchor, self.tip_hash, self.trust),
                ERR_INPUT,
            )
        for bad_tip in (None, 0, "x" * 64, "A" * 64, self.tip_hash[:63], True):
            self.assert_failed(
                verify_finality_pages(pages, self.anchor, bad_tip, self.trust),
                ERR_INPUT,
            )

    def test_page_structure(self) -> None:
        pages = self.paged(2)
        # Top-level key order.
        for broken in (
            {"finalities": [], "anchor": pages[0]["anchor"], "next": None, "head": pages[0]["head"]},
            {"anchor": pages[0]["anchor"], "finalities": [], "next": None},
            dict(pages[0], extra=1),
        ):
            self.assert_failed(
                verify_finality_pages(
                    [broken], self.anchor, self.tip_hash, self.trust
                ),
                ERR_INPUT,
            )
        # Item key order.
        good_item = pages[0]["finalities"][0]
        reordered = {
            "tip": good_item["tip"],
            "finalized": good_item["finalized"],
            "auth": good_item["auth"],
        }
        bad = copy.deepcopy(pages)
        bad[0]["finalities"][0] = reordered
        self.assert_failed(
            verify_finality_pages(bad, self.anchor, self.tip_hash, self.trust),
            ERR_INPUT,
        )
        # Bad signature encoding.
        bad = copy.deepcopy(pages)
        bad[0]["finalities"][0]["auth"]["signature"] = "zz"
        self.assert_failed(
            verify_finality_pages(bad, self.anchor, self.tip_hash, self.trust),
            ERR_INPUT,
        )

    def test_trust_shape(self) -> None:
        pages = self.paged(2)
        for bad_trust in (
            None,
            {},
            {"audit_signers": []},
            {"audit_signers": [{"version": 1}]},
            {"audit_signers": [{"version": 1, "public_key": "zz"}]},
            {"audit_signers": [{"version": 0, "public_key": "a" * 64}]},
        ):
            self.assert_failed(
                verify_finality_pages(pages, self.anchor, self.tip_hash, bad_trust),
                ERR_INPUT,
            )


class VerifyFinalityPagesAuthTests(VerifyFinalityPagesFixture):
    def test_unknown_key_version(self) -> None:
        pages = self.paged(2)
        pages[0]["finalities"][0]["auth"]["key_version"] = 999
        self.assert_failed(
            verify_finality_pages(pages, self.anchor, self.tip_hash, self.trust),
            ERR_AUTH,
        )

    def test_bad_item_signature(self) -> None:
        pages = self.paged(2)
        pages[0]["finalities"][0]["auth"]["signature"] = "0" * 128
        self.assert_failed(
            verify_finality_pages(pages, self.anchor, self.tip_hash, self.trust),
            ERR_AUTH,
        )

    def test_bad_head_signature(self) -> None:
        pages = self.paged(2)
        for page in pages:
            page["head"]["auth"]["signature"] = "0" * 128
        self.assert_failed(
            verify_finality_pages(pages, self.anchor, self.tip_hash, self.trust),
            ERR_AUTH,
        )

    def test_tampered_signed_content(self) -> None:
        pages = self.paged(2)
        pages[0]["finalities"][0]["finalized"]["height"] = 99
        self.assert_failed(
            verify_finality_pages(pages, self.anchor, self.tip_hash, self.trust),
            ERR_AUTH,
        )


class VerifyFinalityPagesIntegrityTests(VerifyFinalityPagesFixture):
    def test_first_anchor_must_be_pinned_anchor(self) -> None:
        pages = self.paged(2)
        self.assert_failed(
            verify_finality_pages(
                pages, self.loc(1), self.tip_hash, self.trust
            ),
            ERR_INTEGRITY,
        )

    def test_later_anchor_must_chain(self) -> None:
        pages = self.paged(1)
        del pages[1]
        self.assert_failed(
            verify_finality_pages(
                pages, self.anchor, self.tip_hash, self.trust
            ),
            ERR_INTEGRITY,
        )

    def test_heads_must_be_identical(self) -> None:
        pages = self.paged(1)
        # Re-sign a different head for the second page.
        different = copy.deepcopy(pages[1]["head"])
        different["tip"] = {
            "tip_hash": self.tip_hash,
            "height": 4,
            "length": 5,
            "status": "confirmed",
        }
        audit = self.store.audit_signer
        different["auth"] = sign_finality(
            audit["private_key"], audit["version"], different["finalized"], different["tip"]
        )
        pages[1]["head"] = different
        self.assert_failed(
            verify_finality_pages(
                pages, self.anchor, self.tip_hash, self.trust
            ),
            ERR_INTEGRITY,
        )

    def test_non_last_page_must_be_non_empty_with_matching_next(self) -> None:
        pages = self.paged(2)
        # Empty non-final page.
        bad = copy.deepcopy(pages)
        bad[0]["finalities"] = []
        self.assert_failed(
            verify_finality_pages(bad, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )
        # next not the last item's finalized.
        bad = copy.deepcopy(pages)
        bad[0]["next"] = self.loc(1)
        self.assert_failed(
            verify_finality_pages(bad, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )
        # Non-final page with null next.
        bad = copy.deepcopy(pages)
        bad[0]["next"] = None
        del bad[1]
        self.assert_failed(
            verify_finality_pages(bad, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )

    def test_last_page_must_close(self) -> None:
        pages = self.paged(2)
        bad = copy.deepcopy(pages)
        bad[-1]["next"] = self.loc(3)
        self.assert_failed(
            verify_finality_pages(bad, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )
        # Last item not reaching head.finalized (``next`` is unsigned
        # pagination metadata, so closing the page early is possible).
        bad = self.paged(1)[:2]
        bad[-1]["next"] = None
        self.assert_failed(
            verify_finality_pages(bad, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )

    def test_credentials_must_be_consecutive(self) -> None:
        pages = self.paged(100)
        # Drop the middle credential: heights skip.
        pages[0]["finalities"] = (
            pages[0]["finalities"][:1] + pages[0]["finalities"][2:]
        )
        self.assert_failed(
            verify_finality_pages(pages, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )

    def test_tip_must_be_confirmed_self_descriptor(self) -> None:
        pages = self.paged(100)
        item = pages[0]["finalities"][0]
        audit = self.store.audit_signer
        # A credential whose tip points elsewhere, honestly re-signed.
        forged_tip = {
            "tip_hash": self.h(2),
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        item["tip"] = forged_tip
        item["auth"] = sign_finality(
            audit["private_key"], audit["version"], item["finalized"], forged_tip
        )
        self.assert_failed(
            verify_finality_pages(pages, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )
        # A pending tip status, honestly re-signed.
        pages = self.paged(100)
        item = pages[0]["finalities"][0]
        forged_tip = dict(item["tip"], status="pending")
        item["tip"] = forged_tip
        item["auth"] = sign_finality(
            audit["private_key"], audit["version"], item["finalized"], forged_tip
        )
        self.assert_failed(
            verify_finality_pages(pages, self.anchor, self.tip_hash, self.trust),
            ERR_INTEGRITY,
        )

    def test_head_tip_must_name_pinned_tip_hash(self) -> None:
        pages = self.paged(2)
        self.assert_failed(
            verify_finality_pages(
                pages, self.anchor, self.h(3), self.trust
            ),
            ERR_INTEGRITY,
        )

    def test_empty_page_only_single_at_head(self) -> None:
        # An empty page whose anchor is not the head.
        page = self.finalities_page(3, self.h(3))
        self.assert_failed(
            verify_finality_pages(
                [page], self.anchor, self.tip_hash, self.trust
            ),
            ERR_INTEGRITY,
        )
        # An empty final page after a non-empty page.
        pages = self.paged(2)
        tail = self.finalities_page(3, self.h(3))
        pages.append(tail)
        self.assert_failed(
            verify_finality_pages(
                pages, self.anchor, self.tip_hash, self.trust
            ),
            ERR_INTEGRITY,
        )


if __name__ == "__main__":
    unittest.main()
