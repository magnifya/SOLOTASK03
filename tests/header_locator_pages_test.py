"""Tests for ledger.light_client.verify_header_locator_pages (multi-page
locator batch).

Builds a confirmed chain with a pending tip, locates it through
POST /v1/chain/headers/locate pages with small limits and verifies the
ordered batch offline: success shape and key order
(``ok, anchor, tip, matched_index, pages, verified_block_hashes`` with the
index starting at 0 and the hashes in chain order excluding the anchor),
the first-page locator-membership anchor, anchor chaining across later page
seams, the shared tip descriptor, the last-page-must-reach-the-tip rule, the
empty-sole-page and pending-position rules, and the input/auth/integrity
categorization. The single-page locator verifier is covered by
tests/header_locator_test.py and stays unchanged.

Run: python3 tests/header_locator_pages_test.py
"""
from __future__ import annotations

import copy
import os
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
    sign_header_page,
    verify_header_locator_pages,
)
from ledger.models import STATUS_PENDING
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class HeaderLocatorPagesFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "locate-pages.json"))
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

    def page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, anchor: dict, limit: int) -> list:
        """The whole chain from ``anchor`` in ``limit``-sized pages."""
        documents = []
        while True:
            page = self.page(anchor["height"], anchor["block_hash"], limit)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == self.tip_hash:
                break
        return documents

    def verify(self, documents, locators, tip_hash=None, trust=None):
        return verify_header_locator_pages(
            documents,
            locators,
            self.tip_hash if tip_hash is None else tip_hash,
            self.trust if trust is None else trust,
        )

    def re_sign(self, document: dict) -> None:
        """Re-sign a tampered document so only integrity is at stake."""
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


class HeaderLocatorPagesVerifyTests(HeaderLocatorPagesFixture):
    def test_verifies_genuine_batches_and_reports_index(self) -> None:
        for limit in (1, 2, 3, 500):
            anchor = self.loc(0)
            documents = self.paged(anchor, limit)
            # The matched locator is the second item (index 1); the first is
            # a fork at the tip and must be skipped over.
            locators = [self.loc(4, "f" * 64), anchor]
            result = self.verify(documents, locators)
            self.assertTrue(result["ok"], (limit, result))
            self.assertEqual(
                list(result.keys()),
                [
                    "ok",
                    "anchor",
                    "tip",
                    "matched_index",
                    "pages",
                    "verified_block_hashes",
                ],
            )
            self.assertEqual(result["anchor"], anchor)
            self.assertEqual(result["matched_index"], 1)
            self.assertEqual(result["tip"], documents[0]["tip"])
            self.assertEqual(result["pages"], len(documents))
            self.assertEqual(
                result["verified_block_hashes"],
                [block.block_hash for block in self.store.chain[1:]],
            )

    def test_deep_anchor_index_zero_excludes_anchor_hash(self) -> None:
        # A matched locator deeper than genesis at index 0; only headers
        # strictly after the anchor are verified.
        documents = self.paged(self.loc(2), 1)
        result = self.verify(documents, [self.loc(2)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["anchor"], self.loc(2))
        self.assertEqual(
            result["verified_block_hashes"],
            [block.block_hash for block in self.store.chain[3:]],
        )

    def test_single_page_batch(self) -> None:
        page = self.page(0, self.genesis_hash)
        result = self.verify([page], [self.loc(0)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(len(result["verified_block_hashes"]), 4)

    def test_single_empty_page_at_tip(self) -> None:
        page = self.page(4, self.tip_hash)
        result = self.verify([page], [self.loc(4)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["verified_block_hashes"], [])

    def test_input_errors(self) -> None:
        page = self.page(0, self.genesis_hash)

        def check(documents, locators, **kwargs):
            result = self.verify(documents, locators, **kwargs)
            self.assertEqual(result, {"ok": False, "error": ERR_INPUT}, result)

        check("not a list", [self.loc(0)])
        check(page, [self.loc(0)])  # a bare document is not a batch
        check([], [self.loc(0)])
        check(["not a dict"], [self.loc(0)])
        first = self.page(0, self.genesis_hash, limit=2)
        check([first, "not a dict"], [self.loc(0)])
        # A first document without an anchor cannot pin itself.
        missing_anchor = copy.deepcopy(first)
        del missing_anchor["anchor"]
        check([missing_anchor], [self.loc(0)])
        # Wrong top-level key order on a page.
        reordered = {
            "headers": first["headers"],
            "anchor": first["anchor"],
            "tip": first["tip"],
            "auth": first["auth"],
        }
        check([reordered], [self.loc(0)])
        # Locator-list shape and ordering.
        check([page], "not-a-list")
        check([page], [])
        check([page], {})
        check([page], [self.loc(0), "x"])
        check([page], [{"block_hash": self.genesis_hash, "height": 0}])
        check([page], [{"height": True, "block_hash": self.genesis_hash}])
        check([page], [{"height": -1, "block_hash": self.genesis_hash}])
        check([page], [{"height": 0, "block_hash": "Z" * 64}])
        check([page], [self.loc(1), self.loc(1)])  # duplicate
        check([page], [self.loc(0), self.loc(1)])  # ascending
        check(
            [page],
            [{"height": 100 - i, "block_hash": "1" * 64} for i in range(65)],
        )
        # Malformed pinned tip hash and trust.
        check([page], [self.loc(0)], tip_hash="nope")
        check([page], [self.loc(0)], trust={"audit_signers": []})
        check([page], [self.loc(0)], trust="bare")

    def test_auth_errors(self) -> None:
        documents = self.paged(self.loc(0), 2)
        # Unknown key version on the second page.
        tampered = copy.deepcopy(documents)
        tampered[1]["auth"] = {"key_version": 7, "signature": "0" * 128}
        self.assertEqual(
            self.verify(tampered, [self.loc(0)]),
            {"ok": False, "error": ERR_AUTH},
        )
        # Known version, bad signature on the first page.
        tampered = copy.deepcopy(documents)
        tampered[0]["auth"]["signature"] = "0" * 128
        self.assertEqual(
            self.verify(tampered, [self.loc(0)]),
            {"ok": False, "error": ERR_AUTH},
        )
        # A trust document without the signing version.
        other_pub = pub_hex(Ed25519PrivateKey.generate())
        trust = {"audit_signers": [{"version": 1, "public_key": other_pub}]}
        self.assertEqual(
            self.verify(documents, [self.loc(0)], trust=trust),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_integrity_errors(self) -> None:
        documents = self.paged(self.loc(0), 2)
        self.assertEqual(len(documents), 2)

        def check(batch, locators=None, **kwargs):
            result = self.verify(
                batch, [self.loc(0)] if locators is None else locators, **kwargs
            )
            self.assertEqual(
                result, {"ok": False, "error": ERR_INTEGRITY}, result
            )

        # The first page's anchor is not offered in the locator list.
        check(documents, [self.loc(2), self.loc(1)])
        # Same height, different hash is not membership.
        check(documents, [{"height": 0, "block_hash": "a" * 64}])
        # Pinned tip hash disagrees.
        check(documents, tip_hash="a" * 64)
        # A tampered header hash, re-signed so auth passes.
        tampered = copy.deepcopy(documents)
        tampered[0]["headers"][1]["block_hash"] = "f" * 64
        self.re_sign(tampered[0])
        check(tampered)
        # A broken seam: the second page's anchor is not the first page's
        # last header.
        tampered = copy.deepcopy(documents)
        tampered[1]["anchor"] = self.loc(0)
        self.re_sign(tampered[1])
        check(tampered)
        # Missing page.
        missing = self.paged(self.loc(0), 1)
        check([missing[0], missing[2]])
        # Duplicate and reordered pages.
        check([documents[0], documents[0]])
        check([documents[1], documents[0]])
        # The last page does not reach the pinned tip.
        check([documents[0]])
        # An empty page anywhere but as the batch's sole page.
        empty = self.page(4, self.tip_hash)
        check([documents[0], empty, documents[1]], [self.loc(4), self.loc(0)])
        # A page after a pending header.
        full = self.page(0, self.genesis_hash)
        check([full, empty], [self.loc(4), self.loc(0)])
        # Pending header in a non-final page, re-signed.
        tampered = copy.deepcopy(documents)
        tampered[0]["headers"][-1]["status"] = STATUS_PENDING
        self.re_sign(tampered[0])
        check(tampered)
        # Diverging tip descriptors across pages, re-signed.
        tampered = copy.deepcopy(documents)
        tampered[1]["tip"]["status"] = "confirmed"
        self.re_sign(tampered[1])
        check(tampered)

    def test_empty_page_only_valid_as_sole_page_at_tip(self) -> None:
        descriptor = self.page(0, self.genesis_hash)["tip"]
        # An empty page whose anchor is not the tip is itself incoherent.
        empty_elsewhere = {
            "anchor": self.loc(2),
            "headers": [],
            "tip": descriptor,
        }
        empty_elsewhere["auth"] = sign_header_page(
            self.store.audit_signer["private_key"],
            self.store.audit_signer["version"],
            empty_elsewhere["anchor"],
            empty_elsewhere["headers"],
            empty_elsewhere["tip"],
        )
        self.assertEqual(
            self.verify([empty_elsewhere], [self.loc(2)]),
            {"ok": False, "error": ERR_INTEGRITY},
        )
        # Even a correct anchor==tip empty page must be the only page.
        empty_tip = self.page(4, self.tip_hash)
        real = self.page(0, self.genesis_hash)
        self.assertEqual(
            self.verify([empty_tip, real], [self.loc(4), self.loc(0)]),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_rotation_keeps_cross_version_batch_verifiable(self) -> None:
        first = self.page(0, self.genesis_hash, limit=2)
        seed = crypto.generate_private_key()
        status, _ = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        trust = self.service.get_trust_document()[1]
        last = first["headers"][-1]
        second = self.page(last["height"], last["block_hash"])
        self.assertEqual(first["auth"]["key_version"], 1)
        self.assertEqual(second["auth"]["key_version"], 2)
        result = verify_header_locator_pages(
            [first, second], [self.loc(0)], self.tip_hash, trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["matched_index"], 0)


if __name__ == "__main__":
    unittest.main()
