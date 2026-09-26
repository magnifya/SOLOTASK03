"""Tests for ledger.light_client.verify_header_pages (multi-page batch).

Builds a confirmed chain with a pending tip, pages it through
GET /v1/chain/headers with small limits and verifies the ordered batch
offline: success shape and key order, anchor chaining across page seams,
the shared tip descriptor, the last-page-must-reach-the-tip rule, the
empty-page and pending-position rules, and the input/auth/integrity
categorization. The single-page verifier and the HTTP/CLI surface are
covered by tests/header_page_test.py and stay unchanged.

Run: python3 tests/header_pages_test.py
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
    verify_header_pages,
)
from ledger.models import STATUS_PENDING
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class HeaderPagesFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.store = LedgerStore(os.path.join(self.tmp, "headers.json"))
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

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit: int) -> list:
        """The whole chain from the genesis anchor in ``limit``-sized pages."""
        documents = []
        anchor = self.anchor
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

    def verify(self, documents, anchor=None, tip_hash=None, trust=None):
        return verify_header_pages(
            documents,
            self.anchor if anchor is None else anchor,
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


class HeaderPagesVerifyTests(HeaderPagesFixture):
    def test_verifies_genuine_batches(self) -> None:
        for limit in (1, 2, 3, 500):
            documents = self.paged(limit)
            result = self.verify(documents)
            self.assertTrue(result["ok"], (limit, result))
            self.assertEqual(
                list(result.keys()),
                ["ok", "anchor", "tip", "pages", "verified_block_hashes"],
            )
            self.assertEqual(result["anchor"], self.anchor)
            self.assertEqual(result["tip"], documents[0]["tip"])
            self.assertEqual(result["pages"], len(documents))
            self.assertEqual(
                result["verified_block_hashes"],
                [block.block_hash for block in self.store.chain[1:]],
            )

    def test_single_page_batch(self) -> None:
        result = self.verify([self.page(0, self.genesis_hash)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(len(result["verified_block_hashes"]), 4)

    def test_trailing_empty_page_at_tip_closes_batch(self) -> None:
        # Confirm the pending tip so the chain tail is confirmed; an empty
        # page may then close the batch at the tip.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        documents = [self.page(0, self.genesis_hash, limit=2)]
        last = documents[0]["headers"][-1]
        documents.append(
            self.page(last["height"], last["block_hash"], limit=2)
        )
        # An explicit empty page whose anchor is the tip may close the batch.
        documents.append(self.page(4, self.tip_hash))
        result = self.verify(documents)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 3)
        self.assertEqual(len(result["verified_block_hashes"]), 4)

    def test_single_empty_page_batch_at_tip(self) -> None:
        # A batch that is only the empty anchor==tip page verifies.
        result = self.verify(
            [self.page(4, self.tip_hash)], anchor={"height": 4, "block_hash": self.tip_hash}
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["verified_block_hashes"], [])

    def test_input_errors(self) -> None:
        page = self.page(0, self.genesis_hash)

        def check(documents, **kwargs):
            result = self.verify(documents, **kwargs)
            self.assertEqual(result, {"ok": False, "error": ERR_INPUT}, result)

        check("not a list")
        check(page)  # a bare document is not a batch
        check([])
        check(["not a dict"])
        first = self.page(0, self.genesis_hash, limit=2)
        check([first, "not a dict"])
        reordered = {"headers": [], "anchor": page["anchor"]}
        reordered.update({"tip": page["tip"], "auth": page["auth"]})
        check([reordered])
        bad = copy.deepcopy(first)
        bad["headers"][0]["height"] = True
        self.re_sign(bad)
        check([first, bad])
        check([page], anchor={"block_hash": self.genesis_hash, "height": 0})
        check([page], tip_hash="not-hex")
        check([page], trust={"audit_signers": []})
        check([page], trust="bare")

    def test_auth_errors(self) -> None:
        documents = self.paged(2)
        # Unknown key version on the second page.
        tampered = copy.deepcopy(documents)
        tampered[1]["auth"] = {"key_version": 7, "signature": "0" * 128}
        self.assertEqual(
            self.verify(tampered), {"ok": False, "error": ERR_AUTH}
        )
        # Known version, bad signature on the first page.
        tampered = copy.deepcopy(documents)
        tampered[0]["auth"]["signature"] = "0" * 128
        self.assertEqual(
            self.verify(tampered), {"ok": False, "error": ERR_AUTH}
        )
        # A trust document without the signing version.
        other_pub = pub_hex(Ed25519PrivateKey.generate())
        trust = {"audit_signers": [{"version": 1, "public_key": other_pub}]}
        self.assertEqual(
            self.verify(documents, trust=trust),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_integrity_errors(self) -> None:
        documents = self.paged(2)
        self.assertEqual(len(documents), 2)

        def check(batch):
            result = self.verify(batch)
            self.assertEqual(
                result, {"ok": False, "error": ERR_INTEGRITY}, result
            )

        # A tampered header hash, re-signed so auth passes.
        tampered = copy.deepcopy(documents)
        tampered[0]["headers"][1]["block_hash"] = "f" * 64
        self.re_sign(tampered[0])
        check(tampered)
        # The first page's anchor does not match the pinned anchor.
        wrong_anchor = {"height": 1, "block_hash": self.store.chain[1].block_hash}
        check_result = self.verify(documents, anchor=wrong_anchor)
        self.assertEqual(
            check_result, {"ok": False, "error": ERR_INTEGRITY}
        )
        # A broken seam: the second page's anchor is not the first page's
        # last header.
        tampered = copy.deepcopy(documents)
        tampered[1]["anchor"] = {"height": 0, "block_hash": self.genesis_hash}
        self.re_sign(tampered[1])
        check(tampered)
        # Missing page: the second page starts after a gap.
        missing = self.paged(1)
        check([missing[0], missing[2]])
        # Duplicate page.
        check([documents[0], documents[0]])
        # Reordered pages.
        check([documents[1], documents[0]])
        # The last page does not reach the pinned tip.
        check([documents[0]])
        # A non-final empty page.
        empty = self.page(4, self.tip_hash)
        check([documents[0], empty, documents[1]])
        # A page after a pending header: the full page ends at the pending
        # tip, so nothing may follow it.
        full = self.page(0, self.genesis_hash)
        check([full, empty])
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
        # A pinned tip hash no page names.
        result = self.verify(documents, tip_hash="a" * 64)
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})

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
        result = verify_header_pages(
            [first, second], self.anchor, self.tip_hash, trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 2)


if __name__ == "__main__":
    unittest.main()
