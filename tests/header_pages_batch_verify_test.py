"""Tests for offline multi-page signed-header verification
(ledger.light_client.verify_header_pages).

Covers the batch-level rules on top of the per-page rules already exercised by
``header_page_test.py``: non-empty array input, fixed success key order
``ok, anchor, tip, pages, verified_block_hashes``, per-page reuse of the
``verify_header_page`` contract (key order, types, signer history, domain
signature, header hashes), a field-for-field identical tip on every page whose
``tip_hash`` is the pinned one, anchor chaining (first page pinned to
``anchor``, every later page pinned to the previous page's last header's
``{height, block_hash}``), height/prev_hash continuity across seams (missing,
duplicate, reordered or overlapping pages are integrity), a pending header
allowed only as the final header of the batch, a non-final page required to be
non-empty and to end strictly before the tip, the last page required to reach
the tip, an empty page allowed only when its anchor is the tip, and the
input/auth/integrity categorization.

Run: python3 tests/header_pages_batch_verify_test.py
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

RESULT_KEY_ORDER = ["ok", "anchor", "tip", "pages", "verified_block_hashes"]
_DEFAULT = object()


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

    def pages(self, sizes) -> list:
        """Split the chain into consecutive header pages of ``sizes`` headers.
        """
        documents = []
        height, block_hash = 0, self.genesis_hash
        cursor = 0
        for size in sizes:
            document = self.page(height, block_hash, limit=size)
            documents.append(document)
            last = document["headers"][-1]
            height, block_hash = last["height"], last["block_hash"]
            cursor += size
        return documents

    def verify(self, documents, *, anchor=_DEFAULT,
               tip_hash=_DEFAULT, trust=_DEFAULT):
        return verify_header_pages(
            documents,
            self.anchor if anchor is _DEFAULT else anchor,
            self.tip_hash if tip_hash is _DEFAULT else tip_hash,
            self.trust if trust is _DEFAULT else trust,
        )

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category}, result)

    def re_sign(self, document: dict) -> None:
        """Re-sign a tampered document with the current audit signer."""
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


class VerifyHeaderPagesSuccessTests(HeaderPagesFixture):
    def test_two_page_success_shape_and_key_order(self) -> None:
        documents = self.pages([2, 2])
        result = self.verify(documents)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), RESULT_KEY_ORDER)
        self.assertEqual(result["anchor"], documents[0]["anchor"])
        self.assertEqual(result["tip"], documents[0]["tip"])
        self.assertEqual(result["pages"], 2)
        self.assertEqual(
            result["verified_block_hashes"],
            [self.store.chain[i].block_hash for i in range(1, 5)],
        )

    def test_three_page_success(self) -> None:
        result = self.verify(self.pages([1, 1, 2]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 3)
        self.assertEqual(result["anchor"], self.anchor)
        self.assertEqual(result["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(
            result["verified_block_hashes"],
            [self.store.chain[i].block_hash for i in range(1, 5)],
        )

    def test_single_page_batch(self) -> None:
        documents = self.pages([4])
        result = self.verify(documents)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(
            result["verified_block_hashes"],
            [self.store.chain[i].block_hash for i in range(1, 5)],
        )

    def test_hashes_exclude_the_anchor_and_follow_chain_order(self) -> None:
        # Start the batch at height 2: the anchor hash must not appear.
        page = self.page(2, self.store.chain[2].block_hash, limit=2)
        result = self.verify(
            [page],
            anchor={"height": 2, "block_hash": self.store.chain[2].block_hash},
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            result["verified_block_hashes"],
            [self.store.chain[3].block_hash, self.store.chain[4].block_hash],
        )

    def test_pending_tip_on_last_page_is_accepted(self) -> None:
        result = self.verify(self.pages([3, 1]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], STATUS_PENDING)
        self.assertEqual(
            result["verified_block_hashes"][-1], self.store.chain[4].block_hash
        )

    def test_single_empty_page_at_tip_verifies_with_empty_hashes(self) -> None:
        empty = self.page(4, self.tip_hash)
        self.assertEqual(empty["headers"], [])
        result = self.verify(
            [empty], anchor={"height": 4, "block_hash": self.tip_hash}
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["verified_block_hashes"], [])

    def test_confirmed_chain_reaching_tip_across_pages(self) -> None:
        # Confirm the pending tip so the chain ends confirmed at height 4.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.store.tip().status, "confirmed")
        result = self.verify(self.pages([2, 2]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], "confirmed")
        self.assertEqual(result["pages"], 2)


class VerifyHeaderPagesInputTests(HeaderPagesFixture):
    def test_documents_must_be_a_non_empty_array(self) -> None:
        for bad in (None, {}, "x", 1, True, [], ()):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(bad), ERR_INPUT)

    def test_page_element_must_be_an_object(self) -> None:
        documents = self.pages([2, 2])
        documents[1] = None
        self.assert_error(self.verify(documents), ERR_INPUT)
        documents = self.pages([2, 2])
        documents[0] = [1, 2, 3]
        self.assert_error(self.verify(documents), ERR_INPUT)

    def test_page_key_order_is_enforced(self) -> None:
        documents = self.pages([2, 2])
        page = documents[1]
        documents[1] = {
            key: page[key] for key in reversed(list(page.keys()))
        }
        self.assert_error(self.verify(documents), ERR_INPUT)

    def test_header_item_key_order_and_types(self) -> None:
        documents = self.pages([2, 2])
        documents[0]["headers"][0]["height"] = "1"
        self.re_sign(documents[0])
        self.assert_error(self.verify(documents), ERR_INPUT)
        documents = self.pages([2, 2])
        documents[0]["headers"][0]["extra"] = 1
        self.re_sign(documents[0])
        self.assert_error(self.verify(documents), ERR_INPUT)

    def test_anchor_shape_defects(self) -> None:
        documents = self.pages([2, 2])
        for bad in (
            None,
            {},
            {"height": 0},
            {"block_hash": self.genesis_hash, "height": 0},
            {"height": -1, "block_hash": self.genesis_hash},
            {"height": 0, "block_hash": "00"},
        ):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(documents, anchor=bad), ERR_INPUT)

    def test_tip_hash_shape_defect(self) -> None:
        documents = self.pages([2, 2])
        for bad in (None, 4, "not-hex", "Z" * 64):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(documents, tip_hash=bad), ERR_INPUT)

    def test_trust_shape_defects(self) -> None:
        documents = self.pages([2, 2])
        for bad in (
            None,
            [],
            "bare",
            {"audit_signers": []},
            {"audit_signers": [{}]},
        ):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(documents, trust=bad), ERR_INPUT)

    def test_input_takes_precedence_over_later_integrity(self) -> None:
        # A malformed second page reports input even though dropping it would
        # leave the batch short of the tip.
        documents = self.pages([2, 2])
        documents[1] = "not-an-object"
        self.assert_error(self.verify(documents), ERR_INPUT)


class VerifyHeaderPagesAuthTests(HeaderPagesFixture):
    def test_unknown_key_version_on_second_page_is_auth(self) -> None:
        documents = self.pages([2, 2])
        documents[1]["auth"] = {"key_version": 9, "signature": "0" * 128}
        self.assert_error(self.verify(documents), ERR_AUTH)

    def test_bad_signature_on_second_page_is_auth(self) -> None:
        documents = self.pages([2, 2])
        documents[1]["auth"]["signature"] = "0" * 128
        self.assert_error(self.verify(documents), ERR_AUTH)

    def test_wrong_signer_key_is_auth(self) -> None:
        other_pub = pub_hex(Ed25519PrivateKey.generate())
        trust = {"audit_signers": [{"version": 1, "public_key": other_pub}]}
        self.assert_error(self.verify(self.pages([2, 2]), trust=trust), ERR_AUTH)

    def test_auth_takes_precedence_over_seam_integrity(self) -> None:
        documents = self.pages([2, 2])
        documents[1]["auth"]["signature"] = "0" * 128
        documents[1]["anchor"] = {"height": 0, "block_hash": "1" * 64}
        self.assert_error(self.verify(documents), ERR_AUTH)

    def test_pages_signed_under_rotated_keys_both_verify(self) -> None:
        # A page minted before rotation (v1) and a page minted after rotation
        # (v2) chain together under the post-rotation signer history.
        first = self.page(0, self.genesis_hash, limit=2)
        self.assertEqual(first["auth"]["key_version"], 1)
        seed = crypto.generate_private_key()
        status, _ = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        trust = self.service.get_trust_document()[1]
        second = self.page(2, first["headers"][-1]["block_hash"])
        self.assertEqual(second["auth"]["key_version"], 2)
        result = verify_header_pages(
            [first, second], self.anchor, self.tip_hash, trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 2)
        # Claiming the v2 envelope under version 1 is an auth failure.
        tampered = copy.deepcopy(second)
        tampered["auth"]["key_version"] = 1
        self.assert_error(
            verify_header_pages(
                [first, tampered], self.anchor, self.tip_hash, trust
            ),
            ERR_AUTH,
        )


class VerifyHeaderPagesIntegrityTests(HeaderPagesFixture):
    def test_first_page_anchor_must_match_pinned_anchor(self) -> None:
        documents = self.pages([2, 2])
        bad_anchor = {"height": 1, "block_hash": self.store.chain[1].block_hash}
        self.assert_error(
            self.verify(documents, anchor=bad_anchor), ERR_INTEGRITY
        )

    def test_broken_seam_anchor(self) -> None:
        documents = self.pages([2, 2])
        documents[1]["anchor"]["block_hash"] = "0" * 64
        self.re_sign(documents[1])
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_missing_page_is_integrity(self) -> None:
        # Split 1/1/2 then drop the middle page: the seam skips height 2.
        documents = self.pages([1, 1, 2])
        del documents[1]
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_duplicate_page_is_integrity(self) -> None:
        documents = self.pages([2, 2])
        documents[1] = copy.deepcopy(documents[0])
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_reordered_pages_are_integrity(self) -> None:
        documents = self.pages([2, 2])
        documents[0], documents[1] = documents[1], documents[0]
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_overlapping_pages_are_integrity(self) -> None:
        # The second page re-delivers height 2 instead of continuing at 3.
        documents = self.pages([2, 2])
        documents[1] = self.page(1, self.store.chain[1].block_hash, limit=2)
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_height_gap_between_pages_is_integrity(self) -> None:
        first = self.pages([2])[0]
        # Anchor at block 2 but the first header delivered is block 4.
        gap_page = self.page(3, self.store.chain[3].block_hash, limit=1)
        gap_page["anchor"] = {
            "height": 2,
            "block_hash": self.store.chain[2].block_hash,
        }
        self.re_sign(gap_page)
        self.assert_error(self.verify([first, gap_page]), ERR_INTEGRITY)

    def test_last_page_must_reach_the_tip(self) -> None:
        # The second page ends at height 3 while the pinned tip is height 4.
        documents = self.pages([2, 1])
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_non_final_page_must_be_non_empty(self) -> None:
        # An empty page (legal only when its anchor is the tip) cannot be
        # followed by more pages; pin the anchor to the tip so only the batch
        # pagination rule is at stake.
        empty = self.page(4, self.tip_hash)
        tip_anchor = {"height": 4, "block_hash": self.tip_hash}
        self.assert_error(
            self.verify(
                [empty, copy.deepcopy(empty)], anchor=tip_anchor
            ),
            ERR_INTEGRITY,
        )

    def test_non_final_page_must_end_before_the_tip(self) -> None:
        # On a fully confirmed chain, a first page that already reaches the
        # tip cannot be followed by another page, even an empty tip page.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        full = self.page(0, self.genesis_hash)
        self.assertEqual(full["headers"][-1]["status"], "confirmed")
        empty = self.page(4, self.tip_hash)
        self.assert_error(self.verify([full, empty]), ERR_INTEGRITY)

    def test_pending_header_only_on_final_page_via_batch(self) -> None:
        # The full first page ends exactly at the global (pending) tip. On its
        # own it verifies, but with another page behind it the pending tip
        # header is no longer the final header of the batch: integrity.
        reaching_tip = self.page(0, self.genesis_hash)
        self.assertEqual(
            reaching_tip["headers"][-1]["status"], STATUS_PENDING
        )
        empty = self.page(4, self.tip_hash)
        self.assert_error(
            self.verify([reaching_tip, empty]), ERR_INTEGRITY
        )

    def test_pending_tip_split_legally_across_pages(self) -> None:
        # Control for the above: confirmed headers then the pending tip last.
        result = self.verify(self.pages([2, 2]))
        self.assertTrue(result["ok"], result)

    def test_tampered_header_hash_is_integrity(self) -> None:
        documents = self.pages([2, 2])
        documents[0]["headers"][0]["block_hash"] = "f" * 64
        self.re_sign(documents[0])
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_broken_prev_hash_link_across_pages(self) -> None:
        documents = self.pages([2, 2])
        # The first header of page 2 must point at page 1's last header.
        documents[1]["headers"][0]["prev_hash"] = "1" * 64
        self.re_sign(documents[1])
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_tip_must_be_field_for_field_identical_across_pages(self) -> None:
        # A per-page-legal but differing tip descriptor on the first page: it
        # ends before the declared tip, so the single-page verifier accepts
        # the bogus height/length; the batch must reject the disagreement.
        documents = self.pages([2, 2])
        documents[0]["tip"]["height"] = 5
        documents[0]["tip"]["length"] = 6
        documents[0]["tip"]["status"] = "confirmed"
        self.re_sign(documents[0])
        self.assert_error(self.verify(documents), ERR_INTEGRITY)

    def test_pinned_tip_hash_mismatch_is_integrity(self) -> None:
        documents = self.pages([2, 2])
        self.assert_error(
            self.verify(documents, tip_hash="a" * 64), ERR_INTEGRITY
        )

    def test_empty_last_page_whose_anchor_is_not_the_tip(self) -> None:
        empty = self.page(4, self.tip_hash)
        empty["anchor"] = {"height": 0, "block_hash": self.genesis_hash}
        self.re_sign(empty)
        self.assert_error(
            self.verify([empty], anchor=self.anchor), ERR_INTEGRITY
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
