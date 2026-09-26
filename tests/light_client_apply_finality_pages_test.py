"""Tests for the atomic paged finality-history application
``ledger.light_client.apply_finality_pages``.

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` and covers:

* success: a multi-page ``GET /v1/chain/finalities`` history applies
  atomically — one generation bump, a version-3 rewrite to
  ``head.finalized`` and the success key order
  ``ok, generation, finalized, pages, applied`` (``pages`` the page
  count, ``applied`` the credential count); a single page covering the
  whole history behaves the same; the single empty page whose anchor
  already is the head is idempotent with byte-identical files;
* failure categories: page structure/key-order/type defects ``input``,
  an unknown key version or a bad signature (in a page item or a head)
  ``auth``, pagination/branch/tip/boundary defects ``integrity`` (heads
  differ, head tip is not the local tip, first anchor is not the stored
  boundary, broken anchor/next chaining, an empty non-final page, a
  non-null final ``next``, a final page that does not reach the head, an
  empty page that is not the single anchor-is-head page, non-consecutive
  or non-confirmed or fork credentials, a credential tip that is not the
  block's descriptor S), a corrupt stored checkpoint ``state`` and a
  missing or unwritable file ``io``; failures never change the file
  bytes and nothing is raised.

The sibling ``apply_finality``/``apply_finalities`` batch surfaces are
covered by tests/light_client_apply_finality_test.py and stay unchanged.

Run: python3 tests/light_client_apply_finality_pages_test.py
"""
from __future__ import annotations

import copy
import hashlib
import json
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
    ERR_IO,
    ERR_STATE,
    advance_headers,
    apply_finality_pages,
    sign_finality,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

CHECKPOINT_KEYS = [
    "v",
    "generation",
    "anchor",
    "tip",
    "finalized",
    "steps",
    "hash",
]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class FinalityPagesFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "headers-checkpoint.json")
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

    def header_page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def finalities_page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_finalities(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit: int, start: int = 0) -> list:
        """Every finalities page from ``start`` in ``limit``-sized steps."""
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

    def checkpoint_to_pending_tip(self) -> None:
        """Advance once: a checkpoint at pending tip height 4, generation 1,
        with the finalized boundary at the genesis anchor."""
        documents = []
        anchor = self.anchor
        while True:
            page = self.header_page(anchor["height"], anchor["block_hash"], 2)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == self.tip_hash:
                break
        result = advance_headers(
            self.path, documents, self.anchor, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)

    def apply(self, pages, trust=None):
        return apply_finality_pages(
            self.path, pages, self.trust if trust is None else trust
        )

    def re_sign(self, credential: dict, version: int | None = None) -> dict:
        """Re-sign a tampered credential with the current audit signer so the
        signature stays valid and only integrity is at stake."""
        signer = self.store.audit_signer
        envelope = sign_finality(
            signer["private_key"],
            signer["version"] if version is None else version,
            credential["finalized"],
            credential["tip"],
        )
        self.assertIsNotNone(envelope)
        credential["auth"] = envelope
        return credential

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def read_checkpoint(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def write_file(self, data) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            if isinstance(data, str):
                fh.write(data)
            else:
                json.dump(data, fh)

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class ApplyFinalityPagesSuccessTests(FinalityPagesFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_multi_page_batch_applies_atomically(self) -> None:
        pages = self.paged(1)
        self.assertEqual(len(pages), 3)
        before = self.read_raw()
        result = self.apply(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result.keys()),
            ["ok", "generation", "finalized", "pages", "applied"],
        )
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(list(result["finalized"].keys()), ["height", "block_hash"])
        self.assertEqual(result["pages"], 3)
        self.assertEqual(result["applied"], 3)
        # One atomic version-3 rewrite: the generation moved exactly once.
        raw = self.read_raw()
        self.assertNotEqual(raw, before)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        data = json.loads(raw)
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 2)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["finalized"], self.loc(3))
        self.assertEqual(data["tip"]["tip_hash"], self.tip_hash)
        body = {key: value for key, value in data.items() if key != "hash"}
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)

    def test_single_page_covering_the_whole_history(self) -> None:
        pages = self.paged(100)
        self.assertEqual(len(pages), 1)
        result = self.apply(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 3)

    def test_two_page_split(self) -> None:
        pages = self.paged(2)
        self.assertEqual(len(pages), 2)
        result = self.apply(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["applied"], 3)
        self.assertEqual(result["finalized"], self.loc(3))

    def test_empty_anchor_is_head_page_is_idempotent(self) -> None:
        result = self.apply(self.paged(1))
        self.assertEqual(result["generation"], 2)
        before = self.read_raw()
        # The endpoint yields an empty page with a null next at the head.
        empty = self.finalities_page(3, self.h(3))
        self.assertEqual(empty["finalities"], [])
        self.assertIsNone(empty["next"])
        repeat = self.apply([empty])
        self.assertTrue(repeat["ok"], repeat)
        self.assertEqual(repeat["generation"], 2)
        self.assertEqual(repeat["finalized"], self.loc(3))
        self.assertEqual(repeat["pages"], 1)
        self.assertEqual(repeat["applied"], 0)
        self.assertEqual(self.read_raw(), before)

    def test_failed_then_successful_apply_lands_one_generation_up(self) -> None:
        pages = self.paged(1)
        broken = copy.deepcopy(pages)
        del broken[1]  # broken pagination: page 2 anchors at page 0's next
        self.assert_error(self.apply(broken), ERR_INTEGRITY)
        result = self.apply(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)


class ApplyFinalityPagesInputTests(FinalityPagesFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_path_must_be_a_non_empty_string(self) -> None:
        pages = self.paged(1)
        for bad_path in ("", None, 7, object()):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    apply_finality_pages(bad_path, pages, self.trust), ERR_INPUT
                )

    def test_pages_must_be_a_non_empty_list(self) -> None:
        for bad_pages in (None, 7, "x", {}, [], object()):
            with self.subTest(bad_pages=bad_pages):
                self.assert_error(self.apply(bad_pages), ERR_INPUT)

    def test_page_must_be_an_object_with_exact_key_order(self) -> None:
        genuine = self.paged(1)
        for bad_page in (None, 7, "x", []):
            self.assert_error(self.apply([bad_page]), ERR_INPUT)
        reordered = {
            "finalities": [],
            "anchor": self.loc(0),
            "next": None,
            "head": genuine[0]["head"],
        }
        self.assert_error(self.apply([reordered]), ERR_INPUT)
        extra = dict(genuine[0])
        extra["extra"] = 1
        self.assert_error(self.apply([extra]), ERR_INPUT)
        missing = dict(genuine[0])
        del missing["head"]
        self.assert_error(self.apply([missing]), ERR_INPUT)

    def test_anchor_and_next_shape(self) -> None:
        genuine = self.paged(1)
        bad_anchor = copy.deepcopy(genuine)
        bad_anchor[0]["anchor"] = {"block_hash": self.h(0), "height": 0}
        self.assert_error(self.apply(bad_anchor), ERR_INPUT)
        bad_anchor = copy.deepcopy(genuine)
        bad_anchor[0]["anchor"] = {"height": True, "block_hash": self.h(0)}
        self.assert_error(self.apply(bad_anchor), ERR_INPUT)
        # next must be null or a closed anchor.
        for bad_next in (7, "x", {"height": 1}, {"height": 1, "block_hash": "zz"}):
            tampered = copy.deepcopy(genuine)
            tampered[0]["next"] = bad_next
            self.assert_error(self.apply(tampered), ERR_INPUT)

    def test_finalities_must_be_a_list_of_credentials(self) -> None:
        genuine = self.paged(1)
        tampered = copy.deepcopy(genuine)
        tampered[0]["finalities"] = {"finalized": None}
        self.assert_error(self.apply(tampered), ERR_INPUT)
        tampered = copy.deepcopy(genuine)
        tampered[0]["finalities"] = [None]
        self.assert_error(self.apply(tampered), ERR_INPUT)
        tampered = copy.deepcopy(genuine)
        item = tampered[0]["finalities"][0]
        item["tip"] = {
            "height": item["tip"]["height"],
            "tip_hash": item["tip"]["tip_hash"],
            "length": item["tip"]["length"],
            "status": item["tip"]["status"],
        }
        self.assert_error(self.apply(tampered), ERR_INPUT)
        tampered = copy.deepcopy(genuine)
        tampered[0]["finalities"][0]["auth"] = {
            "key_version": "1",
            "signature": "a" * 128,
        }
        self.assert_error(self.apply(tampered), ERR_INPUT)

    def test_head_must_be_a_finality_credential(self) -> None:
        genuine = self.paged(1)
        for bad_head in (None, [], {"finalized": None, "tip": None}):
            tampered = copy.deepcopy(genuine)
            for page in tampered:
                page["head"] = bad_head
            self.assert_error(self.apply(tampered), ERR_INPUT)

    def test_trust_must_carry_audit_signers(self) -> None:
        pages = self.paged(1)
        for bad_trust in (None, 7, [], {}, {"audit_signers": []}):
            with self.subTest(bad_trust=bad_trust):
                self.assert_error(
                    apply_finality_pages(self.path, pages, bad_trust), ERR_INPUT
                )

    def test_never_raises_on_garbage(self) -> None:
        self.assert_error(
            apply_finality_pages(object(), object(), object()), ERR_INPUT
        )
        self.assert_error(self.apply([object()]), ERR_INPUT)


class ApplyFinalityPagesAuthTests(FinalityPagesFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_unknown_key_version_in_item_is_auth(self) -> None:
        pages = self.paged(1)
        pages[1]["finalities"][0]["auth"]["key_version"] = 99
        before = self.read_raw()
        self.assert_error(self.apply(pages), ERR_AUTH)
        self.assertEqual(self.read_raw(), before)

    def test_bad_signature_in_item_is_auth(self) -> None:
        pages = self.paged(1)
        signature = pages[0]["finalities"][0]["auth"]["signature"]
        pages[0]["finalities"][0]["auth"]["signature"] = (
            "0" if signature[0] != "0" else "1"
        ) + signature[1:]
        self.assert_error(self.apply(pages), ERR_AUTH)

    def test_bad_signature_in_head_is_auth(self) -> None:
        pages = self.paged(1)
        signature = pages[2]["head"]["auth"]["signature"]
        pages[2]["head"]["auth"]["signature"] = (
            "0" if signature[0] != "0" else "1"
        ) + signature[1:]
        self.assert_error(self.apply(pages), ERR_AUTH)

    def test_unknown_key_version_in_head_is_auth(self) -> None:
        pages = self.paged(1)
        for page in pages:
            page["head"]["auth"]["key_version"] = 99
        self.assert_error(self.apply(pages), ERR_AUTH)

    def test_signature_over_modified_body_is_auth(self) -> None:
        pages = self.paged(1)
        pages[0]["finalities"][0]["finalized"] = self.loc(2)
        # Re-signing is deliberately omitted: the stale signature fails.
        self.assert_error(self.apply(pages), ERR_AUTH)


class ApplyFinalityPagesIntegrityTests(FinalityPagesFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def assert_integrity_leaves_bytes(self, pages) -> None:
        before = self.read_raw()
        self.assert_error(self.apply(pages), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_heads_must_be_identical_across_pages(self) -> None:
        pages = self.paged(1)
        different = copy.deepcopy(pages[1]["head"])
        different["tip"] = dict(different["tip"], length=99)
        pages[1]["head"] = self.re_sign(different)
        self.assert_integrity_leaves_bytes(pages)

    def test_head_tip_must_equal_local_tip(self) -> None:
        pages = self.paged(1)
        for page in pages:
            head = copy.deepcopy(page["head"])
            head["tip"] = dict(head["tip"], status="confirmed")
            page["head"] = self.re_sign(head)
        self.assert_integrity_leaves_bytes(pages)

    def test_first_anchor_must_equal_stored_boundary(self) -> None:
        # Pages fetched from height 1: the stored boundary is the genesis.
        pages = self.paged(1, start=1)
        self.assert_integrity_leaves_bytes(pages)

    def test_later_anchor_must_equal_previous_next(self) -> None:
        pages = self.paged(1)
        del pages[1]  # page 2 no longer anchors at page 0's next
        self.assert_integrity_leaves_bytes(pages)
        pages = self.paged(1)
        pages[0], pages[1] = pages[1], pages[0]
        self.assert_integrity_leaves_bytes(pages)

    def test_non_final_page_must_be_non_empty(self) -> None:
        pages = self.paged(1)
        pages[0]["finalities"] = []
        self.assert_integrity_leaves_bytes(pages)

    def test_non_final_next_must_name_last_finalized(self) -> None:
        pages = self.paged(1)
        pages[0]["next"] = self.loc(2)  # the page's last finalized is 1
        self.assert_integrity_leaves_bytes(pages)

    def test_final_page_next_must_be_null(self) -> None:
        pages = self.paged(1)
        pages[-1]["next"] = self.loc(3)
        self.assert_integrity_leaves_bytes(pages)

    def test_final_page_must_reach_the_head(self) -> None:
        pages = self.paged(1)
        pages[-1]["finalities"] = []  # empty, but not a single page
        self.assert_integrity_leaves_bytes(pages)
        # A final page whose last credential stops below the head.
        pages = self.paged(100)
        self.assertEqual(len(pages), 1)
        pages[0]["finalities"] = pages[0]["finalities"][:2]
        # ... with a null next already; the last finalized is now height 2.
        self.assert_integrity_leaves_bytes(pages)

    def test_empty_page_only_single_and_only_at_the_head(self) -> None:
        # A single empty page whose anchor is not the head boundary.
        empty = self.finalities_page(3, self.h(3))
        misplaced = copy.deepcopy(empty)
        misplaced["anchor"] = self.loc(0)
        self.assert_integrity_leaves_bytes([misplaced])
        # An empty page trailing a non-empty history is a second page.
        pages = self.paged(1)
        self.assert_integrity_leaves_bytes(pages + [empty])

    def test_credentials_must_be_consecutive(self) -> None:
        pages = self.paged(100)
        self.assertEqual(len(pages), 1)
        del pages[0]["finalities"][1]  # heights 1, 3: a gap
        self.assert_integrity_leaves_bytes(pages)
        pages = self.paged(100)
        items = pages[0]["finalities"]
        items[0], items[1] = items[1], items[0]
        self.assert_integrity_leaves_bytes(pages)

    def test_credential_must_match_the_confirmed_branch(self) -> None:
        pages = self.paged(1)
        item = copy.deepcopy(pages[0]["finalities"][0])
        item["finalized"] = self.loc(1, "f" * 64)
        item["tip"] = {
            "tip_hash": "f" * 64,
            "height": 1,
            "length": 2,
            "status": "confirmed",
        }
        pages[0]["finalities"][0] = self.re_sign(item)
        self.assert_integrity_leaves_bytes(pages)

    def test_pending_tip_cannot_be_finalized(self) -> None:
        pages = self.paged(1)
        item = copy.deepcopy(pages[-1]["finalities"][0])
        item["finalized"] = {"height": 4, "block_hash": self.tip_hash}
        item["tip"] = {
            "tip_hash": self.tip_hash,
            "height": 4,
            "length": 5,
            "status": "pending",
        }
        pages[-1]["finalities"].append(self.re_sign(item))
        self.assert_integrity_leaves_bytes(pages)

    def test_credential_tip_must_be_the_blocks_descriptor(self) -> None:
        pages = self.paged(1)
        item = copy.deepcopy(pages[0]["finalities"][0])
        item["tip"] = dict(item["tip"], length=99)
        pages[0]["finalities"][0] = self.re_sign(item)
        self.assert_integrity_leaves_bytes(pages)
        pages = self.paged(1)
        item = copy.deepcopy(pages[0]["finalities"][0])
        item["tip"] = dict(item["tip"], status="pending")
        pages[0]["finalities"][0] = self.re_sign(item)
        self.assert_integrity_leaves_bytes(pages)

    def test_head_finalized_beyond_branch_is_integrity(self) -> None:
        pages = self.paged(1)
        for page in pages:
            head = copy.deepcopy(page["head"])
            head["finalized"] = {"height": 4, "block_hash": self.tip_hash}
            page["head"] = self.re_sign(head)
        # The final page's last credential no longer reaches the head.
        self.assert_integrity_leaves_bytes(pages)


class ApplyFinalityPagesStateTests(FinalityPagesFixture):
    def setUp(self) -> None:
        super().setUp()
        self.checkpoint_to_pending_tip()

    def test_corrupt_json_is_state(self) -> None:
        self.write_file("{not json")
        self.assert_error(self.apply(self.paged(1)), ERR_STATE)

    def test_tampered_hash_is_state(self) -> None:
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        self.write_file(data)
        self.assert_error(self.apply(self.paged(1)), ERR_STATE)

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        payload = json.dumps(data)
        self.write_file(payload)
        self.assert_error(self.apply(self.paged(1)), ERR_STATE)
        self.assertEqual(self.read_raw().decode("utf-8"), payload)

    def test_corrupt_state_wins_over_auth_and_integrity(self) -> None:
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        self.write_file(data)
        forged = self.paged(1)
        forged[0]["finalities"][0]["auth"]["key_version"] = 99
        self.assert_error(self.apply(forged), ERR_STATE)
        broken = self.paged(1)
        del broken[1]
        self.assert_error(self.apply(broken), ERR_STATE)


class ApplyFinalityPagesIoTests(FinalityPagesFixture):
    def test_missing_file_is_io(self) -> None:
        self.assert_error(self.apply(self.paged(1)), ERR_IO)

    def test_missing_file_wins_over_auth(self) -> None:
        forged = self.paged(1)
        forged[0]["finalities"][0]["auth"]["key_version"] = 99
        self.assert_error(self.apply(forged), ERR_IO)

    def test_unwritable_target_path_is_io(self) -> None:
        self.checkpoint_to_pending_tip()
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        self.assert_error(
            apply_finality_pages(directory, self.paged(1), self.trust), ERR_IO
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
