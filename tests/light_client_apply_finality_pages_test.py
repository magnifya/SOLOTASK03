"""Tests for the paginated finality-history light-client consumer
``ledger.light_client.apply_finality_pages``.

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` and covers:

* the happy path: a multi-page and a single-page ``GET
  /v1/chain/finalities`` history apply atomically — the whole batch
  verifies before the version-3 checkpoint is rewritten once, the
  generation bumps by exactly one and the success key order is
  ``ok, generation, finalized, pages, applied``;
* the idempotent empty final page (the anchor already is the finalized
  head): the file bytes stay exactly as they were and the generation
  holds;
* failure categories: structure/key-order/type defects ``input``,
  unknown key versions or bad signatures ``auth``, pagination, branch,
  tip or boundary defects ``integrity``, a corrupt checkpoint ``state``
  and a missing file ``io``; failures never change the file bytes and
  nothing is raised.

Run: python3 tests/light_client_apply_finality_pages_test.py
"""
from __future__ import annotations

import copy
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


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class PagesFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "headers-checkpoint.json")
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
        # Checkpoint the chain to the pending tip via the header pages.
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
        with open(self.path, "rb") as fh:
            self.stored_bytes = fh.read()

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

    def file_bytes(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def assert_failed(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})
        self.assertEqual(self.file_bytes(), self.stored_bytes)


class PagesSuccessTests(PagesFixture):
    def test_multi_page_batch_advances_once(self) -> None:
        pages = self.paged(2)
        self.assertEqual(len(pages), 2)
        generation_before = json.loads(self.stored_bytes)["generation"]
        result = apply_finality_pages(self.path, pages, self.trust)
        self.assertEqual(
            list(result.keys()),
            ["ok", "generation", "finalized", "pages", "applied"],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], generation_before + 1)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["applied"], 3)
        stored = json.loads(self.file_bytes())
        self.assertEqual(stored["v"], 3)
        self.assertEqual(stored["generation"], generation_before + 1)
        self.assertEqual(stored["finalized"], self.loc(3))
        # The tip and anchor are untouched by the finality advance.
        self.assertEqual(stored["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(stored["anchor"], self.anchor)

    def test_single_page_batch(self) -> None:
        pages = self.paged(100)
        self.assertEqual(len(pages), 1)
        result = apply_finality_pages(self.path, pages, self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 3)

    def test_every_page_size(self) -> None:
        for limit in (1, 2, 3, 500):
            fresh = os.path.join(self.tmp, f"checkpoint-{limit}.json")
            shutil.copy(self.path, fresh)
            result = apply_finality_pages(fresh, self.paged(limit), self.trust)
            self.assertTrue(result["ok"], (limit, result))
            self.assertEqual(result["finalized"], self.loc(3))
            self.assertEqual(result["applied"], 3)

    def test_empty_final_page_is_idempotent(self) -> None:
        # Advance to the head first, then re-apply the empty page whose
        # anchor already is the finalized head.
        result = apply_finality_pages(self.path, self.paged(2), self.trust)
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        empty = self.finalities_page(3, self.h(3))
        self.assertEqual(empty["finalities"], [])
        self.assertIsNone(empty["next"])
        result = apply_finality_pages(self.path, [empty], self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["generation"], json.loads(after_advance)["generation"])
        self.assertEqual(self.file_bytes(), after_advance)

    def test_empty_page_before_any_advance(self) -> None:
        # A genuine empty page names the finalized head as its anchor;
        # while the stored boundary is still the genesis anchor that
        # page does not chain from the boundary.
        empty = self.finalities_page(3, self.h(3))
        self.assertEqual(empty["finalities"], [])
        self.assertIsNone(empty["next"])
        result = apply_finality_pages(self.path, [empty], self.trust)
        self.assert_failed(result, ERR_INTEGRITY)
        # An empty single page anchored at the stored boundary but whose
        # head is higher does not reach the head either.
        forged = copy.deepcopy(empty)
        forged["anchor"] = self.loc(0)
        result = apply_finality_pages(self.path, [forged], self.trust)
        self.assert_failed(result, ERR_INTEGRITY)


class PagesInputTests(PagesFixture):
    def test_argument_shape(self) -> None:
        pages = self.paged(2)
        for bad_path in (None, "", 0, 1.5, [], {}):
            self.assert_failed(
                apply_finality_pages(bad_path, pages, self.trust), ERR_INPUT
            )
        for bad_pages in (None, {}, "x", 0, []):
            self.assert_failed(
                apply_finality_pages(self.path, bad_pages, self.trust), ERR_INPUT
            )

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
        bad_anchor2 = copy.deepcopy(good)
        bad_anchor2[0]["anchor"] = {"height": -1, "block_hash": self.h(0)}
        cases.append(bad_anchor2)
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
        # head shape defects.
        bad_head = copy.deepcopy(good)
        bad_head[0]["head"] = {"finalized": self.loc(3)}
        cases.append(bad_head)
        for case in cases:
            self.assert_failed(
                apply_finality_pages(self.path, case, self.trust), ERR_INPUT
            )

    def test_trust_shape(self) -> None:
        pages = self.paged(2)
        for bad_trust in (None, {}, {"audit_signers": []}, {"audit_signers": [{}]}):
            self.assert_failed(
                apply_finality_pages(self.path, pages, bad_trust), ERR_INPUT
            )


class PagesAuthTests(PagesFixture):
    def test_unknown_key_version(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["finalities"][0]["auth"]["key_version"] = 99
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_AUTH
        )

    def test_bad_item_signature(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["finalities"][0]["auth"]["signature"] = "00" * 64
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_AUTH
        )

    def test_bad_head_signature(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["head"]["auth"]["signature"] = "00" * 64
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_AUTH
        )

    def test_tampered_signed_content(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["finalities"][1]["finalized"]["block_hash"] = "0" * 64
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_AUTH
        )


class PagesIntegrityTests(PagesFixture):
    def test_first_anchor_must_be_stored_boundary(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["anchor"] = self.loc(1)
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_later_anchor_must_chain(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["anchor"] = self.loc(1)
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

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
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_non_last_page_must_be_non_empty_with_matching_next(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[0]["next"] = self.loc(1)
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )
        pages = copy.deepcopy(self.paged(2))
        pages[0]["next"] = None
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )
        pages = copy.deepcopy(self.paged(2))
        pages[0]["finalities"] = []
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_last_page_must_close(self) -> None:
        pages = copy.deepcopy(self.paged(2))
        pages[1]["next"] = self.loc(3)
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )
        # A multi-page batch may not end on an empty page.
        pages = copy.deepcopy(self.paged(2))
        pages[1]["finalities"] = []
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )
        # The last page must reach head.finalized.
        pages = copy.deepcopy(self.paged(1))
        pages[1]["finalities"] = pages[1]["finalities"][:1]
        pages[1]["next"] = None
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_credentials_must_be_consecutive(self) -> None:
        pages = copy.deepcopy(self.paged(1))
        # Drop the middle credential of the second page: heights skip.
        del pages[1]["finalities"][0]
        pages[0]["next"] = self.loc(1)
        pages[1]["anchor"] = self.loc(1)
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_branch_mismatch(self) -> None:
        # A credential naming a hash that is not the branch's block.
        pages = self.paged(1)
        forged = copy.deepcopy(pages[0]["finalities"][0])
        forged["finalized"] = {"height": 1, "block_hash": "0" * 64}
        forged["tip"] = {
            "tip_hash": "0" * 64,
            "height": 1,
            "length": 2,
            "status": "confirmed",
        }
        signer = self.service.store.audit_signer
        forged["auth"] = sign_finality(
            signer["private_key"],
            signer["version"],
            forged["finalized"],
            forged["tip"],
        )
        pages[0]["finalities"][0] = forged
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_tip_descriptor_mismatch(self) -> None:
        # A genuine credential whose tip descriptor is replaced by a
        # signed but wrong S (length/status/height off).
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
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_head_tip_must_equal_local_tip(self) -> None:
        pages = self.paged(1)
        head = {
            "finalized": self.loc(3),
            "tip": {
                "tip_hash": self.tip_hash,
                "height": 4,
                "length": 5,
                "status": "confirmed",
            },
        }
        signer = self.service.store.audit_signer
        head["auth"] = sign_finality(
            signer["private_key"], signer["version"], head["finalized"], head["tip"]
        )
        for page in pages:
            page["head"] = copy.deepcopy(head)
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )

    def test_pending_target_rejected(self) -> None:
        # Confirm nothing new: a credential finalizing the pending tip
        # (height 4) names a non-confirmed branch block.
        pages = self.paged(1)
        item = {
            "finalized": self.loc(4),
            "tip": {
                "tip_hash": self.h(4),
                "height": 4,
                "length": 5,
                "status": "pending",
            },
        }
        signer = self.service.store.audit_signer
        item["auth"] = sign_finality(
            signer["private_key"], signer["version"], item["finalized"], item["tip"]
        )
        head = {
            "finalized": self.loc(4),
            "tip": {
                "tip_hash": self.tip_hash,
                "height": 4,
                "length": 5,
                "status": "pending",
            },
        }
        head["auth"] = sign_finality(
            signer["private_key"], signer["version"], head["finalized"], head["tip"]
        )
        pages[0]["finalities"].append(item)
        pages[0]["head"] = head
        self.assert_failed(
            apply_finality_pages(self.path, pages, self.trust), ERR_INTEGRITY
        )


class PagesStateIoTests(PagesFixture):
    def test_missing_file_is_io(self) -> None:
        missing = os.path.join(self.tmp, "missing.json")
        result = apply_finality_pages(missing, self.paged(1), self.trust)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_checkpoint_is_state(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        stored["finalized"] = self.loc(1)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(stored, fh)
        result = apply_finality_pages(self.path, self.paged(1), self.trust)
        self.assertEqual(result, {"ok": False, "error": ERR_STATE})

    def test_unparseable_checkpoint_is_state(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        result = apply_finality_pages(self.path, self.paged(1), self.trust)
        self.assertEqual(result, {"ok": False, "error": ERR_STATE})

    def test_unwritable_file_is_io_and_restored(self) -> None:
        directory = os.path.join(self.tmp, "nowhere")
        path = os.path.join(directory, "checkpoint.json")
        # A missing parent directory makes the load report io.
        result = apply_finality_pages(path, self.paged(1), self.trust)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        # A directory as the checkpoint path is an io failure too.
        result = apply_finality_pages(self.tmp, self.paged(1), self.trust)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})


if __name__ == "__main__":
    unittest.main()
