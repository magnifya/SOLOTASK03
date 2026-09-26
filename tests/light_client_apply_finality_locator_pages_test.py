"""Tests for the locator-driven paginated finality-history consumer
``ledger.light_client.apply_finality_locator_pages``.

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` and covers:

* the happy path: multi-page and single-page ``POST
  /v1/chain/finalities/locate`` histories (the first page anchored at a
  locator matched after an in-order fork miss) apply atomically — the
  whole batch verifies before the version-3 checkpoint is rewritten
  once, the generation bumps by exactly one and the success key order is
  ``ok, generation, finalized, matched_index, pages, applied`` with
  ``matched_index`` the 0-based locator position;
* the idempotent empty final page and a replayed history ending at the
  stored boundary (the file bytes stay exactly as they were and the
  generation holds), plus the empty page at a higher confirmed anchor
  advancing the boundary once;
* failure categories: structure/key-order/type (including a malformed
  ``locators`` list) defects ``input``, unknown key versions or bad
  signatures ``auth``, pagination, matched anchor, branch, tip or
  boundary defects ``integrity``, a corrupt checkpoint ``state`` and a
  missing file ``io``; failures never change the file bytes and nothing
  is raised.

Run: python3 tests/light_client_apply_finality_locator_pages_test.py
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
    apply_finality_locator_pages,
    sign_finality,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class LocatorPagesFixture(unittest.TestCase):
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

    def loc(self, height: int, block_hash: str | None = None) -> dict:
        return {"height": height, "block_hash": self.h(height) if block_hash is None else block_hash}

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

    def located_pages(self, locators: list, limit: int = 1) -> list:
        """The locate first page, then GET-continued pages to the head."""
        status, body = self.service.locate_finality_fork(
            {"locators": locators, "limit": limit}
        )
        self.assertEqual(status, 200, body)
        pages = [body]
        anchor = body["next"]
        while anchor is not None:
            body = self.finalities_page(
                anchor["height"], anchor["block_hash"], limit
            )
            pages.append(body)
            anchor = body["next"]
        return pages

    def default_locators(self) -> list:
        # A fork miss at height 3, the first confirmed hit at height 1,
        # then the genesis point; strictly descending heights.
        return [
            {"height": 3, "block_hash": "f" * 64},
            self.loc(1),
            self.loc(0),
        ]

    def file_bytes(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def assert_failed(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})
        self.assertEqual(self.file_bytes(), self.stored_bytes)


SUCCESS_KEYS = ["ok", "generation", "finalized", "matched_index", "pages", "applied"]


class LocatorPagesSuccessTests(LocatorPagesFixture):
    def test_multi_page_batch_advances_once(self) -> None:
        locators = self.default_locators()
        pages = self.located_pages(locators, 1)
        self.assertEqual(len(pages), 2)
        generation_before = json.loads(self.stored_bytes)["generation"]
        result = apply_finality_locator_pages(
            self.path, pages, locators, self.tip_hash, self.trust
        )
        self.assertEqual(list(result.keys()), SUCCESS_KEYS)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], generation_before + 1)
        self.assertEqual(result["finalized"], self.loc(3))
        # The first in-order confirmed main-chain hit is at index 1.
        self.assertEqual(result["matched_index"], 1)
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["applied"], 2)
        stored = json.loads(self.file_bytes())
        self.assertEqual(stored["v"], 3)
        self.assertEqual(stored["generation"], generation_before + 1)
        self.assertEqual(stored["finalized"], self.loc(3))
        # The tip and anchor are untouched by the finality advance.
        self.assertEqual(stored["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(stored["anchor"], self.anchor)

    def test_single_page_batch(self) -> None:
        # A fork miss at height 2, then the confirmed genesis hit: the
        # 100-row page from genesis carries every credential in one page.
        locators = [self.loc(2, "e" * 64), self.loc(0)]
        pages = self.located_pages(locators, 100)
        self.assertEqual(len(pages), 1)
        result = apply_finality_locator_pages(
            self.path, pages, locators, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["matched_index"], 1)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 3)

    def test_every_page_size(self) -> None:
        locators = self.default_locators()
        for limit in (1, 2, 3, 500):
            fresh = os.path.join(self.tmp, f"checkpoint-{limit}.json")
            shutil.copy(self.path, fresh)
            result = apply_finality_locator_pages(
                fresh, self.located_pages(locators, limit), locators,
                self.tip_hash, self.trust,
            )
            self.assertTrue(result["ok"], (limit, result))
            self.assertEqual(result["finalized"], self.loc(3))
            self.assertEqual(result["matched_index"], 1)
            self.assertEqual(result["applied"], 3 - 1)

    def test_empty_page_at_higher_anchor_advances(self) -> None:
        # An empty single page names the finalized head (height 3) as its
        # anchor; while the stored boundary is still genesis that end
        # target legitimately raises the boundary once.
        empty = self.finalities_page(3, self.h(3))
        self.assertEqual(empty["finalities"], [])
        self.assertIsNone(empty["next"])
        generation_before = json.loads(self.stored_bytes)["generation"]
        result = apply_finality_locator_pages(
            self.path, [empty], [self.loc(3)], self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["generation"], generation_before + 1)

    def test_empty_final_page_is_idempotent(self) -> None:
        locators = self.default_locators()
        result = apply_finality_locator_pages(
            self.path, self.located_pages(locators, 2), locators,
            self.tip_hash, self.trust,
        )
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        empty = self.finalities_page(3, self.h(3))
        result = apply_finality_locator_pages(
            self.path, [empty], [self.loc(3)], self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["generation"], json.loads(after_advance)["generation"])
        self.assertEqual(self.file_bytes(), after_advance)

    def test_replayed_history_ending_at_boundary_is_idempotent(self) -> None:
        locators = self.default_locators()
        result = apply_finality_locator_pages(
            self.path, self.located_pages(locators, 1), locators,
            self.tip_hash, self.trust,
        )
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        # Re-anchoring at height 1 replays credentials 2 and 3 up to the
        # already-stored boundary: idempotent, bytes and generation hold.
        result = apply_finality_locator_pages(
            self.path, self.located_pages(locators, 1), locators,
            self.tip_hash, self.trust,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["matched_index"], 1)
        self.assertEqual(result["applied"], 2)
        self.assertEqual(result["generation"], json.loads(after_advance)["generation"])
        self.assertEqual(self.file_bytes(), after_advance)


class LocatorPagesInputTests(LocatorPagesFixture):
    def test_argument_shape(self) -> None:
        pages = self.located_pages(self.default_locators(), 2)
        locators = self.default_locators()
        for bad_path in (None, "", 0, 1.5, [], {}):
            self.assert_failed(
                apply_finality_locator_pages(
                    bad_path, pages, locators, self.tip_hash, self.trust
                ),
                ERR_INPUT,
            )
        for bad_pages in (None, {}, "x", 0, []):
            self.assert_failed(
                apply_finality_locator_pages(
                    self.path, bad_pages, locators, self.tip_hash, self.trust
                ),
                ERR_INPUT,
            )
        for bad_tip in (None, "", 0, "AB" * 32, "g" * 64, "a" * 63):
            self.assert_failed(
                apply_finality_locator_pages(
                    self.path, pages, locators, bad_tip, self.trust
                ),
                ERR_INPUT,
            )

    def test_locator_shape(self) -> None:
        pages = self.located_pages(self.default_locators(), 2)
        good = self.default_locators()
        bad_locators = (
            None,
            [],
            {},
            "x",
            [self.loc(0)] * 65,
            [{"block_hash": self.h(0), "height": 0}],
            [{"height": "0", "block_hash": self.h(0)}],
            [{"height": -1, "block_hash": self.h(0)}],
            [{"height": True, "block_hash": self.h(0)}],
            [{"height": 0, "block_hash": "z" * 64}],
            # Heights must be strictly descending.
            [self.loc(1), self.loc(1)],
            [self.loc(0), self.loc(1)],
            # A genuine batch against a malformed list.
            good + [{"height": 1.5, "block_hash": self.h(1)}],
        )
        for candidate in bad_locators:
            self.assert_failed(
                apply_finality_locator_pages(
                    self.path, pages, candidate, self.tip_hash, self.trust
                ),
                ERR_INPUT,
            )

    def test_page_structure(self) -> None:
        pages = self.located_pages(self.default_locators(), 2)
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
        bad_anchor[0]["anchor"] = {"block_hash": self.h(1), "height": 1}
        cases.append(bad_anchor)
        bad_next = copy.deepcopy(good)
        bad_next[0]["next"] = 0
        cases.append(bad_next)
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
        # head shape defects.
        bad_head = copy.deepcopy(good)
        bad_head[0]["head"] = {"finalized": self.loc(3)}
        cases.append(bad_head)
        for case in cases:
            self.assert_failed(
                apply_finality_locator_pages(
                    self.path, case, self.default_locators(),
                    self.tip_hash, self.trust,
                ),
                ERR_INPUT,
            )

    def test_trust_shape(self) -> None:
        pages = self.located_pages(self.default_locators(), 2)
        for bad_trust in (None, {}, {"audit_signers": []}, {"audit_signers": [{}]}):
            self.assert_failed(
                apply_finality_locator_pages(
                    self.path, pages, self.default_locators(),
                    self.tip_hash, bad_trust,
                ),
                ERR_INPUT,
            )


class LocatorPagesAuthTests(LocatorPagesFixture):
    def test_unknown_key_version(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        pages[0]["finalities"][0]["auth"]["key_version"] = 99
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_AUTH,
        )

    def test_bad_item_signature(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        pages[1]["finalities"][0]["auth"]["signature"] = "00" * 64
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_AUTH,
        )

    def test_bad_head_signature(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        pages[1]["head"]["auth"]["signature"] = "00" * 64
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_AUTH,
        )

    def test_tampered_signed_content(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        pages[0]["finalities"][0]["finalized"]["block_hash"] = "0" * 64
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_AUTH,
        )


class LocatorPagesIntegrityTests(LocatorPagesFixture):
    def test_first_anchor_absent_from_locators(self) -> None:
        pages = self.located_pages(self.default_locators(), 2)
        # The batch anchors at height 1; offer only other chain points.
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, [self.loc(2), self.loc(0)],
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_matched_anchor_must_be_confirmed(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        # A locator matching the pending tip (height 4) never anchors.
        pages[0]["anchor"] = self.loc(4)
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, [self.loc(4)], self.tip_hash, self.trust
            ),
            ERR_INTEGRITY,
        )

    def test_matched_anchor_must_name_branch_hash(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        pages[0]["anchor"] = self.loc(1, "e" * 64)
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, [self.loc(1, "e" * 64)],
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_head_tip_hash_pin_mismatch(self) -> None:
        pages = self.located_pages(self.default_locators(), 2)
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                "0" * 64, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_heads_must_be_identical(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
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
                self.trust["audit_signers"][-1]["version"],
                head["finalized"],
                head["tip"],
            ),
        }
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_non_last_page_must_be_non_empty_with_matching_next(self) -> None:
        for mutate in ("wrong_next", "null_next", "empty_items"):
            pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
            if mutate == "wrong_next":
                # The one-item page genuinely closes its next at height 2.
                pages[0]["next"] = self.loc(3)
            elif mutate == "null_next":
                pages[0]["next"] = None
            else:
                pages[0]["finalities"] = []
            self.assert_failed(
                apply_finality_locator_pages(
                    self.path, pages, self.default_locators(),
                    self.tip_hash, self.trust,
                ),
                ERR_INTEGRITY,
            )

    def test_last_page_must_close(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        pages[1]["next"] = self.loc(3)
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )
        # The last page must reach head.finalized.
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        pages[1]["finalities"] = pages[1]["finalities"][:0]
        pages[1]["next"] = None
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_credentials_must_be_consecutive(self) -> None:
        pages = copy.deepcopy(self.located_pages(self.default_locators(), 1))
        # Drop the only credential of the second page: heights skip.
        pages[1]["finalities"] = []
        pages[1]["next"] = None
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_branch_mismatch(self) -> None:
        pages = self.located_pages(self.default_locators(), 100)
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
            signer["private_key"], signer["version"],
            forged["finalized"], forged["tip"],
        )
        pages[0]["finalities"][0] = forged
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_tip_descriptor_mismatch(self) -> None:
        pages = self.located_pages(self.default_locators(), 100)
        item = copy.deepcopy(pages[0]["finalities"][0])
        item["tip"] = {
            "tip_hash": self.h(1),
            "height": 1,
            "length": 5,
            "status": "confirmed",
        }
        signer = self.service.store.audit_signer
        item["auth"] = sign_finality(
            signer["private_key"], signer["version"],
            item["finalized"], item["tip"],
        )
        pages[0]["finalities"][0] = item
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_head_tip_must_equal_local_tip(self) -> None:
        pages = self.located_pages(self.default_locators(), 100)
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
            signer["private_key"], signer["version"],
            head["finalized"], head["tip"],
        )
        for page in pages:
            page["head"] = copy.deepcopy(head)
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_pending_target_rejected(self) -> None:
        pages = self.located_pages(self.default_locators(), 100)
        signer = self.service.store.audit_signer
        item = {
            "finalized": self.loc(4),
            "tip": {
                "tip_hash": self.h(4),
                "height": 4,
                "length": 5,
                "status": "pending",
            },
        }
        item["auth"] = sign_finality(
            signer["private_key"], signer["version"],
            item["finalized"], item["tip"],
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
            signer["private_key"], signer["version"],
            head["finalized"], head["tip"],
        )
        pages[0]["finalities"].append(item)
        pages[0]["head"] = head
        self.assert_failed(
            apply_finality_locator_pages(
                self.path, pages, self.default_locators(),
                self.tip_hash, self.trust,
            ),
            ERR_INTEGRITY,
        )

    def test_end_target_must_not_regress_boundary(self) -> None:
        locators = self.default_locators()
        result = apply_finality_locator_pages(
            self.path, self.located_pages(locators, 1), locators,
            self.tip_hash, self.trust,
        )
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        # A signed head ending below the stored boundary is rejected.
        pages = copy.deepcopy(self.located_pages(locators, 100))
        page = pages[0]
        page["finalities"] = [
            it for it in page["finalities"]
            if it["finalized"]["height"] == 2
        ]
        page["next"] = None
        local_tip = json.loads(after_advance)["tip"]
        signer = self.service.store.audit_signer
        head = {"finalized": self.loc(2), "tip": local_tip}
        head["auth"] = sign_finality(
            signer["private_key"], signer["version"],
            head["finalized"], head["tip"],
        )
        page["head"] = head
        result = apply_finality_locator_pages(
            self.path, pages, locators, self.tip_hash, self.trust
        )
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertEqual(self.file_bytes(), after_advance)


class LocatorPagesStateIoTests(LocatorPagesFixture):
    def test_missing_file_is_io(self) -> None:
        missing = os.path.join(self.tmp, "missing.json")
        result = apply_finality_locator_pages(
            missing, self.located_pages(self.default_locators(), 1),
            self.default_locators(), self.tip_hash, self.trust,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_checkpoint_is_state(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        stored["finalized"] = self.loc(1)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(stored, fh)
        result = apply_finality_locator_pages(
            self.path, self.located_pages(self.default_locators(), 1),
            self.default_locators(), self.tip_hash, self.trust,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_STATE})

    def test_unparseable_checkpoint_is_state(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        result = apply_finality_locator_pages(
            self.path, self.located_pages(self.default_locators(), 1),
            self.default_locators(), self.tip_hash, self.trust,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_STATE})

    def test_unwritable_file_is_io(self) -> None:
        directory = os.path.join(self.tmp, "nowhere")
        path = os.path.join(directory, "checkpoint.json")
        result = apply_finality_locator_pages(
            path, self.located_pages(self.default_locators(), 1),
            self.default_locators(), self.tip_hash, self.trust,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        # A directory as the checkpoint path is an io failure too.
        result = apply_finality_locator_pages(
            self.tmp, self.located_pages(self.default_locators(), 1),
            self.default_locators(), self.tip_hash, self.trust,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_IO})


if __name__ == "__main__":
    unittest.main()
