"""Tests for the locator finality-history light-client consumer
``ledger.light_client.apply_finality_locator_pages``.

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` and covers:

* the happy path: a multi-page and a single-page ``POST
  /v1/chain/finalities/locate`` history apply atomically — the whole
  batch verifies before the version-3 checkpoint is rewritten once, the
  generation bumps by exactly one and the success key order is
  ``ok, generation, finalized, matched_index, pages, applied`` with
  ``matched_index`` the 0-based locator position of the first page's
  anchor;
* idempotence: a batch whose closing boundary equals the stored one
  (including the empty single page whose anchor already is the
  finalized head) leaves the file bytes and the generation untouched,
  while an empty page anchored above the stored boundary advances it;
* failure categories: structure/key-order/type defects ``input``,
  unknown key versions or bad signatures ``auth``, pagination, anchor,
  branch, tip or boundary defects ``integrity``, a corrupt checkpoint
  ``state`` and a missing file ``io``; failures never change the file
  bytes or the generation and nothing is raised.

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


_UNSET = object()


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

    def locator_paged(self, locators: list, limit: int) -> list:
        """The locate page for ``locators`` plus every follow-up page."""
        status, body = self.service.locate_finality_fork(
            {"locators": locators, "limit": limit}
        )
        self.assertEqual(status, 200, body)
        pages = [body]
        while pages[-1]["next"] is not None:
            anchor = pages[-1]["next"]
            pages.append(
                self.finalities_page(
                    anchor["height"], anchor["block_hash"], limit
                )
            )
        return pages

    def apply(self, pages, locators, tip_hash=_UNSET, trust=_UNSET, path=_UNSET):
        return apply_finality_locator_pages(
            self.path if path is _UNSET else path,
            pages,
            locators,
            self.tip_hash if tip_hash is _UNSET else tip_hash,
            self.trust if trust is _UNSET else trust,
        )

    def file_bytes(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def assert_failed(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})
        self.assertEqual(self.file_bytes(), self.stored_bytes)


class LocatorPagesSuccessTests(LocatorPagesFixture):
    def test_multi_page_batch_advances_once(self) -> None:
        locators = [self.loc(3, "f" * 64), self.loc(1), self.loc(0)]
        pages = self.locator_paged(locators, 1)
        self.assertEqual(len(pages), 2)
        self.assertEqual(pages[0]["anchor"], self.loc(1))
        generation_before = json.loads(self.stored_bytes)["generation"]
        result = self.apply(pages, locators)
        self.assertEqual(
            list(result.keys()),
            ["ok", "generation", "finalized", "matched_index", "pages", "applied"],
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], generation_before + 1)
        self.assertEqual(result["finalized"], self.loc(3))
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
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 100)
        self.assertEqual(len(pages), 1)
        result = self.apply(pages, locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 3)

    def test_every_page_size(self) -> None:
        for limit in (1, 2, 3, 500):
            fresh = os.path.join(self.tmp, f"checkpoint-{limit}.json")
            shutil.copy(self.path, fresh)
            locators = [self.loc(1), self.loc(0)]
            result = self.apply(
                self.locator_paged(locators, limit), locators, path=fresh
            )
            self.assertTrue(result["ok"], (limit, result))
            self.assertEqual(result["finalized"], self.loc(3))
            self.assertEqual(result["matched_index"], 0)
            self.assertEqual(result["applied"], 2)

    def test_replay_to_stored_boundary_is_idempotent(self) -> None:
        locators = [self.loc(0)]
        result = self.apply(self.locator_paged(locators, 100), locators)
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        generation = json.loads(after_advance)["generation"]
        # Re-applying a batch whose head already is the stored boundary
        # replays history: the bytes and the generation hold.
        replay_locators = [self.loc(1), self.loc(0)]
        replay = self.locator_paged(replay_locators, 100)
        result = self.apply(replay, replay_locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], generation)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["applied"], 2)
        self.assertEqual(self.file_bytes(), after_advance)

    def test_empty_page_at_stored_boundary_is_idempotent(self) -> None:
        locators = [self.loc(0)]
        result = self.apply(self.locator_paged(locators, 100), locators)
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        generation = json.loads(after_advance)["generation"]
        # The empty page anchored at the finalized head itself.
        head_locators = [self.loc(3)]
        empty = self.locator_paged(head_locators, 100)
        self.assertEqual(len(empty), 1)
        self.assertEqual(empty[0]["finalities"], [])
        result = self.apply(empty, head_locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], generation)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["matched_index"], 0)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(self.file_bytes(), after_advance)

    def test_empty_page_above_boundary_advances(self) -> None:
        # A genuine empty page names the finalized head as its anchor;
        # while the stored boundary is still the genesis anchor that
        # boundary advances to the head without any credential.
        head_locators = [self.loc(3)]
        empty = self.locator_paged(head_locators, 100)
        self.assertEqual(empty[0]["finalities"], [])
        generation_before = json.loads(self.stored_bytes)["generation"]
        result = self.apply(empty, head_locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], generation_before + 1)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["applied"], 0)
        stored = json.loads(self.file_bytes())
        self.assertEqual(stored["finalized"], self.loc(3))
        self.assertEqual(stored["generation"], generation_before + 1)


class LocatorPagesInputTests(LocatorPagesFixture):
    def test_argument_shape(self) -> None:
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 2)
        for bad_path in (None, "", 0, 1.5, [], {}):
            self.assert_failed(
                apply_finality_locator_pages(
                    bad_path, pages, locators, self.tip_hash, self.trust
                ),
                ERR_INPUT,
            )
        for bad_pages in (None, {}, "x", 0, []):
            self.assert_failed(self.apply(bad_pages, locators), ERR_INPUT)
        for bad_tip in (None, 0, "zz" * 32, "AB" * 32, self.tip_hash + "00"):
            self.assert_failed(
                self.apply(pages, locators, tip_hash=bad_tip), ERR_INPUT
            )

    def test_locator_list_shape(self) -> None:
        pages = self.locator_paged([self.loc(0)], 2)
        bad_lists = (
            None,
            {},
            "x",
            [],
            [self.loc(0)] * 2,  # heights not strictly descending
            [{"block_hash": self.h(0), "height": 0}],  # item key order
            [{"height": True, "block_hash": self.h(0)}],
            [{"height": -1, "block_hash": self.h(0)}],
            [{"height": 0, "block_hash": "0" * 63}],
            [{"height": i, "block_hash": "1" * 64} for i in range(64, -1, -1)],
        )
        for bad in bad_lists:
            self.assert_failed(self.apply(pages, bad), ERR_INPUT)

    def test_page_structure(self) -> None:
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 2)
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
            self.assert_failed(self.apply(case, locators), ERR_INPUT)

    def test_trust_shape(self) -> None:
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 2)
        for bad_trust in (None, {}, {"audit_signers": []}, {"audit_signers": [{}]}):
            self.assert_failed(
                self.apply(pages, locators, trust=bad_trust), ERR_INPUT
            )


class LocatorPagesAuthTests(LocatorPagesFixture):
    def test_unknown_key_version(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[0]["finalities"][0]["auth"]["key_version"] = 99
        self.assert_failed(self.apply(pages, locators), ERR_AUTH)

    def test_bad_item_signature(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[1]["finalities"][0]["auth"]["signature"] = "00" * 64
        self.assert_failed(self.apply(pages, locators), ERR_AUTH)

    def test_bad_head_signature(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[1]["head"]["auth"]["signature"] = "00" * 64
        self.assert_failed(self.apply(pages, locators), ERR_AUTH)

    def test_tampered_signed_content(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[0]["finalities"][1]["finalized"]["block_hash"] = "0" * 64
        self.assert_failed(self.apply(pages, locators), ERR_AUTH)


class LocatorPagesIntegrityTests(LocatorPagesFixture):
    def test_first_anchor_must_be_in_locators(self) -> None:
        # The pages anchor at height 0 but the offered locators do not.
        pages = self.locator_paged([self.loc(0)], 2)
        self.assert_failed(
            self.apply(pages, [self.loc(2), self.loc(1)]), ERR_INTEGRITY
        )

    def test_matched_anchor_must_be_on_confirmed_branch(self) -> None:
        # A locator naming a fork hash at a real height is matched by the
        # list but not by the replayed branch.
        fork = self.loc(2, "a" * 64)
        pages = self.locator_paged([self.loc(2)], 100)
        pages[0]["anchor"] = fork
        self.assert_failed(self.apply(pages, [fork]), ERR_INTEGRITY)
        # A locator naming the pending tip is not a confirmed block.
        pending = self.loc(4)
        pages = self.locator_paged([self.loc(3)], 100)
        pages[0]["anchor"] = pending
        self.assert_failed(self.apply(pages, [pending]), ERR_INTEGRITY)

    def test_tip_hash_must_match_head(self) -> None:
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 2)
        self.assert_failed(
            self.apply(pages, locators, tip_hash="0" * 64), ERR_INTEGRITY
        )

    def test_later_anchor_must_chain(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[1]["anchor"] = self.loc(1)
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_heads_must_be_identical(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
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
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_non_last_page_must_be_non_empty_with_matching_next(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[0]["next"] = self.loc(1)
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[0]["next"] = None
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[0]["finalities"] = []
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_last_page_must_close(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[1]["next"] = self.loc(3)
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)
        # A multi-page batch may not end on an empty page.
        pages = copy.deepcopy(self.locator_paged(locators, 2))
        pages[1]["finalities"] = []
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)
        # The last page must reach head.finalized.
        pages = copy.deepcopy(self.locator_paged(locators, 1))
        pages[1]["finalities"] = pages[1]["finalities"][:1]
        pages[1]["next"] = None
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_credentials_must_be_consecutive(self) -> None:
        locators = [self.loc(0)]
        pages = copy.deepcopy(self.locator_paged(locators, 1))
        # Drop the middle credential of the second page: heights skip.
        del pages[1]["finalities"][0]
        pages[0]["next"] = self.loc(1)
        pages[1]["anchor"] = self.loc(1)
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_branch_mismatch(self) -> None:
        # A credential naming a hash that is not the branch's block.
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 1)
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
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_tip_descriptor_mismatch(self) -> None:
        # A genuine credential whose tip descriptor is replaced by a
        # signed but wrong S (length/status/height off).
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 1)
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
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_head_tip_must_equal_local_tip(self) -> None:
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 1)
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
        self.assert_failed(self.apply(pages, locators), ERR_INTEGRITY)

    def test_boundary_regression_rejected(self) -> None:
        # Advance to the finalized head first.
        locators = [self.loc(0)]
        result = self.apply(self.locator_paged(locators, 100), locators)
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        # A signed head finalizing a lower block may not move the stored
        # boundary backwards.
        genuine = self.finalities_page(0, self.h(0))
        head = {"finalized": self.loc(1), "tip": genuine["head"]["tip"]}
        signer = self.service.store.audit_signer
        head["auth"] = sign_finality(
            signer["private_key"], signer["version"], head["finalized"], head["tip"]
        )
        page = {
            "anchor": self.loc(1),
            "finalities": [],
            "next": None,
            "head": head,
        }
        result = self.apply([page], [self.loc(1)])
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertEqual(self.file_bytes(), after_advance)

    def test_boundary_sideways_rejected(self) -> None:
        # A signed head finalizing a fork hash at the stored boundary's
        # height may not move the boundary sideways.
        locators = [self.loc(0)]
        result = self.apply(self.locator_paged(locators, 100), locators)
        self.assertTrue(result["ok"], result)
        after_advance = self.file_bytes()
        genuine = self.finalities_page(0, self.h(0))
        fork_target = self.loc(3, "a" * 64)
        head = {"finalized": fork_target, "tip": genuine["head"]["tip"]}
        signer = self.service.store.audit_signer
        head["auth"] = sign_finality(
            signer["private_key"], signer["version"], head["finalized"], head["tip"]
        )
        page = {
            "anchor": self.loc(3),
            "finalities": [],
            "next": None,
            "head": head,
        }
        result = self.apply([page], [self.loc(3)])
        self.assertEqual(result, {"ok": False, "error": ERR_INTEGRITY})
        self.assertEqual(self.file_bytes(), after_advance)


class LocatorPagesStateIoTests(LocatorPagesFixture):
    def test_missing_file_is_io(self) -> None:
        missing = os.path.join(self.tmp, "missing.json")
        locators = [self.loc(0)]
        result = apply_finality_locator_pages(
            missing, self.locator_paged(locators, 1), locators,
            self.tip_hash, self.trust,
        )
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertFalse(os.path.exists(missing))

    def test_corrupt_checkpoint_is_state(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            stored = json.load(fh)
        stored["finalized"] = self.loc(1)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(stored, fh)
        locators = [self.loc(0)]
        result = self.apply(self.locator_paged(locators, 1), locators)
        self.assertEqual(result, {"ok": False, "error": ERR_STATE})

    def test_unparseable_checkpoint_is_state(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        locators = [self.loc(0)]
        result = self.apply(self.locator_paged(locators, 1), locators)
        self.assertEqual(result, {"ok": False, "error": ERR_STATE})

    def test_unwritable_file_is_io(self) -> None:
        directory = os.path.join(self.tmp, "nowhere")
        path = os.path.join(directory, "checkpoint.json")
        locators = [self.loc(0)]
        pages = self.locator_paged(locators, 1)
        # A missing parent directory makes the load report io.
        result = self.apply(pages, locators, path=path)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        # A directory as the checkpoint path is an io failure too.
        result = self.apply(pages, locators, path=self.tmp)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})


if __name__ == "__main__":
    unittest.main()
