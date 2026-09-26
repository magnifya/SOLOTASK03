"""Tests for the irreversible header-checkpoint finality boundary
(``ledger.light_client.finalize_headers``) and its interaction with
``advance_headers`` and ``reorg_headers``.

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` and covers:

* ``finalize_headers(path, height, block_hash) -> dict`` with no default
  arguments and strict parameter shapes (non-empty path, non-boolean
  non-negative height, 64-char lowercase hex hash);
* raising the boundary to a confirmed replayed header: success key order
  ``ok, generation, finalized`` (``finalized`` key order
  ``height, block_hash``), generation bumped once and the file rewritten
  as version 3 with top-level key order
  ``v, generation, anchor, tip, finalized, steps, hash`` and the same
  canonical-json SHA-256 hash/serialization rules as version 2;
* idempotency: re-marking the exact current boundary (including the
  implicit anchor boundary of a fresh checkpoint) returns the current
  generation with byte-identical files;
* integrity failures — lower height, same height/different hash, unknown
  hash, a pending header and a height past the tip — never bump the
  generation nor touch the bytes;
* version-1/version-2 migration (their anchor reads as the finalized
  boundary, the next successful write is v3) and v3 ownership replay
  (a finalized boundary on a dropped fork or at a pending header is
  ``state``);
* reorg finality: a reorg batch must anchor at the finalized boundary or
  a later branch point — anchoring before it is ``integrity`` and leaves
  the file and generation untouched — while anchoring exactly at the
  finalized boundary reorganizes the unfinalized suffix normally;
* error categories ``input``/``integrity``/``state``/``io`` and the
  never-raise contract.

Run: python3 tests/light_client_finalize_headers_test.py
"""
from __future__ import annotations

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
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_IO,
    ERR_STATE,
    advance_headers,
    finalize_headers,
    header_locators,
    reorg_headers,
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
STEP_KEYS = ["kind", "tip_hash", "trust", "documents", "locators"]
V2_STEP_KEYS = ["kind", "tip_hash", "trust", "documents", "locators"]
ANCHOR_KEYS = ["height", "block_hash"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class FinalizeHeadersFixture(unittest.TestCase):
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
                self.service.confirm_block(str(self.store.tip().height))[0], 200
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
        tip_hash = self.store.tip_hash()
        while True:
            page = self.page(anchor["height"], anchor["block_hash"], limit)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == tip_hash:
                break
        return documents

    def locate(self, locators, limit=None) -> dict:
        payload = {"locators": locators}
        if limit is not None:
            payload["limit"] = limit
        status, body = self.service.locate_header_fork(payload)
        self.assertEqual(status, 200, body)
        return body

    def advance(self, documents, anchor, tip_hash=None, trust=None):
        return advance_headers(
            self.path,
            documents,
            anchor,
            self.store.tip_hash() if tip_hash is None else tip_hash,
            self.trust if trust is None else trust,
        )

    def reorg(self, documents, locators, tip_hash=None, trust=None, path=None):
        return reorg_headers(
            self.path if path is None else path,
            documents,
            locators,
            self.store.tip_hash() if tip_hash is None else tip_hash,
            self.trust if trust is None else trust,
        )

    def finalize(self, height, block_hash, path=None):
        return finalize_headers(
            self.path if path is None else path, height, block_hash
        )

    def checkpoint_to_tip_four(self) -> None:
        """Advance once: a checkpoint at pending tip height 4, generation 1."""
        result = self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)

    def extend_to_confirmed_five(self) -> str:
        """Confirm 4, advance the confirmation, mine/advance pending 5.

        Returns the old (pre-fork) height-5 tip hash. The checkpoint ends
        at generation 3 with a confirmed height-4 boundary candidate.
        """
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        confirmed = self.advance([empty], None, tip_hash=self.tip_hash)
        self.assertEqual(confirmed["generation"], 2)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip5 = self.store.tip_hash()
        page5 = self.page(4, self.tip_hash)
        advanced = self.advance([page5], None, tip_hash=tip5)
        self.assertEqual(advanced["generation"], 3)
        return tip5

    def fork_tip(self, amount: int = 8) -> str:
        """Roll the pending tip back and re-mine a divergent pending block."""
        height = self.store.tip().height
        self.assertEqual(self.service.rollback_block(str(height))[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(amount))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        return self.store.tip_hash()

    def read_checkpoint(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def write_file(self, data) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            if isinstance(data, str):
                fh.write(data)
            else:
                json.dump(data, fh)

    def rehash(self, data: dict) -> None:
        """Recompute the checkpoint hash after a tamper, pinning the damage."""
        body = {key: value for key, value in data.items() if key != "hash"}
        data["hash"] = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class FinalizeHeadersSuccessTests(FinalizeHeadersFixture):
    def test_finalize_confirmed_header_writes_v3_boundary(self) -> None:
        self.checkpoint_to_tip_four()
        result = self.finalize(2, self.h(2))
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), ["ok", "generation", "finalized"])
        self.assertEqual(result["generation"], 2)
        self.assertEqual(
            result["finalized"], {"height": 2, "block_hash": self.h(2)}
        )
        self.assertEqual(list(result["finalized"].keys()), ANCHOR_KEYS)

        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        data = json.loads(raw)
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 2)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["finalized"], {"height": 2, "block_hash": self.h(2)})
        self.assertEqual(list(data["finalized"].keys()), ANCHOR_KEYS)
        # Tip and steps are preserved verbatim.
        self.assertEqual(data["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(list(data["steps"][0].keys()), STEP_KEYS)
        body = {key: value for key, value in data.items() if key != "hash"}
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)

    def test_finalize_confirmed_tip(self) -> None:
        self.checkpoint_to_tip_four()
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        self.assertEqual(self.advance([empty], None, tip_hash=self.tip_hash)["generation"], 2)
        result = self.finalize(4, self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(self.read_checkpoint()["finalized"]["height"], 4)

    def test_finalize_anchor_on_fresh_checkpoint_is_idempotent(self) -> None:
        self.checkpoint_to_tip_four()
        before = self.read_raw()
        result = self.finalize(0, self.genesis_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["finalized"], self.anchor)
        self.assertEqual(self.read_raw(), before)

    def test_same_target_is_idempotent_with_byte_identical_file(self) -> None:
        self.checkpoint_to_tip_four()
        first = self.finalize(3, self.h(3))
        self.assertEqual(first["generation"], 2)
        before = self.read_raw()
        replay = self.finalize(3, self.h(3))
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], 2)
        self.assertEqual(replay["finalized"], first["finalized"])
        self.assertEqual(self.read_raw(), before)

    def test_repeated_raises_bump_generation_each_time(self) -> None:
        self.checkpoint_to_tip_four()
        self.assertEqual(self.finalize(1, self.h(1))["generation"], 2)
        self.assertEqual(self.finalize(2, self.h(2))["generation"], 3)
        self.assertEqual(self.finalize(3, self.h(3))["generation"], 4)
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 4)
        self.assertEqual(data["finalized"], {"height": 3, "block_hash": self.h(3)})
        # The checkpoint still strictly reloads.
        derived = header_locators(self.path)
        self.assertTrue(derived["ok"], derived)

    def test_advance_after_finalize_preserves_boundary(self) -> None:
        self.checkpoint_to_tip_four()
        self.assertEqual(self.finalize(2, self.h(2))["generation"], 2)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        result = self.advance([empty], None, tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        data = self.read_checkpoint()
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["finalized"], {"height": 2, "block_hash": self.h(2)})

    def test_version_two_file_finalizes_and_migrates_to_v3(self) -> None:
        documents = self.paged(2)
        legacy = {
            "v": 2,
            "generation": 1,
            "anchor": self.anchor,
            "tip": documents[0]["tip"],
            "steps": [
                {
                    "kind": "linear",
                    "tip_hash": self.tip_hash,
                    "trust": self.trust,
                    "documents": documents,
                    "locators": None,
                }
            ],
        }
        self.rehash(legacy)
        self.write_file(legacy)
        result = self.finalize(2, self.h(2))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        data = self.read_checkpoint()
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["finalized"], {"height": 2, "block_hash": self.h(2)})
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(list(data["steps"][0].keys()), V2_STEP_KEYS)
        # The migrated file strictly replays.
        self.assertTrue(header_locators(self.path)["ok"])

    def test_version_one_file_finalizes_and_migrates_to_v3(self) -> None:
        documents = self.paged(2)
        legacy = {
            "v": 1,
            "generation": 1,
            "anchor": self.anchor,
            "tip": documents[0]["tip"],
            "steps": [
                {"tip_hash": self.tip_hash, "trust": self.trust, "documents": documents}
            ],
        }
        self.rehash(legacy)
        self.write_file(legacy)
        result = self.finalize(2, self.h(2))
        self.assertTrue(result["ok"], result)
        data = self.read_checkpoint()
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["finalized"], {"height": 2, "block_hash": self.h(2)})
        self.assertTrue(header_locators(self.path)["ok"])


class FinalizeHeadersInputTests(FinalizeHeadersFixture):
    def test_path_must_be_a_non_empty_string(self) -> None:
        self.checkpoint_to_tip_four()
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    finalize_headers(bad_path, 2, self.h(2)), ERR_INPUT
                )

    def test_height_must_be_a_non_boolean_non_negative_integer(self) -> None:
        self.checkpoint_to_tip_four()
        for bad_height in (None, "2", True, False, -1, 2.0, [2]):
            with self.subTest(bad_height=bad_height):
                self.assert_error(self.finalize(bad_height, self.h(2)), ERR_INPUT)

    def test_block_hash_must_be_64_lower_hex(self) -> None:
        self.checkpoint_to_tip_four()
        for bad_hash in (
            None,
            2,
            "zz",
            "A" * 64,
            "a" * 63,
            "a" * 65,
            True,
        ):
            with self.subTest(bad_hash=bad_hash):
                self.assert_error(self.finalize(2, bad_hash), ERR_INPUT)

    def test_never_raises_on_garbage(self) -> None:
        result = finalize_headers(object(), object(), object())
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})


class FinalizeHeadersIntegrityTests(FinalizeHeadersFixture):
    def test_pending_header_cannot_be_finalized(self) -> None:
        self.checkpoint_to_tip_four()
        before = self.read_raw()
        # Height 4 is the pending tip.
        self.assert_error(self.finalize(4, self.tip_hash), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_unknown_hash_at_known_height_is_integrity(self) -> None:
        self.checkpoint_to_tip_four()
        before = self.read_raw()
        self.assert_error(self.finalize(2, "f" * 64), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_height_past_tip_is_integrity(self) -> None:
        self.checkpoint_to_tip_four()
        self.assertEqual(self.finalize(3, self.h(3))["generation"], 2)
        before = self.read_raw()
        self.assert_error(self.finalize(5, "a" * 64), ERR_INTEGRITY)
        self.assert_error(self.finalize(99, "a" * 64), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_lower_height_is_integrity(self) -> None:
        self.checkpoint_to_tip_four()
        self.assertEqual(self.finalize(3, self.h(3))["generation"], 2)
        before = self.read_raw()
        self.assert_error(self.finalize(2, self.h(2)), ERR_INTEGRITY)
        self.assert_error(self.finalize(0, self.genesis_hash), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)
        self.assertEqual(self.read_checkpoint()["generation"], 2)

    def test_same_height_different_hash_is_integrity(self) -> None:
        self.checkpoint_to_tip_four()
        self.assertEqual(self.finalize(3, self.h(3))["generation"], 2)
        before = self.read_raw()
        self.assert_error(self.finalize(3, "f" * 64), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_failed_finalize_never_bumps_generation(self) -> None:
        self.checkpoint_to_tip_four()
        before = self.read_raw()
        self.assert_error(self.finalize(4, self.tip_hash), ERR_INTEGRITY)
        self.assert_error(self.finalize(5, "a" * 64), ERR_INTEGRITY)
        # The next valid finalization still lands at generation 2.
        result = self.finalize(2, self.h(2))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertNotEqual(self.read_raw(), before)


class FinalizeHeadersStateTests(FinalizeHeadersFixture):
    def test_corrupt_json_is_state(self) -> None:
        self.checkpoint_to_tip_four()
        self.write_file("{not json")
        self.assert_error(self.finalize(2, self.h(2)), ERR_STATE)

    def test_tampered_finalized_on_dropped_fork_is_state(self) -> None:
        self.checkpoint_to_tip_four()
        tip5 = self.extend_to_confirmed_five()
        self.assertEqual(self.finalize(4, self.tip_hash)["generation"], 4)
        # Reorganize the unfinalized suffix: the height-5 fork replaces the
        # old height-5 block.
        forked5 = self.fork_tip(amount=8)
        locators = [self.loc(5, tip5), self.loc(4, self.tip_hash), self.loc(0)]
        result = self.reorg([self.locate(locators)], locators, tip_hash=forked5)
        self.assertTrue(result["ok"], result)
        # Tamper the boundary onto the old (dropped) height-5 fork hash.
        data = self.read_checkpoint()
        data["finalized"] = {"height": 5, "block_hash": tip5}
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.finalize(5, forked5), ERR_STATE)
        self.assert_error(header_locators(self.path), ERR_STATE)

    def test_finalized_pointing_at_pending_header_is_state(self) -> None:
        self.checkpoint_to_tip_four()
        tip5 = self.extend_to_confirmed_five()
        self.assertEqual(self.finalize(4, self.tip_hash)["generation"], 4)
        forked5 = self.fork_tip(amount=8)
        locators = [self.loc(5, tip5), self.loc(4, self.tip_hash), self.loc(0)]
        result = self.reorg([self.locate(locators)], locators, tip_hash=forked5)
        self.assertTrue(result["ok"], result)
        # A boundary at the pending forked tip can never be owned: state.
        data = self.read_checkpoint()
        data["finalized"] = {"height": 5, "block_hash": forked5}
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.finalize(5, forked5), ERR_STATE)

    def test_tampered_hash_is_state(self) -> None:
        self.checkpoint_to_tip_four()
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        self.write_file(data)
        self.assert_error(self.finalize(2, self.h(2)), ERR_STATE)

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        self.checkpoint_to_tip_four()
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        payload = json.dumps(data)
        self.write_file(payload)
        self.assert_error(self.finalize(2, self.h(2)), ERR_STATE)
        self.assertEqual(self.read_raw().decode("utf-8"), payload)


class FinalizeHeadersIoTests(FinalizeHeadersFixture):
    def test_missing_file_is_io(self) -> None:
        self.assert_error(
            finalize_headers(self.path, 2, "a" * 64), ERR_IO
        )

    def test_unwritable_target_path_is_io(self) -> None:
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        self.assert_error(self.finalize(2, "a" * 64, path=directory), ERR_IO)


class ReorgFinalityTests(FinalizeHeadersFixture):
    def _finalized_five_setup(self) -> str:
        """Checkpoint through a finalized height 4 with a pending tip 5."""
        self.checkpoint_to_tip_four()
        tip5 = self.extend_to_confirmed_five()
        result = self.finalize(4, self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 4)
        return tip5

    def test_reorg_anchoring_before_finalized_is_integrity(self) -> None:
        tip5 = self._finalized_five_setup()
        forked5 = self.fork_tip(amount=8)
        before = self.read_raw()
        # The locator list offers the stale tip and the anchor: the chain
        # matches only genesis, so the batch anchors at height 0 — below
        # the finalized boundary at height 4.
        locators = [self.loc(5, tip5), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(0))
        self.assert_error(
            self.reorg([page], locators, tip_hash=forked5), ERR_INTEGRITY
        )
        # File bytes and generation are untouched.
        self.assertEqual(self.read_raw(), before)
        self.assertEqual(self.read_checkpoint()["generation"], 4)

    def test_reorg_anchoring_exactly_at_finalized_succeeds(self) -> None:
        tip5 = self._finalized_five_setup()
        forked5 = self.fork_tip(amount=8)
        locators = [self.loc(5, tip5), self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(4, self.tip_hash))
        result = self.reorg([page], locators, tip_hash=forked5)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 5)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["tip"]["tip_hash"], forked5)
        data = self.read_checkpoint()
        self.assertEqual(data["v"], 3)
        # The finalized boundary is preserved across the reorg.
        self.assertEqual(data["finalized"], {"height": 4, "block_hash": self.tip_hash})
        self.assertEqual(
            [step["kind"] for step in data["steps"]], ["linear", "linear", "locator"]
        )
        # The reorged checkpoint still strictly replays, boundary owned.
        self.assertTrue(header_locators(self.path)["ok"])

    def test_reorg_anchoring_after_finalized_succeeds(self) -> None:
        # Finalize only height 2, then the same fork anchors at the
        # confirmed height-4 branch point (strictly after finalized).
        self.checkpoint_to_tip_four()
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        self.assertEqual(self.advance([empty], None, tip_hash=self.tip_hash)["generation"], 2)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip5 = self.store.tip_hash()
        self.assertEqual(self.advance([self.page(4, self.tip_hash)], None, tip_hash=tip5)["generation"], 3)
        self.assertEqual(self.finalize(2, self.h(2))["generation"], 4)

        forked5 = self.fork_tip(amount=8)
        locators = [self.loc(5, tip5), self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(4, self.tip_hash))
        result = self.reorg([page], locators, tip_hash=forked5)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 5)
        self.assertEqual(self.read_checkpoint()["finalized"]["height"], 2)

    def test_finality_rejection_leaves_idempotent_replay_intact(self) -> None:
        tip5 = self._finalized_five_setup()
        forked5 = self.fork_tip(amount=8)
        locators = [self.loc(5, tip5), self.loc(0)]
        page = self.locate(locators)
        self.assert_error(self.reorg([page], locators, tip_hash=forked5), ERR_INTEGRITY)
        # The legitimate reorg at the finalized boundary still goes through.
        good_locators = [
            self.loc(5, tip5),
            self.loc(4, self.tip_hash),
            self.loc(0),
        ]
        good_page = self.locate(good_locators)
        result = self.reorg([good_page], good_locators, tip_hash=forked5)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
