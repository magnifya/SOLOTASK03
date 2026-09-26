"""Tests for the irreversible finalization boundary
(``ledger.light_client.finalize_headers``).

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` and covers:

* raising the finalized boundary to the anchor or a confirmed step tip:
  success key order ``ok, generation, finalized`` (finalized key order
  ``height, block_hash``), one generation bump per raise and the v3 file
  shape (top-level key order ``v, generation, anchor, tip, finalized,
  steps, hash``) with the self-excluding canonical-json SHA-256 ``hash``;
* idempotent re-submission of the current boundary (no generation bump,
  file bytes untouched) and migration of version-1/2 files on the first
  successful write;
* ``integrity`` failures: lowering the boundary, a different hash at the
  boundary's height, an unknown height or hash, the pending tip and a
  height above the tip;
* ``input`` failures (bad path/height/block_hash), ``state`` failures (a
  corrupt checkpoint, including a v3 file whose finalized boundary the
  replay does not own) and ``io`` failures (a missing or unreadable file);
* reorg interplay: a reorg anchoring before the finalized boundary is
  ``integrity`` and leaves the file and generation untouched, while a
  reorg at or after the boundary still succeeds.

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

CHECKPOINT_KEYS = ["v", "generation", "anchor", "tip", "finalized", "steps", "hash"]
V1_STEP_KEYS = ["tip_hash", "trust", "documents"]

_DEFAULT = object()


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

    def advance(self, limit: int = 2) -> dict:
        result = advance_headers(
            self.path, self.paged(limit), self.anchor, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        return result

    def finalize(self, height, block_hash=_DEFAULT, path=None):
        return finalize_headers(
            self.path if path is None else path,
            height,
            self.store.chain[height].block_hash if block_hash is _DEFAULT else block_hash,
        )

    def fork_tip(self, amount: int = 6) -> str:
        """Roll the pending tip back and re-mine a divergent pending block."""
        height = self.store.tip().height
        self.assertEqual(self.service.rollback_block(str(height))[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(amount))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        new_tip_hash = self.store.tip_hash()
        self.assertNotEqual(new_tip_hash, self.tip_hash)
        return new_tip_hash

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
    def test_finalize_confirmed_header_bumps_generation(self) -> None:
        self.advance()
        result = self.finalize(2)
        self.assertEqual(list(result.keys()), ["ok", "generation", "finalized"])
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["finalized"], self.loc(2))
        self.assertEqual(list(result["finalized"].keys()), ["height", "block_hash"])

        data = self.read_checkpoint()
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 2)
        self.assertEqual(data["finalized"], self.loc(2))
        self.assertEqual(list(data["finalized"].keys()), ["height", "block_hash"])
        # The hash still covers every field but itself.
        body = {key: data[key] for key in CHECKPOINT_KEYS if key != "hash"}
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)

    def test_finalize_anchor_of_fresh_checkpoint_is_idempotent(self) -> None:
        self.advance()
        before = self.read_raw()
        result = self.finalize(0)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["finalized"], self.anchor)
        # The file bytes stay exactly as they were.
        self.assertEqual(self.read_raw(), before)

    def test_same_target_replay_is_idempotent(self) -> None:
        self.advance()
        self.assertEqual(self.finalize(2)["generation"], 2)
        before = self.read_raw()
        replay = self.finalize(2)
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], 2)
        self.assertEqual(replay["finalized"], self.loc(2))
        self.assertEqual(self.read_raw(), before)

    def test_raising_again_bumps_generation_once_per_raise(self) -> None:
        self.advance()
        self.assertEqual(self.finalize(1)["generation"], 2)
        self.assertEqual(self.finalize(3)["generation"], 3)
        self.assertEqual(self.read_checkpoint()["finalized"], self.loc(3))

    def test_finalized_boundary_survives_advance(self) -> None:
        self.advance()
        self.finalize(2)
        # Confirm the pending tip and extend the chain by one pending block.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        page = self.page(4, self.tip_hash)
        result = advance_headers(
            self.path, [page], None, self.store.tip_hash(), self.trust
        )
        self.assertTrue(result["ok"], result)
        data = self.read_checkpoint()
        self.assertEqual(data["finalized"], self.loc(2))
        self.assertEqual(data["tip"]["height"], 5)
        # The checkpoint still strictly loads for the other readers.
        derived = header_locators(self.path)
        self.assertTrue(derived["ok"], derived)

    def test_version_one_checkpoint_migrates_on_finalize(self) -> None:
        self.advance()
        data = self.read_checkpoint()
        legacy = {
            "v": 1,
            "generation": data["generation"],
            "anchor": data["anchor"],
            "tip": data["tip"],
            "steps": [
                {key: step[key] for key in V1_STEP_KEYS}
                for step in data["steps"]
            ],
        }
        self.rehash(legacy)
        self.write_file(legacy)
        # The legacy file reads as finalized at its anchor; the first
        # successful finalize migrates it to version 3.
        result = self.finalize(2)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        rewritten = self.read_checkpoint()
        self.assertEqual(list(rewritten.keys()), CHECKPOINT_KEYS)
        self.assertEqual(rewritten["v"], 3)
        self.assertEqual(rewritten["finalized"], self.loc(2))

    def test_version_two_checkpoint_migrates_on_finalize(self) -> None:
        self.advance()
        data = self.read_checkpoint()
        v2 = {key: data[key] for key in CHECKPOINT_KEYS if key != "finalized"}
        v2["v"] = 2
        self.rehash(v2)
        self.write_file(v2)
        result = self.finalize(2)
        self.assertTrue(result["ok"], result)
        rewritten = self.read_checkpoint()
        self.assertEqual(rewritten["v"], 3)
        self.assertEqual(rewritten["finalized"], self.loc(2))


class FinalizeHeadersInputTests(FinalizeHeadersFixture):
    def test_path_must_be_a_non_empty_string(self) -> None:
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    finalize_headers(bad_path, 0, self.genesis_hash), ERR_INPUT
                )

    def test_height_must_be_a_plain_non_negative_integer(self) -> None:
        self.advance()
        for bad_height in (None, True, -1, "2", 2.0):
            with self.subTest(bad_height=bad_height):
                self.assert_error(self.finalize(bad_height, "a" * 64), ERR_INPUT)

    def test_block_hash_must_be_64_lower_hex(self) -> None:
        self.advance()
        for bad_hash in (None, 7, "zz", "A" * 64, "a" * 63, "a" * 65, True):
            with self.subTest(bad_hash=bad_hash):
                self.assert_error(self.finalize(2, bad_hash), ERR_INPUT)

    def test_never_raises_on_garbage(self) -> None:
        result = finalize_headers(self.path, object(), object())
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})


class FinalizeHeadersIntegrityTests(FinalizeHeadersFixture):
    def test_lowering_the_boundary_is_integrity(self) -> None:
        self.advance()
        self.assertEqual(self.finalize(3)["generation"], 2)
        before = self.read_raw()
        self.assert_error(self.finalize(2), ERR_INTEGRITY)
        self.assert_error(self.finalize(0), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_same_height_different_hash_is_integrity(self) -> None:
        self.advance()
        self.finalize(2)
        before = self.read_raw()
        self.assert_error(self.finalize(2, "a" * 64), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_unknown_height_or_hash_is_integrity(self) -> None:
        self.advance()
        for bad in (
            (2, "a" * 64),  # unknown hash at a known height
            (9, "a" * 64),  # unknown height and hash
        ):
            with self.subTest(bad=bad):
                self.assert_error(self.finalize(bad[0], bad[1]), ERR_INTEGRITY)

    def test_pending_tip_is_integrity(self) -> None:
        self.advance()
        # Height 4 is the pending tip: not a confirmed header.
        self.assert_error(self.finalize(4, self.tip_hash), ERR_INTEGRITY)

    def test_above_tip_is_integrity(self) -> None:
        self.advance()
        self.assert_error(self.finalize(5, "a" * 64), ERR_INTEGRITY)

    def test_confirmed_tip_after_confirmation_is_owned(self) -> None:
        self.advance()
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        # The confirmation advance records the confirmed tip as a step.
        empty = self.page(4, self.tip_hash)
        result = advance_headers(
            self.path, [empty], None, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        finalized = self.finalize(4, self.tip_hash)
        self.assertTrue(finalized["ok"], finalized)
        self.assertEqual(finalized["finalized"], self.loc(4))


class FinalizeHeadersStateTests(FinalizeHeadersFixture):
    def test_corrupt_json_is_state_not_io(self) -> None:
        self.write_file("{not json")
        self.assert_error(self.finalize(0), ERR_STATE)

    def test_tampered_hash_is_state(self) -> None:
        self.advance()
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        self.write_file(data)
        self.assert_error(self.finalize(2), ERR_STATE)

    def test_tampered_finalized_ownership_is_state(self) -> None:
        self.advance()
        self.finalize(2)
        data = self.read_checkpoint()
        # Pin a boundary the replayed branch does not own.
        data["finalized"] = {"height": 2, "block_hash": "0" * 64}
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.finalize(3), ERR_STATE)

    def test_tampered_finalized_pending_tip_is_state(self) -> None:
        self.advance()
        data = self.read_checkpoint()
        # The pending tip is on the branch but not confirmed.
        data["finalized"] = {"height": 4, "block_hash": self.tip_hash}
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.finalize(2), ERR_STATE)

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        self.advance()
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        payload = json.dumps(data)
        self.write_file(payload)
        self.assert_error(self.finalize(2), ERR_STATE)
        # The corrupt file is left exactly in place.
        self.assertEqual(self.read_raw().decode("utf-8"), payload)


class FinalizeHeadersIoTests(FinalizeHeadersFixture):
    def test_missing_file_is_io(self) -> None:
        self.assert_error(self.finalize(0), ERR_IO)

    def test_unwritable_target_path_is_io(self) -> None:
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        self.assert_error(self.finalize(0, path=directory), ERR_IO)


class FinalizeHeadersReorgTests(FinalizeHeadersFixture):
    def finalize_confirmed_tip(self) -> None:
        """Checkpoint the chain, confirm the tip and finalize it.

        Leaves three steps — closing at (4, pending), (4, confirmed) and
        (5, pending) — with the finalized boundary at the confirmed
        height-4 tip.
        """
        self.advance()
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        confirmed = advance_headers(
            self.path, [empty], None, self.tip_hash, self.trust
        )
        self.assertTrue(confirmed["ok"], confirmed)
        self.assertEqual(self.finalize(4, self.tip_hash)["generation"], 3)
        # Extend the chain by one pending block and checkpoint it.
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.tip5 = self.store.tip_hash()
        page = self.page(4, self.tip_hash)
        extended = advance_headers(self.path, [page], None, self.tip5, self.trust)
        self.assertTrue(extended["ok"], extended)
        self.assertEqual(extended["generation"], 4)

    def test_reorg_before_finalized_boundary_is_integrity(self) -> None:
        self.finalize_confirmed_tip()
        before = self.read_raw()

        forked_tip = self.fork_tip()
        # The fork no longer carries the old height-5 hash; locators that
        # skip the finalized height-4 block anchor the batch at genesis —
        # a boundary before the finalized point.
        locators = [self.loc(5, self.tip5), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(0))
        result = reorg_headers(self.path, [page], locators, forked_tip, self.trust)
        self.assert_error(result, ERR_INTEGRITY)
        # The file and the generation are untouched.
        self.assertEqual(self.read_raw(), before)
        self.assertEqual(self.read_checkpoint()["generation"], 4)

    def test_reorg_at_finalized_boundary_is_accepted(self) -> None:
        self.finalize_confirmed_tip()

        forked_tip = self.fork_tip()
        # The boundary is exactly the finalized height-4 block.
        locators = [self.loc(5, self.tip5), self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(4, self.tip_hash))
        result = reorg_headers(self.path, [page], locators, forked_tip, self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 5)
        self.assertEqual(result["replaced"], 1)
        data = self.read_checkpoint()
        # The finalized boundary survives the reorg.
        self.assertEqual(data["finalized"], self.loc(4))
        self.assertEqual(data["tip"]["tip_hash"], forked_tip)

    def test_reorg_after_finalized_boundary_is_accepted(self) -> None:
        self.finalize_confirmed_tip()
        # Extend the checkpoint by one more pending block at height 6.
        self.assertEqual(self.service.confirm_block("5")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(8))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip6 = self.store.tip_hash()
        page = self.page(5, self.tip5)
        extended = advance_headers(self.path, [page], None, tip6, self.trust)
        self.assertTrue(extended["ok"], extended)

        # Re-mine a divergent height-6 block: the fork point is the
        # height-5 step tip, a branch point after the finalized boundary.
        self.assertEqual(self.service.rollback_block("6")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(9))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        forked_tip = self.store.tip_hash()
        self.assertNotEqual(forked_tip, tip6)
        locators = [self.loc(6, tip6), self.loc(5, self.tip5), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(5, self.tip5))
        result = reorg_headers(self.path, [page], locators, forked_tip, self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(self.read_checkpoint()["finalized"], self.loc(4))


if __name__ == "__main__":
    unittest.main(verbosity=2)
