"""Tests for the atomic header-checkpoint reorganization plus finality
application (``ledger.light_client.reorg_finalized_headers``).

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers``, then rolls the pending tip back
and re-mines a divergent block so a locator batch describes a genuine
reorg, and covers:

* the reorg_headers batch contract (last-matching-step boundary or the
  initial anchor, the finalized-history guard, suffix deletion reported
  as ``replaced`` and the appended ``locator`` step) combined with the
  apply_finalities credential contract in one write — exactly one
  generation bump and a version-3 file with the last credential's
  boundary;
* the success result key order
  ``ok, generation, tip, finalized, replaced, applied`` with ``applied``
  the number of credentials;
* a different batch appending one locator step and writing the last
  boundary (generation + 1); an exact repeat of the last locator step
  neither re-verifying nor appending — fully idempotent (file bytes
  untouched, ``replaced: 0``) when the boundary also matches, otherwise
  only advancing the boundary with ``replaced: 0``;
* processing order input -> state/io -> auth -> integrity, including
  credential tip/status matching on the reorganized branch, strictly
  increasing finalized heights, non-decreasing tip heights, targets only
  the anchor or a confirmed header no higher than their own tip, and the
  final target never regressing or moving sideways;
* error categories ``input`` (parameters, arrays or document
  shape/types), ``auth`` (unknown key version or bad signature),
  ``integrity`` (finality, boundary, chain, tip, ordering, branch or
  boundary defects), ``state`` (a corrupt checkpoint, never truncated or
  rebuilt) and ``io`` (missing or unwritable file) — a failed call never
  changes the file bytes or the generation and nothing is raised.

Run: python3 tests/light_client_reorg_finalized_headers_test.py
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
    finalize_headers,
    reorg_finalized_headers,
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
STEP_KEYS = ["kind", "tip_hash", "trust", "documents", "locators"]
ANCHOR_KEYS = ["height", "block_hash"]
TIP_KEYS = ["tip_hash", "height", "length", "status"]
RESULT_KEYS = ["ok", "generation", "tip", "finalized", "replaced", "applied"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class ReorgFinalizedFixture(unittest.TestCase):
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
        self.old_tip = self.store.tip_hash()
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
        return {"height": height, "block_hash": block_hash or self.h(height)}

    def descriptor(self, height: int) -> dict:
        block = self.store.chain[height]
        return {
            "tip_hash": block.block_hash,
            "height": height,
            "length": height + 1,
            "status": block.status,
        }

    def finality(
        self,
        fin_height: int,
        tip_height: int | None = None,
        tip_hash: str | None = None,
        status: str | None = None,
        version=None,
    ) -> dict:
        """A validly signed credential finalizing ``fin_height`` at the
        ``tip_height`` descriptor (default: the current chain tip)."""
        if tip_height is None:
            tip_height = self.store.tip().height
        tip = self.descriptor(tip_height)
        if tip_hash is not None:
            tip["tip_hash"] = tip_hash
        if status is not None:
            tip["status"] = status
        finalized = self.loc(fin_height)
        signer = self.store.audit_signer
        envelope = sign_finality(
            signer["private_key"],
            signer["version"] if version is None else version,
            finalized,
            tip,
        )
        self.assertIsNotNone(envelope)
        return {"finalized": finalized, "tip": tip, "auth": envelope}

    def page(self, height, block_hash, limit=None) -> dict:
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit: int, anchor=None) -> list:
        """The whole chain from ``anchor`` (default genesis) in pages."""
        documents = []
        anchor = self.anchor if anchor is None else anchor
        tip_hash = self.store.tip_hash()
        while True:
            pg = self.page(anchor["height"], anchor["block_hash"], limit)
            documents.append(pg)
            if not pg["headers"]:
                break
            last = pg["headers"][-1]
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

    def fork_tip(self, amount: int = 6) -> str:
        """Roll the pending tip back and re-mine a divergent pending block."""
        height = self.store.tip().height
        self.assertEqual(self.service.rollback_block(str(height))[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(amount))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        new_tip_hash = self.store.tip_hash()
        self.assertNotEqual(new_tip_hash, self.old_tip)
        return new_tip_hash

    def call(
        self,
        documents,
        finalities,
        locators,
        tip_hash=None,
        trust=None,
        path=None,
    ):
        return reorg_finalized_headers(
            self.path if path is None else path,
            documents,
            finalities,
            locators,
            self.store.tip_hash() if tip_hash is None else tip_hash,
            self.trust if trust is None else trust,
        )

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def read_checkpoint(self) -> dict:
        return json.loads(self.read_raw())

    def write_file(self, data) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            if isinstance(data, str):
                fh.write(data)
            else:
                json.dump(data, fh)

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class ReorgFinalizedSuccessTests(ReorgFinalizedFixture):
    def test_reorg_and_finalize_in_one_generation(self) -> None:
        first = advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        self.assertEqual(first["generation"], 1)

        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        page = self.locate(locators)
        # The rolled-back tip no longer matches; the page anchors at genesis.
        self.assertEqual(page["anchor"], self.loc(0))
        finalities = [self.finality(0), self.finality(2), self.finality(3)]
        result = self.call([page], finalities, locators, tip_hash=forked_tip)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["tip"], page["tip"])
        self.assertEqual(result["tip"]["tip_hash"], forked_tip)
        self.assertEqual(result["tip"]["height"], 4)
        self.assertEqual(result["tip"]["status"], "pending")
        self.assertEqual(list(result["tip"].keys()), TIP_KEYS)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(list(result["finalized"].keys()), ANCHOR_KEYS)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["applied"], 3)

        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        data = json.loads(raw)
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 2)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["tip"], result["tip"])
        self.assertEqual(data["finalized"], self.loc(3))
        self.assertEqual(len(data["steps"]), 1)
        step = data["steps"][0]
        self.assertEqual(list(step.keys()), STEP_KEYS)
        self.assertEqual(step["kind"], "locator")
        self.assertEqual(step["tip_hash"], forked_tip)
        self.assertEqual(step["trust"], self.trust)
        self.assertEqual(step["documents"], [page])
        self.assertEqual(step["locators"], locators)

    def test_boundary_is_last_matching_step_tip(self) -> None:
        advance_headers(
            self.path, self.paged(4), self.anchor, self.old_tip, self.trust
        )
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip5 = self.store.tip_hash()
        second = advance_headers(
            self.path, [self.page(4, self.old_tip)], None, tip5, self.trust
        )
        self.assertEqual(second["generation"], 2)

        # Roll back only height 5 and re-mine it: the fork point is the
        # height-4 block, i.e. the first step's closing tip.
        forked_tip = self.fork_tip(amount=8)
        locators = [self.loc(5, tip5), self.loc(4, self.old_tip), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(4, self.old_tip))
        # Height 4 was recorded pending by step 0, so height 3 is the
        # confirmed finalized target on the reorganized branch.
        result = self.call(
            [page], [self.finality(3, tip_height=5)], locators,
            tip_hash=forked_tip,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["tip"]["tip_hash"], forked_tip)
        self.assertEqual(result["finalized"], self.loc(3))
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 3)
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual(
            [step["kind"] for step in data["steps"]], ["linear", "locator"]
        )

    def test_fully_idempotent_replay_holds_bytes_and_generation(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        page = self.locate(locators)
        finalities = [self.finality(0), self.finality(3)]
        first = self.call([page], finalities, locators, tip_hash=forked_tip)
        self.assertTrue(first["ok"], first)
        before = self.read_raw()
        replay = self.call(
            [copy.deepcopy(page)],
            [copy.deepcopy(document) for document in finalities],
            copy.deepcopy(locators),
            tip_hash=forked_tip,
        )
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(list(replay.keys()), RESULT_KEYS)
        self.assertEqual(replay["generation"], first["generation"])
        self.assertEqual(replay["tip"], first["tip"])
        self.assertEqual(replay["finalized"], first["finalized"])
        self.assertEqual(replay["replaced"], 0)
        self.assertEqual(replay["applied"], 2)
        self.assertEqual(self.read_raw(), before)

    def test_same_step_with_higher_boundary_only_advances_boundary(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        page = self.locate(locators)
        first = self.call(
            [page], [self.finality(0), self.finality(2)], locators,
            tip_hash=forked_tip,
        )
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["generation"], 2)
        self.assertEqual(first["replaced"], 1)
        self.assertEqual(first["finalized"], self.loc(2))
        self.assertEqual(len(self.read_checkpoint()["steps"]), 1)

        # The identical locator batch with a higher credential appends no
        # second step but still advances the boundary, once.
        second = self.call(
            [copy.deepcopy(page)],
            [self.finality(0), self.finality(2), self.finality(3)],
            copy.deepcopy(locators),
            tip_hash=forked_tip,
        )
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], 3)
        self.assertEqual(second["replaced"], 0)
        self.assertEqual(second["tip"], first["tip"])
        self.assertEqual(second["finalized"], self.loc(3))
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 3)
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(data["finalized"], self.loc(3))

        # Replaying that exact call is fully idempotent.
        raw = self.read_raw()
        third = self.call(
            [copy.deepcopy(page)],
            [self.finality(0), self.finality(2), self.finality(3)],
            copy.deepcopy(locators),
            tip_hash=forked_tip,
        )
        self.assertTrue(third["ok"], third)
        self.assertEqual(third["generation"], 3)
        self.assertEqual(third["replaced"], 0)
        self.assertEqual(self.read_raw(), raw)

    def test_different_batch_extending_fork_appends_with_replaced_zero(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        first = self.call(
            [self.locate(locators)], [self.finality(0)], locators,
            tip_hash=forked_tip,
        )
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["replaced"], 1)

        # Confirm the fork and extend it with a pending H5; a second,
        # different reorg batch anchored at H4 matches the last step tip,
        # so it appends another locator step and replaces nothing.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(9))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        forked_tip5 = self.store.tip_hash()
        locators2 = [self.loc(4, forked_tip), self.loc(0)]
        page2 = self.locate(locators2)
        self.assertEqual(page2["anchor"], self.loc(4, forked_tip))
        result = self.call(
            [page2], [self.finality(3, tip_height=5)], locators2,
            tip_hash=forked_tip5,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["replaced"], 0)
        self.assertEqual(result["finalized"], self.loc(3))
        data = self.read_checkpoint()
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual(
            [step["kind"] for step in data["steps"]], ["locator", "locator"]
        )

    def test_multi_page_locator_batch(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        first_page = self.locate(locators, limit=2)
        self.assertEqual(first_page["anchor"], self.loc(0))
        self.assertEqual(len(first_page["headers"]), 2)
        seam = first_page["headers"][-1]
        second_locators = [
            self.loc(seam["height"], seam["block_hash"]),
            self.loc(0),
        ]
        second_page = self.locate(second_locators, limit=2)
        result = self.call(
            [first_page, second_page],
            [self.finality(0), self.finality(3)],
            locators,
            tip_hash=forked_tip,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(result["tip"]["tip_hash"], forked_tip)


class ReorgFinalizedInputTests(ReorgFinalizedFixture):
    def test_path_must_be_a_non_empty_string(self) -> None:
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    reorg_finalized_headers(
                        bad_path, [{}], [{}], [], self.old_tip, self.trust
                    ),
                    ERR_INPUT,
                )

    def test_tip_hash_must_be_64_lower_hex(self) -> None:
        for bad_tip in (None, 7, "zz", "A" * 64, "a" * 63, "a" * 65, True):
            with self.subTest(bad_tip=bad_tip):
                self.assert_error(
                    reorg_finalized_headers(
                        self.path, [{}], [{}], [], bad_tip, self.trust
                    ),
                    ERR_INPUT,
                )

    def test_finalities_must_be_a_non_empty_array(self) -> None:
        self.assert_error(
            reorg_finalized_headers(
                self.path, [{}], [], [], self.old_tip, self.trust
            ),
            ERR_INPUT,
        )
        self.assert_error(
            reorg_finalized_headers(
                self.path, [{}], "x", [], self.old_tip, self.trust
            ),
            ERR_INPUT,
        )

    def test_malformed_credential_is_input_before_file(self) -> None:
        # A missing file must not turn a malformed credential into io:
        # structure precedes state.
        page = {"anchor": self.loc(0), "headers": [], "tip": {}, "auth": {}}
        self.assert_error(
            self.call([page], [{"finalized": {}}], [self.loc(0)]),
            ERR_INPUT,
        )
        self.assertFalse(os.path.exists(self.path))

    def test_malformed_locator_batch_is_input_before_file(self) -> None:
        for bad_documents, bad_locators in (
            ([], [self.loc(0)]),
            ([{"x": 1}], [self.loc(0)]),
            ([{}], []),
            ([{}], "x"),
            ([{}], [self.loc(0), self.loc(0)]),
        ):
            with self.subTest(bad=(bad_documents, bad_locators)):
                self.assert_error(
                    self.call(
                        bad_documents, [self.finality(0)], bad_locators
                    ),
                    ERR_INPUT,
                )
        self.assertFalse(os.path.exists(self.path))

    def test_bad_credential_key_order_and_types_are_input(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        good = self.finality(0)
        bad_order = {
            "tip": good["tip"],
            "finalized": good["finalized"],
            "auth": good["auth"],
        }
        bad_height = self.finality(0)
        bad_height["finalized"] = {"height": True, "block_hash": self.h(0)}
        bad_sig = self.finality(0)
        bad_sig["auth"] = {"key_version": 1, "signature": "zz"}
        for bad in (bad_order, bad_height, bad_sig):
            with self.subTest(bad=bad):
                self.assert_error(
                    self.call(
                        [self.locate(locators)], [bad], locators,
                        tip_hash=forked_tip,
                    ),
                    ERR_INPUT,
                )

    def test_garbage_never_raises(self) -> None:
        result = reorg_finalized_headers(
            self.path, object(), object(), object(), object(), object()
        )
        self.assert_error(result, ERR_INPUT)


class ReorgFinalizedStateIoTests(ReorgFinalizedFixture):
    def _one_reorg_setup(self):
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        return forked_tip, locators

    def test_missing_file_is_io(self) -> None:
        # Well-formed batch and credentials, but no checkpoint exists yet.
        page_doc = self.locate([self.loc(3), self.loc(0)])
        self.assert_error(
            self.call(
                [page_doc], [self.finality(3)], [self.loc(3), self.loc(0)]
            ),
            ERR_IO,
        )

    def test_unparseable_checkpoint_is_state(self) -> None:
        forked_tip, locators = self._one_reorg_setup()
        self.write_file("{not json")
        self.assert_error(
            self.call(
                [self.locate(locators)], [self.finality(0)], locators,
                tip_hash=forked_tip,
            ),
            ERR_STATE,
        )

    def test_tampered_checkpoint_is_state_and_never_truncated(self) -> None:
        forked_tip, locators = self._one_reorg_setup()
        data = self.read_checkpoint()
        payload = json.dumps(data)
        data["hash"] = "1" * 64
        tampered = json.dumps(data)
        self.write_file(tampered)
        self.assert_error(
            self.call(
                [self.locate(locators)], [self.finality(0)], locators,
                tip_hash=forked_tip,
            ),
            ERR_STATE,
        )
        # The corrupt file is left exactly in place.
        self.assertEqual(self.read_raw().decode("utf-8"), tampered)
        self.assertNotEqual(tampered, payload)

    def test_unwritable_path_is_io(self) -> None:
        forked_tip, locators = self._one_reorg_setup()
        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "w", encoding="utf-8") as fh:
            fh.write("x")
        self.assert_error(
            self.call(
                [self.locate(locators)],
                [self.finality(0)],
                locators,
                tip_hash=forked_tip,
                path=os.path.join(blocker, "c.json"),
            ),
            ERR_IO,
        )


class ReorgFinalizedAuthTests(ReorgFinalizedFixture):
    def test_unknown_finality_key_version_is_auth(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        self.assert_error(
            self.call(
                [self.locate(locators)],
                [self.finality(0, version=99)],
                locators,
                tip_hash=forked_tip,
            ),
            ERR_AUTH,
        )

    def test_bad_finality_signature_is_auth(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        credential = self.finality(0)
        credential["auth"] = {
            "key_version": credential["auth"]["key_version"],
            "signature": "0" * 128,
        }
        before = self.read_raw()
        self.assert_error(
            self.call(
                [self.locate(locators)], [credential], locators,
                tip_hash=forked_tip,
            ),
            ERR_AUTH,
        )
        self.assertEqual(self.read_raw(), before)

    def test_bad_page_signature_is_auth(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        page = self.locate(locators)
        page["auth"]["signature"] = "0" * 128
        before = self.read_raw()
        self.assert_error(
            self.call(
                [page], [self.finality(0)], locators, tip_hash=forked_tip
            ),
            ERR_AUTH,
        )
        self.assertEqual(self.read_raw(), before)


class ReorgFinalizedIntegrityTests(ReorgFinalizedFixture):
    def test_anchor_before_finalized_is_integrity(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        raised = finalize_headers(self.path, 2, self.h(2))
        self.assertTrue(raised["ok"], raised)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        before = self.read_raw()
        # The locate page anchors at genesis, height 0 < finalized 2.
        self.assert_error(
            self.call(
                [self.locate(locators)], [self.finality(0)], locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), before)

    def test_credential_tip_on_the_pruned_fork_is_integrity(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        # The credential describes the OLD pending tip the reorg prunes.
        credential = self.finality(
            0, tip_height=4, tip_hash=self.old_tip, status="pending"
        )
        self.assert_error(
            self.call(
                [self.locate(locators)], [credential], locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )

    def test_credential_tip_status_must_match(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        # The forked height-4 tip is pending; claim it confirmed.
        credential = self.finality(0, status="confirmed")
        self.assert_error(
            self.call(
                [self.locate(locators)], [credential], locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )

    def test_pending_finalized_target_is_integrity(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        self.assert_error(
            self.call(
                [self.locate(locators)], [self.finality(4)], locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )

    def test_finalized_heights_must_strictly_increase(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        for pair in (
            [self.finality(2), self.finality(2)],
            [self.finality(2), self.finality(1)],
        ):
            with self.subTest(pair=pair):
                self.assert_error(
                    self.call(
                        [self.locate(locators)], pair, locators,
                        tip_hash=forked_tip,
                    ),
                    ERR_INTEGRITY,
                )

    def test_tip_heights_must_not_decrease(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        self.assert_error(
            self.call(
                [self.locate(locators)],
                [self.finality(0), self.finality(1, tip_height=2)],
                locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )

    def test_target_must_not_cross_its_own_tip(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        self.assert_error(
            self.call(
                [self.locate(locators)],
                [self.finality(3, tip_height=2)],
                locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )

    def test_last_target_must_not_move_sideways(self) -> None:
        # Two linear steps (tips H4 then H5), boundary raised to H2.
        advance_headers(
            self.path, self.paged(4), self.anchor, self.old_tip, self.trust
        )
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip5 = self.store.tip_hash()
        advance_headers(
            self.path, [self.page(4, self.old_tip)], None, tip5, self.trust
        )
        raised = finalize_headers(self.path, 2, self.h(2))
        self.assertTrue(raised["ok"], raised)

        # Fork at H5; the locator batch anchors at H4 (>= finalized H2).
        forked_tip5 = self.fork_tip(amount=8)
        locators = [
            self.loc(5, tip5), self.loc(4, self.old_tip), self.loc(0)
        ]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(4, self.old_tip))
        credential = self.finality(2)
        credential["finalized"] = {"height": 2, "block_hash": "0" * 64}
        signer = self.store.audit_signer
        credential["auth"] = sign_finality(
            signer["private_key"],
            signer["version"],
            credential["finalized"],
            credential["tip"],
        )
        before = self.read_raw()
        self.assert_error(
            self.call([page], [credential], locators, tip_hash=forked_tip5),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), before)

    def test_lower_new_tip_is_integrity(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        before = self.read_raw()
        # Roll the pending tip back without re-mining: the tip drops to H3.
        self.assertEqual(self.service.rollback_block("4")[0], 200)
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["tip"]["height"], 3)
        self.assert_error(
            self.call(
                [page],
                [self.finality(3, tip_height=3)],
                locators,
                tip_hash=page["tip"]["tip_hash"],
            ),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), before)

    def test_failed_call_never_bumps_generation(self) -> None:
        advance_headers(
            self.path, self.paged(2), self.anchor, self.old_tip, self.trust
        )
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip), self.loc(0)]
        # A pending finalized target is integrity and leaves the file.
        self.assert_error(
            self.call(
                [self.locate(locators)], [self.finality(4)], locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )
        # A valid call still lands at generation 2 with one replacement.
        result = self.call(
            [self.locate(locators)], [self.finality(0)], locators,
            tip_hash=forked_tip,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["replaced"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
