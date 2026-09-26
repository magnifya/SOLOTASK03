"""Tests for the durable header-checkpoint reorganization
(``ledger.light_client.reorg_headers``).

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers``, then rolls the pending tip back and
re-mines a divergent block so a locator batch describes a genuine reorg.
Covers:

* the reorg boundary (the last stored step whose closing tip matches the
  batch anchor, else the checkpoint's initial anchor), the dropped suffix
  count reported as ``replaced`` and the appended ``locator`` step;
* the v3 file shape: top-level key order ``v, generation, anchor, tip,
  finalized, steps, hash`` with ``v = 3`` and step key order
  ``kind, tip_hash, trust, documents, locators`` (``linear`` steps carry
  ``locators: null``), the self-excluding canonical-json SHA-256 ``hash``,
  and a generation that may exceed the step count after a replacement;
* tip rules: the new tip never drops in height, a same-height different
  hash is accepted in either status, the same hash only moves
  ``pending -> confirmed`` and anything else is ``integrity``;
* idempotent replay of the exact last locator step (``replaced: 0``, no
  write, no generation bump) and mixed linear/locator histories continuing
  through ``advance_headers`` and ``header_locators``;
* error categories ``input`` (arguments, locator/batch shape), ``auth``
  (signer version or signature), ``integrity`` (boundary, chain, height or
  same-height conflicts), ``state`` (a corrupt existing checkpoint, never
  truncated or rebuilt) and ``io`` (a missing or unreadable file).

Run: python3 tests/light_client_reorg_headers_test.py
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
    header_locators,
    reorg_headers,
    sign_header_page,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

CHECKPOINT_KEYS = ["v", "generation", "anchor", "tip", "finalized", "steps", "hash"]
STEP_KEYS = ["kind", "tip_hash", "trust", "documents", "locators"]
V1_STEP_KEYS = ["tip_hash", "trust", "documents"]

_DEFAULT = object()


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class ReorgHeadersFixture(unittest.TestCase):
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

    def advance(self, documents, anchor, tip_hash=_DEFAULT, trust=None):
        return advance_headers(
            self.path,
            documents,
            anchor,
            self.store.tip_hash() if tip_hash is _DEFAULT else tip_hash,
            self.trust if trust is None else trust,
        )

    def reorg(self, documents, locators, tip_hash=_DEFAULT, trust=None, path=None):
        return reorg_headers(
            self.path if path is None else path,
            documents,
            locators,
            self.store.tip_hash() if tip_hash is _DEFAULT else tip_hash,
            self.trust if trust is None else trust,
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

    def rotate_signer(self) -> dict:
        """Rotate the audit signer and return the updated trust document."""
        seed = crypto.generate_private_key()
        status, _ = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        return self.service.get_trust_document()[1]

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class ReorgHeadersSuccessTests(ReorgHeadersFixture):
    def test_reorg_replaces_suffix_and_appends_locator_step(self) -> None:
        documents = self.paged(2)
        first = self.advance(documents, self.anchor, tip_hash=self.tip_hash)
        self.assertEqual(first["generation"], 1)

        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        # The rolled-back tip no longer matches; the page anchors at genesis.
        self.assertEqual(page["anchor"], self.loc(0))
        result = self.reorg([page], locators, tip_hash=forked_tip)
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result.keys()), ["ok", "generation", "tip", "replaced"]
        )
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["tip"], page["tip"])
        self.assertEqual(result["tip"]["height"], 4)
        self.assertEqual(result["tip"]["tip_hash"], forked_tip)
        self.assertEqual(result["tip"]["status"], "pending")

        data = self.read_checkpoint()
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 2)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["finalized"], self.anchor)
        self.assertEqual(data["tip"], result["tip"])
        # The boundary is the initial anchor, so the one stored linear step
        # is dropped and only the appended locator step remains.
        self.assertEqual(len(data["steps"]), 1)
        locator = data["steps"][0]
        self.assertEqual(list(locator.keys()), STEP_KEYS)
        self.assertEqual(locator["kind"], "locator")
        self.assertEqual(locator["tip_hash"], forked_tip)
        self.assertEqual(locator["trust"], self.trust)
        self.assertEqual(locator["documents"], [page])
        self.assertEqual(locator["locators"], locators)
        body = {key: data[key] for key in CHECKPOINT_KEYS if key != "hash"}
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)

    def test_boundary_is_last_matching_step_tip(self) -> None:
        self.advance(self.paged(4), self.anchor, tip_hash=self.tip_hash)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip5 = self.store.tip_hash()
        second = self.advance([self.page(4, self.tip_hash)], None, tip_hash=tip5)
        self.assertEqual(second["generation"], 2)

        # Roll back only height 5 and re-mine it: the fork point is the
        # confirmed height-4 block, i.e. the first step's closing tip.
        forked_tip = self.fork_tip(amount=8)
        locators = [self.loc(5, tip5), self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(4, self.tip_hash))
        result = self.reorg([page], locators, tip_hash=forked_tip)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["tip"]["height"], 5)
        self.assertEqual(result["tip"]["tip_hash"], forked_tip)

        data = self.read_checkpoint()
        # The generation outruns the step count: one step was replaced.
        self.assertEqual(data["generation"], 3)
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual(
            [step["kind"] for step in data["steps"]], ["linear", "locator"]
        )
        self.assertEqual(data["steps"][0]["tip_hash"], self.tip_hash)
        self.assertEqual(data["steps"][1]["tip_hash"], forked_tip)
        # The mixed history strictly replays on the next read.
        derived = header_locators(self.path)
        self.assertTrue(derived["ok"], derived)
        self.assertEqual(derived["tip"], result["tip"])
        heights = [item["height"] for item in derived["request"]["locators"]]
        self.assertEqual(heights, sorted(heights, reverse=True))

    def test_multi_page_locator_batch(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        first_page = self.locate(locators, limit=2)
        self.assertEqual(first_page["anchor"], self.loc(0))
        self.assertEqual(len(first_page["headers"]), 2)
        seam = first_page["headers"][-1]
        second_locators = [
            self.loc(seam["height"], seam["block_hash"]),
            self.loc(0),
        ]
        second_page = self.locate(second_locators, limit=2)
        result = self.reorg(
            [first_page, second_page], locators, tip_hash=forked_tip
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["tip"]["tip_hash"], forked_tip)

    def test_same_height_same_hash_pending_to_confirmed(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        result = self.reorg([self.locate(locators)], locators, tip_hash=forked_tip)
        self.assertEqual(result["tip"]["status"], "pending")

        # Confirm the forked tip: a locator batch naming the same hash may
        # move it pending -> confirmed without replacing anything.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        confirm_locators = [self.loc(4, forked_tip), self.loc(0)]
        empty = self.locate(confirm_locators)
        self.assertEqual(empty["headers"], [])
        self.assertEqual(empty["tip"]["status"], "confirmed")
        confirmed = self.reorg([empty], confirm_locators, tip_hash=forked_tip)
        self.assertTrue(confirmed["ok"], confirmed)
        self.assertEqual(confirmed["generation"], 3)
        self.assertEqual(confirmed["replaced"], 0)
        self.assertEqual(confirmed["tip"]["status"], "confirmed")
        self.assertEqual(self.read_checkpoint()["tip"]["status"], "confirmed")

    def test_idempotent_replay_of_last_locator_step(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        first = self.reorg([page], locators, tip_hash=forked_tip)
        self.assertEqual(first["generation"], 2)
        before = self.read_raw()
        replay = self.reorg(
            [copy.deepcopy(page)], copy.deepcopy(locators), tip_hash=forked_tip
        )
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], 2)
        self.assertEqual(replay["replaced"], 0)
        self.assertEqual(replay["tip"], first["tip"])
        # The file bytes stay exactly as they were.
        self.assertEqual(self.read_raw(), before)

    def test_advance_after_reorg_appends_linear_step(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        self.reorg([self.locate(locators)], locators, tip_hash=forked_tip)

        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip5 = self.store.tip_hash()
        page = self.page(4, forked_tip)
        result = self.advance([page], None, tip_hash=tip5)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        data = self.read_checkpoint()
        # The reorg replaced the only linear step, so the history is the
        # locator step plus the freshly appended linear one.
        self.assertEqual(
            [step["kind"] for step in data["steps"]],
            ["locator", "linear"],
        )
        self.assertEqual(data["steps"][1]["documents"], [page])
        self.assertIsNone(data["steps"][1]["locators"])

    def test_version_one_checkpoint_reorgs_and_rewrites_as_v3(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
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

        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        result = self.reorg([self.locate(locators)], locators, tip_hash=forked_tip)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["replaced"], 1)
        rewritten = self.read_checkpoint()
        self.assertEqual(rewritten["v"], 3)
        self.assertEqual(rewritten["finalized"], self.anchor)
        # The legacy linear step was replaced at the initial anchor.
        self.assertEqual(
            [list(step.keys()) for step in rewritten["steps"]], [STEP_KEYS]
        )
        self.assertEqual(
            [step["kind"] for step in rewritten["steps"]], ["locator"]
        )


class ReorgHeadersInputTests(ReorgHeadersFixture):
    def test_path_must_be_a_non_empty_string(self) -> None:
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    reorg_headers(bad_path, [], [], self.tip_hash, self.trust),
                    ERR_INPUT,
                )

    def test_tip_hash_must_be_64_lower_hex(self) -> None:
        for bad_tip in (None, 7, "zz", "A" * 64, "a" * 63, "a" * 65, True):
            with self.subTest(bad_tip=bad_tip):
                self.assert_error(self.reorg([], [], tip_hash=bad_tip), ERR_INPUT)

    def test_bad_locators_are_input(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        page = self.locate([self.loc(4), self.loc(0)])
        for bad_locators in (
            None,
            "x",
            [],
            [self.loc(0), self.loc(4)],  # not strictly descending
            [self.loc(4), self.loc(4)],  # duplicate heights
            [{"height": 4, "block_hash": "zz"}],
            [{"block_hash": self.tip_hash, "height": 4}],  # key order
            [self.loc(4, "a" * 64)] * 2,  # duplicate heights again
            [self.loc(0)] * 65,  # too many items
        ):
            with self.subTest(bad_locators=bad_locators):
                self.assert_error(
                    self.reorg([page], bad_locators), ERR_INPUT
                )

    def test_bad_documents_are_input(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        locators = [self.loc(4), self.loc(0)]
        page = self.locate(locators)
        for bad_documents in (None, "x", [], [page, "y"]):
            with self.subTest(bad_documents=bad_documents):
                self.assert_error(
                    self.reorg(bad_documents, locators), ERR_INPUT
                )

    def test_never_raises_on_garbage(self) -> None:
        result = reorg_headers(self.path, object(), object(), object(), object())
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})


class ReorgHeadersVerificationTests(ReorgHeadersFixture):
    def test_auth_failure_unknown_key_version(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        page["auth"] = {"key_version": 9, "signature": "0" * 128}
        self.assert_error(
            self.reorg([page], locators, tip_hash=forked_tip), ERR_AUTH
        )

    def test_auth_failure_bad_signature(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        page["auth"]["signature"] = "0" * 128
        self.assert_error(
            self.reorg([page], locators, tip_hash=forked_tip), ERR_AUTH
        )

    def test_integrity_failure_on_tampered_header(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        page["headers"][0]["block_hash"] = "f" * 64
        self.re_sign(page)
        self.assert_error(
            self.reorg([page], locators, tip_hash=forked_tip), ERR_INTEGRITY
        )

    def test_boundary_anchor_outside_history_is_integrity(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        # A well-signed empty page anchored at a block the checkpoint never
        # recorded: the locator batch verifies, but no stored step tip and
        # not the initial anchor can bound the reorg.
        forged = "a" * 64
        document = {
            "anchor": {"height": 4, "block_hash": forged},
            "headers": [],
            "tip": {
                "tip_hash": forged,
                "height": 4,
                "length": 5,
                "status": "pending",
            },
        }
        self.re_sign(document)
        locators = [{"height": 4, "block_hash": forged}, self.loc(0)]
        self.assert_error(
            self.reorg([document], locators, tip_hash=forged), ERR_INTEGRITY
        )

    def test_lower_tip_is_integrity_and_preserves_bytes(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        before = self.read_raw()
        # Roll the pending tip back without re-mining: the chain tip drops
        # to height 3, below the stored tip.
        self.assertEqual(self.service.rollback_block("4")[0], 200)
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["tip"]["height"], 3)
        self.assert_error(
            self.reorg([page], locators, tip_hash=page["tip"]["tip_hash"]),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), before)

    def test_same_height_same_hash_pending_to_pending_is_integrity(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        result = self.reorg([self.locate(locators)], locators, tip_hash=forked_tip)
        self.assertEqual(result["tip"]["status"], "pending")
        # A different batch (rotated signer) naming the same pending tip.
        rotated = self.rotate_signer()
        confirm_locators = [self.loc(4, forked_tip), self.loc(0)]
        empty = self.locate(confirm_locators)
        self.assertEqual(empty["tip"]["status"], "pending")
        self.assert_error(
            self.reorg([empty], confirm_locators, tip_hash=forked_tip, trust=rotated),
            ERR_INTEGRITY,
        )

    def test_same_height_same_hash_confirmed_to_confirmed_is_integrity(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        self.reorg([self.locate(locators)], locators, tip_hash=forked_tip)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        confirm_locators = [self.loc(4, forked_tip), self.loc(0)]
        confirmed = self.reorg(
            [self.locate(confirm_locators)], confirm_locators, tip_hash=forked_tip
        )
        self.assertEqual(confirmed["tip"]["status"], "confirmed")
        # A different batch (rotated signer) naming the same confirmed tip.
        rotated = self.rotate_signer()
        empty = self.locate(confirm_locators)
        self.assert_error(
            self.reorg([empty], confirm_locators, tip_hash=forked_tip, trust=rotated),
            ERR_INTEGRITY,
        )

    def test_failed_reorg_never_bumps_generation(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.tip_hash), self.loc(0)]
        tampered = self.locate(locators)
        tampered["auth"] = {"key_version": 7, "signature": "0" * 128}
        before = self.read_raw()
        self.assert_error(
            self.reorg([tampered], locators, tip_hash=forked_tip), ERR_AUTH
        )
        self.assertEqual(self.read_raw(), before)
        # A valid reorg still lands at generation 2.
        result = self.reorg([self.locate(locators)], locators, tip_hash=forked_tip)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)


class ReorgHeadersStateTests(ReorgHeadersFixture):
    def test_missing_file_is_io(self) -> None:
        locators = [self.loc(4), self.loc(0)]
        page = self.locate(locators)
        self.assert_error(self.reorg([page], locators), ERR_IO)

    def test_unreadable_path_is_io(self) -> None:
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        locators = [self.loc(4), self.loc(0)]
        page = self.locate(locators)
        self.assert_error(
            self.reorg([page], locators, path=directory), ERR_IO
        )

    def test_corrupt_json_is_state_not_io(self) -> None:
        self.write_file("{not json")
        locators = [self.loc(4), self.loc(0)]
        self.assert_error(self.reorg([self.locate(locators)], locators), ERR_STATE)

    def test_tampered_hash_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        self.write_file(data)
        locators = [self.loc(4), self.loc(0)]
        self.assert_error(self.reorg([self.locate(locators)], locators), ERR_STATE)

    def test_tampered_step_kind_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        data = self.read_checkpoint()
        # A linear step flipped to a locator step without locators.
        data["steps"][0]["kind"] = "locator"
        self.rehash(data)
        self.write_file(data)
        locators = [self.loc(4), self.loc(0)]
        self.assert_error(self.reorg([self.locate(locators)], locators), ERR_STATE)

    def test_tampered_step_documents_replay_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        data = self.read_checkpoint()
        data["steps"][0]["documents"][0]["headers"][0]["block_hash"] = "0" * 64
        self.rehash(data)
        self.write_file(data)
        locators = [self.loc(4), self.loc(0)]
        self.assert_error(self.reorg([self.locate(locators)], locators), ERR_STATE)

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        self.advance(self.paged(2), self.anchor, tip_hash=self.tip_hash)
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        payload = json.dumps(data)
        self.write_file(payload)
        locators = [self.loc(4), self.loc(0)]
        self.assert_error(self.reorg([self.locate(locators)], locators), ERR_STATE)
        # The corrupt file is left exactly in place.
        self.assertEqual(self.read_raw().decode("utf-8"), payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
