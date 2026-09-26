"""Tests for the durable header-page checkpoint
(``ledger.light_client.advance_headers``).

Builds a confirmed chain with a pending tip through the real service, pages
it through GET /v1/chain/headers and covers:

* a first advance from a legal anchor and later advances with ``None`` or
  the stored tip's ``{height, block_hash}``;
* file shape: exact top-level key order ``v, generation, anchor, tip, steps,
  hash``, step key order ``kind, tip_hash, trust, documents, locators`` with
  ``kind: "linear"`` and ``locators: null``, compact UTF-8 JSON with
  non-ASCII unescaped and one trailing newline, and the self-excluding
  canonical-json SHA-256 ``hash``;
* generation starting at 1 and incremented only on a successful advance (a
  failed verification never bumps it), tip monotonicity (never lower; same
  height only pending -> confirmed with the same block hash) and the
  idempotent exact-replay of the last batch;
* success result key order ``ok, generation, tip``;
* error categories ``input`` (bad path/tip_hash/anchor), ``auth``
  (signature), ``integrity`` (batch or tip conflicts), ``state`` (existing
  checkpoint key order, types, hash or replay mismatch; the file is never
  truncated or rebuilt) and ``io``.

Run: python3 tests/light_client_advance_headers_test.py
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
    sign_header_page,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

CHECKPOINT_KEYS = ["v", "generation", "anchor", "tip", "steps", "hash"]
STEP_KEYS = ["kind", "tip_hash", "trust", "documents", "locators"]
V1_STEP_KEYS = ["tip_hash", "trust", "documents"]
ANCHOR_KEYS = ["height", "block_hash"]
TIP_KEYS = ["tip_hash", "height", "length", "status"]

_DEFAULT = object()


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class AdvanceHeadersFixture(unittest.TestCase):
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

    def advance(self, documents, anchor, tip_hash=_DEFAULT, trust=None, path=None):
        return advance_headers(
            self.path if path is None else path,
            documents,
            anchor,
            self.store.tip_hash() if tip_hash is _DEFAULT else tip_hash,
            self.trust if trust is None else trust,
        )

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
        body = {key: data[key] for key in CHECKPOINT_KEYS if key != "hash"}
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


class AdvanceHeadersSuccessTests(AdvanceHeadersFixture):
    def test_first_advance_writes_generation_one_and_expected_shape(self) -> None:
        documents = self.paged(2)
        result = self.advance(documents, self.anchor, tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), ["ok", "generation", "tip"])
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["tip"], documents[0]["tip"])
        self.assertEqual(result["tip"]["height"], 4)
        self.assertEqual(result["tip"]["status"], "pending")

        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        data = json.loads(raw)
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 2)
        self.assertEqual(data["generation"], 1)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(list(data["anchor"].keys()), ANCHOR_KEYS)
        self.assertEqual(data["tip"], result["tip"])
        self.assertEqual(list(data["tip"].keys()), TIP_KEYS)
        self.assertEqual(len(data["steps"]), 1)
        step = data["steps"][0]
        self.assertEqual(list(step.keys()), STEP_KEYS)
        self.assertEqual(step["kind"], "linear")
        self.assertEqual(step["tip_hash"], self.tip_hash)
        self.assertEqual(step["trust"], self.trust)
        self.assertEqual(step["documents"], documents)
        self.assertIsNone(step["locators"])

    def test_hash_covers_every_field_but_itself(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        body = {key: data[key] for key in CHECKPOINT_KEYS if key != "hash"}
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)
        self.assertRegex(data["hash"], r"^[0-9a-f]{64}$")

    def test_file_is_compact_unescaped_utf8(self) -> None:
        # A non-ASCII trust key is stored verbatim and written unescaped.
        trust = dict(self.trust)
        trust["备注"] = "节点-δ"
        result = self.advance(self.paged(4), self.anchor, trust=trust)
        self.assertTrue(result["ok"], result)
        raw = self.read_raw()
        self.assertIn("节点-δ".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertTrue(raw.endswith(b"\n"))

    def test_continue_with_none_anchor_chains_from_stored_tip(self) -> None:
        first = self.advance(self.paged(2), self.anchor)
        self.assertEqual(first["generation"], 1)
        # Confirm the pending tip and extend the chain by one pending block.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        new_tip_hash = self.store.tip_hash()
        page = self.page(4, self.tip_hash)
        second = self.advance([page], None, tip_hash=new_tip_hash)
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], 2)
        self.assertEqual(second["tip"]["height"], 5)
        self.assertEqual(second["tip"]["tip_hash"], new_tip_hash)

        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 2)
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual([list(step.keys()) for step in data["steps"]],
                         [STEP_KEYS, STEP_KEYS])
        # The file anchor stays the first advance's pinned anchor.
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["tip"], second["tip"])
        self.assertEqual(data["steps"][1]["documents"], [page])
        self.assertEqual(data["steps"][1]["tip_hash"], new_tip_hash)

    def test_continue_with_explicit_stored_tip_anchor(self) -> None:
        self.advance(self.paged(2), self.anchor)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        new_tip_hash = self.store.tip_hash()
        page = self.page(4, self.tip_hash)
        stored = {"height": 4, "block_hash": self.tip_hash}
        result = self.advance([page], stored, tip_hash=new_tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)

    def test_same_height_pending_to_confirmed_advances(self) -> None:
        self.advance(self.paged(2), self.anchor)
        # Confirm the pending tip: the chain tip keeps its height and hash.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.store.tip_hash(), self.tip_hash)
        empty = self.page(4, self.tip_hash)
        self.assertEqual(empty["headers"], [])
        self.assertEqual(empty["tip"]["status"], "confirmed")
        result = self.advance([empty], None, tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["tip"]["height"], 4)
        self.assertEqual(result["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(result["tip"]["status"], "confirmed")
        self.assertEqual(self.read_checkpoint()["tip"]["status"], "confirmed")

    def test_exact_last_batch_replay_is_idempotent(self) -> None:
        documents = self.paged(2)
        first = self.advance(documents, self.anchor, tip_hash=self.tip_hash)
        self.assertEqual(first["generation"], 1)
        before = self.read_raw()
        replay = self.advance(
            copy.deepcopy(documents), None, tip_hash=self.tip_hash
        )
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], 1)
        self.assertEqual(replay["tip"], first["tip"])
        # The file bytes stay exactly as they were.
        self.assertEqual(self.read_raw(), before)
        # The same holds when the stored tip anchor is pinned explicitly.
        replay = self.advance(
            copy.deepcopy(documents),
            {"height": 4, "block_hash": self.tip_hash},
            tip_hash=self.tip_hash,
        )
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], 1)
        self.assertEqual(self.read_raw(), before)

    def test_idempotent_replay_of_confirmation_batch(self) -> None:
        self.advance(self.paged(2), self.anchor)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        confirmed = self.advance([empty], None, tip_hash=self.tip_hash)
        self.assertEqual(confirmed["generation"], 2)
        before = self.read_raw()
        replay = self.advance([copy.deepcopy(empty)], None, tip_hash=self.tip_hash)
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], 2)
        self.assertEqual(replay["tip"]["status"], "confirmed")
        self.assertEqual(self.read_raw(), before)

    def test_failed_verification_never_bumps_generation(self) -> None:
        self.advance(self.paged(2), self.anchor)
        before = self.read_raw()
        tampered = copy.deepcopy(self.paged(2))
        tampered[0]["auth"] = {"key_version": 7, "signature": "0" * 128}
        self.assert_error(self.advance(tampered, None), ERR_AUTH)
        self.assertEqual(self.read_raw(), before)
        # A valid continuation still lands at generation 2.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        result = self.advance([empty], None, tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)

    def test_version_one_checkpoint_is_read_and_rewritten_as_v2(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        # Downgrade the file to the legacy version-1 shape: v=1 and steps
        # carrying only tip_hash, trust, documents.
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
        # The legacy file loads and replays; the next advance appends a
        # linear step and rewrites the file as version 2.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        result = self.advance([empty], None, tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        rewritten = self.read_checkpoint()
        self.assertEqual(rewritten["v"], 2)
        self.assertEqual(len(rewritten["steps"]), 2)
        self.assertEqual(
            [list(step.keys()) for step in rewritten["steps"]],
            [STEP_KEYS, STEP_KEYS],
        )
        self.assertEqual(
            [step["kind"] for step in rewritten["steps"]], ["linear", "linear"]
        )
        self.assertIsNone(rewritten["steps"][0]["locators"])


class AdvanceHeadersInputTests(AdvanceHeadersFixture):
    def test_path_must_be_a_non_empty_string(self) -> None:
        documents = self.paged(1)
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    advance_headers(
                        bad_path, documents, self.anchor, self.tip_hash, self.trust
                    ),
                    ERR_INPUT,
                )

    def test_tip_hash_must_be_64_lower_hex(self) -> None:
        documents = self.paged(1)
        for bad_tip in (None, 7, "zz", "A" * 64, "a" * 63, "a" * 65, True):
            with self.subTest(bad_tip=bad_tip):
                self.assert_error(
                    self.advance(documents, self.anchor, tip_hash=bad_tip),
                    ERR_INPUT,
                )

    def test_first_use_requires_a_legal_anchor(self) -> None:
        documents = self.paged(1)
        for bad_anchor in (
            None,
            {},
            {"height": 0},
            {"block_hash": self.genesis_hash, "height": 0},  # wrong key order
            {"height": True, "block_hash": self.genesis_hash},
            {"height": -1, "block_hash": self.genesis_hash},
            {"height": 0, "block_hash": "zz"},
            {"height": 0, "block_hash": self.genesis_hash, "x": 1},
        ):
            with self.subTest(bad_anchor=bad_anchor):
                self.assert_error(self.advance(documents, bad_anchor), ERR_INPUT)

    def test_later_anchor_must_be_none_or_the_stored_tip(self) -> None:
        self.advance(self.paged(2), self.anchor)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        # A legal anchor naming a block other than the stored tip is input.
        self.assert_error(self.advance([empty], self.anchor), ERR_INPUT)
        self.assert_error(
            self.advance([empty], {"height": 9, "block_hash": "a" * 64}),
            ERR_INPUT,
        )
        # Wrong key order on the continuation anchor is input too.
        self.assert_error(
            self.advance(
                [empty], {"block_hash": self.tip_hash, "height": 4}
            ),
            ERR_INPUT,
        )

    def test_bad_documents_are_input(self) -> None:
        # A limited first page ends on a confirmed header, so the garbage
        # second element itself is what the batch verification rejects.
        partial = self.page(0, self.genesis_hash, limit=2)
        for bad_documents in (None, "x", [], [partial, "y"]):
            with self.subTest(bad_documents=bad_documents):
                self.assert_error(
                    self.advance(bad_documents, self.anchor), ERR_INPUT
                )

    def test_never_raises_on_garbage(self) -> None:
        result = advance_headers(self.path, object(), object(), object(), object())
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})


class AdvanceHeadersVerificationTests(AdvanceHeadersFixture):
    def test_auth_failure_unknown_key_version(self) -> None:
        documents = copy.deepcopy(self.paged(2))
        documents[0]["auth"] = {"key_version": 9, "signature": "0" * 128}
        self.assert_error(
            self.advance(documents, self.anchor, tip_hash=self.tip_hash), ERR_AUTH
        )

    def test_auth_failure_bad_signature(self) -> None:
        documents = copy.deepcopy(self.paged(2))
        documents[1]["auth"]["signature"] = "0" * 128
        self.assert_error(
            self.advance(documents, self.anchor, tip_hash=self.tip_hash), ERR_AUTH
        )

    def test_integrity_failure_on_tampered_header(self) -> None:
        documents = copy.deepcopy(self.paged(2))
        documents[0]["headers"][0]["block_hash"] = "f" * 64
        self.re_sign(documents[0])
        self.assert_error(
            self.advance(documents, self.anchor, tip_hash=self.tip_hash),
            ERR_INTEGRITY,
        )

    def test_integrity_failure_on_broken_seam(self) -> None:
        documents = self.paged(1)
        self.assertGreaterEqual(len(documents), 3)
        # A missing page breaks the chain across the seam.
        self.assert_error(
            self.advance(
                [documents[0], documents[2]], self.anchor, tip_hash=self.tip_hash
            ),
            ERR_INTEGRITY,
        )

    def test_same_height_pending_to_pending_is_integrity(self) -> None:
        self.advance(self.paged(2), self.anchor)
        # Re-fetch the (still pending) tip page under a rotated signer so the
        # batch differs from the stored last step, then submit it: the new tip
        # is the same pending tip, which only a confirmation may reuse.
        rotated = self.rotate_signer()
        empty = self.page(4, self.tip_hash)
        self.assertEqual(empty["tip"]["status"], "pending")
        self.assert_error(
            self.advance([empty], None, tip_hash=self.tip_hash, trust=rotated),
            ERR_INTEGRITY,
        )

    def test_same_height_confirmed_to_confirmed_is_integrity(self) -> None:
        self.advance(self.paged(2), self.anchor)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        result = self.advance([empty], None, tip_hash=self.tip_hash)
        self.assertEqual(result["generation"], 2)
        # A different batch (rotated signer) naming the same confirmed tip.
        rotated = self.rotate_signer()
        empty2 = self.page(4, self.tip_hash)
        self.assertNotEqual(empty2["auth"], empty["auth"])
        self.assert_error(
            self.advance([empty2], None, tip_hash=self.tip_hash, trust=rotated),
            ERR_INTEGRITY,
        )

    def test_higher_tip_advances(self) -> None:
        self.advance(self.paged(4), self.anchor)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        page = self.page(4, self.tip_hash)
        result = self.advance([page], None, tip_hash=self.store.tip_hash())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["height"], 5)


class AdvanceHeadersStateTests(AdvanceHeadersFixture):
    def test_corrupt_json_is_state_not_io(self) -> None:
        self.write_file("{not json")
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_top_level_key_reorder_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        reordered = {
            key: data[key]
            for key in ("generation", "v", "anchor", "tip", "steps", "hash")
        }
        self.write_file(reordered)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_step_key_reorder_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        step = data["steps"][0]
        data["steps"][0] = {
            key: step[key]
            for key in ("trust", "kind", "tip_hash", "documents", "locators")
        }
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_tampered_generation_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        data["generation"] = 99
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_tampered_hash_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_tampered_step_documents_replay_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        # Tamper a delivered header hash; the file hash still pins the stored
        # bytes so first re-hash them, then the replay must disagree.
        data["steps"][0]["documents"][0]["headers"][0]["block_hash"] = "0" * 64
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_tampered_stored_tip_replay_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        data["tip"]["status"] = "confirmed"
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_bad_version_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        data["v"] = 3
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_empty_steps_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        data["steps"] = []
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_boolean_generation_is_state(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        data["generation"] = True
        self.rehash(data)
        self.write_file(data)
        self.assert_error(self.advance(self.paged(1), self.anchor), ERR_STATE)

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        self.advance(self.paged(2), self.anchor)
        data = self.read_checkpoint()
        data["hash"] = "1" * 64
        payload = json.dumps(data)
        self.write_file(payload)
        self.assert_error(self.advance(self.paged(1), None), ERR_STATE)
        # The corrupt file is left exactly in place.
        self.assertEqual(self.read_raw().decode("utf-8"), payload)


class AdvanceHeadersIoTests(AdvanceHeadersFixture):
    def test_unwritable_target_path_is_io(self) -> None:
        # Advancing at a path that is a directory cannot atomically replace.
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        result = advance_headers(
            directory, self.paged(1), self.anchor, self.tip_hash, self.trust
        )
        self.assert_error(result, ERR_IO)


if __name__ == "__main__":
    unittest.main(verbosity=2)
