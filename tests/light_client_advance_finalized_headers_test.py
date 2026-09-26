"""Tests for the atomic header-checkpoint advance plus finality application
(``ledger.light_client.advance_finalized_headers``).

Builds a confirmed chain with a pending tip through the real service, pages
it through GET /v1/chain/headers and signs finality credentials with the
audit signer, and covers:

* a first call creating the checkpoint exactly as ``advance_headers`` does
  while raising the finalized boundary in the same write — one ``linear``
  step appended, the generation incremented exactly once, the file in the
  version-3 format;
* the success result key order ``ok, generation, tip, finalized, applied``
  with ``applied`` the number of credentials;
* continuation with ``anchor=None``, the per-credential rules (tip must
  match the same-height header, tip heights non-decreasing, finalized
  heights strictly increasing, targets only the anchor or a confirmed
  header no higher than their tip) and the whole-batch boundary rule (the
  last item may not end below or beside the stored boundary);
* idempotency: a call whose last step and final boundary equal the stored
  ones leaves the file bytes and the generation untouched;
* error categories ``input`` (argument/array/document shape or types),
  ``auth`` (unknown key version or bad signature), ``integrity`` (chain,
  tip, ordering, branch or boundary defects), ``state`` (a corrupt
  checkpoint) and ``io`` — a failed call never changes the file bytes and
  nothing is raised.

Run: python3 tests/light_client_advance_finalized_headers_test.py
"""
from __future__ import annotations

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
    advance_finalized_headers,
    header_locators,
    sign_finality,
    sign_header_page,
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
RESULT_KEYS = ["ok", "generation", "tip", "finalized", "applied"]

_DEFAULT = object()


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class AdvanceFinalizedFixture(unittest.TestCase):
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

    def descriptor(self, height: int) -> dict:
        block = self.store.chain[height]
        return {
            "tip_hash": block.block_hash,
            "height": height,
            "length": height + 1,
            "status": block.status,
        }

    def finality(self, fin_height: int, tip_height: int, version=None) -> dict:
        """A validly signed credential finalizing ``fin_height`` at the
        ``tip_height`` descriptor."""
        signer = self.store.audit_signer
        finalized = self.loc(fin_height)
        tip = self.descriptor(tip_height)
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
            page = self.page(anchor["height"], anchor["block_hash"], limit)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == tip_hash:
                break
        return documents

    def call(
        self,
        documents,
        finalities,
        anchor=_DEFAULT,
        tip_hash=_DEFAULT,
        trust=None,
        path=_DEFAULT,
    ):
        if anchor is _DEFAULT:
            # First use pins the genesis anchor; a continuation passes None.
            anchor = self.anchor if not os.path.exists(self.path) else None
        return advance_finalized_headers(
            self.path if path is _DEFAULT else path,
            documents,
            finalities,
            anchor,
            self.store.tip_hash() if tip_hash is _DEFAULT else tip_hash,
            self.trust if trust is None else trust,
        )

    def re_sign_page(self, document: dict) -> None:
        """Re-sign a tampered header page so only integrity is at stake."""
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

    def re_sign_finality(self, document: dict) -> None:
        """Re-sign a tampered credential so only integrity is at stake."""
        signer = self.store.audit_signer
        envelope = sign_finality(
            signer["private_key"],
            signer["version"],
            document["finalized"],
            document["tip"],
        )
        self.assertIsNotNone(envelope)
        document["auth"] = envelope

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


class AdvanceFinalizedSuccessTests(AdvanceFinalizedFixture):
    def test_first_call_advances_and_finalizes_in_one_generation(self) -> None:
        documents = self.paged(2)
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 4),
        ]
        result = self.call(documents, finalities, tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["tip"], self.descriptor(4))
        self.assertEqual(result["finalized"], self.loc(3))
        self.assertEqual(list(result["finalized"].keys()), ANCHOR_KEYS)
        self.assertEqual(result["applied"], 3)

        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        data = json.loads(raw)
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 1)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["tip"], result["tip"])
        self.assertEqual(list(data["tip"].keys()), TIP_KEYS)
        # The boundary landed with the same single write.
        self.assertEqual(data["finalized"], self.loc(3))
        self.assertEqual(len(data["steps"]), 1)
        step = data["steps"][0]
        self.assertEqual(list(step.keys()), STEP_KEYS)
        self.assertEqual(step["kind"], "linear")
        self.assertIsNone(step["locators"])
        self.assertEqual(step["tip_hash"], self.tip_hash)
        self.assertEqual(step["documents"], documents)
        self.assertEqual(step["trust"], self.trust)

    def test_idempotent_replay_holds_generation_and_bytes(self) -> None:
        documents = self.paged(2)
        finalities = [self.finality(1, 3), self.finality(2, 4)]
        first = self.call(documents, finalities, tip_hash=self.tip_hash)
        self.assertTrue(first["ok"], first)
        raw = self.read_raw()
        again = self.call(documents, finalities, tip_hash=self.tip_hash)
        self.assertTrue(again["ok"], again)
        self.assertEqual(again["generation"], first["generation"])
        self.assertEqual(again["tip"], first["tip"])
        self.assertEqual(again["finalized"], first["finalized"])
        self.assertEqual(again["applied"], 2)
        self.assertEqual(self.read_raw(), raw)

    def test_same_step_can_still_raise_the_boundary_once(self) -> None:
        documents = self.paged(2)
        first = self.call(
            documents, [self.finality(2, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["finalized"], self.loc(2))

        # The identical header batch with a higher credential appends no
        # second step but still advances the boundary, once.
        second = self.call(
            documents, [self.finality(3, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], 2)
        self.assertEqual(second["tip"], first["tip"])
        self.assertEqual(second["finalized"], self.loc(3))
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 2)
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(data["finalized"], self.loc(3))

        # Replaying that exact call is idempotent.
        raw = self.read_raw()
        third = self.call(
            documents, [self.finality(3, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(third["ok"], third)
        self.assertEqual(third["generation"], 2)
        self.assertEqual(self.read_raw(), raw)

    def test_continuation_from_stored_tip_with_none_anchor(self) -> None:
        first = self.call(
            self.paged(2), [self.finality(2, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(first["ok"], first)

        # Extend the chain: confirm the pending tip and mine another block.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("5")[0], 200)
        new_tip_hash = self.store.tip_hash()

        documents = self.paged(2, anchor=self.loc(4))
        # Height 4 stays recorded as the previous step's pending closing
        # tip, so the credentials finalize the confirmed heights 3 and 5.
        result = self.call(
            documents,
            [self.finality(3, 5), self.finality(5, 5)],
            anchor=None,
            tip_hash=new_tip_hash,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["tip"], self.descriptor(5))
        self.assertEqual(result["finalized"], self.loc(5))
        self.assertEqual(result["applied"], 2)
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 2)
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual(data["finalized"], self.loc(5))

        # The checkpoint still strictly reloads and replays.
        located = header_locators(self.path)
        self.assertTrue(located["ok"], located)

    def test_first_call_ending_at_the_anchor_boundary_still_creates(self) -> None:
        # A credential batch whose last item names the initial boundary
        # (the anchor itself) is not idempotent on first use: the
        # checkpoint must still be created with generation 1.
        documents = self.paged(2)
        result = self.call(documents, [self.finality(0, 4)],
                           tip_hash=self.tip_hash)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["finalized"], self.anchor)
        self.assertEqual(result["applied"], 1)
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 1)
        self.assertEqual(data["finalized"], self.anchor)
        self.assertEqual(len(data["steps"]), 1)

    def test_anchor_equal_to_stored_tip_is_accepted(self) -> None:
        first = self.call(
            self.paged(2), [self.finality(1, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(first["ok"], first)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        # An empty page at the confirmed tip moves pending -> confirmed.
        documents = self.paged(2, anchor=self.loc(4))
        result = self.call(
            documents,
            [self.finality(2, 4), self.finality(3, 4), self.finality(4, 4)],
            anchor=self.loc(4),
            tip_hash=self.store.tip_hash(),
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], "confirmed")
        self.assertEqual(result["finalized"], self.loc(4))


class AdvanceFinalizedInputTests(AdvanceFinalizedFixture):
    def test_bad_path_and_tip_hash_are_input(self) -> None:
        documents = self.paged(2)
        finalities = [self.finality(1, 4)]
        self.assert_error(
            self.call(documents, finalities, path=""), ERR_INPUT
        )
        self.assert_error(
            self.call(documents, finalities, path=None), ERR_INPUT
        )
        self.assert_error(
            self.call(documents, finalities, tip_hash="zz"), ERR_INPUT
        )
        self.assert_error(
            self.call(documents, finalities, tip_hash=None), ERR_INPUT
        )
        self.assertFalse(os.path.exists(self.path))

    def test_empty_or_non_list_batches_are_input(self) -> None:
        documents = self.paged(2)
        self.assert_error(self.call([], [self.finality(1, 4)]), ERR_INPUT)
        self.assert_error(self.call("x", [self.finality(1, 4)]), ERR_INPUT)
        self.assert_error(self.call(documents, []), ERR_INPUT)
        self.assert_error(self.call(documents, "x"), ERR_INPUT)
        self.assertFalse(os.path.exists(self.path))

    def test_malformed_credential_is_input(self) -> None:
        documents = self.paged(2)
        good = self.finality(1, 4)
        # Wrong top-level key order.
        bad_order = {
            "tip": good["tip"],
            "finalized": good["finalized"],
            "auth": good["auth"],
        }
        self.assert_error(self.call(documents, [bad_order]), ERR_INPUT)
        # Non-integer height.
        bad_height = self.finality(1, 4)
        bad_height["finalized"] = {"height": True, "block_hash": self.h(1)}
        self.assert_error(self.call(documents, [bad_height]), ERR_INPUT)
        # A malformed trust document.
        self.assert_error(
            self.call(documents, [good], trust={"audit_signers": []}),
            ERR_INPUT,
        )
        self.assertFalse(os.path.exists(self.path))

    def test_first_use_requires_a_legal_anchor(self) -> None:
        documents = self.paged(2)
        finalities = [self.finality(1, 4)]
        self.assert_error(
            self.call(documents, finalities, anchor=None), ERR_INPUT
        )
        self.assert_error(
            self.call(
                documents, finalities, anchor={"block_hash": self.h(0), "height": 0}
            ),
            ERR_INPUT,
        )
        self.assertFalse(os.path.exists(self.path))

    def test_continuation_rejects_a_foreign_anchor(self) -> None:
        first = self.call(
            self.paged(2), [self.finality(1, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(first["ok"], first)
        self.assert_error(
            self.call(self.paged(2), [self.finality(2, 4)], anchor=self.loc(1)),
            ERR_INPUT,
        )


class AdvanceFinalizedAuthTests(AdvanceFinalizedFixture):
    def test_unknown_key_version_is_auth(self) -> None:
        documents = self.paged(2)
        credential = self.finality(1, 4, version=99)
        self.assert_error(self.call(documents, [credential]), ERR_AUTH)
        self.assertFalse(os.path.exists(self.path))

    def test_bad_signature_is_auth(self) -> None:
        documents = self.paged(2)
        credential = self.finality(1, 4)
        credential["auth"] = {
            "key_version": credential["auth"]["key_version"],
            "signature": "0" * 128,
        }
        self.assert_error(self.call(documents, [credential]), ERR_AUTH)
        self.assertFalse(os.path.exists(self.path))

    def test_later_credential_bad_signature_is_auth(self) -> None:
        documents = self.paged(2)
        good = self.finality(1, 4)
        bad = self.finality(2, 4)
        bad["auth"] = {
            "key_version": bad["auth"]["key_version"],
            "signature": "f" * 128,
        }
        self.assert_error(self.call(documents, [good, bad]), ERR_AUTH)
        self.assertFalse(os.path.exists(self.path))

    def test_tampered_credential_is_auth_not_integrity(self) -> None:
        # A credential whose signed content was changed without re-signing.
        documents = self.paged(2)
        credential = self.finality(1, 4)
        credential["finalized"] = self.loc(2)
        self.assert_error(self.call(documents, [credential]), ERR_AUTH)
        self.assertFalse(os.path.exists(self.path))


class AdvanceFinalizedIntegrityTests(AdvanceFinalizedFixture):
    def test_header_batch_defects_surface(self) -> None:
        documents = self.paged(2)
        # Break the chain: the second page no longer links to the first.
        documents[1]["headers"][0]["prev_hash"] = "0" * 64
        self.re_sign_page(documents[1])
        self.assert_error(
            self.call(documents, [self.finality(1, 4)]), ERR_INTEGRITY
        )
        self.assertFalse(os.path.exists(self.path))

    def test_header_page_bad_signature_is_auth(self) -> None:
        documents = self.paged(2)
        documents[0]["auth"] = {
            "key_version": documents[0]["auth"]["key_version"],
            "signature": "0" * 128,
        }
        self.assert_error(
            self.call(documents, [self.finality(1, 4)]), ERR_AUTH
        )
        self.assertFalse(os.path.exists(self.path))

    def test_credential_tip_must_match_the_same_height_header(self) -> None:
        documents = self.paged(2)
        credential = self.finality(1, 4)
        # Re-sign so only the descriptor mismatch is at stake: the height-2
        # descriptor carries a foreign hash.
        credential["tip"] = {
            "tip_hash": "0" * 64,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        self.re_sign_finality(credential)
        self.assert_error(self.call(documents, [credential]), ERR_INTEGRITY)

    def test_credential_tip_status_must_match(self) -> None:
        documents = self.paged(2)
        credential = self.finality(1, 4)
        # The height-4 block is pending; claim it confirmed.
        credential["tip"] = {
            "tip_hash": self.h(4),
            "height": 4,
            "length": 5,
            "status": "confirmed",
        }
        self.re_sign_finality(credential)
        self.assert_error(self.call(documents, [credential]), ERR_INTEGRITY)

    def test_finalized_heights_must_strictly_increase(self) -> None:
        documents = self.paged(2)
        duplicate = [self.finality(2, 4), self.finality(2, 4)]
        self.assert_error(self.call(documents, duplicate), ERR_INTEGRITY)
        regression = [self.finality(2, 4), self.finality(1, 4)]
        self.assert_error(self.call(documents, regression), ERR_INTEGRITY)
        self.assertFalse(os.path.exists(self.path))

    def test_tip_heights_must_not_decrease(self) -> None:
        documents = self.paged(2)
        finalities = [self.finality(1, 4), self.finality(2, 2)]
        self.assert_error(self.call(documents, finalities), ERR_INTEGRITY)

    def test_target_must_not_cross_its_own_tip(self) -> None:
        documents = self.paged(2)
        # Finalized height 3 above the credential's own tip at height 2.
        self.assert_error(
            self.call(documents, [self.finality(3, 2)]), ERR_INTEGRITY
        )

    def test_pending_target_is_rejected(self) -> None:
        documents = self.paged(2)
        # Height 4 is the pending tip: it can never be finalized.
        self.assert_error(
            self.call(documents, [self.finality(4, 4)]), ERR_INTEGRITY
        )

    def test_unknown_target_hash_is_rejected(self) -> None:
        documents = self.paged(2)
        credential = self.finality(1, 4)
        credential["finalized"] = self.loc(1, "0" * 64)
        self.re_sign_finality(credential)
        self.assert_error(self.call(documents, [credential]), ERR_INTEGRITY)

    def test_batch_may_not_end_below_the_stored_boundary(self) -> None:
        first = self.call(
            self.paged(2), [self.finality(3, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(first["ok"], first)
        raw = self.read_raw()
        # A fully valid batch that ends at height 2 regresses the boundary.
        finalities = [self.finality(1, 4), self.finality(2, 4)]
        self.assert_error(
            self.call(self.paged(2), finalities, tip_hash=self.tip_hash),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), raw)

    def test_failed_call_never_touches_the_file(self) -> None:
        first = self.call(
            self.paged(2), [self.finality(1, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(first["ok"], first)
        raw = self.read_raw()
        # A same-height different-hash boundary target is a sideways move.
        credential = self.finality(2, 4)
        credential["finalized"] = self.loc(2, "0" * 64)
        self.re_sign_finality(credential)
        self.assert_error(
            self.call(self.paged(2), [credential], tip_hash=self.tip_hash),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(self.read_checkpoint()["generation"], 1)


class AdvanceFinalizedStateIoTests(AdvanceFinalizedFixture):
    def test_corrupt_checkpoint_is_state(self) -> None:
        first = self.call(
            self.paged(2), [self.finality(1, 4)], tip_hash=self.tip_hash
        )
        self.assertTrue(first["ok"], first)
        raw = self.read_raw()
        # Tamper with the stored boundary without fixing the digest.
        data = self.read_checkpoint()
        data["finalized"] = self.loc(2)
        self.write_file(data)
        self.assert_error(
            self.call(self.paged(2), [self.finality(2, 4)],
                      tip_hash=self.tip_hash),
            ERR_STATE,
        )
        # The file is never truncated or rebuilt.
        self.assertNotEqual(self.read_raw(), raw)
        self.assertEqual(self.read_checkpoint()["finalized"], self.loc(2))

    def test_unparseable_checkpoint_is_state(self) -> None:
        self.write_file("{not json")
        self.assert_error(
            self.call(self.paged(2), [self.finality(1, 4)],
                      tip_hash=self.tip_hash),
            ERR_STATE,
        )

    def test_unwritable_path_is_io(self) -> None:
        documents = self.paged(2)
        finalities = [self.finality(1, 4)]
        # A path inside a file-as-directory cannot be written.
        blocker = os.path.join(self.tmp, "blocker")
        with open(blocker, "w", encoding="utf-8") as fh:
            fh.write("x")
        result = self.call(
            documents, finalities, path=os.path.join(blocker, "c.json")
        )
        self.assert_error(result, ERR_IO)


if __name__ == "__main__":
    unittest.main()
