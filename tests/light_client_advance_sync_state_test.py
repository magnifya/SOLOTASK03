"""Behavioral tests for ``ledger.light_client.advance_sync_state``.

Drives the real service to build a confirmed chain, pages it through
``GET /v1/chain/headers`` and signs finality credentials with the audit
signer, then advances the version-3 header checkpoint and the version-1
``path + ".state"`` sidecar in one all-or-nothing call.

Covers: the exact seven-item ordered bundle; the success key order
``ok, header, state`` with header ``generation, tip, finalized, applied``
and state ``generation, anchor`` (anchor ``height, block_hash, state_root``);
header sync reusing ``advance_finalized_headers`` and state verification
reusing ``verify_state_proof``; the proof anchor equalling the last
credential's finalized; generation starting at 1, content changes bumping
each generation once and a full identical retry writing neither file;
failure categories input/auth/integrity/state/io; the complete-old-pair or
complete-new-pair guarantee (a failure never touches either file, and a
crash between the two writes converges on retry); and never raising.

Run: python3 tests/light_client_advance_sync_state_test.py
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
    advance_finalized_headers,
    advance_sync_state,
    sign_finality,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

RESULT_KEYS = ["ok", "header", "state"]
HEADER_KEYS = ["generation", "tip", "finalized", "applied"]
STATE_KEYS = ["generation", "anchor"]
ANCHOR_KEYS = ["height", "block_hash", "state_root"]
SIDE_ANCHOR_KEYS = ["height", "block_hash", "state_root"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class SyncStateFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "headers.json")
        self.store = LedgerStore(os.path.join(self.tmp, "store.json"))
        self.service = LedgerService(self.store)
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        for amount in (10, 20, 30):
            self.assertEqual(
                self.service.submit_transaction(self._tx(amount))[0], 202
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0],
                200,
            )
        self.genesis_hash = self.store.chain[0].block_hash
        self.trust = self.service.get_trust_document()[1]
        self.anchor0 = {"height": 0, "block_hash": self.genesis_hash}

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

    def descriptor(self, height: int) -> dict:
        block = self.store.chain[height]
        return {
            "tip_hash": block.block_hash,
            "height": height,
            "length": height + 1,
            "status": block.status,
        }

    def finality(self, fin_height: int, tip_height: int) -> dict:
        signer = self.store.audit_signer
        finalized = {"height": fin_height, "block_hash": self.h(fin_height)}
        tip = self.descriptor(tip_height)
        envelope = sign_finality(
            signer["private_key"], signer["version"], finalized, tip
        )
        self.assertIsNotNone(envelope)
        return {"finalized": finalized, "tip": tip, "auth": envelope}

    def pages(self, start_height: int, start_hash: str, tip_hash: str) -> list:
        documents = []
        anchor = {"height": start_height, "block_hash": start_hash}
        while True:
            status, body = self.service.get_chain_headers(
                {
                    "after_height": str(anchor["height"]),
                    "after_hash": anchor["block_hash"],
                    "limit": "2",
                }
            )
            self.assertEqual(status, 200, body)
            documents.append(body)
            if not body["headers"]:
                break
            last = body["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == tip_hash:
                break
        return documents

    def state_proof(self, account: str, height: int | None = None) -> dict:
        params = None if height is None else {"height": str(height)}
        status, body = self.service.get_attested_account_proof(account, params)
        self.assertEqual(status, 200, body)
        return body

    def state_path(self) -> str:
        return self.path + ".state"

    def bundle(
        self,
        documents,
        finalities,
        state_document,
        anchor,
        tip_hash,
        trust=None,
        account=None,
    ) -> list:
        return [
            documents,
            finalities,
            state_document,
            self.sender if account is None else account,
            anchor,
            tip_hash,
            self.trust if trust is None else trust,
        ]

    def sync_to_three(self) -> dict:
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        bundle = self.bundle(
            documents,
            finalities,
            self.state_proof(self.sender),
            self.anchor0,
            self.h(3),
        )
        result = advance_sync_state(self.path, bundle)
        self.assertTrue(result["ok"], result)
        return result

    def read_raw(self, target: str) -> bytes:
        with open(target, "rb") as fh:
            return fh.read()

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class AdvanceSyncStateSuccessTests(SyncStateFixture):
    def test_first_sync_creates_the_full_pair(self) -> None:
        result = self.sync_to_three()
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        header = result["header"]
        state = result["state"]
        self.assertEqual(list(header.keys()), HEADER_KEYS)
        self.assertEqual(list(state.keys()), STATE_KEYS)
        self.assertEqual(list(state["anchor"].keys()), ANCHOR_KEYS)
        self.assertEqual(header["generation"], 1)
        self.assertEqual(header["tip"]["height"], 3)
        self.assertEqual(
            header["finalized"], {"height": 3, "block_hash": self.h(3)}
        )
        self.assertEqual(header["applied"], 3)
        self.assertEqual(state["generation"], 1)
        self.assertEqual(state["anchor"]["height"], 3)
        self.assertEqual(state["anchor"]["block_hash"], self.h(3))
        self.assertTrue(os.path.exists(self.path))
        self.assertTrue(os.path.exists(self.state_path()))
        # The v3 header checkpoint carries one linear step.
        checkpoint = json.loads(self.read_raw(self.path))
        self.assertEqual(checkpoint["v"], 3)
        self.assertEqual(checkpoint["generation"], 1)
        self.assertEqual(len(checkpoint["steps"]), 1)
        # The v1 sidecar pins the proof and trust verbatim at the anchor.
        sidecar = json.loads(self.read_raw(self.state_path()))
        self.assertEqual(sidecar["v"], 1)
        self.assertEqual(sidecar["generation"], 1)
        self.assertEqual(sidecar["account"], self.sender)
        self.assertEqual(list(sidecar["anchor"].keys()), SIDE_ANCHOR_KEYS)
        self.assertEqual(sidecar["anchor"], state["anchor"])

    def test_full_identical_retry_writes_neither_file(self) -> None:
        self.sync_to_three()
        header_before = self.read_raw(self.path)
        state_before = self.read_raw(self.state_path())
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        # A freshly re-signed but equivalent proof at the same anchor.
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender),
                None,
                self.h(3),
            ),
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["header"]["generation"], 1)
        self.assertEqual(result["state"]["generation"], 1)
        self.assertEqual(self.read_raw(self.path), header_before)
        self.assertEqual(self.read_raw(self.state_path()), state_before)

    def test_content_change_bumps_both_generations_once(self) -> None:
        self.sync_to_three()
        self.assertEqual(
            self.service.submit_transaction(self._tx(40))[0], 202
        )
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        documents = self.pages(3, self.h(3), self.h(4))
        finalities = [self.finality(4, 4)]
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender),
                None,
                self.h(4),
            ),
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["header"]["generation"], 2)
        self.assertEqual(
            result["header"]["finalized"],
            {"height": 4, "block_hash": self.h(4)},
        )
        self.assertEqual(result["header"]["applied"], 1)
        self.assertEqual(result["state"]["generation"], 2)
        self.assertEqual(result["state"]["anchor"]["height"], 4)
        self.assertEqual(result["state"]["anchor"]["block_hash"], self.h(4))
        sidecar = json.loads(self.read_raw(self.state_path()))
        self.assertEqual(sidecar["generation"], 2)


class AdvanceSyncStateFailureTests(SyncStateFixture):
    def test_bad_bundle_shapes_are_input(self) -> None:
        self.sync_to_three()
        for bad in (None, 42, "x", b"x", ["only"], [0] * 6, [0] * 8, {}):
            self.assert_error(advance_sync_state(self.path, bad), ERR_INPUT)
        self.assert_error(advance_sync_state("", [0] * 7), ERR_INPUT)
        self.assert_error(advance_sync_state(None, [0] * 7), ERR_INPUT)

    def test_proof_anchor_not_last_finalized_is_integrity(self) -> None:
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        # A valid proof at height 2 against a credential finalizing 3.
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender, 2),
                self.anchor0,
                self.h(3),
            ),
        )
        self.assert_error(result, ERR_INTEGRITY)
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(os.path.exists(self.state_path()))

    def test_bad_state_signature_is_auth(self) -> None:
        self.sync_to_three()
        before_h = self.read_raw(self.path)
        before_s = self.read_raw(self.state_path())
        document = self.state_proof(self.sender)
        document["auth"]["signature"] = "f" * 128
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        result = advance_sync_state(
            self.path,
            self.bundle(documents, finalities, document, None, self.h(3)),
        )
        self.assert_error(result, ERR_AUTH)
        self.assertEqual(self.read_raw(self.path), before_h)
        self.assertEqual(self.read_raw(self.state_path()), before_s)

    def test_bad_finality_signature_is_auth(self) -> None:
        self.sync_to_three()
        documents = self.pages(0, self.genesis_hash, self.h(3))
        credentials = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        credentials[1]["auth"]["signature"] = "f" * 128
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                credentials,
                self.state_proof(self.sender),
                None,
                self.h(3),
            ),
        )
        self.assert_error(result, ERR_AUTH)

    def test_chain_mismatch_is_integrity(self) -> None:
        self.sync_to_three()
        before_h = self.read_raw(self.path)
        before_s = self.read_raw(self.state_path())
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender),
                None,
                "f" * 64,
            ),
        )
        self.assert_error(result, ERR_INTEGRITY)
        self.assertEqual(self.read_raw(self.path), before_h)
        self.assertEqual(self.read_raw(self.state_path()), before_s)

    def test_account_switch_is_integrity(self) -> None:
        self.sync_to_three()
        before_h = self.read_raw(self.path)
        before_s = self.read_raw(self.state_path())
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.bob),
                None,
                self.h(3),
                account=self.bob,
            ),
        )
        self.assert_error(result, ERR_INTEGRITY)
        self.assertEqual(self.read_raw(self.path), before_h)
        self.assertEqual(self.read_raw(self.state_path()), before_s)

    def test_regression_is_integrity(self) -> None:
        self.sync_to_three()
        self.assertEqual(
            self.service.submit_transaction(self._tx(40))[0], 202
        )
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        # Advance only the header to 4; the sidecar stays at 3.
        documents = self.pages(3, self.h(3), self.h(4))
        advanced = advance_finalized_headers(
            self.path, documents, [self.finality(4, 4)], None,
            self.h(4), self.trust,
        )
        self.assertTrue(advanced["ok"], advanced)
        before_h = self.read_raw(self.path)
        before_s = self.read_raw(self.state_path())
        # Re-present a proof at 3 while the batch closes at 4.
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                [self.finality(4, 4)],
                self.state_proof(self.sender, 3),
                None,
                self.h(4),
            ),
        )
        self.assert_error(result, ERR_INTEGRITY)
        self.assertEqual(self.read_raw(self.path), before_h)
        self.assertEqual(self.read_raw(self.state_path()), before_s)

    def test_non_serializable_value_is_input(self) -> None:
        self.sync_to_three()
        before_h = self.read_raw(self.path)
        before_s = self.read_raw(self.state_path())
        bad_trust = copy.deepcopy(self.trust)
        bad_trust["marker"] = object()
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender),
                None,
                self.h(3),
                trust=bad_trust,
            ),
        )
        self.assert_error(result, ERR_INPUT)
        self.assertEqual(self.read_raw(self.path), before_h)
        self.assertEqual(self.read_raw(self.state_path()), before_s)

    def test_corrupt_sidecar_is_state(self) -> None:
        self.sync_to_three()
        with open(self.state_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender),
                self.anchor0,
                self.h(3),
            ),
        )
        self.assert_error(result, ERR_STATE)

    def test_corrupt_header_checkpoint_is_state(self) -> None:
        self.sync_to_three()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("garbage")
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender),
                self.anchor0,
                self.h(3),
            ),
        )
        self.assert_error(result, ERR_STATE)

    def test_orphan_sidecar_without_header_is_io(self) -> None:
        self.sync_to_three()
        sidecar = self.read_raw(self.state_path())
        os.unlink(self.path)
        documents = self.pages(0, self.genesis_hash, self.h(3))
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                finalities,
                self.state_proof(self.sender),
                self.anchor0,
                self.h(3),
            ),
        )
        self.assert_error(result, ERR_IO)
        # The orphan sidecar is left in place and no header is rebuilt.
        self.assertEqual(self.read_raw(self.state_path()), sidecar)
        self.assertFalse(os.path.exists(self.path))

    def test_split_pair_converges_on_retry(self) -> None:
        self.sync_to_three()
        self.assertEqual(
            self.service.submit_transaction(self._tx(40))[0], 202
        )
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        documents = self.pages(3, self.h(3), self.h(4))
        # Simulate a crash between the two writes: advanced header at 4,
        # sidecar still at 3.
        advanced = advance_finalized_headers(
            self.path, documents, [self.finality(4, 4)], None,
            self.h(4), self.trust,
        )
        self.assertTrue(advanced["ok"], advanced)
        self.assertEqual(
            json.loads(self.read_raw(self.state_path()))["generation"], 1
        )
        result = advance_sync_state(
            self.path,
            self.bundle(
                documents,
                [self.finality(4, 4)],
                self.state_proof(self.sender),
                None,
                self.h(4),
            ),
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["header"]["generation"], 2)
        self.assertEqual(result["state"]["generation"], 2)
        self.assertEqual(result["state"]["anchor"]["height"], 4)
        self.assertEqual(
            json.loads(self.read_raw(self.state_path()))["generation"], 2
        )

    def test_never_raises_on_wild_inputs(self) -> None:
        self.sync_to_three()
        for bundle in (42, ["x"], object(), {"a": 1}, (1, 2, 3), [0] * 7):
            for path in (self.path, "", None, 7, object()):
                result = advance_sync_state(path, bundle)
                self.assertIn(result["ok"], (True, False))
                if not result["ok"]:
                    self.assertIn(
                        result["error"],
                        {"input", "auth", "integrity", "state", "io"},
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
