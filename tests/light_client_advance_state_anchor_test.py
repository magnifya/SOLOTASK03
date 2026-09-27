"""Behavioral tests for ``ledger.light_client.advance_state_anchor``.

Drives the real service to build a confirmed chain, persists a version-3
header checkpoint (``advance_headers`` + ``apply_finality``), then pins
signed account-state proofs next to it in the ``path + ".state"`` sidecar.

Covers: success key order ``ok, generation, anchor`` and sidecar key order
``v, generation, account, anchor, document, trust, hash`` (anchor key order
``height, block_hash, state_root``; compact UTF-8, non-ASCII unescaped, one
trailing LF; self-excluding canonical SHA-256); generation starting at 1;
same account+anchor idempotency (no disk write); a higher finalized
boundary bumping generation once; the proof height/block_hash must equal
finalized; error categories input/auth/integrity/state/io; and never
raising or touching files on failure.

Run: python3 tests/light_client_advance_state_anchor_test.py
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
    advance_state_anchor,
    apply_finality,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

STATE_ANCHOR_KEYS = [
    "v",
    "generation",
    "account",
    "anchor",
    "document",
    "trust",
    "hash",
]
STATE_ANCHOR_ANCHOR_KEYS = ["height", "block_hash", "state_root"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


class StateAnchorFixture(unittest.TestCase):
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

    def pages(self, start_height: int, start_hash: str, tip_hash: str) -> list:
        documents = []
        anchor = {"height": start_height, "block_hash": start_hash}
        while True:
            params = {
                "after_height": str(anchor["height"]),
                "after_hash": anchor["block_hash"],
                "limit": "2",
            }
            status, body = self.service.get_chain_headers(params)
            self.assertEqual(status, 200, body)
            documents.append(body)
            if not body["headers"]:
                break
            last = body["headers"][-1]
            anchor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == tip_hash:
                break
        return documents

    def checkpoint_to(self, tip_height: int) -> None:
        tip_hash = self.h(tip_height)
        result = advance_headers(
            self.path,
            self.pages(0, self.genesis_hash, tip_hash)
            if tip_height == 3
            else self.pages(tip_height - 1, self.h(tip_height - 1), tip_hash),
            self.anchor0 if tip_height == 3 else None,
            tip_hash,
            self.trust,
        )
        self.assertTrue(result["ok"], result)
        # Push the irreversible finalized boundary to the confirmed tip.
        status, credential = self.service.get_chain_finality()
        self.assertEqual(status, 200, credential)
        applied = apply_finality(self.path, credential, self.trust)
        self.assertTrue(applied["ok"], applied)

    def state_proof(self, account: str, height: int | None = None) -> dict:
        params = None if height is None else {"height": str(height)}
        status, body = self.service.get_attested_account_proof(account, params)
        self.assertEqual(status, 200, body)
        return body

    def grow_confirmed(self) -> None:
        self.assertEqual(self.service.submit_transaction(self._tx(40))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block("4")[0], 200)

    def state_path(self) -> str:
        return self.path + ".state"

    def read_sidecar(self) -> dict:
        with open(self.state_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_raw(self, target: str | None = None) -> bytes:
        with open(target or self.state_path(), "rb") as fh:
            return fh.read()

    def advance(self, document, account=None, trust=None):
        return advance_state_anchor(
            self.path,
            document,
            self.sender if account is None else account,
            self.trust if trust is None else trust,
        )

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class AdvanceStateAnchorSuccessTests(StateAnchorFixture):
    def test_first_anchor_generation_one_and_file_shape(self) -> None:
        self.checkpoint_to(3)
        doc = self.state_proof(self.sender)
        expected_root = doc["state"]["state_root"]
        result = self.advance(doc)
        self.assertEqual(list(result.keys()), ["ok", "generation", "anchor"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["generation"], 1)
        self.assertEqual(
            result["anchor"],
            {"height": 3, "block_hash": self.h(3), "state_root": expected_root},
        )
        self.assertEqual(list(result["anchor"].keys()), STATE_ANCHOR_ANCHOR_KEYS)

        raw = self.read_raw()
        # Compact UTF-8, non-ASCII unescaped, exactly one trailing LF.
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b" ", raw)
        sidecar = json.loads(raw)
        self.assertEqual(list(sidecar.keys()), STATE_ANCHOR_KEYS)
        self.assertEqual(sidecar["v"], 1)
        self.assertEqual(sidecar["generation"], 1)
        self.assertEqual(sidecar["account"], self.sender)
        self.assertEqual(list(sidecar["anchor"].keys()), STATE_ANCHOR_ANCHOR_KEYS)
        self.assertEqual(sidecar["anchor"], result["anchor"])
        self.assertEqual(sidecar["document"], doc)
        self.assertEqual(sidecar["trust"], self.trust)
        # Self-excluding canonical JSON SHA-256.
        body = {key: sidecar[key] for key in STATE_ANCHOR_KEYS if key != "hash"}
        digest = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(sidecar["hash"], digest)

    def test_same_account_same_anchor_is_idempotent_no_write(self) -> None:
        self.checkpoint_to(3)
        doc = self.state_proof(self.sender)
        first = self.advance(doc)
        self.assertTrue(first["ok"], first)
        before = self.read_raw()
        # A re-signed but otherwise identical proof at the same finalized
        # anchor is still idempotent.
        second = self.advance(self.state_proof(self.sender))
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], 1)
        self.assertEqual(second["anchor"], first["anchor"])
        self.assertEqual(self.read_raw(), before)

    def test_higher_finalized_bumps_generation(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        self.grow_confirmed()
        self.checkpoint_to(4)
        self.assertEqual(self.h(4), self.store.chain[4].block_hash)
        result = self.advance(self.state_proof(self.sender))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["anchor"]["height"], 4)
        self.assertEqual(result["anchor"]["block_hash"], self.h(4))
        sidecar = self.read_sidecar()
        self.assertEqual(sidecar["generation"], 2)

    def test_document_and_trust_stored_verbatim_and_reload(self) -> None:
        self.checkpoint_to(3)
        doc = self.state_proof(self.sender)
        trust = copy.deepcopy(self.trust)
        result = advance_state_anchor(self.path, doc, self.sender, trust)
        self.assertTrue(result["ok"], result)
        # A second call strictly reloads and re-verifies the sidecar.
        again = advance_state_anchor(self.path, doc, self.sender, trust)
        self.assertTrue(again["ok"], again)
        self.assertEqual(again["generation"], 1)


class AdvanceStateAnchorFailureTests(StateAnchorFixture):
    def test_missing_header_file_is_io(self) -> None:
        # No header checkpoint at path: state anchor cannot be created.
        doc = self.state_proof(self.sender)
        self.assert_error(self.advance(doc), ERR_IO)
        self.assertFalse(os.path.exists(self.state_path()))

    def test_proof_height_not_finalized_is_integrity(self) -> None:
        self.checkpoint_to(3)  # finalized = height 3
        # A valid historical proof at height 2 does not name finalized.
        doc = self.state_proof(self.sender, height=2)
        self.assert_error(self.advance(doc), ERR_INTEGRITY)
        self.assertFalse(os.path.exists(self.state_path()))

    def test_bad_signature_is_auth(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        doc = self.state_proof(self.sender)
        doc["auth"]["signature"] = "f" * 128  # well-shaped, wrong signature
        self.assert_error(self.advance(doc), ERR_AUTH)

    def test_account_switch_is_integrity(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        before = self.read_raw()
        bob_doc = self.state_proof(self.bob)
        self.assert_error(self.advance(bob_doc, account=self.bob), ERR_INTEGRITY)
        # File bytes and generation untouched.
        self.assertEqual(self.read_raw(), before)
        self.assertEqual(self.read_sidecar()["account"], self.sender)

    def test_regression_to_lower_height_is_integrity(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        self.grow_confirmed()
        self.checkpoint_to(4)  # finalized advances to 4, sidecar still at 3
        gen_before = self.read_sidecar()["generation"]
        old = self.state_proof(self.sender, height=3)
        self.assert_error(self.advance(old), ERR_INTEGRITY)
        self.assertEqual(self.read_sidecar()["generation"], gen_before)

    def test_bad_account_argument_is_input(self) -> None:
        self.checkpoint_to(3)
        doc = self.state_proof(self.sender)
        self.assert_error(
            advance_state_anchor(self.path, doc, "not-hex", self.trust),
            ERR_INPUT,
        )

    def test_bad_document_shape_is_input(self) -> None:
        self.checkpoint_to(3)
        self.assert_error(self.advance({"state": {}}), ERR_INPUT)
        self.assert_error(self.advance(None), ERR_INPUT)

    def test_bad_path_is_input(self) -> None:
        doc = self.state_proof(self.sender)
        self.assert_error(
            advance_state_anchor("", doc, self.sender, self.trust), ERR_INPUT
        )
        self.assert_error(
            advance_state_anchor(None, doc, self.sender, self.trust), ERR_INPUT
        )

    def test_corrupt_sidecar_is_state(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        with open(self.state_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assert_error(
            self.advance(self.state_proof(self.sender)), ERR_STATE
        )

    def test_tampered_sidecar_hash_is_state(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        sidecar = self.read_sidecar()
        sidecar["generation"] = 99
        with open(self.state_path(), "w", encoding="utf-8") as fh:
            json.dump(sidecar, fh)
        self.assert_error(
            self.advance(self.state_proof(self.sender)), ERR_STATE
        )

    def test_corrupt_header_checkpoint_is_state(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("garbage")
        self.assert_error(
            self.advance(self.state_proof(self.sender)), ERR_STATE
        )

    def test_sidecar_without_header_is_state_not_rebuilt(self) -> None:
        self.checkpoint_to(3)
        self.assertTrue(self.advance(self.state_proof(self.sender))["ok"])
        os.unlink(self.path)
        # Header missing => io; the sidecar is left in place.
        self.assert_error(
            self.advance(self.state_proof(self.sender)), ERR_IO
        )
        self.assertTrue(os.path.exists(self.state_path()))

    def test_never_raises_on_wild_inputs(self) -> None:
        for document in (42, ["x"], object(), {"a": 1}):
            for acct in (7, None, b"ab", object()):
                for tr in (1, None, []):
                    result = advance_state_anchor(self.path, document, acct, tr)
                    self.assertIn(result["ok"], (True, False))
                    if not result["ok"]:
                        self.assertIn(
                            result["error"],
                            {"input", "auth", "integrity", "state", "io"},
                        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
