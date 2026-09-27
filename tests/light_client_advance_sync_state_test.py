"""Behavioral tests for ``ledger.light_client.advance_sync_state``.

Drives the real service to build a confirmed chain, pages it through
GET /v1/chain/headers, signs finality credentials with the audit signer
and requests signed account-state proofs, then advances the version-3
header checkpoint at ``path`` and the version-1 state sidecar at
``path + ".state"`` together in one bundle.

Covers: success key order ``ok, header, state`` (header order
``generation, tip, finalized, applied``; state order ``generation,
anchor``; anchor order ``height, block_hash, state_root``); the bundle's
exact ``documents, finalities, state_document, account, anchor,
tip_hash, trust`` key order; proof anchor equal to the last credential's
``finalized``; same-path lock, v3/v1 file shapes and strict replay;
content-only generation bumps with a fully identical (or equivalent
re-signed) replay writing nothing; independent header/state generation
bumps; roll-forward recovery from a crashed pair commit via the sealed
``path + ".txn"`` journal; error categories input/auth/integrity/state/io;
and never raising on wild input.

Run: python3 tests/light_client_advance_sync_state_test.py
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
    advance_sync_state,
    sign_finality,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

BUNDLE_KEYS = [
    "documents",
    "finalities",
    "state_document",
    "account",
    "anchor",
    "tip_hash",
    "trust",
]
STATE_ANCHOR_KEYS = ["height", "block_hash", "state_root"]
CHECKPOINT_KEYS = ["v", "generation", "anchor", "tip", "finalized", "steps", "hash"]
SIDECAR_KEYS = [
    "v",
    "generation",
    "account",
    "anchor",
    "document",
    "trust",
    "hash",
]


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
                self.service.confirm_block(str(self.store.tip().height))[0], 200
            )
        self.genesis_hash = self.store.chain[0].block_hash
        self.trust = self.service.get_trust_document()[1]
        self.genesis_anchor = {"height": 0, "block_hash": self.genesis_hash}
        self.tip_hash = self.store.tip_hash()

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

    def descriptor(self, height: int) -> dict:
        block = self.store.chain[height]
        return {
            "tip_hash": block.block_hash,
            "height": height,
            "length": height + 1,
            "status": block.status,
        }

    def finality(self, fin_height: int, tip_height: int, version=None) -> dict:
        signer = self.store.audit_signer
        finalized = {"height": fin_height, "block_hash": self.h(fin_height)}
        tip = self.descriptor(tip_height)
        envelope = sign_finality(
            signer["private_key"],
            signer["version"] if version is None else version,
            finalized,
            tip,
        )
        self.assertIsNotNone(envelope)
        return {"finalized": finalized, "tip": tip, "auth": envelope}

    def state_proof(self, account: str, height: int | None = None) -> dict:
        params = None if height is None else {"height": str(height)}
        status, body = self.service.get_attested_account_proof(account, params)
        self.assertEqual(status, 200, body)
        return body

    def bundle(
        self,
        documents,
        finalities,
        state_document,
        account,
        anchor,
        tip_hash,
        trust=None,
    ) -> dict:
        return {
            "documents": documents,
            "finalities": finalities,
            "state_document": state_document,
            "account": account,
            "anchor": anchor,
            "tip_hash": tip_hash,
            "trust": self.trust if trust is None else trust,
        }

    def first_bundle(self) -> dict:
        documents = self.pages(0, self.genesis_hash, self.tip_hash)
        finalities = [
            self.finality(1, 2),
            self.finality(2, 3),
            self.finality(3, 3),
        ]
        return self.bundle(
            documents,
            finalities,
            self.state_proof(self.sender),
            self.sender,
            self.genesis_anchor,
            self.tip_hash,
        )

    def grow_confirmed(self, amount: int = 40) -> int:
        height = self.store.tip().height + 1
        self.assertEqual(self.service.submit_transaction(self._tx(amount))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        self.assertEqual(self.service.confirm_block(str(height))[0], 200)
        return height

    def advance_bundle_to(self, prev_height: int, height: int) -> dict:
        tip_hash = self.store.tip_hash()
        documents = self.pages(prev_height, self.h(prev_height), tip_hash)
        return self.bundle(
            documents,
            [self.finality(height, height)],
            self.state_proof(self.sender),
            self.sender,
            {"height": prev_height, "block_hash": self.h(prev_height)},
            tip_hash,
        )

    def state_path(self) -> str:
        return self.path + ".state"

    def txn_path(self) -> str:
        return self.path + ".txn"

    def read_raw(self, target: str) -> bytes:
        with open(target, "rb") as fh:
            return fh.read()

    def read_json(self, target: str) -> dict:
        with open(target, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class AdvanceSyncStateSuccessTests(SyncStateFixture):
    def test_first_call_creates_the_pair_with_generation_one(self) -> None:
        result = advance_sync_state(self.path, self.first_bundle())
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), ["ok", "header", "state"])
        self.assertEqual(
            list(result["header"].keys()),
            ["generation", "tip", "finalized", "applied"],
        )
        self.assertEqual(list(result["state"].keys()), ["generation", "anchor"])
        self.assertEqual(list(result["state"]["anchor"].keys()), STATE_ANCHOR_KEYS)
        self.assertEqual(result["header"]["generation"], 1)
        self.assertEqual(result["header"]["finalized"], {"height": 3, "block_hash": self.h(3)})
        self.assertEqual(result["header"]["applied"], 3)
        self.assertEqual(result["state"]["generation"], 1)
        self.assertEqual(
            result["state"]["anchor"],
            {
                "height": 3,
                "block_hash": self.h(3),
                "state_root": self.read_json(self.state_path())["anchor"]["state_root"],
            },
        )

        checkpoint = self.read_json(self.path)
        self.assertEqual(list(checkpoint.keys()), CHECKPOINT_KEYS)
        self.assertEqual(checkpoint["v"], 3)
        self.assertEqual(checkpoint["generation"], 1)
        sidecar = self.read_json(self.state_path())
        self.assertEqual(list(sidecar.keys()), SIDECAR_KEYS)
        self.assertEqual(list(sidecar["anchor"].keys()), STATE_ANCHOR_KEYS)
        self.assertEqual(sidecar["v"], 1)
        self.assertEqual(sidecar["generation"], 1)
        self.assertFalse(os.path.exists(self.txn_path()))

    def test_full_replay_is_idempotent_and_writes_nothing(self) -> None:
        first = advance_sync_state(self.path, self.first_bundle())
        self.assertTrue(first["ok"], first)
        header_before = self.read_raw(self.path)
        state_before = self.read_raw(self.state_path())
        # Continuation form anchor=None, exactly like advance_finalized_headers.
        replay = self.first_bundle()
        replay["anchor"] = None
        again = advance_sync_state(self.path, replay)
        self.assertTrue(again["ok"], again)
        self.assertEqual(again["header"]["generation"], 1)
        self.assertEqual(again["state"]["generation"], 1)
        self.assertEqual(self.read_raw(self.path), header_before)
        self.assertEqual(self.read_raw(self.state_path()), state_before)

    def test_resigned_equivalent_proof_keeps_the_sidecar(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        state_before = self.read_raw(self.state_path())
        replay = self.first_bundle()
        replay["anchor"] = None
        # A freshly-signed but anchor-identical proof.
        replay["state_document"] = self.state_proof(self.sender)
        result = advance_sync_state(self.path, replay)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["state"]["generation"], 1)
        self.assertEqual(self.read_raw(self.state_path()), state_before)

    def test_advancing_finalized_bumps_both_generations(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        self.assertEqual(height, 4)
        bundle = self.advance_bundle_to(3, 4)
        result = advance_sync_state(self.path, bundle)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["header"]["generation"], 2)
        self.assertEqual(result["state"]["generation"], 2)
        self.assertEqual(result["header"]["finalized"], {"height": 4, "block_hash": self.h(4)})
        self.assertEqual(result["state"]["anchor"]["height"], 4)
        self.assertEqual(self.read_json(self.path)["generation"], 2)
        self.assertEqual(self.read_json(self.state_path())["generation"], 2)

    def test_header_advance_with_static_finalized_holds_state(self) -> None:
        # The checkpoint moves to a new pending tip while the finalized
        # boundary (and the proof anchor) stays where it was: the header
        # generation bumps once and the sidecar is never rewritten.
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        self.assertEqual(self.service.submit_transaction(self._tx(60))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip_hash = self.store.tip_hash()
        self.assertEqual(self.store.chain[4].status, "pending")
        documents = self.pages(3, self.h(3), tip_hash)
        bundle = self.bundle(
            documents,
            [self.finality(3, 4)],
            self.state_proof(self.sender, height=3),
            self.sender,
            None,
            tip_hash,
        )
        state_before = self.read_raw(self.state_path())
        result = advance_sync_state(self.path, bundle)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["header"]["generation"], 2)
        self.assertEqual(result["header"]["tip"]["height"], 4)
        self.assertEqual(result["header"]["finalized"], {"height": 3, "block_hash": self.h(3)})
        self.assertEqual(result["state"]["generation"], 1)
        self.assertEqual(result["state"]["anchor"]["height"], 3)
        self.assertEqual(self.read_raw(self.state_path()), state_before)


class AdvanceSyncStateFailureTests(SyncStateFixture):
    def test_bad_path_is_input(self) -> None:
        self.assert_error(advance_sync_state("", self.first_bundle()), ERR_INPUT)
        self.assert_error(advance_sync_state(None, self.first_bundle()), ERR_INPUT)

    def test_bundle_shape_is_input(self) -> None:
        good = self.first_bundle()
        self.assert_error(advance_sync_state(self.path, None), ERR_INPUT)
        self.assert_error(advance_sync_state(self.path, 42), ERR_INPUT)
        # Wrong key order.
        reordered = {key: good[key] for key in reversed(BUNDLE_KEYS)}
        self.assert_error(advance_sync_state(self.path, reordered), ERR_INPUT)
        # Unknown key.
        extra = dict(good)
        extra["other"] = 1
        self.assert_error(advance_sync_state(self.path, extra), ERR_INPUT)
        # Empty batches.
        empty_docs = dict(good)
        empty_docs["documents"] = []
        self.assert_error(advance_sync_state(self.path, empty_docs), ERR_INPUT)
        empty_fins = dict(good)
        empty_fins["finalities"] = []
        self.assert_error(advance_sync_state(self.path, empty_fins), ERR_INPUT)
        # Bad hex account / tip hash.
        bad_account = dict(good)
        bad_account["account"] = "zz"
        self.assert_error(advance_sync_state(self.path, bad_account), ERR_INPUT)
        bad_tip = dict(good)
        bad_tip["tip_hash"] = "zz"
        self.assert_error(advance_sync_state(self.path, bad_tip), ERR_INPUT)
        # Bad anchor type/shape (None is the legal continuation anchor).
        bad_anchor = dict(good)
        bad_anchor["anchor"] = {"block_hash": self.h(0), "height": 0}
        self.assert_error(advance_sync_state(self.path, bad_anchor), ERR_INPUT)
        bad_anchor2 = dict(good)
        bad_anchor2["anchor"] = 7
        self.assert_error(advance_sync_state(self.path, bad_anchor2), ERR_INPUT)
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(os.path.exists(self.state_path()))

    def test_first_use_without_anchor_is_input(self) -> None:
        bundle = self.first_bundle()
        bundle["anchor"] = None
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INPUT)
        self.assertFalse(os.path.exists(self.path))

    def test_foreign_continuation_anchor_is_input(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        bundle["anchor"] = {"height": 1, "block_hash": self.h(1)}
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INPUT)

    def test_bad_finality_signature_is_auth(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        credential = bundle["finalities"][0]
        credential["auth"] = {
            "key_version": credential["auth"]["key_version"],
            "signature": "f" * 128,
        }
        bundle["anchor"] = None
        self.assert_error(advance_sync_state(self.path, bundle), ERR_AUTH)

    def test_unknown_key_version_is_auth(self) -> None:
        bundle = self.first_bundle()
        bundle["finalities"] = [self.finality(3, 3, version=99)]
        self.assert_error(advance_sync_state(self.path, bundle), ERR_AUTH)
        self.assertFalse(os.path.exists(self.path))

    def test_bad_state_proof_signature_is_auth(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        bundle["state_document"]["auth"]["signature"] = "f" * 128
        bundle["anchor"] = None
        self.assert_error(advance_sync_state(self.path, bundle), ERR_AUTH)

    def test_proof_anchor_must_equal_last_finalized(self) -> None:
        # Last credential finalizes height 2 while the proof names 3.
        bundle = self.first_bundle()
        bundle["finalities"] = [
            self.finality(1, 2),
            self.finality(2, 3),
        ]
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INTEGRITY)
        self.assertFalse(os.path.exists(self.path))

    def test_historical_proof_is_integrity(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        bundle["state_document"] = self.state_proof(self.sender, height=3)
        bundle["anchor"] = None
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INTEGRITY)

    def test_account_switch_is_integrity(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        bundle["state_document"] = self.state_proof(self.bob)
        bundle["account"] = self.bob
        bundle["anchor"] = None
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INTEGRITY)

    def test_boundary_regression_is_integrity(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        bundle["finalities"] = [self.finality(2, height)]
        bundle["anchor"] = None
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INTEGRITY)

    def test_corrupt_header_is_state(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("garbage")
        replay = self.first_bundle()
        replay["anchor"] = None
        self.assert_error(advance_sync_state(self.path, replay), ERR_STATE)

    def test_corrupt_sidecar_is_state(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.state_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        replay = self.first_bundle()
        replay["anchor"] = None
        self.assert_error(advance_sync_state(self.path, replay), ERR_STATE)

    def test_orphan_sidecar_is_io(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        os.unlink(self.path)
        self.assertTrue(os.path.exists(self.state_path()))
        self.assert_error(
            advance_sync_state(self.path, self.first_bundle()), ERR_IO
        )

    def test_failed_call_leaves_no_journal_and_old_pair(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        good_header = self.read_raw(self.path)
        good_state = self.read_raw(self.state_path())
        bundle = self.advance_bundle_to(3, height)
        # Break the proof binding after all signatures pass: proof at 3 vs
        # finalized 4 -> integrity, nothing may be written.
        bundle["state_document"] = self.state_proof(self.sender, height=3)
        bundle["anchor"] = None
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(self.path), good_header)
        self.assertEqual(self.read_raw(self.state_path()), good_state)
        self.assertFalse(os.path.exists(self.txn_path()))

    def test_non_json_serializable_value_is_input_even_when_idempotent(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )

        class Weird:
            pass

        replay = self.first_bundle()
        replay["anchor"] = None
        replay["trust"] = {"audit_signers": self.trust["audit_signers"], "x": Weird()}
        self.assert_error(advance_sync_state(self.path, replay), ERR_INPUT)
        # Same for an un-JSON-able value buried in the state document.
        replay2 = self.first_bundle()
        replay2["anchor"] = None
        replay2["state_document"] = self.state_proof(self.sender)
        replay2["state_document"]["proof"]["siblings"].append(
            {"direction": "left", "hash": Weird()}
        )
        self.assert_error(advance_sync_state(self.path, replay2), ERR_INPUT)


class AdvanceSyncStateRecoveryTests(SyncStateFixture):
    def _crash_between_header_and_sidecar(self, bundle: dict) -> None:
        """Run one commit that fails the sidecar promotion (3rd fsync write)."""
        import ledger.light_client as light_client

        original = light_client._atomic_write_bytes
        counter = {"calls": 0}

        def flaky(target, payload):
            counter["calls"] += 1
            if counter["calls"] == 3:
                raise OSError("injected crash")
            return original(target, payload)

        light_client._atomic_write_bytes = flaky
        try:
            result = advance_sync_state(self.path, bundle)
        finally:
            light_client._atomic_write_bytes = original
        self.assert_error(result, ERR_IO)
        self.assertTrue(os.path.exists(self.txn_path()))

    def test_journal_rolls_forward_to_the_complete_new_pair(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        self._crash_between_header_and_sidecar(bundle)

        # The stale request first rolls the sealed journal forward, then
        # fails on the stale continuation anchor.
        self.assert_error(advance_sync_state(self.path, bundle), ERR_INPUT)
        self.assertFalse(os.path.exists(self.txn_path()))
        self.assertEqual(self.read_json(self.path)["generation"], 2)
        sidecar = self.read_json(self.state_path())
        self.assertEqual(sidecar["generation"], 2)
        self.assertEqual(sidecar["anchor"]["height"], 4)

        # A replay-shaped request against the recovered tip is idempotent.
        replay = dict(bundle)
        replay["anchor"] = {"height": 4, "block_hash": self.h(4)}
        header_before = self.read_raw(self.path)
        state_before = self.read_raw(self.state_path())
        result = advance_sync_state(self.path, replay)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["header"]["generation"], 2)
        self.assertEqual(result["state"]["generation"], 2)
        self.assertEqual(self.read_raw(self.path), header_before)
        self.assertEqual(self.read_raw(self.state_path()), state_before)

    def test_corrupt_journal_is_state(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        with open(self.txn_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        replay = self.first_bundle()
        replay["anchor"] = None
        self.assert_error(advance_sync_state(self.path, replay), ERR_STATE)

    def test_tampered_resealed_journal_is_state(self) -> None:
        self.assertTrue(
            advance_sync_state(self.path, self.first_bundle())["ok"]
        )
        height = self.grow_confirmed()
        bundle = self.advance_bundle_to(3, height)
        self._crash_between_header_and_sidecar(bundle)
        # Re-seal the outer journal over a moved state generation: the
        # outer seal then matches, but the embedded sidecar's own hash was
        # computed over the old generation and the strict replay rejects
        # it as transaction corruption.
        import ledger.light_client as light_client

        journal = self.read_json(self.txn_path())
        journal["state"]["generation"] = 99
        body = {key: journal[key] for key in ("v", "header", "state")}
        journal["hash"] = light_client.hashlib.sha256(
            light_client._canonical_json_bytes(body)
        ).hexdigest()
        with open(self.txn_path(), "w", encoding="utf-8") as fh:
            json.dump(journal, fh)
        self.assert_error(advance_sync_state(self.path, bundle), ERR_STATE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
