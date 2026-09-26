"""Tests for the durable header-checkpoint reorg
(``ledger.light_client.reorg_headers``).

Builds a main chain through the real service, checkpoints it with
``advance_headers`` (three linear steps tipping at heights 2, 3 and 4) and
then re-anchors the checkpoint at a forked chain served by a second
store/service pair (the deterministic genesis is shared, so identical
transactions reproduce identical blocks and different ones fork it).
Covers:

* the reorg boundary — the last step whose closing tip is the matched
  locator anchor, or the initial anchor when no step matches — with the
  suffix dropped (``replaced`` counts the dropped steps) and one
  ``{kind: "locator", tip_hash, trust, documents, locators}`` step appended;
* tip rules — the new tip never drops in height, a same-height different
  hash is accepted in either status, the same hash only moves
  pending -> confirmed and anything else is an ``integrity`` failure;
* idempotency — re-submitting a last step fully identical to the new
  locator step returns ``replaced`` 0 and touches neither the file bytes
  nor the generation; every other success bumps the generation by one;
* the v2 file shape (top-level ``v, generation, anchor, tip, steps, hash``
  and step ``kind, tip_hash, trust, documents, locators``), legacy v1
  checkpoints still loading and upgrading on write, and linear
  ``advance_headers`` steps chaining after a locator step;
* success key order ``ok, generation, tip, replaced`` and error categories
  ``input``/``auth``/``integrity``/``state``/``io`` with failures leaving
  the file's bytes and the generation untouched.

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
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

CHECKPOINT_KEYS = ["v", "generation", "anchor", "tip", "steps", "hash"]
STEP_KEYS = ["kind", "tip_hash", "trust", "documents", "locators"]
RESULT_KEYS = ["ok", "generation", "tip", "replaced"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class ReorgHeadersFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "headers-checkpoint.json")
        self.store = LedgerStore(os.path.join(self.tmp, "chain-a.json"))
        self.service = LedgerService(self.store)
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        self._forks = 0
        self.genesis_hash = self.store.chain[0].block_hash
        self.anchor = {"height": 0, "block_hash": self.genesis_hash}

        # Checkpoint with three linear steps tipping at heights 2, 3 and 4
        # (each a pending tip at advance time).
        self._mine(self.service, self.store, 10, confirm=True)
        self._mine(self.service, self.store, 20, confirm=False)
        self.assertEqual(self._advance_to_tip()["generation"], 1)
        self.assertEqual(self.service.confirm_block("2")[0], 200)
        self._mine(self.service, self.store, 30, confirm=False)
        self.assertEqual(self._advance_to_tip()["generation"], 2)
        self.assertEqual(self.service.confirm_block("3")[0], 200)
        self._mine(self.service, self.store, 40, confirm=False)
        self.assertEqual(self._advance_to_tip()["generation"], 3)

        self.tip_hash = self.store.tip_hash()
        self.trust = self.service.get_trust_document()[1]

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- chain building ----------------------------------------------------

    def _tx(self, amount: int) -> dict:
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def _mine(self, service, store, amount: int, confirm: bool) -> None:
        self.assertEqual(service.submit_transaction(self._tx(amount))[0], 202)
        self.assertEqual(service.mine_block()[0], 201)
        if confirm:
            self.assertEqual(
                service.confirm_block(str(store.tip().height))[0], 200
            )

    def fork(self):
        """A fresh store/service pair sharing the deterministic genesis."""
        self._forks += 1
        store = LedgerStore(os.path.join(self.tmp, f"chain-fork-{self._forks}.json"))
        return store, LedgerService(store)

    # -- document helpers ----------------------------------------------------

    def paged_from(self, service, anchor: dict, tip_hash: str) -> list:
        documents = []
        current = anchor
        while True:
            status, page = service.get_chain_headers(
                {
                    "after_height": str(current["height"]),
                    "after_hash": current["block_hash"],
                }
            )
            self.assertEqual(status, 200, page)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            current = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == tip_hash:
                break
        return documents

    def locator_batch(self, service, locators: list, tip_hash: str) -> list:
        status, page = service.locate_header_fork({"locators": locators})
        self.assertEqual(status, 200, page)
        documents = [page]
        while page["headers"] and page["headers"][-1]["block_hash"] != tip_hash:
            last = page["headers"][-1]
            documents.extend(
                self.paged_from(
                    service,
                    {"height": last["height"], "block_hash": last["block_hash"]},
                    tip_hash,
                )
            )
            break
        return documents

    def _advance_to_tip(self, anchor=None) -> dict:
        tip_hash = self.store.tip_hash()
        if anchor is None:
            anchor = self.anchor if not os.path.exists(self.path) else None
        if anchor is None:
            stored = self.read_checkpoint()["tip"]
            anchor = {"height": stored["height"], "block_hash": stored["tip_hash"]}
        documents = self.paged_from(self.service, anchor, tip_hash)
        result = advance_headers(
            self.path, documents, anchor, tip_hash, self.service.get_trust_document()[1]
        )
        self.assertTrue(result["ok"], result)
        return result

    def locators(self) -> list:
        result = header_locators(self.path)
        self.assertTrue(result["ok"], result)
        return result["request"]["locators"]

    def reorg(self, documents, locators, tip_hash, trust, path=None):
        return reorg_headers(
            self.path if path is None else path,
            documents,
            locators,
            tip_hash,
            trust,
        )

    def reorg_to_tip(self, service, locators=None) -> dict:
        """Locate ``locators`` on ``service`` and reorg onto its chain tip."""
        if locators is None:
            locators = self.locators()
        tip_hash = service.get_chain_headers(
            {"after_height": "0", "after_hash": self.genesis_hash}
        )[1]["tip"]["tip_hash"]
        trust = service.get_trust_document()[1]
        documents = self.locator_batch(service, locators, tip_hash)
        return self.reorg(documents, locators, tip_hash, trust)

    # -- file helpers --------------------------------------------------------

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
        body = {key: data[key] for key in CHECKPOINT_KEYS if key != "hash"}
        data["hash"] = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class ReorgHeadersSuccessTests(ReorgHeadersFixture):
    def test_full_reorg_replaces_every_step(self) -> None:
        # A fork sharing only the genesis: no step tip matches, so the
        # initial anchor bounds the reorg and every step is replaced.
        store, service = self.fork()
        for amount in (11, 12, 13, 14):
            self._mine(service, store, amount, confirm=True)
        self._mine(service, store, 15, confirm=False)
        self.assertNotEqual(store.chain[1].block_hash, self.store.chain[1].block_hash)

        locators = self.locators()
        result = self.reorg_to_tip(service, locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["generation"], 4)
        self.assertEqual(result["replaced"], 3)
        self.assertEqual(result["tip"]["height"], 5)
        self.assertEqual(result["tip"]["tip_hash"], store.tip_hash())
        self.assertEqual(result["tip"]["status"], "pending")

        data = self.read_checkpoint()
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["v"], 2)
        self.assertEqual(data["generation"], 4)
        # The file anchor never moves.
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["tip"], result["tip"])
        self.assertEqual(len(data["steps"]), 1)
        step = data["steps"][0]
        self.assertEqual(list(step.keys()), STEP_KEYS)
        self.assertEqual(step["kind"], "locator")
        self.assertEqual(step["locators"], locators)
        self.assertEqual(step["tip_hash"], store.tip_hash())
        # The recorded hash recomputes over every other field.
        body = {key: data[key] for key in CHECKPOINT_KEYS if key != "hash"}
        self.assertEqual(
            data["hash"],
            hashlib.sha256(
                json.dumps(
                    body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest(),
        )
        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b", ", raw)

    def test_partial_reorg_drops_only_the_suffix(self) -> None:
        # A fork sharing blocks 1-2 (identical transactions) and diverging
        # at height 3: the boundary is the first step's tip and only the two
        # later steps are replaced.
        store, service = self.fork()
        self._mine(service, store, 10, confirm=True)
        self._mine(service, store, 20, confirm=True)
        self.assertEqual(store.chain[2].block_hash, self.store.chain[2].block_hash)
        self._mine(service, store, 21, confirm=True)
        self._mine(service, store, 22, confirm=True)
        self.assertNotEqual(store.chain[3].block_hash, self.store.chain[3].block_hash)

        locators = self.locators()
        result = self.reorg_to_tip(service, locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 4)
        self.assertEqual(result["replaced"], 2)
        # Same height as the stored tip, a different hash, confirmed while
        # the stored tip was pending: a legal reorg.
        self.assertEqual(result["tip"]["height"], 4)
        self.assertEqual(result["tip"]["tip_hash"], store.tip_hash())
        self.assertEqual(result["tip"]["status"], "confirmed")

        data = self.read_checkpoint()
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual([step["kind"] for step in data["steps"]], ["linear", "locator"])
        self.assertIsNone(data["steps"][0]["locators"])
        self.assertEqual(data["steps"][1]["locators"], locators)

    def test_identical_last_step_is_idempotent(self) -> None:
        store, service = self.fork()
        for amount in (11, 12, 13, 14):
            self._mine(service, store, amount, confirm=True)
        locators = self.locators()
        tip_hash = store.tip_hash()
        trust = service.get_trust_document()[1]
        documents = self.locator_batch(service, locators, tip_hash)
        first = self.reorg(documents, locators, tip_hash, trust)
        self.assertTrue(first["ok"], first)
        before = self.read_raw()

        replay = self.reorg(
            copy.deepcopy(documents), copy.deepcopy(locators), tip_hash, copy.deepcopy(trust)
        )
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(list(replay.keys()), RESULT_KEYS)
        self.assertEqual(replay["generation"], first["generation"])
        self.assertEqual(replay["tip"], first["tip"])
        self.assertEqual(replay["replaced"], 0)
        # The file bytes stay exactly as they were.
        self.assertEqual(self.read_raw(), before)

    def test_same_hash_pending_to_confirmed_reorgs(self) -> None:
        # Confirming the pending tip keeps its height and hash; a locator
        # batch anchored at the tip itself carries the confirmation.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        locators = self.locators()
        self.assertEqual(locators[0], {"height": 4, "block_hash": self.tip_hash})
        result = self.reorg_to_tip(self.service, locators)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 4)
        self.assertEqual(result["replaced"], 0)
        self.assertEqual(result["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(result["tip"]["status"], "confirmed")
        data = self.read_checkpoint()
        self.assertEqual(len(data["steps"]), 4)
        self.assertEqual(data["steps"][-1]["kind"], "locator")

    def test_advance_continues_after_reorg(self) -> None:
        store, service = self.fork()
        for amount in (11, 12, 13, 14):
            self._mine(service, store, amount, confirm=True)
        reorged = self.reorg_to_tip(service)
        self.assertTrue(reorged["ok"], reorged)

        # A linear advance chains from the reorged tip on the fork.
        self._mine(service, store, 15, confirm=False)
        new_tip_hash = store.tip_hash()
        anchor = {"height": 4, "block_hash": reorged["tip"]["tip_hash"]}
        documents = self.paged_from(service, anchor, new_tip_hash)
        trust = service.get_trust_document()[1]
        advanced = advance_headers(self.path, documents, None, new_tip_hash, trust)
        self.assertTrue(advanced["ok"], advanced)
        self.assertEqual(advanced["generation"], 5)
        self.assertEqual(advanced["tip"]["height"], 5)
        data = self.read_checkpoint()
        self.assertEqual(
            [step["kind"] for step in data["steps"]], ["locator", "linear"]
        )
        # The locator request builder reads the rewritten file too.
        locators = header_locators(self.path)
        self.assertTrue(locators["ok"], locators)
        self.assertEqual(locators["tip"], advanced["tip"])

    def test_consecutive_reorgs_chain_locator_steps(self) -> None:
        # A second reorg may itself be reorged: the first locator step is
        # dropped like any other and the file replays two locator steps.
        store_b, service_b = self.fork()
        for amount in (11, 12, 13, 14):
            self._mine(service_b, store_b, amount, confirm=True)
        locators = self.locators()
        first = self.reorg_to_tip(service_b, locators)
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["replaced"], 3)

        store_c, service_c = self.fork()
        for amount in (21, 22, 23, 24, 25):
            self._mine(service_c, store_c, amount, confirm=True)
        second = self.reorg_to_tip(service_c, locators)
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], 5)
        self.assertEqual(second["replaced"], 1)
        self.assertEqual(second["tip"]["tip_hash"], store_c.tip_hash())
        data = self.read_checkpoint()
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(data["steps"][0]["kind"], "locator")
        self.assertEqual(data["steps"][0]["tip_hash"], store_c.tip_hash())

    def test_legacy_v1_checkpoint_reorgs_and_upgrades(self) -> None:
        # Downgrade the stored file to the v1 shape (three-key steps); the
        # reorg still loads it and rewrites it as v2.
        data = self.read_checkpoint()
        data["v"] = 1
        data["steps"] = [
            {
                "tip_hash": step["tip_hash"],
                "trust": step["trust"],
                "documents": step["documents"],
            }
            for step in data["steps"]
        ]
        self.rehash(data)
        self.write_file(data)

        store, service = self.fork()
        for amount in (11, 12, 13, 14, 15):
            self._mine(service, store, amount, confirm=True)
        result = self.reorg_to_tip(service)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 4)
        self.assertEqual(result["replaced"], 3)
        upgraded = self.read_checkpoint()
        self.assertEqual(upgraded["v"], 2)
        self.assertEqual(list(upgraded["steps"][0].keys()), STEP_KEYS)


class ReorgHeadersIntegrityTests(ReorgHeadersFixture):
    def test_lower_tip_is_integrity(self) -> None:
        # A fork tipping below the stored tip's height can never reorg.
        store, service = self.fork()
        self._mine(service, store, 11, confirm=True)
        self._mine(service, store, 12, confirm=False)
        before = self.read_raw()
        self.assert_error(self.reorg_to_tip(service), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)
        self.assertEqual(self.read_checkpoint()["generation"], 3)

    def test_anchor_matching_no_boundary_is_integrity(self) -> None:
        # A main-chain block that is neither a step tip nor the initial
        # anchor cannot bound a reorg.
        locators = [
            {"height": 1, "block_hash": self.store.chain[1].block_hash}
        ]
        before = self.read_raw()
        self.assert_error(self.reorg_to_tip(self.service, locators), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_same_hash_pending_to_pending_is_integrity(self) -> None:
        # A locator batch anchored at the still-pending tip itself names the
        # same pending tip, which only a confirmation may reuse.
        locators = self.locators()
        before = self.read_raw()
        self.assert_error(self.reorg_to_tip(self.service, locators), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_same_hash_confirmed_to_confirmed_is_integrity(self) -> None:
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        result = self.reorg_to_tip(self.service)
        self.assertTrue(result["ok"], result)
        # A different batch (rotated signer) naming the same confirmed tip.
        seed = crypto.generate_private_key()
        status, _ = self.service.rotate_audit_signer(
            {"private_key": seed, "expected_version": 1}
        )
        self.assertEqual(status, 200)
        before = self.read_raw()
        self.assert_error(self.reorg_to_tip(self.service), ERR_INTEGRITY)
        self.assertEqual(self.read_raw(), before)

    def test_tampered_batch_is_integrity(self) -> None:
        store, service = self.fork()
        for amount in (11, 12, 13, 14):
            self._mine(service, store, amount, confirm=True)
        locators = self.locators()
        tip_hash = store.tip_hash()
        trust = service.get_trust_document()[1]
        documents = self.locator_batch(service, locators, tip_hash)
        documents[0]["headers"][0]["block_hash"] = "f" * 64
        before = self.read_raw()
        self.assert_error(
            self.reorg(documents, locators, tip_hash, trust), ERR_AUTH
        )
        self.assertEqual(self.read_raw(), before)


class ReorgHeadersInputTests(ReorgHeadersFixture):
    def test_path_must_be_a_non_empty_string(self) -> None:
        locators = self.locators()
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    reorg_headers(bad_path, [], locators, self.tip_hash, self.trust),
                    ERR_INPUT,
                )

    def test_tip_hash_must_be_64_lower_hex(self) -> None:
        locators = self.locators()
        for bad_tip in (None, 7, "zz", "A" * 64, "a" * 63, True):
            with self.subTest(bad_tip=bad_tip):
                self.assert_error(
                    self.reorg([], locators, bad_tip, self.trust), ERR_INPUT
                )

    def test_bad_locators_are_input(self) -> None:
        tip_hash = self.tip_hash
        for bad_locators in (
            None,
            "x",
            [],
            [{"height": 1, "block_hash": self.genesis_hash}, {"height": 2, "block_hash": self.genesis_hash}],
            [{"block_hash": self.genesis_hash, "height": 1}],
            [{"height": True, "block_hash": self.genesis_hash}],
        ):
            with self.subTest(bad_locators=bad_locators):
                self.assert_error(
                    self.reorg(["doc"], bad_locators, tip_hash, self.trust),
                    ERR_INPUT,
                )

    def test_bad_documents_are_input(self) -> None:
        locators = self.locators()
        for bad_documents in (None, "x", []):
            with self.subTest(bad_documents=bad_documents):
                self.assert_error(
                    self.reorg(bad_documents, locators, self.tip_hash, self.trust),
                    ERR_INPUT,
                )

    def test_never_raises_on_garbage(self) -> None:
        result = reorg_headers(self.path, object(), object(), object(), object())
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})


class ReorgHeadersAuthTests(ReorgHeadersFixture):
    def test_unknown_key_version_is_auth(self) -> None:
        store, service = self.fork()
        for amount in (11, 12, 13, 14):
            self._mine(service, store, amount, confirm=True)
        locators = self.locators()
        tip_hash = store.tip_hash()
        trust = service.get_trust_document()[1]
        documents = self.locator_batch(service, locators, tip_hash)
        documents[0]["auth"] = {"key_version": 9, "signature": "0" * 128}
        before = self.read_raw()
        self.assert_error(
            self.reorg(documents, locators, tip_hash, trust), ERR_AUTH
        )
        self.assertEqual(self.read_raw(), before)

    def test_bad_signature_is_auth(self) -> None:
        store, service = self.fork()
        for amount in (11, 12, 13, 14):
            self._mine(service, store, amount, confirm=True)
        locators = self.locators()
        tip_hash = store.tip_hash()
        trust = service.get_trust_document()[1]
        documents = self.locator_batch(service, locators, tip_hash)
        documents[0]["auth"]["signature"] = "0" * 128
        self.assert_error(
            self.reorg(documents, locators, tip_hash, trust), ERR_AUTH
        )


class ReorgHeadersStateIoTests(ReorgHeadersFixture):
    def test_missing_checkpoint_is_io(self) -> None:
        missing = os.path.join(self.tmp, "never-advanced.json")
        self.assert_error(
            self.reorg([], self.locators(), self.tip_hash, self.trust, path=missing),
            ERR_IO,
        )

    def test_corrupt_checkpoint_is_state(self) -> None:
        locators = self.locators()
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        payload = json.dumps(data)
        self.write_file(payload)
        self.assert_error(
            self.reorg([], locators, self.tip_hash, self.trust), ERR_STATE
        )
        # The corrupt file is left exactly in place.
        self.assertEqual(self.read_raw().decode("utf-8"), payload)

    def test_corrupt_json_is_state(self) -> None:
        locators = self.locators()
        self.write_file("{not json")
        self.assert_error(
            self.reorg([], locators, self.tip_hash, self.trust), ERR_STATE
        )

    def test_unwritable_target_path_is_io(self) -> None:
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        self.assert_error(
            self.reorg([], self.locators(), self.tip_hash, self.trust, path=directory),
            ERR_IO,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
