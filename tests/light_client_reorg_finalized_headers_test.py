"""Tests for the atomic header-checkpoint reorganization plus finality
application (``ledger.light_client.reorg_finalized_headers``).

Builds a confirmed chain with a pending tip through the real service,
checkpoints it with ``advance_headers`` (and optionally a finality
boundary via ``apply_finalities``), then rolls the pending tip back and
re-mines a divergent block so a locator batch describes a genuine reorg.
Covers:

* one atomic write appending the single ``locator`` step, dropping the
  suffix (``replaced``) and writing the last credential's boundary with
  the generation incremented exactly once and the file in the
  version-3 format;
* the success result key order
  ``ok, generation, tip, finalized, replaced, applied``;
* the reorg boundary (last matching step tip, else the initial anchor),
  the rule that it may never be earlier than the stored finalized
  boundary, and credentials judged against the freshly reorged branch;
* idempotency of the exact last locator step with the same final
  boundary (bytes and generation untouched), the same step advancing
  only the boundary (``replaced: 0``, one generation, no appended step)
  and a same-step batch that regresses the boundary being rejected;
* error categories ``input`` (argument/array/document shape or types),
  ``auth`` (unknown key version or bad signature), ``integrity``
  (finality, boundary, chain, tip, ordering, branch or boundary
  defects), ``state`` (a corrupt checkpoint) and ``io`` (a missing or
  unreadable file) — a failed call never changes the file bytes and
  nothing is raised.

Run: python3 tests/light_client_reorg_finalized_headers_test.py
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
    apply_finalities,
    header_locators,
    reorg_finalized_headers,
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
RESULT_KEYS = ["ok", "generation", "tip", "finalized", "replaced", "applied"]

_DEFAULT = object()


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
        # The pending tip captured before any fork is rolled through.
        self.old_tip_hash = self.store.tip_hash()
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
        ``tip_height`` descriptor of the current service chain."""
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

    def finality_for(self, finalized: dict, tip: dict) -> dict:
        """A validly signed credential over explicit closed documents."""
        signer = self.store.audit_signer
        envelope = sign_finality(
            signer["private_key"], signer["version"], finalized, tip
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

    def locate(self, locators, limit=None) -> dict:
        payload = {"locators": locators}
        if limit is not None:
            payload["limit"] = limit
        status, body = self.service.locate_header_fork(payload)
        self.assertEqual(status, 200, body)
        return body

    def advance(self, documents, anchor=_DEFAULT, tip_hash=_DEFAULT, trust=None):
        if anchor is _DEFAULT:
            anchor = self.anchor
        return advance_headers(
            self.path,
            documents,
            anchor,
            self.store.tip_hash() if tip_hash is _DEFAULT else tip_hash,
            self.trust if trust is None else trust,
        )

    def raise_boundary(self, finalities) -> dict:
        return apply_finalities(self.path, finalities, self.trust)

    def fork_tip(self, amount: int = 6) -> str:
        """Roll the pending tip back and re-mine a divergent pending block."""
        height = self.store.tip().height
        self.assertEqual(self.service.rollback_block(str(height))[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(amount))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        forked_tip_hash = self.store.tip_hash()
        self.assertNotEqual(forked_tip_hash, self.old_tip_hash)
        return forked_tip_hash

    def call(
        self,
        documents,
        finalities,
        locators,
        tip_hash=_DEFAULT,
        trust=None,
        path=_DEFAULT,
    ):
        return reorg_finalized_headers(
            self.path if path is _DEFAULT else path,
            documents,
            finalities,
            locators,
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

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class ReorgFinalizedSuccessTests(ReorgFinalizedFixture):
    def test_reorg_and_finalize_happen_in_one_generation(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        page = self.locate(locators)
        # The rolled-back tip no longer matches; the page anchors at genesis.
        self.assertEqual(page["anchor"], self.loc(0))
        finalities = [self.finality(1, 4), self.finality(2, 4)]

        result = self.call([page], finalities, locators, tip_hash=forked_tip)
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["tip"], page["tip"])
        self.assertEqual(result["tip"]["height"], 4)
        self.assertEqual(result["tip"]["tip_hash"], forked_tip)
        self.assertEqual(result["tip"]["status"], "pending")
        self.assertEqual(result["finalized"], self.loc(2))
        self.assertEqual(list(result["finalized"].keys()), ANCHOR_KEYS)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["applied"], 2)

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
        self.assertEqual(data["finalized"], self.loc(2))
        # The one linear step was dropped at the anchor; only the new
        # locator step remains.
        self.assertEqual(len(data["steps"]), 1)
        step = data["steps"][0]
        self.assertEqual(list(step.keys()), STEP_KEYS)
        self.assertEqual(step["kind"], "locator")
        self.assertEqual(step["tip_hash"], forked_tip)
        self.assertEqual(step["trust"], self.trust)
        self.assertEqual(step["documents"], [page])
        self.assertEqual(step["locators"], locators)
        body = {key: data[key] for key in CHECKPOINT_KEYS if key != "hash"}
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)

        # The rewritten checkpoint strictly reloads and replays.
        located = header_locators(self.path)
        self.assertTrue(located["ok"], located)
        self.assertEqual(located["tip"], result["tip"])

    def test_boundary_at_last_matching_step_tip(self) -> None:
        # Three linear steps to a pending tip 5 with height 4 recorded
        # confirmed, and the stored finalized boundary at height 3.
        self.assertTrue(self.advance(self.paged(4))["ok"])
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        # An empty page settles the height-4 tip pending -> confirmed.
        self.assertTrue(
            self.advance([self.page(4, self.old_tip_hash)], None)["ok"]
        )
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        tip5 = self.store.tip_hash()
        self.assertTrue(
            self.advance([self.page(4, self.old_tip_hash)], None, tip_hash=tip5)[
                "ok"
            ]
        )
        # Finalize the shared height-3 block before the fork.
        raised = self.raise_boundary([self.finality(3, 5)])
        self.assertTrue(raised["ok"], raised)

        # Fork only height 5: the fork point is the confirmed height-4
        # block, the closing tip of the last matching stored step.
        forked_tip = self.fork_tip(amount=8)
        locators = [
            self.loc(5, tip5),
            self.loc(4, self.old_tip_hash),
            self.loc(0),
        ]
        page = self.locate(locators)
        self.assertEqual(page["anchor"], self.loc(4, self.old_tip_hash))
        result = self.call(
            [page], [self.finality(4, 5)], locators, tip_hash=forked_tip
        )
        self.assertTrue(result["ok"], result)
        # One step dropped, the boundary advanced 3 -> 4, one generation.
        self.assertEqual(result["generation"], 5)
        self.assertEqual(result["replaced"], 1)
        self.assertEqual(result["finalized"], self.loc(4))
        self.assertEqual(result["applied"], 1)
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 5)
        self.assertEqual(len(data["steps"]), 3)
        self.assertEqual(
            [step["kind"] for step in data["steps"]],
            ["linear", "linear", "locator"],
        )
        self.assertEqual(data["finalized"], self.loc(4))

    def test_idempotent_replay_holds_bytes_and_generation(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        page = self.locate(locators)
        finalities = [self.finality(1, 4), self.finality(2, 4)]
        first = self.call([page], finalities, locators, tip_hash=forked_tip)
        self.assertTrue(first["ok"], first)
        raw = self.read_raw()

        # Earlier credentials may replay history up to the stored
        # boundary; the identical last step plus the same final boundary
        # is idempotent.
        replay = self.call(
            [copy.deepcopy(page)],
            [self.finality(1, 4), self.finality(2, 4)],
            copy.deepcopy(locators),
            tip_hash=forked_tip,
        )
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["generation"], first["generation"])
        self.assertEqual(replay["tip"], first["tip"])
        self.assertEqual(replay["finalized"], first["finalized"])
        self.assertEqual(replay["replaced"], 0)
        self.assertEqual(replay["applied"], 2)
        self.assertEqual(self.read_raw(), raw)

    def test_same_step_with_higher_boundary_advances_boundary_only(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        page = self.locate(locators)
        first = self.call(
            [page], [self.finality(1, 4)], locators, tip_hash=forked_tip
        )
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["finalized"], self.loc(1))
        self.assertEqual(first["replaced"], 1)

        # The identical locator batch with a higher credential: no step
        # appended, nothing replaced, only the boundary moves.
        second = self.call(
            [copy.deepcopy(page)],
            [self.finality(2, 4)],
            copy.deepcopy(locators),
            tip_hash=forked_tip,
        )
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], 3)
        self.assertEqual(second["tip"], first["tip"])
        self.assertEqual(second["finalized"], self.loc(2))
        self.assertEqual(second["replaced"], 0)
        self.assertEqual(second["applied"], 1)
        data = self.read_checkpoint()
        self.assertEqual(data["generation"], 3)
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(data["finalized"], self.loc(2))

        # Replaying that exact boundary-only call is idempotent.
        raw = self.read_raw()
        third = self.call(
            [copy.deepcopy(page)],
            [self.finality(2, 4)],
            copy.deepcopy(locators),
            tip_hash=forked_tip,
        )
        self.assertTrue(third["ok"], third)
        self.assertEqual(third["generation"], 3)
        self.assertEqual(third["replaced"], 0)
        self.assertEqual(self.read_raw(), raw)

    def test_pending_to_confirmed_reorg_then_finalize_tip(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        first = self.call(
            [self.locate(locators)],
            [self.finality(1, 4)],
            locators,
            tip_hash=forked_tip,
        )
        self.assertEqual(first["tip"]["status"], "pending")

        # Confirm the forked tip; an empty locator page moves it
        # pending -> confirmed as a new locator step replacing nothing.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        confirm_locators = [self.loc(4, forked_tip), self.loc(0)]
        empty = self.locate(confirm_locators)
        self.assertEqual(empty["headers"], [])
        self.assertEqual(empty["tip"]["status"], "confirmed")
        result = self.call(
            [empty],
            [self.finality(2, 4), self.finality(4, 4)],
            confirm_locators,
            tip_hash=forked_tip,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)
        self.assertEqual(result["replaced"], 0)
        self.assertEqual(result["tip"]["status"], "confirmed")
        self.assertEqual(result["finalized"], self.loc(4))
        self.assertEqual(result["applied"], 2)
        data = self.read_checkpoint()
        self.assertEqual(
            [step["kind"] for step in data["steps"]], ["locator", "locator"]
        )
        self.assertEqual(data["finalized"], self.loc(4))

    def test_credentials_are_judged_on_the_reorged_branch(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        # Capture the old (rolled-back) height-2 hash branch descriptor.
        old_h2 = self.h(2)
        forked_tip = self.fork_tip()
        # Heights 0..3 are shared with the original chain in this fixture,
        # so finalize through them; a credential for the fork tip verifies.
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        page = self.locate(locators)
        result = self.call(
            [page],
            [self.finality(1, 2), self.finality(2, 4)],
            locators,
            tip_hash=forked_tip,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["finalized"]["block_hash"], old_h2)


class ReorgFinalizedInputTests(ReorgFinalizedFixture):
    def setUp(self) -> None:
        super().setUp()
        # Every input test needs an existing checkpoint.
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip = self.fork_tip()
        self.forked_tip = forked_tip
        self.locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        self.page = self.locate(self.locators)

    def test_path_must_be_a_non_empty_string(self) -> None:
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    reorg_finalized_headers(
                        bad_path,
                        [self.page],
                        [self.finality(1, 4)],
                        self.locators,
                        self.forked_tip,
                        self.trust,
                    ),
                    ERR_INPUT,
                )

    def test_tip_hash_must_be_64_lower_hex(self) -> None:
        for bad_tip in (None, 7, "zz", "A" * 64, "a" * 63, True):
            with self.subTest(bad_tip=bad_tip):
                self.assert_error(
                    self.call(
                        [self.page],
                        [self.finality(1, 4)],
                        self.locators,
                        tip_hash=bad_tip,
                    ),
                    ERR_INPUT,
                )

    def test_finalities_must_be_a_non_empty_array(self) -> None:
        for bad_finalities in (None, [], "x", [self.finality(1, 4), "y"]):
            with self.subTest(bad_finalities=bad_finalities):
                self.assert_error(
                    self.call(
                        [self.page], bad_finalities, self.locators
                    ),
                    ERR_INPUT,
                )

    def test_malformed_credential_is_input(self) -> None:
        good = self.finality(1, 4)
        bad_order = {
            "tip": good["tip"],
            "finalized": good["finalized"],
            "auth": good["auth"],
        }
        self.assert_error(
            self.call([self.page], [bad_order], self.locators), ERR_INPUT
        )
        bad_height = self.finality(1, 4)
        bad_height["finalized"] = {"height": True, "block_hash": self.h(1)}
        self.assert_error(
            self.call([self.page], [bad_height], self.locators), ERR_INPUT
        )
        self.assert_error(
            self.call(
                [self.page],
                [good],
                self.locators,
                trust={"audit_signers": []},
            ),
            ERR_INPUT,
        )

    def test_never_raises_on_garbage(self) -> None:
        result = reorg_finalized_headers(
            self.path, object(), object(), object(), object(), object()
        )
        self.assertEqual(result, {"ok": False, "error": ERR_INPUT})


class ReorgFinalizedAuthTests(ReorgFinalizedFixture):
    def setUp(self) -> None:
        super().setUp()
        self.assertTrue(self.advance(self.paged(2))["ok"])
        self.forked_tip = self.fork_tip()
        self.locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        self.page = self.locate(self.locators)

    def test_unknown_key_version_is_auth(self) -> None:
        credential = self.finality(1, 4, version=99)
        self.assert_error(
            self.call([self.page], [credential], self.locators), ERR_AUTH
        )

    def test_bad_finality_signature_is_auth(self) -> None:
        credential = self.finality(1, 4)
        credential["auth"] = {
            "key_version": credential["auth"]["key_version"],
            "signature": "0" * 128,
        }
        self.assert_error(
            self.call([self.page], [credential], self.locators), ERR_AUTH
        )

    def test_later_credential_bad_signature_is_auth(self) -> None:
        good = self.finality(1, 4)
        bad = self.finality(2, 4)
        bad["auth"] = {
            "key_version": bad["auth"]["key_version"],
            "signature": "f" * 128,
        }
        self.assert_error(
            self.call([self.page], [good, bad], self.locators), ERR_AUTH
        )

    def test_bad_header_page_signature_is_auth(self) -> None:
        page = copy.deepcopy(self.page)
        page["auth"] = {
            "key_version": page["auth"]["key_version"],
            "signature": "0" * 128,
        }
        self.assert_error(
            self.call(
                [page], [self.finality(1, 4)], self.locators
            ),
            ERR_AUTH,
        )

    def test_failed_auth_never_touches_the_file(self) -> None:
        raw = self.read_raw()
        credential = self.finality(1, 4, version=99)
        self.assert_error(
            self.call([self.page], [credential], self.locators), ERR_AUTH
        )
        self.assertEqual(self.read_raw(), raw)


class ReorgFinalizedIntegrityTests(ReorgFinalizedFixture):
    def _fork_page(self):
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        return forked_tip, locators, self.locate(locators)

    def test_anchor_earlier_than_finalized_is_integrity(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        # Raise the finalized boundary to height 3 before forking.
        self.assertTrue(
            self.raise_boundary([self.finality(3, 4)])["ok"]
        )
        raw = self.read_raw()
        forked_tip, locators, page = self._fork_page()
        # The locator batch anchors at genesis, before the boundary.
        self.assertEqual(page["anchor"], self.loc(0))
        self.assert_error(
            self.call(
                [page], [self.finality(1, 4)], locators, tip_hash=forked_tip
            ),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(self.read_checkpoint()["generation"], 2)

    def test_anchor_outside_history_is_integrity(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
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
        self.re_sign_page(document)
        locators = [{"height": 4, "block_hash": forged}, self.loc(0)]
        self.assert_error(
            self.call(
                [document],
                [self.finality_for(self.loc(1), document["tip"])],
                locators,
                tip_hash=forged,
            ),
            ERR_INTEGRITY,
        )

    def test_lower_reorg_tip_is_integrity(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        raw = self.read_raw()
        # Roll the pending tip back without re-mining: the service tip
        # drops to the confirmed height 3.
        self.assertEqual(self.service.rollback_block("4")[0], 200)
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assertEqual(page["tip"]["height"], 3)
        self.assert_error(
            self.call(
                [page],
                [self.finality(3, 3)],
                locators,
                tip_hash=page["tip"]["tip_hash"],
            ),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), raw)

    def test_credential_tip_hash_must_match_reorged_branch(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip, locators, page = self._fork_page()
        # A height-2 descriptor carrying a foreign hash cannot match the
        # reorged branch even though height 2 exists there.
        credential = self.finality_for(
            self.loc(1),
            {
                "tip_hash": "0" * 64,
                "height": 2,
                "length": 3,
                "status": "confirmed",
            },
        )
        self.assert_error(
            self.call([page], [credential], locators, tip_hash=forked_tip),
            ERR_INTEGRITY,
        )

    def test_credential_tip_status_must_match(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip, locators, page = self._fork_page()
        # The forked height-4 block is pending; claim it confirmed.
        credential = self.finality_for(
            self.loc(2),
            {
                "tip_hash": self.h(4),
                "height": 4,
                "length": 5,
                "status": "confirmed",
            },
        )
        self.assert_error(
            self.call([page], [credential], locators, tip_hash=forked_tip),
            ERR_INTEGRITY,
        )

    def test_finalized_heights_must_strictly_increase(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip, locators, page = self._fork_page()
        self.assert_error(
            self.call(
                [page],
                [self.finality(1, 4), self.finality(1, 4)],
                locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )
        self.assert_error(
            self.call(
                [page],
                [self.finality(2, 4), self.finality(1, 4)],
                locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )

    def test_tip_heights_must_not_decrease(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip, locators, page = self._fork_page()
        self.assert_error(
            self.call(
                [page],
                [self.finality(1, 4), self.finality(2, 2)],
                locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )

    def test_target_must_not_cross_its_own_tip(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip, locators, page = self._fork_page()
        # Finalized height 3 above the credential's own tip at height 2.
        self.assert_error(
            self.call(
                [page], [self.finality(3, 2)], locators, tip_hash=forked_tip
            ),
            ERR_INTEGRITY,
        )

    def test_pending_target_is_rejected(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip, locators, page = self._fork_page()
        # Height 4 is the pending forked tip.
        self.assert_error(
            self.call(
                [page], [self.finality(4, 4)], locators, tip_hash=forked_tip
            ),
            ERR_INTEGRITY,
        )

    def test_unknown_target_hash_is_rejected(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        forked_tip, locators, page = self._fork_page()
        credential = self.finality_for(
            self.loc(1, "0" * 64), self.descriptor(4)
        )
        self.assert_error(
            self.call([page], [credential], locators, tip_hash=forked_tip),
            ERR_INTEGRITY,
        )

    def test_target_on_the_dropped_fork_is_rejected(self) -> None:
        # Two linear steps to a confirmed tip 5 with the boundary at 3;
        # a reorg anchored at height 4 drops the old height-5 block.
        self.assertTrue(self.advance(self.paged(4))["ok"])
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        self.assertEqual(self.service.submit_transaction(self._tx(7))[0], 202)
        self.assertEqual(self.service.mine_block()[0], 201)
        old_tip5 = self.store.tip_hash()
        self.assertTrue(
            self.advance([self.page(4, self.old_tip_hash)], None,
                         tip_hash=old_tip5)["ok"]
        )
        self.assertTrue(self.raise_boundary([self.finality(3, 5)])["ok"])

        forked_tip = self.fork_tip(amount=8)
        locators = [
            self.loc(5, old_tip5),
            self.loc(4, self.old_tip_hash),
            self.loc(0),
        ]
        page = self.locate(locators)
        # A credential naming the dropped old fork's tip 5 cannot match
        # the reorged branch (its hash is absent after the prune).
        credential = self.finality_for(
            self.loc(4),
            {
                "tip_hash": old_tip5,
                "height": 5,
                "length": 6,
                "status": "pending",
            },
        )
        self.assert_error(
            self.call([page], [credential], locators, tip_hash=forked_tip),
            ERR_INTEGRITY,
        )

    def test_last_target_must_not_regress_the_boundary(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        self.assertTrue(self.raise_boundary([self.finality(3, 4)])["ok"])
        raw = self.read_raw()
        forked_tip, locators, page = self._fork_page()
        # A fully valid batch whose last target is height 2, below the
        # stored boundary at height 3.
        self.assert_error(
            self.call(
                [page],
                [self.finality(1, 4), self.finality(2, 4)],
                locators,
                tip_hash=forked_tip,
            ),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(self.read_checkpoint()["generation"], 2)

    def test_last_target_sideways_at_the_boundary_is_rejected(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        self.assertTrue(self.raise_boundary([self.finality(3, 4)])["ok"])
        forked_tip, locators, page = self._fork_page()
        credential = self.finality_for(
            self.loc(3, "0" * 64), self.descriptor(4)
        )
        self.assert_error(
            self.call([page], [credential], locators, tip_hash=forked_tip),
            ERR_INTEGRITY,
        )

    def test_failed_call_never_touches_the_file(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        raw = self.read_raw()
        forked_tip, locators, page = self._fork_page()
        # Finalizing the pending tip is an integrity failure.
        self.assert_error(
            self.call(
                [page], [self.finality(4, 4)], locators, tip_hash=forked_tip
            ),
            ERR_INTEGRITY,
        )
        self.assertEqual(self.read_raw(), raw)
        self.assertEqual(self.read_checkpoint()["generation"], 1)


class ReorgFinalizedStateIoTests(ReorgFinalizedFixture):
    def test_missing_file_is_io(self) -> None:
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assert_error(
            self.call(
                [page], [self.finality(1, 4)], locators,
                tip_hash=self.old_tip_hash,
            ),
            ERR_IO,
        )
        self.assertFalse(os.path.exists(self.path))

    def test_unreadable_path_is_io(self) -> None:
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        page = self.locate(locators)
        self.assert_error(
            self.call(
                [page],
                [self.finality(1, 4)],
                locators,
                tip_hash=self.old_tip_hash,
                path=directory,
            ),
            ERR_IO,
        )

    def test_unparseable_checkpoint_is_state(self) -> None:
        self.write_file("{not json")
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        self.assert_error(
            self.call(
                [self.locate(locators)],
                [self.finality(1, 4)],
                locators,
                tip_hash=self.old_tip_hash,
            ),
            ERR_STATE,
        )

    def _fork_page(self):
        forked_tip = self.fork_tip()
        locators = [self.loc(4, self.old_tip_hash), self.loc(0)]
        return forked_tip, locators, self.locate(locators)

    def test_tampered_hash_is_state(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        data = self.read_checkpoint()
        data["hash"] = "0" * 64
        self.write_file(data)
        forked_tip, locators, page = self._fork_page()
        self.assert_error(
            self.call(
                [page], [self.finality(1, 4)], locators, tip_hash=forked_tip
            ),
            ERR_STATE,
        )

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        self.assertTrue(self.advance(self.paged(2))["ok"])
        data = self.read_checkpoint()
        data["finalized"] = self.loc(2)
        payload = json.dumps(data)
        self.write_file(payload)
        forked_tip, locators, page = self._fork_page()
        self.assert_error(
            self.call(
                [page], [self.finality(1, 4)], locators, tip_hash=forked_tip
            ),
            ERR_STATE,
        )
        # The corrupt file is left exactly in place.
        self.assertEqual(self.read_raw().decode("utf-8"), payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)
