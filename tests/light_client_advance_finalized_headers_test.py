"""Tests for ``ledger.light_client.advance_finalized_headers``.

Builds a confirmed chain with a pending tip through the real service and
covers the atomic advance-plus-finalize checkpoint call:

* first use of ``path`` builds the version-3 checkpoint exactly as
  ``advance_headers`` does, with the last credential's target written as
  the ``finalized`` boundary and ``generation`` 1; success key order
  ``ok, generation, tip, finalized, applied`` with ``applied`` the number
  of credentials;
* re-submitting the identical last step with a finality batch ending on
  the stored boundary is idempotent — byte-identical file, no generation
  bump; a later advance appends exactly one ``linear`` step and raises
  the boundary with the generation incremented once;
* failure categories: structure/key-order/type defects ``input``, an
  unknown key version or a bad ``ledger-finality-v1`` signature ``auth``,
  tip/ordering/branch/boundary defects ``integrity``, checkpoint
  parse/digest/replay defects ``state`` and unreadable/unwritable files
  ``io``; failures never change the file bytes and nothing is raised.

Run: python3 tests/light_client_advance_finalized_headers_test.py
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
    advance_finalized_headers,
    sign_finality,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore


def pub_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "headers-checkpoint.json")
        self.store = LedgerStore(os.path.join(self.tmp, "headers.json"))
        self.service = LedgerService(self.store)
        self.key = Ed25519PrivateKey.generate()
        self.sender = pub_hex(self.key)
        self.bob = "b" * 64
        # Confirmed chain 0..3 plus pending tip at height 4.
        for amount in (10, 20, 30):
            tx = self._tx(amount)
            self.assertEqual(self.service.submit_transaction(tx)[0], 202)
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

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tx(self, amount):
        message = crypto.canonical_message(self.sender, self.bob, amount)
        return {
            "from": self.sender,
            "to": self.bob,
            "amount": amount,
            "signature": self.key.sign(message).hex(),
        }

    def h(self, height):
        return self.store.chain[height].block_hash

    def page(self, height, block_hash, limit=None):
        params = {"after_height": str(height), "after_hash": block_hash}
        if limit is not None:
            params["limit"] = str(limit)
        status, body = self.service.get_chain_headers(params)
        self.assertEqual(status, 200, body)
        return body

    def paged(self, limit):
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

    def credential(self, height=None):
        status, body = self.service.get_chain_finality()
        self.assertEqual(status, 200)
        if height is not None:
            body["finalized"] = {"height": height, "block_hash": self.h(height)}
            signer = self.store.audit_signer
            body["auth"] = sign_finality(
                signer["private_key"], signer["version"],
                body["finalized"], body["tip"],
            )
        return body

    def raw(self):
        with open(self.path, "rb") as fh:
            return fh.read()

    def err(self, result, category):
        self.assertEqual(result, {"ok": False, "error": category})


class AdvanceFinalizedTests(Fixture):
    def test_first_use_creates_checkpoint_with_boundary(self):
        docs = self.paged(2)
        creds = [self.credential(1), self.credential(3)]
        result = advance_finalized_headers(
            self.path, docs, creds, self.anchor, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(
            list(result.keys()), ["ok", "generation", "tip", "finalized", "applied"]
        )
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(
            result["finalized"], {"height": 3, "block_hash": self.h(3)}
        )
        self.assertEqual(list(result["finalized"].keys()), ["height", "block_hash"])
        self.assertEqual(result["applied"], 2)

        raw = self.raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        data = json.loads(raw)
        self.assertEqual(
            list(data.keys()),
            ["v", "generation", "anchor", "tip", "finalized", "steps", "hash"],
        )
        self.assertEqual(data["v"], 3)
        self.assertEqual(data["generation"], 1)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["finalized"], {"height": 3, "block_hash": self.h(3)})
        self.assertEqual(len(data["steps"]), 1)
        self.assertEqual(
            list(data["steps"][0].keys()),
            ["kind", "tip_hash", "trust", "documents", "locators"],
        )
        self.assertEqual(data["steps"][0]["kind"], "linear")
        self.assertIsNone(data["steps"][0]["locators"])
        body = {k: v for k, v in data.items() if k != "hash"}
        expected = hashlib.sha256(
            json.dumps(body, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["hash"], expected)

    def test_idempotent_resubmission_byte_identical(self):
        docs = self.paged(2)
        creds = [self.credential(2)]
        first = advance_finalized_headers(
            self.path, docs, creds, self.anchor, self.tip_hash, self.trust
        )
        self.assertTrue(first["ok"], first)
        before = self.raw()
        repeat = advance_finalized_headers(
            self.path, docs, creds, None, self.tip_hash, self.trust
        )
        self.assertTrue(repeat["ok"], repeat)
        self.assertEqual(repeat["generation"], 1)
        self.assertEqual(repeat["applied"], 1)
        self.assertEqual(repeat["finalized"], first["finalized"])
        self.assertEqual(self.raw(), before)

    def test_second_advance_appends_one_step_and_raises_boundary(self):
        docs = self.paged(2)
        first = advance_finalized_headers(
            self.path, docs, [self.credential(1)], self.anchor,
            self.tip_hash, self.trust,
        )
        self.assertTrue(first["ok"], first)
        # Confirm the pending tip, then advance with an empty page and
        # finalize the new confirmed tip.
        self.assertEqual(self.service.confirm_block("4")[0], 200)
        empty = self.page(4, self.tip_hash)
        cred = self.credential(4)
        result = advance_finalized_headers(
            self.path, [empty], [cred], None, self.tip_hash, self.trust
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["tip"]["status"], "confirmed")
        self.assertEqual(
            result["finalized"], {"height": 4, "block_hash": self.tip_hash}
        )
        data = json.loads(self.raw())
        self.assertEqual(len(data["steps"]), 2)
        self.assertEqual(data["generation"], 2)

    def test_input_errors(self):
        docs = self.paged(2)
        cred = self.credential(1)
        self.err(
            advance_finalized_headers("", docs, [cred], self.anchor,
                                      self.tip_hash, self.trust),
            "input",
        )
        self.err(
            advance_finalized_headers(self.path, docs, [cred], self.anchor,
                                      "zz", self.trust),
            "input",
        )
        for bad in (None, [], "x", 7):
            self.err(
                advance_finalized_headers(self.path, docs, bad, self.anchor,
                                          self.tip_hash, self.trust),
                "input",
            )
        bad_doc = copy.deepcopy(cred)
        bad_doc["finalized"] = {"block_hash": self.h(1), "height": 1}
        self.err(
            advance_finalized_headers(self.path, docs, [bad_doc], self.anchor,
                                      self.tip_hash, self.trust),
            "input",
        )
        # First use without a legal anchor.
        self.err(
            advance_finalized_headers(self.path, docs, [cred], None,
                                      self.tip_hash, self.trust),
            "input",
        )
        self.assertFalse(os.path.exists(self.path))

    def test_auth_error(self):
        docs = self.paged(2)
        cred = self.credential(1)
        sig = cred["auth"]["signature"]
        cred["auth"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        self.err(
            advance_finalized_headers(self.path, docs, [cred], self.anchor,
                                      self.tip_hash, self.trust),
            "auth",
        )
        self.assertFalse(os.path.exists(self.path))
        cred2 = self.credential(1)
        cred2["auth"]["key_version"] = 99
        self.err(
            advance_finalized_headers(self.path, docs, [cred2], self.anchor,
                                      self.tip_hash, self.trust),
            "auth",
        )

    def test_integrity_errors(self):
        docs = self.paged(2)
        # Non-increasing finalized heights inside the batch.
        creds = [self.credential(2), self.credential(2)]
        self.err(
            advance_finalized_headers(self.path, docs, creds, self.anchor,
                                      self.tip_hash, self.trust),
            "integrity",
        )
        # Pending header cannot be finalized.
        self.err(
            advance_finalized_headers(
                self.path, docs, [self.credential(4)], self.anchor,
                self.tip_hash, self.trust,
            ),
            "integrity",
        )
        # Unknown hash at a known height.
        cred = self.credential(1)
        cred["finalized"] = {"height": 1, "block_hash": "f" * 64}
        signer = self.store.audit_signer
        cred["auth"] = sign_finality(
            signer["private_key"], signer["version"],
            cred["finalized"], cred["tip"],
        )
        self.err(
            advance_finalized_headers(self.path, docs, [cred], self.anchor,
                                      self.tip_hash, self.trust),
            "integrity",
        )
        self.assertFalse(os.path.exists(self.path))

    def test_boundary_cannot_regress_on_existing_checkpoint(self):
        docs = self.paged(2)
        first = advance_finalized_headers(
            self.path, docs, [self.credential(3)], self.anchor,
            self.tip_hash, self.trust,
        )
        self.assertTrue(first["ok"], first)
        before = self.raw()
        # A new batch (same step, lower boundary) must fail integrity.
        self.err(
            advance_finalized_headers(self.path, docs, [self.credential(1)],
                                      None, self.tip_hash, self.trust),
            "integrity",
        )
        self.assertEqual(self.raw(), before)

    def test_state_and_io(self):
        docs = self.paged(2)
        cred = self.credential(1)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.err(
            advance_finalized_headers(self.path, docs, [cred], None,
                                      self.tip_hash, self.trust),
            "state",
        )
        self.assertEqual(self.raw(), b"{not json")
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        self.err(
            advance_finalized_headers(directory, docs, [cred], self.anchor,
                                      self.tip_hash, self.trust),
            "io",
        )

    def test_failed_batch_leaves_no_file_and_never_raises(self):
        result = advance_finalized_headers(object(), object(), object(),
                                           object(), object(), object())
        self.err(result, "input")
        docs = self.paged(2)
        creds = [self.credential(2), self.credential(1)]  # regressing heights
        self.err(
            advance_finalized_headers(self.path, docs, creds, self.anchor,
                                      self.tip_hash, self.trust),
            "integrity",
        )
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
