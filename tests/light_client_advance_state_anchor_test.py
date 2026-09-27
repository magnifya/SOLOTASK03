"""Tests for the persisted account-state anchor companion of a v3 header
checkpoint (``ledger.light_client.advance_state_anchor``).

Builds a confirmed chain through the real service, checkpoints its signed
header pages and advances the finalized boundary with a signed finality
credential, then covers the ``path + ".state"`` sidecar:

* the header checkpoint and the sidecar are loaded together under the
  per-path lock before an incoming proof is judged;
* the new attested state proof is re-verified via ``verify_state_proof`` and
  must pin the checkpoint's current ``finalized`` boundary (height and
  block hash);
* sidecar file shape: exact top-level key order
  ``v, generation, account, anchor, document, trust, hash`` with ``v`` 1,
  ``generation`` a positive non-boolean integer, anchor key order
  ``height, block_hash, state_root``, ``document``/``trust`` saved verbatim
  and ``hash`` the self-excluding canonical-JSON SHA-256; compact UTF-8
  JSON, non-ASCII unescaped, one trailing LF, atomically replaced;
* generation starts at 1; same account + same anchor is idempotent (no
  write, generation held); switching accounts, a non-finalized proof, a
  regression or a same-height/other-value anchor are ``integrity``; a
  higher finalized boundary increments the generation by one;
* success key order ``ok, generation, anchor``; failure only
  ``ok, error`` with categories ``input``/``auth``/``integrity``/``state``/
  ``io``; a failure never changes either file and the function never
  raises on garbage.

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
    STATE_ANCHOR_KEYS,
    advance_headers,
    advance_state_anchor,
    apply_finality,
)
from ledger.service import LedgerService
from ledger.store import LedgerStore

ANCHOR_KEYS = ["height", "block_hash", "state_root"]

_DEFAULT = object()


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def canonical(obj: object) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class StateAnchorFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "headers.json")
        self.state_path = self.path + ".state"
        self.store = LedgerStore(os.path.join(self.tmp, "ledger.json"))
        self.service = LedgerService(self.store, initial_balance=100_000)
        self.kA, self.A = (lambda k: (k, pub_hex(k)))(Ed25519PrivateKey.generate())
        self.kB, self.B = (lambda k: (k, pub_hex(k)))(Ed25519PrivateKey.generate())
        self.kC, self.C = (lambda k: (k, pub_hex(k)))(Ed25519PrivateKey.generate())
        self.bob = "b" * 64
        self._n = 0

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tx(self, key: Ed25519PrivateKey, sender: str, to: str) -> dict:
        amount = 5 + self._n
        self._n += 1
        message = crypto.canonical_message(sender, to, amount)
        return {
            "from": sender,
            "to": to,
            "amount": amount,
            "signature": key.sign(message).hex(),
        }

    def build_blocks(self, count: int) -> None:
        signers = ((self.kA, self.A, self.B),
                   (self.kC, self.C, self.A),
                   (self.kB, self.B, self.A))
        for _ in range(count):
            key, sender, to = signers[(self._n) % 3]
            self.assertEqual(
                self.service.submit_transaction(self._tx(key, sender, to))[0],
                202,
            )
            self.assertEqual(self.service.mine_block()[0], 201)
            self.assertEqual(
                self.service.confirm_block(str(self.store.tip().height))[0],
                200,
            )

    def pages(self, cursor: dict) -> list:
        """Signed header pages from ``cursor`` up to the current tip."""
        documents = []
        tip_hash = self.store.tip_hash()
        while True:
            status, page = self.service.get_chain_headers(
                {
                    "after_height": str(cursor["height"]),
                    "after_hash": cursor["block_hash"],
                }
            )
            self.assertEqual(status, 200, page)
            documents.append(page)
            if not page["headers"]:
                break
            last = page["headers"][-1]
            cursor = {"height": last["height"], "block_hash": last["block_hash"]}
            if last["block_hash"] == tip_hash:
                break
        return documents

    CONTINUE = object()

    def checkpoint_to_tip(self, from_anchor: object) -> dict:
        """Advance the header checkpoint by paging to the current tip.

        Pass the genesis anchor on first use; pass :attr:`CONTINUE` on a
        later continuation (pages are fetched from the previously stored
        tip and the advance anchor argument is ``None``)."""
        if from_anchor is self.CONTINUE:
            page_start = dict(self.stored_tip)
            anchor_arg: dict | None = None
        else:
            page_start = dict(from_anchor)  # type: ignore[arg-type]
            anchor_arg = from_anchor  # type: ignore[assignment]
        result = advance_headers(
            self.path,
            self.pages(page_start),
            anchor_arg,
            self.store.tip_hash(),
            self.trust,
        )
        self.assertTrue(result["ok"], result)
        self.stored_tip = {
            "height": result["tip"]["height"],
            "block_hash": result["tip"]["tip_hash"],
        }
        return result

    def finalize_tip(self) -> dict:
        status, document = self.service.get_chain_finality()
        self.assertEqual(status, 200, document)
        result = apply_finality(self.path, document, self.trust)
        self.assertTrue(result["ok"], result)
        return result["finalized"]

    def state_proof(self, account: str, params=None) -> dict:
        status, document = self.service.get_attested_account_proof(
            account, params
        )
        self.assertEqual(status, 200, document)
        return document

    def setup_checkpoint(self, blocks: int = 2) -> dict:
        """Create a v3 header checkpoint over ``blocks`` confirmed blocks and
        advance its finalized boundary to the tip; returns the finalized
        anchor ``{height, block_hash}``."""
        self.build_blocks(blocks)
        self.trust = self.service.get_trust_document()[1]
        genesis = self.store.chain[0].block_hash
        self.checkpoint_to_tip({"height": 0, "block_hash": genesis})
        return self.finalize_tip()

    def read_state(self) -> dict:
        with open(self.state_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_state_raw(self) -> bytes:
        with open(self.state_path, "rb") as fh:
            return fh.read()

    def advance(self, document=_DEFAULT, account=_DEFAULT, trust=_DEFAULT) -> dict:
        return advance_state_anchor(
            self.path,
            self.doc if document is _DEFAULT else document,
            self.A if account is _DEFAULT else account,
            self.trust if trust is _DEFAULT else trust,
        )


class AdvanceStateAnchorSuccessTests(StateAnchorFixture):
    def test_first_advance_generation_one_and_file_shape(self) -> None:
        finalized = self.setup_checkpoint()
        self.doc = self.state_proof(self.A)
        result = self.advance()
        self.assertTrue(result["ok"], result)
        self.assertEqual(list(result), ["ok", "generation", "anchor"])
        self.assertEqual(result["generation"], 1)
        self.assertEqual(list(result["anchor"]), ANCHOR_KEYS)
        self.assertEqual(result["anchor"]["height"], finalized["height"])
        self.assertEqual(result["anchor"]["block_hash"], finalized["block_hash"])
        self.assertEqual(
            result["anchor"]["state_root"], self.doc["state"]["state_root"]
        )

        raw = self.read_state_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        record = json.loads(raw)
        self.assertEqual(list(record), list(STATE_ANCHOR_KEYS))
        self.assertEqual(list(record["anchor"]), ANCHOR_KEYS)
        self.assertEqual(record["v"], 1)
        self.assertEqual(record["generation"], 1)
        self.assertEqual(record["account"], self.A)
        # document/trust are saved verbatim.
        self.assertEqual(record["document"], self.doc)
        self.assertEqual(record["trust"], self.trust)
        # The hash is the self-excluding canonical-JSON SHA-256.
        body = {key: value for key, value in record.items() if key != "hash"}
        self.assertEqual(
            record["hash"], hashlib.sha256(canonical(body)).hexdigest()
        )
        # The on-disk bytes are compact, declared-key-order JSON.
        self.assertEqual(
            raw,
            json.dumps(
                record, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8") + b"\n",
        )

    def test_idempotent_same_account_same_anchor_does_not_write(self) -> None:
        self.setup_checkpoint()
        self.doc = self.state_proof(self.A)
        first = self.advance()
        self.assertTrue(first["ok"])
        size = os.path.getsize(self.state_path)
        mtime = os.path.getmtime(self.state_path)
        again = self.advance(
            document=copy.deepcopy(self.doc), trust=copy.deepcopy(self.trust)
        )
        self.assertTrue(again["ok"], again)
        self.assertEqual(again["generation"], 1)
        self.assertEqual(again["anchor"], first["anchor"])
        self.assertEqual(os.path.getsize(self.state_path), size)
        self.assertEqual(os.path.getmtime(self.state_path), mtime)

    def test_higher_finalized_increments_generation(self) -> None:
        self.setup_checkpoint(blocks=2)
        first_doc = self.state_proof(self.A)
        first = advance_state_anchor(self.path, first_doc, self.A, self.trust)
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["generation"], 1)
        first_finalized = {"height": first["anchor"]["height"],
                           "block_hash": first["anchor"]["block_hash"]}

        # One more confirmed block, checkpoint it and finalize it.
        self.build_blocks(1)
        self.checkpoint_to_tip(self.CONTINUE)
        new_finalized = self.finalize_tip()
        self.assertGreater(new_finalized["height"], first_finalized["height"])

        new_doc = self.state_proof(self.A)
        result = advance_state_anchor(self.path, new_doc, self.A, self.trust)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        self.assertEqual(result["anchor"]["height"], new_finalized["height"])
        self.assertEqual(result["anchor"]["block_hash"], new_finalized["block_hash"])
        # The sidecar keeps a single record of the latest anchor.
        record = self.read_state()
        self.assertEqual(record["generation"], 2)
        self.assertEqual(
            record["anchor"]["state_root"], new_doc["state"]["state_root"]
        )


class AdvanceStateAnchorFailureTests(StateAnchorFixture):
    def setUp(self) -> None:
        super().setUp()
        self.finalized = self.setup_checkpoint()
        self.doc = self.state_proof(self.A)

    def test_switching_account_is_integrity(self) -> None:
        self.assertTrue(self.advance()["ok"])
        self.assertEqual(
            self.advance(account=self.B),
            {"ok": False, "error": ERR_INTEGRITY},
        )
        # The rejected account switch did not advance the generation.
        self.assertEqual(self.read_state()["generation"], 1)

    def test_proof_at_non_finalized_height_is_integrity(self) -> None:
        historical = self.state_proof(self.A, {"height": "1"})
        self.assertLess(
            historical["state"]["height"], self.finalized["height"]
        )
        self.assertEqual(
            self.advance(document=historical),
            {"ok": False, "error": ERR_INTEGRITY},
        )
        self.assertFalse(os.path.exists(self.state_path))

    def test_regression_to_lower_anchor_is_integrity(self) -> None:
        self.assertTrue(self.advance()["ok"])
        self.build_blocks(1)
        self.checkpoint_to_tip(self.CONTINUE)
        self.finalize_tip()
        new_doc = self.state_proof(self.A)
        self.assertTrue(
            advance_state_anchor(self.path, new_doc, self.A, self.trust)["ok"]
        )
        # Feeding the older finalized proof again regresses the anchor.
        self.assertEqual(
            self.advance(),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_bad_arguments_are_input(self) -> None:
        for bad_path in ("", None, 7, b"x"):
            self.assertEqual(
                advance_state_anchor(bad_path, self.doc, self.A, self.trust),
                {"ok": False, "error": ERR_INPUT},
                bad_path,
            )
        for bad_account in (None, 7, "ZZ", "a" * 63, "A" * 64):
            self.assertEqual(
                self.advance(account=bad_account),
                {"ok": False, "error": ERR_INPUT},
                bad_account,
            )
        for bad_document in (None, 7, "x", [], {"state": 1},
                             {"state": {}, "proof": {}, "auth": {}}):
            self.assertEqual(
                self.advance(document=bad_document),
                {"ok": False, "error": ERR_INPUT},
            )

    def test_unknown_signer_version_is_auth(self) -> None:
        bad = copy.deepcopy(self.doc)
        bad["auth"] = {**bad["auth"], "key_version": 42}
        self.assertEqual(
            self.advance(document=bad), {"ok": False, "error": ERR_AUTH}
        )
        self.assertFalse(os.path.exists(self.state_path))

    def test_bad_signature_is_auth(self) -> None:
        bad = copy.deepcopy(self.doc)
        signature = bad["auth"]["signature"]
        flipped = ("0" if signature[0] != "0" else "1") + signature[1:]
        bad["auth"] = {**bad["auth"], "signature": flipped}
        self.assertEqual(
            self.advance(document=bad), {"ok": False, "error": ERR_AUTH}
        )

    def test_missing_header_checkpoint_is_io(self) -> None:
        missing = os.path.join(self.tmp, "absent.json")
        result = advance_state_anchor(missing, self.doc, self.A, self.trust)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})

    def test_damaged_header_checkpoint_is_state(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(
            self.advance(), {"ok": False, "error": ERR_STATE}
        )

    def test_damaged_sidecar_digest_is_state(self) -> None:
        self.assertTrue(self.advance()["ok"])
        record = self.read_state()
        # A sidecar whose digest no longer matches is state corruption.
        record["generation"] = 999
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        self.assertEqual(
            self.advance(), {"ok": False, "error": ERR_STATE}
        )

    def test_resealed_tampered_sidecar_is_state(self) -> None:
        self.assertTrue(self.advance()["ok"])
        record = self.read_state()
        # Tamper with the anchor but re-seal a matching digest: the stored
        # proof no longer binds to it, so strict load still reports state.
        record["anchor"]["state_root"] = "0" * 64
        body = {key: value for key, value in record.items() if key != "hash"}
        record["hash"] = hashlib.sha256(canonical(body)).hexdigest()
        with open(self.state_path, "w", encoding="utf-8") as fh:
            json.dump(record, fh)
        self.assertEqual(
            self.advance(), {"ok": False, "error": ERR_STATE}
        )

    def test_sidecar_naming_a_dropped_point_is_state(self) -> None:
        self.assertTrue(self.advance()["ok"])
        # Craft a self-consistent attested state proof at a height the
        # replayed header branch never reaches. verify_state_proof passes on
        # load (the document is internally valid and signed by the audit
        # key), the stored anchor binds to it, but old-anchor branch
        # ownership must reject the unknown height as state corruption.
        from ledger.light_client import sign_state_proof

        account = "d" * 64
        leaf = crypto.account_state_leaf(account, 42, [])
        block_hash = "c" * 64
        state = {
            "state_root": leaf,
            "height": 500,
            "block_hash": block_hash,
            "account_count": 1,
        }
        proof = {
            "account": account,
            "balance": 42,
            "confirmed_transactions": [],
            "index": 0,
            "state_root": leaf,
            "height": 500,
            "block_hash": block_hash,
            "siblings": [],
        }
        signer = self.store.audit_signer
        auth = sign_state_proof(
            signer["private_key"], signer["version"], state, proof
        )
        document = {"state": state, "proof": proof, "auth": auth}
        record = {
            "v": 1,
            "generation": 1,
            "account": account,
            "anchor": {
                "height": 500,
                "block_hash": block_hash,
                "state_root": leaf,
            },
            "document": document,
            "trust": self.trust,
        }
        body = {key: value for key, value in record.items()}
        record["hash"] = hashlib.sha256(canonical(body)).hexdigest()
        with open(self.state_path, "w", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    record, ensure_ascii=False, separators=(",", ":")
                )
                + "\n"
            )
        self.assertEqual(
            self.advance(), {"ok": False, "error": ERR_STATE}
        )

    def test_never_raises_on_garbage(self) -> None:
        for document in (None, 5, object(), {"state": 1}):
            for account in (None, object(), self.A):
                for trust in (None, 7, object(), self.trust):
                    result = advance_state_anchor(
                        self.path, document, account, trust
                    )
                    self.assertIn(result.get("ok"), (True, False))
                    if not result["ok"]:
                        self.assertEqual(set(result), {"ok", "error"})
                        self.assertIn(
                            result["error"],
                            {"input", "auth", "integrity", "state", "io"},
                        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
