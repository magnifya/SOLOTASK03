"""Tests for the durable range-advance checkpoint
(``ledger.light_client.advance``).

Covers:

* a first advance from a legal anchor and later advances with ``None`` or the
  stored tip's ``{height, block_hash}``;
* file shape: exact top-level key order ``generation, anchor, tip, context,
  state_hash``, context key order ``verified_at, trust, documents,
  verified_tx_ids``, compact UTF-8 JSON with non-ASCII unescaped and one
  trailing newline;
* generation starting at 1 and incremented only on success (a failed
  verification never bumps it);
* success result key order with ``generation`` last;
* error categories ``input`` (bad path/now/anchor), ``auth``/``expired``/
  ``integrity`` (batch verification), ``state`` (existing checkpoint key
  order, types, state hash or verified_at replay mismatch) and ``io``;
* an unreadable/unwritable path is ``io`` while a present-but-malformed file
  is ``state``, and a corrupt checkpoint is never truncated or rebuilt.

Run: python3 tests/light_client_advance_test.py
"""
from __future__ import annotations

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
    ERR_EXPIRED,
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_IO,
    ERR_STATE,
    advance,
)
from ledger.models import Block, Transaction
from ledger.store import LedgerStore, attested_range_message

NOW = 1_000_000_000
FUTURE = NOW + 10_000
BOB = "b" * 64

EXPORT_KEY_ORDER = [
    "source",
    "request_id",
    "mode",
    "expires_at",
    "anchor",
    "blocks",
    "tip",
    "attestation",
]
CHECKPOINT_KEYS = ["generation", "anchor", "tip", "context", "state_hash"]
CONTEXT_KEYS = ["verified_at", "trust", "documents", "verified_tx_ids"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


class AdvanceFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "checkpoint.json")
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice_pub = pub_hex(self.alice_key)

        genesis = LedgerStore.create_genesis()
        self.genesis = genesis
        self.anchor = {"height": 0, "block_hash": genesis.block_hash}
        self.blocks: list[Block] = []
        prev_hash = genesis.block_hash
        for position, amount in enumerate((100, 50, 25, 12), start=1):
            tx = Transaction(
                self.alice_pub,
                BOB,
                amount,
                self.alice_key.sign(
                    crypto.canonical_message(self.alice_pub, BOB, amount)
                ).hex(),
            )
            block = Block.create(position, prev_hash, [tx])
            self.blocks.append(block)
            prev_hash = block.block_hash
        self.trust = {
            "sources": {
                "node-att": {"public_key": self.source_pub, "expires_at": FUTURE}
            },
            "allowlist": {"node-plain": FUTURE},
        }

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def anchor_after(self, index: int) -> dict:
        """The closed anchor immediately preceding self.blocks[index]."""
        if index == 0:
            return dict(self.anchor)
        block = self.blocks[index - 1]
        return {"height": block.height, "block_hash": block.block_hash}

    def descriptor(self, anchor: dict, blocks: list) -> dict:
        last = blocks[-1]
        return {
            "tip_hash": last.block_hash,
            "height": last.height,
            "length": anchor["height"] + 1 + len(blocks),
            "status": last.status,
        }

    def make_page(
        self,
        anchor: dict,
        blocks: list,
        *,
        source: str = "node-plain",
        mode: str = "plain",
        request_id: str | None = None,
        expires_at: int = FUTURE,
        signing_key: Ed25519PrivateKey | None = None,
    ) -> dict:
        tip = self.descriptor(anchor, blocks)
        attestation = None
        if mode == "attested":
            key = signing_key or self.source_key
            message = attested_range_message(
                source,
                request_id or "r",
                expires_at,
                anchor,
                [block.to_dict() for block in blocks],
                tip,
            )
            signature = key.sign(hashlib.sha256(message).digest()).hex()
            attestation = {
                "public_key": pub_hex(key),
                "version": 1,
                "signature": signature,
            }
        doc = {
            "source": source,
            "request_id": request_id or "r",
            "mode": mode,
            "expires_at": expires_at,
            "anchor": dict(anchor),
            "blocks": [block.to_dict() for block in blocks],
            "tip": tip,
            "attestation": attestation,
        }
        return {key: doc[key] for key in EXPORT_KEY_ORDER}

    def pages(self, sizes, *, blocks=None, source="node-plain", mode="plain"):
        chain = blocks if blocks is not None else self.blocks
        pages = []
        anchor = dict(self.anchor)
        cursor = 0
        for position, size in enumerate(sizes):
            slice_blocks = chain[cursor : cursor + size]
            pages.append(
                self.make_page(
                    anchor,
                    slice_blocks,
                    source=source,
                    mode=mode,
                    request_id=f"r{position}",
                )
            )
            anchor = {
                "height": slice_blocks[-1].height,
                "block_hash": slice_blocks[-1].block_hash,
            }
            cursor += size
        return pages

    def continuation_page(self, start: int, count: int = 1, **kwargs) -> dict:
        """One page covering self.blocks[start:start+count], anchored correctly."""
        return self.make_page(
            self.anchor_after(start),
            self.blocks[start : start + count],
            **kwargs,
        )

    def read_checkpoint(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})

    def advance(self, docs, anchor, now=NOW, trust=None):
        return advance(
            self.path,
            docs,
            self.trust if trust is None else trust,
            anchor,
            now,
        )


class AdvanceSuccessTests(AdvanceFixture):
    def test_first_advance_writes_generation_one_and_expected_shape(self) -> None:
        docs = self.pages([2])
        result = self.advance(docs, self.anchor)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)
        # The generation is appended as the final result key.
        self.assertEqual(
            list(result.keys()),
            ["ok", "anchor", "tip", "pages", "verified_tx_ids", "generation"],
        )
        self.assertEqual(result["tip"]["height"], 2)
        self.assertEqual(result["pages"], 1)

        raw = self.read_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b"\\u", raw)
        data = json.loads(raw)
        self.assertEqual(list(data.keys()), CHECKPOINT_KEYS)
        self.assertEqual(data["generation"], 1)
        self.assertEqual(data["anchor"], self.anchor)
        self.assertEqual(data["tip"], result["tip"])
        self.assertEqual(list(data["context"].keys()), CONTEXT_KEYS)
        self.assertEqual(data["context"]["verified_at"], NOW)
        self.assertEqual(data["context"]["documents"], docs)
        self.assertEqual(
            data["context"]["verified_tx_ids"], result["verified_tx_ids"]
        )

    def test_file_is_compact_unescaped_utf8(self) -> None:
        # A non-ASCII source/trust key is written unescaped, and the document
        # carries no insignificant whitespace between tokens.
        key = Ed25519PrivateKey.generate()
        pub = pub_hex(key)
        source = "节点-δ"
        trust = {"allowlist": {source: FUTURE}}
        page = self.make_page(self.anchor, [self.blocks[0]], source=source)
        result = advance(os.path.join(self.tmp, "u.json"), [page], trust, self.anchor, NOW)
        self.assertTrue(result["ok"], result)
        with open(os.path.join(self.tmp, "u.json"), "rb") as fh:
            raw = fh.read()
        self.assertIn(source.encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertTrue(raw.endswith(b"\n"))

    def test_state_hash_covers_the_other_fields(self) -> None:
        result = self.advance(self.pages([1]), self.anchor)
        self.assertTrue(result["ok"])
        data = self.read_checkpoint()
        body = {
            "generation": data["generation"],
            "anchor": data["anchor"],
            "tip": data["tip"],
            "context": data["context"],
        }
        expected = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(data["state_hash"], expected)

    def test_continue_with_none_anchor_chains_from_stored_tip(self) -> None:
        first = self.advance(self.pages([1]), self.anchor)
        self.assertEqual(first["generation"], 1)
        second = self.advance([self.continuation_page(1)], None, now=NOW + 5)
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["generation"], 2)
        self.assertEqual(second["anchor"]["height"], 1)
        self.assertEqual(second["tip"]["height"], 2)
        self.assertEqual(self.read_checkpoint()["generation"], 2)

    def test_continue_with_explicit_stored_tip_anchor(self) -> None:
        self.advance(self.pages([2]), self.anchor)
        stored_tip = self.read_checkpoint()["tip"]
        tip_anchor = {"height": stored_tip["height"], "block_hash": stored_tip["tip_hash"]}
        result = self.advance([self.continuation_page(2)], tip_anchor, now=NOW + 6)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)

    def test_reload_replays_context_on_the_next_advance(self) -> None:
        docs = self.pages([1])
        first = self.advance(docs, self.anchor)
        self.assertTrue(first["ok"])
        # A second process/instance continuing the same path must accept it.
        result = advance(
            os.path.join(self.tmp, "checkpoint.json"),
            [self.continuation_page(1)],
            self.trust,
            None,
            NOW + 9,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)


class AdvanceInputTests(AdvanceFixture):
    def test_now_must_be_a_non_boolean_non_negative_integer(self) -> None:
        docs = self.pages([1])
        for bad_now in (True, False, -1, 1.5, "1", None, [1]):
            with self.subTest(bad_now=bad_now):
                self.assert_error(self.advance(docs, self.anchor, bad_now), ERR_INPUT)

    def test_path_must_be_a_non_empty_string(self) -> None:
        docs = self.pages([1])
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assert_error(
                    advance(bad_path, docs, self.trust, self.anchor, NOW),
                    ERR_INPUT,
                )

    def test_first_use_requires_a_legal_anchor(self) -> None:
        docs = self.pages([1])
        for bad_anchor in (
            None,
            {},
            {"height": 0},
            {"height": True, "block_hash": self.anchor["block_hash"]},
            {"height": -1, "block_hash": self.anchor["block_hash"]},
            {"height": 0, "block_hash": "zz"},
            {"height": 0, "block_hash": self.anchor["block_hash"], "x": 1},
        ):
            with self.subTest(bad_anchor=bad_anchor):
                self.assert_error(self.advance(docs, bad_anchor), ERR_INPUT)

    def test_later_anchor_must_be_none_or_the_stored_tip(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        # A legal anchor that names a block other than the stored tip is input.
        self.assert_error(
            self.advance([self.continuation_page(1)], self.anchor), ERR_INPUT
        )
        self.assert_error(
            self.advance(
                [self.continuation_page(1)],
                {"height": 9, "block_hash": "a" * 64},
            ),
            ERR_INPUT,
        )

    def test_empty_batch_is_input(self) -> None:
        self.assert_error(self.advance([], self.anchor), ERR_INPUT)


class AdvanceVerificationTests(AdvanceFixture):
    def test_auth_failure(self) -> None:
        docs = self.pages([1], source="unknown")
        self.assert_error(self.advance(docs, self.anchor), ERR_AUTH)

    def test_expired_failure(self) -> None:
        docs = self.pages([1])
        self.assert_error(self.advance(docs, self.anchor, now=FUTURE + 1), ERR_EXPIRED)

    def test_integrity_failure_on_broken_seam(self) -> None:
        # Continuing with None from a stored tip, then delivering a page
        # anchored elsewhere fails integrity (verification, not input).
        self.advance(self.pages([1]), self.anchor)
        bad_page = self.make_page(
            self.anchor,  # wrong anchor: still genesis, not block 1
            [self.blocks[1]],
            request_id="rx",
        )
        self.assert_error(self.advance([bad_page], None), ERR_INTEGRITY)

    def test_attested_pages_verify(self) -> None:
        docs = self.pages([1], source="node-att", mode="attested")
        result = self.advance(docs, self.anchor)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 1)

    def test_failed_verification_does_not_bump_generation(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        generation = self.read_checkpoint()["generation"]
        before = self.read_raw()
        self.assert_error(
            self.advance(self.pages([1], source="unknown"), None), ERR_AUTH
        )
        # File untouched: same generation, same bytes.
        self.assertEqual(self.read_checkpoint()["generation"], generation)
        self.assertEqual(self.read_raw(), before)


class AdvanceStateTests(AdvanceFixture):
    def _checkpoint_text(self) -> str:
        return self.read_raw().decode("utf-8")

    def _write(self, data) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            if isinstance(data, str):
                fh.write(data)
            else:
                json.dump(data, fh)

    def test_top_level_key_reorder_is_state(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        reordered = {
            key: data[key]
            for key in ("tip", "generation", "context", "anchor", "state_hash")
        }
        self._write(reordered)
        self.assert_error(self.advance(self.pages([1]), self.anchor), ERR_STATE)

    def test_context_key_reorder_is_state(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        ctx = data["context"]
        data["context"] = {
            key: ctx[key]
            for key in ("trust", "verified_at", "documents", "verified_tx_ids")
        }
        self._write(data)
        self.assert_error(self.advance(self.pages([1]), None), ERR_STATE)

    def test_tampered_generation_is_state(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        data["generation"] = 99
        self._write(data)
        self.assert_error(self.advance(self.pages([1]), None), ERR_STATE)

    def test_tampered_state_hash_is_state(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        data["state_hash"] = "0" * 64
        self._write(data)
        self.assert_error(self.advance(self.pages([1]), None), ERR_STATE)

    def test_wrong_field_type_is_state(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        data["generation"] = "1"
        self._write(data)
        self.assert_error(self.advance(self.pages([1]), None), ERR_STATE)

    def test_context_documents_tamper_replay_is_state(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        # Tamper a delivered block hash; the hash still pins the stored bytes
        # so first re-hash them, then the replay must disagree.
        data["context"]["documents"][0]["blocks"][0]["block_hash"] = "0" * 64
        body = {
            "generation": data["generation"],
            "anchor": data["anchor"],
            "tip": data["tip"],
            "context": data["context"],
        }
        data["state_hash"] = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self._write(data)
        self.assert_error(self.advance(self.pages([1]), None), ERR_STATE)

    def test_context_verified_tx_ids_tamper_is_state(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        data["context"]["verified_tx_ids"].append("f" * 64)
        body = {
            "generation": data["generation"],
            "anchor": data["anchor"],
            "tip": data["tip"],
            "context": data["context"],
        }
        data["state_hash"] = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self._write(data)
        self.assert_error(self.advance(self.pages([1]), None), ERR_STATE)

    def test_corrupt_json_is_state_not_io(self) -> None:
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assert_error(self.advance(self.pages([1]), self.anchor), ERR_STATE)

    def test_corrupt_checkpoint_is_never_truncated(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        data["state_hash"] = "1" * 64
        payload = json.dumps(data)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(payload)
        result = self.advance(self.pages([1]), None)
        self.assert_error(result, ERR_STATE)
        # The corrupt file is left exactly in place.
        self.assertEqual(self.read_raw().decode("utf-8"), payload)

    def test_wrong_verified_at_trust_expiry_is_state(self) -> None:
        # The checkpoint was verified while the allowlist was valid; advancing
        # later (even with a fresh valid trust) must replay the stored batch at
        # the stored verified_at against the *stored* trust — but here the
        # stored trust itself expired by the stored verified_at's replay only
        # after tampering, so tamper the stored verified_at beyond its
        # deadline and re-pin the hash: replay must report state.
        self.advance(self.pages([1]), self.anchor)
        data = self.read_checkpoint()
        data["context"]["verified_at"] = FUTURE + 1
        body = {
            "generation": data["generation"],
            "anchor": data["anchor"],
            "tip": data["tip"],
            "context": data["context"],
        }
        data["state_hash"] = hashlib.sha256(
            json.dumps(
                body, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self._write(data)
        self.assert_error(self.advance(self.pages([1]), None), ERR_STATE)


class AdvanceIoTests(AdvanceFixture):
    def test_unwritable_target_path_is_io(self) -> None:
        # Advancing at a path that is a directory cannot atomically replace.
        directory = os.path.join(self.tmp, "a-directory")
        os.makedirs(directory)
        result = advance(
            directory, self.pages([1]), self.trust, self.anchor, NOW
        )
        self.assert_error(result, ERR_IO)


if __name__ == "__main__":
    unittest.main(verbosity=2)
