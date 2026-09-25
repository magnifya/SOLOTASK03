"""Tests for the persistent light-client range checkpoint
(ledger.light_client.advance) and for the snapshot key-order strictness of
trust_sources / source_key_history records.

Covers, for advance(): first-use anchor pinning, generation monotonicity from
1, the declared state/context key orders, the state_hash digest, the compact
unescaped-UTF-8 single-newline file format, resumption with anchor=None or
the stored tip (anchor or descriptor form), anchor/state conflicts (state),
corrupt checkpoints never being truncated or rebuilt (state), I/O failures
(io), now validation (input) and verification failures leaving the file and
generation untouched.

For the key-order fixes: out-of-order trust_sources records,
source_key_history items and keys entries are input errors in
consistency.verify_snapshot and raise StateRecoveryError (carrying path and a
non-empty reason) on store recovery.

Run: python3 tests/light_client_advance_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.consistency import verify_snapshot
from ledger.light_client import (
    CHECKPOINT_CONTEXT_KEYS,
    CHECKPOINT_STATE_KEYS,
    advance,
)
from ledger.models import Block, Transaction
from ledger.service import LedgerService
from ledger.store import LedgerStore, StateRecoveryError

NOW = 1_000_000_000
FUTURE = NOW + 10_000
BOB = "b" * 64
_DEFAULT = object()

RESULT_KEY_ORDER = ["ok", "anchor", "tip", "pages", "verified_tx_ids", "generation"]
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


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


class AdvanceFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "checkpoint.json")
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice_pub = pub_hex(self.alice_key)

        self.anchor_block = LedgerStore.create_genesis()
        self.anchor = {"height": 0, "block_hash": self.anchor_block.block_hash}

        # An eight-block chain, one transaction per block.
        self.txs = []
        self.blocks = []
        prev_hash = self.anchor_block.block_hash
        for position, amount in enumerate([100, 50, 25, 12, 6, 3, 2, 1], start=1):
            tx = Transaction(
                self.alice_pub,
                BOB,
                amount,
                self.alice_key.sign(
                    crypto.canonical_message(self.alice_pub, BOB, amount)
                ).hex(),
            )
            block = Block.create(position, prev_hash, [tx])
            self.txs.append(tx)
            self.blocks.append(block)
            prev_hash = block.block_hash

        self.trust = {"allowlist": {"node-plain": FUTURE}}

    def descriptor(self, anchor: dict, blocks: list) -> dict:
        last = blocks[-1]
        return {
            "tip_hash": last.block_hash,
            "height": last.height,
            "length": anchor["height"] + 1 + len(blocks),
            "status": last.status,
        }

    def make_page(self, anchor: dict, blocks: list, index: int = 0) -> dict:
        doc = {
            "source": "node-plain",
            "request_id": f"r{index}",
            "mode": "plain",
            "expires_at": FUTURE,
            "anchor": dict(anchor),
            "blocks": [b.to_dict() for b in blocks],
            "tip": self.descriptor(anchor, blocks),
            "attestation": None,
        }
        return {key: doc[key] for key in EXPORT_KEY_ORDER}

    def make_pages(self, sizes, blocks=None) -> list:
        chain = self.blocks if blocks is None else blocks
        pages = []
        anchor = dict(self.anchor)
        cursor = 0
        for position, size in enumerate(sizes):
            slice_blocks = chain[cursor : cursor + size]
            pages.append(self.make_page(anchor, slice_blocks, index=position))
            anchor = {
                "height": slice_blocks[-1].height,
                "block_hash": slice_blocks[-1].block_hash,
            }
            cursor += size
        return pages

    def advance(self, docs, anchor=None, now=NOW, trust=None, path=_DEFAULT):
        return advance(
            self.path if path is _DEFAULT else path,
            docs,
            self.trust if trust is None else trust,
            anchor,
            now,
        )

    def read_state(self) -> dict:
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class AdvanceSuccessTests(AdvanceFixture):
    def test_first_advance_result_shape_and_generation(self) -> None:
        result = self.advance(self.make_pages([2, 2]), anchor=self.anchor)
        self.assertEqual(list(result.keys()), RESULT_KEY_ORDER)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["anchor"], self.anchor)
        self.assertEqual(
            result["verified_tx_ids"], sorted(tx.tx_id for tx in self.txs[:4])
        )

    def test_state_file_layout_key_orders_and_hash(self) -> None:
        result = self.advance(self.make_pages([2, 2]), anchor=self.anchor)
        self.assertTrue(result["ok"], result)
        with open(self.path, "rb") as fh:
            raw = fh.read()
        # Compact, non-ASCII unescaped, exactly one trailing newline.
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b'": ', raw)
        self.assertNotIn(b", ", raw)
        document = json.loads(raw.decode("utf-8"))
        self.assertEqual(tuple(document.keys()), CHECKPOINT_STATE_KEYS)
        self.assertEqual(document["generation"], 1)
        self.assertEqual(document["anchor"], result["anchor"])
        self.assertEqual(document["tip"], result["tip"])
        context = document["context"]
        self.assertEqual(tuple(context.keys()), CHECKPOINT_CONTEXT_KEYS)
        self.assertEqual(context["verified_at"], NOW)
        self.assertEqual(context["trust"], self.trust)
        self.assertEqual(context["verified_tx_ids"], result["verified_tx_ids"])
        payload = {key: document[key] for key in CHECKPOINT_STATE_KEYS[:-1]}
        self.assertEqual(
            document["state_hash"], hashlib.sha256(canonical(payload)).hexdigest()
        )

    def test_non_ascii_content_is_not_escaped(self) -> None:
        trust = {"allowlist": {"节点-1": FUTURE}}
        pages = self.make_pages([2])
        for page in pages:
            page["source"] = "节点-1"
        result = self.advance(pages, anchor=self.anchor, trust=trust)
        self.assertTrue(result["ok"], result)
        with open(self.path, "rb") as fh:
            raw = fh.read()
        self.assertIn("节点-1".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        # The state_hash covers the unescaped canonical bytes too.
        document = json.loads(raw.decode("utf-8"))
        payload = {key: document[key] for key in CHECKPOINT_STATE_KEYS[:-1]}
        self.assertEqual(
            document["state_hash"], hashlib.sha256(canonical(payload)).hexdigest()
        )

    def test_second_advance_with_none_anchor_chains_from_stored_tip(self) -> None:
        first = self.advance(self.make_pages([4]), anchor=self.anchor)
        self.assertEqual(first["generation"], 1)
        # The next batch starts where the stored tip closed.
        anchor = {"height": 4, "block_hash": self.blocks[3].block_hash}
        pages = [self.make_page(anchor, self.blocks[4:7], index=1)]
        second = self.advance(pages, anchor=None)
        self.assertEqual(second["generation"], 2, second)
        self.assertEqual(second["tip"]["height"], 7)
        state = self.read_state()
        self.assertEqual(state["generation"], 2)
        self.assertEqual(state["tip"], second["tip"])
        # The stored anchor is the latest batch's pinned anchor, so the
        # persisted context replays end-to-end on the next load.
        self.assertEqual(state["anchor"], anchor)

    def test_second_advance_with_stored_tip_anchor_forms(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        anchor_form = {
            "height": first["tip"]["height"],
            "block_hash": first["tip"]["tip_hash"],
        }
        pages_a = [self.make_page(anchor_form, self.blocks[2:4], index=1)]
        second = self.advance(pages_a, anchor=anchor_form)
        self.assertEqual(second["generation"], 2, second)
        # The full tip descriptor returned earlier is accepted too.
        anchor_b = {"height": 4, "block_hash": self.blocks[3].block_hash}
        pages_b = [self.make_page(anchor_b, self.blocks[4:6], index=2)]
        third = self.advance(pages_b, anchor=dict(second["tip"]))
        self.assertEqual(third["generation"], 3, third)

    def test_failed_advance_does_not_advance_generation(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        self.assertEqual(first["generation"], 1)
        # A batch that does not chain from the stored tip fails integrity and
        # must leave the checkpoint file byte-identical.
        with open(self.path, "rb") as fh:
            before = fh.read()
        bad = self.make_pages([2, 2])  # anchors at genesis, not the stored tip
        result = self.advance(bad, anchor=None)
        self.assert_error(result, "integrity")
        with open(self.path, "rb") as fh:
            self.assertEqual(fh.read(), before)
        # A legal continuation still lands at generation 2, never 3.
        anchor = {"height": 2, "block_hash": self.blocks[1].block_hash}
        ok = self.advance([self.make_page(anchor, self.blocks[2:4], index=1)])
        self.assertEqual(ok["generation"], 2, ok)


class AdvanceInputTests(AdvanceFixture):
    def test_now_must_be_a_non_boolean_non_negative_integer(self) -> None:
        pages = self.make_pages([2])
        for bad in (None, True, False, -1, 1.5, "100", (1,)):
            with self.subTest(now=bad):
                self.assert_error(
                    self.advance(pages, anchor=self.anchor, now=bad), "input"
                )
        self.assertFalse(os.path.exists(self.path))

    def test_first_use_requires_an_anchor(self) -> None:
        self.assert_error(self.advance(self.make_pages([2]), anchor=None), "input")

    def test_first_use_anchor_shape_defects(self) -> None:
        pages = self.make_pages([2])
        for bad in (
            {},
            {"height": 0},
            {"height": "0", "block_hash": self.anchor["block_hash"]},
            {"height": -1, "block_hash": self.anchor["block_hash"]},
            {"height": 0, "block_hash": "00"},
        ):
            with self.subTest(anchor=bad):
                self.assert_error(self.advance(pages, anchor=bad), "input")

    def test_bad_path_is_input(self) -> None:
        pages = self.make_pages([2])
        for bad in (None, "", 3, True):
            with self.subTest(path=bad):
                self.assert_error(
                    self.advance(pages, anchor=self.anchor, path=bad), "input"
                )

    def test_verification_failure_categories_pass_through(self) -> None:
        pages = self.make_pages([2])
        pages[0]["source"] = "node-other"
        self.assert_error(self.advance(pages, anchor=self.anchor), "auth")
        self.assertFalse(os.path.exists(self.path))
        pages = self.make_pages([2])
        pages[0]["expires_at"] = NOW
        self.assert_error(self.advance(pages, anchor=self.anchor), "expired")
        self.assertFalse(os.path.exists(self.path))


class AdvanceStateTests(AdvanceFixture):
    def test_conflicting_anchor_is_state(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        self.assertTrue(first["ok"], first)
        wrong = {"height": 0, "block_hash": "0" * 64}
        result = self.advance(self.make_pages([2]), anchor=wrong)
        self.assert_error(result, "state")
        # A descriptor-form anchor that is not the stored tip conflicts too.
        result = self.advance(
            self.make_pages([2]),
            anchor={
                "tip_hash": "0" * 64,
                "height": 2,
                "length": 3,
                "status": "confirmed",
            },
        )
        self.assert_error(result, "state")
        self.assertEqual(self.read_state()["generation"], 1)

    def test_tampered_file_is_state_and_never_rebuilt(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        self.assertTrue(first["ok"], first)
        document = self.read_state()
        document["generation"] = 7  # hash no longer covers the payload
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        anchor = {"height": 2, "block_hash": self.blocks[1].block_hash}
        result = self.advance([self.make_page(anchor, self.blocks[2:4], index=1)])
        self.assert_error(result, "state")
        # The corrupt file is left alone, not truncated or reset to genesis.
        self.assertEqual(self.read_state()["generation"], 7)

    def test_reordered_state_keys_are_state(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        self.assertTrue(first["ok"], first)
        document = self.read_state()
        reordered = {key: document[key] for key in reversed(CHECKPOINT_STATE_KEYS)}
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(reordered, fh)
        result = self.advance(self.make_pages([2]))
        self.assert_error(result, "state")

    def test_reordered_context_keys_are_state(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        self.assertTrue(first["ok"], first)
        document = self.read_state()
        context = document["context"]
        document["context"] = {
            key: context[key] for key in reversed(CHECKPOINT_CONTEXT_KEYS)
        }
        # Re-seal so only the key-order defect remains.
        payload = {key: document[key] for key in CHECKPOINT_STATE_KEYS[:-1]}
        document["state_hash"] = hashlib.sha256(canonical(payload)).hexdigest()
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        result = self.advance(self.make_pages([2]))
        self.assert_error(result, "state")

    def test_truncated_file_is_state(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        self.assertTrue(first["ok"], first)
        with open(self.path, "rb") as fh:
            raw = fh.read()
        with open(self.path, "wb") as fh:
            fh.write(raw[: len(raw) // 2])
        result = self.advance(self.make_pages([2]))
        self.assert_error(result, "state")

    def test_resealed_but_different_context_fails_replay(self) -> None:
        first = self.advance(self.make_pages([2]), anchor=self.anchor)
        self.assertTrue(first["ok"], first)
        document = self.read_state()
        # Swap in a different (valid) batch and re-seal the hash: the replayed
        # verification no longer reproduces the stored tip.
        document["context"]["documents"] = self.make_pages([3])
        payload = {key: document[key] for key in CHECKPOINT_STATE_KEYS[:-1]}
        document["state_hash"] = hashlib.sha256(canonical(payload)).hexdigest()
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        result = self.advance(self.make_pages([2]))
        self.assert_error(result, "state")

    def test_io_failure(self) -> None:
        # A directory at the checkpoint path cannot be read as a file.
        os.mkdir(os.path.join(self.tmp, "dir-checkpoint"))
        result = self.advance(
            self.make_pages([2]),
            anchor=self.anchor,
            path=os.path.join(self.tmp, "dir-checkpoint"),
        )
        self.assert_error(result, "io")


class SnapshotKeyOrderTests(unittest.TestCase):
    """Out-of-order trust record keys: input offline, fatal on recovery."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.path, initial_balance=1000), initial_balance=1000
        )
        self.assertEqual(
            self.svc.register_trust_source(
                {"source": "node-1", "public_key": "ab" * 32, "expires_at": FUTURE}
            )[0],
            201,
        )

    def load_snapshot(self) -> dict:
        with open(self.path, encoding="utf-8") as fh:
            return json.load(fh)

    def reopen(self) -> None:
        LedgerStore(self.path, initial_balance=1000)

    def test_snapshot_has_trust_sections(self) -> None:
        doc = self.load_snapshot()
        self.assertEqual(len(doc["trust_sources"]), 1)
        self.assertEqual(len(doc["source_key_history"]), 1)
        self.assertTrue(verify_snapshot(doc)["ok"])

    def test_trust_source_record_out_of_order_keys(self) -> None:
        doc = self.load_snapshot()
        record = doc["trust_sources"][0]
        doc["trust_sources"][0] = {
            key: record[key] for key in reversed(list(record.keys()))
        }
        self.assertEqual(verify_snapshot(doc)["error"], "input")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            self.reopen()
        self.assertEqual(ctx.exception.path, self.path)
        self.assertTrue(ctx.exception.reason)

    def test_source_key_history_item_out_of_order_keys(self) -> None:
        doc = self.load_snapshot()
        item = doc["source_key_history"][0]
        # The snapshot persists item keys sorted ("keys" before "source").
        doc["source_key_history"][0] = {"source": item["source"], "keys": item["keys"]}
        self.assertEqual(verify_snapshot(doc)["error"], "input")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            self.reopen()
        self.assertEqual(ctx.exception.path, self.path)
        self.assertTrue(ctx.exception.reason)

    def test_source_key_history_keys_entry_out_of_order_keys(self) -> None:
        doc = self.load_snapshot()
        entry = doc["source_key_history"][0]["keys"][0]
        doc["source_key_history"][0]["keys"][0] = {
            key: entry[key] for key in reversed(list(entry.keys()))
        }
        self.assertEqual(verify_snapshot(doc)["error"], "input")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        with self.assertRaises(StateRecoveryError) as ctx:
            self.reopen()
        self.assertEqual(ctx.exception.path, self.path)
        self.assertTrue(ctx.exception.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
