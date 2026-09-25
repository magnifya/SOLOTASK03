"""Tests for the generational checkpoint history sidecar and
``ledger.light_client.history``.

Covers:

* every successful ``advance`` also writes ``path + ".history"`` with the exact
  top-level key order ``v, base, records, head`` (``v = 1``), base key order
  ``generation, hash`` and record key order ``checkpoint, prev, hash`` where
  ``checkpoint`` is the whole five-key advance checkpoint;
* a fresh history starts ``base = {generation: 0, hash: "0"*64}``; records run
  at consecutive generations starting at ``base.generation + 1``; the first
  ``prev`` is the base hash, later ones the previous record's hash; each
  ``hash = SHA256(ASCII(prev) || canonical_json(checkpoint))`` and ``head`` is
  the last record's hash (all 64 lowercase hex);
* the sidecar is serialized exactly like the checkpoint (compact UTF-8,
  non-ASCII unescaped, one trailing newline);
* a legacy checkpoint with no sidecar is treated as
  ``base = {generation: g-1, hash: Z}`` with that checkpoint as the first
  record; the next advance appends after it;
* ``history(path)`` returns the latest, ``history(path, generation=N)`` one
  specific generation (success key order ``ok, base, record, head, kept`` with
  ``kept = null``); a missing generation is ``state``;
* ``history(path, keep=K)`` retains the last ``min(K, original)`` records:
  ``kept`` is that count, ``record`` the surviving tail, ``base`` becomes the
  last dropped record's generation/hash, the checkpoint at ``path`` is left
  byte-for-byte unchanged and no deletion means unchanged sidecar bytes;
* argument errors are ``input`` (mutually exclusive, non-boolean positive
  integers), a missing/unreadable path is ``io`` and any sidecar hash/shape/
  replay defect or orphan sidecar is ``state``;
* a failed verification never touches either file; a prune that cannot write
  is ``io`` and leaves the original sidecar bytes in place.

Run: python3 tests/checkpoint_history_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger import light_client as ledger_light_client
from ledger.light_client import (
    ERR_INPUT,
    ERR_IO,
    ERR_STATE,
    advance,
    history,
)
from ledger.models import Block, Transaction
from ledger.store import LedgerStore

NOW = 1_000_000_000
FUTURE = NOW + 10_000
BOB = "b" * 64
Z = "0" * 64

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
HISTORY_KEYS = ["v", "base", "records", "head"]
BASE_KEYS = ["generation", "hash"]
RECORD_KEYS = ["checkpoint", "prev", "hash"]
CHECKPOINT_KEYS = ["generation", "anchor", "tip", "context", "state_hash"]
RESULT_KEYS = ["ok", "base", "record", "head", "kept"]


def pub_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def record_hash(prev_hash: str, checkpoint: dict) -> str:
    return hashlib.sha256(
        prev_hash.encode("ascii") + canonical_json(checkpoint)
    ).hexdigest()


class HistoryFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "checkpoint.json")
        self.sidecar = self.path + ".history"
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice_pub = pub_hex(self.alice_key)

        genesis = LedgerStore.create_genesis()
        self.genesis = genesis
        self.anchor = {"height": 0, "block_hash": genesis.block_hash}
        self.blocks: list[Block] = []
        prev_hash = genesis.block_hash
        for position, amount in enumerate((100, 50, 25, 12, 6), start=1):
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
        self.trust = {"allowlist": {"node-plain": FUTURE}}

    def tearDown(self) -> None:
        # Restore write permission in case a test made the directory read-only.
        os.chmod(self.tmp, stat.S_IRWXU)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def anchor_after(self, index: int) -> dict:
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

    def make_page(self, anchor: dict, blocks: list, request_id: str = "r") -> dict:
        tip = self.descriptor(anchor, blocks)
        doc = {
            "source": "node-plain",
            "request_id": request_id,
            "mode": "plain",
            "expires_at": FUTURE,
            "anchor": dict(anchor),
            "blocks": [block.to_dict() for block in blocks],
            "tip": tip,
            "attestation": None,
        }
        return {key: doc[key] for key in EXPORT_KEY_ORDER}

    def advance_one(self, block_index: int, now: int = NOW, request_id: str = "r"):
        return advance(
            self.path,
            [self.make_page(self.anchor_after(block_index),
                            [self.blocks[block_index]], request_id)],
            self.trust,
            None,
            now,
        )

    def first_advance(self, count: int = 1, now: int = NOW):
        pages = []
        anchor = dict(self.anchor)
        for position in range(count):
            blocks = self.blocks[position : position + 1]
            pages.append(self.make_page(anchor, blocks, f"r{position}"))
            anchor = {
                "height": blocks[-1].height,
                "block_hash": blocks[-1].block_hash,
            }
        return advance(self.path, pages, self.trust, self.anchor, now)

    def advance_generations(self, count: int) -> None:
        """Produce generations 1..count, each one block, chained via None."""
        self.first_advance(1, NOW)
        for index in range(1, count):
            result = self.advance_one(index, NOW + index, f"r{index}")
            self.assertTrue(result["ok"], result)

    def read_sidecar(self) -> dict:
        with open(self.sidecar, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_sidecar_raw(self) -> bytes:
        with open(self.sidecar, "rb") as fh:
            return fh.read()

    def read_path_raw(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})

    def assert_chain_valid(self, doc: dict) -> None:
        """Recompute every record link and the head from the sidecar value."""
        self.assertEqual(list(doc.keys()), HISTORY_KEYS)
        self.assertEqual(doc["v"], 1)
        self.assertEqual(list(doc["base"].keys()), BASE_KEYS)
        self.assertTrue(crypto.is_hex64(doc["base"]["hash"]))
        expected_generation = doc["base"]["generation"] + 1
        running = doc["base"]["hash"]
        for record in doc["records"]:
            self.assertEqual(list(record.keys()), RECORD_KEYS)
            self.assertEqual(record["prev"], running)
            self.assertEqual(list(record["checkpoint"].keys()), CHECKPOINT_KEYS)
            self.assertEqual(record["checkpoint"]["generation"], expected_generation)
            self.assertEqual(record_hash(running, record["checkpoint"]), record["hash"])
            running = record["hash"]
            expected_generation += 1
        self.assertEqual(doc["head"], running)


class SidecarWriteTests(HistoryFixture):
    def test_first_advance_writes_sidecar_with_zero_base(self) -> None:
        result = self.first_advance(1)
        self.assertTrue(result["ok"], result)
        doc = self.read_sidecar()
        self.assertEqual(list(doc.keys()), HISTORY_KEYS)
        self.assertEqual(doc["v"], 1)
        self.assertEqual(doc["base"], {"generation": 0, "hash": Z})
        self.assertEqual(len(doc["records"]), 1)
        record = doc["records"][0]
        self.assertEqual(list(record.keys()), RECORD_KEYS)
        self.assertEqual(record["prev"], Z)
        self.assertEqual(record["checkpoint"]["generation"], 1)
        self.assertEqual(record["hash"], record_hash(Z, record["checkpoint"]))
        self.assertEqual(doc["head"], record["hash"])
        self.assert_chain_valid(doc)

    def test_sidecar_uses_checkpoint_serialization(self) -> None:
        self.first_advance(1)
        raw = self.read_sidecar_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)
        self.assertNotIn(b"\\u", raw)

    def test_sidecar_serializes_unescaped_non_ascii(self) -> None:
        source = "节点-δ"
        trust = {"allowlist": {source: FUTURE}}
        page = self.make_page(self.anchor, [self.blocks[0]])
        page["source"] = source
        result = advance(os.path.join(self.tmp, "u.json"), [page], trust,
                         self.anchor, NOW)
        self.assertTrue(result["ok"], result)
        with open(os.path.join(self.tmp, "u.json.history"), "rb") as fh:
            raw = fh.read()
        self.assertIn(source.encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)

    def test_consecutive_advances_chain_records(self) -> None:
        self.advance_generations(4)
        doc = self.read_sidecar()
        self.assert_chain_valid(doc)
        self.assertEqual(doc["base"], {"generation": 0, "hash": Z})
        generations = [r["checkpoint"]["generation"] for r in doc["records"]]
        self.assertEqual(generations, [1, 2, 3, 4])
        # prev links reference the immediate predecessor record hash.
        for position in range(1, 4):
            self.assertEqual(
                doc["records"][position]["prev"],
                doc["records"][position - 1]["hash"],
            )
        self.assertEqual(doc["head"], doc["records"][-1]["hash"])

    def test_embedded_checkpoints_equal_the_live_files(self) -> None:
        self.advance_generations(3)
        doc = self.read_sidecar()
        live = json.loads(self.read_path_raw())
        self.assertEqual(doc["records"][-1]["checkpoint"], live)


class HistoryQueryTests(HistoryFixture):
    def test_default_query_returns_latest(self) -> None:
        self.advance_generations(3)
        result = history(self.path)
        self.assertEqual(list(result.keys()), RESULT_KEYS)
        self.assertTrue(result["ok"])
        self.assertEqual(result["base"], {"generation": 0, "hash": Z})
        self.assertEqual(result["record"]["checkpoint"]["generation"], 3)
        self.assertEqual(list(result["record"].keys()), RECORD_KEYS)
        self.assertEqual(result["head"], self.read_sidecar()["head"])
        self.assertIsNone(result["kept"])

    def test_specific_generation_query(self) -> None:
        self.advance_generations(3)
        for generation in (1, 2, 3):
            with self.subTest(generation=generation):
                result = history(self.path, generation=generation)
                self.assertTrue(result["ok"], result)
                self.assertEqual(
                    result["record"]["checkpoint"]["generation"], generation
                )
                self.assertIsNone(result["kept"])
                self.assertEqual(list(result.keys()), RESULT_KEYS)

    def test_query_first_generation_prev_is_base_hash(self) -> None:
        self.advance_generations(2)
        result = history(self.path, generation=1)
        self.assertEqual(result["record"]["prev"], Z)
        self.assertEqual(result["record"]["hash"],
                         record_hash(Z, result["record"]["checkpoint"]))

    def test_missing_generation_is_state(self) -> None:
        self.advance_generations(2)
        self.assert_error(history(self.path, generation=99), ERR_STATE)

    def test_query_after_prune_only_covers_retained_range(self) -> None:
        self.advance_generations(4)
        pruned = history(self.path, keep=2)
        self.assertTrue(pruned["ok"])
        # Generations 1-2 were dropped: asking for them is state, 3-4 resolve.
        self.assert_error(history(self.path, generation=1), ERR_STATE)
        self.assert_error(history(self.path, generation=2), ERR_STATE)
        self.assertTrue(history(self.path, generation=3)["ok"])
        self.assertTrue(history(self.path, generation=4)["ok"])

    def test_input_validation(self) -> None:
        self.advance_generations(1)
        # generation and keep are mutually exclusive.
        self.assert_error(history(self.path, generation=1, keep=1), ERR_INPUT)
        # Both must be plain (non-boolean) positive integers.
        for bad in (True, False, 0, -1, 1.5, 2.0, "1", [1]):
            with self.subTest(bad=bad):
                self.assert_error(history(self.path, generation=bad), ERR_INPUT)
                self.assert_error(history(self.path, keep=bad), ERR_INPUT)
        self.assert_error(history(self.path, keep=0), ERR_INPUT)

    def test_bad_path_is_input(self) -> None:
        self.assert_error(history(""), ERR_INPUT)
        self.assert_error(history(7), ERR_INPUT)

    def test_missing_path_is_io(self) -> None:
        self.assert_error(history(os.path.join(self.tmp, "absent.json")), ERR_IO)

    def test_path_that_is_a_directory_is_io(self) -> None:
        # A directory cannot be read as a checkpoint file.
        self.assert_error(history(self.tmp), ERR_IO)


class LegacySidecarTests(HistoryFixture):
    def test_legacy_checkpoint_synthesized_as_first_record(self) -> None:
        self.first_advance(1)
        os.unlink(self.sidecar)
        result = history(self.path)
        self.assertTrue(result["ok"], result)
        # Legacy generation 1 -> base (g-1, Z) = (0, Z).
        self.assertEqual(result["base"], {"generation": 0, "hash": Z})
        self.assertEqual(result["record"]["checkpoint"]["generation"], 1)
        self.assertEqual(result["record"]["prev"], Z)
        self.assertEqual(
            result["record"]["hash"],
            record_hash(Z, result["record"]["checkpoint"]),
        )
        self.assertEqual(result["head"], result["record"]["hash"])
        self.assertIsNone(result["kept"])

    def test_legacy_generation_two_base_is_one_zero(self) -> None:
        # A legacy checkpoint at generation g gets base (g-1, Z). Build one by
        # advancing twice then deleting the sidecar: live generation is 2.
        self.advance_generations(2)
        os.unlink(self.sidecar)
        result = history(self.path)
        self.assertTrue(result["ok"])
        self.assertEqual(result["base"], {"generation": 1, "hash": Z})
        self.assertEqual(result["record"]["checkpoint"]["generation"], 2)
        self.assertEqual(result["record"]["prev"], Z)

    def test_advance_appends_after_legacy_record(self) -> None:
        self.first_advance(1)
        os.unlink(self.sidecar)
        result = self.advance_one(1, NOW + 5, "r1")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 2)
        doc = self.read_sidecar()
        self.assert_chain_valid(doc)
        self.assertEqual(doc["base"], {"generation": 0, "hash": Z})
        generations = [r["checkpoint"]["generation"] for r in doc["records"]]
        self.assertEqual(generations, [1, 2])
        # The new record links to the synthesized legacy record's hash.
        legacy_hash = record_hash(Z, doc["records"][0]["checkpoint"])
        self.assertEqual(doc["records"][0]["hash"], legacy_hash)
        self.assertEqual(doc["records"][1]["prev"], legacy_hash)


class KeepPruneTests(HistoryFixture):
    def test_keep_larger_than_count_is_noop_byte_for_byte(self) -> None:
        self.advance_generations(3)
        before = self.read_sidecar_raw()
        result = history(self.path, keep=10)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["kept"], 3)
        self.assertEqual(result["base"], {"generation": 0, "hash": Z})
        self.assertEqual(result["record"]["checkpoint"]["generation"], 3)
        self.assertEqual(self.read_sidecar_raw(), before)

    def test_keep_equal_count_is_noop(self) -> None:
        self.advance_generations(3)
        before = self.read_sidecar_raw()
        result = history(self.path, keep=3)
        self.assertEqual(result["kept"], 3)
        self.assertEqual(self.read_sidecar_raw(), before)

    def test_prune_moves_base_to_last_dropped_record(self) -> None:
        self.advance_generations(4)
        doc_before = self.read_sidecar()
        result = history(self.path, keep=2)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["kept"], 2)
        # The last dropped record is generation 2; base becomes (2, hash2).
        dropped_last = doc_before["records"][1]
        self.assertEqual(
            result["base"],
            {"generation": 2, "hash": dropped_last["hash"]},
        )
        doc = self.read_sidecar()
        self.assert_chain_valid(doc)
        self.assertEqual(doc["base"], result["base"])
        self.assertEqual(len(doc["records"]), 2)
        generations = [r["checkpoint"]["generation"] for r in doc["records"]]
        self.assertEqual(generations, [3, 4])
        # The retained suffix keeps its original prev/hash links verbatim.
        self.assertEqual(doc["records"][0]["prev"], dropped_last["hash"])
        self.assertEqual(doc["head"], doc["records"][-1]["hash"])
        # record is the surviving tail item.
        self.assertEqual(result["record"], doc["records"][-1])
        self.assertEqual(result["head"], doc["head"])

    def test_keep_one_retains_only_the_live_record(self) -> None:
        self.advance_generations(3)
        doc_before = self.read_sidecar()
        result = history(self.path, keep=1)
        self.assertEqual(result["kept"], 1)
        # Last dropped is generation 2.
        self.assertEqual(
            result["base"],
            {"generation": 2, "hash": doc_before["records"][1]["hash"]},
        )
        doc = self.read_sidecar()
        self.assertEqual(len(doc["records"]), 1)
        self.assertEqual(doc["records"][0]["checkpoint"]["generation"], 3)
        self.assert_chain_valid(doc)

    def test_prune_never_touches_the_checkpoint_file(self) -> None:
        self.advance_generations(4)
        path_before = self.read_path_raw()
        history(self.path, keep=1)
        self.assertEqual(self.read_path_raw(), path_before)
        history(self.path, keep=10)
        self.assertEqual(self.read_path_raw(), path_before)

    def test_advance_continues_after_a_prune(self) -> None:
        self.advance_generations(3)
        history(self.path, keep=1)
        result = self.advance_one(3, NOW + 20, "r3")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 4)
        doc = self.read_sidecar()
        self.assert_chain_valid(doc)
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in doc["records"]], [3, 4]
        )
        self.assertEqual(doc["base"]["generation"], 2)

    def test_prune_then_prune_again(self) -> None:
        self.advance_generations(5)
        history(self.path, keep=4)
        doc = self.read_sidecar()
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in doc["records"]],
            [2, 3, 4, 5],
        )
        # Pruning again relative to the surviving tail drops generation 2.
        result = history(self.path, keep=2)
        self.assertEqual(result["kept"], 2)
        self.assertEqual(result["base"]["generation"], 3)
        doc = self.read_sidecar()
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in doc["records"]], [4, 5]
        )
        self.assert_chain_valid(doc)


class SidecarCorruptionTests(HistoryFixture):
    def _write_sidecar(self, value: object) -> None:
        with open(self.sidecar, "w", encoding="utf-8") as fh:
            json.dump(value, fh)

    def test_corrupt_sidecar_json_is_state(self) -> None:
        self.advance_generations(1)
        with open(self.sidecar, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assert_error(history(self.path), ERR_STATE)

    def test_wrong_version_is_state(self) -> None:
        self.advance_generations(1)
        doc = self.read_sidecar()
        doc["v"] = 2
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_top_level_key_reorder_is_state(self) -> None:
        self.advance_generations(1)
        doc = self.read_sidecar()
        reordered = {key: doc[key] for key in ("head", "v", "base", "records")}
        self._write_sidecar(reordered)
        self.assert_error(history(self.path), ERR_STATE)

    def test_record_key_reorder_is_state(self) -> None:
        self.advance_generations(1)
        doc = self.read_sidecar()
        record = doc["records"][0]
        doc["records"][0] = {
            key: record[key] for key in ("hash", "checkpoint", "prev")
        }
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_tampered_prev_is_state(self) -> None:
        self.advance_generations(2)
        doc = self.read_sidecar()
        doc["records"][1]["prev"] = "f" * 64
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_tampered_record_hash_is_state(self) -> None:
        self.advance_generations(1)
        doc = self.read_sidecar()
        doc["records"][0]["hash"] = "f" * 64
        doc["head"] = "f" * 64
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_tampered_head_is_state(self) -> None:
        self.advance_generations(1)
        doc = self.read_sidecar()
        doc["head"] = "f" * 64
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_non_consecutive_generation_is_state(self) -> None:
        self.advance_generations(2)
        doc = self.read_sidecar()
        doc["records"][1]["checkpoint"]["generation"] = 9
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_tampered_embedded_checkpoint_is_state(self) -> None:
        self.advance_generations(1)
        doc = self.read_sidecar()
        doc["records"][0]["checkpoint"]["tip"]["height"] = 999
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_last_record_must_equal_live_checkpoint(self) -> None:
        self.advance_generations(2)
        doc = self.read_sidecar()
        # Drop the live generation-2 record but keep head pointing at gen 1:
        # the surviving last record no longer equals the file at path.
        doc["records"] = doc["records"][:1]
        doc["head"] = doc["records"][0]["hash"]
        self._write_sidecar(doc)
        self.assert_error(history(self.path), ERR_STATE)

    def test_orphan_sidecar_without_checkpoint_is_state(self) -> None:
        with open(self.sidecar, "w", encoding="utf-8") as fh:
            json.dump(
                {"v": 1, "base": {"generation": 0, "hash": Z},
                 "records": [], "head": Z},
                fh,
            )
        self.assert_error(history(self.path), ERR_STATE)

    def test_tampered_sidecar_blocks_advance_too(self) -> None:
        self.advance_generations(1)
        doc = self.read_sidecar()
        doc["head"] = "f" * 64
        self._write_sidecar(doc)
        result = self.advance_one(1, NOW + 5, "r1")
        self.assert_error(result, ERR_STATE)
        # Neither file was rebuilt.
        self.assertEqual(self.read_sidecar()["head"], "f" * 64)


class TransactionTests(HistoryFixture):
    def test_failed_verification_touches_neither_file(self) -> None:
        self.advance_generations(1)
        sidecar_before = self.read_sidecar_raw()
        path_before = self.read_path_raw()
        page = self.make_page(self.anchor, [self.blocks[1]], "rx")
        result = advance(
            self.path, [page],
            {"allowlist": {"unknown": FUTURE}},  # unauthorized source
            None, NOW + 1,
        )
        self.assert_error(result, "auth")
        self.assertEqual(self.read_sidecar_raw(), sidecar_before)
        self.assertEqual(self.read_path_raw(), path_before)

    def test_prune_write_failure_is_io_and_keeps_bytes(self) -> None:
        from unittest import mock

        self.advance_generations(3)
        before = self.read_sidecar_raw()
        real_write = ledger_light_client._atomic_write_bytes

        def fail_write(target, payload, prefix=".light-checkpoint-"):
            raise OSError("simulated prune write failure")

        with mock.patch.object(
            ledger_light_client, "_atomic_write_bytes", side_effect=fail_write
        ):
            result = history(self.path, keep=1)
        self.assert_error(result, ERR_IO)
        # The commit never promoted anything: original sidecar (and checkpoint)
        # bytes are exactly in place.
        self.assertEqual(self.read_sidecar_raw(), before)

    def test_advance_compensates_checkpoint_when_sidecar_write_fails(self) -> None:
        from unittest import mock

        self.advance_generations(1)
        sidecar_before = self.read_sidecar_raw()
        path_before = self.read_path_raw()
        real_write = ledger_light_client._atomic_write_bytes
        sidecar_target = self.sidecar
        calls = {"n": 0}

        def flaky_write(target, payload, prefix=".light-checkpoint-"):
            calls["n"] += 1
            # Commit order is checkpoint first, sidecar second: fail only the
            # sidecar promotion so the checkpoint must be rolled back.
            if target == sidecar_target and calls["n"] == 2:
                raise OSError("simulated sidecar write failure")
            return real_write(target, payload, prefix)

        with mock.patch.object(
            ledger_light_client, "_atomic_write_bytes", side_effect=flaky_write
        ):
            result = self.advance_one(1, NOW + 5, "r1")
        self.assert_error(result, ERR_IO)
        # Compensation restored both files to their pre-transaction bytes.
        self.assertEqual(self.read_path_raw(), path_before)
        self.assertEqual(self.read_sidecar_raw(), sidecar_before)
        # The history is still internally consistent after the rollback.
        self.assertTrue(history(self.path)["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
