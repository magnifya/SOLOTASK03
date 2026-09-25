"""Tests for the advance checkpoint generation-history sidecar
(``ledger.light_client.advance`` writing ``path + ".history"``) and the
``ledger.light_client.history`` query/prune entry point.

Covers:

* sidecar shape: exact top-level key order ``v, base, records, head``, base
  key order ``generation, hash``, record key order ``checkpoint, prev, hash``
  with ``checkpoint`` the persisted five-key document, compact UTF-8 JSON
  with non-ASCII unescaped and one trailing newline;
* chaining: generations consecutive from ``base.generation + 1``, first
  ``prev`` = ``base.hash``, later ``prev`` = previous record's ``hash``,
  ``hash = SHA256(ASCII(prev) || canonical_json(checkpoint))``, ``head`` the
  last record's hash;
* bootstrap: a fresh path starts at ``base = {0, Z}`` (Z = 64 zeros) and a
  pre-existing generation-``g`` checkpoint without a sidecar is migrated as
  ``base = {g-1, Z}`` with that checkpoint as the first record;
* ``history`` queries (default last / explicit generation), ``keep`` pruning
  (``kept = min(keep, count)``, base advancing to the last pruned record,
  untouched bytes when nothing is pruned, checkpoint file never rewritten);
* error categories ``input`` (bad arguments), ``io`` (missing/unreadable/
  unwritable sidecar) and ``state`` (tampered sidecar, unknown generation,
  sidecar/checkpoint mismatch, orphan sidecar);
* transactional ``io`` compensation restoring the original bytes.

Run: python3 tests/light_client_history_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from light_client_advance_test import (  # noqa: E402
    NOW,
    FUTURE,
    AdvanceFixture,
)

from ledger.light_client import (  # noqa: E402
    ERR_INPUT,
    ERR_IO,
    ERR_STATE,
    advance,
    history,
)

ZERO = "0" * 64
HISTORY_KEYS = ["v", "base", "records", "head"]
BASE_KEYS = ["generation", "hash"]
RECORD_KEYS = ["checkpoint", "prev", "hash"]
CHECKPOINT_KEYS = ["generation", "anchor", "tip", "context", "state_hash"]


def canonical_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def record_hash(prev: str, checkpoint: dict) -> str:
    return hashlib.sha256(
        prev.encode("ascii") + canonical_bytes(checkpoint)
    ).hexdigest()


class HistoryFixture(AdvanceFixture):
    def setUp(self) -> None:
        super().setUp()
        self.sidecar_path = self.path + ".history"

    def sidecar_exists(self) -> bool:
        return os.path.exists(self.sidecar_path)

    def read_sidecar(self) -> dict:
        with open(self.sidecar_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_sidecar_raw(self) -> bytes:
        with open(self.sidecar_path, "rb") as fh:
            return fh.read()

    def write_sidecar(self, data) -> None:
        with open(self.sidecar_path, "w", encoding="utf-8") as fh:
            if isinstance(data, str):
                fh.write(data)
            else:
                json.dump(data, fh)

    def assert_chain(self, sidecar: dict, count: int) -> None:
        """The full sidecar invariant: shape, chaining, hashes and head."""
        self.assertEqual(list(sidecar.keys()), HISTORY_KEYS)
        self.assertEqual(sidecar["v"], 1)
        self.assertEqual(list(sidecar["base"].keys()), BASE_KEYS)
        records = sidecar["records"]
        self.assertEqual(len(records), count)
        prev = sidecar["base"]["hash"]
        generation = sidecar["base"]["generation"]
        for record in records:
            self.assertEqual(list(record.keys()), RECORD_KEYS)
            self.assertEqual(list(record["checkpoint"].keys()), CHECKPOINT_KEYS)
            generation += 1
            self.assertEqual(record["checkpoint"]["generation"], generation)
            self.assertEqual(record["prev"], prev)
            self.assertEqual(
                record["hash"], record_hash(prev, record["checkpoint"])
            )
            prev = record["hash"]
        self.assertEqual(sidecar["head"], prev)

    def advance_n(self, count: int) -> None:
        """Advance ``count`` single-block generations from the genesis anchor."""
        anchor = self.anchor
        for index in range(count):
            result = self.advance([self.continuation_page(index)], anchor)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["generation"], index + 1)
            anchor = None


class SidecarShapeTests(HistoryFixture):
    def test_first_advance_writes_sidecar_with_zero_base(self) -> None:
        result = self.advance(self.pages([1]), self.anchor)
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.sidecar_exists())

        raw = self.read_sidecar_raw()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertFalse(raw.endswith(b"\n\n"))
        self.assertNotIn(b", ", raw)
        self.assertNotIn(b": ", raw)

        sidecar = json.loads(raw)
        self.assert_chain(sidecar, 1)
        self.assertEqual(sidecar["base"], {"generation": 0, "hash": ZERO})
        record = sidecar["records"][0]
        self.assertEqual(record["prev"], ZERO)
        self.assertEqual(record["checkpoint"], self.read_checkpoint())
        self.assertEqual(sidecar["head"], record["hash"])

    def test_sidecar_is_compact_unescaped_utf8(self) -> None:
        source = "节点-δ"
        trust = {"allowlist": {source: FUTURE}}
        page = self.make_page(self.anchor, [self.blocks[0]], source=source)
        path = os.path.join(self.tmp, "u.json")
        result = advance(path, [page], trust, self.anchor, NOW)
        self.assertTrue(result["ok"], result)
        with open(path + ".history", "rb") as fh:
            raw = fh.read()
        self.assertIn(source.encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertTrue(raw.endswith(b"\n"))

    def test_advance_appends_and_chains_records(self) -> None:
        self.advance_n(3)
        sidecar = self.read_sidecar()
        self.assert_chain(sidecar, 3)
        self.assertEqual(sidecar["base"], {"generation": 0, "hash": ZERO})
        generations = [
            record["checkpoint"]["generation"] for record in sidecar["records"]
        ]
        self.assertEqual(generations, [1, 2, 3])
        # The last record pins exactly the persisted checkpoint document.
        self.assertEqual(sidecar["records"][-1]["checkpoint"], self.read_checkpoint())

    def test_failed_verification_leaves_sidecar_untouched(self) -> None:
        self.advance(self.pages([1]), self.anchor)
        before = self.read_sidecar_raw()
        checkpoint_before = self.read_raw()
        result = self.advance(self.pages([1], source="unknown"), None)
        self.assertEqual(result, {"ok": False, "error": "auth"})
        self.assertEqual(self.read_sidecar_raw(), before)
        self.assertEqual(self.read_raw(), checkpoint_before)

    def test_migration_from_legacy_checkpoint_without_sidecar(self) -> None:
        # Two generations written by an old version: no sidecar exists.
        self.advance_n(2)
        legacy_checkpoint = self.read_checkpoint()
        os.unlink(self.sidecar_path)

        result = self.advance([self.continuation_page(2)], None, now=NOW + 7)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 3)

        sidecar = self.read_sidecar()
        self.assert_chain(sidecar, 2)
        # The legacy checkpoint became the first record over a zero base one
        # generation below it.
        self.assertEqual(sidecar["base"], {"generation": 1, "hash": ZERO})
        first, second = sidecar["records"]
        self.assertEqual(first["checkpoint"], legacy_checkpoint)
        self.assertEqual(first["prev"], ZERO)
        self.assertEqual(second["checkpoint"], self.read_checkpoint())
        self.assertEqual(second["prev"], first["hash"])
        self.assertEqual(sidecar["head"], second["hash"])


class HistoryQueryTests(HistoryFixture):
    def test_default_query_reports_the_last_generation(self) -> None:
        self.advance_n(3)
        result = history(self.path)
        self.assertEqual(list(result.keys()), ["ok", "base", "record", "head", "kept"])
        self.assertTrue(result["ok"], result)
        self.assertIsNone(result["kept"])
        self.assertEqual(result["base"], {"generation": 0, "hash": ZERO})
        self.assertEqual(list(result["record"].keys()), RECORD_KEYS)
        self.assertEqual(result["record"]["checkpoint"]["generation"], 3)
        sidecar = self.read_sidecar()
        self.assertEqual(result["record"], sidecar["records"][-1])
        self.assertEqual(result["head"], sidecar["head"])

    def test_query_specific_generation(self) -> None:
        self.advance_n(3)
        result = history(self.path, generation=2)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["record"]["checkpoint"]["generation"], 2)
        self.assertEqual(result["record"], self.read_sidecar()["records"][1])
        self.assertIsNone(result["kept"])

    def test_query_unknown_generation_is_state(self) -> None:
        self.advance_n(2)
        self.assertEqual(
            history(self.path, generation=9), {"ok": False, "error": ERR_STATE}
        )

    def test_query_does_not_touch_the_files(self) -> None:
        self.advance_n(2)
        sidecar_before = self.read_sidecar_raw()
        checkpoint_before = self.read_raw()
        self.assertTrue(history(self.path)["ok"])
        self.assertTrue(history(self.path, generation=1)["ok"])
        self.assertEqual(self.read_sidecar_raw(), sidecar_before)
        self.assertEqual(self.read_raw(), checkpoint_before)

    def test_mutually_exclusive_and_positive_integer_arguments(self) -> None:
        self.advance_n(1)
        self.assertEqual(
            history(self.path, generation=1, keep=1),
            {"ok": False, "error": ERR_INPUT},
        )
        for bad in (0, -1, True, False, 1.5, "1", [1]):
            with self.subTest(bad=bad):
                self.assertEqual(
                    history(self.path, generation=bad),
                    {"ok": False, "error": ERR_INPUT},
                )
                self.assertEqual(
                    history(self.path, keep=bad),
                    {"ok": False, "error": ERR_INPUT},
                )

    def test_bad_path_is_input(self) -> None:
        for bad_path in ("", None, 7):
            with self.subTest(bad_path=bad_path):
                self.assertEqual(
                    history(bad_path), {"ok": False, "error": ERR_INPUT}
                )

    def test_missing_sidecar_is_io(self) -> None:
        # Never advanced at all.
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_IO})
        # A checkpoint without its sidecar (legacy or lost) is also missing.
        self.advance_n(1)
        os.unlink(self.sidecar_path)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_IO})


class HistoryKeepTests(HistoryFixture):
    def test_keep_prunes_and_advances_base(self) -> None:
        self.advance_n(4)
        sidecar = self.read_sidecar()
        checkpoint_before = self.read_raw()
        pruned_hash = sidecar["records"][1]["hash"]  # generation 2 record

        result = history(self.path, keep=2)
        self.assertEqual(list(result.keys()), ["ok", "base", "record", "head", "kept"])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["kept"], 2)
        self.assertEqual(
            result["base"], {"generation": 2, "hash": pruned_hash}
        )
        self.assertEqual(result["record"]["checkpoint"]["generation"], 4)
        self.assertEqual(result["head"], sidecar["head"])

        pruned = self.read_sidecar()
        self.assert_chain(pruned, 2)
        self.assertEqual(pruned["base"], {"generation": 2, "hash": pruned_hash})
        generations = [
            record["checkpoint"]["generation"] for record in pruned["records"]
        ]
        self.assertEqual(generations, [3, 4])
        self.assertEqual(pruned["records"][0]["prev"], pruned_hash)
        self.assertEqual(pruned["head"], sidecar["head"])
        # The checkpoint file itself is never rewritten by a prune.
        self.assertEqual(self.read_raw(), checkpoint_before)

    def test_keep_beyond_count_leaves_bytes_untouched(self) -> None:
        self.advance_n(2)
        before = self.read_sidecar_raw()
        result = history(self.path, keep=10)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["kept"], 2)
        self.assertEqual(result["base"], {"generation": 0, "hash": ZERO})
        self.assertEqual(result["record"]["checkpoint"]["generation"], 2)
        self.assertEqual(self.read_sidecar_raw(), before)

    def test_keep_exact_count_leaves_bytes_untouched(self) -> None:
        self.advance_n(2)
        before = self.read_sidecar_raw()
        result = history(self.path, keep=2)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["kept"], 2)
        self.assertEqual(self.read_sidecar_raw(), before)

    def test_pruned_generation_is_no_longer_queryable(self) -> None:
        self.advance_n(3)
        self.assertTrue(history(self.path, keep=1)["ok"])
        self.assertEqual(
            history(self.path, generation=2), {"ok": False, "error": ERR_STATE}
        )
        result = history(self.path, generation=3)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["base"]["generation"], 2)

    def test_advance_continues_after_a_prune(self) -> None:
        self.advance_n(3)
        self.assertTrue(history(self.path, keep=1)["ok"])
        result = self.advance([self.continuation_page(3)], None, now=NOW + 3)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["generation"], 4)
        sidecar = self.read_sidecar()
        self.assert_chain(sidecar, 2)
        self.assertEqual(sidecar["base"]["generation"], 2)
        generations = [
            record["checkpoint"]["generation"] for record in sidecar["records"]
        ]
        self.assertEqual(generations, [3, 4])

    def test_failed_keep_write_restores_original_bytes(self) -> None:
        self.advance_n(3)
        before = self.read_sidecar_raw()
        with mock.patch(
            "ledger.light_client._atomic_write_history",
            side_effect=OSError("disk full"),
        ):
            result = history(self.path, keep=1)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertEqual(self.read_sidecar_raw(), before)


class HistoryStateTests(HistoryFixture):
    def test_corrupt_sidecar_json_is_state(self) -> None:
        self.advance_n(1)
        self.write_sidecar("{not json")
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_top_level_key_reorder_is_state(self) -> None:
        self.advance_n(1)
        sidecar = self.read_sidecar()
        reordered = {
            key: sidecar[key] for key in ("base", "v", "head", "records")
        }
        self.write_sidecar(reordered)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_wrong_version_is_state(self) -> None:
        self.advance_n(1)
        sidecar = self.read_sidecar()
        sidecar["v"] = 2
        self.write_sidecar(sidecar)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_tampered_record_hash_is_state(self) -> None:
        self.advance_n(2)
        sidecar = self.read_sidecar()
        sidecar["records"][0]["hash"] = "1" * 64
        self.write_sidecar(sidecar)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_tampered_prev_link_is_state(self) -> None:
        self.advance_n(2)
        sidecar = self.read_sidecar()
        sidecar["records"][1]["prev"] = "2" * 64
        self.write_sidecar(sidecar)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_tampered_head_is_state(self) -> None:
        self.advance_n(1)
        sidecar = self.read_sidecar()
        sidecar["head"] = "3" * 64
        self.write_sidecar(sidecar)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_tampered_base_is_state(self) -> None:
        self.advance_n(1)
        sidecar = self.read_sidecar()
        sidecar["base"]["generation"] = 5
        self.write_sidecar(sidecar)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_dropped_record_is_state(self) -> None:
        self.advance_n(2)
        sidecar = self.read_sidecar()
        del sidecar["records"][0]
        self.write_sidecar(sidecar)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_tampered_record_checkpoint_is_state(self) -> None:
        self.advance_n(1)
        sidecar = self.read_sidecar()
        sidecar["records"][0]["checkpoint"]["generation"] = 7
        self.write_sidecar(sidecar)
        self.assertEqual(history(self.path), {"ok": False, "error": ERR_STATE})

    def test_corrupt_sidecar_blocks_advance_with_state(self) -> None:
        self.advance_n(1)
        sidecar = self.read_sidecar()
        sidecar["head"] = "4" * 64
        payload = json.dumps(sidecar)
        self.write_sidecar(payload)
        result = self.advance([self.continuation_page(1)], None)
        self.assertEqual(result, {"ok": False, "error": ERR_STATE})
        # Neither file is truncated or rebuilt.
        self.assertEqual(self.read_sidecar_raw().decode("utf-8"), payload)
        self.assertEqual(self.read_checkpoint()["generation"], 1)

    def test_sidecar_checkpoint_mismatch_is_state(self) -> None:
        self.advance_n(2)
        stale = self.read_sidecar()
        del stale["records"][1]
        stale["head"] = stale["records"][0]["hash"]
        self.write_sidecar(stale)
        self.assertEqual(
            self.advance([self.continuation_page(2)], None),
            {"ok": False, "error": ERR_STATE},
        )

    def test_orphan_sidecar_without_checkpoint_is_state(self) -> None:
        self.advance_n(1)
        os.unlink(self.path)
        self.assertEqual(
            self.advance(self.pages([1]), self.anchor),
            {"ok": False, "error": ERR_STATE},
        )


class HistoryIoTests(HistoryFixture):
    def test_failed_first_advance_compensates_the_checkpoint(self) -> None:
        # The checkpoint write succeeds but the sidecar write fails: the
        # freshly written checkpoint is rolled back.
        with mock.patch(
            "ledger.light_client._atomic_write_history",
            side_effect=OSError("disk full"),
        ):
            result = self.advance(self.pages([1]), self.anchor)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertFalse(os.path.exists(self.path))
        self.assertFalse(self.sidecar_exists())

    def test_failed_later_advance_restores_both_files(self) -> None:
        self.advance_n(1)
        checkpoint_before = self.read_raw()
        sidecar_before = self.read_sidecar_raw()
        with mock.patch(
            "ledger.light_client._atomic_write_history",
            side_effect=OSError("disk full"),
        ):
            result = self.advance([self.continuation_page(1)], None)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertEqual(self.read_raw(), checkpoint_before)
        self.assertEqual(self.read_sidecar_raw(), sidecar_before)

    def test_failed_checkpoint_write_compensates_the_sidecar(self) -> None:
        self.advance_n(1)
        sidecar_before = self.read_sidecar_raw()
        with mock.patch(
            "ledger.light_client._atomic_write_checkpoint",
            side_effect=OSError("disk full"),
        ):
            result = self.advance([self.continuation_page(1)], None)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertEqual(self.read_checkpoint()["generation"], 1)
        self.assertEqual(self.read_sidecar_raw(), sidecar_before)

    def test_obstructed_sidecar_path_is_io(self) -> None:
        # The sidecar path is a directory: it can neither be read nor
        # replaced, and the checkpoint is left exactly as it was.
        self.advance_n(1)
        checkpoint_before = self.read_raw()
        os.unlink(self.sidecar_path)
        os.makedirs(self.sidecar_path)
        result = self.advance([self.continuation_page(1)], None)
        self.assertEqual(result, {"ok": False, "error": ERR_IO})
        self.assertEqual(self.read_raw(), checkpoint_before)

    def test_unwritable_directory_is_io(self) -> None:
        missing_dir = os.path.join(self.tmp, "no-such-dir", "cp.json")
        # The parent cannot be created because a file sits in its place.
        blocker = os.path.join(self.tmp, "no-such-dir")
        with open(blocker, "w", encoding="utf-8") as fh:
            fh.write("x")
        result = advance(
            missing_dir, self.pages([1]), self.trust, self.anchor, NOW
        )
        self.assertEqual(result, {"ok": False, "error": ERR_IO})


if __name__ == "__main__":
    unittest.main(verbosity=2)
