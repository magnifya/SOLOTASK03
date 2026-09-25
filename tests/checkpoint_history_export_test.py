"""Tests for signed, paginated checkpoint-history export and offline
verification (``ledger.light_client.export_history`` and
``ledger.light_client.verify_history``).

Covers:

* ``export_history`` page shape: exact top-level key order
  ``base, records, next, head, checkpoint, auth``, auth key order
  ``public_key, signature``, nested key orders inherited from the sidecar and
  checkpoint, ``records`` non-empty, ``next`` the last record generation when
  another page follows and ``null`` on the final page, ``checkpoint`` equal to
  the last retained record's checkpoint;
* the Ed25519 signature over the canonical JSON of the auth-less page;
* strict argument validation (64 lowercase hex seed ``key``, ``after``
  None or a non-boolean non-negative int naming base or a non-last retained
  generation, ``limit`` a non-boolean int 1..200) with ``input``, missing
  files ``io`` and corrupt state / unusable cursors ``state``;
* ``verify_history`` structure (``input``), pinned key and signatures
  (``auth``), shared base/head/checkpoint, cross-page generation and prev/hash
  chaining in step with ``next`` cursors, checkpoint state-hash/context
  replay with anchor continuity, final-page closure and rejection of missing,
  duplicated or reordered pages (``integrity``); failures are always
  ``{"ok": False, "error": ...}`` and never raise.

Run: python3 tests/checkpoint_history_export_test.py
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from light_client_advance_test import (  # noqa: E402
    AdvanceFixture,
    FUTURE,
)
from light_client_history_test import HistoryFixture  # noqa: E402

from ledger import crypto  # noqa: E402
from ledger.models import Block, Transaction  # noqa: E402
from ledger.light_client import (  # noqa: E402
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_IO,
    ERR_STATE,
    _canonical_json_bytes,
    export_history,
    history,
    verify_history,
)

PAGE_KEYS = ["base", "records", "next", "head", "checkpoint", "auth"]
AUTH_KEYS = ["public_key", "signature"]
BOB = "b" * 64


class ExportFixture(HistoryFixture):
    def setUp(self) -> None:
        super().setUp()
        # The base fixture holds four blocks; extend it so six generations can
        # be advanced with continuation pages.
        prev_hash = self.blocks[-1].block_hash
        for generation in range(5, 10):
            transaction = Transaction(
                self.alice_pub,
                BOB,
                6,
                self.alice_key.sign(
                    crypto.canonical_message(self.alice_pub, BOB, 6)
                ).hex(),
            )
            block = Block.create(generation, prev_hash, [transaction])
            self.blocks.append(block)
            prev_hash = block.block_hash
        self.signing_key = crypto.generate_private_key()
        self.public_key = crypto.derive_public_key(self.signing_key)

    def export_all(self, limit: int) -> list[dict]:
        """Walk the whole sidecar from base to the null-cursor final page."""
        pages: list[dict] = []
        after = None
        while True:
            page = export_history(self.path, self.signing_key, after=after,
                                  limit=limit)
            self.assertNotIn("error", page, page)
            pages.append(page)
            if page["next"] is None:
                return pages
            after = page["next"]

    def resign(self, page: dict, key: str | None = None) -> dict:
        """Re-sign an (edited) page with ``key`` (default the fixture key)."""
        seed = key or self.signing_key
        unsigned = {name: page[name] for name in PAGE_KEYS if name != "auth"}
        digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
        page = dict(page)
        page["auth"] = {
            "public_key": crypto.derive_public_key(seed),
            "signature": crypto.sign_message(seed, digest),
        }
        return page


class ExportHistoryTests(ExportFixture):
    def test_single_page_shape_and_signature(self) -> None:
        self.advance_n(3)
        page = export_history(self.path, self.signing_key)
        self.assertEqual(list(page.keys()), PAGE_KEYS)
        self.assertEqual(list(page["auth"].keys()), AUTH_KEYS)
        self.assertEqual(page["auth"]["public_key"], self.public_key)
        self.assertTrue(crypto.is_hex128(page["auth"]["signature"]))
        self.assertEqual(page["base"], {"generation": 0, "hash": "0" * 64})
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in page["records"]], [1, 2, 3]
        )
        self.assertIsNone(page["next"])
        self.assertEqual(
            page["head"], page["records"][-1]["hash"]
        )
        self.assertEqual(
            page["checkpoint"], page["records"][-1]["checkpoint"]
        )
        # Nested key orders are inherited verbatim from the sidecar.
        self.assertEqual(
            list(page["records"][0].keys()),
            ["checkpoint", "prev", "hash"],
        )
        self.assertEqual(
            list(page["records"][0]["checkpoint"].keys()),
            ["generation", "anchor", "tip", "context", "state_hash"],
        )
        # The signature verifies over the canonical auth-less page.
        unsigned = {name: page[name] for name in PAGE_KEYS if name != "auth"}
        digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
        self.assertTrue(
            crypto.verify_signature(
                self.public_key, digest, page["auth"]["signature"]
            )
        )
        self.assertEqual(verify_history([page], self.public_key), {"ok": True})

    def test_walk_with_cursors_and_limits(self) -> None:
        self.advance_n(6)
        for limit in (1, 2, 3, 5, 6, 200):
            pages = self.export_all(limit)
            self.assertTrue(all(len(p["records"]) <= limit for p in pages))
            self.assertEqual(
                [r["checkpoint"]["generation"]
                 for p in pages for r in p["records"]],
                [1, 2, 3, 4, 5, 6],
            )
            for position, page in enumerate(pages):
                last_generation = page["records"][-1]["checkpoint"]["generation"]
                if position == len(pages) - 1:
                    self.assertIsNone(page["next"])
                else:
                    self.assertEqual(page["next"], last_generation)
            self.assertEqual(verify_history(pages, self.public_key),
                             {"ok": True})

    def test_after_base_and_after_generation(self) -> None:
        self.advance_n(4)
        # after=None and after=base.generation both start at the first record.
        none_page = export_history(self.path, self.signing_key, limit=10)
        base_page = export_history(self.path, self.signing_key, after=0,
                                   limit=10)
        self.assertEqual(none_page, base_page)
        # after=2 starts at generation 3; the final page closes with null.
        page = export_history(self.path, self.signing_key, after=2, limit=10)
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in page["records"]], [3, 4]
        )
        self.assertIsNone(page["next"])
        # The cursor is the last record of an exactly-full non-final page.
        page = export_history(self.path, self.signing_key, after=1, limit=2)
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in page["records"]], [2, 3]
        )
        self.assertEqual(page["next"], 3)

    def test_argument_validation_is_input(self) -> None:
        self.advance_n(2)
        good_key = self.signing_key
        for bad_path in ("", 123, None):
            self.assertEqual(
                export_history(bad_path, good_key),
                {"ok": False, "error": ERR_INPUT},
            )
        for bad_key in ("", "x" * 64, "A" * 64, "0" * 63, "0" * 65, 123,
                        b"0" * 64):
            self.assertEqual(
                export_history(self.path, bad_key)["error"],
                ERR_INPUT,
                bad_key,
            )
        for bad_after in (-1, 0.0, 1.5, True, False, "1", [1]):
            self.assertEqual(
                export_history(self.path, good_key, after=bad_after)["error"],
                ERR_INPUT,
                bad_after,
            )
        for bad_limit in (0, 201, -1, 0.0, 1.5, True, False, "5", None, []):
            self.assertEqual(
                export_history(self.path, good_key, limit=bad_limit)["error"],
                ERR_INPUT,
                bad_limit,
            )

    def test_bad_cursor_is_state(self) -> None:
        self.advance_n(3)
        # The last retained generation is a legal int but names no successor.
        self.assertEqual(
            export_history(self.path, self.signing_key, after=3),
            {"ok": False, "error": ERR_STATE},
        )
        # An unknown generation inside/outside range is also state.
        self.assertEqual(
            export_history(self.path, self.signing_key, after=99)["error"],
            ERR_STATE,
        )

    def test_missing_sidecar_is_io_checkpoint_without_sidecar_rejected(self) -> None:
        # Never advanced: no files at all.
        fresh = os.path.join(self.tmp, "fresh.json")
        self.assertEqual(
            export_history(fresh, self.signing_key),
            {"ok": False, "error": ERR_IO},
        )
        # A sidecar without its checkpoint is unrecoverable state corruption.
        self.advance_n(1)
        os.unlink(self.path)
        self.assertEqual(
            export_history(self.path, self.signing_key)["error"], ERR_STATE
        )

    def test_corrupt_files_are_state(self) -> None:
        self.advance_n(2)
        self.write_sidecar("{not json")
        self.assertEqual(
            export_history(self.path, self.signing_key)["error"], ERR_STATE
        )

    def test_pruned_sidecar_exports_from_advanced_base(self) -> None:
        self.advance_n(6)
        self.assertTrue(history(self.path, keep=3)["ok"])
        page = export_history(self.path, self.signing_key, limit=10)
        self.assertEqual(page["base"]["generation"], 3)
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in page["records"]],
            [4, 5, 6],
        )
        self.assertIsNone(page["next"])
        self.assertEqual(verify_history([page], self.public_key),
                         {"ok": True})
        # after the advanced base starts at its first retained record.
        page = export_history(self.path, self.signing_key, after=3, limit=10)
        self.assertEqual(
            [r["checkpoint"]["generation"] for r in page["records"]],
            [4, 5, 6],
        )


class VerifyHistoryTests(ExportFixture):
    def setUp(self) -> None:
        super().setUp()
        self.advance_n(6)
        self.pages = self.export_all(2)
        self.assertEqual(len(self.pages), 3)

    def test_valid_batch_success(self) -> None:
        self.assertEqual(
            verify_history(self.pages, self.public_key), {"ok": True}
        )
        self.assertEqual(
            verify_history(self.export_all(1), self.public_key),
            {"ok": True},
        )
        self.assertEqual(
            verify_history(self.export_all(6), self.public_key),
            {"ok": True},
        )

    def test_structure_errors_are_input(self) -> None:
        self.assertEqual(verify_history([], self.public_key)["error"],
                         ERR_INPUT)
        self.assertEqual(verify_history("x", self.public_key)["error"],
                         ERR_INPUT)
        self.assertEqual(verify_history(self.pages, 123)["error"],
                         ERR_INPUT)
        self.assertEqual(verify_history(self.pages, "Z" * 64)["error"],
                         ERR_INPUT)

        page = self.pages[0]
        # Wrong top-level key order / missing or extra keys.
        reordered = {name: page[name] for name in reversed(PAGE_KEYS)}
        self.assertEqual(
            verify_history([reordered], self.public_key)["error"], ERR_INPUT
        )
        missing = {name: page[name] for name in PAGE_KEYS if name != "head"}
        self.assertEqual(
            verify_history([missing], self.public_key)["error"], ERR_INPUT
        )
        extra = dict(page, extra=1)
        self.assertEqual(
            verify_history([extra], self.public_key)["error"], ERR_INPUT
        )
        # Empty records or a non-int next.
        bad_records = dict(page, records=[])
        self.assertEqual(
            verify_history([bad_records], self.public_key)["error"], ERR_INPUT
        )
        bad_next = dict(page, next="1")
        self.assertEqual(
            verify_history([bad_next], self.public_key)["error"], ERR_INPUT
        )
        bad_next_bool = dict(page, next=True)
        self.assertEqual(
            verify_history([bad_next_bool], self.public_key)["error"],
            ERR_INPUT,
        )
        # auth shape defects.
        bad_auth = dict(page, auth={"signature": page["auth"]["signature"]})
        self.assertEqual(
            verify_history([bad_auth], self.public_key)["error"], ERR_INPUT
        )
        bad_auth_sig = dict(page, auth={"public_key": self.public_key,
                                       "signature": "z" * 128})
        self.assertEqual(
            verify_history([bad_auth_sig], self.public_key)["error"],
            ERR_INPUT,
        )
        # A boolean pretending to be a generation inside a checkpoint.
        tampered = copy.deepcopy(page)
        tampered["records"][0]["checkpoint"]["generation"] = True
        self.assertEqual(
            verify_history([tampered], self.public_key)["error"], ERR_INPUT
        )
        # Nested key order defect.
        tampered = copy.deepcopy(page)
        checkpoint = tampered["checkpoint"]
        tampered["checkpoint"] = {
            name: checkpoint[name]
            for name in ("state_hash", "generation", "anchor", "tip",
                         "context")
        }
        self.assertEqual(
            verify_history([tampered], self.public_key)["error"], ERR_INPUT
        )

    def test_wrong_key_and_bad_signature_are_auth(self) -> None:
        other_seed = crypto.generate_private_key()
        other_pub = crypto.derive_public_key(other_seed)
        self.assertEqual(
            verify_history(self.pages, other_pub)["error"], ERR_AUTH
        )
        bad_sig = copy.deepcopy(self.pages[0])
        bad_sig["auth"] = {
            "public_key": self.public_key,
            "signature": "0" * 128,
        }
        self.assertEqual(
            verify_history([bad_sig], self.public_key)["error"], ERR_AUTH
        )
        # A page re-signed by another key but still naming it is rejected.
        foreign = self.resign(copy.deepcopy(self.pages[0]), other_seed)
        self.assertEqual(
            verify_history([foreign], self.public_key)["error"], ERR_AUTH
        )

    def test_tampered_unsigned_content_is_integrity(self) -> None:
        # Editing an unsigned field and honestly re-signing cannot make the
        # history verify: the chaining/replay checks reject it.
        tampered = self.resign(copy.deepcopy(self.pages[1]))
        tampered["head"] = "f" * 64
        tampered = self.resign(tampered)
        self.assertEqual(
            verify_history([self.pages[0], tampered, self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )

        tampered = self.resign(copy.deepcopy(self.pages[1]))
        tampered["records"][0]["checkpoint"]["tip"]["height"] = 999
        tampered = self.resign(tampered)
        self.assertEqual(
            verify_history([self.pages[0], tampered, self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )

    def test_inconsistent_shared_fields_are_integrity(self) -> None:
        edited = self.resign(copy.deepcopy(self.pages[1]))
        edited["base"] = {"generation": 0, "hash": "1" * 64}
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([self.pages[0], edited, self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )
        edited = self.resign(copy.deepcopy(self.pages[1]))
        edited["checkpoint"] = copy.deepcopy(
            self.pages[0]["records"][0]["checkpoint"]
        )
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([self.pages[0], edited, self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )

    def test_missing_duplicate_reordered_pages_are_integrity(self) -> None:
        # Drop the middle page.
        self.assertEqual(
            verify_history([self.pages[0], self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )
        # Reorder pages.
        self.assertEqual(
            verify_history([self.pages[1], self.pages[0], self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )
        # Duplicate the first page.
        self.assertEqual(
            verify_history([self.pages[0], self.pages[0], self.pages[1],
                            self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )

    def test_next_cursor_must_seam_and_final_page_must_close(self) -> None:
        # A non-final page must not carry a null cursor.
        edited = self.resign(copy.deepcopy(self.pages[0]))
        edited["next"] = None
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([edited, self.pages[1], self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )
        # A wrong cursor value on a non-final page.
        edited = self.resign(copy.deepcopy(self.pages[0]))
        edited["next"] = 1
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([edited, self.pages[1], self.pages[2]],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )
        # The final page must carry null.
        edited = self.resign(copy.deepcopy(self.pages[2]))
        edited["next"] = 6
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([self.pages[0], self.pages[1], edited],
                           self.public_key)["error"],
            ERR_INTEGRITY,
        )

    def test_record_hash_chain_is_checked(self) -> None:
        edited = self.resign(copy.deepcopy(self.pages[0]))
        edited["records"][0]["prev"] = "1" * 64
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([edited], self.public_key)["error"], ERR_INTEGRITY
        )
        edited = self.resign(copy.deepcopy(self.pages[0]))
        edited["records"][0]["hash"] = "1" * 64
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([edited], self.public_key)["error"], ERR_INTEGRITY
        )

    def test_final_record_must_reach_head_and_checkpoint(self) -> None:
        # The one-page export of a prefix cannot close the full history: its
        # last record hash is not the shared head and its checkpoint differs.
        prefix = self.pages[0]
        edited = copy.deepcopy(prefix)
        edited["next"] = None
        edited = self.resign(edited)
        self.assertEqual(
            verify_history([edited], self.public_key)["error"], ERR_INTEGRITY
        )

    def test_never_raises_on_garbage(self) -> None:
        for garbage in (None, 1, "x", {"x": 1}, [None], [1, 2], [[]],
                       [{"records": []}], json.loads("[true]")):
            result = verify_history(garbage, self.public_key)
            self.assertFalse(result["ok"], garbage)
            self.assertIn(result["error"],
                          (ERR_INPUT, ERR_AUTH, ERR_INTEGRITY))


if __name__ == "__main__":
    import unittest

    unittest.main()
