"""Tests for signed, paginated checkpoint-history export and its offline
verification (``ledger.light_client.export_history`` / ``verify_history``).

Covers:

* export page shape: exact top-level key order
  ``base, records, next, head, checkpoint, auth``, auth key order
  ``public_key, signature``, nested documents byte-identical to the sidecar
  records (``base``, ``{checkpoint, prev, hash}`` and the five-key
  checkpoint), ``records`` non-empty, ``next`` the last record's generation
  when another page follows and ``null`` otherwise;
* pagination: ``after=None`` and ``after=base.generation`` both start at the
  first retained record, an ``after`` of a retained non-last generation
  continues after it, exact page-boundary cursors;
* the Ed25519 authenticator: ``public_key`` derived from the seed and the
  signature over SHA-256 of the canonical (sorted, compact, unescaped
  non-ASCII) JSON of the page with ``auth`` removed — including non-ASCII
  checkpoint content;
* pruned sidecars export from their advanced base and restart cursors;
* export never mutates the checkpoint or sidecar;
* argument/error mapping: ``input`` (bad path/key/after/limit), ``io``
  (missing sidecar), ``state`` (tampered sidecar, cursor naming the last or a
  non-retained generation);
* offline verification: success for one and several pages, exact structure
  checks (``input``), public key/signature trust (``auth``), and chain,
  pagination, cross-page agreement and checkpoint-replay defects — including
  pages re-signed after tampering — mapped to ``integrity``; failures never
  raise and a success is exactly ``{"ok": True}``.

Run: python3 tests/light_client_history_export_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from light_client_advance_test import (  # noqa: E402
    NOW,
    FUTURE,
    AdvanceFixture,
)

from ledger import crypto  # noqa: E402
from ledger.light_client import (  # noqa: E402
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    ERR_IO,
    ERR_STATE,
    HISTORY_AUTH_KEYS,
    HISTORY_BASE_KEYS,
    HISTORY_PAGE_KEYS,
    HISTORY_RECORD_KEYS,
    CHECKPOINT_KEYS,
    advance,
    export_history,
    history,
    verify_history,
)

PAGE_KEYS = list(HISTORY_PAGE_KEYS)
AUTH_KEYS = list(HISTORY_AUTH_KEYS)
BASE_KEYS = list(HISTORY_BASE_KEYS)
RECORD_KEYS = list(HISTORY_RECORD_KEYS)


def canonical_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def page_signature(page: dict, seed: str) -> str:
    """Independently recompute a page's Ed25519 signature."""
    unsigned = {key: value for key, value in page.items() if key != "auth"}
    digest = hashlib.sha256(canonical_bytes(unsigned)).digest()
    return crypto.sign_message(seed, digest)


def resign(page: dict, seed: str) -> dict:
    """Deep-copy a page and re-sign it (used to deliver tampered-but-signed pages)."""
    signed = json.loads(json.dumps(page))
    signed["auth"]["signature"] = page_signature(signed, seed)
    return signed


class ExportFixture(AdvanceFixture):
    def setUp(self) -> None:
        super().setUp()
        self.seed = crypto.generate_private_key()
        self.public = crypto.derive_public_key(self.seed)

    def advance_n(self, count: int) -> None:
        """Advance ``count`` single-block generations from the genesis anchor."""
        anchor = self.anchor
        for index in range(count):
            result = self.advance([self.continuation_page(index)], anchor)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["generation"], index + 1)
            anchor = None

    def export_pages(self, page_size: int) -> list[dict]:
        """Walk the whole retained history with ``export_history``."""
        pages = []
        cursor = None
        while True:
            page = export_history(self.path, self.seed, cursor, page_size)
            self.assertTrue(_is_ok(page), page)
            pages.append(page)
            if page["next"] is None:
                return pages
            cursor = page["next"]

    def read_sidecar(self) -> dict:
        with open(self.path + ".history", "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_sidecar_raw(self) -> bytes:
        with open(self.path + ".history", "rb") as fh:
            return fh.read()


def _is_ok(result: dict) -> bool:
    return isinstance(result, dict) and result.get("ok") is not False and "auth" in result


class ExportShapeTests(ExportFixture):
    def test_single_page_key_order_and_nested_shapes(self) -> None:
        self.advance_n(2)
        page = export_history(self.path, self.seed)
        self.assertEqual(list(page.keys()), PAGE_KEYS)
        self.assertEqual(list(page["auth"].keys()), AUTH_KEYS)
        self.assertEqual(list(page["base"].keys()), BASE_KEYS)
        for record in page["records"]:
            self.assertEqual(list(record.keys()), RECORD_KEYS)
            self.assertEqual(list(record["checkpoint"].keys()), list(CHECKPOINT_KEYS))

        sidecar = self.read_sidecar()
        self.assertEqual(page["base"], sidecar["base"])
        self.assertEqual(page["records"], sidecar["records"])
        self.assertEqual(page["head"], sidecar["head"])
        self.assertEqual(
            page["checkpoint"], sidecar["records"][-1]["checkpoint"]
        )
        self.assertIsNone(page["next"])
        self.assertEqual(page["auth"]["public_key"], self.public)

    def test_auth_signature_covers_canonical_json_without_auth(self) -> None:
        self.advance_n(1)
        page = export_history(self.path, self.seed)
        expected = page_signature(page, self.seed)
        self.assertEqual(page["auth"]["signature"], expected)
        self.assertTrue(
            crypto.verify_signature(
                page["auth"]["public_key"],
                hashlib.sha256(canonical_bytes(
                    {k: v for k, v in page.items() if k != "auth"}
                )).digest(),
                page["auth"]["signature"],
            )
        )

    def test_non_ascii_checkpoint_is_signed_over_unescaped_json(self) -> None:
        source = "节点-δ"
        trust = {"allowlist": {source: FUTURE}}
        unicode_path = os.path.join(self.tmp, "u.json")
        page_doc = self.make_page(self.anchor, [self.blocks[0]], source=source)
        result = advance(unicode_path, [page_doc], trust, self.anchor, NOW)
        self.assertTrue(result["ok"], result)

        page = export_history(unicode_path, self.seed)
        unsigned = {k: v for k, v in page.items() if k != "auth"}
        raw = canonical_bytes(unsigned)
        self.assertIn(source.encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)
        self.assertTrue(
            crypto.verify_signature(
                self.public,
                hashlib.sha256(raw).digest(),
                page["auth"]["signature"],
            )
        )
        self.assertEqual(verify_history([page], self.public), {"ok": True})


class ExportPaginationTests(ExportFixture):
    def test_walk_all_pages_with_cursors(self) -> None:
        self.advance_n(4)
        pages = self.export_pages(2)
        self.assertEqual(len(pages), 2)
        gens = lambda recs: [r["checkpoint"]["generation"] for r in recs]
        self.assertEqual(gens(pages[0]["records"]), [1, 2])
        self.assertEqual(pages[0]["next"], 2)
        self.assertEqual(gens(pages[1]["records"]), [3, 4])
        self.assertIsNone(pages[1]["next"])
        # Shared identity fields ride along on every page.
        for page in pages:
            self.assertEqual(page["base"], pages[0]["base"])
            self.assertEqual(page["head"], pages[0]["head"])
            self.assertEqual(page["checkpoint"], pages[0]["checkpoint"])
            self.assertEqual(page["auth"]["public_key"], self.public)
        self.assertEqual(pages[0]["head"], pages[1]["records"][-1]["hash"])
        self.assertEqual(verify_history(pages, self.public), {"ok": True})

    def test_uneven_page_sizes(self) -> None:
        self.advance_n(4)
        pages = self.export_pages(3)
        gens = lambda recs: [r["checkpoint"]["generation"] for r in recs]
        self.assertEqual(gens(pages[0]["records"]), [1, 2, 3])
        self.assertEqual(pages[0]["next"], 3)
        self.assertEqual(gens(pages[1]["records"]), [4])
        self.assertIsNone(pages[1]["next"])
        self.assertEqual(verify_history(pages, self.public), {"ok": True})

    def test_after_base_generation_restarts_at_first_record(self) -> None:
        self.advance_n(3)
        base_generation = self.read_sidecar()["base"]["generation"]
        from_none = export_history(self.path, self.seed, None, 50)
        from_base = export_history(self.path, self.seed, base_generation, 50)
        self.assertEqual(from_none, from_base)

    def test_explicit_after_continues_after_named_record(self) -> None:
        self.advance_n(4)
        page = export_history(self.path, self.seed, 1, 2)
        gens = [r["checkpoint"]["generation"] for r in page["records"]]
        self.assertEqual(gens, [2, 3])
        self.assertEqual(page["next"], 3)

    def test_after_last_record_is_state(self) -> None:
        self.advance_n(2)
        self.assertEqual(
            export_history(self.path, self.seed, 2),
            {"ok": False, "error": ERR_STATE},
        )

    def test_after_non_retained_generation_is_state(self) -> None:
        self.advance_n(3)
        for cursor in (0, 9, 4):
            with self.subTest(cursor=cursor):
                # Base is generation 0 here, so cursor 0 restarts legally;
                # only out-of-retain cursors are state.
                result = export_history(self.path, self.seed, cursor)
                if cursor == 0:
                    self.assertTrue(_is_ok(result), result)
                else:
                    self.assertEqual(result, {"ok": False, "error": ERR_STATE})

    def test_pruned_sidecar_exports_from_advanced_base(self) -> None:
        self.advance_n(4)
        self.assertTrue(history(self.path, keep=2)["ok"])
        page = export_history(self.path, self.seed)
        gens = [r["checkpoint"]["generation"] for r in page["records"]]
        self.assertEqual(gens, [3, 4])
        self.assertEqual(page["base"]["generation"], 2)
        # Restart cursor naming the advanced base is legal.
        again = export_history(self.path, self.seed, page["base"]["generation"])
        self.assertEqual(again["records"], page["records"])
        # A pre-prune generation is gone for good: a stale cursor is state.
        self.assertEqual(
            export_history(self.path, self.seed, 1),
            {"ok": False, "error": ERR_STATE},
        )
        self.assertEqual(verify_history([page], self.public), {"ok": True})

    def test_export_never_mutates_files(self) -> None:
        self.advance_n(3)
        sidecar_before = self.read_sidecar_raw()
        checkpoint_before = open(self.path, "rb").read()
        export_history(self.path, self.seed, None, 1)
        export_history(self.path, self.seed, 1, 1)
        export_history(self.path, self.seed)
        self.assertEqual(self.read_sidecar_raw(), sidecar_before)
        self.assertEqual(open(self.path, "rb").read(), checkpoint_before)


class ExportArgumentTests(ExportFixture):
    def test_bad_path_is_input(self) -> None:
        for bad in ("", None, 7):
            with self.subTest(bad=bad):
                self.assertEqual(
                    export_history(bad, self.seed),
                    {"ok": False, "error": ERR_INPUT},
                )

    def test_bad_key_is_input(self) -> None:
        self.advance_n(1)
        for bad in ("", "zz" * 32, "A" * 64, "a" * 63, self.seed.upper(), 123):
            with self.subTest(bad=bad):
                self.assertEqual(
                    export_history(self.path, bad),
                    {"ok": False, "error": ERR_INPUT},
                )

    def test_bad_after_is_input(self) -> None:
        self.advance_n(1)
        for bad in (-1, True, False, 1.0, "1", [1]):
            with self.subTest(bad=bad):
                self.assertEqual(
                    export_history(self.path, self.seed, bad),
                    {"ok": False, "error": ERR_INPUT},
                )

    def test_bad_limit_is_input(self) -> None:
        self.advance_n(1)
        for bad in (0, -1, 201, True, False, 1.5, "2", None):
            with self.subTest(bad=bad):
                self.assertEqual(
                    export_history(self.path, self.seed, None, bad),
                    {"ok": False, "error": ERR_INPUT},
                )

    def test_limit_boundaries_succeed(self) -> None:
        self.advance_n(2)
        self.assertTrue(_is_ok(export_history(self.path, self.seed, None, 1)))
        self.assertTrue(_is_ok(export_history(self.path, self.seed, None, 200)))

    def test_missing_sidecar_is_io(self) -> None:
        self.assertEqual(
            export_history(self.path, self.seed),
            {"ok": False, "error": ERR_IO},
        )
        self.advance_n(1)
        os.unlink(self.path + ".history")
        self.assertEqual(
            export_history(self.path, self.seed),
            {"ok": False, "error": ERR_IO},
        )

    def test_tampered_sidecar_is_state(self) -> None:
        self.advance_n(1)
        sidecar = self.read_sidecar()
        sidecar["head"] = "9" * 64
        with open(self.path + ".history", "w", encoding="utf-8") as fh:
            json.dump(sidecar, fh)
        self.assertEqual(
            export_history(self.path, self.seed),
            {"ok": False, "error": ERR_STATE},
        )


class VerifySuccessTests(ExportFixture):
    def test_single_page_success_is_exactly_ok_true(self) -> None:
        self.advance_n(3)
        page = export_history(self.path, self.seed)
        self.assertEqual(verify_history([page], self.public), {"ok": True})
        self.assertEqual(list(verify_history([page], self.public).keys()), ["ok"])

    def test_full_walk_verifies(self) -> None:
        self.advance_n(4)
        for size in (1, 2, 3, 4, 50):
            with self.subTest(size=size):
                pages = self.export_pages(size)
                self.assertEqual(verify_history(pages, self.public), {"ok": True})

    def test_restarted_first_page_verifies_alone(self) -> None:
        # A page re-exported with after=base.generation is the same document.
        self.advance_n(2)
        page = export_history(
            self.path, self.seed, self.read_sidecar()["base"]["generation"]
        )
        self.assertEqual(verify_history([page], self.public), {"ok": True})


class VerifyInputTests(ExportFixture):
    def setUp(self) -> None:
        super().setUp()
        self.advance_n(2)
        self.page = export_history(self.path, self.seed)

    _UNSET = object()

    def _reject_input(self, pages, public_key=_UNSET) -> None:
        key = self.public if public_key is self._UNSET else public_key
        self.assertEqual(
            verify_history(pages, key),
            {"ok": False, "error": ERR_INPUT},
        )

    def test_pages_must_be_a_non_empty_list(self) -> None:
        for bad in (None, 1, "x", {}, True, []):
            with self.subTest(bad=bad):
                self._reject_input(bad)

    def test_public_key_must_be_64_lowercase_hex(self) -> None:
        for bad in (None, 123, b"", "a" * 63, "A" * 64, "g" * 64, self.public.upper()):
            with self.subTest(bad=bad):
                self._reject_input([self.page], bad)

    def test_page_must_be_a_dict(self) -> None:
        self._reject_input([None])
        self._reject_input([1])
        self._reject_input(["page"])

    def test_wrong_top_level_key_order_or_set_is_input(self) -> None:
        reordered = {key: self.page[key] for key in reversed(PAGE_KEYS)}
        self._reject_input([reordered])
        missing = dict(self.page)
        del missing["head"]
        self._reject_input([missing])
        extra = dict(self.page)
        extra["extra"] = 1
        self._reject_input([extra])

    def test_bad_nested_types_are_input(self) -> None:
        def patched(**changes):
            doc = json.loads(json.dumps(self.page))
            doc.update(changes)
            return doc

        self._reject_input([patched(next="1")])
        self._reject_input([patched(next=-1)])
        self._reject_input([patched(head="z" * 64)])
        self._reject_input([patched(records=[])])
        self._reject_input([patched(records="x")])

        bad_base = json.loads(json.dumps(self.page))
        bad_base["base"]["generation"] = -1
        self._reject_input([bad_base])
        bad_base = json.loads(json.dumps(self.page))
        bad_base["base"]["hash"] = "Z" * 64
        self._reject_input([bad_base])

        bad_auth = json.loads(json.dumps(self.page))
        bad_auth["auth"] = {"public_key": self.public}
        self._reject_input([bad_auth])
        bad_auth = json.loads(json.dumps(self.page))
        bad_auth["auth"]["public_key"] = "x" * 64
        self._reject_input([bad_auth])
        bad_auth = json.loads(json.dumps(self.page))
        bad_auth["auth"]["signature"] = "s" * 127
        self._reject_input([bad_auth])

        bad_record = json.loads(json.dumps(self.page))
        bad_record["records"][0]["prev"] = 42
        self._reject_input([bad_record])

        bad_checkpoint = json.loads(json.dumps(self.page))
        bad_checkpoint["checkpoint"]["generation"] = "1"
        self._reject_input([bad_checkpoint])

    def test_garbage_nested_values_never_raise(self) -> None:
        # Defensive: structurally unforeseeable inputs report input.
        weird = json.loads(json.dumps(self.page))
        weird["records"][0] = {"checkpoint": None, "prev": None, "hash": None}
        self._reject_input([weird])
        weird2 = json.loads(json.dumps(self.page))
        weird2["base"] = []
        self._reject_input([weird2])


class VerifyAuthTests(ExportFixture):
    def setUp(self) -> None:
        super().setUp()
        self.advance_n(3)
        self.pages = self.export_pages(2)

    def test_wrong_pinned_key_is_auth(self) -> None:
        other = crypto.derive_public_key(crypto.generate_private_key())
        self.assertEqual(
            verify_history(self.pages, other),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_bad_signature_is_auth(self) -> None:
        pages = json.loads(json.dumps(self.pages))
        pages[0]["auth"]["signature"] = "b" * 128
        self.assertEqual(
            verify_history(pages, self.public),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_embedded_key_mismatch_is_auth(self) -> None:
        pages = json.loads(json.dumps(self.pages))
        other_seed = crypto.generate_private_key()
        pages[0]["auth"]["public_key"] = crypto.derive_public_key(other_seed)
        pages[0]["auth"]["signature"] = page_signature(pages[0], other_seed)
        self.assertEqual(
            verify_history(pages, self.public),
            {"ok": False, "error": ERR_AUTH},
        )

    def test_unsigned_field_tampering_is_auth(self) -> None:
        # Any byte tampering without the signing key dies at the signature.
        pages = json.loads(json.dumps(self.pages))
        pages[0]["records"][0]["prev"] = "f" * 64
        self.assertEqual(
            verify_history(pages, self.public),
            {"ok": False, "error": ERR_AUTH},
        )
        pages = json.loads(json.dumps(self.pages))
        pages[0]["head"] = "1" * 64
        self.assertEqual(
            verify_history(pages, self.public),
            {"ok": False, "error": ERR_AUTH},
        )


class VerifyIntegrityTests(ExportFixture):
    def setUp(self) -> None:
        super().setUp()
        self.advance_n(4)

    def _verify(self, pages) -> dict:
        return verify_history(pages, self.public)

    def test_missing_page_is_integrity(self) -> None:
        pages = self.export_pages(1)
        self.assertEqual(
            self._verify([pages[0], pages[2], pages[3]]),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_duplicated_page_is_integrity(self) -> None:
        pages = self.export_pages(1)
        self.assertEqual(
            self._verify([pages[0], pages[0], pages[2], pages[3]]),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_shuffled_pages_are_integrity(self) -> None:
        pages = self.export_pages(1)
        self.assertEqual(
            self._verify([pages[0], pages[2], pages[1], pages[3]]),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_non_final_page_with_null_next_is_integrity(self) -> None:
        pages = self.export_pages(2)
        pages[0] = resign({**pages[0], "next": None}, self.seed)
        self.assertEqual(
            self._verify(pages), {"ok": False, "error": ERR_INTEGRITY}
        )

    def test_final_page_with_cursor_is_integrity(self) -> None:
        page = export_history(self.path, self.seed)
        tampered = resign({**page, "next": 4}, self.seed)
        self.assertEqual(
            verify_history([tampered], self.public),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_wrong_next_cursor_is_integrity(self) -> None:
        pages = self.export_pages(1)
        pages[0] = resign({**pages[0], "next": 2}, self.seed)  # really 1
        self.assertEqual(
            self._verify(pages[:2]), {"ok": False, "error": ERR_INTEGRITY}
        )

    def test_cross_page_base_difference_is_integrity(self) -> None:
        pages = self.export_pages(1)
        doctored = json.loads(json.dumps(pages[1]))
        doctored["base"] = {"generation": 1, "hash": doctored["records"][0]["prev"]}
        pages[1] = resign(doctored, self.seed)
        self.assertEqual(
            self._verify(pages[:2]), {"ok": False, "error": ERR_INTEGRITY}
        )

    def test_cross_page_head_difference_is_integrity(self) -> None:
        pages = self.export_pages(1)
        pages[0] = resign({**pages[0], "head": "1" * 64}, self.seed)
        self.assertEqual(
            self._verify(pages[:2]), {"ok": False, "error": ERR_INTEGRITY}
        )

    def test_cross_page_checkpoint_difference_is_integrity(self) -> None:
        pages = self.export_pages(1)
        other_checkpoint = pages[1]["records"][0]["checkpoint"]
        pages[0] = resign({**pages[0], "checkpoint": other_checkpoint}, self.seed)
        self.assertEqual(
            self._verify(pages[:2]), {"ok": False, "error": ERR_INTEGRITY}
        )

    def test_last_record_hash_not_head_is_integrity(self) -> None:
        page = export_history(self.path, self.seed)
        tampered = resign({**page, "head": "2" * 64}, self.seed)
        self.assertEqual(
            verify_history([tampered], self.public),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_pinned_checkpoint_not_last_record_is_integrity(self) -> None:
        page = export_history(self.path, self.seed, None, 1)
        # Page ends at generation 1; pin a different valid checkpoint.
        other = export_history(self.path, self.seed, 1, 1)["records"][0][
            "checkpoint"
        ]
        tampered = resign({**page, "checkpoint": other}, self.seed)
        self.assertEqual(
            verify_history([tampered], self.public),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_resigned_record_chain_tamper_is_integrity(self) -> None:
        page = export_history(self.path, self.seed)
        tampered = json.loads(json.dumps(page))
        tampered["records"][0]["hash"] = "3" * 64
        tampered = resign(tampered, self.seed)
        self.assertEqual(
            verify_history([tampered], self.public),
            {"ok": False, "error": ERR_INTEGRITY},
        )

    def test_resigned_checkpoint_content_tamper_is_integrity(self) -> None:
        # Mutate the checkpoint body consistently (record + pinned doc),
        # recompute the record hash chain and head, then re-sign: the only
        # remaining defence is the checkpoint state-hash/replay check.
        page = export_history(self.path, self.seed)
        doctored = json.loads(json.dumps(page))
        for record in doctored["records"]:
            record["checkpoint"]["context"]["verified_tx_ids"] = []
        doctored["checkpoint"]["context"]["verified_tx_ids"] = []
        prev = doctored["base"]["hash"]
        for record in doctored["records"]:
            record["prev"] = prev
            record["hash"] = hashlib.sha256(
                prev.encode("ascii") + canonical_bytes(record["checkpoint"])
            ).hexdigest()
            prev = record["hash"]
        doctored["head"] = prev
        doctored = resign(doctored, self.seed)
        self.assertEqual(
            verify_history([doctored], self.public),
            {"ok": False, "error": ERR_INTEGRITY},
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
