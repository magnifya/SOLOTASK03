"""Tests for signer-rotation trust verification of exported checkpoint
history (``ledger.light_client.verify_history_trust``).

Covers:

* the trust document shape: exact top-level key order ``root, records,
  head``, record key order ``at, key, status, prev, signature``, ``at`` a
  non-boolean positive integer strictly increasing, ``key``/``prev`` 64
  lowercase hex, ``status`` exactly ``active``/``revoked``, ``signature``
  128 lowercase hex, ``records`` non-empty;
* the certificate chain: first ``prev`` 64 zeros, later ``prev`` the
  SHA-256 of the previous record's canonical JSON, ``head`` the last
  record's hash, and every record signed by the pinned ``root`` over the
  SHA-256 of the record's canonical JSON without ``signature``;
* authorization: an ``active`` record authorizes its key from ``at`` until
  the key's next record, a ``revoked`` record withdraws it until a later
  ``active``; each page's ``auth.public_key`` (pages may differ) must be
  authorized at every generation's ``verified_at`` it signs, and
  consecutive generations signed by the same key must not cross a
  revocation/reactivation boundary;
* error categories ``input`` (structure/types), ``auth`` (root mismatch,
  certificate or page signature, unknown/revoked key) and ``integrity``
  (``at`` order, ``prev``/``head`` chain, crossed boundary, and every
  chaining/pagination/replay rule inherited from ``verify_history``);
  failures never raise.

Run: python3 tests/history_trust_verify_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from light_client_advance_test import NOW  # noqa: E402
from checkpoint_history_export_test import ExportFixture  # noqa: E402

from ledger import crypto  # noqa: E402
from ledger.light_client import (  # noqa: E402
    ERR_AUTH,
    ERR_INPUT,
    ERR_INTEGRITY,
    _canonical_json_bytes,
    export_history,
    verify_history_trust,
)

ZERO = "0" * 64
TRUST_KEYS = ["root", "records", "head"]
TRUST_RECORD_KEYS = ["at", "key", "status", "prev", "signature"]


def canonical_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def record_hash(record: dict) -> str:
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


class TrustFixture(ExportFixture):
    """Six generations verified at NOW, NOW+10, ..., NOW+50, plus keys."""

    def setUp(self) -> None:
        super().setUp()
        anchor = self.anchor
        for index in range(6):
            result = self.advance([self.continuation_page(index)], anchor,
                                  now=NOW + 10 * index)
            self.assertTrue(result["ok"], result)
            anchor = None
        self.root_seed = crypto.generate_private_key()
        self.root_pub = crypto.derive_public_key(self.root_seed)
        self.key1 = crypto.generate_private_key()
        self.pub1 = crypto.derive_public_key(self.key1)
        self.key2 = crypto.generate_private_key()
        self.pub2 = crypto.derive_public_key(self.key2)

    def make_trust(self, entries: list, root_seed: str | None = None) -> dict:
        """A trust document over ``(at, key, status)`` certificate entries."""
        seed = root_seed or self.root_seed
        records = []
        prev = ZERO
        for at, key, status in entries:
            body = {"at": at, "key": key, "status": status, "prev": prev}
            digest = hashlib.sha256(canonical_bytes(body)).digest()
            record = {
                "at": at,
                "key": key,
                "status": status,
                "prev": prev,
                "signature": crypto.sign_message(seed, digest),
            }
            records.append(record)
            prev = record_hash(record)
        return {
            "root": crypto.derive_public_key(seed),
            "records": records,
            "head": prev,
        }

    def single_trust(self) -> dict:
        """The baseline trust: key1 active since before the first advance."""
        return self.make_trust([(NOW - 5, self.pub1, "active")])

    def export_all(self, limit: int, seed: str | None = None) -> list:
        """Walk the whole sidecar, every page signed by ``seed`` (key1)."""
        pages: list[dict] = []
        after = None
        while True:
            page = export_history(self.path, seed or self.key1, after=after,
                                  limit=limit)
            self.assertNotIn("error", page, page)
            pages.append(page)
            if page["next"] is None:
                return pages
            after = page["next"]

    def clone(self, value):
        return json.loads(json.dumps(value))


class VerifyHistoryTrustTests(TrustFixture):
    def test_trust_document_shape(self) -> None:
        trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                 (NOW + 25, self.pub2, "active")])
        self.assertEqual(list(trust.keys()), TRUST_KEYS)
        prev = ZERO
        for record, (at, key, _) in zip(
            trust["records"], [(NOW - 5, self.pub1, None),
                               (NOW + 25, self.pub2, None)]
        ):
            self.assertEqual(list(record.keys()), TRUST_RECORD_KEYS)
            self.assertEqual(record["at"], at)
            self.assertEqual(record["key"], key)
            self.assertEqual(record["prev"], prev)
            prev = record_hash(record)
        self.assertEqual(trust["head"], prev)

    def test_valid_single_key_batches(self) -> None:
        trust = self.single_trust()
        for limit in (1, 2, 6, 10):
            self.assertEqual(
                verify_history_trust(self.export_all(limit), trust,
                                     self.root_pub),
                {"ok": True},
            )

    def test_rotation_across_pages(self) -> None:
        # key1 signs generations 1-2, is revoked, key2 signs the rest.
        trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                 (NOW + 15, self.pub1, "revoked"),
                                 (NOW + 16, self.pub2, "active")])
        page1 = export_history(self.path, self.key1, limit=2)
        page2 = export_history(self.path, self.key2, after=2, limit=2)
        page3 = export_history(self.path, self.key2, after=4, limit=2)
        self.assertEqual(
            verify_history_trust([page1, page2, page3], trust, self.root_pub),
            {"ok": True},
        )

    def test_revoked_key_signing_later_generations_is_auth(self) -> None:
        trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                 (NOW + 15, self.pub1, "revoked"),
                                 (NOW + 16, self.pub2, "active")])
        page1 = export_history(self.path, self.key1, limit=2)
        bad = export_history(self.path, self.key1, after=2, limit=2)
        page3 = export_history(self.path, self.key2, after=4, limit=2)
        self.assertEqual(
            verify_history_trust([page1, bad, page3], trust,
                                 self.root_pub)["error"],
            ERR_AUTH,
        )

    def test_unknown_key_is_auth(self) -> None:
        trust = self.single_trust()
        pages = self.export_all(10, seed=self.key2)
        self.assertEqual(
            verify_history_trust(pages, trust, self.root_pub)["error"],
            ERR_AUTH,
        )

    def test_key_not_yet_active_is_auth(self) -> None:
        trust = self.make_trust([(NOW + 100, self.pub1, "active")])
        self.assertEqual(
            verify_history_trust(self.export_all(2), trust,
                                 self.root_pub)["error"],
            ERR_AUTH,
        )

    def test_revoked_key_is_auth(self) -> None:
        trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                 (NOW + 25, self.pub1, "revoked")])
        self.assertEqual(
            verify_history_trust(self.export_all(2), trust,
                                 self.root_pub)["error"],
            ERR_AUTH,
        )

    def test_root_mismatch_is_auth(self) -> None:
        trust = self.single_trust()
        pages = self.export_all(2)
        self.assertEqual(
            verify_history_trust(pages, trust, self.pub1)["error"], ERR_AUTH
        )
        other = self.make_trust([(NOW - 5, self.pub1, "active")],
                                root_seed=self.key2)
        self.assertEqual(
            verify_history_trust(pages, other, self.root_pub)["error"],
            ERR_AUTH,
        )

    def test_certificate_signature_is_auth(self) -> None:
        trust = self.single_trust()
        trust["records"][0]["signature"] = "0" * 128
        self.assertEqual(
            verify_history_trust(self.export_all(2), trust,
                                 self.root_pub)["error"],
            ERR_AUTH,
        )

    def test_page_signature_is_auth(self) -> None:
        trust = self.single_trust()
        pages = self.export_all(2)
        pages[0]["auth"]["signature"] = "0" * 128
        self.assertEqual(
            verify_history_trust(pages, trust, self.root_pub)["error"],
            ERR_AUTH,
        )

    def test_boundary_crossing_is_integrity(self) -> None:
        # key1 revoked and reactivated between generations 1 (NOW) and 2
        # (NOW+10): one key's consecutive generations span the boundary.
        trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                 (NOW + 5, self.pub1, "revoked"),
                                 (NOW + 8, self.pub1, "active")])
        self.assertEqual(
            verify_history_trust(self.export_all(10), trust,
                                 self.root_pub)["error"],
            ERR_INTEGRITY,
        )
        # Re-pagination does not help: generations 1 and 2 are consecutive
        # and signed by the same key across the boundary either way.
        page1 = export_history(self.path, self.key1, limit=1)
        page2 = export_history(self.path, self.key1, after=1, limit=10)
        self.assertEqual(
            verify_history_trust([page1, page2], trust,
                                 self.root_pub)["error"],
            ERR_INTEGRITY,
        )

    def test_key_switch_at_boundary_verifies(self) -> None:
        # The same timeline with key2 taking over after the revocation is a
        # legitimate rotation, not a crossed boundary.
        trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                 (NOW + 5, self.pub1, "revoked"),
                                 (NOW + 8, self.pub2, "active")])
        page1 = export_history(self.path, self.key1, limit=1)
        page2 = export_history(self.path, self.key2, after=1, limit=10)
        self.assertEqual(
            verify_history_trust([page1, page2], trust, self.root_pub),
            {"ok": True},
        )

    def test_at_not_increasing_is_integrity(self) -> None:
        trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                 (NOW - 6, self.pub2, "active")])
        self.assertEqual(
            verify_history_trust(self.export_all(2), trust,
                                 self.root_pub)["error"],
            ERR_INTEGRITY,
        )

    def test_broken_prev_chain_is_integrity(self) -> None:
        for index in (0, 1):
            trust = self.make_trust([(NOW - 5, self.pub1, "active"),
                                     (NOW, self.pub2, "active")])
            trust["records"][index]["prev"] = "1" * 64
            # Re-sign so only the chain link is broken.
            record = trust["records"][index]
            body = {key: record[key]
                    for key in ("at", "key", "status", "prev")}
            digest = hashlib.sha256(canonical_bytes(body)).digest()
            record["signature"] = crypto.sign_message(self.root_seed, digest)
            self.assertEqual(
                verify_history_trust(self.export_all(2), trust,
                                     self.root_pub)["error"],
                ERR_INTEGRITY,
            )

    def test_tampered_head_is_integrity(self) -> None:
        trust = self.single_trust()
        trust["head"] = "1" * 64
        self.assertEqual(
            verify_history_trust(self.export_all(2), trust,
                                 self.root_pub)["error"],
            ERR_INTEGRITY,
        )

    def test_structure_errors_are_input(self) -> None:
        pages = self.export_all(2)
        trust = self.single_trust()
        self.assertEqual(
            verify_history_trust([], trust, self.root_pub)["error"], ERR_INPUT
        )
        self.assertEqual(
            verify_history_trust("x", trust, self.root_pub)["error"],
            ERR_INPUT,
        )
        self.assertEqual(
            verify_history_trust(pages, "x", self.root_pub)["error"],
            ERR_INPUT,
        )
        self.assertEqual(
            verify_history_trust(pages, trust, 123)["error"], ERR_INPUT
        )
        self.assertEqual(
            verify_history_trust(pages, trust, "Z" * 64)["error"], ERR_INPUT
        )

        missing = self.single_trust()
        del missing["head"]
        self.assertEqual(
            verify_history_trust(pages, missing, self.root_pub)["error"],
            ERR_INPUT,
        )
        extra = self.single_trust()
        extra["extra"] = 1
        self.assertEqual(
            verify_history_trust(pages, extra, self.root_pub)["error"],
            ERR_INPUT,
        )
        reordered = self.single_trust()
        reordered["records"][0] = {
            "signature": reordered["records"][0]["signature"],
            "prev": ZERO,
            "status": "active",
            "key": self.pub1,
            "at": NOW - 5,
        }
        self.assertEqual(
            verify_history_trust(pages, reordered, self.root_pub)["error"],
            ERR_INPUT,
        )
        empty = self.single_trust()
        empty["records"] = []
        self.assertEqual(
            verify_history_trust(pages, empty, self.root_pub)["error"],
            ERR_INPUT,
        )
        for bad_at in (True, 0, -1, 1.5, "1"):
            bad = self.single_trust()
            bad["records"][0]["at"] = bad_at
            self.assertEqual(
                verify_history_trust(pages, bad, self.root_pub)["error"],
                ERR_INPUT,
            )
        bad_status = self.single_trust()
        bad_status["records"][0]["status"] = "revokd"
        self.assertEqual(
            verify_history_trust(pages, bad_status, self.root_pub)["error"],
            ERR_INPUT,
        )
        bad_hex = self.single_trust()
        bad_hex["records"][0]["key"] = "Z" * 64
        self.assertEqual(
            verify_history_trust(pages, bad_hex, self.root_pub)["error"],
            ERR_INPUT,
        )
        bad_sig = self.single_trust()
        bad_sig["records"][0]["signature"] = "0" * 127
        self.assertEqual(
            verify_history_trust(pages, bad_sig, self.root_pub)["error"],
            ERR_INPUT,
        )

    def test_page_chaining_rules_are_inherited(self) -> None:
        trust = self.single_trust()
        pages = self.export_all(2)
        # A tampered cross-page link, re-signed so only chaining is broken.
        pages[1]["records"][0]["prev"] = "1" * 64
        unsigned = {key: pages[1][key]
                    for key in ("base", "records", "next", "head",
                                "checkpoint")}
        digest = hashlib.sha256(_canonical_json_bytes(unsigned)).digest()
        pages[1]["auth"] = {
            "public_key": self.pub1,
            "signature": crypto.sign_message(self.key1, digest),
        }
        self.assertEqual(
            verify_history_trust(pages, trust, self.root_pub)["error"],
            ERR_INTEGRITY,
        )
        # A dropped page breaks the generation sequence.
        self.assertEqual(
            verify_history_trust([pages[0], pages[2]], trust,
                                 self.root_pub)["error"],
            ERR_INTEGRITY,
        )


if __name__ == "__main__":
    unittest.main()
