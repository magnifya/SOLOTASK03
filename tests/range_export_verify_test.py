"""Tests for offline range-export verification (ledger.light_client.verify_range_export).

Covers the fixed top-level key order ``source, request_id, mode, expires_at,
anchor, blocks, tip, attestation``, the strict expected-anchor binding,
standalone tail recomputation (heights, prev_hash linkage, tx_id/Ed25519,
uniqueness/ordering, Merkle roots, block hashes, pending-only-at-tip), the
closed tip summary, plain (allowlist, ``attestation: null``) and attested
(``trust.sources`` + ``ledger-sync-range-v1`` signature) authorization,
input/auth/expired/integrity categorization, and the offline
``ledger verify-range`` CLI (file/stdin input, exit codes, single-line JSON).

Run: python3 tests/range_export_verify_test.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.light_client import (
    ERR_AUTH,
    ERR_EXPIRED,
    ERR_INPUT,
    ERR_INTEGRITY,
    verify_range_export,
)
from ledger.models import STATUS_PENDING, Block, Transaction
from ledger.store import LedgerStore, attested_range_message

NOW = 1_000_000_000
FUTURE = NOW + 10_000
PAST = NOW - 1
BOB = "b" * 64
_DEFAULT = object()

RESULT_KEY_ORDER = [
    "ok",
    "source",
    "request_id",
    "mode",
    "anchor",
    "tip",
    "verified_tx_ids",
]
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


class RangeExportFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice_pub = pub_hex(self.alice_key)

        # The caller-pinned anchor is the (confirmed, empty) genesis block.
        self.anchor_block = LedgerStore.create_genesis()
        self.anchor = {"height": 0, "block_hash": self.anchor_block.block_hash}
        self.tx1 = Transaction(
            self.alice_pub, BOB, 100,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 100)
            ).hex(),
        )
        self.block1 = Block.create(1, self.anchor_block.block_hash, [self.tx1])
        self.tx2 = Transaction(
            self.alice_pub, BOB, 50,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 50)
            ).hex(),
        )
        self.block2 = Block.create(
            2, self.block1.block_hash, [self.tx2], status=STATUS_PENDING
        )
        self.tail = [self.block1, self.block2]
        self.tip = {
            "tip_hash": self.block2.block_hash,
            "height": 2,
            "length": 3,
            "status": "pending",
        }
        self.trust = {
            "sources": {
                "node-att": {"public_key": self.source_pub, "expires_at": FUTURE}
            },
            "allowlist": {"node-plain": FUTURE},
        }

    def document(self, **overrides) -> dict:
        doc = {
            "source": "node-plain",
            "request_id": "r1",
            "mode": "plain",
            "expires_at": FUTURE,
            "anchor": dict(self.anchor),
            "blocks": [b.to_dict() for b in self.tail],
            "tip": dict(self.tip),
            "attestation": None,
        }
        doc.update(overrides)
        # update() appends new keys at the end; rebuild in the fixed order so
        # overrides never disturb the documented top-level key sequence.
        return {key: doc[key] for key in EXPORT_KEY_ORDER}

    def attested_document(self, **overrides) -> dict:
        overrides.setdefault("source", "node-att")
        overrides.setdefault("mode", "attested")
        doc = self.document(**overrides)
        message = attested_range_message(
            doc["source"],
            doc["request_id"],
            doc["expires_at"],
            doc["anchor"],
            doc["blocks"],
            doc["tip"],
        )
        signature = self.source_key.sign(hashlib.sha256(message).digest()).hex()
        doc["attestation"] = {
            "public_key": self.source_pub,
            "version": 1,
            "signature": signature,
        }
        return doc

    def verify(self, document, expected_anchor=_DEFAULT, trust=_DEFAULT, now=NOW):
        return verify_range_export(
            document,
            self.anchor if expected_anchor is _DEFAULT else expected_anchor,
            self.trust if trust is _DEFAULT else trust,
            now=now,
        )

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class VerifyRangeExportSuccessTests(RangeExportFixture):
    def test_plain_success_shape_and_key_order(self) -> None:
        result = self.verify(self.document())
        self.assertEqual(list(result.keys()), RESULT_KEY_ORDER)
        self.assertEqual(
            result,
            {
                "ok": True,
                "source": "node-plain",
                "request_id": "r1",
                "mode": "plain",
                "anchor": self.anchor,
                "tip": self.tip,
                "verified_tx_ids": sorted([self.tx1.tx_id, self.tx2.tx_id]),
            },
        )

    def test_attested_success(self) -> None:
        result = self.verify(self.attested_document())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["mode"], "attested")
        self.assertEqual(result["tip"], self.tip)

    def test_pending_only_at_tip_is_accepted(self) -> None:
        # The fixture tail already ends in the pending block2.
        result = self.verify(self.document())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], "pending")

    def test_confirmed_tail_tip(self) -> None:
        tip = {
            "tip_hash": self.block1.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
        }
        result = self.verify(
            self.document(blocks=[self.block1.to_dict()], tip=tip)
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["verified_tx_ids"], [self.tx1.tx_id])

    def test_now_none_uses_wall_clock(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["allowlist"]["node-plain"] = live
        result = verify_range_export(
            self.document(expires_at=live), self.anchor, trust
        )
        self.assertTrue(result["ok"], result)


class VerifyRangeExportInputTests(RangeExportFixture):
    def test_document_not_a_dict(self) -> None:
        for bad in (None, [], "x", 1):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(bad), ERR_INPUT)

    def test_top_level_key_order_is_enforced(self) -> None:
        doc = self.document()
        shuffled = {key: doc[key] for key in reversed(EXPORT_KEY_ORDER)}
        self.assert_error(self.verify(shuffled), ERR_INPUT)

    def test_missing_and_extra_top_level_keys(self) -> None:
        for key in EXPORT_KEY_ORDER:
            with self.subTest(missing=key):
                doc = self.document()
                del doc[key]
                self.assert_error(self.verify(doc), ERR_INPUT)
        doc = self.document()
        doc["extra"] = 1
        self.assert_error(self.verify(doc), ERR_INPUT)

    def test_field_type_defects(self) -> None:
        cases = [
            {"source": ""},
            {"source": 1},
            {"request_id": ""},
            {"request_id": None},
            {"mode": "signed"},
            {"mode": None},
            {"expires_at": True},
            {"expires_at": str(FUTURE)},
            {"expires_at": float(FUTURE)},
            {"blocks": []},
            {"blocks": {}},
            {"tip": None},
            {"tip": {"tip_hash": self.tip["tip_hash"]}},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                self.assert_error(self.verify(self.document(**overrides)), ERR_INPUT)

    def test_tip_key_set_is_exact(self) -> None:
        tip = dict(self.tip, extra=1)
        self.assert_error(self.verify(self.document(tip=tip)), ERR_INPUT)

    def test_anchor_shape_defects(self) -> None:
        bad_anchors = [
            None,
            {},
            {"height": 0},
            {"height": True, "block_hash": self.anchor["block_hash"]},
            {"height": -1, "block_hash": self.anchor["block_hash"]},
            {"height": 0, "block_hash": "zz"},
            {"height": 0, "block_hash": self.anchor["block_hash"], "x": 1},
        ]
        for bad in bad_anchors:
            with self.subTest(anchor=bad):
                self.assert_error(self.verify(self.document(anchor=bad)), ERR_INPUT)

    def test_expected_anchor_shape_defects(self) -> None:
        bad = [
            None,
            {},
            {"height": 0},
            {"height": "0", "block_hash": self.anchor["block_hash"]},
            {"height": 0, "block_hash": "00"},
            {"height": 0, "block_hash": self.anchor["block_hash"], "x": 1},
        ]
        for anchor in bad:
            with self.subTest(expected=anchor):
                self.assert_error(self.verify(self.document(), anchor), ERR_INPUT)

    def test_attestation_shape_defects(self) -> None:
        base = self.attested_document()["attestation"]
        bad = [
            None,
            {},
            {**base, "public_key": "zz"},
            {**base, "version": 0},
            {**base, "version": True},
            {**base, "signature": "00"},
            {**base, "extra": 1},
        ]
        for attestation in bad:
            with self.subTest(attestation=attestation):
                doc = self.attested_document()
                doc["attestation"] = attestation
                self.assert_error(self.verify(doc), ERR_INPUT)

    def test_trust_shape_defects(self) -> None:
        bad_trusts = [
            None,
            [],
            {"sources": []},
            {"sources": {"node-att": []}},
            {"sources": {"node-att": {"public_key": self.source_pub}}},
            {"sources": {"node-att": {"public_key": "zz", "expires_at": FUTURE}}},
            {"sources": {"": {"public_key": self.source_pub, "expires_at": FUTURE}}},
            {"allowlist": []},
            {"allowlist": {"node-plain": True}},
        ]
        for trust in bad_trusts:
            with self.subTest(trust=trust):
                self.assert_error(self.verify(self.document(), trust=trust), ERR_INPUT)

    def test_tail_field_type_defects_are_input(self) -> None:
        # A non-integer height or a non-positive/non-integer amount is a
        # raw-value type defect (input), not a chain mismatch.
        block = self.block1.to_dict()
        block["height"] = "1"
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INPUT)

        block = self.block1.to_dict()
        block["transactions"][0]["amount"] = 0
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INPUT)

        block = self.block1.to_dict()
        block["transactions"][0]["amount"] = 1.5
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INPUT)


class VerifyRangeExportAuthTests(RangeExportFixture):
    def test_plain_source_must_be_allowlisted(self) -> None:
        self.assert_error(
            self.verify(self.document(source="node-att")), ERR_AUTH
        )

    def test_plain_export_must_not_carry_attestation(self) -> None:
        doc = self.document()
        doc["attestation"] = {
            "public_key": self.source_pub,
            "version": 1,
            "signature": "ab" * 64,
        }
        self.assert_error(self.verify(doc), ERR_AUTH)

    def test_attested_source_must_be_in_sources(self) -> None:
        doc = self.attested_document(source="node-plain")
        self.assert_error(self.verify(doc), ERR_AUTH)

    def test_attestation_key_must_match_the_pinned_key(self) -> None:
        doc = self.attested_document()
        other = Ed25519PrivateKey.generate()
        doc["attestation"]["public_key"] = pub_hex(other)
        self.assert_error(self.verify(doc), ERR_AUTH)


class VerifyRangeExportExpiredTests(RangeExportFixture):
    def test_document_deadline(self) -> None:
        self.assert_error(
            self.verify(self.document(expires_at=PAST)), ERR_EXPIRED
        )
        # ``expires_at <= now`` counts as expired.
        self.assert_error(
            self.verify(self.document(expires_at=NOW)), ERR_EXPIRED
        )

    def test_allowlist_deadline(self) -> None:
        trust = json.loads(json.dumps(self.trust))
        trust["allowlist"]["node-plain"] = NOW
        self.assert_error(self.verify(self.document(), trust=trust), ERR_EXPIRED)

    def test_sources_deadline(self) -> None:
        trust = json.loads(json.dumps(self.trust))
        trust["sources"]["node-att"]["expires_at"] = NOW
        self.assert_error(
            self.verify(self.attested_document(), trust=trust), ERR_EXPIRED
        )

    def test_expiry_checked_before_integrity(self) -> None:
        # An expired document with a tampered tail still reports expired.
        doc = self.document(expires_at=PAST)
        doc["blocks"][0]["block_hash"] = "0" * 64
        self.assert_error(self.verify(doc), ERR_EXPIRED)


class VerifyRangeExportIntegrityTests(RangeExportFixture):
    def test_expected_anchor_must_strictly_equal(self) -> None:
        for expected in (
            {"height": 1, "block_hash": self.anchor["block_hash"]},
            {"height": 0, "block_hash": "0" * 64},
        ):
            with self.subTest(expected=expected):
                self.assert_error(
                    self.verify(self.document(), expected), ERR_INTEGRITY
                )

    def test_tail_linkage_defects(self) -> None:
        # First prev_hash must be the anchor hash.
        block = self.block1.to_dict()
        block["prev_hash"] = "0" * 64
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INTEGRITY)

        # Heights must run consecutively from anchor.height + 1.
        block = self.block1.to_dict()
        block["height"] = 5
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INTEGRITY)

        # Recomputed block hash must match.
        block = self.block1.to_dict()
        block["block_hash"] = "0" * 64
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INTEGRITY)

        # Recomputed Merkle root must match.
        block = self.block1.to_dict()
        block["merkle_root"] = "0" * 64
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INTEGRITY)

    def test_pending_block_before_tip(self) -> None:
        blocks = [self.block2.to_dict(), self.block1.to_dict()]
        # Reorder so a pending block sits before the tip: also fix the
        # heights/linkage would fail anyway, so craft a genuine case instead.
        pending_first = Block.create(
            1, self.anchor_block.block_hash, [self.tx1], status=STATUS_PENDING
        )
        confirmed_second = Block.create(2, pending_first.block_hash, [self.tx2])
        blocks = [pending_first.to_dict(), confirmed_second.to_dict()]
        tip = {
            "tip_hash": confirmed_second.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        self.assert_error(
            self.verify(self.document(blocks=blocks, tip=tip)), ERR_INTEGRITY
        )

    def test_transaction_defects(self) -> None:
        # Tampered Ed25519 signature.
        block = self.block1.to_dict()
        block["transactions"][0]["signature"] = "ab" * 64
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INTEGRITY)

        # Stored tx_id must equal the recomputed one.
        block = self.block1.to_dict()
        block["transactions"][0]["tx_id"] = "0" * 64
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INTEGRITY)

        # The same transaction twice in the tail is a uniqueness failure.
        tx = self.tx1.to_dict()
        dup = Block.create(1, self.anchor_block.block_hash, [self.tx1, self.tx1])
        block = dup.to_dict()
        block["transactions"] = [dict(tx), dict(tx)]
        self.assert_error(self.verify(self.document(blocks=[block])), ERR_INTEGRITY)

    def test_transactions_must_be_ascending_inside_a_block(self) -> None:
        tx_a = Transaction(
            self.alice_pub, BOB, 7,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 7)
            ).hex(),
        )
        tx_b = Transaction(
            self.alice_pub, BOB, 8,
            self.alice_key.sign(
                crypto.canonical_message(self.alice_pub, BOB, 8)
            ).hex(),
        )
        first, second = sorted([tx_a, tx_b], key=lambda tx: tx.tx_id)
        block = Block.create(1, self.anchor_block.block_hash, [second, first])
        raw = block.to_dict()
        raw["transactions"] = [second.to_dict(), first.to_dict()]
        self.assert_error(self.verify(self.document(blocks=[raw])), ERR_INTEGRITY)

    def test_tip_summary_must_recompute(self) -> None:
        for field, bad in (
            ("tip_hash", "0" * 64),
            ("height", 7),
            ("length", 9),
            ("status", "confirmed"),
        ):
            with self.subTest(field=field):
                tip = dict(self.tip, **{field: bad})
                self.assert_error(
                    self.verify(self.document(tip=tip)), ERR_INTEGRITY
                )

    def test_attested_signature_must_verify(self) -> None:
        doc = self.attested_document()
        doc["attestation"]["signature"] = "ab" * 64
        self.assert_error(self.verify(doc), ERR_INTEGRITY)

        # A signature over a different message (e.g. after tampering with the
        # delivered expires_at) no longer verifies.
        doc = self.attested_document()
        doc["expires_at"] = FUTURE + 1
        self.assert_error(self.verify(doc), ERR_INTEGRITY)


class VerifyRangeExportCliTests(RangeExportFixture):
    def _live_document(self, **overrides) -> dict:
        live = int(time.time()) + 10_000
        overrides.setdefault("expires_at", live)
        return self.document(**overrides)

    def _live_trust(self) -> dict:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["allowlist"]["node-plain"] = live
        trust["sources"]["node-att"]["expires_at"] = live
        return trust

    def _run(self, argv: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
        repo = Path(__file__).resolve().parent.parent
        env = dict(os.environ, PYTHONPATH=str(repo))
        return subprocess.run(
            [sys.executable, "-m", "ledger.cli", "verify-range", *argv],
            input=stdin,
            capture_output=True,
            text=True,
            env=env,
        )

    def _run_with_files(
        self, document_text: str, trust: dict, *extra: str
    ) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            dpath = Path(tmp) / "export.json"
            tpath = Path(tmp) / "trust.json"
            dpath.write_text(document_text)
            tpath.write_text(json.dumps(trust))
            return self._run(
                [
                    "--export", str(dpath),
                    "--trust", str(tpath),
                    "--anchor-height", str(self.anchor["height"]),
                    "--anchor-hash", self.anchor["block_hash"],
                    *extra,
                ]
            )

    def test_success_from_file_exit_zero_single_line(self) -> None:
        proc = self._run_with_files(
            json.dumps(self._live_document()), self._live_trust()
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
        body = json.loads(proc.stdout)
        self.assertEqual(list(body.keys()), RESULT_KEY_ORDER)
        self.assertTrue(body["ok"])
        self.assertEqual(body["anchor"], self.anchor)
        self.assertEqual(body["tip"], self.tip)

    def test_success_from_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp) / "trust.json"
            tpath.write_text(json.dumps(self._live_trust()))
            proc = self._run(
                [
                    "--export", "-",
                    "--trust", str(tpath),
                    "--anchor-height", "0",
                    "--anchor-hash", self.anchor["block_hash"],
                ],
                stdin=json.dumps(self._live_document()),
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["ok"])

    def test_verification_failure_exit_one(self) -> None:
        proc = self._run_with_files(
            json.dumps(self._live_document(expires_at=1)), self._live_trust()
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "error": "expired"})

    def test_unreadable_or_non_json_export_is_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp) / "trust.json"
            tpath.write_text(json.dumps(self._live_trust()))
            proc = self._run(
                [
                    "--export", str(Path(tmp) / "missing.json"),
                    "--trust", str(tpath),
                    "--anchor-height", "0",
                    "--anchor-hash", self.anchor["block_hash"],
                ]
            )
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(
                json.loads(proc.stdout), {"ok": False, "error": "input"}
            )
        proc = self._run_with_files("not json", self._live_trust())
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "error": "input"})

    def test_unreadable_trust_is_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dpath = Path(tmp) / "export.json"
            dpath.write_text(json.dumps(self._live_document()))
            proc = self._run(
                [
                    "--export", str(dpath),
                    "--trust", str(Path(tmp) / "missing.json"),
                    "--anchor-height", "0",
                    "--anchor-hash", self.anchor["block_hash"],
                ]
            )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "error": "input"})

    def test_illegal_anchor_arguments_are_input(self) -> None:
        document = json.dumps(self._live_document())
        trust = self._live_trust()
        for height, hash_arg in (
            ("abc", self.anchor["block_hash"]),
            ("-1", self.anchor["block_hash"]),
            ("1.5", self.anchor["block_hash"]),
            ("0", "zz"),
            ("0", ""),
        ):
            with self.subTest(height=height, hash=hash_arg):
                with tempfile.TemporaryDirectory() as tmp:
                    dpath = Path(tmp) / "export.json"
                    tpath = Path(tmp) / "trust.json"
                    dpath.write_text(document)
                    tpath.write_text(json.dumps(trust))
                    proc = self._run(
                        [
                            "--export", str(dpath),
                            "--trust", str(tpath),
                            "--anchor-height", height,
                            "--anchor-hash", hash_arg,
                        ]
                    )
                self.assertEqual(proc.returncode, 1)
                self.assertEqual(
                    json.loads(proc.stdout), {"ok": False, "error": "input"}
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
