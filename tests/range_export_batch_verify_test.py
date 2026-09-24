"""Tests for offline multi-page incremental range verification
(ledger.light_client.verify_range_exports).

Covers the batch-level rules on top of the per-page rules already exercised by
``range_export_verify_test.py``: non-empty array input, fixed success key order
``ok, anchor, tip, pages, verified_tx_ids``, anchor chaining (first page pinned
to ``expected_anchor``, every later page pinned to the previous page's tip's
``{height, block_hash}``), broken seams and height jumps (integrity),
cross-page tx_id uniqueness (integrity), pending blocks only on the last page
(integrity), input/auth/expired/integrity categorization, and the offline
``ledger verify-range-batch`` CLI (file/stdin input, exit codes, single-line
JSON).

Run: python3 tests/range_export_batch_verify_test.py
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
    verify_range_exports,
)
from ledger.models import STATUS_PENDING, Block, Transaction
from ledger.store import LedgerStore, attested_range_message

NOW = 1_000_000_000
FUTURE = NOW + 10_000
PAST = NOW - 1
BOB = "b" * 64
_DEFAULT = object()

RESULT_KEY_ORDER = ["ok", "anchor", "tip", "pages", "verified_tx_ids"]
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


class RangeExportBatchFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice_pub = pub_hex(self.alice_key)

        # The caller-pinned anchor is the (confirmed, empty) genesis block.
        self.anchor_block = LedgerStore.create_genesis()
        self.anchor = {"height": 0, "block_hash": self.anchor_block.block_hash}

        # A four-block chain, one transaction per block.
        self.amounts = [100, 50, 25, 12]
        self.txs = []
        self.blocks = []
        prev_hash = self.anchor_block.block_hash
        for position, amount in enumerate(self.amounts, start=1):
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

        self.trust = {
            "sources": {
                "node-att": {"public_key": self.source_pub, "expires_at": FUTURE}
            },
            "allowlist": {"node-plain": FUTURE},
        }

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
        index: int = 0,
        signing_key: Ed25519PrivateKey | None = None,
    ) -> dict:
        tip = self.descriptor(anchor, blocks)
        attestation = None
        if mode == "attested":
            key = signing_key or self.source_key
            message = attested_range_message(
                source,
                request_id if request_id is not None else f"r{index}",
                expires_at,
                anchor,
                [b.to_dict() for b in blocks],
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
            "request_id": request_id if request_id is not None else f"r{index}",
            "mode": mode,
            "expires_at": expires_at,
            "anchor": dict(anchor),
            "blocks": [b.to_dict() for b in blocks],
            "tip": tip,
            "attestation": attestation,
        }
        return {key: doc[key] for key in EXPORT_KEY_ORDER}

    def make_pages(
        self,
        sizes,
        *,
        blocks: list | None = None,
        source: str = "node-plain",
        mode: str = "plain",
        expires_at: int = FUTURE,
    ) -> list:
        """Split the chain into consecutive range-export pages.

        ``sizes`` lists the number of blocks per page; each page's anchor is
        closed from the previous page's tip (the first from genesis).
        """
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
                    expires_at=expires_at,
                    index=position,
                )
            )
            anchor = {
                "height": slice_blocks[-1].height,
                "block_hash": slice_blocks[-1].block_hash,
            }
            cursor += size
        return pages

    def verify(self, documents, expected_anchor=_DEFAULT, trust=_DEFAULT, now=NOW):
        return verify_range_exports(
            documents,
            self.anchor if expected_anchor is _DEFAULT else expected_anchor,
            self.trust if trust is _DEFAULT else trust,
            now=now,
        )

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class VerifyRangeExportsSuccessTests(RangeExportBatchFixture):
    def test_two_page_success_shape_and_key_order(self) -> None:
        pages = self.make_pages([1, 3])
        result = self.verify(pages)
        self.assertEqual(list(result.keys()), RESULT_KEY_ORDER)
        self.assertEqual(
            result,
            {
                "ok": True,
                "anchor": self.anchor,
                "tip": self.descriptor(self.anchor, self.blocks),
                "pages": 2,
                "verified_tx_ids": sorted(tx.tx_id for tx in self.txs),
            },
        )

    def test_three_page_success(self) -> None:
        result = self.verify(self.make_pages([1, 1, 2]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 3)
        self.assertEqual(result["anchor"], self.anchor)
        self.assertEqual(
            result["tip"]["tip_hash"], self.blocks[-1].block_hash
        )
        self.assertEqual(
            result["verified_tx_ids"], sorted(tx.tx_id for tx in self.txs)
        )

    def test_single_page_batch(self) -> None:
        result = self.verify(self.make_pages([4]))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 1)
        self.assertEqual(
            result["tip"], self.descriptor(self.anchor, self.blocks)
        )

    def test_attested_pages(self) -> None:
        pages = self.make_pages([2, 2], source="node-att", mode="attested")
        result = self.verify(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 2)

    def test_pending_block_on_last_page_is_accepted(self) -> None:
        # Re-create the final block as pending; block hashes do not cover the
        # status field, so the chain linkage stays intact.
        pending_last = Block.create(
            4, self.blocks[2].block_hash, [self.txs[3]], status=STATUS_PENDING
        )
        pages = self.make_pages([2, 2], blocks=self.blocks[:3] + [pending_last])
        result = self.verify(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], "pending")

    def test_verified_tx_ids_are_ascending_across_pages(self) -> None:
        result = self.verify(self.make_pages([3, 1]))
        ids = result["verified_tx_ids"]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), 4)

    def test_now_none_uses_wall_clock(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["allowlist"]["node-plain"] = live
        result = self.verify(
            self.make_pages([2, 2], expires_at=live), trust=trust, now=None
        )
        self.assertTrue(result["ok"], result)


class VerifyRangeExportsInputTests(RangeExportBatchFixture):
    def test_documents_must_be_a_non_empty_array(self) -> None:
        for bad in (None, {}, "x", 1, True, [], ()):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(bad), ERR_INPUT)

    def test_page_element_must_be_an_object(self) -> None:
        pages = self.make_pages([1, 3])
        pages[1] = None
        self.assert_error(self.verify(pages), ERR_INPUT)
        pages = self.make_pages([1, 3])
        pages[0] = [1, 2, 3]
        self.assert_error(self.verify(pages), ERR_INPUT)

    def test_page_key_order_is_enforced(self) -> None:
        pages = self.make_pages([1, 3])
        page = pages[1]
        pages[1] = {key: page[key] for key in reversed(EXPORT_KEY_ORDER)}
        self.assert_error(self.verify(pages), ERR_INPUT)

    def test_page_with_empty_blocks_is_input(self) -> None:
        pages = self.make_pages([1, 3])
        pages[1]["blocks"] = []
        self.assert_error(self.verify(pages), ERR_INPUT)

    def test_expected_anchor_shape_defects(self) -> None:
        pages = self.make_pages([1, 3])
        for bad in (
            None,
            {},
            {"height": 0},
            {"height": "0", "block_hash": self.anchor["block_hash"]},
            {"height": -1, "block_hash": self.anchor["block_hash"]},
            {"height": 0, "block_hash": "00"},
        ):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(pages, bad), ERR_INPUT)

    def test_trust_shape_defects(self) -> None:
        pages = self.make_pages([1, 3])
        for bad in (None, [], {"sources": []}, {"allowlist": {"node-plain": 1.5}}):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(pages, trust=bad), ERR_INPUT)

    def test_raw_field_type_defect_inside_a_page_is_input(self) -> None:
        pages = self.make_pages([1, 3])
        pages[0]["blocks"][0]["height"] = "1"
        self.assert_error(self.verify(pages), ERR_INPUT)


class VerifyRangeExportsAuthTests(RangeExportBatchFixture):
    def test_untrusted_source_on_second_page_is_auth(self) -> None:
        pages = self.make_pages([1, 3])
        pages[1]["source"] = "node-other"
        self.assert_error(self.verify(pages), ERR_AUTH)

    def test_plain_page_with_attestation_is_auth(self) -> None:
        pages = self.make_pages([1, 3])
        pages[0]["attestation"] = {
            "public_key": self.source_pub,
            "version": 1,
            "signature": "ab" * 64,
        }
        self.assert_error(self.verify(pages), ERR_AUTH)

    def test_attested_page_under_wrong_key_is_auth(self) -> None:
        pages = self.make_pages([2, 2], source="node-att", mode="attested")
        other = Ed25519PrivateKey.generate()
        pages[1]["attestation"]["public_key"] = pub_hex(other)
        self.assert_error(self.verify(pages), ERR_AUTH)

    def test_auth_failure_takes_precedence_over_later_integrity(self) -> None:
        # The untrusted second page also has a broken anchor; auth wins.
        pages = self.make_pages([1, 3])
        pages[1]["source"] = "node-other"
        pages[1]["anchor"]["block_hash"] = "0" * 64
        self.assert_error(self.verify(pages), ERR_AUTH)


class VerifyRangeExportsExpiredTests(RangeExportBatchFixture):
    def test_expired_second_page(self) -> None:
        pages = self.make_pages([1, 3])
        pages[1]["expires_at"] = PAST
        self.assert_error(self.verify(pages), ERR_EXPIRED)

    def test_expires_at_equal_now_is_expired(self) -> None:
        pages = self.make_pages([1, 3])
        pages[0]["expires_at"] = NOW
        self.assert_error(self.verify(pages), ERR_EXPIRED)

    def test_expiry_checked_before_chain_integrity(self) -> None:
        pages = self.make_pages([1, 3])
        pages[1]["expires_at"] = PAST
        pages[1]["blocks"][0]["block_hash"] = "0" * 64
        self.assert_error(self.verify(pages), ERR_EXPIRED)


class VerifyRangeExportsIntegrityTests(RangeExportBatchFixture):
    def test_broken_seam_anchor_hash(self) -> None:
        pages = self.make_pages([1, 3])
        pages[1]["anchor"]["block_hash"] = "0" * 64
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_first_page_anchor_must_match_expected(self) -> None:
        pages = self.make_pages([1, 3])
        expected = {"height": 0, "block_hash": "0" * 64}
        self.assert_error(self.verify(pages, expected), ERR_INTEGRITY)

    def test_height_jump_between_pages(self) -> None:
        # Page 2 claims to follow block1 but starts delivering block 3: the
        # tail recomputation expects consecutive heights from anchor.height+1.
        pages = self.make_pages([1, 3])
        pages[1] = self.make_page(
            {"height": 1, "block_hash": self.blocks[0].block_hash},
            self.blocks[2:],
            index=1,
        )
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_overlapping_pages(self) -> None:
        # Page 2 re-delivers block 2 even though page 1 already reached it:
        # its anchor must be block2's tip, so the seam breaks.
        pages = self.make_pages([2, 2])
        pages[1] = self.make_page(
            {"height": 1, "block_hash": self.blocks[0].block_hash},
            self.blocks[1:3],
            index=1,
        )
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_duplicate_tx_id_across_pages(self) -> None:
        # A second block re-spending the same (already verified) transaction
        # passes per-page checks but violates batch-wide uniqueness.
        duplicate = Block.create(
            2, self.blocks[0].block_hash, [self.txs[0]]
        )
        pages = self.make_pages([1, 1], blocks=[self.blocks[0], duplicate])
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_pending_block_before_last_page(self) -> None:
        # Page 1 ends in a pending block; page 2's confirmed block follows it.
        # Each page individually is legal, but pending may only end the batch.
        pending_first = Block.create(
            1, self.anchor_block.block_hash, [self.txs[0]], status=STATUS_PENDING
        )
        confirmed_second = Block.create(
            2, pending_first.block_hash, [self.txs[1]]
        )
        pages = self.make_pages(
            [1, 1], blocks=[pending_first, confirmed_second]
        )
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_pending_block_in_middle_of_a_page_is_integrity(self) -> None:
        # A pending block inside the first page (which is followed by another
        # page) is already a per-page integrity failure.
        pending_middle = Block.create(
            2, self.blocks[0].block_hash, [self.txs[1]], status=STATUS_PENDING
        )
        after = Block.create(3, pending_middle.block_hash, [self.txs[2]])
        pages = self.make_pages(
            [2, 1], blocks=[self.blocks[0], pending_middle, after]
        )
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_tampered_tip_summary_on_second_page(self) -> None:
        pages = self.make_pages([1, 3])
        pages[1]["tip"]["height"] = 99
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_bad_attested_signature_on_later_page(self) -> None:
        pages = self.make_pages([2, 2], source="node-att", mode="attested")
        pages[1]["attestation"]["signature"] = "ab" * 64
        self.assert_error(self.verify(pages), ERR_INTEGRITY)


class VerifyRangeBatchCliTests(RangeExportBatchFixture):
    def _live_pages(self) -> list:
        live = int(time.time()) + 10_000
        return self.make_pages([2, 2], expires_at=live)

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
            [sys.executable, "-m", "ledger.cli", "verify-range-batch", *argv],
            input=stdin,
            capture_output=True,
            text=True,
            env=env,
        )

    def _run_with_files(
        self, exports_text: str, trust: dict, *extra: str
    ) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            epath = Path(tmp) / "exports.json"
            tpath = Path(tmp) / "trust.json"
            epath.write_text(exports_text)
            tpath.write_text(json.dumps(trust))
            return self._run(
                [
                    "--exports", str(epath),
                    "--trust", str(tpath),
                    "--anchor-height", str(self.anchor["height"]),
                    "--anchor-hash", self.anchor["block_hash"],
                    *extra,
                ]
            )

    def test_success_from_file_exit_zero_single_line(self) -> None:
        proc = self._run_with_files(
            json.dumps(self._live_pages()), self._live_trust()
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
        body = json.loads(proc.stdout)
        self.assertEqual(list(body.keys()), RESULT_KEY_ORDER)
        self.assertTrue(body["ok"])
        self.assertEqual(body["pages"], 2)
        self.assertEqual(body["anchor"], self.anchor)
        self.assertEqual(
            body["tip"], self.descriptor(self.anchor, self.blocks)
        )

    def test_success_from_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp) / "trust.json"
            tpath.write_text(json.dumps(self._live_trust()))
            proc = self._run(
                [
                    "--exports", "-",
                    "--trust", str(tpath),
                    "--anchor-height", "0",
                    "--anchor-hash", self.anchor["block_hash"],
                ],
                stdin=json.dumps(self._live_pages()),
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["pages"], 2)

    def test_broken_batch_exit_one_integrity(self) -> None:
        pages = self._live_pages()
        pages[1]["anchor"]["block_hash"] = "0" * 64
        proc = self._run_with_files(json.dumps(pages), self._live_trust())
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            json.loads(proc.stdout), {"ok": False, "error": "integrity"}
        )

    def test_non_array_json_is_input(self) -> None:
        proc = self._run_with_files("{}", self._live_trust())
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "error": "input"})

    def test_empty_array_is_input(self) -> None:
        proc = self._run_with_files("[]", self._live_trust())
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "error": "input"})

    def test_unreadable_or_non_json_exports_is_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp) / "trust.json"
            tpath.write_text(json.dumps(self._live_trust()))
            proc = self._run(
                [
                    "--exports", str(Path(tmp) / "missing.json"),
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
            epath = Path(tmp) / "exports.json"
            epath.write_text(json.dumps(self._live_pages()))
            proc = self._run(
                [
                    "--exports", str(epath),
                    "--trust", str(Path(tmp) / "missing.json"),
                    "--anchor-height", "0",
                    "--anchor-hash", self.anchor["block_hash"],
                ]
            )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "error": "input"})

    def test_illegal_anchor_arguments_are_input(self) -> None:
        exports = json.dumps(self._live_pages())
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
                    epath = Path(tmp) / "exports.json"
                    tpath = Path(tmp) / "trust.json"
                    epath.write_text(exports)
                    tpath.write_text(json.dumps(trust))
                    proc = self._run(
                        [
                            "--exports", str(epath),
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
