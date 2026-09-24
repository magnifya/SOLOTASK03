"""Tests for multi-page incremental range offline continuous verification
(ledger.light_client.verify_range_exports).

Covers the non-empty page array, per-page re-verification with the single
``verify_range_export`` rules (fixed eight-key order, tail recomputation,
plain/attested authorization, input/auth/expired/integrity categorization),
the cross-page rules — the first anchor pinned to ``expected_anchor``, each
later anchor equal to the previous page's closed tip reduced to
``{height, block_hash}`` (broken anchor/height jump -> integrity), tx_ids
unique across all pages (a repeat -> integrity), a pending tail allowed only
on the final page (a following page -> integrity) — the fixed success key
order ``ok, anchor, tip, pages, verified_tx_ids`` (``tip`` the last page's,
``pages`` the page count, ``verified_tx_ids`` delivery-wide ascending) and
the offline ``ledger verify-range-batch`` CLI (array file/stdin input, exit
codes, single-line JSON).

Run: python3 tests/range_batch_verify_test.py
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


class RangeBatchFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.source_key = Ed25519PrivateKey.generate()
        self.source_pub = pub_hex(self.source_key)
        self.alice_key = Ed25519PrivateKey.generate()
        self.alice_pub = pub_hex(self.alice_key)

        # The caller-pinned anchor is the (confirmed, empty) genesis block.
        self.anchor_block = LedgerStore.create_genesis()
        self.anchor = {"height": 0, "block_hash": self.anchor_block.block_hash}

        def make_tx(amount: int) -> Transaction:
            return Transaction(
                self.alice_pub,
                BOB,
                amount,
                self.alice_key.sign(
                    crypto.canonical_message(self.alice_pub, BOB, amount)
                ).hex(),
            )

        self.tx1 = make_tx(100)
        self.tx2 = make_tx(90)
        self.tx3 = make_tx(80)
        self.block1 = Block.create(1, self.anchor_block.block_hash, [self.tx1])
        self.block2 = Block.create(2, self.block1.block_hash, [self.tx2])
        self.block3 = Block.create(
            3, self.block2.block_hash, [self.tx3], status=STATUS_PENDING
        )
        # A pending block at height 2 (and a confirmed block on top of it) for
        # the pending-followed-by-a-page cases.
        self.block2_pending = Block.create(
            2, self.block1.block_hash, [self.tx2], status=STATUS_PENDING
        )
        self.block3_on_pending = Block.create(
            3, self.block2_pending.block_hash, [self.tx3]
        )
        self.trust = {
            "sources": {
                "node-att": {"public_key": self.source_pub, "expires_at": FUTURE}
            },
            "allowlist": {"node-plain": FUTURE},
        }

    def tip_for(self, anchor: dict, blocks: list[Block], status: str | None = None) -> dict:
        last = blocks[-1]
        return {
            "tip_hash": last.block_hash,
            "height": last.height,
            "length": anchor["height"] + 1 + len(blocks),
            "status": status if status is not None else last.status,
        }

    def page(
        self,
        anchor: dict,
        blocks: list[Block],
        *,
        source: str = "node-plain",
        mode: str = "plain",
        request_id: str | None = None,
        expires_at: int = FUTURE,
        tip: dict | None = None,
    ) -> dict:
        if tip is None:
            tip = self.tip_for(anchor, blocks)
        document = {
            "source": source,
            "request_id": request_id if request_id is not None else f"r-{tip['height']}",
            "mode": mode,
            "expires_at": expires_at,
            "anchor": dict(anchor),
            "blocks": [block.to_dict() for block in blocks],
            "tip": dict(tip),
            "attestation": None,
        }
        if mode == "attested":
            message = attested_range_message(
                document["source"],
                document["request_id"],
                document["expires_at"],
                document["anchor"],
                document["blocks"],
                document["tip"],
            )
            document["attestation"] = {
                "public_key": self.source_pub,
                "version": 1,
                "signature": self.source_key.sign(
                    hashlib.sha256(message).digest()
                ).hex(),
            }
        # Rebuild in the contract-fixed order so callers mutating fields never
        # disturb the documented top-level key sequence.
        return {key: document[key] for key in EXPORT_KEY_ORDER}

    def pages(self) -> list[dict]:
        anchor1 = self.anchor
        tip1 = self.tip_for(anchor1, [self.block1])
        anchor2 = {"height": tip1["height"], "block_hash": tip1["tip_hash"]}
        tip2 = self.tip_for(anchor2, [self.block2])
        anchor3 = {"height": tip2["height"], "block_hash": tip2["tip_hash"]}
        tip3 = self.tip_for(anchor3, [self.block3])
        return [
            self.page(anchor1, [self.block1], tip=tip1, source="node-plain"),
            self.page(
                anchor2, [self.block2], tip=tip2, source="node-att", mode="attested"
            ),
            self.page(anchor3, [self.block3], tip=tip3, source="node-plain"),
        ]

    def verify(self, documents, expected_anchor=_DEFAULT, trust=_DEFAULT, now=NOW):
        return verify_range_exports(
            documents,
            self.anchor if expected_anchor is _DEFAULT else expected_anchor,
            self.trust if trust is _DEFAULT else trust,
            now=now,
        )

    def assert_error(self, result: dict, category: str) -> None:
        self.assertEqual(result, {"ok": False, "error": category})


class VerifyRangeExportsSuccessTests(RangeBatchFixture):
    def test_multi_page_success_shape_and_key_order(self) -> None:
        pages = self.pages()
        result = self.verify(pages)
        self.assertEqual(list(result.keys()), RESULT_KEY_ORDER)
        self.assertEqual(
            result,
            {
                "ok": True,
                "anchor": self.anchor,
                "tip": pages[-1]["tip"],
                "pages": 3,
                "verified_tx_ids": sorted(
                    [self.tx1.tx_id, self.tx2.tx_id, self.tx3.tx_id]
                ),
            },
        )

    def test_single_page_array_is_accepted(self) -> None:
        page = self.page(self.anchor, [self.block1])
        result = self.verify([page])
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["anchor"], self.anchor)
        self.assertEqual(result["tip"], page["tip"])
        self.assertEqual(result["verified_tx_ids"], [self.tx1.tx_id])

    def test_anchor_is_the_first_pages_and_tip_the_last_pages(self) -> None:
        pages = self.pages()
        result = self.verify(pages)
        self.assertEqual(result["anchor"], pages[0]["anchor"])
        self.assertEqual(result["tip"], pages[-1]["tip"])
        # The intermediate tip never leaks into the result.
        self.assertNotEqual(result["tip"], pages[0]["tip"])

    def test_pending_tail_on_final_page_is_accepted(self) -> None:
        result = self.verify(self.pages())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], "pending")

    def test_verified_tx_ids_delivery_wide_and_ascending(self) -> None:
        result = self.verify(self.pages())
        expected = sorted([self.tx1.tx_id, self.tx2.tx_id, self.tx3.tx_id])
        self.assertEqual(result["verified_tx_ids"], expected)
        self.assertEqual(result["verified_tx_ids"], sorted(result["verified_tx_ids"]))

    def test_all_pages_confirmed(self) -> None:
        block3_confirmed = Block.create(3, self.block2.block_hash, [self.tx3])
        anchor1 = self.anchor
        tip1 = self.tip_for(anchor1, [self.block1])
        anchor2 = {"height": 1, "block_hash": self.block1.block_hash}
        pages = [
            self.page(anchor1, [self.block1], tip=tip1),
            self.page(
                anchor2,
                [self.block2, block3_confirmed],
                source="node-att",
                mode="attested",
            ),
        ]
        result = self.verify(pages)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["tip"]["status"], "confirmed")
        self.assertEqual(result["tip"]["height"], 3)

    def test_now_none_uses_wall_clock(self) -> None:
        live = int(time.time()) + 10_000
        trust = json.loads(json.dumps(self.trust))
        trust["allowlist"]["node-plain"] = live
        anchor1 = self.anchor
        tip1 = self.tip_for(anchor1, [self.block1])
        anchor2 = {"height": 1, "block_hash": self.block1.block_hash}
        pages = [
            self.page(anchor1, [self.block1], tip=tip1, expires_at=live),
            self.page(anchor2, [self.block2], expires_at=live),
        ]
        result = verify_range_exports(pages, self.anchor, trust)
        self.assertTrue(result["ok"], result)


class VerifyRangeExportsInputTests(RangeBatchFixture):
    def test_documents_must_be_a_non_empty_array(self) -> None:
        for bad in (None, {}, "x", 1, True, []):
            with self.subTest(bad=bad):
                self.assert_error(self.verify(bad), ERR_INPUT)

    def test_malformed_page_is_input(self) -> None:
        pages = self.pages()
        pages[1] = {"not": "an export"}
        self.assert_error(self.verify(pages), ERR_INPUT)

    def test_page_element_wrong_type_is_input(self) -> None:
        for bad in (None, [], "x", 1):
            with self.subTest(bad=bad):
                pages = self.pages()
                pages[0] = bad
                self.assert_error(self.verify(pages), ERR_INPUT)

    def test_wrong_top_level_key_order_on_any_page_is_input(self) -> None:
        pages = self.pages()
        shuffled = {key: pages[1][key] for key in reversed(EXPORT_KEY_ORDER)}
        pages[1] = shuffled
        self.assert_error(self.verify(pages), ERR_INPUT)

    def test_bad_expected_anchor_is_input(self) -> None:
        for anchor in (
            None,
            {},
            {"height": "0", "block_hash": self.anchor["block_hash"]},
            {"height": 0, "block_hash": "00"},
        ):
            with self.subTest(anchor=anchor):
                self.assert_error(self.verify(self.pages(), anchor), ERR_INPUT)

    def test_bad_trust_is_input(self) -> None:
        self.assert_error(self.verify(self.pages(), trust=None), ERR_INPUT)
        self.assert_error(
            self.verify(self.pages(), trust={"allowlist": []}), ERR_INPUT
        )


class VerifyRangeExportsAuthTests(RangeBatchFixture):
    def test_first_page_source_must_be_trusted(self) -> None:
        pages = self.pages()
        pages[0]["source"] = "node-unknown"
        self.assert_error(self.verify(pages), ERR_AUTH)

    def test_later_page_source_must_be_trusted(self) -> None:
        pages = self.pages()
        pages[1]["source"] = "node-unknown"
        self.assert_error(self.verify(pages), ERR_AUTH)

    def test_later_plain_page_must_not_carry_attestation(self) -> None:
        pages = self.pages()
        pages[1] = self.page(
            {"height": 1, "block_hash": self.block1.block_hash},
            [self.block2],
            source="node-plain",
            mode="plain",
        )
        pages[1]["attestation"] = {
            "public_key": self.source_pub,
            "version": 1,
            "signature": "ab" * 64,
        }
        self.assert_error(self.verify(pages), ERR_AUTH)

    def test_later_attested_page_key_mismatch_is_auth(self) -> None:
        pages = self.pages()
        other = Ed25519PrivateKey.generate()
        pages[1]["attestation"]["public_key"] = pub_hex(other)
        self.assert_error(self.verify(pages), ERR_AUTH)


class VerifyRangeExportsExpiredTests(RangeBatchFixture):
    def test_later_page_own_deadline(self) -> None:
        pages = self.pages()
        pages[1]["expires_at"] = PAST
        self.assert_error(self.verify(pages), ERR_EXPIRED)
        pages = self.pages()
        pages[1]["expires_at"] = NOW
        self.assert_error(self.verify(pages), ERR_EXPIRED)

    def test_later_page_allowlist_deadline(self) -> None:
        trust = json.loads(json.dumps(self.trust))
        trust["allowlist"]["node-plain"] = NOW
        # Page three is the plain page; its allowlist entry has expired.
        self.assert_error(self.verify(self.pages(), trust=trust), ERR_EXPIRED)

    def test_expiry_checked_before_later_page_integrity(self) -> None:
        pages = self.pages()
        pages[1]["expires_at"] = PAST
        pages[1]["blocks"][0]["block_hash"] = "0" * 64
        self.assert_error(self.verify(pages), ERR_EXPIRED)


class VerifyRangeExportsIntegrityTests(RangeBatchFixture):
    def test_first_page_anchor_must_match_expected(self) -> None:
        pages = self.pages()
        pages[0]["anchor"] = {"height": 0, "block_hash": "0" * 64}
        # The supplied tip/blocks are now inconsistent too, but the strict
        # anchor equality is the first integrity check after authorization.
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_later_anchor_must_equal_previous_tip_hash(self) -> None:
        pages = self.pages()
        pages[1]["anchor"]["block_hash"] = "0" * 64
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_later_anchor_must_equal_previous_tip_height(self) -> None:
        # A height jump: page two claims to start at height 9 although page
        # one's closed tip sits at height 1.
        pages = self.pages()
        pages[1]["anchor"]["height"] = 9
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_anchor_must_use_the_tip_hash_not_another_field(self) -> None:
        pages = self.pages()
        pages[1]["anchor"]["block_hash"] = pages[0]["blocks"][-1]["prev_hash"]
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_duplicate_tx_id_across_pages(self) -> None:
        # A block that is valid standalone (tx unique inside the page) but
        # repeats page one's tx_id across the delivery.
        repeat = Block.create(2, self.block1.block_hash, [self.tx1])
        anchor1 = self.anchor
        tip1 = self.tip_for(anchor1, [self.block1])
        pages = [
            self.page(anchor1, [self.block1], tip=tip1),
            self.page(
                {"height": 1, "block_hash": self.block1.block_hash}, [repeat]
            ),
        ]
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_pending_page_followed_by_another_page(self) -> None:
        # Page one ends pending at height 2; page two validly extends it. The
        # pending block is not the delivery tip, so the batch must fail even
        # though every individual page verifies on its own.
        anchor1 = self.anchor
        page1 = self.page(
            anchor1,
            [self.block1, self.block2_pending],
            source="node-plain",
        )
        pending_tip = page1["tip"]
        anchor2 = {"height": pending_tip["height"], "block_hash": pending_tip["tip_hash"]}
        page2 = self.page(
            anchor2, [self.block3_on_pending], source="node-plain"
        )
        # Sanity: each page individually verifies.
        from ledger.light_client import verify_range_export

        self.assertTrue(
            verify_range_export(page1, self.anchor, self.trust, now=NOW)["ok"]
        )
        self.assertTrue(
            verify_range_export(page2, anchor2, self.trust, now=NOW)["ok"]
        )
        self.assert_error(self.verify([page1, page2]), ERR_INTEGRITY)

    def test_tampered_block_on_later_page(self) -> None:
        pages = self.pages()
        pages[1]["blocks"][0]["block_hash"] = "0" * 64
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_bad_attestation_signature_on_later_page(self) -> None:
        pages = self.pages()
        pages[1]["attestation"]["signature"] = "ab" * 64
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_tip_summary_tampered_on_later_page(self) -> None:
        pages = self.pages()
        pages[1]["tip"]["height"] = 42
        self.assert_error(self.verify(pages), ERR_INTEGRITY)

    def test_duplicate_tx_does_not_poison_a_later_good_batch(self) -> None:
        # A failed batch must not mutate shared state: a fresh verification of
        # a good delivery afterwards still succeeds.
        pages = self.pages()
        bad = json.loads(json.dumps(pages))
        repeat = Block.create(2, self.block1.block_hash, [self.tx1]).to_dict()
        bad[1]["blocks"] = [repeat]
        self.assert_error(self.verify(bad), ERR_INTEGRITY)
        self.assertTrue(self.verify(pages)["ok"])


class VerifyRangeBatchCliTests(RangeBatchFixture):
    def _live_pages(self) -> list[dict]:
        live = int(time.time()) + 10_000
        anchor1 = self.anchor
        block1 = self.block1
        tip1 = {
            "tip_hash": block1.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
        }
        page1 = self.page(anchor1, [block1], tip=tip1, expires_at=live)
        page2 = self.page(
            {"height": 1, "block_hash": block1.block_hash},
            [self.block2, self.block3],
            source="node-plain",
            expires_at=live,
        )
        return [page1, page2]

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
        self, documents_text: str, trust: dict, *extra: str
    ) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            dpath = Path(tmp) / "exports.json"
            tpath = Path(tmp) / "trust.json"
            dpath.write_text(documents_text)
            tpath.write_text(json.dumps(trust))
            return self._run(
                [
                    "--exports", str(dpath),
                    "--trust", str(tpath),
                    "--anchor-height", str(self.anchor["height"]),
                    "--anchor-hash", self.anchor["block_hash"],
                    *extra,
                ]
            )

    def test_success_from_file_exit_zero_single_line(self) -> None:
        pages = self._live_pages()
        proc = self._run_with_files(json.dumps(pages), self._live_trust())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(proc.stdout.strip().splitlines()), 1)
        body = json.loads(proc.stdout)
        self.assertEqual(list(body.keys()), RESULT_KEY_ORDER)
        self.assertTrue(body["ok"])
        self.assertEqual(body["anchor"], self.anchor)
        self.assertEqual(body["tip"], pages[-1]["tip"])
        self.assertEqual(body["pages"], 2)
        self.assertEqual(
            body["verified_tx_ids"],
            sorted([self.tx1.tx_id, self.tx2.tx_id, self.tx3.tx_id]),
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
        body = json.loads(proc.stdout)
        self.assertTrue(body["ok"])
        self.assertEqual(body["pages"], 2)

    def test_verification_failure_exit_one(self) -> None:
        pages = self._live_pages()
        pages[1]["anchor"]["block_hash"] = "0" * 64
        proc = self._run_with_files(json.dumps(pages), self._live_trust())
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(
            json.loads(proc.stdout), {"ok": False, "error": "integrity"}
        )

    def test_non_array_json_is_input(self) -> None:
        proc = self._run_with_files(
            json.dumps(self._live_pages()[0]), self._live_trust()
        )
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
            dpath = Path(tmp) / "exports.json"
            dpath.write_text(json.dumps(self._live_pages()))
            proc = self._run(
                [
                    "--exports", str(dpath),
                    "--trust", str(Path(tmp) / "missing.json"),
                    "--anchor-height", "0",
                    "--anchor-hash", self.anchor["block_hash"],
                ]
            )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout), {"ok": False, "error": "input"})

    def test_illegal_anchor_arguments_are_input(self) -> None:
        documents = json.dumps(self._live_pages())
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
                    dpath = Path(tmp) / "exports.json"
                    tpath = Path(tmp) / "trust.json"
                    dpath.write_text(documents)
                    tpath.write_text(json.dumps(trust))
                    proc = self._run(
                        [
                            "--exports", str(dpath),
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
