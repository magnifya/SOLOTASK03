"""Tests for ledger.light_client.verify_range_export and the verify-range CLI.

A range-export document (the response of GET /v1/forks/sync/range/export,
top-level key order ``source, request_id, mode, expires_at, anchor, blocks,
tip, attestation``) is verified offline against a caller-pinned anchor and a
local trust document: strict structure (input), mode-specific source trust
(auth: plain needs the allowlist and attestation=null, attested needs
trust.sources), deadlines (expired), then the pinned anchor equality, the
recomputed tail (heights, prev_hash linkage, per-transaction tx_id and
Ed25519 signature, unique sorted tx_ids, Merkle roots, block hashes, pending
only as the final block), the recomputed tip summary and — for attested
exports — the frozen-key signature over the canonical ledger-sync-range-v1
message (integrity). Success returns the fixed key order
``ok, source, request_id, mode, anchor, tip, verified_tx_ids`` with
verified_tx_ids ascending; failure returns ``{"ok": False, "error":
"input"|"auth"|"expired"|"integrity"}`` and never raises. The
``verify-range --export FILE|- --trust TRUST --anchor-height H
--anchor-hash HASH`` CLI prints one JSON line and exits 0/1; a bad file,
bad JSON or bad anchor parameters are ``input``.

Run: python3 tests/light_client_range_export_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.light_client import verify_range_export
from ledger.models import STATUS_PENDING, Block, Transaction
from ledger.service import LedgerService
from ledger.store import LedgerStore, attested_range_message

SUCCESS_KEY_ORDER = [
    "ok",
    "source",
    "request_id",
    "mode",
    "anchor",
    "tip",
    "verified_tx_ids",
]


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def seed_of(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    msg = crypto.canonical_message(sender, to, amount)
    return Transaction.from_dict(
        {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}
    )


class VerifyRangeExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.svc = LedgerService(
            LedgerStore(os.path.join(self.tmp, "state.json"), initial_balance=1000),
            initial_balance=1000,
        )
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.now = int(time.time())
        self.exp = self.now + 10_000_000
        # A confirmed canonical chain 0..1 the exported ranges anchor on.
        self.svc.submit_transaction(
            {
                "from": self.A,
                "to": self.B,
                "amount": 3,
                "signature": self.ka.sign(
                    crypto.canonical_message(self.A, self.B, 3)
                ).hex(),
            }
        )
        self.assertEqual(self.svc.mine_block()[0], 201)
        self.assertEqual(self.svc.confirm_block(1)[0], 200)
        self.anchor_block = self.svc.store.chain[1]
        self.anchor = {"height": 1, "block_hash": self.anchor_block.block_hash}
        self.trust = {
            "allowlist": {"plain-node": self.exp},
            "sources": {
                "att-node": {"public_key": self.C, "expires_at": self.exp}
            },
        }

    # -- helpers --------------------------------------------------------------

    def _tail(self, amount: int, n: int = 1, pending_last: bool = False) -> list[Block]:
        blocks: list[Block] = []
        prev = self.anchor_block.block_hash
        for i in range(n):
            status = (
                STATUS_PENDING if pending_last and i == n - 1 else "confirmed"
            )
            block = Block.create(
                self.anchor["height"] + 1 + i,
                prev,
                [tx_obj(self.ka, self.A, self.B, amount + i)],
                status,
            )
            blocks.append(block)
            prev = block.block_hash
        return blocks

    @staticmethod
    def _tip(anchor: dict, tail: list[Block]) -> dict:
        end = tail[-1]
        return {
            "tip_hash": end.block_hash,
            "height": end.height,
            "length": anchor["height"] + 1 + len(tail),
            "status": end.status,
        }

    def _export_plain(self, tail: list[Block], request_id: str = "r1") -> dict:
        self.svc.register_trust_source(
            {"source": "plain-node", "public_key": self.A, "expires_at": self.exp}
        )
        status, body = self.svc.submit_fork_sync_range(
            {
                "source": "plain-node",
                "request_id": request_id,
                "expires_at": self.exp,
                "anchor": self.anchor,
                "blocks": [b.to_dict() for b in tail],
                "tip": self._tip(self.anchor, tail),
            }
        )
        self.assertEqual(status, 201, body)
        status, document = self.svc.export_fork_sync_range(
            {"source": "plain-node", "request_id": request_id, "mode": "plain"}
        )
        self.assertEqual(status, 200, document)
        return document

    def _export_attested(self, tail: list[Block], request_id: str = "r2") -> dict:
        self.svc.register_trust_source(
            {"source": "att-node", "public_key": self.C, "expires_at": self.exp}
        )
        blocks = [b.to_dict() for b in tail]
        tip = self._tip(self.anchor, tail)
        message = attested_range_message(
            "att-node", request_id, self.exp, self.anchor, blocks, tip
        )
        signature = crypto.sign_message(
            seed_of(self.kc), hashlib.sha256(message).digest()
        )
        status, body = self.svc.submit_fork_sync_range_attested(
            {
                "source": "att-node",
                "request_id": request_id,
                "expires_at": self.exp,
                "anchor": self.anchor,
                "blocks": blocks,
                "tip": tip,
                "signature": signature,
            }
        )
        self.assertEqual(status, 201, body)
        status, document = self.svc.export_fork_sync_range(
            {"source": "att-node", "request_id": request_id, "mode": "attested"}
        )
        self.assertEqual(status, 200, document)
        return document

    @staticmethod
    def _tx_ids(document: dict) -> list[str]:
        return sorted(
            tx["tx_id"] for block in document["blocks"] for tx in block["transactions"]
        )

    # -- success ---------------------------------------------------------------

    def test_plain_success_key_order_and_sorted_tx_ids(self) -> None:
        document = self._export_plain(self._tail(7, n=2))
        result = verify_range_export(document, self.anchor, self.trust, now=self.now)
        self.assertEqual(list(result), SUCCESS_KEY_ORDER)
        self.assertIs(result["ok"], True)
        self.assertEqual(result["source"], "plain-node")
        self.assertEqual(result["request_id"], "r1")
        self.assertEqual(result["mode"], "plain")
        self.assertEqual(result["anchor"], self.anchor)
        self.assertEqual(result["tip"], document["tip"])
        self.assertEqual(result["verified_tx_ids"], self._tx_ids(document))

    def test_plain_pending_last_block_success(self) -> None:
        document = self._export_plain(self._tail(9, n=2, pending_last=True))
        result = verify_range_export(document, self.anchor, self.trust, now=self.now)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["tip"]["status"], "pending")

    def test_attested_success(self) -> None:
        document = self._export_attested(self._tail(11))
        result = verify_range_export(document, self.anchor, self.trust, now=self.now)
        self.assertEqual(list(result), SUCCESS_KEY_ORDER)
        self.assertIs(result["ok"], True)
        self.assertEqual(result["mode"], "attested")
        self.assertEqual(result["verified_tx_ids"], self._tx_ids(document))

    def test_attested_survives_trust_rotation(self) -> None:
        # The frozen attestation key verifies even after the registry rotated.
        document = self._export_attested(self._tail(13))
        _k, new_pub = keypair()
        status, _ = self.svc.rotate_trust_source(
            "att-node",
            {"public_key": new_pub, "expires_at": self.exp, "expected_version": 1},
        )
        self.assertEqual(status, 200)
        trust = {
            "sources": {"att-node": {"public_key": new_pub, "expires_at": self.exp}}
        }
        result = verify_range_export(document, self.anchor, trust, now=self.now)
        self.assertTrue(result["ok"], result)

    def test_now_defaults_to_wall_clock(self) -> None:
        document = self._export_plain(self._tail(15))
        result = verify_range_export(document, self.anchor, self.trust)
        self.assertTrue(result["ok"], result)

    # -- input ------------------------------------------------------------------

    def test_input_structure(self) -> None:
        document = self._export_plain(self._tail(17))
        self.assertEqual(
            verify_range_export("nope", self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "input"},
        )
        self.assertEqual(
            verify_range_export(document, self.anchor, "nope", now=self.now),
            {"ok": False, "error": "input"},
        )
        # Top-level key order is part of the contract.
        reordered = {
            key: document[key]
            for key in (
                "request_id", "source", "mode", "expires_at",
                "anchor", "blocks", "tip", "attestation",
            )
        }
        self.assertEqual(
            verify_range_export(reordered, self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "input"},
        )
        for field in (
            "source", "request_id", "mode", "expires_at",
            "anchor", "blocks", "tip", "attestation",
        ):
            bad = dict(document)
            del bad[field]
            self.assertEqual(
                verify_range_export(bad, self.anchor, self.trust, now=self.now),
                {"ok": False, "error": "input"},
                field,
            )
        variants = []
        for changes in (
            {"source": ""},
            {"request_id": ""},
            {"mode": "all"},
            {"expires_at": True},
            {"expires_at": "123"},
            {"anchor": {"height": 1}},
            {"anchor": {"height": True, "block_hash": self.anchor["block_hash"]}},
            {"anchor": {"height": -1, "block_hash": self.anchor["block_hash"]}},
            {"anchor": {"height": 1, "block_hash": "z" * 64}},
            {"blocks": []},
            {"blocks": "x"},
            {"tip": {"tip_hash": "0" * 64}},
        ):
            bad = json.loads(json.dumps(document))
            bad.update(changes)
            variants.append(bad)
        tip_extra = json.loads(json.dumps(document["tip"]))
        tip_extra["extra"] = 1
        bad = json.loads(json.dumps(document))
        bad["tip"] = tip_extra
        variants.append(bad)
        for bad in variants:
            self.assertEqual(
                verify_range_export(bad, self.anchor, self.trust, now=self.now),
                {"ok": False, "error": "input"},
                bad.get("mode"),
            )

    def test_input_expected_anchor_and_trust_shapes(self) -> None:
        document = self._export_plain(self._tail(19))
        for bad_anchor in (
            None,
            {"height": 1},
            {"height": "1", "block_hash": self.anchor["block_hash"]},
            {"height": 1, "block_hash": "ZZ"},
            {"height": 1.0, "block_hash": self.anchor["block_hash"]},
        ):
            self.assertEqual(
                verify_range_export(document, bad_anchor, self.trust, now=self.now),
                {"ok": False, "error": "input"},
                bad_anchor,
            )
        for bad_trust in (
            {"sources": []},
            {"allowlist": {"plain-node": "soon"}},
            {"sources": {"att-node": {"public_key": "zz", "expires_at": self.exp}}},
            {"sources": {"att-node": {"public_key": self.C}}},
        ):
            self.assertEqual(
                verify_range_export(document, self.anchor, bad_trust, now=self.now),
                {"ok": False, "error": "input"},
                bad_trust,
            )

    def test_input_raw_block_field_types(self) -> None:
        document = self._export_plain(self._tail(21))
        bad = json.loads(json.dumps(document))
        bad["blocks"][0]["height"] = "2"
        self.assertEqual(
            verify_range_export(bad, self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "input"},
        )
        bad = json.loads(json.dumps(document))
        bad["blocks"][0]["transactions"][0]["amount"] = 1.5
        self.assertEqual(
            verify_range_export(bad, self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "input"},
        )

    # -- auth --------------------------------------------------------------------

    def test_auth_source_membership_by_mode(self) -> None:
        plain = self._export_plain(self._tail(23))
        attested = self._export_attested(self._tail(25))
        # Unknown sources.
        self.assertEqual(
            verify_range_export(plain, self.anchor, {"allowlist": {}}, now=self.now),
            {"ok": False, "error": "auth"},
        )
        self.assertEqual(
            verify_range_export(attested, self.anchor, {"sources": {}}, now=self.now),
            {"ok": False, "error": "auth"},
        )
        # A plain export is not authorized by a sources entry alone ...
        self.assertEqual(
            verify_range_export(
                plain,
                self.anchor,
                {"sources": {"plain-node": {"public_key": self.A, "expires_at": self.exp}}},
                now=self.now,
            ),
            {"ok": False, "error": "auth"},
        )
        # ... and an attested export is not authorized by the allowlist.
        self.assertEqual(
            verify_range_export(
                attested,
                self.anchor,
                {"allowlist": {"att-node": self.exp}},
                now=self.now,
            ),
            {"ok": False, "error": "auth"},
        )

    def test_auth_plain_must_not_carry_attestation(self) -> None:
        plain = self._export_plain(self._tail(27))
        attested = self._export_attested(self._tail(29))
        bad = dict(plain)
        bad["attestation"] = attested["attestation"]
        self.assertEqual(
            verify_range_export(bad, self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "auth"},
        )
        # A structurally malformed attestation value is an input defect.
        for malformed in ("sig", {"public_key": "zz"}, {"public_key": "0" * 64}):
            bad = dict(plain)
            bad["attestation"] = malformed
            self.assertEqual(
                verify_range_export(bad, self.anchor, self.trust, now=self.now),
                {"ok": False, "error": "input"},
                malformed,
            )

    # -- expired ------------------------------------------------------------------

    def test_expired_document_and_trust_entries(self) -> None:
        plain = self._export_plain(self._tail(31))
        attested = self._export_attested(self._tail(33))
        # The document deadline itself (<= now counts as expired).
        self.assertEqual(
            verify_range_export(plain, self.anchor, self.trust, now=self.exp),
            {"ok": False, "error": "expired"},
        )
        # The allowlist entry deadline.
        self.assertEqual(
            verify_range_export(
                plain,
                self.anchor,
                {"allowlist": {"plain-node": self.now}},
                now=self.now,
            ),
            {"ok": False, "error": "expired"},
        )
        # The sources entry deadline.
        self.assertEqual(
            verify_range_export(
                attested,
                self.anchor,
                {"sources": {"att-node": {"public_key": self.C, "expires_at": self.now}}},
                now=self.now,
            ),
            {"ok": False, "error": "expired"},
        )

    # -- integrity ------------------------------------------------------------------

    def test_integrity_anchor_mismatch(self) -> None:
        document = self._export_plain(self._tail(35))
        for wrong in (
            {"height": 0, "block_hash": self.anchor["block_hash"]},
            {"height": 1, "block_hash": "0" * 64},
            {"height": 2, "block_hash": self.anchor["block_hash"]},
        ):
            self.assertEqual(
                verify_range_export(document, wrong, self.trust, now=self.now),
                {"ok": False, "error": "integrity"},
                wrong,
            )

    def test_integrity_tail_recomputation(self) -> None:
        document = self._export_plain(self._tail(37, n=2))
        cases = []

        bad = json.loads(json.dumps(document))
        bad["blocks"][0]["transactions"][0]["amount"] += 1
        cases.append(bad)  # tx_id / merkle / block_hash no longer recompute

        bad = json.loads(json.dumps(document))
        bad["blocks"][1]["prev_hash"] = "0" * 64
        cases.append(bad)  # broken linkage

        bad = json.loads(json.dumps(document))
        bad["blocks"][0]["height"] = 5
        cases.append(bad)  # non-consecutive height

        bad = json.loads(json.dumps(document))
        bad["blocks"][0]["status"] = "pending"
        cases.append(bad)  # pending before the tail tip

        bad = json.loads(json.dumps(document))
        bad["blocks"][0]["transactions"][0]["signature"] = "f" * 128
        cases.append(bad)  # bad Ed25519 signature

        bad = json.loads(json.dumps(document))
        dup = bad["blocks"][0]["transactions"][0]
        bad["blocks"][1]["transactions"] = [dup]
        cases.append(bad)  # duplicate tx_id across the tail

        for bad in cases:
            self.assertEqual(
                verify_range_export(bad, self.anchor, self.trust, now=self.now),
                {"ok": False, "error": "integrity"},
            )

    def test_integrity_tip_mismatch(self) -> None:
        document = self._export_plain(self._tail(39))
        for field, value in (
            ("tip_hash", "0" * 64),
            ("height", 99),
            ("length", 99),
            ("status", "pending"),
        ):
            bad = json.loads(json.dumps(document))
            bad["tip"][field] = value
            self.assertEqual(
                verify_range_export(bad, self.anchor, self.trust, now=self.now),
                {"ok": False, "error": "integrity"},
                field,
            )

    def test_integrity_attested_signature(self) -> None:
        document = self._export_attested(self._tail(41))
        # A syntactically valid but cryptographically wrong signature.
        bad = json.loads(json.dumps(document))
        bad["attestation"]["signature"] = "f" * 128
        self.assertEqual(
            verify_range_export(bad, self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "integrity"},
        )
        # Re-signing the same content with a different key fails too.
        bad = json.loads(json.dumps(document))
        message = attested_range_message(
            "att-node", "r2", self.exp, self.anchor,
            bad["blocks"], bad["tip"],
        )
        bad["attestation"]["signature"] = crypto.sign_message(
            seed_of(self.ka), hashlib.sha256(message).digest()
        )
        self.assertEqual(
            verify_range_export(bad, self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "integrity"},
        )
        # A tampered signed field (request_id) invalidates the signature.
        bad = json.loads(json.dumps(document))
        bad["request_id"] = "rX"
        self.assertEqual(
            verify_range_export(bad, self.anchor, self.trust, now=self.now),
            {"ok": False, "error": "integrity"},
        )

    def test_never_raises_on_garbage(self) -> None:
        for garbage in (None, 42, [], {"source": object()}, {"mode": "plain"}):
            result = verify_range_export(garbage, self.anchor, self.trust)
            self.assertEqual(result, {"ok": False, "error": "input"}, garbage)


class VerifyRangeCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        svc = LedgerService(
            LedgerStore(os.path.join(cls.tmp, "state.json"), initial_balance=1000),
            initial_balance=1000,
        )
        ka, cls.A = keypair()
        _kb, cls.B = keypair()
        cls.exp = int(time.time()) + 10_000_000
        svc.submit_transaction(
            {
                "from": cls.A,
                "to": cls.B,
                "amount": 3,
                "signature": ka.sign(crypto.canonical_message(cls.A, cls.B, 3)).hex(),
            }
        )
        assert svc.mine_block()[0] == 201
        assert svc.confirm_block(1)[0] == 200
        anchor_block = svc.store.chain[1]
        cls.anchor = {"height": 1, "block_hash": anchor_block.block_hash}
        tail = Block.create(
            2, anchor_block.block_hash, [tx_obj(ka, cls.A, cls.B, 10)], "confirmed"
        )
        svc.register_trust_source(
            {"source": "node-1", "public_key": cls.A, "expires_at": cls.exp}
        )
        status, body = svc.submit_fork_sync_range(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": cls.exp,
                "anchor": cls.anchor,
                "blocks": [tail.to_dict()],
                "tip": {
                    "tip_hash": tail.block_hash,
                    "height": 2,
                    "length": 3,
                    "status": "confirmed",
                },
            }
        )
        assert status == 201, body
        status, cls.document = svc.export_fork_sync_range(
            {"source": "node-1", "request_id": "req-1", "mode": "plain"}
        )
        assert status == 200, cls.document
        cls.export_path = os.path.join(cls.tmp, "range.json")
        with open(cls.export_path, "w", encoding="utf-8") as fh:
            json.dump(cls.document, fh)
        cls.trust_path = os.path.join(cls.tmp, "trust.json")
        with open(cls.trust_path, "w", encoding="utf-8") as fh:
            json.dump({"allowlist": {"node-1": cls.exp}}, fh)

    def _run_cli(self, *args: str, stdin: str | None = None) -> tuple[int, str]:
        buf = io.StringIO()
        old_stdin = sys.stdin
        if stdin is not None:
            sys.stdin = io.StringIO(stdin)
        try:
            with redirect_stdout(buf):
                rc = cli_main(list(args))
        finally:
            sys.stdin = old_stdin
        return rc, buf.getvalue()

    def _args(self, *extra: str) -> tuple[str, ...]:
        return (
            "verify-range",
            "--export", self.export_path,
            "--trust", self.trust_path,
            "--anchor-height", str(self.anchor["height"]),
            "--anchor-hash", self.anchor["block_hash"],
            *extra,
        )

    def test_success_single_line_exit_0(self) -> None:
        rc, out = self._run_cli(*self._args())
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.count("\n"), 1)
        body = json.loads(out)
        self.assertEqual(list(body), SUCCESS_KEY_ORDER)
        self.assertIs(body["ok"], True)
        self.assertEqual(body["source"], "node-1")
        self.assertEqual(body["anchor"], self.anchor)

    def test_stdin_export_exit_0(self) -> None:
        rc, out = self._run_cli(
            "verify-range",
            "--export", "-",
            "--trust", self.trust_path,
            "--anchor-height", "1",
            "--anchor-hash", self.anchor["block_hash"],
            stdin=json.dumps(self.document),
        )
        self.assertEqual(rc, 0, out)
        self.assertIs(json.loads(out)["ok"], True)

    def test_verification_failure_exit_1(self) -> None:
        rc, out = self._run_cli(
            "verify-range",
            "--export", self.export_path,
            "--trust", self.trust_path,
            "--anchor-height", "2",
            "--anchor-hash", self.anchor["block_hash"],
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out), {"ok": False, "error": "integrity"})

    def test_bad_file_json_and_params_are_input(self) -> None:
        # Unreadable export file.
        rc, out = self._run_cli(
            "verify-range",
            "--export", os.path.join(self.tmp, "missing.json"),
            "--trust", self.trust_path,
            "--anchor-height", "1",
            "--anchor-hash", self.anchor["block_hash"],
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out), {"ok": False, "error": "input"})
        # Malformed JSON on stdin.
        rc, out = self._run_cli(
            "verify-range",
            "--export", "-",
            "--trust", self.trust_path,
            "--anchor-height", "1",
            "--anchor-hash", self.anchor["block_hash"],
            stdin="{not json",
        )
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out), {"ok": False, "error": "input"})
        # Malformed anchor parameters.
        for height, hash_value in (
            ("x", self.anchor["block_hash"]),
            ("-1", self.anchor["block_hash"]),
            ("1.0", self.anchor["block_hash"]),
            ("1", "zz"),
            ("1", "0" * 63),
        ):
            rc, out = self._run_cli(
                "verify-range",
                "--export", self.export_path,
                "--trust", self.trust_path,
                "--anchor-height", height,
                "--anchor-hash", hash_value,
            )
            self.assertEqual(rc, 1, (height, hash_value))
            self.assertEqual(
                json.loads(out), {"ok": False, "error": "input"}, (height, hash_value)
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
