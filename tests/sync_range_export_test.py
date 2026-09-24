"""Tests for GET /v1/forks/sync/range/export and the ``sync-range-export`` CLI.

The endpoint exports one received INCREMENTAL range delivery by its
idempotency key: exactly the three single-valued query parameters ``source``,
``request_id`` and ``mode`` (``plain``/``attested`` only) are accepted —
missing, repeated, empty, unknown or illegal parameters are 400. A hit returns
200 with the fixed key order
``source, request_id, mode, expires_at, anchor, blocks, tip, attestation``:
``expires_at`` is a non-boolean integer, ``anchor`` is
``{height, block_hash}`` (non-negative integer, 64 lowercase hex), ``blocks``
is the non-empty delivered tail of README-order block documents, ``tip`` is
``{tip_hash, height, length, status}`` recomputed from anchor + blocks, and
``attestation`` is null for plain or the frozen
``{public_key, version, signature}`` for attested (64 hex key, positive
version, 128 hex signature) with the signature re-verified over the canonical
``ledger-sync-range-v1`` message. Whole-chain (non-range) records answer 409;
unknown, expired or cleaned keys answer 404. Before exporting, the tail, the
assembled chain, the fingerprint and (attested) the frozen signature are all
re-verified; a mismatch silently drops the cached record and its fork (audit
history untouched) and answers 404; a failed cleanup save restores the state
and raises OSError. Exports stay consistent across restart and after the
candidate is adopted (rebuilt from the canonical prefix).

Run: python3 tests/sync_range_export_test.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ledger import crypto
from ledger.cli import main as cli_main
from ledger.models import STATUS_PENDING, Block, Transaction
from ledger.server import build_handler
from ledger.service import LedgerService
from ledger.store import (
    LedgerStore,
    attested_message,
    attested_range_message,
)

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
ANCHOR_KEY_ORDER = ["height", "block_hash"]
TIP_KEY_ORDER = ["tip_hash", "height", "length", "status"]
ATTESTATION_KEY_ORDER = ["public_key", "version", "signature"]
BLOCK_KEY_ORDER = [
    "height",
    "prev_hash",
    "merkle_root",
    "block_hash",
    "status",
    "transactions",
]


def keypair() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return key, pub


def seed_keypair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return seed, pub


def tx_obj(key: Ed25519PrivateKey, sender: str, to: str, amount: int) -> Transaction:
    msg = crypto.canonical_message(sender, to, amount)
    return Transaction.from_dict(
        {"from": sender, "to": to, "amount": amount, "signature": key.sign(msg).hex()}
    )


class SyncRangeExportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        # A confirmed canonical chain 0..1 the ranges anchor on.
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
        self.anchor_block = self.store.chain[1]
        self.anchor = {
            "height": 1,
            "block_hash": self.anchor_block.block_hash,
        }

    # -- helpers --------------------------------------------------------------

    def _register(self, source: str, pub: str) -> None:
        status, body = self.svc.register_trust_source(
            {
                "source": source,
                "public_key": pub,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        self.assertIn(status, (200, 201), body)

    def _tail(self, key: Ed25519PrivateKey, sender: str, to: str,
              amount: int, status: str = "confirmed",
              start_height: int = 2) -> Block:
        return Block.create(
            start_height, self.anchor_block.block_hash,
            [tx_obj(key, sender, to, amount)], status,
        )

    def _tip(self, tail: Block) -> dict:
        return {
            "tip_hash": tail.block_hash,
            "height": tail.height,
            "length": self.anchor["height"] + 2,
            "status": tail.status,
        }

    def _plain_range(
        self, source: str, request_id: str, tail: Block,
        pub: str | None = None,
    ) -> tuple[int, dict]:
        self._register(source, pub or format(abs(hash(request_id)) % 0xFFFF + 1, "064x"))
        return self.svc.submit_fork_sync_range(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": int(time.time()) + 3600,
                "anchor": self.anchor,
                "blocks": [tail.to_dict()],
                "tip": self._tip(tail),
            }
        )

    def _attested_range(
        self, source: str, request_id: str, tail: Block, seed: str, pub: str
    ) -> tuple[int, dict, str]:
        self._register(source, pub)
        tip = self._tip(tail)
        expires_at = int(time.time()) + 3600
        message = attested_range_message(
            source, request_id, expires_at, self.anchor, [tail.to_dict()], tip
        )
        signature = crypto.sign_message(seed, hashlib.sha256(message).digest())
        self.assertIsNotNone(signature)
        status, body = self.svc.submit_fork_sync_range_attested(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "anchor": self.anchor,
                "blocks": [tail.to_dict()],
                "tip": tip,
                "signature": signature,
            }
        )
        return status, body, signature

    def _export(
        self, source: str, request_id: str, mode: str
    ) -> tuple[int, dict]:
        return self.svc.export_fork_sync_range(
            {"source": source, "request_id": request_id, "mode": mode}
        )

    def _seed_plain(self) -> tuple[str, Block]:
        tail = self._tail(self.ka, self.A, self.C, 7)
        status, body = self._plain_range("plain-node", "r1", tail, self.A)
        self.assertEqual(status, 201, body)
        return body["tip_hash"], tail

    def _seed_attested(self) -> tuple[str, Block, str, str, str]:
        seed, pub = seed_keypair()
        key = self._load_seed(seed)
        tail = self._tail(key, pub, self.C, 8)
        status, body, signature = self._attested_range(
            "att-node", "r2", tail, seed, pub
        )
        self.assertEqual(status, 201, body)
        return body["tip_hash"], tail, seed, pub, signature

    @staticmethod
    def _load_seed(seed: str) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))

    # -- parameter validation --------------------------------------------------

    def test_missing_and_unknown_params_400(self) -> None:
        self._seed_plain()
        good = {"source": "plain-node", "request_id": "r1", "mode": "plain"}
        for missing in ("source", "request_id", "mode"):
            params = {k: v for k, v in good.items() if k != missing}
            self.assertEqual(
                self.svc.export_fork_sync_range(params)[0], 400, missing
            )
        for extra in ("limit", "cursor", "tip_hash", "anchor", "Mode", ""):
            params = dict(good)
            params[extra] = "x"
            self.assertEqual(
                self.svc.export_fork_sync_range(params)[0], 400, extra
            )

    def test_invalid_values_400(self) -> None:
        self._seed_plain()
        for bad_mode in ("all", "PLAIN", "Attested", "", "range", "plain "):
            self.assertEqual(
                self._export("plain-node", "r1", bad_mode)[0], 400, bad_mode
            )
        self.assertEqual(self._export("", "r1", "plain")[0], 400)
        self.assertEqual(self._export("plain-node", "", "plain")[0], 400)
        self.assertEqual(self._export(1, "r1", "plain")[0], 400)  # type: ignore[arg-type]
        self.assertEqual(self._export("plain-node", 2, "plain")[0], 400)  # type: ignore[arg-type]

    # -- plain range export ----------------------------------------------------

    def test_plain_range_export_success(self) -> None:
        tip_hash, tail = self._seed_plain()
        status, body = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["source"], "plain-node")
        self.assertEqual(body["request_id"], "r1")
        self.assertEqual(body["mode"], "plain")
        self.assertIsInstance(body["expires_at"], int)
        self.assertNotIsInstance(body["expires_at"], bool)
        self.assertIsNone(body["attestation"])
        # Anchor: fixed key order and strict types.
        self.assertEqual(list(body["anchor"]), ANCHOR_KEY_ORDER)
        self.assertEqual(body["anchor"], self.anchor)
        self.assertIsInstance(body["anchor"]["height"], int)
        self.assertNotIsInstance(body["anchor"]["height"], bool)
        # Blocks: non-empty README-order tail documents, exactly the tail.
        self.assertIsInstance(body["blocks"], list)
        self.assertEqual(len(body["blocks"]), 1)
        self.assertEqual(list(body["blocks"][0]), BLOCK_KEY_ORDER)
        self.assertEqual(body["blocks"], [tail.to_dict()])
        # Tip: recomputed from anchor + blocks, fixed key order.
        self.assertEqual(list(body["tip"]), TIP_KEY_ORDER)
        self.assertEqual(
            body["tip"],
            {
                "tip_hash": tip_hash,
                "height": 2,
                "length": 3,
                "status": "confirmed",
            },
        )

    def test_plain_range_export_pending_tip(self) -> None:
        tail = self._tail(self.ka, self.A, self.C, 9, status=STATUS_PENDING)
        status, body = self._plain_range("p-node", "rp", tail, self.A)
        self.assertEqual(status, 201, body)
        status, body = self._export("p-node", "rp", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tip"]["status"], "pending")
        self.assertEqual(body["blocks"][-1]["status"], "pending")

    def test_multi_block_tail_tip_recomputed(self) -> None:
        # A two-block tail after the height-1 anchor.
        tail1 = self._tail(self.ka, self.A, self.C, 11)
        tail2 = Block.create(
            3, tail1.block_hash, [tx_obj(self.ka, self.A, self.B, 4)], "confirmed"
        )
        self._register("multi-node", self.A)
        tip = {
            "tip_hash": tail2.block_hash,
            "height": 3,
            "length": 4,
            "status": "confirmed",
        }
        status, body = self.svc.submit_fork_sync_range(
            {
                "source": "multi-node",
                "request_id": "rm",
                "expires_at": int(time.time()) + 3600,
                "anchor": self.anchor,
                "blocks": [tail1.to_dict(), tail2.to_dict()],
                "tip": tip,
            }
        )
        self.assertEqual(status, 201, body)
        status, body = self._export("multi-node", "rm", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["blocks"], [tail1.to_dict(), tail2.to_dict()])
        self.assertEqual(body["tip"], tip)
        self.assertEqual(body["anchor"], self.anchor)

    # -- attested range export --------------------------------------------------

    def test_attested_range_export_success(self) -> None:
        tip_hash, tail, seed, pub, signature = self._seed_attested()
        status, body = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["mode"], "attested")
        self.assertEqual(body["tip"]["tip_hash"], tip_hash)
        self.assertEqual(body["blocks"], [tail.to_dict()])
        attestation = body["attestation"]
        self.assertEqual(list(attestation), ATTESTATION_KEY_ORDER)
        self.assertEqual(attestation["public_key"], pub)
        self.assertTrue(crypto.is_hex64(attestation["public_key"]))
        self.assertIsInstance(attestation["version"], int)
        self.assertNotIsInstance(attestation["version"], bool)
        self.assertGreaterEqual(attestation["version"], 1)
        self.assertTrue(crypto.is_hex128(attestation["signature"]))
        self.assertEqual(attestation["signature"], signature)
        # The exported attestation re-verifies over the canonical range
        # domain message (SHA-256 then Ed25519 under the frozen public key).
        message = attested_range_message(
            "att-node",
            "r2",
            body["expires_at"],
            body["anchor"],
            body["blocks"],
            body["tip"],
        )
        digest = hashlib.sha256(message).digest()
        self.assertTrue(
            crypto.verify_signature(pub, digest, attestation["signature"])
        )

    def test_attested_range_export_survives_rotation(self) -> None:
        tip_hash, tail, seed, pub, signature = self._seed_attested()
        new_seed, new_pub = seed_keypair()
        status, body = self.svc.rotate_trust_source(
            "att-node",
            {
                "public_key": new_pub,
                "expires_at": int(time.time()) + 10_000_000,
                "expected_version": 1,
            },
        )
        self.assertEqual(status, 200, body)
        status, body = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["attestation"]["public_key"], pub)
        self.assertEqual(body["attestation"]["version"], 1)
        self.assertEqual(body["attestation"]["signature"], signature)

    # -- namespaces, non-range records, unknown ---------------------------------

    def test_unknown_and_cross_namespace_404(self) -> None:
        self._seed_plain()
        self._seed_attested()
        self.assertEqual(self._export("ghost", "r1", "plain")[0], 404)
        self.assertEqual(self._export("plain-node", "nope", "plain")[0], 404)
        # The two tables are separate idempotency namespaces.
        self.assertEqual(self._export("plain-node", "r1", "attested")[0], 404)
        self.assertEqual(self._export("att-node", "r2", "plain")[0], 404)

    def test_whole_chain_records_409(self) -> None:
        # A plain whole-chain sync record is not a range record.
        genesis = self.store.chain[0]
        fork = Block.create(
            1, genesis.block_hash, [tx_obj(self.kc, self.C, self.B, 5)], "confirmed"
        )
        self._register("full-node", self.C)
        status, body = self.svc.submit_fork_sync(
            {
                "source": "full-node",
                "request_id": "f1",
                "expires_at": int(time.time()) + 3600,
                "candidate": {
                    "tip_hash": fork.block_hash,
                    "height": 1,
                    "length": 2,
                    "status": "confirmed",
                    "blocks": [genesis.to_dict(), fork.to_dict()],
                },
            }
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(self._export("full-node", "f1", "plain")[0], 409)

        # An attested whole-chain record is not a range record either.
        seed, pub = seed_keypair()
        key = self._load_seed(seed)
        fork2 = Block.create(
            1, genesis.block_hash, [tx_obj(key, pub, self.B, 6)], "confirmed"
        )
        candidate = {
            "tip_hash": fork2.block_hash,
            "height": 1,
            "length": 2,
            "status": "confirmed",
            "blocks": [genesis.to_dict(), fork2.to_dict()],
        }
        expires_at = int(time.time()) + 3600
        message = attested_message("full-att-node", "f2", expires_at, candidate)
        signature = crypto.sign_message(seed, hashlib.sha256(message).digest())
        self._register("full-att-node", pub)
        status, body = self.svc.submit_fork_sync_attested(
            {
                "source": "full-att-node",
                "request_id": "f2",
                "expires_at": expires_at,
                "candidate": candidate,
                "signature": signature,
            }
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(
            self._export("full-att-node", "f2", "attested")[0], 409
        )
        # The rejected exports leave the records in place.
        self.assertIn(("full-node", "f1"), self.store.syncs)
        self.assertIn(("full-att-node", "f2"), self.store.attested_syncs)
        # A range record still exports normally alongside them.
        self._seed_plain()
        self.assertEqual(self._export("plain-node", "r1", "plain")[0], 200)

    def test_range_records_still_409_on_whole_chain_export(self) -> None:
        # The pre-existing whole-chain export endpoint keeps answering 409
        # for the range records that the new endpoint exports.
        tip_hash, _tail = self._seed_plain()
        self.assertEqual(
            self.svc.export_fork_sync(
                {"source": "plain-node", "request_id": "r1", "mode": "plain"}
            )[0],
            409,
        )

    # -- expiry, adoption, restart ----------------------------------------------

    def test_expired_record_404(self) -> None:
        tip_hash, _tail = self._seed_plain()
        self.store.syncs[("plain-node", "r1")]["expires_at"] = int(time.time()) - 5
        self.store.save()
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        # The sweep removed the record and its fork and appended exactly one
        # sync_expired event.
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)
        expired = [
            e for e in self.store.audit_events if e["kind"] == "sync_expired"
        ]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["request_id"], "r1")
        # A repeat stays 404 without a second event.
        self.assertEqual(self._export("plain-node", "r1", "plain")[0], 404)
        expired = [
            e for e in self.store.audit_events if e["kind"] == "sync_expired"
        ]
        self.assertEqual(len(expired), 1)

    def test_adopted_tip_exports_from_canonical_prefix(self) -> None:
        tip_hash, tail = self._seed_plain()
        status, body = self.svc.adopt_fork(tip_hash)
        self.assertEqual(status, 200, body)
        self.assertNotIn(tip_hash, self.store.forks)
        self.assertEqual(self.store.chain[-1].block_hash, tip_hash)
        status, body = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200, body)
        # The export still carries only the delivered tail, rebuilt from the
        # canonical prefix without a new authoritative copy.
        self.assertEqual(body["anchor"], self.anchor)
        self.assertEqual(body["blocks"], [tail.to_dict()])
        self.assertEqual(body["tip"], self._tip(tail))
        self.assertNotIn(tip_hash, self.store.forks)

    def test_restart_consistency(self) -> None:
        self._seed_plain()
        self._seed_attested()
        status, plain_before = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200)
        status, att_before = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200)
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.store = self.svc.store
        status, plain_after = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200)
        status, att_after = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200)
        self.assertEqual(plain_before, plain_after)
        self.assertEqual(att_before, att_after)

    # -- cache drops on re-verification mismatch --------------------------------

    def test_plain_fingerprint_mismatch_drops_cache_404(self) -> None:
        tip_hash, _tail = self._seed_plain()
        events_before = [dict(e) for e in self.store.audit_events]
        self.store.syncs[("plain-node", "r1")]["fingerprint"] = "0" * 64
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)
        # The audit history is preserved verbatim: no new event.
        self.assertEqual(
            [dict(e) for e in self.store.audit_events], events_before
        )
        svc2 = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.assertNotIn(("plain-node", "r1"), svc2.store.syncs)
        self.assertNotIn(tip_hash, svc2.store.forks)

    def test_plain_tampered_tail_drops_cache_404(self) -> None:
        tip_hash, _tail = self._seed_plain()
        rec = self.store.syncs[("plain-node", "r1")]
        rec["range"]["blocks"][0]["block_hash"] = "a" * 64
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)

    def test_plain_tampered_stored_fork_drops_cache_404(self) -> None:
        tip_hash, _tail = self._seed_plain()
        tampered = [b.to_dict() for b in self.store.forks[tip_hash]]
        tampered[-1] = dict(tampered[-1])
        # Strip transactions while keeping the stored block_hash: the
        # recomputed block hash / Merkle root no longer matches.
        tampered[-1]["transactions"] = []
        self.store.forks[tip_hash] = [Block.from_dict(b) for b in tampered]
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)

    def test_plain_frozen_summary_mismatch_drops_cache_404(self) -> None:
        tip_hash, _tail = self._seed_plain()
        self.store.syncs[("plain-node", "r1")]["height"] = 99
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)

    def test_attested_signature_mismatch_drops_cache_404(self) -> None:
        tip_hash, _tail, _seed, _pub, _sig = self._seed_attested()
        events_before = [dict(e) for e in self.store.audit_events]
        self.store.attested_syncs[("att-node", "r2")]["attested"][
            "signature"
        ] = "f" * 128
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip_hash, self.store.forks)
        self.assertEqual(
            [dict(e) for e in self.store.audit_events], events_before
        )

    def test_attested_fingerprint_mismatch_drops_cache_404(self) -> None:
        tip_hash, _tail, _seed, _pub, _sig = self._seed_attested()
        self.store.attested_syncs[("att-node", "r2")]["fingerprint"] = "0" * 64
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip_hash, self.store.forks)

    def test_attested_frozen_summary_mismatch_drops_cache_404(self) -> None:
        tip_hash, _tail, _seed, _pub, _sig = self._seed_attested()
        self.store.attested_syncs[("att-node", "r2")]["length"] = 999
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip_hash, self.store.forks)

    def test_cleanup_save_failure_restores_and_raises(self) -> None:
        tip_hash, _tail = self._seed_plain()
        self.store.syncs[("plain-node", "r1")]["fingerprint"] = "0" * 64
        original_save = self.store.save

        def failing_save() -> None:
            raise OSError("simulated persistence failure")

        self.store.save = failing_save
        try:
            with self.assertRaises(OSError):
                self._export("plain-node", "r1", "plain")
        finally:
            self.store.save = original_save
        # The failed cleanup restored the record and its fork.
        self.assertIn(("plain-node", "r1"), self.store.syncs)
        self.assertIn(tip_hash, self.store.forks)
        # Once the save recovers the stale record is dropped for real.
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)

    def test_successful_export_is_a_pure_read(self) -> None:
        self._seed_plain()
        generation = self.store.generation
        events = len(self.store.audit_events)
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200)
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(len(self.store.audit_events), events)


class SyncRangeExportHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.svc)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls._seed_range_record()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    @classmethod
    def _seed_range_record(cls) -> None:
        cls.svc.register_trust_source(
            {
                "source": "node-1",
                "public_key": cls.A,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        cls.svc.submit_transaction(
            {
                "from": cls.A,
                "to": cls.B,
                "amount": 3,
                "signature": cls.ka.sign(
                    crypto.canonical_message(cls.A, cls.B, 3)
                ).hex(),
            }
        )
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200
        anchor_block = cls.svc.store.chain[1]
        tail = Block.create(
            2,
            anchor_block.block_hash,
            [tx_obj(cls.ka, cls.A, cls.B, 10)],
            "confirmed",
        )
        cls.tip = {
            "tip_hash": tail.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        cls.anchor = {"height": 1, "block_hash": anchor_block.block_hash}
        status, body = cls.svc.submit_fork_sync_range(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "anchor": cls.anchor,
                "blocks": [tail.to_dict()],
                "tip": cls.tip,
            }
        )
        assert status == 201, body
        cls.tip_hash = body["tip_hash"]

    def _get_raw(self, query: str) -> tuple[int, str]:
        url = (
            f"http://127.0.0.1:{self.port}/v1/forks/sync/range/export{query}"
        )
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def test_success_and_key_order(self) -> None:
        status, raw = self._get_raw(
            "?source=node-1&request_id=req-1&mode=plain"
        )
        self.assertEqual(status, 200, raw)
        body = json.loads(raw)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["tip"], self.tip)
        self.assertEqual(body["anchor"], self.anchor)
        self.assertEqual(list(body["anchor"]), ANCHOR_KEY_ORDER)
        self.assertEqual(list(body["tip"]), TIP_KEY_ORDER)
        self.assertIsNone(body["attestation"])
        self.assertEqual(len(body["blocks"]), 1)

    def test_repeated_params_400(self) -> None:
        for query in (
            "?source=node-1&source=node-1&request_id=req-1&mode=plain",
            "?source=node-1&request_id=req-1&request_id=req-1&mode=plain",
            "?source=node-1&request_id=req-1&mode=plain&mode=plain",
        ):
            status, _ = self._get_raw(query)
            self.assertEqual(status, 400, query)

    def test_missing_unknown_and_invalid_params_400(self) -> None:
        for query in (
            "",
            "?source=node-1&request_id=req-1",
            "?source=node-1&mode=plain",
            "?request_id=req-1&mode=plain",
            "?source=node-1&request_id=req-1&mode=plain&limit=5",
            "?source=node-1&request_id=req-1&mode=all",
            "?source=&request_id=req-1&mode=plain",
            "?source=node-1&request_id=&mode=plain",
        ):
            status, _ = self._get_raw(query)
            self.assertEqual(status, 400, query)

    def test_unknown_record_404(self) -> None:
        status, _ = self._get_raw(
            "?source=node-1&request_id=ghost&mode=plain"
        )
        self.assertEqual(status, 404)
        status, _ = self._get_raw(
            "?source=node-1&request_id=req-1&mode=attested"
        )
        self.assertEqual(status, 404)


class SyncRangeExportCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.svc)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"--base-url=http://127.0.0.1:{cls.port}"
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.svc.register_trust_source(
            {
                "source": "node-1",
                "public_key": cls.A,
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        cls.svc.submit_transaction(
            {
                "from": cls.A,
                "to": cls.B,
                "amount": 3,
                "signature": cls.ka.sign(
                    crypto.canonical_message(cls.A, cls.B, 3)
                ).hex(),
            }
        )
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200
        anchor_block = cls.svc.store.chain[1]
        cls.tail = Block.create(
            2,
            anchor_block.block_hash,
            [tx_obj(cls.ka, cls.A, cls.B, 10)],
            "confirmed",
        )
        cls.anchor = {"height": 1, "block_hash": anchor_block.block_hash}
        status, body = cls.svc.submit_fork_sync_range(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "anchor": cls.anchor,
                "blocks": [cls.tail.to_dict()],
                "tip": {
                    "tip_hash": cls.tail.block_hash,
                    "height": 2,
                    "length": 3,
                    "status": "confirmed",
                },
            }
        )
        assert status == 201, body
        cls.tip_hash = body["tip_hash"]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def _run_cli(self, *args: str) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main([self.base, *args])
        return rc, buf.getvalue()

    def test_sync_range_export_success_single_line(self) -> None:
        rc, out = self._run_cli(
            "sync-range-export",
            "--source", "node-1",
            "--request-id", "req-1",
            "--mode", "plain",
        )
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(out.strip().splitlines()), 1)
        body = json.loads(out)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["tip"]["tip_hash"], self.tip_hash)
        self.assertEqual(body["mode"], "plain")
        self.assertIsNone(body["attestation"])
        self.assertEqual(body["blocks"], [self.tail.to_dict()])
        self.assertEqual(body["anchor"], self.anchor)

    def test_sync_range_export_non_2xx_exit_1(self) -> None:
        rc, out = self._run_cli(
            "sync-range-export",
            "--source", "node-1",
            "--request-id", "ghost",
            "--mode", "plain",
        )
        self.assertEqual(rc, 1)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertIn("error", json.loads(out))


if __name__ == "__main__":
    unittest.main(verbosity=2)
