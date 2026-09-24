"""Tests for GET /v1/forks/sync/range/export and the ``sync-range-export`` CLI.

The endpoint exports one received INCREMENTAL-RANGE sync by its idempotency
key: exactly the three single-valued query parameters ``source``,
``request_id`` and ``mode`` (``plain``/``attested`` only) are accepted —
missing, repeated, empty or unknown parameters are 400. A whole-chain
(non-range) record answers 409; an unknown, expired or cleaned record answers
404. A hit returns 200 with the fixed top-level key order
``source, request_id, mode, expires_at, anchor, blocks, tip, attestation``:
``expires_at`` is a non-boolean integer, ``anchor`` is
``{height, block_hash}``, ``blocks`` is the non-empty delivered tail in README
block key order and ``tip`` is the closed ``{tip_hash, height, length,
status}`` summary RECOMPUTED from anchor + blocks. Plain records return
``attestation: null``; attested records return the frozen
``{public_key, version, signature}`` after re-verifying the
``ledger-sync-range-v1`` Ed25519 signature, the fingerprint, the standalone
tail (heights, prev_hash, block hashes, Merkle roots, tx ids/signatures) and
the assembled stored chain. A mismatch silently drops the record/fork (audit
history untouched) and answers 404; a failed cleanup save restores state and
raises OSError. Exports stay consistent across restart, and the CLI
``sync-range-export`` prints one JSON line and exits 1 on any non-2xx.

Run: python3 tests/range_sync_export_test.py
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
BLOCK_KEY_ORDER = [
    "height",
    "prev_hash",
    "merkle_root",
    "block_hash",
    "status",
    "transactions",
]
ATTESTATION_KEY_ORDER = ["public_key", "version", "signature"]


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


def make_fork(blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class RangeExportServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.state_path = os.path.join(self.tmp, "state.json")
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        self.genesis = self.store.chain[0]
        self.ka, self.A = keypair()
        self.kb, self.B = keypair()
        self.kc, self.C = keypair()
        self.exp = int(time.time()) + 10_000_000
        self._trust_seq = 0
        # Advance the canonical chain to a confirmed height-1 anchor.
        status, _ = self.svc.submit_transaction(
            {
                "from": self.A,
                "to": self.B,
                "amount": 3,
                "signature": self.ka.sign(
                    crypto.canonical_message(self.A, self.B, 3)
                ).hex(),
            }
        )
        self.assertEqual(status, 202)
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
            {"source": source, "public_key": pub, "expires_at": self.exp}
        )
        self.assertIn(status, (200, 201), body)

    def _trust_dummy(self, source: str) -> None:
        self._trust_seq += 1
        self._register(source, format(0x3000 + self._trust_seq, "064x"))

    def _tail(self, to: str, amount: int, start: int = 2, prev=None,
              status: str = "confirmed") -> Block:
        return Block.create(
            start,
            prev if prev is not None else self.anchor_block.block_hash,
            [tx_obj(self.ka, self.A, to, amount)],
            status,
        )

    def _tip(self, tail: Block) -> dict:
        return {
            "tip_hash": tail.block_hash,
            "height": tail.height,
            "length": tail.height + 1,
            "status": tail.status,
        }

    def _plain_range(
        self, source: str, request_id: str, tail_blocks: list[Block],
        expires_at: int | None = None,
    ) -> tuple[int, dict]:
        self._trust_dummy(source)
        anchor = {"height": tail_blocks[0].height - 1,
                  "block_hash": tail_blocks[0].prev_hash}
        tip = self._tip(tail_blocks[-1])
        return self.svc.submit_fork_sync_range(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at or int(time.time()) + 3600,
                "anchor": anchor,
                "blocks": [b.to_dict() for b in tail_blocks],
                "tip": tip,
            }
        )

    def _attested_range(
        self,
        source: str,
        request_id: str,
        tail_blocks: list[Block],
        seed: str,
        pub: str,
    ) -> tuple[int, dict, str]:
        self._register(source, pub)
        anchor = {"height": tail_blocks[0].height - 1,
                  "block_hash": tail_blocks[0].prev_hash}
        tip = self._tip(tail_blocks[-1])
        expires_at = int(time.time()) + 3600
        message = attested_range_message(
            source,
            request_id,
            expires_at,
            anchor,
            [b.to_dict() for b in tail_blocks],
            tip,
        )
        signature = crypto.sign_message(seed, hashlib.sha256(message).digest())
        self.assertIsNotNone(signature)
        status, body = self.svc.submit_fork_sync_range_attested(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "anchor": anchor,
                "blocks": [b.to_dict() for b in tail_blocks],
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

    def _seed_plain(self) -> tuple[dict, Block]:
        tail = self._tail(self.C, 7)
        status, body = self._plain_range("plain-node", "r1", [tail])
        self.assertEqual(status, 201, body)
        return self._tip(tail), tail

    def _seed_attested(self) -> tuple[dict, Block, str, str, str]:
        seed, pub = seed_keypair()
        tail = self._tail(self.C, 8)
        status, body, signature = self._attested_range(
            "att-node", "r2", [tail], seed, pub
        )
        self.assertEqual(status, 201, body)
        return self._tip(tail), tail, pub, signature, seed

    def _seed_plain_full_sync(self) -> None:
        self._trust_dummy("full-node")
        block1 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 9)]
        )
        status, body = self.svc.submit_fork_sync(
            {
                "source": "full-node",
                "request_id": "f1",
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork([self.genesis, block1]),
            }
        )
        self.assertEqual(status, 201, body)

    def _seed_attested_full_sync(self) -> None:
        seed, pub = seed_keypair()
        self._register("full-att-node", pub)
        block1 = Block.create(
            1, self.genesis.block_hash, [tx_obj(self.ka, self.A, self.B, 11)]
        )
        candidate = make_fork([self.genesis, block1])
        expires_at = int(time.time()) + 3600
        message = attested_message("full-att-node", "f2", expires_at, candidate)
        signature = crypto.sign_message(seed, hashlib.sha256(message).digest())
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
            self.assertEqual(self._export("plain-node", "r1", bad_mode)[0], 400)
        self.assertEqual(self._export("", "r1", "plain")[0], 400)
        self.assertEqual(self._export("plain-node", "", "plain")[0], 400)

    # -- plain export -----------------------------------------------------------

    def test_plain_export_success_shape_and_content(self) -> None:
        tip, tail = self._seed_plain()
        status, body = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["source"], "plain-node")
        self.assertEqual(body["request_id"], "r1")
        self.assertEqual(body["mode"], "plain")
        self.assertIsInstance(body["expires_at"], int)
        self.assertNotIsInstance(body["expires_at"], bool)
        self.assertEqual(list(body["anchor"]), ANCHOR_KEY_ORDER)
        self.assertEqual(body["anchor"], self.anchor)
        self.assertIsInstance(body["anchor"]["height"], int)
        self.assertNotIsInstance(body["anchor"]["height"], bool)
        self.assertTrue(crypto.is_hex64(body["anchor"]["block_hash"]))
        self.assertIsInstance(body["blocks"], list)
        self.assertEqual(len(body["blocks"]), 1)
        block_doc = body["blocks"][0]
        self.assertEqual(list(block_doc), BLOCK_KEY_ORDER)
        self.assertEqual(block_doc, tail.to_dict())
        self.assertEqual(list(body["tip"]), TIP_KEY_ORDER)
        self.assertEqual(body["tip"], tip)
        self.assertTrue(crypto.is_hex64(body["tip"]["tip_hash"]))
        self.assertIsNone(body["attestation"])

    def test_multi_block_tail_tip_is_recomputed(self) -> None:
        t2 = self._tail(self.B, 2, start=2)
        t3 = self._tail(self.C, 4, start=3, prev=t2.block_hash)
        status, body = self._plain_range("multi-node", "m1", [t2, t3])
        self.assertEqual(status, 201, body)
        status, body = self._export("multi-node", "m1", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual([b["height"] for b in body["blocks"]], [2, 3])
        self.assertEqual(
            body["tip"],
            {"tip_hash": t3.block_hash, "height": 3, "length": 4,
             "status": "confirmed"},
        )
        # The exported range can be pushed again as an idempotent replay.
        status, replay = self.svc.submit_fork_sync_range(
            {
                "source": "multi-node",
                "request_id": "m1",
                "expires_at": body["expires_at"],
                "anchor": body["anchor"],
                "blocks": body["blocks"],
                "tip": body["tip"],
            }
        )
        self.assertEqual(status, 200, replay)

    def test_pending_tail_export(self) -> None:
        tail = self._tail(self.C, 5, status=STATUS_PENDING)
        status, body = self._plain_range("p-node", "rp", [tail])
        self.assertEqual(status, 201, body)
        status, body = self._export("p-node", "rp", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tip"]["status"], "pending")
        self.assertEqual(body["blocks"][-1]["status"], "pending")

    # -- attested export ---------------------------------------------------------

    def test_attested_export_success(self) -> None:
        tip, tail, pub, signature, _seed = self._seed_attested()
        status, body = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["mode"], "attested")
        self.assertEqual(body["anchor"], self.anchor)
        self.assertEqual(body["blocks"], [tail.to_dict()])
        self.assertEqual(body["tip"], tip)
        attestation = body["attestation"]
        self.assertEqual(list(attestation), ATTESTATION_KEY_ORDER)
        self.assertTrue(crypto.is_hex64(attestation["public_key"]))
        self.assertEqual(attestation["public_key"], pub)
        self.assertIsInstance(attestation["version"], int)
        self.assertNotIsInstance(attestation["version"], bool)
        self.assertGreaterEqual(attestation["version"], 1)
        self.assertTrue(crypto.is_hex128(attestation["signature"]))
        self.assertEqual(attestation["signature"], signature)
        # The exported attestation re-verifies over the range-v1 domain message.
        message = attested_range_message(
            "att-node",
            "r2",
            body["expires_at"],
            body["anchor"],
            body["blocks"],
            body["tip"],
        )
        self.assertTrue(
            crypto.verify_signature(
                pub, hashlib.sha256(message).digest(), signature
            )
        )

    def test_attested_export_survives_rotation(self) -> None:
        _tip, _tail, pub, _signature, _seed = self._seed_attested()
        new_seed, new_pub = seed_keypair()
        status, body = self.svc.rotate_trust_source(
            "att-node",
            {
                "public_key": new_pub,
                "expires_at": self.exp,
                "expected_version": 1,
            },
        )
        self.assertEqual(status, 200, body)
        status, body = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["attestation"]["public_key"], pub)
        self.assertEqual(body["attestation"]["version"], 1)

    # -- non-range records are 409 ------------------------------------------------

    def test_whole_chain_records_409(self) -> None:
        self._seed_plain_full_sync()
        self._seed_attested_full_sync()
        self.assertEqual(self._export("full-node", "f1", "plain")[0], 409)
        self.assertEqual(
            self._export("full-att-node", "f2", "attested")[0], 409
        )
        # The records survive the rejected exports.
        self.assertIn(("full-node", "f1"), self.store.syncs)
        self.assertIn(("full-att-node", "f2"), self.store.attested_syncs)

    def test_range_records_remain_409_on_whole_chain_export(self) -> None:
        self._seed_plain()
        _tip, _tail, _pub, _sig, _seed = self._seed_attested()
        self.assertEqual(
            self.svc.export_fork_sync(
                {"source": "plain-node", "request_id": "r1", "mode": "plain"}
            )[0],
            409,
        )
        self.assertEqual(
            self.svc.export_fork_sync(
                {"source": "att-node", "request_id": "r2", "mode": "attested"}
            )[0],
            409,
        )

    # -- unknown / namespace / expiry --------------------------------------------

    def test_unknown_and_cross_namespace_404(self) -> None:
        self._seed_plain()
        self._seed_attested()
        self.assertEqual(self._export("ghost", "r1", "plain")[0], 404)
        self.assertEqual(self._export("plain-node", "nope", "plain")[0], 404)
        self.assertEqual(self._export("plain-node", "r1", "attested")[0], 404)
        self.assertEqual(self._export("att-node", "r2", "plain")[0], 404)

    def test_expired_record_404_with_one_event(self) -> None:
        tip, _tail = self._seed_plain()
        self.store.syncs[("plain-node", "r1")]["expires_at"] = int(time.time()) - 5
        self.store.save()
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip["tip_hash"], self.store.forks)
        expired = [
            e for e in self.store.audit_events if e["kind"] == "sync_expired"
        ]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["request_id"], "r1")
        self.assertEqual(self._export("plain-node", "r1", "plain")[0], 404)

    # -- adoption, restart, concurrency ------------------------------------------

    def test_adopted_tip_exports_from_canonical_prefix(self) -> None:
        tip, tail = self._seed_plain()
        status, body = self.svc.adopt_fork(tip["tip_hash"])
        self.assertEqual(status, 200, body)
        self.assertNotIn(tip["tip_hash"], self.store.forks)
        self.assertEqual(self.store.chain[-1].block_hash, tip["tip_hash"])
        status, body = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tip"], tip)
        self.assertEqual(body["blocks"], [tail.to_dict()])
        self.assertEqual(body["anchor"], self.anchor)

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

    def test_concurrent_exports_are_consistent(self) -> None:
        self._seed_plain()
        results: list[tuple[int, object]] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            results.append(self._export("plain-node", "r1", "plain"))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(status == 200 for status, _ in results))
        first = results[0][1]
        self.assertTrue(all(body == first for _, body in results))

    def test_successful_export_is_a_pure_read(self) -> None:
        self._seed_plain()
        generation = self.store.generation
        events = len(self.store.audit_events)
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200)
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(len(self.store.audit_events), events)

    # -- mismatch cache drops ----------------------------------------------------

    def test_plain_fingerprint_mismatch_drops_cache_404(self) -> None:
        tip, _tail = self._seed_plain()
        events_before = [dict(e) for e in self.store.audit_events]
        self.store.syncs[("plain-node", "r1")]["fingerprint"] = "0" * 64
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip["tip_hash"], self.store.forks)
        self.assertEqual(
            [dict(e) for e in self.store.audit_events], events_before
        )
        svc2 = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000),
            initial_balance=1000,
        )
        self.assertNotIn(("plain-node", "r1"), svc2.store.syncs)
        self.assertNotIn(tip["tip_hash"], svc2.store.forks)

    def test_plain_tampered_fork_drops_cache_404(self) -> None:
        tip, tail = self._seed_plain()
        tampered = [tail.to_dict()]
        tampered[0] = dict(tampered[0])
        tampered[0]["transactions"] = []
        from ledger.models import Block as _Block

        # Assemble a bad stored chain sharing the anchor prefix but a
        # mismatched tail; the export re-verification must detect it.
        self.store.forks[tip["tip_hash"]] = [
            *self.store.chain[:2],
            _Block.from_dict(tampered[0]),
        ]
        # The bad block still carries the claimed tip hash record, so the
        # delivered tail itself differs from the stored tail.
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip["tip_hash"], self.store.forks)

    def test_attested_signature_mismatch_drops_cache_404(self) -> None:
        tip, _tail, _pub, _signature, _seed = self._seed_attested()
        events_before = [dict(e) for e in self.store.audit_events]
        self.store.attested_syncs[("att-node", "r2")]["attested"][
            "signature"
        ] = "f" * 128
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip["tip_hash"], self.store.forks)
        self.assertEqual(
            [dict(e) for e in self.store.audit_events], events_before
        )

    def test_attested_fingerprint_mismatch_drops_cache_404(self) -> None:
        tip, _tail, _pub, _signature, _seed = self._seed_attested()
        self.store.attested_syncs[("att-node", "r2")]["fingerprint"] = "0" * 64
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip["tip_hash"], self.store.forks)

    def test_tampered_signed_tip_drops_cache_404(self) -> None:
        tip, _tail, _pub, _signature, _seed = self._seed_attested()
        signed_range = self.store.attested_syncs[("att-node", "r2")][
            "attested"
        ]["range"]
        signed_range["tip"] = dict(tip)
        signed_range["tip"]["height"] = tip["height"] + 1
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip["tip_hash"], self.store.forks)

    def test_cleanup_save_failure_restores_and_raises(self) -> None:
        tip, _tail = self._seed_plain()
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
        self.assertIn(("plain-node", "r1"), self.store.syncs)
        self.assertIn(tip["tip_hash"], self.store.forks)
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)


class RangeExportHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.svc)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls.kc, cls.C = keypair()
        cls._seed_records()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    @classmethod
    def _seed_records(cls) -> None:
        svc = cls.svc
        svc.register_trust_source(
            {
                "source": "node-1",
                "public_key": format(0x4444, "064x"),
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        status, _ = svc.submit_transaction(
            {
                "from": cls.A,
                "to": cls.B,
                "amount": 3,
                "signature": cls.ka.sign(
                    crypto.canonical_message(cls.A, cls.B, 3)
                ).hex(),
            }
        )
        assert status == 202
        assert svc.mine_block()[0] == 201
        assert svc.confirm_block(1)[0] == 200
        anchor_block = svc.store.chain[1]
        tail = Block.create(
            2,
            anchor_block.block_hash,
            [tx_obj(cls.ka, cls.A, cls.C, 7)],
            "confirmed",
        )
        tip = {"tip_hash": tail.block_hash, "height": 2, "length": 3,
               "status": "confirmed"}
        status, body = svc.submit_fork_sync_range(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "anchor": {"height": 1, "block_hash": anchor_block.block_hash},
                "blocks": [tail.to_dict()],
                "tip": tip,
            }
        )
        assert status == 201, body
        cls.tip_hash = body["tip_hash"]

    def _get_raw(self, query: str) -> tuple[int, str]:
        url = f"http://127.0.0.1:{self.port}/v1/forks/sync/range/export{query}"
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
        self.assertEqual(body["tip"]["tip_hash"], self.tip_hash)
        self.assertIsNone(body["attestation"])
        self.assertEqual(list(body["anchor"]), ANCHOR_KEY_ORDER)
        self.assertEqual(list(body["tip"]), TIP_KEY_ORDER)
        self.assertEqual(list(body["blocks"][0]), BLOCK_KEY_ORDER)

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

    def test_route_does_not_match_fork_export(self) -> None:
        # The generic fork export route must not swallow the range-export
        # path (which would treat "sync" as a tip hash and answer 404).
        status, raw = self._get_raw(
            "?source=node-1&request_id=req-1&mode=plain"
        )
        self.assertEqual(status, 200, raw)


class RangeExportCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), build_handler(cls.svc)
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"--base-url=http://127.0.0.1:{cls.port}"
        ka, A = keypair()
        _kb, B = keypair()
        _kc, C = keypair()
        cls.svc.register_trust_source(
            {
                "source": "node-1",
                "public_key": format(0x5555, "064x"),
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        status, _ = cls.svc.submit_transaction(
            {
                "from": A,
                "to": B,
                "amount": 3,
                "signature": ka.sign(
                    crypto.canonical_message(A, B, 3)
                ).hex(),
            }
        )
        assert status == 202
        assert cls.svc.mine_block()[0] == 201
        assert cls.svc.confirm_block(1)[0] == 200
        anchor_block = cls.svc.store.chain[1]
        tail = Block.create(
            2, anchor_block.block_hash, [tx_obj(ka, A, C, 7)], "confirmed"
        )
        tip = {"tip_hash": tail.block_hash, "height": 2, "length": 3,
               "status": "confirmed"}
        status, body = cls.svc.submit_fork_sync_range(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "anchor": {"height": 1, "block_hash": anchor_block.block_hash},
                "blocks": [tail.to_dict()],
                "tip": tip,
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
