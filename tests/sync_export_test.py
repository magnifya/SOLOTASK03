"""Tests for GET /v1/forks/sync/export and the ``sync-export`` CLI.

The endpoint exports one received sync candidate by its idempotency key:
exactly the three single-valued query parameters ``source``, ``request_id``
and ``mode`` (``plain``/``attested`` only) are accepted — missing, repeated,
empty or unknown parameters are 400. A hit returns 200 with the fixed key
order ``source, request_id, mode, expires_at, tip_hash, height, length,
status, candidate, attestation``: plain records export the five-field
candidate document with ``attestation: null``; attested records export the
signed candidate verbatim plus the frozen ``{public_key, version,
signature}``, re-verified against the domain message, the frozen key and the
fingerprint. Incremental range records are 409; unknown, expired or cleaned
records are 404. The candidate is rebuilt under the store lock from the
stored fork or — after adoption — the canonical prefix, with no new
authoritative copy; a signature/digest mismatch drops the cached record
(audit history untouched) and answers 404, and a failed cleanup save
restores the pre-cleanup state and raises OSError.

Run: python3 tests/sync_export_test.py
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
from ledger.models import Block, Transaction
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
    "tip_hash",
    "height",
    "length",
    "status",
    "candidate",
    "attestation",
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


def make_fork(blocks: list[Block]) -> dict:
    tip = blocks[-1]
    return {
        "tip_hash": tip.block_hash,
        "height": tip.height,
        "length": len(blocks),
        "status": tip.status,
        "blocks": [b.to_dict() for b in blocks],
    }


class SyncExportServiceTests(unittest.TestCase):
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
        self._trust_seq = 0

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

    def _trust_dummy(self, source: str) -> None:
        self._trust_seq += 1
        self._register(source, format(0x1000 + self._trust_seq, "064x"))

    def _block(self, height: int, prev: str, to: str, amount: int, status: str = "confirmed") -> Block:
        return Block.create(
            height, prev, [tx_obj(self.ka, self.A, to, amount)], status
        )

    def _plain_sync(
        self, source: str, request_id: str, blocks: list[Block]
    ) -> tuple[int, dict]:
        self._trust_dummy(source)
        return self.svc.submit_fork_sync(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork(blocks),
            }
        )

    def _attested_sync(
        self,
        source: str,
        request_id: str,
        blocks: list[Block],
        seed: str,
        pub: str,
    ) -> tuple[int, dict]:
        self._register(source, pub)
        candidate = make_fork(blocks)
        expires_at = int(time.time()) + 3600
        message = attested_message(source, request_id, expires_at, candidate)
        signature = crypto.sign_message(seed, hashlib.sha256(message).digest())
        self.assertIsNotNone(signature)
        return self.svc.submit_fork_sync_attested(
            {
                "source": source,
                "request_id": request_id,
                "expires_at": expires_at,
                "candidate": candidate,
                "signature": signature,
            }
        )

    def _export(
        self, source: str, request_id: str, mode: str
    ) -> tuple[int, dict]:
        return self.svc.export_fork_sync(
            {"source": source, "request_id": request_id, "mode": mode}
        )

    def _seed_plain(self) -> tuple[str, list[Block]]:
        blocks = [self.genesis, self._block(1, self.genesis.block_hash, self.B, 10)]
        status, body = self._plain_sync("plain-node", "r1", blocks)
        self.assertEqual(status, 201, body)
        return body["tip_hash"], blocks

    def _seed_attested(self) -> tuple[str, list[Block], str, str]:
        seed, pub = seed_keypair()
        blocks = [self.genesis, self._block(1, self.genesis.block_hash, self.C, 20)]
        status, body = self._attested_sync("att-node", "r2", blocks, seed, pub)
        self.assertEqual(status, 201, body)
        return body["tip_hash"], blocks, seed, pub

    # -- parameter validation --------------------------------------------------

    def test_missing_and_unknown_params_400(self) -> None:
        self._seed_plain()
        good = {"source": "plain-node", "request_id": "r1", "mode": "plain"}
        for missing in ("source", "request_id", "mode"):
            params = {k: v for k, v in good.items() if k != missing}
            self.assertEqual(self.svc.export_fork_sync(params)[0], 400, missing)
        for extra in ("limit", "cursor", "tip_hash", "height", "Mode", ""):
            params = dict(good)
            params[extra] = "x"
            self.assertEqual(self.svc.export_fork_sync(params)[0], 400, extra)

    def test_invalid_values_400(self) -> None:
        self._seed_plain()
        for bad_mode in ("all", "PLAIN", "Attested", "", "signed", "plain "):
            self.assertEqual(
                self._export("plain-node", "r1", bad_mode)[0], 400, bad_mode
            )
        self.assertEqual(self._export("", "r1", "plain")[0], 400)
        self.assertEqual(self._export("plain-node", "", "plain")[0], 400)

    # -- plain export -----------------------------------------------------------

    def test_plain_export_success(self) -> None:
        tip_hash, blocks = self._seed_plain()
        status, body = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["source"], "plain-node")
        self.assertEqual(body["request_id"], "r1")
        self.assertEqual(body["mode"], "plain")
        self.assertIsInstance(body["expires_at"], int)
        self.assertNotIsInstance(body["expires_at"], bool)
        self.assertIsInstance(body["height"], int)
        self.assertIsInstance(body["length"], int)
        self.assertTrue(crypto.is_hex64(body["tip_hash"]))
        self.assertEqual(body["tip_hash"], tip_hash)
        self.assertEqual(body["status"], "confirmed")
        self.assertIsNone(body["attestation"])
        candidate = body["candidate"]
        self.assertEqual(
            list(candidate), ["tip_hash", "height", "length", "status", "blocks"]
        )
        self.assertEqual(candidate["tip_hash"], tip_hash)
        self.assertEqual(candidate["height"], 1)
        self.assertEqual(candidate["length"], 2)
        self.assertEqual(candidate["status"], "confirmed")
        self.assertEqual(candidate["blocks"], [b.to_dict() for b in blocks])
        # The exported document re-validates as a candidate chain.
        fork = self.store.validate_fork_blocks(candidate["blocks"])
        self.assertEqual(fork[-1].block_hash, tip_hash)

    def test_plain_export_pending_tip(self) -> None:
        block1 = self._block(1, self.genesis.block_hash, self.B, 10)
        block2 = Block.create(
            2, block1.block_hash, [tx_obj(self.ka, self.A, self.C, 5)], "pending"
        )
        status, body = self._plain_sync("p-node", "rp", [self.genesis, block1, block2])
        self.assertEqual(status, 201, body)
        self.assertEqual(body["status"], "pending")
        status, body = self._export("p-node", "rp", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["status"], "pending")
        self.assertEqual(body["height"], 2)
        self.assertEqual(body["length"], 3)
        self.assertEqual(body["candidate"]["status"], "pending")
        self.assertEqual(body["candidate"]["blocks"][-1]["status"], "pending")

    # -- attested export ---------------------------------------------------------

    def test_attested_export_success(self) -> None:
        tip_hash, blocks, seed, pub = self._seed_attested()
        status, body = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200, body)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["mode"], "attested")
        self.assertEqual(body["tip_hash"], tip_hash)
        # The signed candidate is preserved verbatim (the exact signed form).
        signed = self.store.attested_syncs[("att-node", "r2")]["attested"]
        self.assertEqual(body["candidate"], signed["candidate"])
        self.assertEqual(body["candidate"]["blocks"], [b.to_dict() for b in blocks])
        attestation = body["attestation"]
        self.assertEqual(list(attestation), ["public_key", "version", "signature"])
        self.assertEqual(attestation["public_key"], pub)
        self.assertEqual(attestation["version"], 1)
        self.assertTrue(crypto.is_hex128(attestation["signature"]))
        # The exported attestation re-verifies against the domain message.
        message = attested_message(
            "att-node", "r2", body["expires_at"], body["candidate"]
        )
        digest = hashlib.sha256(message).digest()
        self.assertTrue(
            crypto.verify_signature(
                attestation["public_key"], digest, attestation["signature"]
            )
        )

    def test_attested_export_survives_rotation(self) -> None:
        # The frozen key/version are exported even after the source rotates.
        tip_hash, blocks, seed, pub = self._seed_attested()
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

    # -- namespaces, range records, unknown -------------------------------------

    def test_unknown_and_cross_namespace_404(self) -> None:
        self._seed_plain()
        self._seed_attested()
        self.assertEqual(self._export("ghost", "r1", "plain")[0], 404)
        self.assertEqual(self._export("plain-node", "nope", "plain")[0], 404)
        # The two tables are separate namespaces: a plain key is unknown in
        # the attested table and vice versa.
        self.assertEqual(self._export("plain-node", "r1", "attested")[0], 404)
        self.assertEqual(self._export("att-node", "r2", "plain")[0], 404)

    def test_range_records_409(self) -> None:
        # Advance the canonical chain so a range can anchor on it.
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
        anchor_block = self.store.chain[1]
        tail = Block.create(
            2, anchor_block.block_hash, [tx_obj(self.ka, self.A, self.C, 7)], "confirmed"
        )
        tip = {
            "tip_hash": tail.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        anchor = {"height": 1, "block_hash": anchor_block.block_hash}
        # Plain range record.
        self._trust_dummy("range-node")
        status, body = self.svc.submit_fork_sync_range(
            {
                "source": "range-node",
                "request_id": "rr1",
                "expires_at": int(time.time()) + 3600,
                "anchor": anchor,
                "blocks": [tail.to_dict()],
                "tip": tip,
            }
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(self._export("range-node", "rr1", "plain")[0], 409)
        # Attested range record.
        seed, pub = seed_keypair()
        self._register("att-range-node", pub)
        tail2 = Block.create(
            2, anchor_block.block_hash, [tx_obj(self.kb, self.B, self.C, 8)], "confirmed"
        )
        tip2 = {
            "tip_hash": tail2.block_hash,
            "height": 2,
            "length": 3,
            "status": "confirmed",
        }
        expires_at = int(time.time()) + 3600
        message = attested_range_message(
            "att-range-node", "rr2", expires_at, anchor, [tail2.to_dict()], tip2
        )
        signature = crypto.sign_message(seed, hashlib.sha256(message).digest())
        status, body = self.svc.submit_fork_sync_range_attested(
            {
                "source": "att-range-node",
                "request_id": "rr2",
                "expires_at": expires_at,
                "anchor": anchor,
                "blocks": [tail2.to_dict()],
                "tip": tip2,
                "signature": signature,
            }
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(self._export("att-range-node", "rr2", "attested")[0], 409)
        # The records themselves survive the failed exports.
        self.assertIn(("range-node", "rr1"), self.store.syncs)
        self.assertIn(("att-range-node", "rr2"), self.store.attested_syncs)

    # -- expiry, adoption, restart ------------------------------------------------

    def test_expired_record_404(self) -> None:
        tip_hash, _blocks = self._seed_plain()
        self.store.syncs[("plain-node", "r1")]["expires_at"] = int(time.time()) - 5
        self.store.save()
        status, body = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        # The expiry sweep removed the record and its fork, and appended
        # exactly one sync_expired event.
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)
        expired = [e for e in self.store.audit_events if e["kind"] == "sync_expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["request_id"], "r1")
        # A repeated export stays 404 without a second event.
        self.assertEqual(self._export("plain-node", "r1", "plain")[0], 404)
        expired = [e for e in self.store.audit_events if e["kind"] == "sync_expired"]
        self.assertEqual(len(expired), 1)

    def test_adopted_tip_exports_from_canonical_prefix(self) -> None:
        tip_hash, blocks = self._seed_plain()
        # The synced fork is strictly longer than canonical: adopt it.
        status, body = self.svc.adopt_fork(tip_hash)
        self.assertEqual(status, 200, body)
        self.assertNotIn(tip_hash, self.store.forks)
        self.assertEqual(self.store.chain[-1].block_hash, tip_hash)
        status, body = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["tip_hash"], tip_hash)
        self.assertEqual(
            body["candidate"]["blocks"], [b.to_dict() for b in self.store.chain]
        )
        self.assertEqual(body["candidate"]["length"], len(self.store.chain))

    def test_restart_consistency(self) -> None:
        self._seed_plain()
        self._seed_attested()
        status, plain_before = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200)
        status, att_before = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200)
        # Restart from the persisted snapshot.
        self.svc = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.store = self.svc.store
        status, plain_after = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200)
        status, att_after = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 200)
        self.assertEqual(plain_before, plain_after)
        self.assertEqual(att_before, att_after)

    # -- cache-drop on mismatch ----------------------------------------------------

    def test_plain_fingerprint_mismatch_drops_cache_404(self) -> None:
        tip_hash, _blocks = self._seed_plain()
        events_before = [dict(e) for e in self.store.audit_events]
        # Corrupt the in-memory record's fingerprint (simulating a tampered
        # cache); the export re-verification must drop it and answer 404.
        self.store.syncs[("plain-node", "r1")]["fingerprint"] = "0" * 64
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)
        # The audit history is preserved verbatim: no new event is appended.
        self.assertEqual([dict(e) for e in self.store.audit_events], events_before)
        # The drop is persisted: a restart does not resurrect the record.
        svc2 = LedgerService(
            LedgerStore(self.state_path, initial_balance=1000), initial_balance=1000
        )
        self.assertNotIn(("plain-node", "r1"), svc2.store.syncs)
        self.assertNotIn(tip_hash, svc2.store.forks)

    def test_plain_tampered_fork_drops_cache_404(self) -> None:
        tip_hash, blocks = self._seed_plain()
        # Tamper with the stored fork so the recomputed fingerprint differs.
        tampered = [b.to_dict() for b in blocks]
        tampered[-1] = dict(tampered[-1])
        tampered[-1]["transactions"] = []
        from ledger.models import Block as _Block

        self.store.forks[tip_hash] = [_Block.from_dict(b) for b in tampered]
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)
        self.assertNotIn(tip_hash, self.store.forks)

    def test_attested_signature_mismatch_drops_cache_404(self) -> None:
        tip_hash, _blocks, _seed, _pub = self._seed_attested()
        events_before = [dict(e) for e in self.store.audit_events]
        attested = self.store.attested_syncs[("att-node", "r2")]["attested"]
        attested["signature"] = "f" * 128
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip_hash, self.store.forks)
        self.assertEqual([dict(e) for e in self.store.audit_events], events_before)

    def test_attested_fingerprint_mismatch_drops_cache_404(self) -> None:
        tip_hash, _blocks, _seed, _pub = self._seed_attested()
        self.store.attested_syncs[("att-node", "r2")]["fingerprint"] = "0" * 64
        status, _ = self._export("att-node", "r2", "attested")
        self.assertEqual(status, 404)
        self.assertNotIn(("att-node", "r2"), self.store.attested_syncs)
        self.assertNotIn(tip_hash, self.store.forks)

    def test_cleanup_save_failure_restores_and_raises(self) -> None:
        tip_hash, _blocks = self._seed_plain()
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
        # The failed cleanup restored the pre-cleanup state.
        self.assertIn(("plain-node", "r1"), self.store.syncs)
        self.assertIn(tip_hash, self.store.forks)
        # After the save recovers the stale record is dropped for real.
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 404)
        self.assertNotIn(("plain-node", "r1"), self.store.syncs)

    def test_export_does_not_persist_or_mutate(self) -> None:
        self._seed_plain()
        generation = self.store.generation
        events = len(self.store.audit_events)
        status, _ = self._export("plain-node", "r1", "plain")
        self.assertEqual(status, 200)
        # A successful export is a pure read: no generation advance, no
        # audit event, no new authoritative copy.
        self.assertEqual(self.store.generation, generation)
        self.assertEqual(len(self.store.audit_events), events)


class SyncExportHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.svc))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.ka, cls.A = keypair()
        cls.kb, cls.B = keypair()
        cls._seed_plain_record()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    @classmethod
    def _seed_plain_record(cls) -> None:
        cls.svc.register_trust_source(
            {
                "source": "node-1",
                "public_key": format(0x2222, "064x"),
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        genesis = cls.svc.store.chain[0]
        block = Block.create(
            1, genesis.block_hash, [tx_obj(cls.ka, cls.A, cls.B, 10)], "confirmed"
        )
        status, body = cls.svc.submit_fork_sync(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork([genesis, block]),
            }
        )
        assert status == 201, body
        cls.tip_hash = body["tip_hash"]

    def _get_raw(self, query: str) -> tuple[int, str]:
        url = f"http://127.0.0.1:{self.port}/v1/forks/sync/export{query}"
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def test_success_and_key_order(self) -> None:
        status, raw = self._get_raw("?source=node-1&request_id=req-1&mode=plain")
        self.assertEqual(status, 200, raw)
        body = json.loads(raw)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["tip_hash"], self.tip_hash)
        self.assertIsNone(body["attestation"])
        self.assertEqual(
            list(body["candidate"]),
            ["tip_hash", "height", "length", "status", "blocks"],
        )

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
        status, _ = self._get_raw("?source=node-1&request_id=ghost&mode=plain")
        self.assertEqual(status, 404)
        status, _ = self._get_raw("?source=node-1&request_id=req-1&mode=attested")
        self.assertEqual(status, 404)


class SyncExportCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.svc = LedgerService(
            LedgerStore(cls.state_path, initial_balance=1000), initial_balance=1000
        )
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(cls.svc))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"--base-url=http://127.0.0.1:{cls.port}"
        ka, A = keypair()
        _kb, B = keypair()
        cls.svc.register_trust_source(
            {
                "source": "node-1",
                "public_key": format(0x3333, "064x"),
                "expires_at": int(time.time()) + 10_000_000,
            }
        )
        genesis = cls.svc.store.chain[0]
        block = Block.create(
            1, genesis.block_hash, [tx_obj(ka, A, B, 10)], "confirmed"
        )
        status, body = cls.svc.submit_fork_sync(
            {
                "source": "node-1",
                "request_id": "req-1",
                "expires_at": int(time.time()) + 3600,
                "candidate": make_fork([genesis, block]),
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

    def test_sync_export_success_single_line(self) -> None:
        rc, out = self._run_cli(
            "sync-export",
            "--source",
            "node-1",
            "--request-id",
            "req-1",
            "--mode",
            "plain",
        )
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(out.strip().splitlines()), 1)
        body = json.loads(out)
        self.assertEqual(list(body), EXPORT_KEY_ORDER)
        self.assertEqual(body["tip_hash"], self.tip_hash)
        self.assertEqual(body["mode"], "plain")
        self.assertIsNone(body["attestation"])

    def test_sync_export_non_2xx_exit_1(self) -> None:
        rc, out = self._run_cli(
            "sync-export",
            "--source",
            "node-1",
            "--request-id",
            "ghost",
            "--mode",
            "plain",
        )
        self.assertEqual(rc, 1)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertIn("error", json.loads(out))


if __name__ == "__main__":
    unittest.main(verbosity=2)
